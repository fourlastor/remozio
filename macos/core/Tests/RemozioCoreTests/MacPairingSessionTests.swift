import Foundation
import Security
import Synchronization
import XCTest
import RemozioProtocol
@testable import RemozioCore

// Logical IPC and software keys. These controls grant no native administrator rights or installed service identity.
private actor MacPairingRootFixture: MacPairingRootControl {
    let fixture: TransportPairingFixture
    var started = false
    var stages = 0
    var commits = 0
    var loseCommitReply = false
    var remainingRePairChecks: Int?
    var heldCommit: AsyncStream<Void>?
    func canRePair(_ selection: PairedPhoneSelection) -> Bool {
        guard let remainingRePairChecks else { return true }
        self.remainingRePairChecks = max(0, remainingRePairChecks - 1)
        return remainingRePairChecks > 0
    }
    func permitRePairChecks(_ count: Int) { remainingRePairChecks = count }
    func holdCommit(_ signal: AsyncStream<Void>) { heldCommit = signal }
    init(_ fixture: TransportPairingFixture) { self.fixture = fixture }
    func start() -> AuthorityPairingContext {
        started = true
        return .init(macID: fixture.configuration.macID, accountID: fixture.configuration.accountID,
            authorityPublicKey: fixture.invitation.authorityPublicKey, transportPublicKey: fixture.invitation.transportPublicKey,
            minimumEnvelopeVersion: 1, lifetimeMilliseconds: 1000)
    }
    func stage(_ proposal: PairingPhoneProposal, authorization: Data) throws -> PairingTranscript {
        XCTAssertTrue(started); XCTAssertEqual(authorization.count, MemoryLayout<AuthorizationExternalForm>.size)
        try proposal.validate(fixture.transcript); stages += 1; return fixture.transcript
    }
    func commit(confirmedDigest: Data, biometricProof: Data, authorization: Data) async throws -> Data {
        XCTAssertEqual(try fixture.transcript.digest(), confirmedDigest)
        XCTAssertTrue(try fixture.transcript.verify(signature: biometricProof, publicKey: fixture.transcript.biometricKey.publicKey, purpose: .phoneBiometric))
        commits += 1
        if let heldCommit { for await _ in heldCommit {} }
        if loseCommitReply { throw MacPairingSessionError.closed }
        return try fixture.receipt()
    }
    func loseReply() { loseCommitReply = true }
    nonisolated func abort() {}
    func close() {}
}
private actor MacPairingTransportFixture: MacPairingTransportControl {
    let fixture: TransportPairingFixture
    let id = Data(repeating: 23, count: 16)
    var phase = TransportPairingPhase.proposed
    var proof: Data?
    var disappear = false
    var receipts = 0
    var loseReceiptReply = false
    var rePairStarts = 0
    private let aborts = Mutex(0)
    nonisolated var abortCount: Int { aborts.withLock { $0 } }
    var staged = 0
    private var beforeCurrentReply: (@Sendable () -> Void)?
    func start(rePair: RePairInvitation) throws -> UInt16 {
        XCTAssertEqual(rePair.predecessor, fixture.proposal.replacement)
        XCTAssertEqual(try rePair.invitation.encode(), try fixture.invitation.encode())
        rePairStarts += 1
        return 4321
    }
    init(_ fixture: TransportPairingFixture) { self.fixture = fixture }
    func start(invitation: PairingInvitation) throws -> UInt16 { XCTAssertEqual(try invitation.encode(), try fixture.invitation.encode()); return 4321 }
    func current() throws -> TransportPairingSnapshot {
        defer {
            beforeCurrentReply?()
            beforeCurrentReply = nil
        }
        return try .init(port: 4321, candidates: disappear ? [] : [.init(id: id, proposal: fixture.proposal, phase: phase, biometricProof: proof)])
    }
    func stage(candidateID: Data, transcript: PairingTranscript) throws {
        staged += 1
        XCTAssertEqual(candidateID, id); XCTAssertEqual(try transcript.encode(), try fixture.transcript.encode()); phase = .awaitingProof
    }
    func deliverReceipt(candidateID: Data, signature: Data) throws {
        XCTAssertEqual(candidateID, id)
        XCTAssertTrue(try fixture.transcript.verify(signature: signature, publicKey: fixture.transcript.macAuthorityKey, purpose: .macCommit))
        receipts += 1
        if loseReceiptReply { throw MacPairingSessionError.closed }
        phase = .receiptSent
    }
    func showProof(_ value: Data) { proof = value; phase = .proofReady }
    func removeCandidate() { disappear = true }
    func beforeNextCurrentReply(_ action: @escaping @Sendable () -> Void) { beforeCurrentReply = action }
    func loseDelivery() { loseReceiptReply = true }
    nonisolated func abort() { aborts.withLock { $0 += 1 } }
    func close() {}
}
private actor MacPairingAdministratorFixture: MacPairingAdministrator {
    let root: MacPairingRootFixture
    var cancel = false
    var hold = false
    var waiting: CheckedContinuation<Data, any Error>?
    init(_ root: MacPairingRootFixture) { self.root = root }
    func authorization() async throws -> Data {
        let started = await root.started; XCTAssertTrue(started)
        if cancel { throw SetupAdministratorAuthorizationError.cancelled }
        if hold { return try await withCheckedThrowingContinuation { waiting = $0 } }
        return Data(count: MemoryLayout<AuthorizationExternalForm>.size)
    }
    func cancelAuthorization() { cancel = true }
    func holdAuthorization() { hold = true }
    var isWaiting: Bool { waiting != nil }
    func release() {
        hold = false
        let old = waiting; waiting = nil
        old?.resume(returning: Data(count: MemoryLayout<AuthorizationExternalForm>.size))
    }
    func close() {}
}
private final class MacPairingClockFixture: Sendable {
    enum Failure: Error { case sample }
    private let values = Mutex((wall: UInt64(1000), elapsed: UInt64(0), failed: false))

    func wall() -> UInt64 { values.withLock { $0.wall } }
    func elapsed() throws -> UInt64 {
        try values.withLock {
            guard !$0.failed else { throw Failure.sample }
            return $0.elapsed
        }
    }
    func setWall(_ milliseconds: UInt64) { values.withLock { $0.wall = milliseconds } }
    func setElapsed(_ milliseconds: UInt64) { values.withLock { $0.elapsed = milliseconds } }
    func failElapsedRead() { values.withLock { $0.failed = true } }
}
final class MacPairingSessionTests: XCTestCase {
    private struct Owner {
        let fixture: TransportPairingFixture
        let root: MacPairingRootFixture
        let transport: MacPairingTransportFixture
        let admin: MacPairingAdministratorFixture
        let clock = MacPairingClockFixture()
        let session: MacPairingSession
        init(rePair: Bool = false, selectedRevision: UUID? = nil, elapsedAtV2OpenReply: UInt64? = nil) throws {
            let fixture = try TransportPairingFixture(rePair: rePair)
            self.fixture = fixture
            root = .init(fixture); transport = .init(fixture); admin = .init(root)
            let predecessor = try fixture.proposal.replacement.map { replacement in
                PairedPhoneSelection(macID: fixture.configuration.macID, accountID: fixture.configuration.accountID,
                    revision: try selectedRevision ?? GatewayHostSnapshot.uuid(fixture.transcript.expectedTrustRevision),
                    phone: DeliveryRecipient(phoneID: replacement.phoneID, enrollmentEpoch: replacement.epoch))
            }
            let clock = clock, root = root
            let v2 = try elapsedAtV2OpenReply.map { elapsed in
                let exported = try PairingInvitationV2(invitation: fixture.invitation, windowID: Data(repeating: 1, count: 16),
                    secret: Data(repeating: 2, count: 32), replacement: fixture.proposal.replacement, lifetimeMilliseconds: 1000)
                return MacPairingV2Control(open: { _, _ in clock.setElapsed(elapsed); return exported },
                    listen: { _ in }, stage: { proposal, _, authorization in try await root.stage(proposal, authorization: authorization) })
            }
            session = .init(root: root, transport: transport, administrator: admin, predecessor: predecessor, v2: v2,
                unixMilliseconds: { clock.wall() }, elapsedMilliseconds: { try clock.elapsed() })
        }
        func start() async throws {
            _ = try await session.start(label: "Fixture"); _ = try await session.current()
        }
        func select() async throws { _ = try await session.select(candidateID: transport.id) }
        func prepareProof() async throws {
            try await select(); _ = try await session.confirmComparison()
            try await transport.showProof(fixture.proof()); _ = try await session.current()
        }
    }
    func testCompleteFlowCommitsTheConfirmedTranscriptAndSendsOneReceipt() async throws {
        let o = try Owner(); try await o.start(); try await o.prepareProof()
        let before = await o.session.snapshot()
        XCTAssertEqual(before.comparisonCode, try o.fixture.transcript.verificationCode()); XCTAssertTrue(before.phoneProofAvailable)
        let after = try await o.session.commit(); XCTAssertEqual(after.phase, .receiptSent)
        do { _ = try await o.session.commit(); XCTFail() } catch {}
        let commits = await o.root.commits, receipts = await o.transport.receipts
        XCTAssertEqual(commits, 1); XCTAssertEqual(receipts, 1); await o.session.close()
    }
    func testRePairRevalidatesSelectionBeforePublishingAndStaging() async throws {
        let denied = try Owner(rePair: true)
        await denied.root.permitRePairChecks(0)
        do { try await denied.start(); XCTFail("Published a stale selection") }
        catch { XCTAssertTrue(error is MacPairingSessionError) }
        let starts = await denied.transport.rePairStarts
        XCTAssertEqual(starts, 0)

        let stale = try Owner(rePair: true)
        try await stale.start()
        let snapshot = await stale.session.snapshot()
        XCTAssertEqual(snapshot.rePairInvitation?.predecessor, stale.fixture.proposal.replacement)
        await stale.root.permitRePairChecks(0)
        do { try await stale.select(); XCTFail("Staged a stale selection") }
        catch { XCTAssertTrue(error is MacPairingSessionError) }
        let stages = await stale.root.stages
        XCTAssertEqual(stages, 0)
    }

    func testRePairRechecksEligibilityAfterWaitingForTheHelper() async throws {
        let o = try Owner(rePair: true)
        await o.root.permitRePairChecks(1)
        do { try await o.start(); XCTFail("Published an invitation after eligibility changed") }
        catch MacPairingSessionError.ineligiblePredecessor {}
        let starts = await o.transport.rePairStarts
        let snapshot = await o.session.snapshot()
        XCTAssertEqual(starts, 1)
        XCTAssertGreaterThan(o.transport.abortCount, 0)
        XCTAssertNil(snapshot.rePairInvitation)
    }

    func testRePairRejectsAStagedTranscriptForADifferentTrustRevision() async throws {
        let o = try Owner(rePair: true, selectedRevision: GatewayHostSnapshot.uuid(Data(repeating: 12, count: 16)))
        try await o.start()
        do { try await o.select(); XCTFail("Exposed a transcript for a different revision") }
        catch MacPairingSessionError.ineligiblePredecessor {}
        let rootStages = await o.root.stages
        let transportStages = await o.transport.staged
        XCTAssertEqual(rootStages, 1)
        XCTAssertEqual(transportStages, 0)
        let state = await o.session.snapshot()
        XCTAssertNil(state.comparisonCode)
    }

    func testRePairCloseWaitsForSubmittedCommitAndPreservesReceipt() async throws {
        let o = try Owner(rePair: true)
        let release = AsyncStream<Void>.makeStream()
        defer { release.continuation.finish() }
        await o.root.holdCommit(release.stream)
        try await o.start()
        try await o.prepareProof()
        let commit = Task { @Sendable in try await o.session.commit() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while await o.root.commits == 0, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        let commits = await o.root.commits
        XCTAssertEqual(commits, 1)
        let closed = Mutex(false)
        let close = Task { @Sendable in
            let known = await o.session.closeForRePair()
            closed.withLock { $0 = true }
            return known
        }
        try await Task.sleep(for: .milliseconds(40))
        XCTAssertFalse(closed.withLock { $0 })
        XCTAssertEqual(o.transport.abortCount, 0)
        o.clock.setElapsed(1000)
        release.continuation.finish()
        let state = try await commit.value
        let current = await close.value
        XCTAssertTrue(current)
        XCTAssertEqual(state.phase, .receiptSent)
        let receipts = await o.transport.receipts
        XCTAssertEqual(receipts, 1)
        XCTAssertGreaterThan(o.transport.abortCount, 0)
    }

    func testRePairCloseRefusesAReplacementAfterAnUnknownCommit() async throws {
        let o = try Owner(rePair: true)
        try await o.start()
        try await o.prepareProof()
        await o.root.loseReply()
        do { _ = try await o.session.commit(); XCTFail("Received an unavailable receipt") } catch {}
        let known = await o.session.closeForRePair()
        XCTAssertFalse(known)
    }

    func testProofDoesNotReplaceExplicitHumanConfirmation() async throws {
        let o = try Owner(); try await o.start(); try await o.select()
        try await o.transport.showProof(o.fixture.proof()); _ = try await o.session.current()
        do { _ = try await o.session.commit(); XCTFail() } catch {}
        let commits = await o.root.commits; XCTAssertEqual(commits, 0); await o.session.close()
    }
    func testLostRootReplyRemainsUnknownAndNeverRepeatsCommit() async throws {
        let o = try Owner(); try await o.start(); try await o.prepareProof(); await o.root.loseReply()
        do { _ = try await o.session.commit(); XCTFail() } catch {}
        let state = await o.session.snapshot(); XCTAssertEqual(state.phase, .outcomeUnknown)
        do { _ = try await o.session.commit(); XCTFail() } catch {}
        let commits = await o.root.commits, receipts = await o.transport.receipts
        XCTAssertEqual(commits, 1); XCTAssertEqual(receipts, 0); await o.session.close()
    }
    func testLostDeliveryPreservesVerifiedMacRegistrationWithoutClaimingPhoneActivation() async throws {
        let o = try Owner(); try await o.start(); try await o.prepareProof(); await o.transport.loseDelivery()
        let state = try await o.session.commit(); XCTAssertEqual(state.phase, .registeredOnMac)
        do { _ = try await o.session.commit(); XCTFail() } catch {}
        let commits = await o.root.commits, receipts = await o.transport.receipts
        XCTAssertEqual(commits, 1); XCTAssertEqual(receipts, 1); await o.session.close()
    }
    func testCancelledAdministratorPromptKeepsTheUnstagedFlowAvailable() async throws {
        let o = try Owner(); try await o.start(); await o.admin.cancelAuthorization()
        do { try await o.select(); XCTFail() } catch {}
        let state = await o.session.snapshot(), stages = await o.root.stages
        XCTAssertEqual(state.phase, .waitingForPhone); XCTAssertEqual(stages, 0); await o.session.close()
    }
    func testCandidateDisappearanceDuringAuthorizationNeverStagesRoot() async throws {
        let o = try Owner(); try await o.start(); await o.admin.holdAuthorization()
        let selection = Task { @Sendable in try await o.select() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !(await o.admin.isWaiting), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(5)) }
        let waiting = await o.admin.isWaiting; XCTAssertTrue(waiting)
        await o.transport.removeCandidate(); await o.admin.release()
        do { try await selection.value; XCTFail() } catch {}
        let stages = await o.root.stages; XCTAssertEqual(stages, 0); await o.session.close()
    }
    func testAbortDuringAuthorizationCannotStageAfterTheOSReplyReturns() async throws {
        let o = try Owner(); try await o.start(); await o.admin.holdAuthorization()
        let selection = Task { @Sendable in try await o.select() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !(await o.admin.isWaiting), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(5)) }
        let waiting = await o.admin.isWaiting; XCTAssertTrue(waiting)
        o.session.abort(); await o.admin.release()
        do { try await selection.value; XCTFail() } catch {}
        let stages = await o.root.stages, snapshot = await o.session.snapshot()
        XCTAssertEqual(stages, 0); XCTAssertEqual(snapshot.phase, .closed); await o.session.close()
    }
    func testElapsedDeadlineClearsActionAvailabilityBeforeCommit() async throws {
        let o = try Owner(); try await o.start(); try await o.prepareProof(); o.clock.setElapsed(1000)
        do { _ = try await o.session.current(); XCTFail() } catch {}
        let state = await o.session.snapshot(), commits = await o.root.commits
        XCTAssertEqual(state.phase, .expired); XCTAssertEqual(state.remainingMilliseconds, 0); XCTAssertEqual(commits, 0); await o.session.close()
    }
    func testConfirmationAtDeadlineExpiresAndClearsPairingData() async throws {
        let o = try Owner(); try await o.start(); try await o.select()
        o.clock.setElapsed(1000)
        do { _ = try await o.session.confirmComparison(); XCTFail("Confirmed an expired transcript") }
        catch MacPairingSessionError.expired {}
        try await assertExpiredBeforeCommit(o)
    }

    func testCommitExpiresWhileWaitingForAdministratorAuthorization() async throws {
        let o = try Owner(); try await o.start(); try await o.prepareProof()
        await o.admin.holdAuthorization()
        let commit = Task { @Sendable in try await o.session.commit() }
        let readyBy = ContinuousClock.now.advanced(by: .seconds(2))
        while !(await o.admin.isWaiting), ContinuousClock.now < readyBy {
            try await Task.sleep(for: .milliseconds(5))
        }
        let waiting = await o.admin.isWaiting
        XCTAssertTrue(waiting)
        o.clock.setElapsed(60_000)
        await o.admin.release()
        do { _ = try await commit.value; XCTFail("Submitted a commit after expiry") }
        catch MacPairingSessionError.expired {}
        try await assertExpiredBeforeCommit(o)
    }

    func testProofReplyThatCrossesDeadlineIsDiscarded() async throws {
        let o = try Owner(); try await o.start(); try await o.select()
        _ = try await o.session.confirmComparison()
        try await o.transport.showProof(o.fixture.proof())
        await o.transport.beforeNextCurrentReply { o.clock.setElapsed(1000) }
        do { _ = try await o.session.current(); XCTFail("Accepted a proof after expiry") }
        catch MacPairingSessionError.expired {}
        try await assertExpiredBeforeCommit(o)
    }

    func testV2DeadlineIncludesTheOpenCallAndDoesNotRestartAtStaging() async throws {
        let o = try Owner(elapsedAtV2OpenReply: 100); try await o.start()
        let opened = await o.session.snapshot()
        XCTAssertEqual(opened.remainingMilliseconds, 900)
        o.clock.setElapsed(800)
        try await o.select()
        let staged = await o.session.snapshot()
        XCTAssertEqual(staged.remainingMilliseconds, 200)
        o.clock.setElapsed(1000)
        do { _ = try await o.session.confirmComparison(); XCTFail("Extended the v2 window when staging") }
        catch MacPairingSessionError.expired {}
        try await assertExpiredBeforeCommit(o)
    }

    func testSignedWindowMayShortenV2DeadlineDespiteLaterWallClockChange() async throws {
        let o = try Owner(elapsedAtV2OpenReply: 100); try await o.start()
        o.clock.setWall(1900)
        try await o.select()
        let staged = await o.session.snapshot()
        XCTAssertEqual(staged.remainingMilliseconds, 100)
        o.clock.setWall(1000)
        o.clock.setElapsed(200)
        do { _ = try await o.session.confirmComparison(); XCTFail("Extended the deadline after the wall clock changed") }
        catch MacPairingSessionError.expired {}
        try await assertExpiredBeforeCommit(o)
    }

    func testElapsedClockFailurePreventsCommit() async throws {
        let o = try Owner(); try await o.start(); try await o.prepareProof()
        o.clock.failElapsedRead()
        do { _ = try await o.session.commit(); XCTFail("Submitted a commit without a clock sample") }
        catch MacPairingClockFixture.Failure.sample {}
        let state = await o.session.snapshot(), commits = await o.root.commits
        XCTAssertEqual(state.phase, .unavailable)
        XCTAssertEqual(state.remainingMilliseconds, 0)
        XCTAssertFalse(state.phoneProofAvailable)
        XCTAssertEqual(commits, 0)
        XCTAssertGreaterThan(o.transport.abortCount, 0)
    }

    private func assertExpiredBeforeCommit(_ o: Owner) async throws {
        let state = await o.session.snapshot()
        XCTAssertEqual(state.phase, .expired)
        XCTAssertEqual(state.remainingMilliseconds, 0)
        XCTAssertNil(state.comparisonCode)
        XCTAssertTrue(state.candidates.isEmpty)
        XCTAssertFalse(state.phoneProofAvailable)
        XCTAssertGreaterThan(o.transport.abortCount, 0)
        do { _ = try await o.session.commit(); XCTFail("Submitted a commit from an expired session") }
        catch MacPairingSessionError.invalidState {}
        let commits = await o.root.commits
        XCTAssertEqual(commits, 0)
    }

    func testInvalidProofNeverReachesCommit() async throws {
        let o = try Owner(); try await o.start(); try await o.select(); _ = try await o.session.confirmComparison()
        await o.transport.showProof(Data(count: 64))
        do { _ = try await o.session.current(); XCTFail() } catch {}
        let commits = await o.root.commits; XCTAssertEqual(commits, 0); await o.session.close()
    }
}
