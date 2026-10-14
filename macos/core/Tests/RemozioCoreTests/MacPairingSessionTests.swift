import Foundation
import Security
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
    func commit(confirmedDigest: Data, biometricProof: Data, authorization: Data) throws -> Data {
        XCTAssertEqual(try fixture.transcript.digest(), confirmedDigest)
        XCTAssertTrue(try fixture.transcript.verify(signature: biometricProof, publicKey: fixture.transcript.biometricKey.publicKey, purpose: .phoneBiometric))
        commits += 1
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
    init(_ fixture: TransportPairingFixture) { self.fixture = fixture }
    func start(invitation: PairingInvitation) throws -> UInt16 { XCTAssertEqual(try invitation.encode(), try fixture.invitation.encode()); return 4321 }
    func current() throws -> TransportPairingSnapshot {
        try .init(port: 4321, candidates: disappear ? [] : [.init(id: id, proposal: fixture.proposal, phase: phase, biometricProof: proof)])
    }
    func stage(candidateID: Data, transcript: PairingTranscript) throws {
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
    func loseDelivery() { loseReceiptReply = true }
    nonisolated func abort() {}
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
    func release() { let old = waiting; waiting = nil; old?.resume(returning: Data(count: MemoryLayout<AuthorizationExternalForm>.size)) }
    func close() {}
}
private final class MacPairingClockFixture: @unchecked Sendable {
    private let lock = NSLock()
    private var elapsed: UInt64 = 0
    func now() -> UInt64 { lock.withLock { elapsed } }
    func advance() { lock.withLock { elapsed = 1000 } }
}
final class MacPairingSessionTests: XCTestCase {
    private struct Owner {
        let fixture: TransportPairingFixture
        let root: MacPairingRootFixture
        let transport: MacPairingTransportFixture
        let admin: MacPairingAdministratorFixture
        let clock = MacPairingClockFixture()
        let session: MacPairingSession
        init() throws {
            fixture = try .init(); root = .init(fixture); transport = .init(fixture); admin = .init(root)
            let clock = clock
            session = .init(root: root, transport: transport, administrator: admin,
                unixMilliseconds: { 1000 }, elapsedMilliseconds: { clock.now() })
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
        let o = try Owner(); try await o.start(); try await o.prepareProof(); o.clock.advance()
        do { _ = try await o.session.current(); XCTFail() } catch {}
        let state = await o.session.snapshot(), commits = await o.root.commits
        XCTAssertEqual(state.phase, .expired); XCTAssertEqual(state.remainingMilliseconds, 0); XCTAssertEqual(commits, 0); await o.session.close()
    }
    func testInvalidProofNeverReachesCommit() async throws {
        let o = try Owner(); try await o.start(); try await o.select(); _ = try await o.session.confirmComparison()
        await o.transport.showProof(Data(count: 64))
        do { _ = try await o.session.current(); XCTFail() } catch {}
        let commits = await o.root.commits; XCTAssertEqual(commits, 0); await o.session.close()
    }
}
