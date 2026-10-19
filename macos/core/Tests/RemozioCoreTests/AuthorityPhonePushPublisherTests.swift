import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityPhonePushPublisherTests: XCTestCase, @unchecked Sendable {
    private final class Clock: Sendable {
        let epoch: UUID
        let value = Mutex<UInt64>(100)
        init(_ epoch: UUID) { self.epoch = epoch }
        func now() -> AuthorityMoment { .init(epoch: epoch, milliseconds: value.withLock { $0 }) }
        func wall() -> UInt64 { 900 + value.withLock { $0 } }
        func advance(_ amount: UInt64) { value.withLock { $0 += amount } }
    }
    private actor Provider {
        var challenges: [PushTokenChallenge] = []
        func probe(_ probe: FCMTokenProbe) -> FCMDeliveryResult { challenges.append(probe.payload); return .accepted }
    }
    private final class Driver: GatewayRootDriver {
        struct State {
            var probes = 0
            var candidates = 0
            var activations = 0
            var mappedReplies = 0
            var lastMappedCandidate: Data?
            var mappedCandidates: Set<Data> = []
            var closed = false
            var rejectMappingQuery = false
            var mappingQueries = 0
            var rejectedCandidateCalls = 0
            var rejectedActivationCalls = 0
            var dropActivationReply = false
            var tamperHeadSignature = false
            var rejectedPhones: Set<Data> = []
            var onCandidate: (@Sendable () throws -> Void)?
        }
        let state = Mutex(State())
        let coordinator: GatewayDeliveryCoordinator
        let lease: GatewayAuthorityLease
        let receiptKey: P256.Signing.PrivateKey
        init(coordinator: GatewayDeliveryCoordinator, lease: GatewayAuthorityLease, key: P256.Signing.PrivateKey) {
            self.coordinator = coordinator; self.lease = lease; receiptKey = key
        }
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: GatewayRootCall, reply: @escaping @Sendable (GatewayRootResponse) -> Void) {
            Task {
                do {
                    switch call {
                    case .hello: reply(.version(3))
                    case .synchronize(let bytes):
                        try await coordinator.synchronizeHost(GatewayHostSnapshot.decode(bytes), lease: lease)
                        reply(.synchronized(true))
                    case .command(let bytes):
                        switch try GatewayRootCommand.decode(bytes) {
                        case .head(let query):
                            if GatewayMappingStateWire.isQuery(query) {
                                state.withLock { $0.mappingQueries += 1 }
                                if state.withLock({ $0.rejectMappingQuery }) { return reply(.command(nil)) }
                                let value = try await coordinator.mappingStateReply(canonicalQuery: query) { try self.receiptKey.signature(for: $0).rawRepresentation }
                                let fields = try GatewayMappingStateWire.fields(value.canonicalPayload, kind: 5, last: 10, limits: GatewayMappingStateWire.replyLimits)
                                if fields[8] == .unsigned(1), case .bytes(let candidate) = fields[6] {
                                    state.withLock { $0.mappedReplies += 1; $0.lastMappedCandidate = candidate; _ = $0.mappedCandidates.insert(candidate) }
                                }
                                reply(.command(try GatewayRootCommand.reply([.bytes(value.canonicalPayload), .bytes(value.signature)])))
                            } else {
                                let value = try await coordinator.recoveryHeadReply(canonicalQuery: query) { try self.receiptKey.signature(for: $0).rawRepresentation }
                                let signature = state.withLock { $0.tamperHeadSignature } ? Data(repeating: 0, count: 64) : value.signature
                                reply(.command(try GatewayRootCommand.reply([.bytes(value.canonicalPayload), .bytes(signature)])))
                            }
                        case .candidate(let payload, let signature, let version, let phone, let token):
                            if state.withLock({ $0.rejectedPhones.contains(phone) }) { return reply(.command(nil)) }
                            let rejected = state.withLock { state in
                                guard state.rejectedCandidateCalls > 0 else { return false }
                                state.rejectedCandidateCalls -= 1; return true
                            }
                            if rejected { return reply(.command(nil)) }
                            let value = try await coordinator.admitCandidate(canonicalPayload: payload, signature: signature, wireVersion: version, registrationToken: token, phoneID: phone)
                            let hook = state.withLock { state in state.candidates += 1; let hook = state.onCandidate; state.onCandidate = nil; return hook }
                            try hook?()
                            reply(.command(try GatewayRootCommand.reply([.bytes(value.receipt.canonicalPayload), .bytes(value.receipt.signature), .boolean(value.inserted)])))
                        case .recipient(let payload, let signature, let version, let phone, let kind):
                            let rejected = state.withLock { state in
                                guard state.rejectedActivationCalls > 0 else { return false }
                                state.rejectedActivationCalls -= 1; return true
                            }
                            if rejected { return reply(.command(nil)) }
                            let value = try await coordinator.applyRecipient(canonicalPayload: payload, signature: signature, wireVersion: version, kind: kind, phoneID: phone)
                            let drop = state.withLock { state in
                                state.activations += 1
                                let drop = state.dropActivationReply; state.dropActivationReply = false; return drop
                            }
                            if drop { return reply(.command(nil)) }
                            reply(.command(try GatewayRootCommand.reply([.bytes(value.receipt.canonicalPayload), .bytes(value.receipt.signature), .boolean(value.inserted)])))
                        case .probe(let operation, let phone):
                            state.withLock { $0.probes += 1 }
                            try await coordinator.startProbe(operationID: operation, phoneID: phone)
                            reply(.command(try GatewayRootCommand.reply([.boolean(true)])))
                        default: reply(.command(nil))
                        }
                    }
                } catch { reply(.command(nil)) }
            }
        }
        func close() { state.withLock { $0.closed = true }; lease.retire() }
    }
    private enum EarlierControl: CaseIterable { case phoneRevocation, submissionRotation, submissionRevocation }
    private final class Fixture: @unchecked Sendable {
        let root: AuthorityPhonePushRegistrationTests.Harness
        let clock: Clock
        let journal: AuthorityJournal
        let provider = Provider()
        let coordinator: GatewayDeliveryCoordinator
        let earlierControl: GatewayAuthorityEnvelope?
        let driver: Driver
        let publisher: AuthorityWakePublisher
        let phonePushConfiguration: AuthorityPhonePushPublication
        init(enrollmentCount: Int = 1, maximumPhonesPerTurn: Int = 16, earlier: EarlierControl? = nil, candidateBeforeEarlier: Bool = false,
             enablePhonePush: Bool = true) throws {
            var retained: GatewayAuthorityEnvelope?
            let root = try AuthorityPhonePushRegistrationTests.Harness(enrollmentCount: enrollmentCount, gatewaySetup: { tx, r, key, limits, epoch, writer in
                guard let earlier else { return }
                let now = AuthorityMoment(epoch: epoch, milliseconds: 100)
                if candidateBeforeEarlier {
                    _ = try tx.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: Data(repeating: 5, count: 16),
                        authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16), registration: r, registrationActive: true,
                        expectedTrustRevision: tx.approvalTrustSnapshot().revision, expectedHead: 0, nowUnixMillis: 1000, now: now,
                        sign: { try key.signature(for: GatewayTokenCandidateSigningInput.make(wireVersion: 1,
                            canonicalPayload: $0.encode(limits: limits), payloadLimits: limits, inputLimits: limits)).rawRepresentation })
                }
                let head = try tx.gatewayAuthorityHead(r)
                switch earlier {
                case .phoneRevocation:
                    let gateway = EnrollmentGatewayRemoval(registration: r, expectedHead: head, nowUnixMillis: 1000, now: now,
                        sign: { try key.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .phoneRevocation,
                            canonicalPayload: $0.encode(limits: limits), payloadLimits: limits, inputLimits: limits)).rawRepresentation })
                    retained = try tx.revokeApprovalEnrollment(phoneID: Data(repeating: 15, count: 16), epoch: Data(repeating: 19, count: 16),
                        expectedTrustRevision: tx.approvalTrustSnapshot().revision, eventID: Data(repeating: 90, count: 16), receiptTimeMs: 1000,
                        writer: writer, expectedAuditHead: UInt64(enrollmentCount), gateway: gateway).gatewayControl
                case .submissionRotation, .submissionRevocation:
                    _ = try tx.installCodePolicy(AuthorityCodePolicy(entries: [
                        AuthorityCodeEntry(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
                            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 3, count: 20), active: true)
                    ]), expectedRevision: nil)
                    try tx.installCommandSubmissionReplay()
                    try tx.installGatewaySubmissionHistory(r)
                    let sign: (GatewaySubmissionControl) throws -> Data = {
                        try key.signature(for: GatewaySubmissionSigningInput.make(wireVersion: 1, kind: $0.kind,
                            canonicalPayload: $0.encode(limits: limits), payloadLimits: limits, inputLimits: limits)).rawRepresentation
                    }
                    if earlier == .submissionRotation {
                        retained = try tx.rotateGatewaySubmission(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                            registration: r, registrationActive: true, expectedHead: head, nowUnixMillis: 1000, now: now, sign: sign)
                    } else {
                        retained = try tx.revokeGatewaySubmission(credentialID: Data(repeating: 80, count: 16),
                            registration: r, registrationActive: true, expectedHead: head, nowUnixMillis: 1000, now: now, sign: sign)
                    }
                }
            }); self.root = root; earlierControl = retained
            let clock = Clock(root.clock); self.clock = clock
            let journal = AuthorityJournal(requests: root.owner); self.journal = journal
            let directory = root.root.appendingPathComponent("gateway")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "gateway.sqlite"] {
                let fd = Darwin.open(directory.appendingPathComponent(name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }; Darwin.close(fd)
            }
            let db = try GatewayDatabase(lease: ProtectedGatewayLease(anchor: root.root.path, relativeDirectory: "gateway", serviceUID: getuid(), ancestorUID: getuid()),
                identity: root.registration, payloadLimits: root.limits, signingLimits: root.limits, maximumOperations: 30,
                maximumPendingPerEnrollment: 5, maximumLifetimeMillis: 1000, clockEpoch: clock.epoch, busyMilliseconds: 100, initialize: true,
                probePolicy: GatewayProbePolicy(maximumAttempts: 3, minimumRetryDelayMillis: 50, maximumTTLSeconds: 60))
            let lease = try GatewayAuthorityLease(epoch: clock.epoch, maximumLifetime: 1000, sample: { clock.now() })
            let tokens = try FCMTokenSource(now: { .now }, refresh: { FCMTokenLease(value: try FCMAccessToken("synthetic"), expiresAt: .now.advanced(by: .seconds(3600))) })
            let provider = provider
            let coordinator = try GatewayDeliveryCoordinator(database: db, identity: root.registration, tokens: tokens,
                policy: GatewayDeliveryPolicy(maximumFlights: 2, minimumSendIntervalMillis: 1, retryBaseDelayMillis: 1, maximumRetryBackoffMillis: 1),
                sample: { .init(wall: clock.wall(), moment: clock.now()) }, sleep: { clock.advance($0) },
                send: { probe, _ in await provider.probe(probe) },
                wakePolicy: GatewayWakePolicy(maximumEntries: 8, maximumAttempts: 1, minimumEnrollmentIntervalMillis: 1, maximumLifetimeMillis: 5000, maximumTTLSeconds: 60),
                sendWake: { _, _ in .registrationInvalid }, validateAuthority: { try lease.validate() })
            self.coordinator = coordinator
            let key = P256.Signing.PrivateKey(), driver = Driver(coordinator: coordinator, lease: lease, key: key)
            self.driver = driver
            let configuration = try AuthorityPhonePushPublication(provider: root.provider, gatewayPublicKey: key.publicKey.x963Representation, maximumPhonesPerTurn: maximumPhonesPerTurn, wallTime: { clock.wall() })
            phonePushConfiguration = configuration
            publisher = try AuthorityWakePublisher(journal: journal, channel: GatewayRootChannel(driver: driver), registration: root.registration,
                leaseMilliseconds: 1000, clock: { clock.now() }, routing: {
                    var router = PresenceRouter(configuration: try PresenceConfiguration(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 100))
                    return router.evaluate(mode: .away, snapshot: PresenceSnapshot(), now: PresenceMoment(epoch: clock.epoch, milliseconds: clock.now().milliseconds))
                }, phonePush: enablePhonePush ? configuration : nil)
        }
        func offer(phoneIndex: Int = 0) throws -> PhonePushRegistrationMetadata {
            try journal.withRequests { _ in
                guard case .prepared(_, let metadata) = try root.exchange(root.offer(), time: clock.now().milliseconds, binding: root.bindings[phoneIndex]) else { throw CocoaError(.fileReadUnknown) }
                return metadata
            }
        }
        func prove(_ metadata: PhonePushRegistrationMetadata, challenge: PushTokenChallenge, phoneIndex: Int = 0) throws {
            try journal.withRequests { _ in
                let frame = PhonePushRegistrationFrame.proof(correlationID: Data(repeating: 99, count: 16), proof: try metadata.proof(challenge))
                guard case .outcome(_, .proofCommitted) = try root.exchange(frame, time: clock.now().milliseconds, binding: root.bindings[phoneIndex]) else { throw CocoaError(.fileReadUnknown) }
            }
        }
        func state() throws -> GatewayCurrentTokenState? {
            try journal.withRequests { owner in
                try owner.currentPhonePushRegistration(root.provider, phoneID: Data(repeating: 5, count: 16), enrollmentEpoch: Data(repeating: 9, count: 16), now: clock.now(), wall: clock.wall())
            }
        }
        func assertGatewayHead(_ expected: UInt64, file: StaticString = #filePath, line: UInt = #line) async throws {
            let key = driver.receiptKey
            let owner = try GatewayHeadQueryOwner(registration: root.registration, gatewayPublicKey: key.publicKey.x963Representation,
                clockEpoch: clock.epoch, lifetimeMillis: 500)
            let reply = try await coordinator.recoveryHeadReply(canonicalQuery: owner.makeQuery(now: clock.now()),
                sign: { try key.signature(for: $0).rawRepresentation })
            XCTAssertEqual(try owner.accept(reply, now: clock.now()).evidence.revision, expected, file: file, line: line)
        }
        func recoveryState() throws -> PhonePushRecoveryState {
            try journal.withRequests { owner in
                let request = PhonePushRecoveryFrame.resume(correlationID: Data(repeating: 98, count: 16),
                    offer: try PhonePushTokenOffer(token: "synthetic-token", projectID: "project", senderID: "123", packageName: "dev.remozio.android"))
                guard case .state(_, let state) = try owner.phonePushRecovery(request, binding: root.binding, provider: root.provider,
                    now: clock.now(), wall: clock.wall(), validateTransport: { _ in }) else { throw CocoaError(.fileReadUnknown) }
                return state
            }
        }
        func publishEarlierControl() async throws {
            let control = try XCTUnwrap(earlierControl)
            if control.kind == 3 {
                let applied = try await coordinator.applyRecipient(canonicalPayload: control.canonicalPayload, signature: control.signature,
                    wireVersion: 1, kind: .phoneRevocation, phoneID: Data(repeating: 15, count: 16))
                XCTAssertTrue(applied.inserted)
                XCTAssertEqual(applied.receipt.canonicalPayload, control.canonicalPayload)
            } else {
                _ = try await coordinator.applySubmission(canonicalPayload: control.canonicalPayload, signature: control.signature, wireVersion: 1)
            }
        }
        func close() async { await publisher.close(); try? await coordinator.shutdown(); try? journal.close() }
    }
    private func waitFor(_ condition: () async -> Bool) async throws {
        for _ in 0..<1000 { if await condition() { return }; try await Task.sleep(for: .milliseconds(1)) }
        XCTFail("Fixture did not settle"); throw CocoaError(.featureUnsupported)
    }
    func testLiveProviderInstallationKeepsThePublisherSessionAndCompletesTheExistingCandidate() async throws {
        let f = try Fixture(enablePhonePush: false), digest = Data(repeating: 91, count: 32)
        let metadata = try f.offer(), before = try f.root.store.read()
        try await f.publisher.start(); try await f.publisher.reconcile()
        let disabled = await f.publisher.phonePushDiagnostic; XCTAssertEqual(disabled, .disabled)
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 0)
        let installed = try await f.publisher.installPhonePush(f.phonePushConfiguration, configurationDigest: digest)
        XCTAssertTrue(installed); XCTAssertEqual(try f.root.store.read(), before)
        try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        let challenge = await f.provider.challenges[0]
        XCTAssertEqual(challenge.candidateID, metadata.candidateID)
        try f.prove(metadata, challenge: challenge); try await f.publisher.reconcile()
        XCTAssertGreaterThan(f.driver.state.withLock { $0.mappedReplies }, 0)
        XCTAssertEqual(try f.recoveryState().phase, .mappingObserved)
        XCTAssertFalse(f.driver.state.withLock { $0.closed })
        await f.close()
    }
    func testMatchingPublisherInstallationRetainsProbeHistoryAndRejectsReplacement() async throws {
        let f = try Fixture(enablePhonePush: false), digest = Data(repeating: 92, count: 32)
        _ = try f.offer(); try await f.publisher.start()
        _ = try await f.publisher.installPhonePush(f.phonePushConfiguration, configurationDigest: digest)
        try await f.publisher.reconcile(); try await waitFor { await f.provider.challenges.count == 1 }
        let checkpoint = try f.root.store.read()
        let changed = try await f.publisher.installPhonePush(f.phonePushConfiguration, configurationDigest: digest)
        XCTAssertFalse(changed); XCTAssertEqual(try f.root.store.read(), checkpoint)
        try await f.publisher.reconcile(); XCTAssertEqual(f.driver.state.withLock { $0.probes }, 1)
        do {
            _ = try await f.publisher.installPhonePush(f.phonePushConfiguration, configurationDigest: Data(repeating: 93, count: 32)); XCTFail()
        } catch { XCTAssertEqual(error as? GatewayPreparationError, .changedScope) }
        await f.close()
        do { _ = try await f.publisher.installPhonePush(f.phonePushConfiguration, configurationDigest: digest); XCTFail() }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
    }
    private static func didEnter(_ semaphore: DispatchSemaphore) -> Bool { semaphore.wait(timeout: .now() + 5) == .success }
    func testProviderInstallationRefusesAnInFlightPublicationTurn() async throws {
        let f = try Fixture(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        _ = try f.offer(); try await f.publisher.start()
        f.driver.state.withLock { $0.onCandidate = {
            entered.signal()
            guard release.wait(timeout: .now() + 5) == .success else { throw CocoaError(.featureUnsupported) }
        } }
        let turn = Task { try await f.publisher.reconcile() }
        let reached = await Task.detached { Self.didEnter(entered) }.value
        XCTAssertTrue(reached)
        do { _ = try await f.publisher.installPhonePush(f.phonePushConfiguration, configurationDigest: Data(repeating: 94, count: 32)); XCTFail() }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .busy) }
        release.signal(); try await turn.value
        XCTAssertFalse(f.driver.state.withLock { $0.closed }); await f.close()
    }
    func testRegistrationWaitsForEveryEarlierNonRegistrationControl() async throws {
        for kind in EarlierControl.allCases {
            let f = try Fixture(enrollmentCount: 2, maximumPhonesPerTurn: 1, earlier: kind)
            let metadata = try f.offer(), control = try XCTUnwrap(f.earlierControl)
            try await f.publisher.start()
            try await f.publisher.reconcile(); try await f.publisher.reconcile()
            XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 0, "Registration skipped \(kind)")
            XCTAssertEqual(f.driver.state.withLock { $0.probes }, 0)
            try await f.assertGatewayHead(0)
            let diagnostic = await f.publisher.phonePushDiagnostic
            XCTAssertEqual(diagnostic, .retryPending)
            try await f.publishEarlierControl()
            try await f.assertGatewayHead(control.revision)
            try await f.publisher.reconcile(); try await f.publisher.reconcile()
            try await waitFor { await f.provider.challenges.count == 1 }
            let challenge = await f.provider.challenges[0]
            XCTAssertEqual(challenge.candidateID, metadata.candidateID)
            try await f.assertGatewayHead(control.revision + 1)
            try f.prove(metadata, challenge: await f.provider.challenges[0])
            try await f.publisher.reconcile()
            XCTAssertGreaterThan(f.driver.state.withLock { $0.mappedReplies }, 0)
            await f.close()
        }
    }
    func testControlBetweenCandidateAndProofBlocksOnlyTheLaterActivation() async throws {
        for kind in EarlierControl.allCases {
            let f = try Fixture(enrollmentCount: 2, earlier: kind, candidateBeforeEarlier: true)
            let retained = try XCTUnwrap(f.state()), control = try XCTUnwrap(f.earlierControl)
            let candidate = try GatewayTokenCandidate.decode(retained.candidate.canonicalPayload, limits: f.root.limits)
            let metadata = try PhonePushRegistrationMetadata(candidate)
            try await f.publisher.start(); try await f.publisher.reconcile()
            try await waitFor { await f.provider.challenges.count == 1 }
            try await f.assertGatewayHead(candidate.revision)
            try f.prove(metadata, challenge: await f.provider.challenges[0])
            try await f.publisher.reconcile(); try await f.publisher.reconcile()
            XCTAssertEqual(f.driver.state.withLock { $0.activations }, 0)
            try await f.assertGatewayHead(candidate.revision)
            let diagnostic = await f.publisher.phonePushDiagnostic
            XCTAssertEqual(diagnostic, .retryPending)
            try await f.publishEarlierControl()
            try await f.assertGatewayHead(control.revision)
            try await f.publisher.reconcile()
            XCTAssertEqual(f.driver.state.withLock { $0.activations }, 1)
            XCTAssertGreaterThan(f.driver.state.withLock { $0.mappedReplies }, 0)
            await f.close()
        }
    }
    func testExpiredNonRegistrationControlsStillBlockLaterRegistration() async throws {
        for kind in EarlierControl.allCases {
            let f = try Fixture(enrollmentCount: 2, earlier: kind)
            f.clock.advance(1001)
            let metadata = try f.offer()
            try await f.publisher.start()
            try await f.publisher.reconcile(); try await f.publisher.reconcile()
            try await f.assertGatewayHead(0)
            XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 0)
            XCTAssertEqual(f.driver.state.withLock { $0.probes }, 0)
            XCTAssertEqual(try f.state()?.candidate.operationID, metadata.operationID)
            let diagnostic = await f.publisher.phonePushDiagnostic
            XCTAssertEqual(diagnostic, .retryPending)
            await f.close()
        }
    }
    func testCandidateProbeProofAndActivationUseTheSingleRootChannel() async throws {
        let f = try Fixture(), metadata = try f.offer()
        try await f.publisher.start(); try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        let challenge = await f.provider.challenges[0]
        XCTAssertEqual(challenge.candidateID, metadata.candidateID)
        try f.prove(metadata, challenge: challenge)
        try await f.publisher.reconcile(); try await f.publisher.reconcile()
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 1)
        XCTAssertNotNil(try f.state()?.activation)
        XCTAssertEqual(f.driver.state.withLock { $0.activations }, 1)
        XCTAssertGreaterThan(f.driver.state.withLock { $0.mappedReplies }, 0)
        XCTAssertEqual(try f.recoveryState().phase, .mappingObserved)
        let before = try f.root.store.read()
        try await f.publisher.reconcile()
        XCTAssertEqual(try f.root.store.read(), before)
        let mappedBeforeExpiry = f.driver.state.withLock { $0.mappedReplies }
        f.clock.advance(1100)
        try await f.publisher.reconcile()
        XCTAssertGreaterThan(f.driver.state.withLock { $0.mappedReplies }, mappedBeforeExpiry)
        XCTAssertEqual(try f.state()?.candidate.operationID, metadata.operationID)
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 1)
        XCTAssertEqual(try f.recoveryState().phase, .mappingObserved)
        await f.publisher.close()
        XCTAssertEqual(try f.recoveryState().phase, .proofCommitted)
        await f.close()
    }
    func testProviderInvalidationRepairsWithFreshProofAndRetainsPairing() async throws {
        let f = try Fixture(), metadata = try f.offer()
        try await f.publisher.start(); try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        try f.prove(metadata, challenge: await f.provider.challenges[0])
        try await f.publisher.reconcile(); try await f.publisher.reconcile()
        XCTAssertEqual(f.driver.state.withLock { $0.lastMappedCandidate }, metadata.candidateID)
        let enrollment = try f.journal.withRequests { try XCTUnwrap($0.wakeDeliveryTrust().enrollments.first) }
        let now = f.clock.now()
        let delivery = PhoneRequestDelivery(id: UUID(), recipient: DeliveryRecipient(enrollment), requestID: Data(repeating: 70, count: 16),
            admittedAt: now, deadlineMilliseconds: now.milliseconds + 500)
        _ = try await f.coordinator.enqueueWake(delivery)
        _ = try await f.coordinator.deliverWakeBatch(phoneID: enrollment.approval.phoneID, enrollmentEpoch: enrollment.epoch)
        try await f.publisher.reconcile()
        let repaired = try XCTUnwrap(f.state())
        XCTAssertNil(repaired.activation)
        let candidate = try GatewayTokenCandidate.decode(repaired.candidate.canonicalPayload, limits: f.root.limits)
        XCTAssertNotEqual(candidate.binding.candidateID, metadata.candidateID)
        XCTAssertEqual(candidate.binding.enrollmentEpoch, metadata.enrollmentEpoch)
        XCTAssertEqual(candidate.binding.enrollmentTag, metadata.enrollmentTag)
        XCTAssertEqual(candidate.binding.tokenDigest, metadata.tokenDigest)
        let freshMetadata = try PhonePushRegistrationMetadata(candidate)
        try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 2 }
        try f.prove(freshMetadata, challenge: await f.provider.challenges[1])
        try await f.publisher.reconcile()
        XCTAssertEqual(f.driver.state.withLock { $0.lastMappedCandidate }, candidate.binding.candidateID)
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 2)
        await f.close()
    }

    func testSupersededCandidateCannotStartAProbeAfterTheReply() async throws {
        let f = try Fixture(); _ = try f.offer()
        f.driver.state.withLock { $0.onCandidate = { _ = try f.offer() } }
        try await f.publisher.start(); try await f.publisher.reconcile()
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 0)
        try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 1)
        await f.close()
    }
    func testExpiredProbeWaitsForThePhoneWithoutFillingRetainedHistory() async throws {
        let f = try Fixture(), metadata = try f.offer()
        try await f.publisher.start(); try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        f.clock.advance(1100)
        try await f.publisher.reconcile()
        let head = try f.root.head, checkpoint = try f.root.store.read()
        for _ in 0..<40 {
            f.clock.advance(1100)
            try await f.publisher.reconcile()
        }
        XCTAssertEqual(try f.root.head, head)
        XCTAssertEqual(try f.root.store.read(), checkpoint)
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 1)
        XCTAssertEqual(try f.state()?.candidate.operationID, metadata.operationID)
        let fresh = try f.offer()
        XCTAssertEqual(fresh.enrollmentEpoch, metadata.enrollmentEpoch)
        XCTAssertNotEqual(fresh.candidateID, metadata.candidateID)
        try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 2 }
        XCTAssertFalse(f.root.owner.retired)
        await f.close()
    }
    func testThreePhonesProgressAcrossBoundedTurnsWithoutRepeatedProbes() async throws {
        let f = try Fixture(enrollmentCount: 3, maximumPhonesPerTurn: 1)
        let metadata = try (0..<3).map { try f.offer(phoneIndex: $0) }
        try await f.publisher.start()
        for expected in 1...3 {
            try await f.publisher.reconcile()
            try await waitFor { await f.provider.challenges.count == expected }
            XCTAssertEqual(f.driver.state.withLock { $0.probes }, expected)
        }
        let challenges = await f.provider.challenges
        XCTAssertEqual(Set(challenges.map(\.candidateID)), Set(metadata.map(\.candidateID)))
        for _ in 0..<6 { try await f.publisher.reconcile() }
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 3)
        XCTAssertFalse(f.root.owner.retired)
        await f.close()
    }
    func testTransientCandidateRejectionPreservesAllPhonesAndOriginalOffers() async throws {
        let f = try Fixture(enrollmentCount: 3, maximumPhonesPerTurn: 1)
        let metadata = try (0..<3).map { try f.offer(phoneIndex: $0) }
        let head = try f.root.head
        f.driver.state.withLock { $0.rejectedCandidateCalls = 1 }
        try await f.publisher.start()
        for _ in 0..<8 { try await f.publisher.reconcile() }
        try await waitFor { await f.provider.challenges.count == 3 }
        let challenges = await f.provider.challenges
        XCTAssertEqual(Set(challenges.map(\.candidateID)), Set(metadata.map(\.candidateID)))
        XCTAssertEqual(try f.root.head, head)
        XCTAssertFalse(f.driver.state.withLock { $0.closed })
        XCTAssertFalse(f.root.owner.retired)
        await f.close()
    }
    func testExpiredLeaseAfterCandidateReplyStopsPublicationAndClosesTheChannel() async throws {
        let f = try Fixture(); _ = try f.offer()
        f.driver.state.withLock { $0.onCandidate = { f.clock.advance(1000) } }
        try await f.publisher.start()
        do { try await f.publisher.reconcile(); XCTFail("Expired lease was accepted") }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .expiredLease) }
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 0)
        XCTAssertTrue(f.driver.state.withLock { $0.closed })
        XCTAssertFalse(f.root.owner.retired)
        await f.close()
    }
    func testRetiredOwnerAfterCandidateReplyCannotStartAProbe() async throws {
        let f = try Fixture(); _ = try f.offer()
        f.driver.state.withLock { $0.onCandidate = { try f.journal.withRequests { $0.close() } } }
        try await f.publisher.start()
        do { try await f.publisher.reconcile(); XCTFail("Retired owner was accepted") } catch {}
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 0)
        XCTAssertTrue(f.driver.state.withLock { $0.closed })
        XCTAssertTrue(f.root.owner.retired)
        await f.close()
    }
    func testInvalidGatewayHeadCannotPublishAndDoesNotRetireHealthyRoot() async throws {
        let f = try Fixture(); _ = try f.offer()
        f.driver.state.withLock { $0.tamperHeadSignature = true }
        try await f.publisher.start(); try await f.publisher.reconcile()
        XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 0)
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 0)
        XCTAssertFalse(f.driver.state.withLock { $0.closed })
        XCTAssertFalse(f.root.owner.retired)
        let failedDiagnostic = await f.publisher.phonePushDiagnostic
        XCTAssertEqual(failedDiagnostic, .retryPending)
        f.driver.state.withLock { $0.tamperHeadSignature = false }
        try await f.publisher.reconcile()
        let recoveredDiagnostic = await f.publisher.phonePushDiagnostic
        XCTAssertEqual(recoveredDiagnostic, .turnCompleted)
        try await waitFor { await f.provider.challenges.count == 1 }
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 1)
        await f.close()
    }
    func testCandidateOfferOrderDoesNotDependOnEnrollmentCursorOrder() async throws {
        for (count, budget) in [(2, 1), (3, 2)] {
            let f = try Fixture(enrollmentCount: count, maximumPhonesPerTurn: budget)
            let phones = try f.journal.withRequests { try $0.wakeDeliveryTrust().enrollments.map { $0.approval.phoneID } }
            let order = try phones.map { phone in try XCTUnwrap(f.root.bindings.firstIndex { $0.scope.phoneID == phone }) }
            let metadata = try order.reversed().map { try f.offer(phoneIndex: $0) }
            let head = try f.root.head
            try await f.publisher.start()
            for _ in 0..<(count + 3) { try await f.publisher.reconcile() }
            try await waitFor { await f.provider.challenges.count == count }
            let challenges = await f.provider.challenges
            XCTAssertEqual(Set(challenges.map(\.candidateID)), Set(metadata.map(\.candidateID)))
            XCTAssertEqual(try f.root.head, head)
            XCTAssertEqual(f.driver.state.withLock { $0.probes }, count)
            await f.close()
        }
    }
    func testEarlierCandidatesPublishBeforeActivationAtTheOnePhoneBudget() async throws {
        for count in [2, 3] {
            let f = try Fixture(enrollmentCount: count, maximumPhonesPerTurn: 1)
            let first = try f.offer()
            try await f.publisher.start()
            for _ in 0..<count { try await f.publisher.reconcile() }
            try await waitFor { await f.provider.challenges.count == 1 }
            let others = try (1..<count).map { try f.offer(phoneIndex: $0) }
            try f.prove(first, challenge: await f.provider.challenges[0])
            let head = try f.root.head
            for _ in 0..<8 { try await f.publisher.reconcile() }
            let challenges = await f.provider.challenges
            XCTAssertEqual(Set(challenges.map(\.candidateID)), Set(([first] + others).map(\.candidateID)))
            XCTAssertTrue(f.driver.state.withLock { $0.mappedCandidates.contains(first.candidateID) })
            XCTAssertEqual(try f.root.head, head)
            XCTAssertEqual(f.driver.state.withLock { $0.probes }, count)
            XCTAssertFalse(f.root.owner.retired)
            await f.close()
        }
    }
    func testReversePhoneProofOrderPublishesBothActivationsWithinEitherBudget() async throws {
        for budget in [1, 16] {
            for rejectFirst in [false, true] {
                let f = try Fixture(enrollmentCount: 2, maximumPhonesPerTurn: budget)
                let metadata = try (0..<2).map { try f.offer(phoneIndex: $0) }
                try await f.publisher.start()
                try await f.publisher.reconcile(); try await f.publisher.reconcile()
                try await waitFor { await f.provider.challenges.count == 2 }
                let challenges = await f.provider.challenges
                for index in [1, 0] {
                    let challenge = try XCTUnwrap(challenges.first { $0.candidateID == metadata[index].candidateID })
                    try f.prove(metadata[index], challenge: challenge, phoneIndex: index)
                }
                let head = try f.root.head
                if rejectFirst { f.driver.state.withLock { $0.rejectedActivationCalls = 1 } }
                for _ in 0..<6 { try await f.publisher.reconcile() }
                XCTAssertEqual(f.driver.state.withLock { $0.mappedCandidates }, Set(metadata.map(\.candidateID)))
                XCTAssertEqual(f.driver.state.withLock { $0.probes }, 2)
                XCTAssertEqual(try f.root.head, head)
                XCTAssertFalse(f.root.owner.retired)
                await f.close()
            }
        }
    }
    func testTemporaryMappingQueryRejectionRecoversOnTheSameConnection() async throws {
        let f = try Fixture(), metadata = try f.offer()
        try await f.publisher.start(); try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        try f.prove(metadata, challenge: await f.provider.challenges[0])
        let activation = try XCTUnwrap(f.state()?.activation)
        f.driver.state.withLock { $0.rejectMappingQuery = true }
        try await f.publisher.reconcile()
        f.driver.state.withLock { $0.rejectMappingQuery = false }
        try await f.publisher.reconcile()
        XCTAssertEqual(f.driver.state.withLock { $0.lastMappedCandidate }, metadata.candidateID)
        XCTAssertEqual(try f.state()?.activation?.operationID, activation.operationID)
        XCTAssertFalse(f.driver.state.withLock { $0.closed })
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 1)
        await f.close()
    }
    func testTransientControlRejectionsRetainTheCommittedActivation() async throws {
        for candidateCall in [true, false] {
            let f = try Fixture(), metadata = try f.offer()
            try await f.publisher.start(); try await f.publisher.reconcile()
            try await waitFor { await f.provider.challenges.count == 1 }
            try f.prove(metadata, challenge: await f.provider.challenges[0])
            let original = try XCTUnwrap(f.state()), head = try f.root.head
            f.driver.state.withLock { state in
                if candidateCall { state.rejectedCandidateCalls = 1 }
                else { state.rejectedActivationCalls = 1 }
            }
            try await f.publisher.reconcile()
            XCTAssertEqual(try f.state()?.activation?.operationID, original.activation?.operationID)
            XCTAssertEqual(try f.state()?.candidate.operationID, original.candidate.operationID)
            XCTAssertEqual(try f.root.head, head)
            try await f.publisher.reconcile()
            XCTAssertEqual(f.driver.state.withLock { $0.lastMappedCandidate }, metadata.candidateID)
            XCTAssertEqual(f.driver.state.withLock { $0.probes }, 1)
            await f.close()
        }
    }
    func testLostActivationReplyDoesNotReplaceAnAlreadyMappedActivation() async throws {
        let f = try Fixture(), metadata = try f.offer()
        try await f.publisher.start(); try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        try f.prove(metadata, challenge: await f.provider.challenges[0])
        let original = try XCTUnwrap(f.state()), head = try f.root.head
        f.driver.state.withLock { $0.dropActivationReply = true }
        try await f.publisher.reconcile()
        XCTAssertEqual(try f.state()?.activation?.operationID, original.activation?.operationID)
        XCTAssertEqual(try f.root.head, head)
        try await f.publisher.reconcile()
        XCTAssertEqual(f.driver.state.withLock { $0.lastMappedCandidate }, metadata.candidateID)
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 1)
        await f.close()
    }
    func testExpiredUnappliedActivationRequiresFreshAbsenceBeforeRenewal() async throws {
        let f = try Fixture(), metadata = try f.offer()
        try await f.publisher.start(); try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        try f.prove(metadata, challenge: await f.provider.challenges[0])
        f.clock.advance(1100)
        try await f.publisher.reconcile()
        let replacement = try XCTUnwrap(f.state())
        XCTAssertNil(replacement.activation)
        XCTAssertNotEqual(replacement.candidate.operationID, metadata.operationID)
        XCTAssertEqual(f.driver.state.withLock { $0.mappingQueries }, 2)
        await f.close()
    }
    func testLegacyMappingQueryRejectionKeepsTheControlConnection() async throws {
        let f = try Fixture(), metadata = try f.offer()
        try await f.publisher.start(); try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        try f.prove(metadata, challenge: await f.provider.challenges[0])
        f.driver.state.withLock { $0.rejectMappingQuery = true }
        try await f.publisher.reconcile(); try await f.publisher.reconcile()
        let diagnostic = await f.publisher.phonePushDiagnostic
        XCTAssertEqual(diagnostic, .retryPending)
        XCTAssertEqual(f.driver.state.withLock { $0.mappingQueries }, 2)
        XCTAssertFalse(f.driver.state.withLock { $0.closed })
        XCTAssertFalse(f.root.owner.retired)
        await f.close()
    }
}
