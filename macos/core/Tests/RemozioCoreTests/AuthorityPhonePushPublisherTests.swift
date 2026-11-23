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
            var rejectedRevocationCalls = 0
            var revocations = 0
            var rejectRecoveryProbe = false
            var recoveryProbes = 0
            var rejectTombstoneProbe = false
            var dropTombstoneReply = false
            var tombstoneCalls = 0
            var tombstones: [GatewayControlTombstone] = []
            var recoveredBytes: Data?
            var recoveredSignature: Data?
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
                            if query == GatewayRootCommand.phoneRevocationRecoveryProbe {
                                let rejected = state.withLock { state in
                                    state.recoveryProbes += 1
                                    return state.rejectRecoveryProbe
                                }
                                if rejected { return reply(.command(nil)) }
                                let registration = try await coordinator.phoneRevocationRecoveryRegistration(lease: lease)
                                reply(.command(try GatewayRootCommand.reply([.unsigned(1), .bytes(registration.encode())])))
                            } else if query == GatewayRootCommand.abandonGrantProbe {
                                if state.withLock({ $0.rejectTombstoneProbe }) { return reply(.command(nil)) }
                                let registration = try await coordinator.phoneRevocationRecoveryRegistration(lease: lease)
                                reply(.command(try GatewayRootCommand.reply([.unsigned(1), .bytes(registration.encode())])))
                            } else if GatewayMappingStateWire.isQuery(query) {
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
                        case .history(let query):
                            let value = try await coordinator.recoveryHistoryReply(canonicalQuery: query) { try self.receiptKey.signature(for: $0).rawRepresentation }
                            reply(.command(try GatewayRootCommand.reply([.bytes(value.canonicalPayload), .bytes(value.signature)])))
                        case .abandonGrant(let payload, let signature, let expectedHead):
                            let drop = state.withLock {
                                $0.tombstoneCalls += 1
                                return $0.dropTombstoneReply
                            }
                            if drop { return reply(.command(nil)) }
                            let value = try await coordinator.abandonGrant(canonicalPayload: payload, signature: signature,
                                expectedHead: expectedHead, lease: lease)
                            if value.inserted { state.withLock { $0.tombstones.append(value.receipt.tombstone) } }
                            reply(.command(try GatewayRootCommand.reply([.bytes(value.receipt.canonicalPayload), .bytes(value.receipt.signature), .boolean(value.inserted)])))
                        case .recoverPhoneRevocation(let payload, let signature, let phone, let expectedHead):
                            let rejected = state.withLock { state in
                                guard state.rejectedRevocationCalls > 0 else { return false }
                                state.rejectedRevocationCalls -= 1; return true
                            }
                            if rejected { return reply(.command(nil)) }
                            let value = try await coordinator.recoverPhoneRevocation(canonicalPayload: payload, signature: signature,
                                phoneID: phone, expectedHead: expectedHead, lease: lease)
                            state.withLock {
                                $0.revocations += 1; $0.recoveredBytes = payload; $0.recoveredSignature = signature
                            }
                            reply(.command(try GatewayRootCommand.reply([.bytes(value.receipt.canonicalPayload), .bytes(value.receipt.signature), .boolean(value.inserted)])))
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
        let revocationState: AuthorityGatewayRevocationState
        let phonePushConfiguration: AuthorityPhonePushPublication
        init(enrollmentCount: Int = 1, maximumPhonesPerTurn: Int = 16, earlier: EarlierControl? = nil, candidateBeforeEarlier: Bool = false,
             enablePhonePush: Bool = true, enableRootGateway: Bool = true, prepareRetirementSchema: Bool = false,
             phonePushSource: (@Sendable () -> AuthorityPhonePushPublication?)? = nil,
             beforePublisherSigns: (@Sendable (Clock) -> Void)? = nil) throws {
            var retained: GatewayAuthorityEnvelope?
            let root = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: enableRootGateway, enrollmentCount: enrollmentCount,
                gatewayLedgerEnabled: enableRootGateway, gatewaySetup: { tx, r, key, limits, epoch, writer in
                if prepareRetirementSchema || earlier == .submissionRotation || earlier == .submissionRevocation {
                    _ = try tx.installCodePolicy(AuthorityCodePolicy(entries: [
                        AuthorityCodeEntry(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.authority",
                            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 3, count: 20), active: true)
                    ]), expectedRevision: nil)
                }
                guard let earlier else { return }
                let now = AuthorityMoment(epoch: epoch, milliseconds: 100)
                if candidateBeforeEarlier {
                    let other = earlier == .phoneRevocation && enrollmentCount > 1
                    _ = try tx.prepareGatewayCandidate(registrationToken: "synthetic-token",
                        authenticatedPhoneID: Data(repeating: other ? 15 : 5, count: 16),
                        authenticatedEnrollmentEpoch: Data(repeating: other ? 19 : 9, count: 16), registration: r, registrationActive: true,
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
                    let phone = UInt8(enrollmentCount == 1 ? 5 : 15), epoch = UInt8(enrollmentCount == 1 ? 9 : 19)
                    retained = try tx.revokeApprovalEnrollment(phoneID: Data(repeating: phone, count: 16), epoch: Data(repeating: epoch, count: 16),
                        expectedTrustRevision: tx.approvalTrustSnapshot().revision, eventID: Data(repeating: 90, count: 16), receiptTimeMs: 1000,
                        writer: writer, expectedAuditHead: UInt64(enrollmentCount), gateway: gateway).gatewayControl
                case .submissionRotation, .submissionRevocation:
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
            let registrationProvider: AuthorityPhonePushRegistration
            if let beforePublisherSigns {
                let rootKey = root.key
                registrationProvider = AuthorityPhonePushRegistration(policy: root.provider.policy, signing: { bytes in
                    beforePublisherSigns(clock)
                    return try rootKey.signature(for: bytes).rawRepresentation
                })
            } else {
                registrationProvider = root.provider
            }
            let configuration = try AuthorityPhonePushPublication(provider: registrationProvider, gatewayPublicKey: key.publicKey.x963Representation, maximumPhonesPerTurn: maximumPhonesPerTurn, wallTime: { clock.wall() })
            phonePushConfiguration = configuration
            revocationState = AuthorityGatewayRevocationState(registration: root.registration)
            publisher = try AuthorityWakePublisher(journal: journal, channel: GatewayRootChannel(driver: driver), registration: root.registration,
                leaseMilliseconds: 1000, clock: { clock.now() }, routing: {
                    var router = PresenceRouter(configuration: try PresenceConfiguration(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 100))
                    return router.evaluate(mode: .away, snapshot: PresenceSnapshot(), now: PresenceMoment(epoch: clock.epoch, milliseconds: clock.now().milliseconds))
                }, phonePush: enablePhonePush ? configuration : nil, phonePushSource: phonePushSource, gatewayRevocations: revocationState)
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
                    offer: try PhonePushTokenOffer(token: "synthetic-token", projectID: "project", senderID: "123", packageName: "dev.sebastiano.remozio.android"))
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
    func testServiceEnablesSuspendsAndRestoresPushOnTheSameForegroundAndGatewayOwners() async throws {
        let slot = Mutex<AuthorityPhonePushCapability?>(nil)
        let f = try Fixture(enablePhonePush: false, enableRootGateway: false, phonePushSource: { slot.withLock { $0?.publication } })
        let cap = AuthorityPhonePushCapability(journal: f.journal, registration: f.root.registration,
            clock: { f.clock.now() }, wall: { f.clock.wall() }, makeProvider: { _ in f.root.provider })
        slot.withLock { $0 = cap }
        let options = try AuthorityPhonePushStartupConfiguration(projectID: "project", senderID: "123", packageName: "dev.sebastiano.remozio.android",
            gatewayReceiptPublicKey: f.driver.receiptKey.publicKey.x963Representation, maximumControls: 30, candidateLifetimeMilliseconds: 1000)
        let service = try AuthorityWakeService(makePublisher: { f.publisher }, hints: AuthorityWakeHintSource(registration: f.root.registration),
            interval: 100, startRequests: {}, closeRequests: {}, phonePushCapability: cap)
        let now = f.clock.now(), contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let draft = ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: Data([0xa0]),
            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
            firstObservedAt: now, deadlineMilliseconds: 1100, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 2000)
        let pending = try f.journal.withRequests { try $0.admitFixture(draft, now: now, receiptTimeMs: 1000) }
        let before = try f.journal.withRequests { try $0.state(requestID: pending.requestID) }
        try await service.start(); try await waitFor { await service.wakeStatus == .running }
        let digest = Data(repeating: 95, count: 32)
        let installed = try await service.installPhonePush(options, commitDigest: digest, verifyCurrent: {})
        XCTAssertTrue(installed)
        let metadata = try f.offer(); try await waitFor { await f.provider.challenges.count == 1 }
        try f.prove(metadata, challenge: await f.provider.challenges[0]); try await waitFor { (try? f.recoveryState().phase) == .mappingObserved }
        XCTAssertGreaterThan(f.driver.state.withLock { $0.mappedReplies }, 0)
        XCTAssertEqual(try f.recoveryState().phase, .mappingObserved)
        await service.suspendPhonePush(); try await waitFor { await f.publisher.phonePushDiagnostic == .disabled }
        XCTAssertNil(cap.publication); XCTAssertFalse(f.driver.state.withLock { $0.closed })
        let handler = cap.registrationProvider(), offer = try f.root.offer()
        guard case .outcome(_, .unavailable) = try f.journal.withRequests({ try handler($0, f.root.binding, offer, { _ in }) }) else { return XCTFail() }
        let restored = try await service.installPhonePush(options, commitDigest: digest, verifyCurrent: {})
        XCTAssertTrue(restored); try await waitFor { await f.publisher.phonePushDiagnostic == .turnCompleted }
        XCTAssertEqual(f.driver.state.withLock { $0.probes }, 1)
        XCTAssertEqual(try f.journal.withRequests { try $0.state(requestID: pending.requestID) }, before)
        XCTAssertTrue(try f.journal.validatePeer(f.root.binding)); let retired = await service.isRetired; XCTAssertFalse(retired)
        try await service.close(); await f.close()
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
        for kind in EarlierControl.allCases where kind != .phoneRevocation {
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
        for kind in EarlierControl.allCases where kind != .phoneRevocation {
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
    func testLiveRevocationRetriesTheSameEnvelopeBeforeLaterRegistration() async throws {
        let f = try Fixture(enrollmentCount: 2, maximumPhonesPerTurn: 1, earlier: .phoneRevocation)
        let control = try XCTUnwrap(f.earlierControl)
        _ = try f.offer()
        f.driver.state.withLock { $0.rejectedRevocationCalls = 1 }
        try await f.publisher.start()
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(0)
        XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 0)
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(control.revision)
        XCTAssertEqual(f.driver.state.withLock { $0.revocations }, 1)
        XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 0)
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(control.revision + 1)
        XCTAssertEqual(f.driver.state.withLock { $0.revocations }, 1)
        XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 1)
        await f.close()
    }

    func testAbandonsRevokedPhonesCandidateBeforeRevocationAndAnotherPhonesGrant() async throws {
        let f = try Fixture(enrollmentCount: 2, earlier: .phoneRevocation, candidateBeforeEarlier: true, prepareRetirementSchema: true)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 13)
        let revocation = try XCTUnwrap(f.earlierControl)
        XCTAssertEqual(revocation.revision, 2)
        _ = try f.offer()
        try await f.publisher.start()
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(1)
        let abandoned = try XCTUnwrap(f.driver.state.withLock { $0.tombstones.first })
        XCTAssertEqual(abandoned.originalKind, .candidate)
        XCTAssertEqual(abandoned.revision, 1)
        XCTAssertNotNil(try f.journal.read { try $0.signedGatewayGrantAbandonment(abandoned) })
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 18)
        XCTAssertEqual(f.driver.state.withLock { $0.revocations }, 0)
        XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 0)
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(2)
        let acknowledgment = try XCTUnwrap(f.journal.read { try $0.gatewayAcknowledgment(f.root.registration) })
        XCTAssertEqual(acknowledgment.operationID, abandoned.operationID)
        XCTAssertTrue(acknowledgment.abandonedGrant)
        XCTAssertEqual(f.driver.state.withLock { $0.revocations }, 1)
        XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 0)
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(3)
        XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 1)
        XCTAssertEqual(f.revocationState.deliveryStatus(revocation.operationID), .gatewayApplied)
        await f.close()
    }

    func testLeaseExpiryDuringTombstoneSigningPreventsSendingIt() async throws {
        let f = try Fixture(earlier: .phoneRevocation, candidateBeforeEarlier: true, prepareRetirementSchema: true,
            beforePublisherSigns: { $0.advance(1000) })
        try await f.publisher.start()
        do {
            try await f.publisher.reconcile()
            XCTFail("Expected the publication lease to expire")
        } catch {
            XCTAssertEqual(error as? AuthorityWakePublisherError, .expiredLease)
        }
        XCTAssertNotNil(try f.journal.read { try $0.firstUnconfirmedGrantAbandonment() })
        XCTAssertEqual(f.driver.state.withLock { $0.tombstoneCalls }, 0)
        XCTAssertTrue(f.driver.state.withLock { $0.closed })
        try await f.assertGatewayHead(0)
        try f.root.assertCheckpoint()
        await f.close()
    }

    func testExpiredActivationOfActivePhoneClosesGapBeforeAnotherPhonesGrant() async throws {
        let f = try Fixture(enrollmentCount: 2, prepareRetirementSchema: true)
        let metadata = try f.offer()
        try await f.publisher.start()
        try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        try f.prove(metadata, challenge: await f.provider.challenges[0])
        let activation = try XCTUnwrap(f.state()?.activation)
        XCTAssertEqual(activation.revision, 2)
        f.driver.state.withLock { $0.rejectedActivationCalls = 1 }
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(1)
        f.clock.advance(1001)
        let next = try f.offer(phoneIndex: 1)
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(2)
        let receipt = try XCTUnwrap(f.driver.state.withLock { $0.tombstones.first })
        XCTAssertEqual(receipt.originalKind, .activation)
        XCTAssertEqual(receipt.operationID, activation.operationID)
        XCTAssertEqual(f.driver.state.withLock { $0.activations }, 0)
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(3)
        try await waitFor { await f.provider.challenges.contains { $0.candidateID == next.candidateID } }
        XCTAssertEqual(try f.journal.read { try $0.approvalEnrollments().filter { $0.approval.active }.count }, 2)
        await f.close()
    }

    func testSupersededLiveGrantWaitsForExpiryBeforeTheNextCandidate() async throws {
        let f = try Fixture(prepareRetirementSchema: true)
        let earlier = try f.offer()
        f.clock.advance(500)
        let later = try f.offer()
        try await f.publisher.start()
        try await f.publisher.reconcile()
        let enrollments = try f.journal.read { try $0.approvalEnrollments() }
        XCTAssertEqual(f.revocationState.health(enrollments, now: f.clock.now()), .waitingForGrantExpiry)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 13)
        try await f.assertGatewayHead(0)
        f.clock.advance(501)
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(1)
        XCTAssertEqual(f.driver.state.withLock { $0.tombstones.first?.operationID }, earlier.operationID)
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(2)
        try await waitFor { await f.provider.challenges.contains { $0.candidateID == later.candidateID } }
        await f.close()
    }

    func testLegacyGatewayReportsAnExpiredGrantEvenWithoutARevocationIntent() async throws {
        let f = try Fixture(prepareRetirementSchema: true)
        _ = try f.offer()
        f.driver.state.withLock { $0.rejectTombstoneProbe = true }
        f.clock.advance(1001)
        try await f.publisher.start()
        try await f.publisher.reconcile()
        let enrollments = try f.journal.read { try $0.approvalEnrollments() }
        XCTAssertTrue(enrollments.allSatisfy { $0.gatewayRevocation == nil })
        XCTAssertEqual(f.revocationState.health(enrollments, now: f.clock.now()), .gatewayUpdateNeeded)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 13)
        try await f.assertGatewayHead(0)
        await f.close()
    }

    func testEmptyTombstoneRepliesStayInconclusiveUntilSignedHeadAdvances() async throws {
        let f = try Fixture(prepareRetirementSchema: true)
        _ = try f.offer()
        f.clock.advance(1001)
        f.driver.state.withLock { $0.dropTombstoneReply = true }
        try await f.publisher.start()
        let enrollments = try f.journal.read { try $0.approvalEnrollments() }
        let firstAttempt = f.clock.wall()
        for _ in 0..<3 {
            try await f.publisher.reconcile()
            XCTAssertEqual(f.revocationState.health(enrollments, now: f.clock.now()), .grantAbandonmentInconclusive)
            XCTAssertEqual(try f.journal.read { try $0.firstUnconfirmedGrantAbandonment() }, firstAttempt)
            f.clock.advance(10)
        }
        try await f.assertGatewayHead(0)
        f.driver.state.withLock { $0.dropTombstoneReply = false }
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(1)
        try await f.publisher.reconcile()
        XCTAssertEqual(f.revocationState.health(enrollments, now: f.clock.now()), .clear)
        XCTAssertNil(try f.journal.read { try $0.firstUnconfirmedGrantAbandonment() })
        await f.close()
    }

    func testLiveRevocationPublishesAfterTheLastPhoneIsRemoved() async throws {
        let f = try Fixture(enrollmentCount: 1, earlier: .phoneRevocation)
        let control = try XCTUnwrap(f.earlierControl)
        try await f.publisher.start()
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(control.revision)
        XCTAssertEqual(f.driver.state.withLock { $0.revocations }, 1)
        XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 0)
        await f.close()
    }

    func testExpiredRevocationReplaysOriginalAfterRootJournalReopens() async throws {
        let f = try Fixture(enrollmentCount: 2, earlier: .phoneRevocation)
        let retained = try XCTUnwrap(f.earlierControl)
        try f.journal.close()
        f.root.store.close()
        let anchor = f.root.root.path, limits = f.root.limits, registration = f.root.registration
        let rootClock = Clock(UUID())
        f.clock.advance(1001); rootClock.advance(1001)
        let storage = try AuthorityStorage(openJournal: {
            try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "store", owner: getuid()),
                macID: registration.macID, accountID: registration.accountID, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 30, busyMilliseconds: 100, initialize: false,
                gatewayPolicy: GatewayAuthorityPolicy(payloadLimits: limits, signingLimits: limits, maximumControls: 30,
                    candidateLifetimeMillis: 1000, clockEpoch: rootClock.epoch))
        }, openContinuity: { _ in
            try ContinuityStore(lease: ProtectedContinuityLease(anchor: anchor, relativeDirectory: "continuity", owner: getuid()),
                macID: registration.macID, accountID: registration.accountID, initialize: nil)
        })
        let journal = try AuthorityJournal(storage: storage)
        defer { try? journal.close() }
        try journal.prepareRequests(clockEpoch: rootClock.epoch, maximumPayloadBytes: 4096)
        let frame = try journal.withRequests {
            try $0.phonePushRegistration(f.root.offer(), binding: f.root.binding, provider: f.root.provider,
                now: rootClock.now(), wall: rootClock.wall(), validateTransport: { _ in })
        }
        guard case .prepared = frame else { return XCTFail("The other phone did not prepare a registration") }
        let publisher = try AuthorityWakePublisher(journal: journal, channel: GatewayRootChannel(driver: f.driver),
            registration: registration, leaseMilliseconds: 1000, clock: { rootClock.now() }, routing: {
                var router = PresenceRouter(configuration: try PresenceConfiguration(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 100))
                return router.evaluate(mode: .away, snapshot: PresenceSnapshot(),
                    now: PresenceMoment(epoch: rootClock.epoch, milliseconds: rootClock.now().milliseconds))
            }, phonePush: f.phonePushConfiguration, gatewayRevocations: f.revocationState)
        try await publisher.start()
        try await publisher.reconcile()
        try await f.assertGatewayHead(retained.revision)
        XCTAssertEqual(f.revocationState.deliveryStatus(retained.operationID), .gatewayPending)
        XCTAssertEqual(f.driver.state.withLock { $0.recoveredBytes }, retained.canonicalPayload)
        XCTAssertEqual(f.driver.state.withLock { $0.recoveredSignature }, retained.signature)
        try await publisher.reconcile()
        try await f.assertGatewayHead(retained.revision + 1)
        XCTAssertEqual(f.revocationState.deliveryStatus(retained.operationID), .gatewayApplied)
        XCTAssertEqual(f.driver.state.withLock { $0.revocations }, 1)
        XCTAssertEqual(f.driver.state.withLock { $0.candidates }, 1)
        await publisher.close()
    }

    func testLegacyGatewayBlocksRevocationAndPreservesLaterRegistration() async throws {
        let f = try Fixture(enrollmentCount: 2, earlier: .phoneRevocation)
        let retained = try XCTUnwrap(f.earlierControl)
        let metadata = try f.offer()
        f.driver.state.withLock { $0.rejectRecoveryProbe = true }
        try await f.publisher.start()
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(0)
        let diagnostic = await f.publisher.phonePushDiagnostic
        XCTAssertEqual(diagnostic, .retryPending)
        let enrollments = try f.journal.read { try $0.approvalEnrollments() }
        XCTAssertEqual(f.revocationState.health(enrollments, now: f.clock.now()), .gatewayUpdateNeeded)
        XCTAssertEqual(f.revocationState.availability(now: f.clock.now()), .gatewayUnsupported)
        XCTAssertEqual(f.revocationState.deliveryStatus(retained.operationID), .gatewayBlocked)
        XCTAssertEqual(try f.state()?.candidate.operationID, metadata.operationID)
        XCTAssertEqual(f.driver.state.withLock { $0.revocations }, 0)
        await f.close()
    }

    func testRejectedRevocationCapabilityIsRetriedOnTheSameConnection() async throws {
        let f = try Fixture(enrollmentCount: 2, earlier: .phoneRevocation)
        let retained = try XCTUnwrap(f.earlierControl)
        f.driver.state.withLock { $0.rejectRecoveryProbe = true }
        try await f.publisher.start()
        try await f.publisher.reconcile()
        XCTAssertEqual(f.driver.state.withLock { $0.recoveryProbes }, 1)
        try await f.publisher.reconcile()
        XCTAssertEqual(f.driver.state.withLock { $0.recoveryProbes }, 1)
        f.clock.advance(30_000)
        f.driver.state.withLock { $0.rejectRecoveryProbe = false }
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(retained.revision)
        try await f.publisher.reconcile()
        XCTAssertEqual(f.driver.state.withLock { $0.recoveryProbes }, 2)
        XCTAssertEqual(f.revocationState.availability(now: f.clock.now()), .available)
        XCTAssertEqual(f.revocationState.deliveryStatus(retained.operationID), .gatewayApplied)
        await f.close()
    }

    func testGatewaySnapshotProjectsReplacementAndRetainsOldEnrollmentAtRoot() throws {
        let f = try Fixture(enrollmentCount: 2, earlier: .phoneRevocation)
        let retained = try f.journal.withRequests { try $0.wakeDeliveryTrust().enrollments }
        let old = try XCTUnwrap(retained.first { !$0.approval.active })
        let other = try XCTUnwrap(retained.first { $0.approval.active })
        let replacement = try StoredApprovalEnrollment(epoch: Data(repeating: 91, count: 16),
            notificationTag: Data(repeating: 92, count: 32), identityPublicKey: old.identityPublicKey,
            approval: ApprovalEnrollment(phoneID: old.approval.phoneID, active: true,
                capabilities: old.approval.capabilities, keys: old.approval.keys))
        for order in [[old, replacement, other], [replacement, other, old]] {
            let rows = try AuthorityWakePublisher.gatewaySnapshotEnrollments(order)
            XCTAssertEqual(rows.count, 2)
            XCTAssertEqual(rows.first { $0.phoneID == old.approval.phoneID }?.epoch, replacement.epoch)
            XCTAssertEqual(rows.first { $0.phoneID == other.approval.phoneID }?.epoch, other.epoch)
        }
        XCTAssertTrue(try f.journal.withRequests { try $0.wakeDeliveryTrust().enrollments.contains { $0.epoch == old.epoch && !$0.approval.active } })
    }

    func testExpiredNonRegistrationControlsStillBlockLaterRegistration() async throws {
        for kind in EarlierControl.allCases where kind != .phoneRevocation {
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
        let f = try Fixture(prepareRetirementSchema: true), metadata = try f.offer()
        try await f.publisher.start()
        try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 1 }
        try f.prove(metadata, challenge: await f.provider.challenges[0])
        let original = try XCTUnwrap(f.state()?.activation)
        try await f.assertGatewayHead(1)

        f.clock.advance(1100)
        try await f.publisher.reconcile()
        let tombstone = try XCTUnwrap(f.driver.state.withLock { $0.tombstones.first })
        XCTAssertEqual(tombstone.originalKind, .activation)
        XCTAssertEqual(tombstone.operationID, original.operationID)
        XCTAssertEqual(try f.journal.read { try $0.storageSchemaVersion }, 18)
        XCTAssertFalse(try XCTUnwrap(f.state()).activationAbandonmentConfirmed)
        XCTAssertEqual(f.driver.state.withLock { $0.mappingQueries }, 0)
        try await f.assertGatewayHead(2)

        f.driver.state.withLock { $0.rejectMappingQuery = true }
        try await f.publisher.reconcile()
        let acknowledgment = try XCTUnwrap(f.journal.read { try $0.gatewayAcknowledgment(f.root.registration) })
        XCTAssertEqual(acknowledgment.operationID, original.operationID)
        XCTAssertTrue(acknowledgment.abandonedGrant)
        XCTAssertTrue(try XCTUnwrap(f.state()).activationAbandonmentConfirmed)
        XCTAssertEqual(try f.state()?.candidate.operationID, metadata.operationID)
        XCTAssertEqual(f.driver.state.withLock { $0.mappingQueries }, 1)

        f.driver.state.withLock { $0.rejectMappingQuery = false }
        try await f.publisher.reconcile()
        let replacement = try XCTUnwrap(f.state())
        XCTAssertNil(replacement.activation)
        XCTAssertNotEqual(replacement.candidate.operationID, metadata.operationID)
        XCTAssertEqual(f.driver.state.withLock { $0.mappingQueries }, 2)
        try await f.assertGatewayHead(2)

        let candidate = try GatewayTokenCandidate.decode(replacement.candidate.canonicalPayload, limits: f.root.limits)
        let fresh = try PhonePushRegistrationMetadata(candidate)
        XCTAssertEqual(fresh.enrollmentEpoch, metadata.enrollmentEpoch)
        XCTAssertEqual(fresh.enrollmentTag, metadata.enrollmentTag)
        try await f.publisher.reconcile()
        try await waitFor { await f.provider.challenges.count == 2 }
        try await f.assertGatewayHead(3)
        XCTAssertEqual(f.driver.state.withLock { $0.activations }, 0)
        try f.prove(fresh, challenge: await f.provider.challenges[1])
        try await f.publisher.reconcile()
        try await f.assertGatewayHead(4)
        let published = try XCTUnwrap(f.state()?.activation)
        XCTAssertNotEqual(published.operationID, original.operationID)
        XCTAssertEqual(published.revision, 4)
        XCTAssertEqual(f.driver.state.withLock { $0.lastMappedCandidate }, fresh.candidateID)
        XCTAssertEqual(try f.recoveryState().phase, .mappingObserved)
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
