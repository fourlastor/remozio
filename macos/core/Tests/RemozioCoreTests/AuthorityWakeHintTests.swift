import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityWakeHintTests: XCTestCase, @unchecked Sendable {
    private final class HintDriver: AuthorityWakeHintDriver {
        struct State {
            var version: UInt64 = 1
            var failVersion = false
            var bytes: Data?
            var calls: [AuthorityWakeHintCall] = []
            var closed = 0
        }
        let value = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: AuthorityWakeHintCall, reply: @escaping @Sendable (AuthorityWakeHintResponse) -> Void) {
            reply(value.withLock { state in
                state.calls.append(call)
                switch call {
                case .hello: return .version(1)
                case .version: return state.failVersion ? .failed : .version(state.version)
                case .hints: return .hints(state.bytes)
                }
            })
        }
        func close() { value.withLock { $0.closed += 1 } }
    }
    private final class OrdinaryDriver: AuthorityXPCDriver {
        let closes = Mutex(0)
        let bytes: Data
        init(_ bytes: Data) { self.bytes = bytes }
        func start(invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.snapshot(bytes)) }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func close() { closes.withLock { $0 += 1 } }
    }
    private final class WakeDriver: GatewayWakeDriver {
        struct State {
            var challengeNumber: UInt8 = 0
            var challenge = Data()
            var submissions: [(Data, Data)] = []
            var reject = 0
            var closed = 0
        }
        let value = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: GatewayWakeCall, reply: @escaping @Sendable (GatewayWakeResponse) -> Void) {
            reply(value.withLock { state in
                switch call {
                case .hello: return .version(1)
                case .challenge:
                    state.challengeNumber += 1; state.challenge = Data(repeating: state.challengeNumber, count: 32)
                    return .challenge(state.challenge)
                case .wake(let payload, let signature):
                    state.submissions.append((payload, signature))
                    if state.reject > 0 { state.reject -= 1; return .accepted(false) }
                    return .accepted(true)
                }
            })
        }
        func close() { value.withLock { $0.closed += 1 } }
    }
    private func signer(_ binding: GatewaySubmissionBinding, key: P256.Signing.PrivateKey) throws -> GatewayWakeSigner {
        let credential = Data(repeating: 3, count: 16)
        let config = try GatewayWakeSignerConfiguration(binding: binding, credentialID: credential, transportUID: 401,
            ownerUID: 501, gatewayUID: 402, serviceName: "dev.remozio.gateway.wake", teamID: "TEAMID1234",
            gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [Data(repeating: 4, count: 20)],
            custody: .protectedFile, keyRecordPath: "/Library/Remozio/transport/wake.cbor", publicKey: key.publicKey.x963Representation)
        let record = try GatewayWakeKeyRecord(binding: binding, credentialID: credential, fileKey: key)
        return try GatewayWakeSigner.load(configuration: config, realUID: 401, effectiveUID: 401, read: { _, _ in try record.encode() })
    }
    private func binding(_ value: UInt8 = 1) throws -> GatewaySubmissionBinding {
        let id = Data(repeating: value, count: 16)
        return try .init(ownerID: id, macID: id, accountID: id, gatewayID: id, lifecycleEpoch: id)
    }
    func testCanonicalOpaqueHintsRejectWrongScopeDuplicateIDsAndUnknownFields() throws {
        let binding = try binding(), ids = [UUID(), UUID()], hints = try AuthorityWakeHints(binding: binding, deliveryIDs: ids)
        let encoded = try hints.encode()
        XCTAssertEqual(try AuthorityWakeHints.decode(encoded, expectedBinding: binding).deliveryIDs, hints.deliveryIDs)
        XCTAssertThrowsError(try AuthorityWakeHints.decode(encoded, expectedBinding: self.binding(2)))
        XCTAssertThrowsError(try AuthorityWakeHints(binding: binding, deliveryIDs: [ids[0], ids[0]]))
        XCTAssertThrowsError(try AuthorityWakeHints(binding: binding, deliveryIDs: (0...1024).map { _ in UUID() }))
        let limits = try CBORLimits(maxBytes: 20_000, maxDepth: 2, maxItems: 1040)
        guard case .map(var fields) = try DeterministicCBOR.decode(encoded, limits: limits) else { return XCTFail() }
        fields[7] = .text("not part of the protocol")
        XCTAssertThrowsError(try AuthorityWakeHints.decode(DeterministicCBOR.encode(.map(fields), limits: limits), expectedBinding: binding))
        fields.removeValue(forKey: 7); fields[0] = .unsigned(2)
        XCTAssertThrowsError(try AuthorityWakeHints.decode(DeterministicCBOR.encode(.map(fields), limits: limits), expectedBinding: binding))
    }
    func testUnsupportedOrUnimplementedWakeHandshakeLeavesOrdinaryConnectionUsable() async throws {
        let binding = try binding(), trust = DirectApprovalTrust(macID: binding.macID, accountID: binding.accountID, revision: UUID(), peers: [])
        for failSelector in [false, true] {
            let ordinary = OrdinaryDriver(try AuthorityTrustCodec.encodeSnapshot(trust)), approval = AuthorityXPCChannel(driver: ordinary)
            let hint = HintDriver(), wake = AuthorityWakeHintChannel(driver: hint, binding: binding)
            hint.value.withLock { $0.version = 0; $0.failVersion = failSelector }
            try await approval.start()
            do { try await wake.start(); XCTFail("Unsupported wake peer") }
            catch {
                XCTAssertEqual(error as? AuthorityWakeHintChannelError, failSelector ? .closed : .unsupportedVersion)
            }
            let current = try await approval.fetchTrust(expectedMacID: binding.macID, expectedAccountID: binding.accountID)
            XCTAssertEqual(current.revision, trust.revision)
            let supported = try await approval.supportsRequestExchange(); XCTAssertFalse(supported)
            XCTAssertEqual(ordinary.closes.withLock { $0 }, 0)
            XCTAssertEqual(hint.value.withLock { $0.closed }, 1)
            XCTAssertEqual(hint.value.withLock { $0.calls.count }, 2)
            await approval.close()
        }
    }
    func testHintClientNegotiatesBeforeFetchingAndRejectsWrongGatewayLifecycle() async throws {
        let binding = try binding(), driver = HintDriver(), channel = AuthorityWakeHintChannel(driver: driver, binding: binding)
        let ids = [UUID()]
        driver.value.withLock { $0.bytes = try? AuthorityWakeHints(binding: binding, deliveryIDs: ids).encode() }
        do { _ = try await channel.current(); XCTFail() } catch { XCTAssertEqual(error as? AuthorityWakeHintChannelError, .closed) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 0)
        try await channel.start()
        let current = try await channel.current(); XCTAssertEqual(current.deliveryIDs, ids)
        let other = try self.binding(2)
        driver.value.withLock { $0.bytes = try? AuthorityWakeHints(binding: other, deliveryIDs: ids).encode() }
        do { _ = try await channel.current(); XCTFail("Cross-gateway hint") }
        catch { XCTAssertEqual(error as? AuthorityWakeHintChannelError, .invalidMessage) }
        XCTAssertEqual(driver.value.withLock { $0.closed }, 1)
    }
    func testEndpointNegotiationAndInvocationChecksPrecedeHintHandler() throws {
        let binding = try binding(), reads = Mutex(0), checks = Mutex(0), invalidations = Mutex(0)
        let hints = try AuthorityWakeHints(binding: binding, deliveryIDs: [UUID()])
        let trust = DirectApprovalTrust(macID: binding.macID, accountID: binding.accountID, revision: UUID(), peers: [])
        let endpoint = try AuthorityXPCEndpoint(macID: binding.macID, accountID: binding.accountID, budget: AuthorityXPCWorkBudget(),
            verify: { checks.withLock { $0 += 1 } }, invalidate: { invalidations.withLock { $0 += 1 } },
            snapshot: { trust }, validate: { _ in true }, wakeHints: { reads.withLock { $0 += 1 }; return hints })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.requestWakeVersion { XCTAssertEqual($0, 1) }
        endpoint.wakeDeliveryHints { bytes in XCTAssertEqual(bytes, try? hints.encode()) }
        XCTAssertEqual(checks.withLock { $0 }, 3); XCTAssertEqual(reads.withLock { $0 }, 1)
        XCTAssertEqual(invalidations.withLock { $0 }, 0)
        endpoint.close()
    }
    func testMissingNegotiationOrChangedInvocationCannotReadHintFeed() throws {
        let binding = try binding(), trust = DirectApprovalTrust(macID: binding.macID, accountID: binding.accountID, revision: UUID(), peers: [])
        let hints = try AuthorityWakeHints(binding: binding, deliveryIDs: [UUID()])
        for changeIdentity in [false, true] {
            let checks = Mutex(0), reads = Mutex(0)
            let endpoint = try AuthorityXPCEndpoint(macID: binding.macID, accountID: binding.accountID, budget: AuthorityXPCWorkBudget(),
                verify: {
                    let count = checks.withLock { $0 += 1; return $0 }
                    if changeIdentity && count > 2 { throw XPCPeerPolicyError.wrongPeer }
                }, invalidate: {}, snapshot: { trust }, validate: { _ in true },
                wakeHints: { reads.withLock { $0 += 1 }; return hints })
            endpoint.hello { XCTAssertEqual($0, 1) }
            if changeIdentity { endpoint.requestWakeVersion { XCTAssertEqual($0, 1) } }
            endpoint.wakeDeliveryHints { XCTAssertNil($0) }
            XCTAssertEqual(reads.withLock { $0 }, 0)
        }
    }
    func testTransportRuntimeSignsFreshChallengeRetriesRejectionAndDoesNotRepeatAcceptedHints() async throws {
        let binding = try binding(), key = P256.Signing.PrivateKey(), id = UUID(), hintDriver = HintDriver(), wakeDriver = WakeDriver()
        hintDriver.value.withLock { $0.bytes = try? AuthorityWakeHints(binding: binding, deliveryIDs: [id]).encode() }
        wakeDriver.value.withLock { $0.reject = 1 }
        let runtime = try TransportWakeRuntime(hints: AuthorityWakeHintChannel(driver: hintDriver, binding: binding),
            gateway: GatewayWakeChannel(driver: wakeDriver), signer: signer(binding, key: key))
        try await runtime.start(); try await runtime.poll(); try await runtime.poll(); try await runtime.poll()
        let submissions = wakeDriver.value.withLock { $0.submissions }
        XCTAssertEqual(submissions.count, 2)
        for (index, sent) in submissions.enumerated() {
            let submission = try GatewayWakeSubmission.decode(sent.0)
            XCTAssertEqual(submission.binding, binding)
            XCTAssertEqual(submission.deliveryID, GatewayHostSnapshot.bytes(id))
            XCTAssertEqual(submission.challenge, Data(repeating: UInt8(index + 1), count: 32))
            XCTAssertTrue(try key.publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: sent.1), for: submission.signingInput()))
        }
        hintDriver.value.withLock { $0.bytes = try? AuthorityWakeHints(binding: binding, deliveryIDs: []).encode() }
        try await runtime.poll()
        XCTAssertEqual(wakeDriver.value.withLock { $0.submissions.count }, 2)
        await runtime.close()
        XCTAssertEqual(hintDriver.value.withLock { $0.closed }, 1)
        XCTAssertEqual(wakeDriver.value.withLock { $0.closed }, 1)
        do { try await runtime.poll(); XCTFail("Closed runtime woke a phone") } catch { XCTAssertEqual(error as? TransportWakeRuntimeError, .closed) }
    }
    func testUnsupportedHintExtensionCannotStartGatewayRuntimeOrUseUnmatchedSignerScope() async throws {
        let binding = try binding(), hintDriver = HintDriver(), wakeDriver = WakeDriver(), signer = try signer(binding, key: P256.Signing.PrivateKey())
        XCTAssertThrowsError(try TransportWakeRuntime(hints: AuthorityWakeHintChannel(driver: hintDriver, binding: self.binding(2)),
            gateway: GatewayWakeChannel(driver: wakeDriver), signer: signer))
        hintDriver.value.withLock { $0.version = 0 }
        let runtime = try TransportWakeRuntime(hints: AuthorityWakeHintChannel(driver: hintDriver, binding: binding),
            gateway: GatewayWakeChannel(driver: wakeDriver), signer: signer)
        do { try await runtime.start(); XCTFail("Unsupported runtime started") }
        catch { XCTAssertEqual(error as? AuthorityWakeHintChannelError, .unsupportedVersion) }
        XCTAssertEqual(wakeDriver.value.withLock { $0.challengeNumber }, 0)
        XCTAssertTrue(wakeDriver.value.withLock { $0.submissions.isEmpty })
    }
    private func waitFor(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw GatewayWakeChannelError.timedOut }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    func testRecoveringTransportUsesFreshChannelsAndOriginalHintWithoutClosingOrdinaryConnection() async throws {
        let binding = try binding(), key = P256.Signing.PrivateKey(), id = UUID()
        let trust = DirectApprovalTrust(macID: binding.macID, accountID: binding.accountID, revision: UUID(), peers: [])
        let ordinaryDriver = OrdinaryDriver(try AuthorityTrustCodec.encodeSnapshot(trust))
        let ordinary = AuthorityXPCChannel(driver: ordinaryDriver)
        try await ordinary.start()
        let firstHint = HintDriver(), secondHint = HintDriver(), firstWake = WakeDriver(), secondWake = WakeDriver()
        let bytes = try AuthorityWakeHints(binding: binding, deliveryIDs: [id]).encode()
        firstHint.value.withLock { $0.bytes = bytes }
        secondHint.value.withLock { $0.bytes = bytes }
        secondWake.value.withLock { $0.challengeNumber = 20 }
        let attempts = Mutex(0)
        let runner = try TransportWakeRunner(intervalMilliseconds: 10, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100,
            makeAttempt: { [self] in
                let number = attempts.withLock { $0 += 1; return $0 }
                guard number <= 2 else { throw GatewayWakeSignerError.invalidConfiguration }
                let hintDriver = number == 1 ? firstHint : secondHint
                let wakeDriver = number == 1 ? firstWake : secondWake
                let runtime = try TransportWakeRuntime(hints: AuthorityWakeHintChannel(driver: hintDriver, binding: binding),
                    gateway: GatewayWakeChannel(driver: wakeDriver), signer: signer(binding, key: key))
                return TransportWakeAttempt(start: { try await runtime.start() }, poll: { try await runtime.poll() },
                    close: { await runtime.close() })
            }, report: { _ in })
        try await runner.start()
        try await waitFor { firstWake.value.withLock { $0.submissions.count } == 1 }
        firstHint.value.withLock { $0.bytes = nil }
        try await waitFor { secondWake.value.withLock { $0.submissions.count } == 1 }
        try await Task.sleep(for: .milliseconds(40))
        let current = try await ordinary.fetchTrust(expectedMacID: binding.macID, expectedAccountID: binding.accountID)
        XCTAssertEqual(current.revision, trust.revision)
        XCTAssertEqual(ordinaryDriver.closes.withLock { $0 }, 0)
        XCTAssertEqual(attempts.withLock { $0 }, 2)
        for (driver, challenge) in [(firstWake, UInt8(1)), (secondWake, UInt8(21))] {
            let submissions = driver.value.withLock { $0.submissions }
            XCTAssertEqual(submissions.count, 1)
            let sent = try XCTUnwrap(submissions.first)
            let submission = try GatewayWakeSubmission.decode(sent.0)
            XCTAssertEqual(submission.binding, binding)
            XCTAssertEqual(submission.deliveryID, GatewayHostSnapshot.bytes(id))
            XCTAssertEqual(submission.challenge, Data(repeating: challenge, count: 32))
            XCTAssertTrue(try key.publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: sent.1),
                for: submission.signingInput()))
        }
        let negotiation = secondHint.value.withLock { $0.calls.prefix(2).map { call in
            switch call { case .hello: "hello"; case .version: "version"; case .hints: "hints" }
        } }
        XCTAssertEqual(negotiation, ["hello", "version"])
        await runner.close()
        // Driver invalidation also occurs when the channel is released.
        for driver in [firstHint, secondHint] { XCTAssertEqual(driver.value.withLock { $0.closed }, 2) }
        for driver in [firstWake, secondWake] { XCTAssertEqual(driver.value.withLock { $0.closed }, 2) }
        await ordinary.close()
    }
    func testMalformedHintPayloadsCloseWithoutSigningAndRecoverWithThePinnedScope() async throws {
        let binding = try binding(), key = P256.Signing.PrivateKey()
        let ids = [UUID(), UUID()], good = try AuthorityWakeHints(binding: binding, deliveryIDs: ids).encode()
        let limits = try CBORLimits(maxBytes: 20_000, maxDepth: 2, maxItems: 1040)
        guard case .map(let fields) = try DeterministicCBOR.decode(good, limits: limits) else { return XCTFail() }
        var unknown = fields; unknown[7] = .unsigned(1)
        var noncanonical = fields
        guard case .array(let orderedIDs) = fields[6] else { return XCTFail() }
        noncanonical[6] = .array(Array(orderedIDs.reversed()))
        var invalidID = fields; invalidID[6] = .array([.bytes(Data(repeating: 0, count: 15))])
        let cases: [(String, Data)] = [
            ("invalid CBOR", Data([0xff])),
            ("unknown field", try DeterministicCBOR.encode(.map(unknown), limits: limits)),
            ("noncanonical IDs", try DeterministicCBOR.encode(.map(noncanonical), limits: limits)),
            ("wrong scope", try AuthorityWakeHints(binding: self.binding(2), deliveryIDs: ids).encode()),
            ("invalid ID", try DeterministicCBOR.encode(.map(invalidID), limits: limits))
        ]
        for (label, bad) in cases {
            let firstHint = HintDriver(), secondHint = HintDriver(), firstWake = WakeDriver(), secondWake = WakeDriver()
            firstHint.value.withLock { $0.bytes = bad }; secondHint.value.withLock { $0.bytes = good }
            let attempts = Mutex(0)
            let runner = try TransportWakeRunner(intervalMilliseconds: 10, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100,
                makeAttempt: { [self] in
                    let number = attempts.withLock { $0 += 1; return $0 }
                    guard number <= 2 else { throw GatewayWakeSignerError.invalidConfiguration }
                    let runtime = try TransportWakeRuntime(
                        hints: AuthorityWakeHintChannel(driver: number == 1 ? firstHint : secondHint, binding: binding),
                        gateway: GatewayWakeChannel(driver: number == 1 ? firstWake : secondWake), signer: signer(binding, key: key))
                    return TransportWakeAttempt(start: { try await runtime.start() }, poll: { try await runtime.poll() },
                        close: { await runtime.close() })
                }, report: { _ in })
            try await runner.start()
            try await waitFor { runner.status == .failed || secondWake.value.withLock { $0.submissions.count } == ids.count }
            await runner.close()
            XCTAssertEqual(attempts.withLock { $0 }, 2, label)
            XCTAssertEqual(firstWake.value.withLock { $0.challengeNumber }, 0, label)
            XCTAssertTrue(firstWake.value.withLock { $0.submissions.isEmpty }, label)
            XCTAssertEqual(firstHint.value.withLock { $0.closed }, 2, label)
            XCTAssertEqual(firstWake.value.withLock { $0.closed }, 2, label)
            let submissions = secondWake.value.withLock { $0.submissions }
            XCTAssertEqual(submissions.count, ids.count, label)
            var delivered = Set<UUID>()
            for sent in submissions {
                let submission = try GatewayWakeSubmission.decode(sent.0)
                XCTAssertEqual(submission.binding, binding, label)
                delivered.insert(try GatewayHostSnapshot.uuid(submission.deliveryID))
                XCTAssertTrue(try key.publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: sent.1),
                    for: submission.signingInput()), label)
            }
            XCTAssertEqual(delivered, Set(ids), label)
        }
    }

    func testPermanentWakeSignerFailureLeavesOrdinaryConnectionUsableWithoutRetry() async throws {
        let binding = try binding(), trust = DirectApprovalTrust(macID: binding.macID, accountID: binding.accountID, revision: UUID(), peers: [])
        let ordinaryDriver = OrdinaryDriver(try AuthorityTrustCodec.encodeSnapshot(trust))
        let ordinary = AuthorityXPCChannel(driver: ordinaryDriver)
        try await ordinary.start()
        let attempts = Mutex(0)
        let runner = try TransportWakeRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, makeAttempt: {
            attempts.withLock { $0 += 1 }
            throw GatewayWakeSignerError.wrongIdentity
        }, report: { _ in })
        try await runner.start()
        try await waitFor { runner.status == .failed }
        try await Task.sleep(for: .milliseconds(150))
        let current = try await ordinary.fetchTrust(expectedMacID: binding.macID, expectedAccountID: binding.accountID)
        XCTAssertEqual(current.revision, trust.revision)
        XCTAssertEqual(attempts.withLock { $0 }, 1)
        XCTAssertEqual(ordinaryDriver.closes.withLock { $0 }, 0)
        await runner.close(); await ordinary.close()
    }

}
