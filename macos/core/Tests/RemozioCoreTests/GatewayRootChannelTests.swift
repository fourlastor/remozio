import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayRootChannelTests: XCTestCase, @unchecked Sendable {
    private final class Driver: GatewayRootDriver {
        struct State {
            var calls: [GatewayRootCall] = []
            var closed = 0
            var closeDuringStart = false
            var lost: (@Sendable () -> Void)?
            var version: UInt64 = 1
            var hold = false
            var response: Data?
            var reply: (@Sendable (GatewayRootResponse) -> Void)?
        }
        let value = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) {
            let lose = value.withLock { $0.lost = closed; return $0.closeDuringStart }
            if lose { closed() }
        }
        func disconnect() { value.withLock { $0.lost }?() }
        func invoke(_ call: GatewayRootCall, reply: @escaping @Sendable (GatewayRootResponse) -> Void) {
            let result: GatewayRootResponse? = value.withLock { state in
                state.calls.append(call)
                if state.hold { state.reply = reply; return nil }
                switch call {
                case .hello: return .version(state.version)
                case .synchronize: return .synchronized(true)
                case .command: return .command(state.response)
                }
            }
            if let result { reply(result) }
        }
        func close() { value.withLock { $0.closed += 1 } }
    }
    private func snapshot() throws -> GatewayHostSnapshot {
        let id = Data(repeating: 1, count: 16)
        let identity = try GatewayRegistrationIdentity(ownerID: id, macID: id, accountID: id, gatewayID: id,
            lifecycleEpoch: id, rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        return try GatewayHostSnapshot(registration: identity, rootEpoch: UUID(), sequence: 1, observedAtMilliseconds: 100,
            leaseDeadlineMilliseconds: 200, enrollments: [], active: false, phoneRouting: false)
    }
    func testStartedDriverIsReleasedAfterExplicitCloseOrOwnerDeinitialization() async throws {
        for explicitClose in [false, true] {
            var driver: Driver? = Driver()
            weak var released = driver
            var channel: GatewayRootChannel? = GatewayRootChannel(driver: try XCTUnwrap(driver))
            try await channel?.start()
            if explicitClose { await channel?.close() }
            channel = nil; driver = nil
            XCTAssertNil(released, "The stored close callback must not retain its own driver")
            released = nil
        }
    }
    func testRetainedReplyDoesNotKeepDriverAliveAfterTimeout() async throws {
        var driver: Driver? = Driver()
        driver?.value.withLock { $0.hold = true }
        weak var released = driver
        var channel: GatewayRootChannel? = GatewayRootChannel(driver: try XCTUnwrap(driver), timeoutMilliseconds: 20)
        do { try await channel?.start(); XCTFail() } catch {
            XCTAssertEqual(error as? GatewayRootChannelError, .timedOut)
        }
        channel = nil; driver = nil
        XCTAssertNil(released, "The stored reply callback must not retain its own driver")
        released = nil
    }
    func testConnectionLossDuringStartCannotSendHello() async throws {
        let driver = Driver(); driver.value.withLock { $0.closeDuringStart = true }
        let channel = GatewayRootChannel(driver: driver)
        do { try await channel.start(); XCTFail() } catch { XCTAssertEqual(error as? GatewayRootChannelError, .closed) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 0)
    }
    func testConnectionLossDuringSensitiveCallValidationCannotDispatchBeforeActorCleanup() async throws {
        let driver = Driver(), armed = Mutex(false)
        let channel = GatewayRootChannel(driver: driver, verifyAccount: {
            if armed.withLock({ $0 }) { driver.disconnect() }
        })
        try await channel.start(); armed.withLock { $0 = true }
        do { try await channel.synchronize(snapshot()); XCTFail() } catch { XCTAssertEqual(error as? GatewayRootChannelError, .closed) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 1)
    }
    func testSensitiveCallsCannotPrecedeHandshakeOrFollowUnknownVersion() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver)
        do { try await channel.synchronize(snapshot()); XCTFail() } catch {}
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 0)
        driver.value.withLock { $0.version = 4 }
        do { try await channel.start(); XCTFail() } catch {}
        do { try await channel.synchronize(snapshot()); XCTFail() } catch {}
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 1)
        if case .hello = driver.value.withLock({ $0.calls[0] }) {} else { XCTFail() }
        await channel.close()
    }
    func testValidHandshakeAllowsBoundedSnapshotAndUnverifiedRecoveryData() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver)
        driver.value.withLock { $0.response = try? GatewayRootCommand.reply([.bytes(Data([1])), .bytes(Data(repeating: 2, count: 64))]) }
        try await channel.start()
        try await channel.synchronize(snapshot())
        let reply = try await channel.head(query: Data([1]))
        XCTAssertEqual(reply.canonicalPayload, Data([1]))
        XCTAssertEqual(reply.signature.count, 64)
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 3)
        await channel.close()
    }
    func testMalformedRecoveryReplyRetiresChannel() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver)
        driver.value.withLock { $0.response = try? GatewayRootCommand.reply([.bytes(Data([1])), .bytes(Data(repeating: 2, count: 63))]) }
        try await channel.start()
        do { _ = try await channel.head(query: Data([1])); XCTFail() } catch {}
        do { try await channel.synchronize(snapshot()); XCTFail() } catch {}
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
        await channel.close()
    }
    func testTimeoutClosesConnectionAndLateHelloCannotReopenIt() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver, timeoutMilliseconds: 20)
        driver.value.withLock { $0.hold = true }
        do { try await channel.start(); XCTFail() } catch {
            XCTAssertEqual(error as? GatewayRootChannelError, .timedOut)
        }
        driver.value.withLock { $0.reply }?(.version(1))
        do { try await channel.synchronize(snapshot()); XCTFail() } catch {}
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 1)
        await channel.close()
    }
    func testWrongAccountCannotSendHello() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver, verifyAccount: { throw GatewayServiceError.wrongAccount })
        do { try await channel.start(); XCTFail() } catch { XCTAssertEqual(error as? GatewayServiceError, .wrongAccount) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 0)
        await channel.close()
    }
    private func submissionEnvelope() throws -> (GatewayAuthorityEnvelope, GatewayRegistrationIdentity) {
        let key = P256.Signing.PrivateKey(), id = Data(repeating: 1, count: 16)
        let registration = try GatewayRegistrationIdentity(ownerID: id, macID: id, accountID: id, gatewayID: id,
            lifecycleEpoch: id, rootPublicKey: key.publicKey.x963Representation)
        let limits = try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128)
        let value = try GatewaySubmissionControl(kind: .rotation,
            binding: GatewaySubmissionBinding(ownerID: id, macID: id, accountID: id, gatewayID: id, lifecycleEpoch: id),
            revision: 1, operationID: Data(repeating: 2, count: 16), issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000,
            credentialID: Data(repeating: 3, count: 16), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        let payload = try value.encode(limits: limits)
        let signature = try key.signature(for: GatewaySubmissionSigningInput.make(wireVersion: 1, kind: .rotation,
            canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)).rawRepresentation
        return (GatewayAuthorityEnvelope(kind: 4, operationID: value.operationID, revision: 1,
            canonicalPayload: payload, signature: signature, registrationToken: nil), registration)
    }
    func testLegacyPeerRejectsSubmissionBeforeSendingAndKeepsLegacyOperations() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver), (envelope, registration) = try submissionEnvelope()
        try await channel.start()
        do { _ = try await channel.applySubmission(envelope, registration: registration); XCTFail() }
        catch { XCTAssertEqual(error as? GatewayRootChannelError, .unsupportedVersion) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 1)
        driver.value.withLock { $0.response = try? GatewayRootCommand.reply([.bytes(Data([1])), .bytes(Data(repeating: 2, count: 64))]) }
        _ = try await channel.head(query: Data([1]))
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
        await channel.close()
    }
    func testVersionTwoPeerReturnsOnlyTheAuthenticatedOriginalSubmissionReceipt() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver), (envelope, registration) = try submissionEnvelope()
        driver.value.withLock {
            $0.version = 2
            $0.response = try? GatewayRootCommand.reply([.bytes(envelope.canonicalPayload), .bytes(envelope.signature), .boolean(false)], version: 2)
        }
        try await channel.start()
        let result = try await channel.applySubmission(envelope, registration: registration)
        XCTAssertFalse(result.inserted); XCTAssertEqual(result.receipt.canonicalPayload, envelope.canonicalPayload)
        guard case .command(let bytes) = driver.value.withLock({ $0.calls[1] }),
              case .submission = try GatewayRootCommand.decode(bytes) else { return XCTFail("Expected credential command") }
        XCTAssertEqual(try DeterministicCBOR.decode(bytes, limits: GatewayRootCommand.limits),
            .array([.unsigned(2), .unsigned(7), .bytes(envelope.canonicalPayload), .bytes(envelope.signature), .unsigned(1)]))
        await channel.close()
    }
    func testInvalidRootReceiptOrWrongReplyVersionRetiresCredentialChannel() async throws {
        let (envelope, registration) = try submissionEnvelope()
        for mutation in 0..<3 {
            let driver = Driver(), channel = GatewayRootChannel(driver: driver)
            driver.value.withLock {
                $0.version = 2
                $0.response = try? GatewayRootCommand.reply([
                    .bytes(mutation == 0 ? Data([1]) : envelope.canonicalPayload),
                    .bytes(mutation == 1 ? Data(repeating: 0, count: 64) : envelope.signature),
                    .boolean(true)], version: mutation == 2 ? 1 : 2)
            }
            try await channel.start()
            do { _ = try await channel.applySubmission(envelope, registration: registration); XCTFail() } catch {}
            do { _ = try await channel.head(query: Data([1])); XCTFail() }
            catch { XCTAssertEqual(error as? GatewayRootChannelError, .closed) }
            XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
        }
    }

    func testRegistrationRejectsLegacyPeersBeforeSendingSensitiveFields() async throws {
        let delivery = PhoneRequestDelivery(id: UUID(), recipient: DeliveryRecipient(phoneID: Data(repeating: 1, count: 16),
            enrollmentEpoch: Data(repeating: 2, count: 16)), requestID: Data(repeating: 3, count: 16),
            admittedAt: AuthorityMoment(epoch: UUID(), milliseconds: 100), deadlineMilliseconds: 200)
        for version: UInt64 in [1, 2, 3] {
            let driver = Driver(), channel = GatewayRootChannel(driver: driver)
            driver.value.withLock { $0.version = version; $0.response = try? GatewayRootCommand.reply([.boolean(true)], version: 3) }
            try await channel.start()
            if version < 3 {
                do { _ = try await channel.command(.registerWake(delivery)); XCTFail("Legacy peer received a grant") }
                catch { XCTAssertEqual(error as? GatewayRootChannelError, .unsupportedVersion) }
                XCTAssertEqual(driver.value.withLock { $0.calls.count }, 1)
            } else {
                let reply = try await channel.command(.registerWake(delivery))
                XCTAssertEqual(reply, [.unsigned(3), .boolean(true)])
                XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
            }
            await channel.close()
        }
    }

}
