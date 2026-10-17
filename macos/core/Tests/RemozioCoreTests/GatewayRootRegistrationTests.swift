import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayRootRegistrationTests: XCTestCase, @unchecked Sendable {
    private final class Driver: GatewayRootDriver {
        struct State { var calls: [GatewayRootCall] = []; var response: Data?; var closed = false }
        let state = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: GatewayRootCall, reply: @escaping @Sendable (GatewayRootResponse) -> Void) {
            let result: GatewayRootResponse = state.withLock {
                $0.calls.append(call)
                switch call { case .hello: return .version(3); case .synchronize: return .synchronized(true); case .command: return .command($0.response) }
            }
            reply(result)
        }
        func close() { state.withLock { $0.closed = true } }
    }
    private struct Fixture {
        let key = P256.Signing.PrivateKey()
        let limits = try! CBORLimits(maxBytes: 4096, maxDepth: 8, maxItems: 128)
        let token = "synthetic-private-address"
        var registration: GatewayRegistrationIdentity {
            get throws { try .init(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
                lifecycleEpoch: id(5), rootPublicKey: key.publicKey.x963Representation) }
        }
        func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
        func envelope(_ activation: Bool) throws -> GatewayAuthorityEnvelope {
            let binding = try GatewayTokenBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
                lifecycleEpoch: id(5), phoneID: id(6), enrollmentEpoch: id(7), candidateID: id(8),
                tokenDigest: Data(SHA256.hash(data: Data(token.utf8))), challenge: Data(repeating: 9, count: 32),
                enrollmentTag: Data(repeating: 10, count: 32))
            let revision: UInt64 = activation ? 2 : 1, operation = id(activation ? 12 : 11)
            let payload: Data, input: Data
            if activation {
                payload = try GatewayMappingActivation(binding: binding, revision: revision, operationID: operation,
                    issuedAtUnixMillis: 100, expiresAtUnixMillis: 200).encode(limits: limits)
                input = try GatewayRecipientSigningInput.make(wireVersion: 1, kind: .activation,
                    canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
            } else {
                payload = try GatewayTokenCandidate(binding: binding, revision: revision, operationID: operation,
                    issuedAtUnixMillis: 100, expiresAtUnixMillis: 200).encode(limits: limits)
                input = try GatewayTokenCandidateSigningInput.make(wireVersion: 1,
                    canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
            }
            return GatewayAuthorityEnvelope(kind: activation ? 2 : 1, operationID: operation, revision: revision,
                canonicalPayload: payload, signature: try key.signature(for: input).rawRepresentation,
                registrationToken: activation ? nil : token)
        }
    }
    func testLegacyGatewayRejectsOptionalMappingQueryWithoutLosingTheControlConnection() async throws {
        let f = Fixture(), envelope = try f.envelope(false), driver = Driver(), channel = GatewayRootChannel(driver: driver)
        let value = try GatewayTokenCandidate.decode(envelope.canonicalPayload, limits: f.limits), epoch = UUID()
        let owner = try GatewayMappingQueryOwner(scope: GatewayMappingScope(registration: f.registration, binding: value.binding),
            gatewayPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation, clockEpoch: epoch)
        // The old peer rejects the inner payload, after accepting the unchanged outer head command.
        try await channel.start()
        do { _ = try await channel.mappingState(query: owner.query(now: .init(epoch: epoch, milliseconds: 1))); XCTFail() }
        catch { XCTAssertEqual(error as? GatewayRootChannelError, .rejected) }
        XCTAssertFalse(driver.state.withLock { $0.closed })
        driver.state.withLock { $0.response = try? GatewayRootCommand.reply([.bytes(Data([1])), .bytes(Data(repeating: 2, count: 64))]) }
        let response = try await channel.head(query: Data([1]))
        XCTAssertEqual(response.canonicalPayload, Data([1]))
        XCTAssertEqual(driver.state.withLock { $0.calls.count }, 3)
        await channel.close()
    }
    func testExactOriginalReceiptAndDuplicateAdmissionForBothControls() async throws {
        let f = Fixture()
        for activation in [false, true] {
            let e = try f.envelope(activation), driver = Driver(), channel = GatewayRootChannel(driver: driver)
            driver.state.withLock { $0.response = try? GatewayRootCommand.reply([.bytes(e.canonicalPayload), .bytes(e.signature), .boolean(false)]) }
            try await channel.start()
            if activation {
                let result = try await channel.applyTokenActivation(e, registration: f.registration)
                XCTAssertFalse(result.inserted); XCTAssertEqual(result.receipt.operationID, e.operationID)
            } else {
                let result = try await channel.applyTokenCandidate(e, registration: f.registration)
                XCTAssertFalse(result.inserted); XCTAssertEqual(result.receipt.candidate.operationID, e.operationID)
            }
            guard case .command(let bytes) = driver.state.withLock({ $0.calls[1] }) else { return XCTFail() }
            switch try GatewayRootCommand.decode(bytes) {
            case .candidate(_, _, _, let phone, let token): XCTAssertFalse(activation); XCTAssertEqual(phone, f.id(6)); XCTAssertEqual(token, f.token)
            case .recipient(_, _, _, let phone, let kind): XCTAssertTrue(activation); XCTAssertEqual(phone, f.id(6)); XCTAssertEqual(kind, .activation)
            default: XCTFail()
            }
            await channel.close()
        }
    }
    func testMalformedOrDifferentReceiptRetiresChannelWithoutASecondCall() async throws {
        let f = Fixture()
        for activation in [false, true] {
            for mutation in 0..<4 {
                let e = try f.envelope(activation), driver = Driver(), channel = GatewayRootChannel(driver: driver)
                driver.state.withLock { $0.response = try? GatewayRootCommand.reply([
                    .bytes(mutation == 0 ? Data([1]) : e.canonicalPayload),
                    .bytes(mutation == 1 ? Data(repeating: 0, count: 64) : e.signature),
                    mutation == 2 ? .unsigned(1) : .boolean(true)], version: mutation == 3 ? 2 : 1) }
                try await channel.start()
                do {
                    if activation { _ = try await channel.applyTokenActivation(e, registration: f.registration) }
                    else { _ = try await channel.applyTokenCandidate(e, registration: f.registration) }
                    XCTFail()
                } catch {}
                do { _ = try await channel.head(query: Data([1])); XCTFail() }
                catch { XCTAssertEqual(error as? GatewayRootChannelError, .closed) }
                XCTAssertEqual(driver.state.withLock { $0.calls.count }, 2)
                await channel.close()
            }
        }
    }
    func testInvalidOutgoingEnvelopeNeverSendsPrivateFields() async throws {
        let f = Fixture()
        for activation in [false, true] {
            for mutation in 0..<4 {
                let e = try f.envelope(activation), driver = Driver(), channel = GatewayRootChannel(driver: driver)
                let changed = GatewayAuthorityEnvelope(kind: mutation == 0 ? 9 : e.kind,
                    operationID: mutation == 1 ? f.id(99) : e.operationID, revision: e.revision,
                    canonicalPayload: e.canonicalPayload, signature: mutation == 2 ? Data(repeating: 0, count: 64) : e.signature,
                    registrationToken: mutation == 3 ? "wrong-private-token" : e.registrationToken)
                try await channel.start()
                do {
                    if activation { _ = try await channel.applyTokenActivation(changed, registration: f.registration) }
                    else { _ = try await channel.applyTokenCandidate(changed, registration: f.registration) }
                    XCTFail()
                } catch {}
                XCTAssertEqual(driver.state.withLock { $0.calls.count }, 1)
                await channel.close()
            }
        }
    }
}
