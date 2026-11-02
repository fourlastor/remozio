import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayWakeSubmissionTests: XCTestCase {
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func fixture() throws -> (GatewayWakeSubmission, GatewayRegistrationIdentity, GatewayActiveSubmissionCredential, P256.Signing.PrivateKey) {
        let key = P256.Signing.PrivateKey(), root = P256.Signing.PrivateKey()
        let binding = try GatewaySubmissionBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4), lifecycleEpoch: id(5))
        let registration = try GatewayRegistrationIdentity(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: root.publicKey.x963Representation)
        let control = try GatewaySubmissionControl(kind: .rotation, binding: binding, revision: 1, operationID: id(6),
            issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000, credentialID: id(7), publicKey: key.publicKey.x963Representation)
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 128)
        let payload = try control.encode(limits: limits)
        let signature = try root.signature(for: GatewaySubmissionSigningInput.make(wireVersion: 1, kind: .rotation,
            canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)).rawRepresentation
        let credential = GatewayActiveSubmissionCredential(receipt: GatewaySubmissionReceipt(control: control, canonicalPayload: payload, signature: signature))
        let value = try GatewayWakeSubmission(binding: binding, credentialID: id(7), deliveryID: id(8), challenge: id(9, count: 32))
        return (value, registration, credential, key)
    }

    func testWakeSchemaCarriesOnlyScopeCredentialDeliveryAndChallenge() throws {
        let (value, _, _, _) = try fixture(), encoded = try value.encode()
        let decoded = try GatewayWakeSubmission.decode(encoded)
        XCTAssertEqual(try decoded.encode(), encoded)
        XCTAssertEqual(decoded.binding, value.binding); XCTAssertEqual(decoded.deliveryID, id(8))
        XCTAssertEqual(value.description, "GatewayWakeSubmission(redacted)")
        guard case .map(let fields) = try DeterministicCBOR.decode(encoded, limits: GatewayWakeSubmission.limits) else { return XCTFail() }
        XCTAssertEqual(Set(fields.keys), Set(UInt64(0)...4))
        for extra in [CBORValue.unsigned(999999), .text("recipient"), .bytes(id(10))] {
            var changed = fields; changed[5] = extra
            XCTAssertThrowsError(try GatewayWakeSubmission.decode(DeterministicCBOR.encode(.map(changed), limits: GatewayWakeSubmission.limits)))
        }
        for version in [UInt64(0), 2, UInt64.max] {
            var changed = fields; changed[0] = .unsigned(version)
            XCTAssertThrowsError(try GatewayWakeSubmission.decode(DeterministicCBOR.encode(.map(changed), limits: GatewayWakeSubmission.limits)))
        }
    }

    func testPossessionBindsCurrentCredentialScopeAndLiveServerChallenge() throws {
        let (value, registration, credential, key) = try fixture()
        let signature = try key.signature(for: value.signingInput()).rawRepresentation
        XCTAssertNoThrow(try value.authenticate(signature: signature, expectedChallenge: value.challenge, registration: registration, credential: credential))
        XCTAssertThrowsError(try value.authenticate(signature: signature, expectedChallenge: id(10, count: 32), registration: registration, credential: credential))
        let replacement = try GatewayWakeSubmission(binding: value.binding, credentialID: id(11), deliveryID: value.deliveryID, challenge: value.challenge)
        XCTAssertThrowsError(try replacement.authenticate(signature: key.signature(for: replacement.signingInput()).rawRepresentation,
            expectedChallenge: value.challenge, registration: registration, credential: credential)) {
            XCTAssertEqual($0 as? GatewayWakeSubmissionError, .unavailableCredential)
        }
        for changed in 0..<5 {
            var ids = [id(1), id(2), id(3), id(4), id(5)]; ids[changed] = id(12)
            let other = try GatewaySubmissionBinding(ownerID: ids[0], macID: ids[1], accountID: ids[2], gatewayID: ids[3], lifecycleEpoch: ids[4])
            let crossed = try GatewayWakeSubmission(binding: other, credentialID: value.credentialID, deliveryID: value.deliveryID, challenge: value.challenge)
            XCTAssertThrowsError(try crossed.authenticate(signature: key.signature(for: crossed.signingInput()).rawRepresentation,
                expectedChallenge: value.challenge, registration: registration, credential: credential)) {
                XCTAssertEqual($0 as? GatewayWakeSubmissionError, .wrongScope)
            }
        }
    }

    func testWrongKeyDomainDeliveryAndMalformedSignatureCannotAuthenticate() throws {
        let (value, registration, credential, key) = try fixture()
        let limits = try CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 12)
        let wrongDomain = try DeterministicCBOR.encode(.map([0: .text("dev.sebastiano.remozio.macos.gateway"), 1: .unsigned(1),
            2: .unsigned(1), 3: .bytes(value.encode())]), limits: limits)
        for signature in [try P256.Signing.PrivateKey().signature(for: value.signingInput()).rawRepresentation,
                          try key.signature(for: wrongDomain).rawRepresentation, Data(repeating: 0, count: 64), Data(repeating: 0, count: 63)] {
            XCTAssertThrowsError(try value.authenticate(signature: signature, expectedChallenge: value.challenge, registration: registration, credential: credential)) {
                XCTAssertEqual($0 as? GatewayWakeSubmissionError, .invalidSignature)
            }
        }
        let changed = try GatewayWakeSubmission(binding: value.binding, credentialID: value.credentialID, deliveryID: id(13), challenge: value.challenge)
        XCTAssertThrowsError(try changed.authenticate(signature: key.signature(for: value.signingInput()).rawRepresentation,
            expectedChallenge: value.challenge, registration: registration, credential: credential))
        XCTAssertThrowsError(try value.signingInput(wireVersion: 2))
    }
}
