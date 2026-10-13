import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class EnclaveAuthorityRequestSignerTests: XCTestCase {
    private func id(_ value: UInt8) -> Data { Data(repeating: value, count: 16) }
    private func configuration() throws -> AuthorityServiceConfiguration {
        try AuthorityServiceConfiguration(macID: id(1), accountID: id(2), journalDirectory: "/private/tmp/remozio-test-journal",
            serviceName: "dev.remozio.authority.test", teamID: "ABCDEFGHIJ", transportIdentifier: "dev.remozio.transport",
            transportHashes: [Data(repeating: 3, count: 20)], transportUID: 501)
    }
    func testRecordRoundTripsBoundedWrappedBytesAndRedactsDescription() throws {
        let key = P256.Signing.PrivateKey()
        for count in [1, 16_384] {
            let record = try AuthoritySigningKeyRecord(macID: id(1), accountID: id(2),
                publicKey: key.publicKey.x963Representation, representation: Data(repeating: 0x55, count: count))
            let bytes = try record.encode(), decoded = try AuthoritySigningKeyRecord.decode(bytes)
            XCTAssertLessThanOrEqual(bytes.count, AuthoritySigningKeyRecord.maximumBytes)
            XCTAssertEqual(decoded.macID, record.macID); XCTAssertEqual(decoded.accountID, record.accountID)
            XCTAssertEqual(decoded.publicKey, record.publicKey); XCTAssertEqual(try decoded.encode(), bytes)
            XCTAssertEqual(record.description, "AuthoritySigningKeyRecord(redacted)")
        }
    }
    func testRecordRejectsUnknownSchemaWrongScopeShapeAndMalformedKeyStorage() throws {
        let key = P256.Signing.PrivateKey(), publicKey = key.publicKey.x963Representation
        let record = try AuthoritySigningKeyRecord(macID: id(1), accountID: id(2), publicKey: publicKey, representation: Data([1]))
        let limits = try CBORLimits(maxBytes: 20_000, maxDepth: 2, maxItems: 16)
        guard case .map(let fields) = try DeterministicCBOR.decode(record.encode(), limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .bytes(Data(count: 15))),
            (2, .bytes(Data(count: 17))), (3, .bytes(Data(count: 65))), (4, .bytes(Data())),
            (4, .bytes(Data(count: 16_385))), (4, .text("key")), (5, .null)] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try AuthoritySigningKeyRecord.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        for bytes in [Data(), try record.encode() + Data([0]), Data(count: AuthoritySigningKeyRecord.maximumBytes + 1)] {
            XCTAssertThrowsError(try AuthoritySigningKeyRecord.decode(bytes))
        }
    }
    func testIdentityMismatchRejectsBeforeHardwareRestore() throws {
        let key = P256.Signing.PrivateKey(), config = try configuration()
        for (mac, account, pin) in [(id(3), id(2), key.publicKey.x963Representation),
            (id(1), id(3), key.publicKey.x963Representation), (id(1), id(2), P256.Signing.PrivateKey().publicKey.x963Representation)] {
            let record = try AuthoritySigningKeyRecord(macID: mac, accountID: account, publicKey: key.publicKey.x963Representation,
                representation: Data([1]))
            XCTAssertThrowsError(try EnclaveAuthorityRequestSigner.restore(record.encode(), configuration: config, expectedPublicKey: pin)) {
                XCTAssertEqual($0 as? AuthorityRequestSignerError, .wrongIdentity)
            }
        }
    }
    func testSoftwarePrivateKeyCannotBecomeAnAuthoritySigner() throws {
        let software = P256.Signing.PrivateKey(), config = try configuration()
        for bytes in [software.rawRepresentation, software.derRepresentation] {
            let record = try AuthoritySigningKeyRecord(macID: id(1), accountID: id(2),
                publicKey: software.publicKey.x963Representation, representation: bytes)
            XCTAssertThrowsError(try EnclaveAuthorityRequestSigner.restore(record.encode(), configuration: config,
                expectedPublicKey: software.publicKey.x963Representation)) {
                XCTAssertEqual($0 as? AuthorityRequestSignerError, .unavailable)
            }
        }
    }
    func testSoftwareBlobCannotPassTheSetupHardwareProof() throws {
        let software = P256.Signing.PrivateKey()
        let record = try AuthoritySigningKeyRecord(macID: id(1), accountID: id(2),
            publicKey: software.publicKey.x963Representation, representation: software.rawRepresentation)
        XCTAssertThrowsError(try record.verifyProvisioningHardware()) {
            XCTAssertEqual($0 as? AuthorityRequestSignerError, .unavailable)
        }
    }
    func testDisposableHardwareKeyRestoresAndSignsWithoutAuthenticationUI() throws {
        guard SecureEnclave.isAvailable else { throw XCTSkip("Requires Secure Enclave hardware; pre-login custody remains unproved") }
        let context = LAContext(); context.interactionNotAllowed = true
        defer { context.invalidate() }
        var failure: Unmanaged<CFError>?
        let access = try XCTUnwrap(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage, &failure))
        let original = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
        let record = try AuthoritySigningKeyRecord(macID: id(1), accountID: id(2), key: original)
        let restored = try EnclaveAuthorityRequestSigner.restore(record.encode(), configuration: configuration(),
            expectedPublicKey: original.publicKey.x963Representation)
        let message = Data("Remozio disposable provider signer test".utf8)
        let signature = try restored.sign(message)
        XCTAssertTrue(try original.publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: signature), for: message))
        XCTAssertEqual(restored.publicKey, original.publicKey.x963Representation)
        XCTAssertEqual(restored.description, "EnclaveAuthorityRequestSigner(redacted)")
        let other = P256.Signing.PrivateKey()
        let substituted = try AuthoritySigningKeyRecord(macID: id(1), accountID: id(2), publicKey: other.publicKey.x963Representation,
            representation: original.dataRepresentation)
        XCTAssertThrowsError(try EnclaveAuthorityRequestSigner.restore(substituted.encode(), configuration: configuration(),
            expectedPublicKey: other.publicKey.x963Representation)) {
            XCTAssertEqual($0 as? AuthorityRequestSignerError, .wrongIdentity)
        }
    }
}
