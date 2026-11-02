import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayWakeSignerTests: XCTestCase {
    private func binding(changed: Int? = nil) throws -> GatewaySubmissionBinding {
        let ids = (0..<5).map { (index: Int) in Data(repeating: UInt8(changed == index ? 9 : index + 1), count: 16) }
        return try GatewaySubmissionBinding(ownerID: ids[0], macID: ids[1], accountID: ids[2], gatewayID: ids[3], lifecycleEpoch: ids[4])
    }
    private func configuration(key: P256.Signing.PrivateKey, scope: GatewaySubmissionBinding? = nil,
                               credential: Data = Data(repeating: 6, count: 16), custody: GatewayWakeKeyCustody = .protectedFile,
                               owner: UInt32 = 501, transport: UInt32 = 401, gateway: UInt32 = 402,
                               path: String = "/Library/Remozio/transport/wake.cbor") throws -> GatewayWakeSignerConfiguration {
        try GatewayWakeSignerConfiguration(binding: scope ?? binding(), credentialID: credential, transportUID: transport,
            ownerUID: owner, gatewayUID: gateway, serviceName: "dev.remozio.gateway.wake", teamID: "TEAMID1234",
            gatewayIdentifier: "dev.sebastiano.remozio.macos.gateway", gatewayHashes: [Data(repeating: 7, count: 20)],
            custody: custody, keyRecordPath: path, publicKey: key.publicKey.x963Representation)
    }
    private func record(key: P256.Signing.PrivateKey, scope: GatewaySubmissionBinding? = nil,
                        credential: Data = Data(repeating: 6, count: 16)) throws -> GatewayWakeKeyRecord {
        try GatewayWakeKeyRecord(binding: scope ?? binding(), credentialID: credential, fileKey: key)
    }
    private func load(_ config: GatewayWakeSignerConfiguration, record: GatewayWakeKeyRecord) throws -> GatewayWakeSigner {
        try GatewayWakeSigner.load(configuration: config, realUID: 401, effectiveUID: 401) { path, uid in
            XCTAssertEqual(path, config.keyRecordPath); XCTAssertEqual(uid, config.transportUID)
            return try record.encode()
        }
    }
    func testExplicitFileSignerSignsOnlyWakePurposeAndBoundIdentity() throws {
        let key = P256.Signing.PrivateKey(), config = try configuration(key: key), record = try record(key: key)
        let signer = try load(config, record: record)
        let submission = try GatewayWakeSubmission(binding: binding(), credentialID: config.credentialID,
            deliveryID: Data(repeating: 8, count: 16), challenge: Data(repeating: 9, count: 32))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signer.sign(submission))
        XCTAssertTrue(try key.publicKey.isValidSignature(signature, for: submission.signingInput()))
        XCTAssertFalse(try key.publicKey.isValidSignature(signature, for: submission.encode()))
        XCTAssertEqual(signer.publicKey, config.publicKey)
        XCTAssertEqual(signer.description, "GatewayWakeSigner(redacted)")
        XCTAssertEqual(record.debugDescription, "GatewayWakeKeyRecord(redacted)")
        for index in 0..<5 {
            let wrong = try GatewayWakeSubmission(binding: binding(changed: index), credentialID: config.credentialID,
                deliveryID: submission.deliveryID, challenge: submission.challenge)
            XCTAssertThrowsError(try signer.sign(wrong)) { XCTAssertEqual($0 as? GatewayWakeSignerError, .wrongIdentity) }
        }
        let rotated = try GatewayWakeSubmission(binding: binding(), credentialID: Data(repeating: 10, count: 16),
            deliveryID: submission.deliveryID, challenge: submission.challenge)
        XCTAssertThrowsError(try signer.sign(rotated)) { XCTAssertEqual($0 as? GatewayWakeSignerError, .wrongIdentity) }
    }
    func testConfigurationAndRecordCanonicalRoundTripsRetainExplicitCustody() throws {
        let key = P256.Signing.PrivateKey()
        for custody in [GatewayWakeKeyCustody.protectedFile, .secureEnclave] {
            let config = try configuration(key: key, custody: custody)
            let restored = try GatewayWakeSignerConfiguration.decode(config.canonicalBytes)
            XCTAssertEqual(restored.canonicalBytes, config.canonicalBytes); XCTAssertEqual(restored.custody, custody)
            XCTAssertEqual(restored.binding, config.binding); XCTAssertEqual(restored.gatewayPolicy.expectedUserID, 402)
            XCTAssertEqual(restored.debugDescription, "GatewayWakeSignerConfiguration(redacted)")
        }
        let original = try record(key: key)
        XCTAssertEqual(try GatewayWakeKeyRecord.decode(original.encode()).encode(), try original.encode())
    }
    func testDedicatedAccountValidationPrecedesAnyKeyRead() throws {
        let config = try configuration(key: P256.Signing.PrivateKey())
        for (real, effective): (UInt32, UInt32) in [(0, 0), (501, 501), (402, 402), (401, 0), (0, 401)] {
            XCTAssertThrowsError(try GatewayWakeSigner.load(configuration: config, realUID: real, effectiveUID: effective,
                read: { _, _ in XCTFail("Wrong accounts must not read key bytes"); return Data() })) {
                XCTAssertEqual($0 as? GatewayWakeSignerError, .wrongAccount)
            }
        }
    }
    func testRecordSubstitutionCannotChangeScopeCredentialPublicKeyOrCustody() throws {
        let key = P256.Signing.PrivateKey(), config = try configuration(key: key)
        for index in 0..<5 {
            XCTAssertThrowsError(try load(config, record: record(key: key, scope: binding(changed: index)))) {
                XCTAssertEqual($0 as? GatewayWakeSignerError, .wrongIdentity)
            }
        }
        XCTAssertThrowsError(try load(config, record: record(key: key, credential: Data(repeating: 11, count: 16))))
        XCTAssertThrowsError(try load(config, record: record(key: P256.Signing.PrivateKey())))
        let hardware = try GatewayWakeKeyRecord(binding: binding(), credentialID: config.credentialID, publicKey: config.publicKey,
            custody: .secureEnclave, representation: Data(repeating: 1, count: 32))
        XCTAssertThrowsError(try load(config, record: hardware)) { XCTAssertEqual($0 as? GatewayWakeSignerError, .wrongIdentity) }
        XCTAssertThrowsError(try load(configuration(key: key, custody: .secureEnclave), record: record(key: key))) {
            XCTAssertEqual($0 as? GatewayWakeSignerError, .wrongIdentity)
        }
    }
    func testFileKeyBytesMustMatchTheProtectedPublicPin() throws {
        let key = P256.Signing.PrivateKey(), config = try configuration(key: key)
        for bytes in [P256.Signing.PrivateKey().rawRepresentation, Data(repeating: 0, count: 32)] {
            let wrong = try GatewayWakeKeyRecord(binding: binding(), credentialID: config.credentialID, publicKey: config.publicKey,
                custody: .protectedFile, representation: bytes)
            XCTAssertThrowsError(try load(config, record: wrong)) { XCTAssertEqual($0 as? GatewayWakeSignerError, .invalidRecord) }
        }
    }
    func testReadFailureIsPropagatedWithoutAnotherLookupOrNewKey() throws {
        enum ReadError: Error { case unavailable }
        let config = try configuration(key: P256.Signing.PrivateKey())
        var reads = 0
        XCTAssertThrowsError(try GatewayWakeSigner.load(configuration: config, realUID: 401, effectiveUID: 401, read: { _, _ in
            reads += 1; throw ReadError.unavailable
        })) { XCTAssertTrue($0 is ReadError) }
        XCTAssertEqual(reads, 1)
    }
    func testRejectsUnprotectedPathsAndSharedAccounts() throws {
        let key = P256.Signing.PrivateKey()
        for path in ["relative", "/", "/tmp//key", "/tmp/../key", "/tmp/./key", "/tmp/key\0"] {
            XCTAssertThrowsError(try configuration(key: key, path: path))
        }
        for (owner, transport, gateway): (UInt32, UInt32, UInt32) in [(0, 401, 402), (501, 0, 402),
            (501, 401, 0), (501, 501, 402), (501, 401, 401), (501, 401, 501), (501, UInt32.max, 402)] {
            XCTAssertThrowsError(try configuration(key: key, owner: owner, transport: transport, gateway: gateway))
        }
    }
    func testUnknownSchemaFieldsCustodyAndDuplicatePinsAreRejected() throws {
        let config = try configuration(key: P256.Signing.PrivateKey()), limits = try CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 128)
        guard case .map(let fields) = try DeterministicCBOR.decode(config.canonicalBytes, limits: limits) else { return XCTFail() }
        var mutations = [fields, fields, fields, fields]
        mutations[0][0] = .unsigned(2); mutations[1][14] = .null; mutations[2][10] = .unsigned(3)
        mutations[3][9] = .array([.bytes(Data(repeating: 7, count: 20)), .bytes(Data(repeating: 7, count: 20))])
        for mutation in mutations {
            XCTAssertThrowsError(try GatewayWakeSignerConfiguration.decode(DeterministicCBOR.encode(.map(mutation), limits: limits)))
        }
        let record = try record(key: P256.Signing.PrivateKey())
        guard case .map(let recordFields) = try DeterministicCBOR.decode(record.encode(), limits: limits) else { return XCTFail() }
        var invalid = recordFields; invalid[0] = .unsigned(2)
        XCTAssertThrowsError(try GatewayWakeKeyRecord.decode(DeterministicCBOR.encode(.map(invalid), limits: limits)))
        invalid = recordFields; invalid[5] = .bytes(Data())
        XCTAssertThrowsError(try GatewayWakeKeyRecord.decode(DeterministicCBOR.encode(.map(invalid), limits: limits)))
    }
}
