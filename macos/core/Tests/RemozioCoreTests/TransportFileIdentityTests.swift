import CryptoKit
import Foundation
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

final class TransportFileIdentityTests: XCTestCase {
    private let path = "/Library/Application Support/Remozio/transport/identity.cbor"
    private func configuration(source: ApprovalTransportIdentitySource, pin: Data) throws -> ApprovalTransportConfiguration {
        try ApprovalTransportConfiguration(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            ownerUID: 501, serviceUID: 401, authorityServiceName: "dev.sebastiano.remozio.macos.authority",
            teamID: "TEAMID1234", authorityIdentifier: "dev.sebastiano.remozio.macos.authority", authorityHashes: [Data(repeating: 3, count: 20)],
            identitySource: source, identityPublicKeyInfo: pin)
    }
    private func encode(_ fields: [UInt64: CBORValue]) throws -> Data {
        try DeterministicCBOR.encode(.map(fields), limits: CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 128))
    }
    private func fields(key: P256.Signing.PrivateKey, certificate: Data) -> [UInt64: CBORValue] {
        [0: .unsigned(1), 1: .text("remozio-transport-identity"), 2: .bytes(key.x963Representation), 3: .bytes(certificate)]
    }

    func testExplicitFileConfigurationPreservesVersionOneAndRejectsCustodyTypeConfusion() throws {
        let pin = P256.Signing.PrivateKey().publicKey.derRepresentation
        let file = try configuration(source: .protectedFile(path: path), pin: pin)
        let hardware = try configuration(source: .secureEnclaveKeychain(reference: Data([1])), pin: pin)
        for original in [file, hardware] {
            let decoded = try ApprovalTransportConfiguration.decode(original.canonicalBytes)
            XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
            XCTAssertEqual(decoded.identitySource, original.identitySource)
        }
        XCTAssertNil(file.identityReference)
        XCTAssertEqual(hardware.identityReference, Data([1]))
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 128)
        guard case .map(let original) = try DeterministicCBOR.decode(file.canonicalBytes, limits: limits) else { return XCTFail() }
        XCTAssertEqual(original[0], .unsigned(2)); XCTAssertEqual(original[9], .text(path))
        for (field, value): (UInt64, CBORValue?) in [(0, .unsigned(1)), (0, .unsigned(3)), (9, .bytes(Data([1]))),
                                                 (9, nil), (14, .null)] {
            var changed = original; changed[field] = value
            XCTAssertThrowsError(try ApprovalTransportConfiguration.decode(encode(changed)))
        }
        for invalid in ["", "/", "relative", "/a//key", "/a/../key", "/a/./key", "/a/key/", "/a/ke\0y", "/" + String(repeating: "x", count: 256)] {
            XCTAssertThrowsError(try configuration(source: .protectedFile(path: invalid), pin: pin))
        }
    }

    func testConfiguredFileDoesNotSearchKeychainAndRetainsIdentityAcrossReloads() throws {
        let key = P256.Signing.PrivateKey(), certificate = try certificate(key)
        let encoded = try encode(fields(key: key, certificate: certificate))
        let configuration = try configuration(source: .protectedFile(path: path), pin: key.publicKey.derRepresentation)
        var reads = 0
        for _ in 0..<2 {
            let identity = try ApprovalTransportIdentity.load(configuration: configuration, lookup: { _ in
                XCTFail("File custody must not search a keychain")
                return (errSecItemNotFound, nil)
            }, readFile: { path, uid in
                reads += 1; XCTAssertEqual(path, self.path); XCTAssertEqual(uid, 401)
                return encoded
            })
            var privateKey: SecKey?
            XCTAssertEqual(SecIdentityCopyPrivateKey(identity, &privateKey), errSecSuccess)
            let message = Data("disposable transport signing test".utf8)
            let signature = try XCTUnwrap(SecKeyCreateSignature(try XCTUnwrap(privateKey),
                .ecdsaSignatureMessageX962SHA256, message as CFData, nil) as Data?)
            XCTAssertTrue(try key.publicKey.isValidSignature(P256.Signing.ECDSASignature(derRepresentation: signature), for: message))
        }
        XCTAssertEqual(reads, 2)
        XCTAssertThrowsError(try ApprovalTransportIdentity.load(configuration: configuration, lookup: { _ in
            XCTFail("Unreadable file must not trigger a keychain fallback")
            return (errSecSuccess, nil)
        }, readFile: { _, _ in throw ApprovalTransportStartupError.identityUnavailable }))
        XCTAssertThrowsError(try ApprovalTransportIdentity.load(configuration: configuration)) {
            XCTAssertEqual($0 as? ApprovalTransportStartupError, .wrongAccount)
        }
    }

    func testRejectsWrongCertificateKeyWrongPinAndExpiredCertificates() throws {
        let key = P256.Signing.PrivateKey(), other = P256.Signing.PrivateKey()
        for (certificate, pin) in [(try certificate(other), key.publicKey.derRepresentation),
                                   (try certificate(key), other.publicKey.derRepresentation),
                                   (try certificate(key, before: -600, after: -300), key.publicKey.derRepresentation),
                                   (try certificate(key, before: 300, after: 600), key.publicKey.derRepresentation)] {
            XCTAssertThrowsError(try TransportFileIdentity.load(bytes: encode(fields(key: key, certificate: certificate)), publicKeyInfo: pin))
        }
    }

    func testSoftwareIdentityCannotSatisfyHardwareCustody() throws {
        let key = P256.Signing.PrivateKey()
        let identity = try TransportFileIdentity.load(bytes: encode(fields(key: key, certificate: certificate(key))),
            publicKeyInfo: key.publicKey.derRepresentation)
        let hardware = try configuration(source: .secureEnclaveKeychain(reference: Data([1])), pin: key.publicKey.derRepresentation)
        XCTAssertThrowsError(try ApprovalTransportIdentity.load(configuration: hardware, lookup: { _ in
            (errSecSuccess, identity)
        }, readFile: { _, _ in
            XCTFail("A software keychain identity must not trigger file fallback")
            return Data()
        })) { XCTAssertEqual($0 as? ApprovalTransportStartupError, .invalidIdentity) }
    }

    func testRejectsUnknownSchemaRolesMalformedKeysAndAmbiguousEncoding() throws {
        let key = P256.Signing.PrivateKey(), original = fields(key: key, certificate: try certificate(key))
        for (field, value): (UInt64, CBORValue?) in [(0, .unsigned(2)), (1, .text("remozio-authority-identity")),
            (2, .bytes(Data(repeating: 0, count: 97))), (2, .bytes(key.rawRepresentation)),
            (2, .bytes(P384.Signing.PrivateKey().x963Representation)), (3, .bytes(Data([0x30, 0]))),
            (3, .bytes(Data(repeating: 0, count: 8193))), (3, nil), (4, .null)] {
            var changed = original; changed[field] = value
            XCTAssertThrowsError(try TransportFileIdentity.load(bytes: encode(changed), publicKeyInfo: key.publicKey.derRepresentation))
        }
        var inconsistent = key.x963Representation
        inconsistent.replaceSubrange(0..<65, with: P256.Signing.PrivateKey().publicKey.x963Representation)
        var changed = original; changed[2] = .bytes(inconsistent)
        XCTAssertThrowsError(try TransportFileIdentity.load(bytes: encode(changed), publicKeyInfo: key.publicKey.derRepresentation))
        let canonical = try encode(original)
        for bytes in [Data(), canonical + Data([0]), Data(canonical.dropLast()), Data(repeating: 0, count: 16385)] {
            XCTAssertThrowsError(try TransportFileIdentity.load(bytes: bytes, publicKeyInfo: key.publicKey.derRepresentation))
        }
    }

    // Synthetic, short-lived certificates only. This helper does not issue production certificates or persist keys.
    private func certificate(_ key: P256.Signing.PrivateKey, before: TimeInterval = -60, after: TimeInterval = 300) throws -> Data {
        func der(_ tag: UInt8, _ bytes: Data) -> Data {
            let count = bytes.count
            let length: [UInt8] = count < 128 ? [UInt8(count)] : count < 256 ? [0x81, UInt8(count)] : [0x82, UInt8(count >> 8), UInt8(count & 255)]
            return Data([tag] + length) + bytes
        }
        func sequence(_ bytes: Data) -> Data { der(0x30, bytes) }
        let algorithm = sequence(Data([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]))
        let subject = sequence(der(0x31, sequence(Data([0x06, 0x03, 0x55, 0x04, 0x03]) + der(0x0c, Data("disposable-remozio-transport".utf8)))))
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        let now = Date()
        let validity = sequence(der(0x17, Data(formatter.string(from: now.addingTimeInterval(before)).utf8))
            + der(0x17, Data(formatter.string(from: now.addingTimeInterval(after)).utf8)))
        let tbs = sequence(Data([0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01])
            + algorithm + subject + validity + subject + key.publicKey.derRepresentation)
        return sequence(tbs + algorithm + der(0x03, Data([0]) + (try key.signature(for: tbs)).derRepresentation))
    }
}
