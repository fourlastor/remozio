import CryptoKit
import Foundation
import RemozioProtocol
import Security
import XCTest
import X509
@testable import RemozioCore

final class TransportTLSCertificateTests: XCTestCase {
    private func native(_ key: P256.Signing.PrivateKey) throws -> SecKey {
        try XCTUnwrap(SecKeyCreateWithData(key.x963Representation as CFData,
            [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate,
             kSecAttrKeySizeInBits: 256] as CFDictionary, nil))
    }

    func testNativeLeafUsesSameKeyForBothTLSRolesAndRejectsWrongPin() throws {
        let key = P256.Signing.PrivateKey(), now = Date()
        let encoded = try TransportTLSCertificate.issue(key: native(key),
            notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
        let certificate = try Certificate(try XCTUnwrap(SecCertificateCreateWithData(nil, encoded as CFData)))
        XCTAssertEqual(certificate.version, .v3)
        XCTAssertEqual(certificate.issuer, certificate.subject)
        XCTAssertEqual(certificate.signatureAlgorithm, .ecdsaWithSHA256)
        XCTAssertTrue(certificate.publicKey.isValidSignature(certificate.signature, for: certificate))
        XCTAssertEqual(try certificate.extensions.basicConstraints, .notCertificateAuthority)
        XCTAssertEqual(try certificate.extensions.keyUsage, KeyUsage(digitalSignature: true))
        XCTAssertEqual(try certificate.extensions.extendedKeyUsage, try ExtendedKeyUsage([.serverAuth, .clientAuth]))
        let pin = try PinnedTLSPeer(subjectPublicKeyInfo: key.publicKey.derRepresentation)
        XCTAssertTrue(pin.accepts(certificate: encoded, at: now))
        XCTAssertFalse(pin.accepts(certificate: encoded, at: now.addingTimeInterval(-120)))
        XCTAssertFalse(pin.accepts(certificate: encoded, at: now.addingTimeInterval(660)))
        XCTAssertFalse(try PinnedTLSPeer(subjectPublicKeyInfo: P256.Signing.PrivateKey().publicKey.derRepresentation)
            .accepts(certificate: encoded, at: now))
    }

    func testWholeSecondEncodingCannotExtendRequestedValidity() throws {
        let key = try native(P256.Signing.PrivateKey())
        let encoded = try TransportTLSCertificate.issue(key: key,
            notValidBefore: Date(timeIntervalSince1970: 1_800_000_000.25),
            notValidAfter: Date(timeIntervalSince1970: 1_800_000_600.75))
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil, encoded as CFData))
        let before = try XCTUnwrap(SecCertificateCopyNotValidBeforeDate(certificate))
        let after = try XCTUnwrap(SecCertificateCopyNotValidAfterDate(certificate))
        XCTAssertEqual(CFDateGetAbsoluteTime(before), Date(timeIntervalSince1970: 1_800_000_001).timeIntervalSinceReferenceDate)
        XCTAssertEqual(CFDateGetAbsoluteTime(after), Date(timeIntervalSince1970: 1_800_000_600).timeIntervalSinceReferenceDate)
    }

    func testIssuingAnotherCertificateRetainsPinButChangesSerialAndSignature() throws {
        let key = P256.Signing.PrivateKey(), nativeKey = try native(key), now = Date()
        let first = try TransportTLSCertificate.issue(key: nativeKey,
            notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
        let next = try TransportTLSCertificate.issue(key: nativeKey,
            notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(1200))
        let a = try Certificate(try XCTUnwrap(SecCertificateCreateWithData(nil, first as CFData)))
        let b = try Certificate(try XCTUnwrap(SecCertificateCreateWithData(nil, next as CFData)))
        XCTAssertEqual(a.publicKey, b.publicKey)
        XCTAssertNotEqual(a.serialNumber, b.serialNumber)
        XCTAssertNotEqual(a.signature, b.signature)
        for encoded in [first, next] {
            XCTAssertTrue(try PinnedTLSPeer(subjectPublicKeyInfo: key.publicKey.derRepresentation)
                .accepts(certificate: encoded, at: now))
        }
    }

    func testRejectsPublicOrNonP256KeysAndUnrepresentableValidity() throws {
        let key = try native(P256.Signing.PrivateKey()), now = Date()
        let other = P384.Signing.PrivateKey()
        let p384 = try XCTUnwrap(SecKeyCreateWithData(other.x963Representation as CFData,
            [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate,
             kSecAttrKeySizeInBits: 384] as CFDictionary, nil))
        for invalid in [try XCTUnwrap(SecKeyCopyPublicKey(key)), p384] {
            XCTAssertThrowsError(try TransportTLSCertificate.issue(key: invalid,
                notValidBefore: now, notValidAfter: now.addingTimeInterval(600))) {
                XCTAssertEqual($0 as? TransportTLSCertificateError, .invalidKey)
            }
        }
        for (before, after) in [(now, now), (now, now.addingTimeInterval(-1)),
            (Date(timeIntervalSince1970: .nan), now), (now, Date(timeIntervalSince1970: .infinity)),
            (Date(timeIntervalSince1970: -62_135_596_801), now),
            (now, Date(timeIntervalSince1970: 253_402_300_800)),
            (Date(timeIntervalSince1970: 100.1), Date(timeIntervalSince1970: 100.9))] {
            XCTAssertThrowsError(try TransportTLSCertificate.issue(key: key, notValidBefore: before, notValidAfter: after)) {
                XCTAssertEqual($0 as? TransportTLSCertificateError, .invalidValidity)
            }
        }
    }

    func testFileProducerLoadsIntoNativeIdentityWithoutChangingPublicKeyForms() throws {
        let now = Date()
        let created = try TransportFileIdentity.create(notValidBefore: now.addingTimeInterval(-60),
            notValidAfter: now.addingTimeInterval(600))
        let pin = try P256.Signing.PublicKey(derRepresentation: created.subjectPublicKeyInfo)
        XCTAssertEqual(pin.x963Representation, created.publicKeyX963)
        guard case .map(let fields) = try DeterministicCBOR.decode(created.encoded,
            limits: CBORLimits(maxBytes: 16384, maxDepth: 1, maxItems: 9)), case .bytes(let privateBytes) = fields[2] else {
            return XCTFail("Missing explicit transport file key")
        }
        XCTAssertEqual(try P256.Signing.PrivateKey(x963Representation: privateBytes).publicKey.derRepresentation,
            created.subjectPublicKeyInfo)
        for _ in 0..<2 {
            let identity = try TransportFileIdentity.load(bytes: created.encoded, publicKeyInfo: created.subjectPublicKeyInfo)
            var key: SecKey?
            XCTAssertEqual(SecIdentityCopyPrivateKey(identity, &key), errSecSuccess)
            let message = Data("transport file producer native signing".utf8)
            let signature = try XCTUnwrap(SecKeyCreateSignature(try XCTUnwrap(key), .ecdsaSignatureMessageX962SHA256,
                message as CFData, nil) as Data?)
            XCTAssertTrue(try pin.isValidSignature(P256.Signing.ECDSASignature(derRepresentation: signature), for: message))
        }
        let other = try TransportFileIdentity.create(notValidBefore: now.addingTimeInterval(-60),
            notValidAfter: now.addingTimeInterval(600))
        XCTAssertNotEqual(other.subjectPublicKeyInfo, created.subjectPublicKeyInfo)
        XCTAssertThrowsError(try TransportFileIdentity.load(bytes: created.encoded, publicKeyInfo: other.subjectPublicKeyInfo))
    }
}
