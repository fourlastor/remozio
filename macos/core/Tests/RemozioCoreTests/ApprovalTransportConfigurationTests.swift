import CryptoKit
import Foundation
import LocalAuthentication
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

final class ApprovalTransportConfigurationTests: XCTestCase {
    private func configuration(owner: UInt32 = 501, service: UInt32 = 401, reference: Data = Data([1, 2, 3])) throws -> ApprovalTransportConfiguration {
        try ApprovalTransportConfiguration(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            ownerUID: owner, serviceUID: service, authorityServiceName: "dev.remozio.authority",
            teamID: "TEAMID1234", authorityIdentifier: "dev.remozio.authority", authorityHashes: [Data(repeating: 3, count: 20)],
            identityReference: reference, identityPublicKeyInfo: P256.Signing.PrivateKey().publicKey.derRepresentation)
    }

    func testNativeProcessValidationPrecedesPrivateAccessAndMapsLookupFailure() throws {
        let own = getuid(), other: uid_t = own == 601 ? 602 : 601
        guard own > 0 else { throw XCTSkip("Ordinary-user fixture") }
        let value = try configuration(owner: other, service: own)
        var calls = 0
        try value.requireNativeProcess { service, owner in
            calls += 1; XCTAssertEqual(service, own); XCTAssertEqual(owner, other)
        }
        XCTAssertEqual(calls, 1)
        XCTAssertThrowsError(try value.requireNativeProcess { _, _ in throw DedicatedServiceAccountError.unsafeAccount }) {
            XCTAssertEqual($0 as? ApprovalTransportStartupError, .wrongAccount)
        }
        XCTAssertThrowsError(try value.requireNativeProcess()) {
            XCTAssertEqual($0 as? ApprovalTransportStartupError, .wrongAccount)
        }
    }
    func testCanonicalRoundTripFixesRootAuthorityAndDedicatedUID() throws {
        let original = try configuration()
        let loaded = try ApprovalTransportConfiguration.decode(original.canonicalBytes)
        XCTAssertEqual(loaded.canonicalBytes, original.canonicalBytes)
        XCTAssertEqual(loaded.authorityPolicy.expectedUserID, 0)
        XCTAssertEqual(loaded.serviceUID, 401)
        XCTAssertEqual(loaded.description, "ApprovalTransportConfiguration(redacted)")
        try loaded.requireProcess(realUID: 401, effectiveUID: 401)
        let accounts: [(UInt32, UInt32)] = [(0, 0), (501, 501), (401, 0), (0, 401)]
        for (real, effective) in accounts {
            XCTAssertThrowsError(try loaded.requireProcess(realUID: real, effectiveUID: effective))
        }
    }
    func testRejectsOwnerRootAndUnboundedKeychainReferences() throws {
        let accounts: [(UInt32, UInt32)] = [(0, 401), (501, 0), (501, 501), (501, UInt32.max)]
        for (owner, service) in accounts {
            XCTAssertThrowsError(try configuration(owner: owner, service: service))
        }
        XCTAssertThrowsError(try configuration(reference: Data()))
        XCTAssertThrowsError(try configuration(reference: Data(repeating: 1, count: 4097)))
    }
    func testRejectsUnknownVersionsFieldsAndDuplicatePins() throws {
        let original = try configuration()
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 128)
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        var mutations = [fields, fields, fields]
        mutations[0][0] = .unsigned(2)
        mutations[1][14] = .null
        mutations[2][8] = .array([.bytes(Data(repeating: 3, count: 20)), .bytes(Data(repeating: 3, count: 20))])
        for values in mutations {
            XCTAssertThrowsError(try ApprovalTransportConfiguration.decode(DeterministicCBOR.encode(.map(values), limits: limits)))
        }
    }
    func testExactIdentityLookupDisallowsUIAndDoesNotTryAnotherKey() throws {
        let configuration = try configuration()
        let reference = try XCTUnwrap(configuration.identityReference)
        var calls = 0
        XCTAssertThrowsError(try ApprovalTransportIdentity.load(configuration: configuration, lookup: { query in
            calls += 1
            let fields = query as NSDictionary
            XCTAssertEqual(fields[kSecClass] as? String, kSecClassIdentity as String)
            XCTAssertEqual(fields[kSecMatchItemList] as? [Data], [reference])
            XCTAssertEqual(fields[kSecMatchLimit] as? String, kSecMatchLimitOne as String)
            XCTAssertEqual((fields[kSecUseAuthenticationContext] as? LAContext)?.interactionNotAllowed, true)
            return (errSecInteractionNotAllowed, nil)
        }, readFile: { _, _ in
            XCTFail("A failed hardware lookup must not read a software key")
            return Data()
        })) { XCTAssertEqual($0 as? ApprovalTransportStartupError, .identityUnavailable) }
        XCTAssertEqual(calls, 1)
        XCTAssertThrowsError(try ApprovalTransportIdentity.load(configuration: configuration, lookup: { _ in
            (errSecSuccess, "wrong item type" as CFString)
        })) { XCTAssertEqual($0 as? ApprovalTransportStartupError, .invalidIdentity) }
    }
}
