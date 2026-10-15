import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimePreparationMaterialTests: XCTestCase {
    private struct Refused: Error {}
    private func fixture(_ body: (AccountPreparationFixture, AccountPreparationIntent, ServiceAccountPlan, ProtectedSetupDirectory) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner storage fixture") }
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        let services = try plan(account)
        let directory = try ProtectedSetupDirectory(anchor: f.root.path, relativePath: "runtime", owner: getuid())
        defer { directory.close() }
        try body(f, account, services, directory)
    }
    private func plan(_ account: AccountPreparationIntent) throws -> ServiceAccountPlan {
        let claims = try [ServiceAccountClaim(accountID: account.accountID, role: .transport, number: 20000,
            userID: UUID(), groupID: UUID()), .init(accountID: account.accountID, role: .gateway, number: 20001,
            userID: UUID(), groupID: UUID())]
        return try .init(account: account, planID: AccountPreparationIntent.randomID(), claims: claims)
    }
    private func material(_ services: ServiceAccountPlan) throws -> RuntimePreparationMaterial {
        let now = Date()
        return try .create(services: services, notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
    }
    private func path(_ directory: ProtectedSetupDirectory) -> String {
        directory.path + "/" + AdministrativeSetupPublication.File.runtimeRecord.name
    }
    private func restore(_ directory: ProtectedSetupDirectory, _ account: AccountPreparationIntent, _ plan: ServiceAccountPlan,
                         expected: RuntimeMaterialReference? = nil, verify: () throws -> Void = {},
                         make: () throws -> RuntimePreparationMaterial,
                         stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RuntimePreparationMaterial {
        try RuntimeMaterialPreparation.restoreOrCreate(directory: directory, owner: getuid(), account: account,
            services: plan, expected: expected, verifyCurrent: verify, make: make, didStage: stage)
    }

    func testScopedMaterialRoundTripKeepsSecretOutsideTheMachineReference() throws {
        try fixture { _, account, services, _ in
            let value = try material(services), encoded = try value.encoded
            let decoded = try RuntimePreparationMaterial.decode(encoded), reference = try value.reference
            XCTAssertEqual(try decoded.reference, reference)
            XCTAssertEqual(reference.materialDigest, Data(SHA256.hash(data: encoded)))
            XCTAssertEqual(try RuntimeMaterialReference.decode(reference.encoded), reference)
            XCTAssertNoThrow(try reference.validate(account: account, services: services))
            XCTAssertEqual(try reference.transportPublicKeyX963,
                try P256.Signing.PublicKey(derRepresentation: reference.transportPublicKeyInfo).x963Representation)
            XCTAssertEqual(reference.gateway.rootPublicKey, services.authorityPublicKey)
            XCTAssertNil(try reference.encoded.range(of: value.transportIdentity))
            XCTAssertEqual(String(reflecting: value), "RuntimePreparationMaterial(redacted)")
        }
    }

    func testLostPublicationAcknowledgmentRetainsTheKeyAndAllGatewayIdentifiers() throws {
        try fixture { _, account, services, directory in
            var creations = 0
            XCTAssertThrowsError(try restore(directory, account, services, make: {
                creations += 1; return try self.material(services)
            }, stage: { if case .published = $0 { throw Refused() } })) { XCTAssertTrue($0 is Refused) }
            let before = try Data(contentsOf: URL(fileURLWithPath: path(directory)))
            let recovered = try restore(directory, account, services, make: { XCTFail("Do not replace retained material"); throw Refused() })
            let expected = try RuntimePreparationMaterial.decode(before).reference
            XCTAssertEqual(try recovered.reference, expected)
            XCTAssertEqual(creations, 1)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(directory))), before)
            let again = try restore(directory, account, services, expected: expected,
                make: { XCTFail("A retained pin cannot authorize creation"); throw Refused() })
            XCTAssertEqual(try again.reference, expected)
        }
    }

    func testMissingEstablishedMaterialNeverInvokesTheFactory() throws {
        try fixture { _, account, services, directory in
            let first = try restore(directory, account, services, make: { try self.material(services) })
            let expected = try first.reference
            try FileManager.default.removeItem(atPath: path(directory))
            XCTAssertThrowsError(try restore(directory, account, services, expected: expected,
                make: { XCTFail("Never regenerate an established key"); throw Refused() })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .missingMaterial)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
        }
    }

    func testDifferentRetainedIdentityAndChangedServiceClaimsAreNotAdopted() throws {
        try fixture { _, account, services, directory in
            let original = try restore(directory, account, services, make: { try self.material(services) })
            let substitute = try material(services), bytes = try substitute.encoded
            try bytes.write(to: URL(fileURLWithPath: path(directory)))
            XCTAssertEqual(chmod(path(directory), 0o600), 0)
            XCTAssertThrowsError(try restore(directory, account, services, expected: original.reference,
                make: { XCTFail("Do not overwrite a conflict"); throw Refused() })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(directory))), bytes)
            let changed = try plan(account)
            XCTAssertThrowsError(try restore(directory, account, changed,
                make: { XCTFail("Do not adopt another service plan"); throw Refused() })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
        }
    }

    func testMalformedOrPublicExistingMaterialIsNotReset() throws {
        for malformed in [true, false] {
            try fixture { _, account, services, directory in
                let bytes = malformed ? Data([0xff]) : try material(services).encoded
                try bytes.write(to: URL(fileURLWithPath: path(directory)))
                XCTAssertEqual(chmod(path(directory), malformed ? 0o600 : 0o644), 0)
                XCTAssertThrowsError(try restore(directory, account, services,
                    make: { XCTFail("Never recover by resetting an invalid existing record"); throw Refused() }))
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(directory))), bytes)
            }
        }
    }

    func testFailedScopeVerificationLeavesNoPublishedMaterial() throws {
        try fixture { _, account, services, directory in
            XCTAssertThrowsError(try restore(directory, account, services, verify: { throw Refused() },
                make: { XCTFail("Verify before key creation"); throw Refused() })) { XCTAssertTrue($0 is Refused) }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
            var verifications = 0
            XCTAssertThrowsError(try restore(directory, account, services,
                verify: { verifications += 1; if verifications == 2 { throw Refused() } },
                make: { try self.material(services) })) { XCTAssertTrue($0 is Refused) }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
        }
    }

    func testWrongPinsAuthorityScopeAndCodecVersionsAreRejected() throws {
        try fixture { _, _, services, _ in
            let value = try material(services), other = try material(services)
            XCTAssertThrowsError(try RuntimePreparationMaterial(materialID: value.materialID, services: services,
                transportIdentity: value.transportIdentity, transportPublicKeyInfo: other.transportPublicKeyInfo, gateway: value.gateway))
            let wrongRoot = try GatewayRegistrationIdentity(ownerID: value.gateway.ownerID, macID: services.macID,
                accountID: services.accountID, gatewayID: value.gateway.gatewayID, lifecycleEpoch: value.gateway.lifecycleEpoch,
                rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
            XCTAssertThrowsError(try RuntimeMaterialReference(materialID: value.materialID, services: services,
                materialDigest: Data(repeating: 1, count: 32), transportPublicKeyInfo: value.transportPublicKeyInfo, gateway: wrongRoot))
            guard case .map(let fields) = try DeterministicCBOR.decode(value.encoded, limits: RuntimePreparationMaterial.limits) else {
                return XCTFail("Missing fixture map")
            }
            for (key, changed): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("remozio-authority-identity")),
                (2, .bytes(Data())), (7, .null)] {
                var copy = fields; copy[key] = changed
                let bytes = try DeterministicCBOR.encode(.map(copy), limits: CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 64))
                XCTAssertThrowsError(try RuntimePreparationMaterial.decode(bytes))
            }
        }
    }

    func testNativePreparationRefusesOrdinaryAccountBeforeProtectedOperations() throws {
        try fixture { _, account, services, _ in
            XCTAssertThrowsError(try RuntimeMaterialPreparation.prepareFileIdentity(account: account, services: services,
                expected: nil, fileCustodyAccepted: true, verifyCurrent: { XCTFail("Do not enter native setup") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
}
