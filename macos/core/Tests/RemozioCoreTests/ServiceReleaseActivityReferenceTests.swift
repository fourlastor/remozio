import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class ServiceReleaseActivityReferenceTests: XCTestCase {
    private struct Interrupted: Error {}
    private let loose = try! CBORLimits(maxBytes: 65536, maxDepth: 8, maxItems: 128)
    private func activity(_ services: ServiceAccountPlan, inode: UInt64 = 20) throws -> ServiceReleaseActivityReference {
        try .init(services: services, identities: [.transport: .init(device: UInt32.max, inode: inode),
            .gateway: .init(device: UInt32.max, inode: UInt64.max)])
    }
    private func extended(_ original: RuntimePreparationMaterial, activity: ServiceReleaseActivityReference) throws -> RuntimePreparationMaterial {
        try .init(materialID: original.materialID, services: original.services, transportIdentity: original.transportIdentity,
            transportPublicKeyInfo: original.transportPublicKeyInfo, gateway: original.gateway, serviceActivity: activity)
    }
    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let result) = try DeterministicCBOR.decode(bytes, limits: loose) else {
            throw RuntimePreparationError.invalidRecord
        }; return result
    }
    private func owned(_ body: (AccountPreparationFixture, PreparationIntentStore, AccountPreparationIntent, ServiceAccountPlan) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owned runtime retention") }
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        let services = try ServiceAccountPlan(account: account, planID: AccountPreparationIntent.randomID(), claims: [
            .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
            .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
        try machine.retainServiceAccountPlan(services); try machine.completeServiceAccountPlan(services)
        try body(f, machine, account, services)
    }
    func testCanonicalReferenceBindsTheCompleteServicePlanAndBothRoles() throws {
        let f = try RuntimeActivationFixture(), a = try activity(f.services)
        XCTAssertEqual(try ServiceReleaseActivityReference.decode(a.encoded), a)
        XCTAssertEqual(a.identity(for: .transport), .init(device: UInt32.max, inode: 20))
        XCTAssertEqual(a.identity(for: .gateway), .init(device: UInt32.max, inode: UInt64.max))
        XCTAssertEqual(a.identities.count, 2); XCTAssertNoThrow(try a.validate(services: f.services))
        XCTAssertEqual(String(reflecting: a), "ServiceReleaseActivityReference(redacted)")
        let other = try ServiceAccountPlan(account: f.account, planID: AccountPreparationIntent.randomID(), claims: f.services.claims)
        XCTAssertThrowsError(try a.validate(services: other)) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
        XCTAssertThrowsError(try extended(f.material, activity: activity(other)))
    }
    func testMissingZeroAndAliasedRoleIdentitiesAreRejected() throws {
        let f = try RuntimeActivationFixture(), a = try activity(f.services)
        for identities: [ServiceAccountRole: PreparationFileIdentity] in [[:], [.transport: a.transport],
            [.transport: a.transport, .gateway: a.transport], [.transport: .init(device: 1, inode: 0), .gateway: a.gateway],
            [.transport: a.transport, .gateway: .init(device: 1, inode: 0)]] {
            XCTAssertThrowsError(try ServiceReleaseActivityReference(services: f.services, identities: identities))
        }
    }
    func testClosedReferenceRejectsWrongPurposeVersionShapeAndNumbers() throws {
        let f = try RuntimeActivationFixture(), a = try activity(f.services), original = try fields(a.encoded)
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("remozio-runtime-file-material")),
            (2, .bytes(Data())), (3, .array([.unsigned(UInt64(UInt32.max) + 1), .unsigned(1)])),
            (3, .array([.unsigned(1), .unsigned(0)])), (3, .array([.unsigned(1)])),
            (4, original[3]!), (5, .null)] {
            var copy = original; copy[key] = value
            XCTAssertThrowsError(try ServiceReleaseActivityReference.decode(DeterministicCBOR.encode(.map(copy), limits: loose)))
        }
        for key in original.keys {
            var copy = original; copy[key] = nil
            XCTAssertThrowsError(try ServiceReleaseActivityReference.decode(DeterministicCBOR.encode(.map(copy), limits: loose)))
        }
        var trailing = try a.encoded; trailing.append(0)
        XCTAssertThrowsError(try ServiceReleaseActivityReference.decode(trailing))
    }
    func testLegacyMaterialAndReferenceKeepTheirExactOriginalEncoding() throws {
        let f = try RuntimeActivationFixture(), m = f.material, r = try m.reference
        XCTAssertNil(m.serviceActivity); XCTAssertNil(r.serviceActivity)
        let materialBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-runtime-file-material"),
            2: .bytes(m.materialID), 3: .bytes(m.services.encoded), 4: .bytes(m.transportIdentity),
            5: .bytes(m.transportPublicKeyInfo), 6: .bytes(m.gateway.encode())]), limits: loose)
        let referenceBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(r.materialID),
            2: .bytes(r.services.encoded), 3: .bytes(r.materialDigest), 4: .bytes(r.transportPublicKeyInfo),
            5: .bytes(r.gateway.encode())]), limits: loose)
        XCTAssertEqual(try m.encoded, materialBytes); XCTAssertEqual(try r.encoded, referenceBytes)
        XCTAssertEqual(try RuntimePreparationMaterial.decode(materialBytes).encoded, materialBytes)
        XCTAssertEqual(try RuntimeMaterialReference.decode(referenceBytes).encoded, referenceBytes)
    }
    func testVersionTwoKeepsExistingKeysAndGatewayIdentityAndBindsActivityInTheDigest() throws {
        let f = try RuntimeActivationFixture(), a = try activity(f.services), m = try extended(f.material, activity: a), r = try m.reference
        XCTAssertEqual(try RuntimePreparationMaterial.decode(m.encoded).reference, r)
        XCTAssertEqual(try RuntimeMaterialReference.decode(r.encoded), r)
        XCTAssertEqual(r.serviceActivity, a); XCTAssertEqual(r.gateway, f.material.gateway)
        XCTAssertEqual(r.transportPublicKeyInfo, f.material.transportPublicKeyInfo)
        XCTAssertEqual(m.transportIdentity, f.material.transportIdentity)
        XCTAssertEqual(r.materialDigest, Data(SHA256.hash(data: try m.encoded)))
        XCTAssertNotEqual(r.materialDigest, try f.material.reference.materialDigest)
        XCTAssertNil(try r.encoded.range(of: m.transportIdentity)); XCTAssertLessThanOrEqual(try r.encoded.count, 8192)
        let changed = try extended(f.material, activity: activity(f.services, inode: 21))
        XCTAssertNotEqual(try changed.reference.materialDigest, r.materialDigest)
        XCTAssertEqual(try fields(m.encoded)[0], .unsigned(2)); XCTAssertEqual(try fields(r.encoded)[0], .unsigned(2))
    }
    func testRuntimeRecordsRejectMissingNullUnknownAndDowngradedActivity() throws {
        let f = try RuntimeActivationFixture(), m = try extended(f.material, activity: activity(f.services))
        for (bytes, activityKey, decode): (Data, UInt64, (Data) throws -> Void) in [
            (try m.encoded, 7, { _ = try RuntimePreparationMaterial.decode($0) }),
            (try m.reference.encoded, 6, { _ = try RuntimeMaterialReference.decode($0) })] {
            let original = try fields(bytes)
            var variants: [[UInt64: CBORValue]] = []
            var copy = original; copy[activityKey] = nil; variants.append(copy)
            copy = original; copy[activityKey] = .null; variants.append(copy)
            copy = original; copy[activityKey] = .bytes(Data()); variants.append(copy)
            copy = original; copy[0] = .unsigned(1); variants.append(copy)
            copy = original; copy[0] = .unsigned(3); variants.append(copy)
            copy = original; copy[activityKey + 1] = .null; variants.append(copy)
            for variant in variants { XCTAssertThrowsError(try decode(DeterministicCBOR.encode(.map(variant), limits: loose))) }
        }
    }
    func testNestedForeignServiceScopeCannotDecodeAsTheOuterRuntimeScope() throws {
        let f = try RuntimeActivationFixture(), other = try RuntimeActivationFixture()
        let m = try extended(f.material, activity: activity(f.services)), foreign = try activity(other.services).encoded
        for (bytes, key, decode): (Data, UInt64, (Data) throws -> Void) in [
            (try m.encoded, 7, { _ = try RuntimePreparationMaterial.decode($0) }),
            (try m.reference.encoded, 6, { _ = try RuntimeMaterialReference.decode($0) })] {
            var copy = try fields(bytes); copy[key] = .bytes(foreign)
            XCTAssertThrowsError(try decode(DeterministicCBOR.encode(.map(copy), limits: loose)))
        }
    }
    func testRealSQLiteRetainsAndRestoresTheSameSelectionWithoutAnotherRegistry() throws {
        try owned { f, machine, account, services in
            let now = Date(), a = try activity(services)
            let m = try RuntimePreparationMaterial.create(services: services, notValidBefore: now.addingTimeInterval(-60),
                notValidAfter: now.addingTimeInterval(600), serviceActivity: a), reference = try m.reference
            try machine.retainRuntimeMaterial(reference); try machine.retainRuntimeMaterial(reference)
            XCTAssertFalse(try machine.runtimePreparation(accountID: account.accountID).configurationPublished)
            try machine.close()
            let reopened = try f.open(); defer { try? reopened.close() }
            XCTAssertEqual(try reopened.runtimePreparation(accountID: account.accountID).reference, reference)
            try reopened.completeRuntimePublication(reference)
            XCTAssertTrue(try reopened.runtimePreparation(accountID: account.accountID).configurationPublished)
            let changed = try extended(m, activity: activity(services, inode: 21))
            XCTAssertThrowsError(try reopened.retainRuntimeMaterial(changed.reference)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertEqual(try reopened.runtimePreparation(accountID: account.accountID).reference, reference)
            XCTAssertEqual(try f.sql("PRAGMA user_version"), 6)
        }
    }
    func testLostPrivatePublicationReplyRestoresKeysAndActivityWithoutCallingTheFactory() throws {
        try owned { f, _, account, services in
            let directory = try ProtectedSetupDirectory(anchor: f.root.path, relativePath: "runtime-activity", owner: getuid())
            defer { directory.close() }
            let now = Date(), m = try RuntimePreparationMaterial.create(services: services, notValidBefore: now.addingTimeInterval(-60),
                notValidAfter: now.addingTimeInterval(600), serviceActivity: activity(services))
            XCTAssertThrowsError(try RuntimeMaterialPreparation.restoreOrCreate(directory: directory, owner: getuid(), account: account,
                services: services, expected: nil, verifyCurrent: {}, make: { m },
                didStage: { if case .published = $0 { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            let before = try Data(contentsOf: URL(fileURLWithPath: directory.path + "/" + AdministrativeSetupPublication.File.runtimeRecord.name))
            let restored = try RuntimeMaterialPreparation.restoreOrCreate(directory: directory, owner: getuid(), account: account,
                services: services, expected: m.reference, verifyCurrent: {}, make: { XCTFail("Never regenerate retained material"); throw Interrupted() })
            XCTAssertEqual(try restored.encoded, before); XCTAssertEqual(restored.serviceActivity, m.serviceActivity)
            XCTAssertEqual(restored.transportIdentity, m.transportIdentity); XCTAssertEqual(restored.gateway, m.gateway)
        }
    }
    func testIncompleteConsumerWiringCannotRegisterAnExtendedActivationPlan() throws {
        let f = try RuntimeActivationFixture(), m = try extended(f.material, activity: activity(f.services)), reference = try m.reference
        XCTAssertThrowsError(try RuntimeActivationPlan(account: f.account, initialization: XCTUnwrap(f.machine.initialization(accountID: f.account.accountID)),
            runtime: .init(reference: reference, configurationPublished: true), inventory: XCTUnwrap(f.machine.inventory()))) {
            XCTAssertEqual($0 as? RuntimeActivationError, .unavailable)
        }
        var map = try fields(f.plan.encoded); map[1] = .bytes(try reference.encoded)
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(DeterministicCBOR.encode(.map(map), limits: loose))) {
            XCTAssertEqual($0 as? RuntimeActivationError, .unavailable)
        }
        XCTAssertEqual(try RuntimeActivationPlan.decode(f.plan.encoded).encoded, try f.plan.encoded)
    }
}
