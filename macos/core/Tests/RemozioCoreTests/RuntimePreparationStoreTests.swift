import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimePreparationStoreTests: XCTestCase {
    private struct Interrupted: Error {}
    private func fixture(completeServices: Bool = true,
                         _ body: (AccountPreparationFixture, AccountPreparationIntent, ServiceAccountPlan, PreparationIntentStore) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner SQLite fixture") }
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine)), services = try plan(account, firstNumber: 20000)
        try machine.retainServiceAccountPlan(services)
        if completeServices { try machine.completeServiceAccountPlan(services) }
        try body(f, account, services, machine)
    }
    private func plan(_ account: AccountPreparationIntent, firstNumber: UInt32) throws -> ServiceAccountPlan {
        try .init(account: account, planID: AccountPreparationIntent.randomID(), claims: [
            .init(accountID: account.accountID, role: .transport, number: firstNumber, userID: UUID(), groupID: UUID()),
            .init(accountID: account.accountID, role: .gateway, number: firstNumber + 1, userID: UUID(), groupID: UUID())])
    }
    private func reference(_ services: ServiceAccountPlan) throws -> RuntimeMaterialReference {
        let now = Date()
        return try RuntimePreparationMaterial.create(services: services, notValidBefore: now.addingTimeInterval(-60),
            notValidAfter: now.addingTimeInterval(600)).reference
    }

    func testMigrationRetainsExistingAccountInventoryAndServiceReservations() throws {
        try fixture { f, account, services, machine in
            XCTAssertEqual(try f.sql("PRAGMA user_version"), 5)
            let inventory = try XCTUnwrap(machine.inventory())
            XCTAssertEqual(try machine.runtimePreparation(accountID: account.accountID), .init(reference: nil, configurationPublished: false))
            let value = try reference(services)
            try machine.retainRuntimeMaterial(value)
            XCTAssertEqual(try f.sql("PRAGMA user_version"), 6)
            XCTAssertEqual(try machine.runtimePreparation(accountID: account.accountID), .init(reference: value, configurationPublished: false))
            XCTAssertEqual(try machine.inventory(), inventory)
            XCTAssertEqual(try machine.accountPreparation(ownerUID: account.ownerUID), account)
            XCTAssertEqual(try machine.serviceAccountPlan(accountID: account.accountID), .init(plan: services, complete: true))
            XCTAssertEqual(try machine.reservedServiceAccountNumbers(), Set(services.claims.map(\.number)))
            XCTAssertTrue(try XCTUnwrap(machine.initialization(accountID: account.accountID)).complete)
        }
    }

    func testMatchingReplayCannotClearCompletionOrReplaceThePinnedIdentity() throws {
        try fixture { f, account, services, machine in
            let value = try reference(services), different = try reference(services)
            try machine.retainRuntimeMaterial(value)
            try machine.completeRuntimePublication(value)
            try machine.retainRuntimeMaterial(value)
            try machine.completeRuntimePublication(value)
            XCTAssertEqual(try machine.runtimePreparation(accountID: account.accountID), .init(reference: value, configurationPublished: true))
            XCTAssertThrowsError(try machine.retainRuntimeMaterial(different)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertThrowsError(try machine.completeRuntimePublication(different))
            XCTAssertEqual(try f.sql("SELECT COUNT(*) FROM runtime_preparation_v1"), 1)
            XCTAssertEqual(try machine.runtimePreparation(accountID: account.accountID).reference, value)
        }
    }

    func testIncompleteServiceClaimsCannotAdvanceTheStorageSchema() throws {
        try fixture(completeServices: false) { f, account, services, machine in
            let value = try reference(services)
            XCTAssertThrowsError(try machine.retainRuntimeMaterial(value)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .incomplete)
            }
            XCTAssertEqual(try f.sql("PRAGMA user_version"), 5)
            XCTAssertEqual(try machine.runtimePreparation(accountID: account.accountID), .init(reference: nil, configurationPublished: false))
            try machine.completeServiceAccountPlan(services)
            try machine.retainRuntimeMaterial(value)
            XCTAssertEqual(try machine.runtimePreparation(accountID: account.accountID).reference, value)
        }
    }

    func testCompletionCannotCreateAnUnretainedIdentityReference() throws {
        try fixture { f, _, services, machine in
            XCTAssertThrowsError(try machine.completeRuntimePublication(reference(services))) {
                XCTAssertEqual($0 as? RuntimePreparationError, .incomplete)
            }
            XCTAssertEqual(try f.sql("PRAGMA user_version"), 5)
        }
    }

    func testLostCommitAcknowledgmentsPreserveIdentityAndPublicationOnReopen() throws {
        for completion in [false, true] {
            try fixture { f, account, services, machine in
                let value = try reference(services)
                if completion { try machine.retainRuntimeMaterial(value) }
                try machine.close()
                var armed = false
                let writer = try f.open(hook: { if armed { throw Interrupted() } })
                armed = true
                XCTAssertThrowsError(try completion ? writer.completeRuntimePublication(value) : writer.retainRuntimeMaterial(value)) {
                    XCTAssertTrue($0 is Interrupted)
                }
                XCTAssertThrowsError(try writer.runtimePreparation(accountID: account.accountID))
                try writer.close()
                let restored = try f.open(); defer { try? restored.close() }
                XCTAssertEqual(try restored.runtimePreparation(accountID: account.accountID),
                    .init(reference: value, configurationPublished: completion))
                try restored.retainRuntimeMaterial(value)
                if completion { try restored.completeRuntimePublication(value) }
                XCTAssertEqual(try restored.runtimePreparation(accountID: account.accountID),
                    .init(reference: value, configurationPublished: completion))
            }
        }
    }

    func testAnotherAccountCannotReuseTheMaterialIdentifierOrTransportPin() throws {
        for collision in ["material", "pin"] {
            try fixture { f, account, services, machine in
                let first = try reference(services)
                try machine.retainRuntimeMaterial(first)
                let identity = LocalAccountIdentity(uid: account.ownerUID + 1, primaryGroupID: getgid(), directoryID: UUID())
                let secondAccount = try f.resume(machine, f.begin(machine, identity: identity))
                let secondPlan = try plan(secondAccount, firstNumber: 20002)
                try machine.retainServiceAccountPlan(secondPlan); try machine.completeServiceAccountPlan(secondPlan)
                let original = try reference(secondPlan)
                let changed = try RuntimeMaterialReference(materialID: collision == "material" ? first.materialID : original.materialID,
                    services: secondPlan, materialDigest: original.materialDigest,
                    transportPublicKeyInfo: collision == "pin" ? first.transportPublicKeyInfo : original.transportPublicKeyInfo,
                    gateway: original.gateway)
                XCTAssertThrowsError(try machine.retainRuntimeMaterial(changed)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
                }
                XCTAssertEqual(try machine.runtimePreparation(accountID: secondAccount.accountID), .init(reference: nil, configurationPublished: false))
                XCTAssertEqual(try machine.runtimePreparation(accountID: account.accountID).reference, first)
            }
        }
    }

    func testMalformedRecordsAndMismatchedIndexColumnsRetireTheConnection() throws {
        for mutation in ["UPDATE runtime_preparation_v1 SET record=x'00'",
                         "UPDATE runtime_preparation_v1 SET digest=zeroblob(32)",
                         "UPDATE runtime_preparation_v1 SET pin=zeroblob(91)",
                         "UPDATE runtime_preparation_v1 SET material=zeroblob(16)"] {
            try fixture { f, account, services, machine in
                try machine.retainRuntimeMaterial(reference(services))
                _ = try f.sql(mutation)
                XCTAssertThrowsError(try machine.runtimePreparation(accountID: account.accountID)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
                XCTAssertThrowsError(try machine.runtimePreparation(accountID: account.accountID)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
                }
                XCTAssertEqual(try f.sql("SELECT COUNT(*) FROM runtime_preparation_v1"), 1)
            }
        }
    }
}
