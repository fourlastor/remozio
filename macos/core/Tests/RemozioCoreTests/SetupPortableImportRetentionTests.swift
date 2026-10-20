import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned storage proves scoped retention. No native administrator, production Root or installed XPC admission is exercised.
final class SetupPortableImportRetentionTests: XCTestCase {
    private struct Interrupted: Error {}
    final class Fixture {
        let f: AccountPreparationFixture
        let account: AccountPreparationIntent
        let inventory: InstallationInventory
        let services: ServiceAccountPlan
        let owner: SetupAccountOwner
        init() throws {
            f = try .init()
            let machine = try f.open(initialize: true)
            account = try f.resume(machine, f.begin(machine))
            services = try .init(account: account, planID: AccountPreparationIntent.randomID(), claims: [
                .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
                .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
            try machine.retainServiceAccountPlan(services); try machine.completeServiceAccountPlan(services)
            inventory = try XCTUnwrap(machine.inventory()); try machine.close()
            let fixture = f, identity = f.identity
            owner = try .init(openMachine: { try fixture.open() }, expectedReleaseDigest: f.release,
                resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.policy,
                lookupAccount: { uid in guard uid == identity.uid else { throw AdministrativeSetupError.wrongAccount }; return identity })
        }
        deinit { try? owner.close() }
        var directory: String { f.root.path + "/machine/SharedSetupImport" }
        func proposal(token: String = "synthetic-owner-import-secret") throws -> PortableSetup {
            try .init(defaults: .init(presence: .init(idleMilliseconds: 420_000, observationLifetimeMilliseconds: 5000,
                unavailableGraceMilliseconds: 30_000), gateway: GatewaySetupForm().settingsSelection()),
                cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                    dnsSuffix: "remozio.example.invalid", apiToken: token))
        }
        func read() throws -> SetupPortableImportProgress {
            guard let result = try owner.portableImportProgress(callerUID: getuid()) else { throw Interrupted() }; return result
        }
        func retain(_ expected: SetupPortableImportProgress, proposal: PortableSetup? = nil,
                    stage: (SharedSetupImportPublication.Stage) throws -> Void = { _ in }) throws -> SetupPortableImportProgress {
            try owner.retainPortableImport(callerUID: getuid(), expected: expected, proposal: proposal ?? self.proposal(), didStage: stage)
        }
        func journal(initialize: Bool = false) throws -> SharedSetupImportJournal {
            if initialize { try f.prepare("machine/SharedSetupImport", .sharedSetupImport) }
            return try .init(lease: .init(anchor: f.root.path, relativeDirectory: "machine/SharedSetupImport", owner: getuid(),
                ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(), macID: inventory.macID,
                installationID: inventory.installationID, initialize: initialize)
        }
        func publishRuntime() throws {
            let machine = try f.open(); defer { try? machine.close() }
            let now = Date(), material = try RuntimePreparationMaterial.create(services: services,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
            try machine.retainRuntimeMaterial(material.reference); try machine.completeRuntimePublication(material.reference)
        }
    }
    func testOwnerPublishesOnlyTheSecretFreeRecipeAndPreservesUnconfiguredRuntime() throws {
        let f = try Fixture(), before = try f.read(), result = try f.retain(before)
        XCTAssertNotNil(result.operationID); XCTAssertEqual(result.phase, .retained)
        XCTAssertEqual(result.runtime, before.runtime); XCTAssertEqual(try f.read(), result)
        let journal = try f.journal(); defer { try? journal.close() }
        let records = try journal.records(); XCTAssertEqual(records.count, 1)
        XCTAssertTrue(try records[0].matches(f.proposal()))
        let bytes = try Data(contentsOf: URL(fileURLWithPath: f.directory + "/setup-import.sqlite"))
        XCTAssertNil(bytes.range(of: Data("synthetic-owner-import-secret".utf8)))
        XCTAssertFalse(result.runtime.configurationPublished); XCTAssertNil(result.runtime.materialID)
    }
    func testLostReplyRequiresReadbackAndCannotCreateAReplacementOperation() throws {
        let f = try Fixture(), before = try f.read(), first = try f.retain(before)
        XCTAssertThrowsError(try f.retain(before)) { XCTAssertEqual($0 as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try f.retain(f.read()), first)
        let journal = try f.journal(); defer { try? journal.close() }; XCTAssertEqual(try journal.records().count, 1)
    }
    func testReopenedBundleMustMatchCredentialsEvenWhenPublicRecipeIsIdentical() throws {
        let f = try Fixture(), result = try f.retain(f.read())
        XCTAssertThrowsError(try f.retain(result, proposal: f.proposal(token: "different-synthetic-secret"))) {
            XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
        }
        XCTAssertEqual(try f.read(), result)
    }
    func testForeignDestinationWrongCallerAndClosedOwnerCannotRetain() throws {
        let f = try Fixture(), other = try Fixture(), expected = try f.read()
        XCTAssertThrowsError(try other.retain(expected))
        XCTAssertFalse(FileManager.default.fileExists(atPath: other.directory))
        XCTAssertThrowsError(try f.owner.retainPortableImport(callerUID: getuid() + 1, expected: expected, proposal: f.proposal()))
        try f.owner.close(); XCTAssertThrowsError(try f.retain(expected))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.directory))
    }
    func testExistingRuntimeAndStaleRuntimeCannotBeAdoptedByStartingAnImport() throws {
        let f = try Fixture(), expected = try f.read(); try f.publishRuntime()
        XCTAssertThrowsError(try f.retain(expected)) { XCTAssertEqual($0 as? AdministrativeSetupError, .staleProgress) }
        XCTAssertThrowsError(try f.retain(f.read())) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.directory))
    }
    func testPartialOrEmptyFinalJournalCannotBeRepairedOrInitialized() throws {
        let f = try Fixture(), expected = try f.read(); try f.f.prepare("machine/SharedSetupImport", .sharedSetupImport)
        let before = try Data(contentsOf: URL(fileURLWithPath: f.directory + "/setup-import.sqlite"))
        XCTAssertThrowsError(try f.retain(expected))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.directory + "/setup-import.sqlite")), before)
        let g = try Fixture(), fresh = try g.read(), empty = try g.journal(initialize: true); try empty.close()
        XCTAssertThrowsError(try g.retain(fresh)) { XCTAssertEqual($0 as? SharedSetupImportError, .corruptRecord) }
        let reopened = try g.journal(); defer { try? reopened.close() }; XCTAssertTrue(try reopened.records().isEmpty)
    }
    func testFailureBeforePublicationLeavesNoAcceptedImportAndAllowsAnExplicitRetry() throws {
        let f = try Fixture(), before = try f.read()
        XCTAssertThrowsError(try f.retain(before, stage: { if $0 == .beforePublication { throw Interrupted() } }))
        XCTAssertEqual(try f.read(), before); XCTAssertFalse(FileManager.default.fileExists(atPath: f.directory))
        let result = try f.retain(before); XCTAssertNotNil(result.operationID)
    }
    func testUnknownReplyAfterPublicationRetainsTheExactOperationForReadback() throws {
        let f = try Fixture(), before = try f.read()
        XCTAssertThrowsError(try f.retain(before, stage: { if $0 == .published { throw Interrupted() } }))
        let result = try f.read(); XCTAssertNotNil(result.operationID)
        XCTAssertThrowsError(try f.retain(before)) { XCTAssertEqual($0 as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try f.retain(result), result)
    }
    func testBusyJournalIsNotAbsenceAndDoesNotReplaceTheOperation() throws {
        let f = try Fixture(), retained = try f.retain(f.read()), held = try f.journal()
        XCTAssertThrowsError(try f.retain(retained)) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        try held.close(); XCTAssertEqual(try f.read(), retained)
    }
}
