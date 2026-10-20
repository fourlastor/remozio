import Foundation
import XCTest
@testable import RemozioCore

final class SharedSetupImportRetentionTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Fixture {
        let f: SharedSetupImportFixture
        let machine: PreparationIntentStore
        let journal: SharedSetupImportJournal
        init() throws {
            f = try .init()
            machine = try f.accountFixture.open()
            let plan = try ServiceAccountPlan(account: f.account, planID: AccountPreparationIntent.randomID(), claims: [
                .init(accountID: f.account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
                .init(accountID: f.account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
            try machine.retainServiceAccountPlan(plan); try machine.completeServiceAccountPlan(plan)
            journal = try f.open(initialize: true)
        }
        deinit { try? journal.close(); try? machine.close() }
        func progress() throws -> SetupRuntimeProgress {
            try .init(account: f.account, services: machine.serviceAccountPlan(accountID: f.account.accountID),
                state: machine.runtimePreparation(accountID: f.account.accountID))
        }
        func retain(expected: SharedSetupImportIntent? = nil, proposal: PortableSetup? = nil,
                    verify: () throws -> Void = {}) throws -> SharedSetupImportIntent {
            try SharedSetupImportRetention.retain(machine: machine, account: f.account, expectedRuntime: progress(),
                expectedImport: expected, proposal: proposal ?? f.proposal(), journal: journal, verifyCurrent: verify)
        }
    }
    func testFreshDestinationRetainsTheReviewedRecipeWithoutPreparingOrActivatingRuntime() throws {
        let f = try Fixture(), before = try f.progress(), inventory = try f.machine.inventory()
        let intent = try f.retain()
        XCTAssertTrue(try intent.matches(f.f.proposal())); XCTAssertEqual(intent.phase, .retained)
        XCTAssertEqual(try f.journal.current(scope: f.f.scope), intent)
        XCTAssertEqual(try f.progress(), before); XCTAssertEqual(try f.machine.inventory(), inventory)
        XCTAssertNil(try f.machine.runtimePreparation(accountID: f.f.account.accountID).reference)
        XCTAssertFalse(try f.machine.runtimeActivation(accountID: f.f.account.accountID).jobsRegistered)
    }
    func testLostReplyRequiresCurrentProgressAndResumesTheSameOperation() throws {
        let f = try Fixture(), first = try f.retain()
        XCTAssertThrowsError(try f.retain()) { XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision) }
        XCTAssertEqual(try f.retain(expected: first), first)
        XCTAssertEqual(try f.journal.records().count, 1)
    }
    func testDifferentBundleCannotReplaceAnExistingImport() throws {
        let f = try Fixture(), first = try f.retain(), base = try f.f.proposal()
        let different = PortableSetup(defaults: base.defaults)
        XCTAssertThrowsError(try f.retain(expected: first, proposal: different)) {
            XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
        }
        XCTAssertEqual(try f.journal.current(scope: f.f.scope), first)
    }
    func testExistingRuntimeCannotBeAdoptedByStartingAnImport() throws {
        let f = try Fixture(), services = try XCTUnwrap(f.machine.serviceAccountPlan(accountID: f.f.account.accountID).plan)
        let now = Date(), material = try RuntimePreparationMaterial.create(services: services,
            notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
        try f.machine.retainRuntimeMaterial(material.reference)
        XCTAssertThrowsError(try f.retain()) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
        XCTAssertTrue(try f.journal.records().isEmpty)
        try f.machine.completeRuntimePublication(material.reference)
        XCTAssertThrowsError(try f.retain()) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
        XCTAssertTrue(try f.journal.records().isEmpty)
    }
    func testScopeRefusalBeforeRetentionLeavesNoImport() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.retain(verify: { throw Interrupted() })) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertTrue(try f.journal.records().isEmpty)
    }
    func testLostReplyAfterRetentionKeepsTheSameOperationForReconciliation() throws {
        let f = try Fixture(); var checks = 0
        XCTAssertThrowsError(try f.retain(verify: { checks += 1; if checks == 3 { throw Interrupted() } })) {
            XCTAssertTrue($0 is Interrupted)
        }
        let retained = try XCTUnwrap(f.journal.current(scope: f.f.scope))
        XCTAssertEqual(try f.retain(expected: retained), retained)
    }
    func testAnAdvancedImportCannotClaimAnUnpublishedRuntime() throws {
        let f = try Fixture(), first = try f.retain(), advanced = try f.journal.advance(first, to: .runtimePublished)
        XCTAssertThrowsError(try f.retain(expected: advanced)) { XCTAssertEqual($0 as? RuntimePreparationError, .incomplete) }
        XCTAssertEqual(try f.journal.current(scope: f.f.scope), advanced)
    }
}
