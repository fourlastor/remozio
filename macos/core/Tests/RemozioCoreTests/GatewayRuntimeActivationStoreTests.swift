import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

final class GatewayRuntimeActivationStoreTests: XCTestCase {
    private struct Interrupted: Error {}
    private func ready() throws -> GatewayJournalSetupExchangeTests.Fixture {
        let f = try GatewayJournalSetupExchangeTests.Fixture()
        try f.retainCompletion(.decode(f.initialize())); return f
    }
    private func plan(_ f: GatewayJournalSetupExchangeTests.Fixture, poll: UInt64 = 1000) throws -> GatewayRuntimeActivationPlan {
        try .init(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()),
            wakePollMilliseconds: poll)
    }
    func testReadDoesNotMigrateAndRetentionPreservesForegroundAndCompletedJournal() throws {
        let f = try ready(), machine = f.runtime.machine, value = try plan(f)
        let inventory = try machine.inventory(), journal = try f.state(), foreground = try machine.runtimeActivation(accountID: value.accountID)
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 9)
        XCTAssertNil(try machine.gatewayRuntimeActivation(accountID: value.accountID).plan)
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 9)
        try machine.retainGatewayRuntimeActivation(value); try machine.retainGatewayRuntimeActivation(value)
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 10)
        XCTAssertEqual(try f.runtime.f.sql("SELECT COUNT(*) FROM gateway_runtime_activation_v1"), 1)
        let state = try machine.gatewayRuntimeActivation(accountID: value.accountID)
        XCTAssertEqual(try state.plan?.encoded, try value.encoded); XCTAssertFalse(state.filesPublished); XCTAssertFalse(state.jobRegistered)
        XCTAssertEqual(try machine.inventory(), inventory); XCTAssertEqual(try f.state(), journal)
        XCTAssertEqual(try machine.runtimeActivation(accountID: value.accountID).plan?.encoded, try foreground.plan?.encoded)
        XCTAssertTrue(try machine.runtimeActivation(accountID: value.accountID).jobsRegistered)
    }
    func testFabricatedCompletionCannotMigrateTheActualPendingJournal() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(), machine = f.runtime.machine
        let value = try GatewayRuntimeActivationPlan(journal: .init(intent: f.intent, initialized: true),
            foreground: f.runtime.plan, inventory: XCTUnwrap(machine.inventory()))
        XCTAssertThrowsError(try machine.retainGatewayRuntimeActivation(value))
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 9)
        XCTAssertNil(try machine.gatewayRuntimeActivation(accountID: value.accountID).plan)
        try f.retainCompletion(.decode(f.initialize())); try machine.retainGatewayRuntimeActivation(value)
        XCTAssertEqual(try machine.gatewayRuntimeActivation(accountID: value.accountID).plan?.encoded, try value.encoded)
    }
    func testPublicationEnrollmentAndRegistrationRemainSeparateMonotonicSteps() throws {
        let f = try ready(), machine = f.runtime.machine, value = try plan(f), original = try XCTUnwrap(machine.inventory())
        XCTAssertThrowsError(try machine.markGatewayRuntimePublished(value))
        XCTAssertThrowsError(try machine.enrollGatewayRuntimeActivation(value))
        XCTAssertThrowsError(try machine.markGatewayRuntimeRegistered(value))
        try machine.retainGatewayRuntimeActivation(value)
        XCTAssertThrowsError(try machine.enrollGatewayRuntimeActivation(value))
        XCTAssertThrowsError(try machine.markGatewayRuntimeRegistered(value))
        try machine.markGatewayRuntimePublished(value); try machine.markGatewayRuntimePublished(value)
        XCTAssertEqual(try machine.inventory(), original)
        XCTAssertThrowsError(try machine.markGatewayRuntimeRegistered(value))
        let enrolled = try machine.enrollGatewayRuntimeActivation(value)
        XCTAssertEqual(enrolled.accounts, original.accounts); XCTAssertNotEqual(enrolled.revision, original.revision)
        XCTAssertEqual(enrolled.services.count, original.services.count + 1)
        XCTAssertEqual(enrolled.services.filter { $0.role != .notificationGateway }, original.services)
        XCTAssertEqual(enrolled.services.filter { $0.role == .notificationGateway }, [try value.gatewayJob.declaration])
        XCTAssertEqual(try machine.enrollGatewayRuntimeActivation(value), enrolled)
        XCTAssertFalse(try machine.gatewayRuntimeActivation(accountID: value.accountID).jobRegistered)
        try machine.markGatewayRuntimeRegistered(value); try machine.markGatewayRuntimeRegistered(value)
        try machine.retainGatewayRuntimeActivation(value); try machine.markGatewayRuntimePublished(value)
        let state = try machine.gatewayRuntimeActivation(accountID: value.accountID)
        XCTAssertTrue(state.filesPublished); XCTAssertTrue(state.jobRegistered)
        XCTAssertEqual(try machine.inventory(), enrolled)
    }
    func testChangedTimingAndForeignScopeCannotReplaceTheRetainedPlan() throws {
        let f = try ready(), second = try ready(), machine = f.runtime.machine
        let value = try plan(f), changed = try plan(f, poll: 2000), foreign = try plan(second)
        try machine.retainGatewayRuntimeActivation(value); try machine.markGatewayRuntimePublished(value)
        let original = try machine.inventory()
        for other in [changed, foreign] {
            XCTAssertThrowsError(try machine.retainGatewayRuntimeActivation(other))
            XCTAssertThrowsError(try machine.markGatewayRuntimePublished(other))
            XCTAssertThrowsError(try machine.enrollGatewayRuntimeActivation(other))
            XCTAssertThrowsError(try machine.markGatewayRuntimeRegistered(other))
        }
        let state = try machine.gatewayRuntimeActivation(accountID: value.accountID)
        XCTAssertEqual(try state.plan?.encoded, try value.encoded); XCTAssertTrue(state.filesPublished); XCTAssertFalse(state.jobRegistered)
        XCTAssertEqual(try machine.inventory(), original)
    }
    func testAnAlreadyDeclaredGatewayWithoutAnIntentCannotBeAdopted() throws {
        let f = try ready(), machine = f.runtime.machine, value = try plan(f)
        let original = try XCTUnwrap(machine.inventory())
        let proposal = try value.proposal(journal: f.state(), foreground: f.runtime.plan, inventory: original)
        _ = try machine.writeInventory(proposal.enrolledInventory(original), expectedRevision: original.revision)
        XCTAssertThrowsError(try machine.retainGatewayRuntimeActivation(value))
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 9)
        XCTAssertNil(try machine.gatewayRuntimeActivation(accountID: value.accountID).plan)
    }
    func testLostCommitAcknowledgmentsRecoverEachDurableStageWithoutReplacingThePlan() throws {
        for stage in 0...3 {
            let f = try ready(), machine = f.runtime.machine, value = try plan(f)
            if stage > 0 { try machine.retainGatewayRuntimeActivation(value) }
            if stage > 1 { try machine.markGatewayRuntimePublished(value) }
            if stage > 2 { _ = try machine.enrollGatewayRuntimeActivation(value) }
            try machine.close()
            var armed = false
            let writer = try f.runtime.f.open(hook: { if armed { throw Interrupted() } }); armed = true
            XCTAssertThrowsError(try {
                switch stage {
                case 0: try writer.retainGatewayRuntimeActivation(value)
                case 1: try writer.markGatewayRuntimePublished(value)
                case 2: _ = try writer.enrollGatewayRuntimeActivation(value)
                default: try writer.markGatewayRuntimeRegistered(value)
                }
            }()) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertThrowsError(try writer.gatewayRuntimeActivation(accountID: value.accountID)); try writer.close()
            let restored = try f.runtime.f.open(); defer { try? restored.close() }
            let state = try restored.gatewayRuntimeActivation(accountID: value.accountID)
            XCTAssertEqual(try state.plan?.encoded, try value.encoded)
            XCTAssertEqual(state.filesPublished, stage >= 1); XCTAssertEqual(state.jobRegistered, stage == 3)
            XCTAssertEqual(try XCTUnwrap(restored.inventory()).services.contains { $0.role == .notificationGateway }, stage >= 2)
            try restored.retainGatewayRuntimeActivation(value); try restored.markGatewayRuntimePublished(value)
            _ = try restored.enrollGatewayRuntimeActivation(value); try restored.markGatewayRuntimeRegistered(value)
            XCTAssertTrue(try restored.gatewayRuntimeActivation(accountID: value.accountID).jobRegistered)
        }
    }
    private func tamper(_ f: GatewayJournalSetupExchangeTests.Fixture, _ sql: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open_v2(f.runtime.f.root.path + "/machine/installation.sqlite", &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK, let db else { throw Interrupted() }
        defer { sqlite3_close(db) }
        guard sqlite3_exec(db, "PRAGMA ignore_check_constraints=ON;" + sql, nil, nil, nil) == SQLITE_OK else { throw Interrupted() }
    }
    func testCorruptIndexesFlagsAndRecordsCannotHideTheRowOrKeepTheStoreAvailable() throws {
        for change in ["account=zeroblob(16)", "journal=zeroblob(16)", "material=zeroblob(16)", "digest=zeroblob(32)",
                       "record=x'00'", "published=2", "registered=1,published=0"] {
            let f = try ready(), value = try plan(f), machine = f.runtime.machine
            try machine.retainGatewayRuntimeActivation(value); try tamper(f, "UPDATE gateway_runtime_activation_v1 SET " + change)
            XCTAssertThrowsError(try machine.gatewayRuntimeActivation(accountID: value.accountID)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord, change)
            }
            XCTAssertThrowsError(try machine.gatewayRuntimeActivation(accountID: value.accountID)) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
            XCTAssertEqual(try f.runtime.f.sql("SELECT COUNT(*) FROM gateway_runtime_activation_v1"), 1)
        }
    }
    func testHistoricalStateDoesNotOpenTheServiceJournalAndUnknownHeadersAreRejected() throws {
        let f = try ready(), value = try plan(f), machine = f.runtime.machine
        try machine.retainGatewayRuntimeActivation(value); try machine.markGatewayRuntimePublished(value)
        _ = try machine.enrollGatewayRuntimeActivation(value); try machine.markGatewayRuntimeRegistered(value)
        try FileManager.default.removeItem(at: f.root.appendingPathComponent("Service/Gateway/gateway.sqlite"))
        let state = try machine.gatewayRuntimeActivation(accountID: value.accountID)
        XCTAssertTrue(state.jobRegistered); XCTAssertTrue(state.filesPublished); try machine.close()
        let restored = try f.runtime.f.open(); XCTAssertTrue(try restored.gatewayRuntimeActivation(accountID: value.accountID).jobRegistered)
        try restored.close(); _ = try f.runtime.f.sql("PRAGMA user_version=11")
        XCTAssertThrowsError(try f.runtime.f.open()) { XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore) }
        _ = try f.runtime.f.sql("PRAGMA user_version=10"); _ = try f.runtime.f.sql("DROP TABLE gateway_runtime_activation_v1")
        XCTAssertThrowsError(try f.runtime.f.open()) { XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore) }
    }
}
