import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

final class GatewayRuntimeSettingsStoreTests: XCTestCase {
    private struct Interrupted: Error {}
    struct Ready {
        let fixture: GatewayJournalSetupExchangeTests.Fixture
        let activation: GatewayRuntimeActivationPlan
        init(register: Bool = true, nativeConsumerHosts: Bool = false) throws {
            fixture = try .init(nativeConsumerHosts: nativeConsumerHosts); let f = fixture
            try f.retainCompletion(.decode(f.initialize()))
            activation = try .init(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()))
            try f.runtime.machine.retainGatewayRuntimeActivation(activation)
            if register {
                try f.runtime.machine.markGatewayRuntimePublished(activation)
                _ = try f.runtime.machine.enrollGatewayRuntimeActivation(activation)
                try f.runtime.machine.markGatewayRuntimeRegistered(activation)
            }
        }
        func revision(_ number: UInt8 = 1, previous: GatewayRuntimeSettingsRevision? = nil) throws -> GatewayRuntimeSettingsRevision {
            try .init(id: Data(repeating: number, count: 16), selection: .init(service: fixture.intent.configuration.settings,
                activation: .init(wakePollMilliseconds: UInt64(number) * 1000, wakeTimeoutMilliseconds: 6000)),
                activation: activation, previous: previous, journal: fixture.state(), foreground: fixture.runtime.plan,
                inventory: XCTUnwrap(fixture.runtime.machine.inventory()))
        }
    }
    private func finish(_ value: GatewayRuntimeSettingsRevision, _ store: PreparationIntentStore) throws {
        for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() { try store.markGatewaySettingsTransition(value, phase: phase) }
        try store.completeGatewaySettingsTransition(value)
    }
    func testReadsKeepSchemaTenAndRetentionReopensAtTheSamePendingRevision() throws {
        let r = try Ready(), f = r.fixture, store = f.runtime.machine, revision = try r.revision()
        XCTAssertNil(try store.gatewaySettingsTransition(accountID: revision.accountID).pending)
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 10)
        try store.retainGatewaySettingsTransition(revision); try store.retainGatewaySettingsTransition(revision)
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 11)
        XCTAssertEqual(try f.runtime.f.sql("SELECT COUNT(*) FROM gateway_settings_transition_v1"), 1)
        let pending = try store.gatewaySettingsTransition(accountID: revision.accountID)
        XCTAssertNil(pending.active); XCTAssertEqual(try pending.pending?.encoded, try revision.encoded); XCTAssertEqual(pending.phase, .retained)
        try store.close(); let restored = try f.runtime.f.open(); defer { try? restored.close() }
        XCTAssertEqual(try restored.gatewaySettingsTransition(accountID: revision.accountID).pending?.encoded, try revision.encoded)
    }
    func testIncompleteActivationAndForeignAccountCannotMigrateOrRetainSettings() throws {
        let r = try Ready(register: false), other = try Ready(), store = r.fixture.runtime.machine
        XCTAssertThrowsError(try store.retainGatewaySettingsTransition(r.revision()))
        XCTAssertThrowsError(try store.retainGatewaySettingsTransition(other.revision()))
        XCTAssertEqual(try r.fixture.runtime.f.sql("PRAGMA user_version"), 10)
    }
    func testStagesCannotBeSkippedAndRepeatedAcknowledgmentsDoNotAdvanceThem() throws {
        let r = try Ready(), store = r.fixture.runtime.machine, value = try r.revision()
        try store.retainGatewaySettingsTransition(value)
        XCTAssertThrowsError(try store.markGatewaySettingsTransition(value, phase: .filesPublished))
        XCTAssertThrowsError(try store.completeGatewaySettingsTransition(value))
        XCTAssertEqual(try store.gatewaySettingsTransition(accountID: value.accountID).phase, .retained)
        for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() {
            try store.markGatewaySettingsTransition(value, phase: phase); try store.markGatewaySettingsTransition(value, phase: phase)
            XCTAssertEqual(try store.gatewaySettingsTransition(accountID: value.accountID).phase, phase)
        }
        try store.markGatewaySettingsTransition(value, phase: .retained)
        XCTAssertEqual(try store.gatewaySettingsTransition(accountID: value.accountID).phase, .consumersObserved)
        try store.completeGatewaySettingsTransition(value); try store.completeGatewaySettingsTransition(value)
        XCTAssertNil(try store.gatewaySettingsTransition(accountID: value.accountID).pending)
    }
    func testCurrentRevisionChangesAtomicallyAndStaleOrCompetingRevisionsCannotReplaceIt() throws {
        let r = try Ready(), store = r.fixture.runtime.machine, first = try r.revision(), competing = try r.revision(2)
        try store.retainGatewaySettingsTransition(first)
        XCTAssertThrowsError(try store.retainGatewaySettingsTransition(competing))
        XCTAssertThrowsError(try store.markGatewaySettingsTransition(competing, phase: .quiesced))
        try finish(first, store)
        XCTAssertThrowsError(try store.retainGatewaySettingsTransition(competing))
        let second = try r.revision(3, previous: first)
        try store.retainGatewaySettingsTransition(second)
        XCTAssertThrowsError(try store.retainGatewaySettingsTransition(first))
        XCTAssertThrowsError(try store.completeGatewaySettingsTransition(first))
        XCTAssertEqual(try store.gatewaySettingsTransition(accountID: first.accountID).active?.encoded, try first.encoded)
        try finish(second, store)
        let done = try store.gatewaySettingsTransition(accountID: first.accountID)
        XCTAssertEqual(try done.active?.encoded, try second.encoded); XCTAssertNil(done.pending); XCTAssertNil(done.phase)
        XCTAssertThrowsError(try store.retainGatewaySettingsTransition(first))
        XCTAssertEqual(try store.gatewayRuntimeActivation(accountID: first.accountID).plan?.encoded, try r.activation.encoded)
        XCTAssertTrue(try store.gatewayRuntimeActivation(accountID: first.accountID).jobRegistered)
        XCTAssertEqual(try r.fixture.state().intent, r.fixture.intent)
    }
    func testLostCommitRepliesRecoverTheCommittedStageWithoutRepeatingAnExternalAction() throws {
        for stage in 0...4 {
            let r = try Ready(), f = r.fixture, store = f.runtime.machine, value = try r.revision()
            if stage > 0 { try store.retainGatewaySettingsTransition(value) }
            if stage > 1 {
                for raw in 1..<stage { try store.markGatewaySettingsTransition(value, phase: XCTUnwrap(.init(rawValue: Int64(raw)))) }
            }
            try store.close(); var armed = false
            let writer = try f.runtime.f.open(hook: { if armed { throw Interrupted() } }); armed = true
            XCTAssertThrowsError(try {
                if stage == 0 { try writer.retainGatewaySettingsTransition(value) }
                else if stage == 4 { try writer.completeGatewaySettingsTransition(value) }
                else { try writer.markGatewaySettingsTransition(value, phase: XCTUnwrap(.init(rawValue: Int64(stage)))) }
            }()) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertThrowsError(try writer.gatewaySettingsTransition(accountID: value.accountID)); try writer.close()
            let restored = try f.runtime.f.open(); defer { try? restored.close() }
            let state = try restored.gatewaySettingsTransition(accountID: value.accountID)
            if stage == 4 { XCTAssertNil(state.pending); XCTAssertEqual(try state.active?.encoded, try value.encoded) }
            else { XCTAssertEqual(try state.pending?.encoded, try value.encoded); XCTAssertEqual(state.phase?.rawValue, Int64(stage)) }
        }
    }
    private func tamper(_ r: Ready, _ change: String) throws {
        let path = r.fixture.runtime.f.root.appendingPathComponent("machine/installation.sqlite").path
        var connection: OpaquePointer?
        guard sqlite3_open_v2(path, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK,
              let connection else { throw Interrupted() }
        defer { sqlite3_close(connection) }
        guard sqlite3_exec(connection, "PRAGMA ignore_check_constraints=ON;UPDATE gateway_settings_transition_v1 SET " + change, nil, nil, nil) == SQLITE_OK else { throw Interrupted() }
    }
    func testCorruptIndexRecordOrStageClosesTheStoreInsteadOfHidingTheTransition() throws {
        for change in ["account=zeroblob(16)", "activation=zeroblob(32)", "sequence=1", "digest=zeroblob(32)",
                       "pending=x'00'", "phase=9", "pending=NULL"] {
            let r = try Ready(), value = try r.revision(), store = r.fixture.runtime.machine
            try store.retainGatewaySettingsTransition(value); try tamper(r, change)
            XCTAssertThrowsError(try store.gatewaySettingsTransition(accountID: value.accountID)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord, change)
            }
            XCTAssertThrowsError(try store.gatewaySettingsTransition(accountID: value.accountID)) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
        }
    }
}
