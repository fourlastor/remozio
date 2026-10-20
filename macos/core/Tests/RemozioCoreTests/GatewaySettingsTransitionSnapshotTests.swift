import Foundation
import XCTest
@testable import RemozioCore

final class GatewaySettingsTransitionSnapshotTests: XCTestCase {
    private typealias Ready = GatewayRuntimeSettingsStoreTests.Ready
    private func expected(_ value: Ready, machine: PreparationIntentStore) throws -> SetupGatewayActivationProgress {
        let owner = value.fixture.runtime.plan.host.command.callerUID
        let account = try XCTUnwrap(machine.accountPreparation(ownerUID: owner))
        let setup = try SetupGatewayProgress(account: account,
            runtime: machine.runtimePreparation(accountID: account.accountID),
            activation: machine.runtimeActivation(accountID: account.accountID),
            material: machine.gatewayPreparation(accountID: account.accountID),
            journal: machine.gatewayJournalPreparation(accountID: account.accountID))
        return try .init(setup: setup, state: machine.gatewayRuntimeActivation(accountID: account.accountID))
    }
    private func load(_ value: Ready, revision: GatewayRuntimeSettingsRevision,
                      machine: PreparationIntentStore) throws -> GatewaySettingsTransitionSnapshot {
        try .load(machine: machine, ownerUID: value.fixture.runtime.plan.host.command.callerUID,
            expected: expected(value, machine: machine), revision: revision)
    }
    private func complete(_ value: GatewayRuntimeSettingsRevision, machine: PreparationIntentStore) throws {
        for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() {
            try machine.markGatewaySettingsTransition(value, phase: phase)
        }
        try machine.completeGatewaySettingsTransition(value)
    }
    func testPendingSnapshotSurvivesARealStoreCloseAndReopenWithoutRetainingItsLease() throws {
        let ready = try Ready(), machine = ready.fixture.runtime.machine, revision = try ready.revision()
        try machine.retainGatewaySettingsTransition(revision)
        let before = try machine.gatewaySettingsTransition(accountID: revision.accountID)
        let snapshot = try load(ready, revision: revision, machine: machine)
        XCTAssertEqual(try snapshot.plan.revision.encoded, try revision.encoded)
        XCTAssertEqual(try machine.gatewaySettingsTransition(accountID: revision.accountID).pending?.encoded, try before.pending?.encoded)
        XCTAssertEqual(try machine.gatewaySettingsTransition(accountID: revision.accountID).phase, before.phase)
        try machine.close()
        let reopened = try ready.fixture.runtime.f.open(); defer { try? reopened.close() }
        var calls = 0
        try snapshot.withPendingScope(machine: reopened) { scope, initialization in
            calls += 1; XCTAssertEqual(try scope.fence.revision.encoded, try revision.encoded)
            XCTAssertTrue(initialization.complete)
        }
        XCTAssertEqual(calls, 1)
    }
    func testAnUnretainedOrForeignRevisionCannotBecomeAPendingSnapshotOrMigrateTheStore() throws {
        let ready = try Ready(), machine = ready.fixture.runtime.machine, revision = try ready.revision()
        XCTAssertThrowsError(try load(ready, revision: revision, machine: machine))
        XCTAssertEqual(try ready.fixture.runtime.f.sql("PRAGMA user_version"), 10)
        try machine.retainGatewaySettingsTransition(revision)
        let foreign = try Ready().revision()
        XCTAssertThrowsError(try load(ready, revision: foreign, machine: machine))
        XCTAssertEqual(try machine.gatewaySettingsTransition(accountID: revision.accountID).pending?.encoded, try revision.encoded)
    }
    func testWrongOwnerAndForeignActivationProgressRefuseWithoutChangingThePendingRevision() throws {
        let ready = try Ready(), machine = ready.fixture.runtime.machine, revision = try ready.revision()
        try machine.retainGatewaySettingsTransition(revision)
        let progress = try expected(ready, machine: machine)
        XCTAssertThrowsError(try GatewaySettingsTransitionSnapshot.load(machine: machine,
            ownerUID: progress.setup.ownerUID + 1, expected: progress, revision: revision))
        let other = try Ready()
        XCTAssertThrowsError(try GatewaySettingsTransitionSnapshot.load(machine: machine,
            ownerUID: progress.setup.ownerUID, expected: expected(other, machine: other.fixture.runtime.machine), revision: revision))
        XCTAssertEqual(try machine.gatewaySettingsTransition(accountID: revision.accountID).pending?.encoded, try revision.encoded)
    }
    func testCompletionChangesTheAllowedScopeAndASuccessorInvalidatesTheOldSnapshot() throws {
        let ready = try Ready(), machine = ready.fixture.runtime.machine, revision = try ready.revision()
        try machine.retainGatewaySettingsTransition(revision)
        let snapshot = try load(ready, revision: revision, machine: machine)
        XCTAssertThrowsError(try snapshot.withCompleteScope(machine: machine) { _, _ in XCTFail() })
        try complete(revision, machine: machine)
        XCTAssertThrowsError(try snapshot.withPendingScope(machine: machine) { _, _ in XCTFail() })
        try snapshot.withCompleteScope(machine: machine) { _, _ in }
        let next = try ready.revision(2, previous: revision)
        try machine.retainGatewaySettingsTransition(next)
        XCTAssertThrowsError(try snapshot.withCompleteScope(machine: machine) { _, _ in XCTFail() })
        XCTAssertThrowsError(try snapshot.withPendingScope(machine: machine) { _, _ in XCTFail() })
    }
}
