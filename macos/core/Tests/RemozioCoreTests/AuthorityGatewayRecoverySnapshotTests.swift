import Foundation
import XCTest
@testable import RemozioCore

final class AuthorityGatewayRecoverySnapshotTests: XCTestCase {
    private struct Fixture {
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let revision: GatewayRuntimeSettingsRevision
        init() throws {
            ready = try .init(); revision = try ready.revision()
            try ready.fixture.runtime.machine.retainGatewaySettingsTransition(revision)
        }
        var machine: PreparationIntentStore { ready.fixture.runtime.machine }
        var authority: InstalledAuthorityCommandConfiguration { ready.fixture.runtime.plan.host }
        func complete() throws {
            for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() { try machine.markGatewaySettingsTransition(revision, phase: phase) }
            try machine.completeGatewaySettingsTransition(revision)
        }
        func snapshot(_ attempt: UInt8 = 1) throws -> AuthorityGatewayRecoverySnapshot {
            try .load(machine: machine, authority: authority, attemptID: Data(repeating: attempt, count: 16))
        }
    }
    func testStatusDistinguishesInitialPendingAndCompletedWithoutGrantingRecovery() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), machine = r.fixture.runtime.machine, authority = r.fixture.runtime.plan.host
        XCTAssertEqual(try AuthorityGatewayRecoverySnapshot.status(machine: machine, authority: authority), .initial)
        XCTAssertThrowsError(try AuthorityGatewayRecoverySnapshot.load(machine: machine, authority: authority, attemptID: Data(repeating: 1, count: 16)))
        let revision = try r.revision(); try machine.retainGatewaySettingsTransition(revision)
        XCTAssertEqual(try AuthorityGatewayRecoverySnapshot.status(machine: machine, authority: authority), .pending)
        XCTAssertThrowsError(try AuthorityGatewayRecoverySnapshot.load(machine: machine, authority: authority, attemptID: Data(repeating: 1, count: 16)))
        for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() { try machine.markGatewaySettingsTransition(revision, phase: phase) }
        try machine.completeGatewaySettingsTransition(revision)
        XCTAssertEqual(try AuthorityGatewayRecoverySnapshot.status(machine: machine, authority: authority), .completed)
    }
    func testImmutableSnapshotRevalidatesAfterTheOriginalMachineWriterCloses() throws {
        let f = try Fixture(); try f.complete(); let snapshot = try f.snapshot(), authority = f.authority
        let expected = try snapshot.plan.fence.encoded, inventory = try f.machine.inventory()
        try f.machine.close()
        let reopened = try f.ready.fixture.runtime.f.open(); defer { try? reopened.close() }
        try snapshot.validate(machine: reopened, authority: authority)
        var invoked = false
        try snapshot.withPublicationScope(machine: reopened, authority: authority) { scope in
            invoked = true; XCTAssertEqual(try scope.plan.fence.encoded, expected)
        }
        XCTAssertTrue(invoked); XCTAssertEqual(try reopened.inventory(), inventory)
        XCTAssertEqual(try reopened.gatewaySettingsTransition(accountID: snapshot.account.accountID).active?.encoded, try f.revision.encoded)
    }
    func testAnotherNativeAuthorityOrAccountCannotUseTheSnapshot() throws {
        let f = try Fixture(), other = try Fixture(); try f.complete(); try other.complete()
        let snapshot = try f.snapshot()
        XCTAssertThrowsError(try snapshot.validate(machine: other.machine, authority: other.authority))
        XCTAssertThrowsError(try snapshot.validate(machine: f.machine, authority: other.authority))
        XCTAssertThrowsError(try AuthorityGatewayRecoverySnapshot.load(machine: f.machine, authority: other.authority, attemptID: Data(repeating: 1, count: 16)))
    }
    func testPendingOrCompletedSuccessorCannotReuseTheOldPublicationScope() throws {
        let f = try Fixture(); try f.complete(); let snapshot = try f.snapshot(), next = try f.ready.revision(2, previous: f.revision)
        try f.machine.retainGatewaySettingsTransition(next)
        var invoked = false
        XCTAssertThrowsError(try snapshot.withPublicationScope(machine: f.machine, authority: f.authority) { _ in invoked = true })
        XCTAssertFalse(invoked); XCTAssertThrowsError(try f.snapshot())
        for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() { try f.machine.markGatewaySettingsTransition(next, phase: phase) }
        try f.machine.completeGatewaySettingsTransition(next)
        XCTAssertThrowsError(try snapshot.validate(machine: f.machine, authority: f.authority))
        let current = try f.snapshot(); XCTAssertEqual(current.plan.commit.settingsSequence, 2)
    }
    func testScopeChangeInsideSynchronousPublicationIsDetectedBeforeReturning() throws {
        let f = try Fixture(); try f.complete(); let snapshot = try f.snapshot(), next = try f.ready.revision(2, previous: f.revision)
        XCTAssertThrowsError(try snapshot.withPublicationScope(machine: f.machine, authority: f.authority) { _ in
            try f.machine.retainGatewaySettingsTransition(next)
        })
        XCTAssertEqual(try f.machine.gatewaySettingsTransition(accountID: f.revision.accountID).pending?.encoded, try next.encoded)
    }
}
