import Foundation
import XCTest
@testable import RemozioCore

/// Owned SQLite recovery and logical signed metadata. Native Root startup remains a separate integration gate.
final class AuthorityGatewaySettingsStartupPlanTests: XCTestCase {
    private typealias Ready = GatewayRuntimeSettingsStoreTests.Ready
    private func plan(_ r: Ready, store: PreparationIntentStore? = nil) throws -> AuthorityGatewaySettingsStartupPlan {
        try XCTUnwrap(AuthorityGatewaySettingsStartupPlan.load(machine: store ?? r.fixture.runtime.machine,
            authority: r.fixture.runtime.plan.host))
    }
    private func complete(_ r: Ready, revision: GatewayRuntimeSettingsRevision) throws {
        let store = r.fixture.runtime.machine
        try store.retainGatewaySettingsTransition(revision)
        for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() { try store.markGatewaySettingsTransition(revision, phase: phase) }
        try store.completeGatewaySettingsTransition(revision)
    }
    func testInitialActivationHasOneExactCommitFloorWithoutChangingAnyRetainedState() throws {
        let r = try Ready(), store = r.fixture.runtime.machine
        let before = try store.gatewaySettingsTransition(accountID: r.activation.accountID), foreground = try r.fixture.runtime.plan.encoded
        let startup = try plan(r), initial = try GatewayRuntimeCommit(r.activation.extensions).observationDigest
        XCTAssertFalse(startup.requiresFreshQuiescence); XCTAssertNil(startup.pendingChange)
        XCTAssertEqual(startup.activeCommitDigest, initial); XCTAssertTrue(startup.allowsInitialInstallation(commitDigest: initial))
        XCTAssertFalse(startup.allowsInitialInstallation(commitDigest: Data(repeating: 0, count: 32)))
        XCTAssertEqual(startup.options.canonicalBytes, r.activation.extensions.authority.material.phonePush.canonicalBytes)
        XCTAssertEqual(try store.gatewaySettingsTransition(accountID: r.activation.accountID).phase, before.phase)
        XCTAssertEqual(try r.fixture.runtime.plan.encoded, foreground)
        XCTAssertEqual(String(describing: startup), "AuthorityGatewaySettingsStartupPlan(redacted)")
    }
    func testEveryPendingPhaseRequiresFreshQuiescenceAfterTheStoreReopens() throws {
        for phase in GatewayRuntimeSettingsPhase.allCases {
            let r = try Ready(), store = r.fixture.runtime.machine, revision = try r.revision()
            try store.retainGatewaySettingsTransition(revision)
            for stage in GatewayRuntimeSettingsPhase.allCases.dropFirst() where stage.rawValue <= phase.rawValue {
                try store.markGatewaySettingsTransition(revision, phase: stage)
            }
            try store.close(); let restored = try r.fixture.runtime.f.open(); defer { try? restored.close() }
            let startup = try plan(r, store: restored), change = try XCTUnwrap(startup.pendingChange)
            XCTAssertTrue(startup.requiresFreshQuiescence); XCTAssertEqual(change.revisionDigest, try revision.digest)
            XCTAssertEqual(change.previousCommitDigest, startup.activeCommitDigest)
            XCTAssertFalse(startup.allowsInitialInstallation(commitDigest: change.previousCommitDigest))
            XCTAssertFalse(startup.allowsInitialInstallation(commitDigest: change.selectedCommitDigest))
            XCTAssertEqual(try restored.gatewaySettingsTransition(accountID: revision.accountID).phase, phase)
            XCTAssertEqual(try restored.gatewaySettingsTransition(accountID: revision.accountID).pending?.encoded, try revision.encoded)
        }
    }
    func testCompletionPinsTheNewFloorAndRejectsThePreviousActivationCommitAfterReopen() throws {
        let r = try Ready(), first = try r.revision(), initial = try plan(r).activeCommitDigest
        try complete(r, revision: first)
        let selected = try plan(r); XCTAssertFalse(selected.requiresFreshQuiescence)
        XCTAssertNotEqual(selected.activeCommitDigest, initial); XCTAssertFalse(selected.allowsInitialInstallation(commitDigest: initial))
        XCTAssertTrue(selected.requiresConsumerRecovery)
        XCTAssertFalse(selected.allowsInitialInstallation(commitDigest: selected.activeCommitDigest))
        try r.fixture.runtime.machine.close(); let restored = try r.fixture.runtime.f.open(); defer { try? restored.close() }
        let reopened = try plan(r, store: restored)
        XCTAssertEqual(reopened.activeCommitDigest, selected.activeCommitDigest)
        XCTAssertTrue(reopened.requiresConsumerRecovery)
        XCTAssertFalse(reopened.allowsInitialInstallation(commitDigest: reopened.activeCommitDigest))
    }
    func testAnActiveRevisionAndItsPendingSuccessorKeepBothExactCommitBindings() throws {
        let r = try Ready(), first = try r.revision(); try complete(r, revision: first)
        let previous = try plan(r).activeCommitDigest, second = try r.revision(2, previous: first)
        try r.fixture.runtime.machine.retainGatewaySettingsTransition(second)
        let pending = try plan(r), change = try XCTUnwrap(pending.pendingChange)
        XCTAssertEqual(pending.activeCommitDigest, previous); XCTAssertEqual(change.previousCommitDigest, previous)
        XCTAssertEqual(change.revisionDigest, try second.digest); XCTAssertNotEqual(change.selectedCommitDigest, previous)
        XCTAssertFalse(pending.allowsInitialInstallation(commitDigest: previous))
    }
    func testForeignAuthorityAndInconsistentPendingStateCannotBecomeAStartupFence() throws {
        let r = try Ready(), other = try Ready(), f = r.fixture
        XCTAssertThrowsError(try AuthorityGatewaySettingsStartupPlan.load(machine: f.runtime.machine, authority: other.fixture.runtime.plan.host))
        let inventory = try XCTUnwrap(f.runtime.machine.inventory())
        XCTAssertThrowsError(try AuthorityGatewaySettingsStartupPlan(authority: f.runtime.plan.host,
            state: .init(active: nil, pending: nil, phase: .quiesced), activation: r.activation,
            journal: f.state(), foreground: f.runtime.plan, inventory: inventory))
        let foreign = try other.revision()
        XCTAssertThrowsError(try AuthorityGatewaySettingsStartupPlan(authority: f.runtime.plan.host,
            state: .init(active: nil, pending: foreign, phase: .retained), activation: r.activation,
            journal: f.state(), foreground: f.runtime.plan, inventory: inventory))
    }
    func testIncompleteGatewayActivationDoesNotAuthorizeOptionalStartup() throws {
        let r = try Ready(register: false)
        XCTAssertThrowsError(try AuthorityGatewaySettingsStartupPlan.load(machine: r.fixture.runtime.machine,
            authority: r.fixture.runtime.plan.host))
    }
}
