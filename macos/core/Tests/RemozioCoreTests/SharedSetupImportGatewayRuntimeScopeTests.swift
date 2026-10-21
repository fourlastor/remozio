import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SharedSetupImportGatewayRuntimeScopeTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Fixture {
        let core: GatewayJournalSetupStoreTests.Fixture
        let proposal: PortableSetup
        var retained: SharedSetupImportIntent
        init(phase: SetupPortableImportProgress.Phase = .gatewayPrepared, publish: Bool = true,
             changedLimits: Bool = false, senderID: String = "123", provider: Bool = true) throws {
            core = try .init()
            try core.machine.retainGatewayJournalIntent(core.intent)
            let selection = try GatewayRuntimeSettingsSelection(service: core.bundle.gateway.settings, activation: .init(),
                maximumWakeConnections: changedLimits ? 5 : 4)
            proposal = .init(defaults: .init(presence: core.runtime.plan.host.command.presence.presence.policy, gateway: selection),
                fcm: provider ? core.provider : nil,
                pushClient: provider ? try .init(projectID: core.provider.project, senderID: senderID, packageName: "dev.remozio.android") : nil)
            retained = try .init(scope: .init(account: core.runtime.account, inventory: XCTUnwrap(core.machine.inventory())), proposal: proposal)
            if publish { try publishImport(phase: phase) }
        }
        func publishImport(phase: SetupPortableImportProgress.Phase) throws {
            let account = core.runtime.account, f = core.runtime.f
            try f.prepare("machine/SharedSetupImport", .sharedSetupImport)
            let journal = try SharedSetupImportJournal(lease: .init(anchor: f.root.path, relativeDirectory: "machine/SharedSetupImport",
                owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(),
                macID: account.macID, installationID: account.installationID, initialize: true)
            defer { try? journal.close() }
            try journal.begin(retained)
            while retained.phase.rawValue < phase.rawValue {
                guard let next = SetupPortableImportProgress.Phase(rawValue: retained.phase.rawValue + 1) else { throw Interrupted() }
                retained = try journal.advance(retained, to: next)
            }
        }
        func advance(to phase: SetupPortableImportProgress.Phase) throws {
            retained = try core.machine.withSharedImportJournal { journal in
                guard let journal else { throw Interrupted() }; return try journal.advance(retained, to: phase)
            }
        }
        func validate(expected: SharedSetupImportIntent? = nil, legacy: Bool = false,
                      activation: GatewayRuntimeActivationSettings? = nil) throws {
            try SharedSetupImportGatewayRuntimeScope.validate(machine: core.machine, account: core.runtime.account,
                expected: legacy ? nil : expected ?? retained, activationSettings: activation)
        }
        func scope(expected: SharedSetupImportIntent?) throws -> GatewayJournalSetupRootScope {
            let inventory = try XCTUnwrap(core.machine.inventory()), foreground = core.runtime.plan
            let configuration = try GatewayJournalSetupServiceConfiguration(intent: core.intent,
                bundlePath: inventory.bundlePath, codePolicy: foreground.host.codePolicy)
            return try .init(machine: core.machine, account: core.runtime.account, foreground: foreground, inventory: inventory,
                configuration: configuration, expected: core.state(), expectedImport: expected)
        }
    }
    func testLegacyRootOperationWithoutAnImportPreservesItsExistingScope() throws {
        let f = try Fixture(publish: false)
        try f.validate(legacy: true)
        let scope = try f.scope(expected: nil); defer { try? scope.close() }
        try scope.verifyCurrent()
    }
    func testImportAcceptedAfterCallerPreflightBlocksTheLegacyRootOperation() throws {
        let f = try Fixture(publish: false); try f.validate(legacy: true)
        try f.publishImport(phase: .gatewayPrepared)
        XCTAssertThrowsError(try f.scope(expected: nil)) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
    }
    func testLegacyOperationsStayBlockedUntilRootCompletion() throws {
        let f = try Fixture(phase: .retained)
        for phase: SetupPortableImportProgress.Phase in [.retained, .runtimePublished, .gatewayPrepared, .relayPrepared] {
            if f.retained.phase != phase { try f.advance(to: phase) }
            XCTAssertThrowsError(try f.validate(legacy: true)) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
        }
        try f.advance(to: .rootComplete); XCTAssertNoThrow(try f.validate(legacy: true))
    }
    func testImportCannotInitializeGatewayBeforePreparedOutputsExist() throws {
        for phase: SetupPortableImportProgress.Phase in [.retained, .runtimePublished] {
            let f = try Fixture(phase: phase)
            XCTAssertThrowsError(try f.validate()) { XCTAssertEqual($0 as? SharedSetupImportError, .invalidTransition) }
        }
    }
    func testBothPreparedPhasesAcceptOnlyTheCurrentExactImport() throws {
        let f = try Fixture(); try f.validate(); let old = f.retained
        try f.advance(to: .relayPrepared); try f.validate()
        XCTAssertThrowsError(try f.validate(expected: old)) { XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision) }
    }
    func testACompetingOperationCannotAdoptTheSameGatewayOutputs() throws {
        let f = try Fixture()
        let other = try SharedSetupImportIntent(scope: f.retained.scope, proposal: f.proposal)
            .advanced(to: .runtimePublished).advanced(to: .gatewayPrepared)
        XCTAssertThrowsError(try f.validate(expected: other)) { XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision) }
    }
    func testGatewayConnectionLimitsAndPushScopeMustMatchTheReviewedRecipe() throws {
        let limits = try Fixture(changedLimits: true)
        XCTAssertThrowsError(try limits.validate()) { XCTAssertEqual($0 as? GatewayPreparationError, .changedScope) }
        let sender = try Fixture(senderID: "456")
        XCTAssertThrowsError(try sender.validate()) { XCTAssertEqual($0 as? GatewayPreparationError, .changedScope) }
    }
    func testGatewayActivationCannotReplaceImportedActivationTimingsWithDefaults() throws {
        let f = try Fixture(), selected = try XCTUnwrap(f.proposal.defaults.gateway).activation
        try f.validate(activation: selected)
        let changed = try GatewayRuntimeActivationSettings(wakePollMilliseconds: selected.wakePollMilliseconds + 1,
            wakeTimeoutMilliseconds: selected.wakeTimeoutMilliseconds)
        XCTAssertThrowsError(try f.validate(activation: changed)) { XCTAssertEqual($0 as? GatewayPreparationError, .conflictingMaterial) }
    }
    func testProviderFreeOrCompletedImportsDoNotAuthorizeGatewayMutation() throws {
        let empty = try Fixture(provider: false)
        XCTAssertThrowsError(try empty.validate()) { XCTAssertEqual($0 as? GatewayPreparationError, .incomplete) }
        let done = try Fixture(phase: .rootComplete)
        XCTAssertThrowsError(try done.validate()) { XCTAssertEqual($0 as? SharedSetupImportError, .invalidTransition) }
    }
    func testAnOpenRootScopeRechecksTheImportBeforeItsNextOperation() throws {
        let f = try Fixture(), scope = try f.scope(expected: f.retained)
        defer { try? scope.close() }
        try scope.verifyCurrent(); try f.advance(to: .relayPrepared)
        XCTAssertThrowsError(try scope.verifyCurrent()) { XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision) }
        XCTAssertFalse(try f.core.state().initialized)
    }
}
