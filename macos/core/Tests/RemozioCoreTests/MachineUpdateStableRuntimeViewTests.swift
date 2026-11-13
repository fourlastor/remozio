import Foundation
import XCTest
@testable import RemozioCore

/// Owned metadata fixtures do not prove native startup, file custody, or provider compatibility.
final class MachineUpdateStableRuntimeViewTests: XCTestCase {
    private typealias Fixture = RetainedRuntimeCompatibilityFixture
    private typealias View = MachineUpdateStableRuntimeView
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedRuntimeCompatibilityFixture(body)
    }
    private func inputs(_ f: Fixture, retained: [MachineUpdateRetainedSetupActivationSnapshot] = []) throws
        -> MachineUpdateStableRuntimeViewInputs {
        try f.machine.stableRuntimeViewInputs(expected: f.machine.stableRuntimeSource(candidate: f.candidate),
            retained: retained, candidate: f.candidate)
    }
    private func duplicatingRuntime(_ value: MachineUpdateStableRuntimeViewInputs) throws
        -> MachineUpdateStableRuntimeViewInputs {
        let old = value.runtime.inputs, runtime = try XCTUnwrap(old.runtimes.first)
        let copy = RuntimeReleaseCompatibilitySnapshot.Inputs(schemaVersion: old.schemaVersion, macID: old.macID,
            inventory: old.inventory, runtimes: old.runtimes + [runtime], gateways: old.gateways,
            sharedImport: old.sharedImport, auditUpgrades: old.auditUpgrades, auditGraphs: old.auditGraphs,
            auditCutovers: old.auditCutovers, updateAdmissionRegistration: old.updateAdmissionRegistration,
            machineUpdateActivation: old.machineUpdateActivation, machineUpdateReplacement: old.machineUpdateReplacement,
            machineUpdateConfigurationEpoch: old.machineUpdateConfigurationEpoch, machineUpdateBackendEpoch: old.machineUpdateBackendEpoch,
            completionIntent: old.completionIntent, completionPublication: old.completionPublication, installedRelease: old.installedRelease)
        // This malformed value tests the view's refusal without bypassing a production reader.
        let malformed = RuntimeReleaseCompatibilitySnapshot(inputs: copy, requirements: value.runtime.requirements)
        return try .init(source: value.source, retained: value.retained, runtime: malformed,
            currentJournals: value.currentJournals)
    }

    func testViewSelectsCurrentMembersAndKeepsUnconfiguredRetainedStartupClosed() throws {
        try fixture { f in
            let input = try inputs(f), before = try f.machine.stableMachineUpdateSnapshot(candidate: f.candidate)
            let view = try View(compatibility: input, candidate: f.candidate)
            XCTAssertEqual(view.accounts.map(\.accountID), input.source.accounts.map(\.accountID))
            XCTAssertEqual(view.description, "MachineUpdateStableRuntimeView(redacted)")
            XCTAssertEqual(view.debugDescription, view.description)
            let retained = try XCTUnwrap(view.accounts.first { $0.accountID == f.plan.accountID && $0.scope.ownerUID == f.owner.uid })
            XCTAssertEqual(retained.scope.origin, .retained)
            XCTAssertFalse(retained.scope.inInventory)
            XCTAssertThrowsError(try view.account(f.plan.accountID, ownerUID: f.owner.uid)) {
                XCTAssertEqual($0 as? PreparationStoreError, .notFound)
            }
            XCTAssertNil(retained.configuration)
            XCTAssertNil(retained.ordinaryActivation)
            XCTAssertNil(retained.host)
            XCTAssertTrue(retained.runtime?.configurationPublished == true)
            XCTAssertThrowsError(try view.startupAccount(f.plan.accountID, ownerUID: f.owner.uid)) {
                XCTAssertEqual($0 as? PreparationStoreError, .notFound)
            }
            for account in view.accounts where account.scope.inInventory {
                XCTAssertEqual(try view.account(account.accountID, ownerUID: account.scope.ownerUID).scope, account.scope)
            }
            XCTAssertThrowsError(try view.account(f.plan.accountID, ownerUID: f.owner.uid ^ 1)) {
                XCTAssertEqual($0 as? PreparationStoreError, .notFound)
            }
            XCTAssertThrowsError(try view.account(Data(repeating: 239, count: 16), ownerUID: f.owner.uid)) {
                XCTAssertEqual($0 as? PreparationStoreError, .notFound)
            }
            try view.requireCurrent(machine: f.machine, candidate: f.candidate)
            try f.machine.stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before)
        }
    }

    func testViewKeepsTheInstalledConfigurationAndRegisteredStartupPrerequisites() throws {
        try fixture { f in
            let input = try inputs(f), view = try View(compatibility: input, candidate: f.candidate)
            let archive = try input.source.actual.installed.configuration()
            let configured = view.accounts.filter { $0.configuration != nil && $0.scope.inInventory }
            XCTAssertFalse(configured.isEmpty)
            for account in configured {
                let actual = try XCTUnwrap(account.configuration)
                let expected = try XCTUnwrap(archive.configuration(accountID: account.accountID)).completion
                XCTAssertEqual(try actual.encoded, try expected.encoded)
                XCTAssertEqual(account.host?.canonicalBytes, expected.host.canonicalBytes)
                XCTAssertNil(account.ordinaryActivation)
                if account.runtime?.jobsRegistered == true && account.scope.preparation?.storagePrepared == true {
                    let selected = try view.startupAccount(account.accountID, ownerUID: account.scope.ownerUID)
                    XCTAssertEqual(selected.accountID, account.accountID)
                    XCTAssertTrue(selected.scope.initialization?.complete == true)
                } else {
                    XCTAssertThrowsError(try view.startupAccount(account.accountID, ownerUID: account.scope.ownerUID))
                }
            }
            try view.requireSame(as: View(compatibility: inputs(f), candidate: f.candidate))
        }
    }

    func testViewRefusesDuplicateRuntimeMetadataAndRetainedActivationOutsideTheInstalledSelection() throws {
        try fixture { f in
            let control = try inputs(f)
            XCTAssertNoThrow(try View(compatibility: control, candidate: f.candidate))
            XCTAssertThrowsError(try View(compatibility: duplicatingRuntime(control), candidate: f.candidate)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            try f.inject()
            let retained = try f.capture(), typed = try inputs(f, retained: [retained])
            XCTAssertEqual(typed.runtime.inputs.runtimes.first { $0.reference == f.plan.reference }?.activationRecord,
                try f.plan.encoded)
            XCTAssertThrowsError(try View(compatibility: typed, candidate: f.candidate)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .incomplete)
            }
            XCTAssertThrowsError(try RuntimeActivationPlan.decode(f.plan.encoded))
            XCTAssertNoThrow(try f.machine.inventory())
            try typed.requireCurrent(machine: f.machine, candidate: f.candidate)
        }
    }

    func testViewRejectsChangedImportEvidenceAndCanCaptureTheFreshActualSource() throws {
        try fixture { f in
            let original = try View(compatibility: inputs(f), candidate: f.candidate)
            try f.createImportJournal()
            XCTAssertThrowsError(try original.requireCurrent(machine: f.machine, candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            let current = try View(compatibility: inputs(f), candidate: f.candidate)
            XCTAssertNotEqual(current.compatibility.runtime.inputs.sharedImport, original.compatibility.runtime.inputs.sharedImport)
            XCTAssertThrowsError(try current.requireSame(as: original)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try current.requireCurrent(machine: f.machine, candidate: f.candidate)
            XCTAssertNoThrow(try f.machine.inventory())
        }
    }
    func testInstalledRetainedMemberUsesCompletionHostScopeAndCurrentReleaseValidation() throws {
        try MachineUpdateReplacementTests.withInstalledRetainedRuntimeViewFixture { machine, candidate, runtime in
            let source = runtime.setup.source, inventory = source.actual.inventory
            let scope = try source.account(runtime.preparation.accountID, ownerUID: runtime.preparation.ownerUID)
            XCTAssertEqual(scope.origin, .retained)
            XCTAssertTrue(scope.inInventory)
            let archive = try source.actual.installed.configuration()
            let configuration = try XCTUnwrap(archive.configuration(accountID: scope.accountID)).completion
            XCTAssertEqual(configuration.policyStage, .completion)
            XCTAssertNotEqual(runtime.preparation.releaseDigest, inventory.releaseDigest)
            XCTAssertNotEqual(try configuration.gateway.codePolicy.bytes, try runtime.preparation.initialAuthority.codePolicy.bytes)
            XCTAssertThrowsError(try configuration.gateway.validate(account: runtime.preparation, inventory: inventory)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            try configuration.gateway.requireConfigurationScope(account: runtime.preparation, inventory: inventory)
            try configuration.gateway.validateRelease(candidate)
            let inputs = try machine.stableRuntimeViewInputs(expected: source, retained: [], candidate: candidate)
            let view = try View(compatibility: inputs, candidate: candidate)
            let selected = try view.account(scope.accountID, ownerUID: scope.ownerUID)
            XCTAssertEqual(selected.scope, scope)
            XCTAssertEqual(try selected.configuration?.encoded, try configuration.encoded)
            XCTAssertEqual(selected.host?.canonicalBytes, configuration.host.canonicalBytes)
            try view.requireCurrent(machine: machine, candidate: candidate)
            try runtime.requireCurrent(machine: machine, candidate: candidate)
        }
    }

}
