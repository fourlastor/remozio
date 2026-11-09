import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

private enum ReplacementFixtureError: Error { case injected, signature }

private struct SharedRestartSnapshot: @unchecked Sendable {
    let value: MachineUpdateRestartSnapshot
}

/// Owns synthetic application trees and real SQLite files. It grants no installed Root authority.
private final class MachineReplacementFixture {
    let files: BoundAdmissionRegistrationFixture
    var machine: UpdateCandidateStorageFixture { files.machine }
    let installed: ReleaseDestinationLease
    let directory: ReleaseDestinationLease
    let candidate: UpdateSchedulingCandidateRecord
    let activation: MachineUpdateActivationRecord
    let policySnapshot: AuthorityCodePolicySnapshot
    let oldRelease: SignedReleaseEvidence
    let newRelease: SignedReleaseEvidence
    let installedReadiness: Bool
    var quiet: UpdateQuiescenceLease
    let oldIdentity: PreparationFileIdentity
    let newIdentity: PreparationFileIdentity
    var oldURL: URL { URL(fileURLWithPath: installed.path).appendingPathComponent("Remozio.app") }
    var preparedURL: URL { URL(fileURLWithPath: machine.destination.path).appendingPathComponent(candidate.preparation.bundleName) }
    init(configurationEpoch: Bool = false, backendEpoch: Bool = false, installedReadiness: Bool = false,
         completionIntent: Bool = false,
         beforeActivation: (BoundAdmissionRegistrationFixture) throws -> Void = { _ in }) throws {
        self.installedReadiness = installedReadiness
        files = try .init(machine: UpdateCandidateStorageFixture(admission: true, activation: true,
            replacement: true, ownedInstalledBundle: true))
        try beforeActivation(files)
        let registration = try files.prepare(); oldRelease = files.machine.release
        try MachineUpdateActivationStorage.enableInLease(installedRelease: oldRelease, policy: files.machine.policy, store: files.machine.store)
        try MachineUpdateReplacementStorage.enableInLease(installedRelease: oldRelease, policy: files.machine.policy, store: files.machine.store)
        let parent = files.root.appendingPathComponent("Installed")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false); XCTAssertEqual(chmod(parent.path, 0o755), 0)
        let app = parent.appendingPathComponent("Remozio.app")
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: false); XCTAssertEqual(chmod(app.path, 0o755), 0)
        try Data("installed before replacement".utf8).write(to: app.appendingPathComponent("fixture"))
        XCTAssertEqual(chmod(app.appendingPathComponent("fixture").path, 0o644), 0)
        installed = try .init(anchor: files.root.path, relativeDirectory: "Installed", owner: getuid())
        directory = try files.directory()
        XCTAssertEqual(try files.machine.store.inventory()?.bundlePath, app.path)
        newRelease = try files.machine.editedRelease { c in
            var formats = c.formats
            var requiredFormats: [RetainedReleaseFormat] = []
            if configurationEpoch || backendEpoch {
                requiredFormats += try MachineUpdateConfigurationEpochRecord.requirements
                    + MachineUpdateConfigurationEpochRecord.publicationRequirements
                    + GatewaySettingsConsumerHostConfiguration.releaseBoundFormatRequirements
            }
            if backendEpoch {
                requiredFormats += try MachineUpdateBackendEpochRecord.requirements + MachineUpdateBackendEpochRecord.publicationRequirements
                requiredFormats += try MachineUpdateConsumerHealthReleaseValidation.formatRequirements
            }
            if completionIntent {
                requiredFormats += try MachineUpdateCompletionIntentRecord.requirements
                    + MachineUpdateCompletionPublicationRecord.requirements + MachineUpdateInstalledReleaseRecord.requirements
                    + MachineUpdateInstalledReleaseRecord.provenanceRequirements + MachineUpdateActivationRecord.finalizationRequirements
            }
            if installedReadiness { requiredFormats += try MachineUpdateAuthorityReadinessJobTransition.formatRequirements }
            for required in requiredFormats where required.role == c.role {
                    if let index = formats.firstIndex(where: { $0.name == required.name }) {
                        let current = formats[index]
                        formats[index] = try .init(name: current.name, readers: current.readers.union(required.readVersions),
                            writers: current.writers.union(required.writeVersions))
                    } else {
                        formats.append(try .init(name: required.name, readers: required.readVersions, writers: required.writeVersions))
                    }
            }
            return try .init(role: c.role, identifier: c.identifier, generation: c.generation + 1, relativePath: c.relativePath,
                codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: formats, requests: c.requests)
        }
        candidate = try files.machine.select(files.machine.copy(release: newRelease))
        oldIdentity = try installed.preparationCopyIdentity(name: "Remozio.app")
        newIdentity = try XCTUnwrap(candidate.preparation.copyIdentity)
        let drain = try UpdateActivationAdmission(anchor: files.root.path, relativeDirectory: "machine",
            owner: getuid(), expected: registration.machine).beginDrain()
        let pending = try files.machine.store.beginMachineUpdateActivation(candidate: candidate, registration: registration,
            runtime: files.machine.store.retainedRuntimeCompatibilityInputs(), replacing: nil,
            directory: directory, drain: drain, verifyCurrent: {})
        quiet = try XCTUnwrap(drain.acquireQuiescence())
        let preflight = try files.machine.policyPreflight(pending, directory: directory, quiet: quiet)
        let account = files.machine.account
        policySnapshot = try XCTUnwrap(preflight.policies.first { $0.accountID == account }?.snapshot)
        activation = try files.machine.store.markMachineUpdateActivationStarted(pending, preflight: preflight,
            directory: directory, quiescence: quiet, verifyCurrent: {})
    }
    deinit { quiet.close(); installed.close(); directory.close() }
    func inspect(_ path: URL, _ team: String, _ identifier: String) throws -> SignedReleaseEvidence {
        switch try String(contentsOf: path.appendingPathComponent("fixture"), encoding: .utf8) {
        case "installed before replacement": return oldRelease
        case "synthetic candidate copy": return newRelease
        default: throw ReplacementFixtureError.signature
        }
    }
    func run(stage: (ProtectedMachineUpdateReplacement.Stage) throws -> Void = { _ in },
        policy: (() throws -> AuthorityCodePolicy)? = nil) throws -> MachineUpdateReplacementEvidence {
        try ProtectedMachineUpdateReplacement.replaceOrRecoverInLease(activation: activation, machineDirectory: directory,
            installed: installed, prepared: machine.destination, store: machine.store, quiescence: quiet,
            readPolicy: policy ?? { self.machine.policy }, inspect: inspect, didStage: stage)
    }
    func reopen(inventoryRecordLimit: Int32 = 278_528) throws {
        quiet.close(); try machine.reopen(inventoryRecordLimit: inventoryRecordLimit)
        let drain = try UpdateActivationAdmission(anchor: files.root.path, relativeDirectory: "machine",
            owner: getuid(), expected: files.machine.store.updateAdmissionRegistration()!.machine).beginDrain()
        quiet = try XCTUnwrap(drain.acquireQuiescence())
    }
    func assertBefore(file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try installed.preparationCopyIdentity(name: "Remozio.app"), oldIdentity, file: file, line: line)
        XCTAssertEqual(try machine.destination.preparationCopyIdentity(name: candidate.preparation.bundleName), newIdentity, file: file, line: line)
    }
    func assertAfter(file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try installed.preparationCopyIdentity(name: "Remozio.app"), newIdentity, file: file, line: line)
        XCTAssertEqual(try machine.destination.preparationCopyIdentity(name: candidate.preparation.bundleName), oldIdentity, file: file, line: line)
    }
}

final class MachineUpdateReplacementTests: XCTestCase {
    private typealias Fixture = MachineReplacementFixture
    private func observe(_ f: Fixture, policy: (() throws -> AuthorityCodePolicy)? = nil) throws -> MachineUpdateReplacementObservation {
        try ProtectedMachineUpdateReplacement.observeInLease(activation: f.activation, machineDirectory: f.directory,
            installed: f.installed, prepared: f.machine.destination, store: f.machine.store,
            readPolicy: policy ?? { f.machine.policy }, inspect: f.inspect)
    }

    private func bindRestartSource(_ f: Fixture) throws {
        XCTAssertThrowsError(try f.run(stage: { if $0 == .bindingCommitted { throw ReplacementFixtureError.injected } }))
    }

    private func restartSource(_ f: Fixture) throws -> MachineUpdateRestartSource {
        try f.machine.store.machineUpdateRestartSource(f.activation, directory: f.directory)
    }

    private func reserveRestartAccount(_ files: BoundAdmissionRegistrationFixture, offset: UInt32 = 1000,
                                       initialize: Bool = false, complete: Bool = false) throws -> AccountPreparationIntent {
        let fixture = files.machine.f.f
        let identity = LocalAccountIdentity(uid: getuid() + offset, primaryGroupID: getgid(), directoryID: UUID())
        let account = try fixture.begin(files.machine.store, identity: identity)
        if complete { return try fixture.resume(files.machine.store, account) }
        if initialize {
            let pinned = try files.machine.store.pinAccountPreparation(expected: account, publicKey: fixture.key)
            _ = try fixture.beginStores(files.machine.store, pinned)
            return pinned
        }
        return account
    }

    func testObservationRequiresADurableBindingWithoutCreatingOne() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try observe(f)) { XCTAssertEqual($0 as? MachineUpdateReplacementError, .changedBinding) }
        XCTAssertNil(try f.machine.store.machineUpdateReplacement()); try f.assertBefore()
    }

    func testWarmReplacementReadsStillRejectChangedRowsAndCurrentCandidateColumns() throws {
        let mutations = [
            "UPDATE machine_update_replacement_v1 SET revision=zeroblob(16) WHERE id=1",
            "UPDATE machine_update_replacement_v1 SET record=x'00' WHERE id=1",
            "UPDATE update_scheduling_candidate_v1 SET generation=zeroblob(8) WHERE id=1"]
        for mutation in mutations {
            let f = try Fixture()
            try bindRestartSource(f)
            let expected = try XCTUnwrap(f.machine.store.machineUpdateReplacement())
            XCTAssertEqual(try f.machine.store.machineUpdateReplacement(), expected)
            try f.machine.sql(mutation)
            XCTAssertThrowsError(try f.machine.store.machineUpdateReplacement()) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            XCTAssertThrowsError(try f.machine.store.records())
            try f.assertBefore()
        }
    }

    func testObservationBeforeExchangeReportsThePreparedLocationAndMakesNoProgress() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .bindingCommitted { throw ReplacementFixtureError.injected } }))
        let before = try f.machine.store.retainedRuntimeCompatibilityInputs()
        let result = try observe(f)
        XCTAssertEqual(result.location, .prepared); XCTAssertEqual(result.record.phase, .prepared)
        XCTAssertEqual(result.activation, f.activation)
        XCTAssertEqual(try result.release.manifest.canonicalBytes, try f.newRelease.manifest.canonicalBytes)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs(), before); try f.assertBefore()
    }

    func testObservationOfAnUnacknowledgedExchangeDoesNotPersistRecoveryOrSwapBack() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .immediatelyAfterExchange { throw ReplacementFixtureError.injected } }))
        let before = try f.machine.store.retainedRuntimeCompatibilityInputs(); f.quiet.close()
        let result = try observe(f)
        XCTAssertEqual(result.location, .installed); XCTAssertEqual(result.record.phase, .prepared)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs(), before); try f.assertAfter()
    }

    func testObservationRefusesAChangedProtectedPolicyAfterExchange() throws {
        let f = try Fixture(); _ = try f.run()
        let raised = try AuthorityCodePolicy(entries: f.machine.policy.entries.map {
            try .init(role: $0.role, teamID: $0.teamID, identifier: $0.identifier, installedGeneration: 2,
                minimumGeneration: 2, codeDirectoryHash: $0.codeDirectoryHash, active: $0.active)
        })
        XCTAssertThrowsError(try observe(f, policy: { raised })) {
            XCTAssertEqual($0 as? MachineUpdateReplacementError, .changedBinding)
        }
        try f.assertAfter()
    }

    func testObservationRefusesAnInstalledCloneWithTheSameSignatureBytes() throws {
        let f = try Fixture(); _ = try f.run()
        try FileManager.default.moveItem(at: f.oldURL, to: f.oldURL.appendingPathExtension("original"))
        try FileManager.default.createDirectory(at: f.oldURL, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(f.oldURL.path, 0o755), 0)
        try Data("synthetic inactive copy".utf8).write(to: f.oldURL.appendingPathComponent("fixture"))
        XCTAssertThrowsError(try observe(f)) { XCTAssertEqual($0 as? MachineUpdateReplacementError, .unknownOutcome) }
    }

    func testObservationRefusesAForeignMachineDirectoryBeforeSignatureInspection() throws {
        let f = try Fixture(), other = try Fixture(); _ = try f.run()
        XCTAssertThrowsError(try ProtectedMachineUpdateReplacement.observeInLease(activation: f.activation,
            machineDirectory: other.directory, installed: f.installed, prepared: f.machine.destination, store: f.machine.store,
            readPolicy: { f.machine.policy }, inspect: { _, _, _ in
                XCTFail("Foreign directory reached signature inspection"); throw ReplacementFixtureError.injected
            }))
        try f.assertAfter()
    }

    func testObservationVerifierExpiresAndRefusesMachineReentry() throws {
        let f = try Fixture(); _ = try f.run()
        let context = try f.machine.store.machineUpdateReplacementContext(f.activation)
        var escaped: (() throws -> Void)?
        try f.machine.store.withCurrentMachineUpdateReplacement(context, directory: f.directory) { validate in
            escaped = validate; try validate()
            XCTAssertThrowsError(try f.machine.store.machineUpdateReplacement()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            XCTAssertThrowsError(try f.machine.store.close()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
        }
        XCTAssertThrowsError(try XCTUnwrap(escaped)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        try f.assertAfter()
    }

    func testNativeObservationRefusesOrdinaryIdentityBeforeReadingPolicy() throws {
        let f = try Fixture(); _ = try f.run()
        XCTAssertThrowsError(try ProtectedMachineUpdateReplacement.observe(activation: f.activation, machineDirectory: f.directory,
            installed: f.installed, prepared: f.machine.destination, store: f.machine.store,
            readPolicy: { XCTFail("Ordinary observation reached policy"); return f.machine.policy })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        try f.assertAfter()
    }

    func testRestartSourceRequiresAReplacementBindingWithoutCreatingOne() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try restartSource(f)) { XCTAssertEqual($0 as? MachineUpdateReplacementError, .changedBinding) }
        XCTAssertNil(try f.machine.store.machineUpdateReplacement())
    }

    func testRestartSourceKeepsTheHistoricalScopeAfterTheActualExchange() throws {
        let f = try Fixture(), before = try f.machine.store.accountPreparation(ownerUID: getuid())
        _ = try f.run(); let source = try restartSource(f)
        let account = try XCTUnwrap(source.accounts.first { $0.accountID == f.machine.account })
        XCTAssertEqual(account.preparation, before); XCTAssertTrue(try XCTUnwrap(account.initialization).complete)
        XCTAssertEqual(account.initialization?.releaseDigest, source.replacement.inventory.releaseDigest)
        XCTAssertEqual(account.services, f.machine.f.plan.reference.services); XCTAssertTrue(account.servicesComplete)
        XCTAssertEqual(source.description, "MachineUpdateRestartSource(redacted)")
        XCTAssertEqual(source.debugDescription, source.description); try f.assertAfter()
    }

    func testRestartSourceIncludesAnUnpreparedReservationOutsideTheInventory() throws {
        var reserved: AccountPreparationIntent?
        let f = try Fixture(beforeActivation: { reserved = try self.reserveRestartAccount($0) })
        try bindRestartSource(f); let source = try restartSource(f), pending = try XCTUnwrap(reserved)
        XCTAssertFalse(source.replacement.inventory.accounts.contains { $0.accountID == pending.accountID })
        let captured = try XCTUnwrap(source.accounts.first { $0.accountID == pending.accountID })
        XCTAssertEqual(captured.preparation, pending); XCTAssertNil(captured.initialization)
        XCTAssertNil(captured.services); XCTAssertFalse(captured.servicesComplete)
    }

    func testRestartSourceRetainsAnIncompleteInitializationWithoutCompletingIt() throws {
        var reserved: AccountPreparationIntent?
        let f = try Fixture(beforeActivation: { reserved = try self.reserveRestartAccount($0, initialize: true) })
        try bindRestartSource(f); let source = try restartSource(f), pending = try XCTUnwrap(reserved)
        let captured = try XCTUnwrap(source.accounts.first { $0.accountID == pending.accountID })
        XCTAssertEqual(captured.preparation, pending); XCTAssertFalse(try XCTUnwrap(captured.initialization).complete)
        XCTAssertEqual(captured.initialization?.initializationBytes, pending.initializationBytes)
        XCTAssertFalse(try XCTUnwrap(f.machine.store.initialization(accountID: pending.accountID)).complete)
    }

    func testRestartSourcePreservesPreparedAccountsThatHaveNotEnrolledRuntime() throws {
        var reserved: AccountPreparationIntent?
        let f = try Fixture(beforeActivation: { reserved = try self.reserveRestartAccount($0, complete: true) })
        try bindRestartSource(f); let source = try restartSource(f), pending = try XCTUnwrap(reserved)
        let captured = try XCTUnwrap(source.accounts.first { $0.accountID == pending.accountID })
        XCTAssertTrue(try XCTUnwrap(captured.preparation).storagePrepared)
        XCTAssertTrue(try XCTUnwrap(captured.initialization).complete); XCTAssertNil(captured.services)
        XCTAssertFalse(source.replacement.runtime.runtimes.contains { $0.reference.services.accountID == pending.accountID })
    }

    func testRestartSourceCapturesAllReservationsInStableAccountOrder() throws {
        let f = try Fixture(beforeActivation: {
            _ = try self.reserveRestartAccount($0, offset: 1001)
            _ = try self.reserveRestartAccount($0, offset: 1002, initialize: true)
        })
        try bindRestartSource(f); let first = try restartSource(f), second = try restartSource(f)
        XCTAssertEqual(first, second); XCTAssertEqual(first.accounts.count, 3)
        XCTAssertEqual(first.accounts.map(\.accountID), first.accounts.map(\.accountID).sorted { $0.lexicographicallyPrecedes($1) })
    }

    func testDeletingAnUnenrolledReservationInvalidatesTheEntireRestartSource() throws {
        let f = try Fixture(beforeActivation: { _ = try self.reserveRestartAccount($0) })
        try bindRestartSource(f); let source = try restartSource(f)
        try f.machine.sql("DELETE FROM account_preparation_v1 WHERE owner=\(getuid() + 1000)")
        XCTAssertThrowsError(try f.machine.store.withCurrentMachineUpdateRestartSource(source, directory: f.directory) { _ in
            XCTFail("A changed reservation reached the scoped operation")
        }) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
    }

    func testRestartSourceVerifierExpiresAndRejectsMachineReentry() throws {
        let f = try Fixture(); try bindRestartSource(f); let source = try restartSource(f)
        var escaped: (() throws -> Void)?
        try f.machine.store.withCurrentMachineUpdateRestartSource(source, directory: f.directory) { validate in
            escaped = validate; try validate()
            XCTAssertThrowsError(try f.machine.store.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            XCTAssertThrowsError(try f.machine.store.close()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
        }
        XCTAssertThrowsError(try XCTUnwrap(escaped)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }

    func testRestartSourceRejectsAForeignMachineDirectory() throws {
        let f = try Fixture(), other = try Fixture(); try bindRestartSource(f)
        XCTAssertThrowsError(try f.machine.store.machineUpdateRestartSource(f.activation, directory: other.directory))
        let source = try restartSource(f)
        XCTAssertThrowsError(try f.machine.store.withCurrentMachineUpdateRestartSource(source, directory: other.directory) { _ in
            XCTFail("A foreign machine directory reached the scoped operation")
        })
    }

    func testNativeRestartSourceRequiresRootBeforeLoadingMachineRecords() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try MachineUpdateRestartSource.capture(activation: f.activation, machineDirectory: f.directory,
            store: f.machine.store)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertNil(try f.machine.store.machineUpdateReplacement())
    }

    func testActualAtomicExchangePreservesTheOldBundleAndClosesAdmission() throws {
        let f = try Fixture(), inventory = try f.machine.store.inventory(), policy = f.machine.policy
        let result = try f.run(); try f.assertAfter()
        XCTAssertEqual(result.record.phase, .observed); XCTAssertFalse(result.recoveredAfterExchange)
        XCTAssertEqual(try result.release.manifest.canonicalBytes, try f.newRelease.manifest.canonicalBytes)
        XCTAssertEqual(result.release.codeDirectoryHashes, f.newRelease.codeDirectoryHashes)
        XCTAssertEqual(try f.machine.store.machineUpdateActivation(), f.activation)
        XCTAssertEqual(try f.machine.store.inventory(), inventory); XCTAssertEqual(f.machine.policy, policy)
        XCTAssertThrowsError(try UpdateAdmissionBarrier(directory: f.files.directory(), owner: getuid(),
            expected: f.files.machine.store.updateAdmissionRegistration()!.machine).acquireAdmission())
        XCTAssertThrowsError(try f.machine.store.retireUpdateCandidate(f.candidate))
    }

    func testObservedExchangeIsIdempotentAndNeverSwapsBack() throws {
        let f = try Fixture(), first = try f.run(); try f.reopen()
        var exchanges = 0
        let recovered = try f.run(stage: { if $0 == .immediatelyBeforeExchange { exchanges += 1 } })
        XCTAssertTrue(recovered.recoveredAfterExchange); XCTAssertEqual(recovered.record, first.record)
        XCTAssertEqual(exchanges, 0); try f.assertAfter()
    }

    func testFailureAfterExchangeRecoversTheActualLayoutWithoutAnotherSwap() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .immediatelyAfterExchange { throw ReplacementFixtureError.injected } }))
        try f.assertAfter(); XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared)
        try f.reopen(); var exchanges = 0
        let result = try f.run(stage: { if $0 == .immediatelyBeforeExchange { exchanges += 1 } })
        XCTAssertTrue(result.recoveredAfterExchange); XCTAssertEqual(exchanges, 0)
        XCTAssertEqual(result.record.phase, .observed); try f.assertAfter()
    }

    func testRecoveryAfterAnUnsyncedExchangeSyncsBothParentsBeforeTheObservedCommit() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .exchangedBeforeParentSync { throw ReplacementFixtureError.injected } }))
        try f.assertAfter(); XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared)
        try f.reopen(); var stages: [ProtectedMachineUpdateReplacement.Stage] = []
        let result = try f.run(stage: { stages.append($0) })
        XCTAssertEqual(stages, [.parentsSynchronized]); XCTAssertTrue(result.recoveredAfterExchange)
        XCTAssertEqual(result.record.phase, .observed); try f.assertAfter()
    }

    func testAFailedRecoveredParentSyncKeepsThePreparedRecord() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .exchangedBeforeParentSync { throw ReplacementFixtureError.injected } }))
        try f.reopen()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .parentsSynchronized { throw ReplacementFixtureError.injected } }))
        try f.assertAfter(); XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared)
        try f.reopen(); let result = try f.run()
        XCTAssertTrue(result.recoveredAfterExchange); XCTAssertEqual(result.record.phase, .observed); try f.assertAfter()
    }

    func testAFreshExchangeSyncsBothParentsBeforeItsAfterExchangeStage() throws {
        let f = try Fixture(); var stages: [ProtectedMachineUpdateReplacement.Stage] = []
        let result = try f.run(stage: { stages.append($0) })
        XCTAssertEqual(stages, [.bindingCommitted, .immediatelyBeforeExchange, .exchangedBeforeParentSync,
                                .parentsSynchronized, .immediatelyAfterExchange])
        XCTAssertFalse(result.recoveredAfterExchange); XCTAssertEqual(result.record.phase, .observed)
    }

    func testFailureBeforeExchangeRetainsBothOperandsForExplicitRecovery() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .bindingCommitted { throw ReplacementFixtureError.injected } }))
        let retained = try XCTUnwrap(f.machine.store.machineUpdateReplacement()); XCTAssertEqual(retained.phase, .prepared)
        try f.assertBefore(); try f.reopen()
        let result = try f.run(); XCTAssertEqual(result.record.activationAttempt, retained.activationAttempt)
        XCTAssertFalse(result.recoveredAfterExchange); try f.assertAfter()
    }

    func testUnknownBindingCommitNeverEntersTheExchange() throws {
        let f = try Fixture(); try f.machine.reopen(hook: { throw ReplacementFixtureError.injected })
        XCTAssertThrowsError(try f.run()); try f.assertBefore()
        XCTAssertThrowsError(try f.machine.store.machineUpdateReplacement())
        try f.reopen(); XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared)
        _ = try f.run(); try f.assertAfter()
    }

    func testUnknownObservationCommitRecoversWithoutRepeatingTheExchange() throws {
        let f = try Fixture(); var commits = 0
        try f.machine.reopen(hook: { commits += 1; if commits == 2 { throw ReplacementFixtureError.injected } })
        XCTAssertThrowsError(try f.run()); XCTAssertEqual(commits, 2); try f.assertAfter()
        XCTAssertThrowsError(try f.machine.store.machineUpdateReplacement())
        try f.reopen(); let retained = try XCTUnwrap(f.machine.store.machineUpdateReplacement()); XCTAssertEqual(retained.phase, .observed)
        let result = try f.run(stage: { if $0 == .immediatelyBeforeExchange { XCTFail("Recovery repeated a known exchange") } })
        XCTAssertEqual(result.record, retained); XCTAssertTrue(result.recoveredAfterExchange)
    }

    func testReplacementInodeIsNotAdoptedEvenWithIdenticalFixtureBytes() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .bindingCommitted { throw ReplacementFixtureError.injected } }))
        try FileManager.default.moveItem(at: f.preparedURL, to: f.preparedURL.appendingPathExtension("original"))
        try FileManager.default.createDirectory(at: f.preparedURL, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(f.preparedURL.path, 0o755), 0)
        try Data("synthetic inactive copy".utf8).write(to: f.preparedURL.appendingPathComponent("fixture"))
        XCTAssertThrowsError(try f.run()) { XCTAssertEqual($0 as? MachineUpdateReplacementError, .unknownOutcome) }
        XCTAssertEqual(try f.installed.preparationCopyIdentity(name: "Remozio.app"), f.oldIdentity)
        XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared)
    }

    func testAChangedPreparedSignatureIsRefusedImmediatelyBeforeExchange() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .immediatelyBeforeExchange {
            try Data("changed candidate".utf8).write(to: f.preparedURL.appendingPathComponent("fixture"))
        } }))
        try f.assertBefore(); XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared)
    }

    func testChangingProtectedPolicyAfterBindingDoesNotRebindTheAttempt() throws {
        let f = try Fixture(); var changed = false
        let raised = try AuthorityCodePolicy(entries: f.machine.policy.entries.map {
            try .init(role: $0.role, teamID: $0.teamID, identifier: $0.identifier, installedGeneration: 2,
                minimumGeneration: 2, codeDirectoryHash: $0.codeDirectoryHash, active: $0.active)
        })
        XCTAssertThrowsError(try f.run(stage: { if $0 == .bindingCommitted { changed = true } },
            policy: { changed ? raised : f.machine.policy }))
        try f.assertBefore(); XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared)
    }

    func testForeignQuiescenceCannotReachSignatureInspectionOrBindTheSwap() throws {
        let f = try Fixture(), other = try Fixture()
        XCTAssertThrowsError(try ProtectedMachineUpdateReplacement.replaceOrRecoverInLease(activation: f.activation,
            machineDirectory: f.directory, installed: f.installed, prepared: f.machine.destination, store: f.machine.store,
            quiescence: other.quiet, readPolicy: { f.machine.policy }, inspect: { _, _, _ in
                XCTFail("Foreign activity reached signature inspection"); throw ReplacementFixtureError.injected
            }))
        XCTAssertNil(try f.machine.store.machineUpdateReplacement()); try f.assertBefore()
    }

    func testClosedQuiescenceCannotBindOrExchange() throws {
        let f = try Fixture(); f.quiet.close()
        XCTAssertThrowsError(try f.run()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertNil(try f.machine.store.machineUpdateReplacement()); try f.assertBefore()
    }

    func testRestartCheckingCannotStartAReplacement() throws {
        let f = try Fixture(), checking = try f.activation.advancing(to: .restartChecking)
        XCTAssertThrowsError(try ProtectedMachineUpdateReplacement.replaceOrRecoverInLease(activation: checking,
            machineDirectory: f.directory, installed: f.installed, prepared: f.machine.destination, store: f.machine.store,
            quiescence: f.quiet, readPolicy: { f.machine.policy }, inspect: f.inspect)) {
            XCTAssertEqual($0 as? MachineUpdateReplacementError, .wrongPhase)
        }
        XCTAssertNil(try f.machine.store.machineUpdateReplacement()); try f.assertBefore()
    }

    func testRestartCheckingIsRefusedWithoutAReplacementRecord() throws {
        let f = try Fixture(); XCTAssertNil(try f.machine.store.machineUpdateReplacement())
        let restart = try f.quiet.releaseActivityForRestart(); defer { restart.close() }
        XCTAssertThrowsError(try f.machine.store.markMachineUpdateRestartChecking(f.activation, directory: f.directory,
            restart: restart, verifyCurrent: {})) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
        XCTAssertEqual(try f.machine.store.machineUpdateActivation(), f.activation); try f.assertBefore()
    }

    func testRestartCheckingIsRefusedWhileTheReplacementIsOnlyPrepared() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .bindingCommitted { throw ReplacementFixtureError.injected } }))
        XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared)
        try f.reopen(); let restart = try f.quiet.releaseActivityForRestart(); defer { restart.close() }
        XCTAssertThrowsError(try f.machine.store.markMachineUpdateRestartChecking(f.activation, directory: f.directory,
            restart: restart, verifyCurrent: {})) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
        XCTAssertEqual(try f.machine.store.machineUpdateActivation(), f.activation)
        XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared); try f.assertBefore()
    }

    func testRestartCheckingWaitsForTheRecoveredParentSyncAndObservedCommit() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .exchangedBeforeParentSync { throw ReplacementFixtureError.injected } }))
        try f.assertAfter(); XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared)
        try f.reopen()
        do {
            let restart = try f.quiet.releaseActivityForRestart(); defer { restart.close() }
            XCTAssertThrowsError(try f.machine.store.markMachineUpdateRestartChecking(f.activation, directory: f.directory,
                restart: restart, verifyCurrent: {})) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
        }
        XCTAssertEqual(try f.machine.store.machineUpdateActivation(), f.activation)
        try f.reopen(); var stages: [ProtectedMachineUpdateReplacement.Stage] = []
        let result = try f.run(stage: { stages.append($0) })
        XCTAssertEqual(stages, [.parentsSynchronized]); XCTAssertTrue(result.recoveredAfterExchange)
        XCTAssertEqual(result.record.phase, .observed); try f.assertAfter()
        let restart = try f.quiet.releaseActivityForRestart(); defer { restart.close() }
        let checking = try f.machine.store.markMachineUpdateRestartChecking(f.activation, directory: f.directory,
            restart: restart, verifyCurrent: {})
        XCTAssertEqual(checking.phase, .restartChecking)
    }

    func testRestartCheckingAfterTheObservedSwapKeepsTheDigestAndClosedAdmission() throws {
        let f = try Fixture(); XCTAssertEqual(try f.run().record.phase, .observed)
        let restart = try f.quiet.releaseActivityForRestart(); defer { restart.close() }
        let checking = try f.machine.store.markMachineUpdateRestartChecking(f.activation, directory: f.directory,
            restart: restart, verifyCurrent: {})
        XCTAssertEqual(checking.phase, .restartChecking)
        XCTAssertEqual(checking.formatVersion, 2); XCTAssertEqual(checking.policyPreflightDigest, f.activation.policyPreflightDigest)
        let health = try f.files.activity().acquireShared(); health.close()
        let registration = try XCTUnwrap(f.machine.store.updateAdmissionRegistration())
        XCTAssertThrowsError(try UpdateAdmissionBarrier(directory: f.files.directory(), owner: getuid(),
            expected: registration.machine).acquireAdmission())
    }

    func testForeignActivationRevisionCannotBindTheLocalOperands() throws {
        let f = try Fixture(), other = try Fixture()
        XCTAssertThrowsError(try ProtectedMachineUpdateReplacement.replaceOrRecoverInLease(activation: other.activation,
            machineDirectory: f.directory, installed: f.installed, prepared: f.machine.destination, store: f.machine.store,
            quiescence: f.quiet, readPolicy: { f.machine.policy }, inspect: f.inspect))
        XCTAssertNil(try f.machine.store.machineUpdateReplacement()); try f.assertBefore()
    }

    func testAReplacedParentIsNotAdoptedDuringRecovery() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .bindingCommitted { throw ReplacementFixtureError.injected } }))
        let parent = URL(fileURLWithPath: f.installed.path)
        try FileManager.default.moveItem(at: parent, to: parent.appendingPathExtension("original"))
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        XCTAssertThrowsError(try f.run())
        XCTAssertEqual(try f.machine.store.machineUpdateReplacement()?.phase, .prepared)
    }

    func testScopedMachineVerifierExpiresAndRejectsWriterReentry() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .bindingCommitted { throw ReplacementFixtureError.injected } }))
        let binding = try XCTUnwrap(f.machine.store.machineUpdateReplacement()), runtime = try f.machine.store.retainedRuntimeCompatibilityInputs()
        var saved: (() throws -> Void)?
        try f.quiet.withExclusiveActivity { _ in
            try f.machine.store.withBoundMachineUpdateReplacement(binding, activation: f.activation, runtime: runtime,
                directory: f.directory, quiescence: f.quiet) { validate in
                    saved = validate; try validate()
                    XCTAssertThrowsError(try f.machine.store.machineUpdateReplacement()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
                    XCTAssertThrowsError(try f.machine.store.close()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
                }
        }
        XCTAssertThrowsError(try XCTUnwrap(saved)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        try f.assertBefore()
    }

    func testCloseDuringExchangeRetainsTheActualKernelGateUntilTheCallbackSettles() throws {
        let f = try Fixture(); var checked = false
        let identity = try f.machine.store.updateAdmissionRegistration()!.machine
        _ = try f.run(stage: { if $0 == .immediatelyAfterExchange {
            f.quiet.close()
            XCTAssertThrowsError(try UpdateAdmissionBarrier(directory: f.files.directory(), owner: getuid(),
                expected: identity).acquireAdmission())
            checked = true
        } })
        XCTAssertTrue(checked); XCTAssertThrowsError(try f.quiet.validate()); try f.assertAfter()
        XCTAssertEqual(try f.machine.store.machineUpdateActivation(), f.activation)
    }

    func testStorageUpgradeIsExplicitAndCannotRunDuringAnActivePhase() throws {
        let files = try BoundAdmissionRegistrationFixture(machine: UpdateCandidateStorageFixture(admission: true, activation: true, replacement: true)); _ = try files.prepare()
        try MachineUpdateActivationStorage.enableInLease(installedRelease: files.machine.release,
            policy: files.machine.policy, store: files.machine.store)
        XCTAssertNil(try files.machine.store.machineUpdateReplacement())
        XCTAssertEqual(try files.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 17)
        let candidate = try files.machine.select(files.machine.copy()), directory = try files.directory()
        let drain = try UpdateActivationAdmission(anchor: files.root.path, relativeDirectory: "machine", owner: getuid(),
            expected: files.machine.store.updateAdmissionRegistration()!.machine).beginDrain()
        defer { directory.close(); drain.close() }
        _ = try files.machine.store.beginMachineUpdateActivation(candidate: candidate,
            registration: files.machine.store.updateAdmissionRegistration()!, runtime: files.machine.store.retainedRuntimeCompatibilityInputs(),
            replacing: nil, directory: directory, drain: drain, verifyCurrent: {})
        XCTAssertThrowsError(try MachineUpdateReplacementStorage.enableInLease(installedRelease: files.machine.release,
            policy: files.machine.policy, store: files.machine.store))
        XCTAssertEqual(try files.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 17)
    }

    func testTheCodecIsCanonicalBoundedAndRedactsItsOperands() throws {
        let f = try Fixture(), result = try f.run(), bytes = try result.record.encoded
        XCTAssertEqual(try MachineUpdateReplacementRecord.decode(bytes), result.record)
        XCTAssertEqual(result.record.description, "MachineUpdateReplacementRecord(redacted)")
        XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(bytes + Data([0x20])))
        XCTAssertThrowsError(try MachineUpdateReplacementRecord.decode(Data(repeating: 0, count: MachineUpdateReplacementRecord.maximumBytes + 1)))
    }

    func testNativeEntryRefusesOrdinaryIdentityBeforeInspectionOrFilesystemChanges() throws {
        let f = try Fixture(); XCTAssertNotEqual(getuid(), 0)
        XCTAssertThrowsError(try ProtectedMachineUpdateReplacement.replaceOrRecover(activation: f.activation,
            machineDirectory: f.directory, installed: f.installed, prepared: f.machine.destination, store: f.machine.store,
            quiescence: f.quiet, readPolicy: { XCTFail("Ordinary entry reached policy"); return f.machine.policy })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertNil(try f.machine.store.machineUpdateReplacement()); try f.assertBefore()
    }

    /// Swift marks fork() unavailable, so the symbol is loaded directly. The child only runs one scoped verifier and exits.
    private static let forkProcess: @convention(c) () -> pid_t = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork") else { preconditionFailure("fork is not available") }
        return unsafeBitCast(symbol, to: (@convention(c) () -> pid_t).self)
    }()
    private func assertForkRefuses(_ validate: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) throws {
        let child = Self.forkProcess()
        guard child >= 0 else { throw JournalLeaseError.system(errno) }
        if child == 0 {
            do { try validate(); _exit(1) }
            catch JournalLeaseError.invalidated { _exit(0) }
            catch { _exit(2) }
        }
        let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
        var status: Int32 = 0
        while DispatchTime.now().uptimeNanoseconds < deadline {
            let result = waitpid(child, &status, WNOHANG)
            if result == child { XCTAssertEqual(status, 0, file: file, line: line); return }
            if result < 0, errno != EINTR { throw JournalLeaseError.system(errno) }
            usleep(10_000)
        }
        _ = kill(child, SIGKILL)
        while waitpid(child, &status, 0) < 0 && errno == EINTR {}
        XCTFail("The forked verifier did not refuse promptly", file: file, line: line)
    }
    func testEveryScopedVerifierRejectsAForkBeforeReadingTheMachineConnection() throws {
        let f = try Fixture(); try bindRestartSource(f)
        let context = try f.machine.store.machineUpdateReplacementContext(f.activation)
        try f.machine.store.withCurrentMachineUpdateReplacement(context, directory: f.directory) { validate in
            try assertForkRefuses(validate)
        }
        let binding = try XCTUnwrap(context.replacement)
        try f.quiet.withExclusiveActivity { _ in
            try f.machine.store.withBoundMachineUpdateReplacement(binding, activation: f.activation,
                runtime: context.runtime, directory: f.directory, quiescence: f.quiet) { validate in
                try assertForkRefuses(validate)
            }
        }
        let source = try restartSource(f)
        try f.machine.store.withCurrentMachineUpdateRestartSource(source, directory: f.directory) { validate in
            try assertForkRefuses(validate)
        }
        try f.assertBefore()
    }

    private func releasePolicySnapshot(_ f: Fixture) -> AuthorityCodePolicySnapshot {
        f.policySnapshot
    }

    private func releaseBinding(_ f: Fixture, source: MachineUpdateRestartSource,
                                policy: AuthorityCodePolicySnapshot) throws -> RuntimeReleaseBinding {
        try .init(accountID: f.machine.account, source: source, candidate: f.newRelease,
            policy: MachineUpdatePolicyPlan(source: policy, candidate: f.newRelease))
    }

    func testConfigurationEpochMigrationIsExplicitAndIdempotent() throws {
        let files = try BoundAdmissionRegistrationFixture(machine: UpdateCandidateStorageFixture(
            admission: true, activation: true, replacement: true))
        let machine = files.machine, release = machine.release
        try MachineUpdateActivationStorage.enableInLease(installedRelease: release, policy: machine.policy, store: machine.store)
        try MachineUpdateReplacementStorage.enableInLease(installedRelease: release, policy: machine.policy, store: machine.store)
        XCTAssertNil(try machine.store.machineUpdateConfigurationEpoch())
        XCTAssertEqual(try machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 18)
        XCTAssertThrowsError(try MachineUpdateConfigurationEpochStorage.enableInLease(installedRelease: release,
            policy: machine.policy, store: machine.store))
        let digest = try InstallationInventory.digest(release)
        XCTAssertThrowsError(try machine.store.upgradeMachineUpdateConfigurationEpochStorage(
            expectedInstalledReleaseDigest: Data(repeating: 0, count: 32)))
        XCTAssertEqual(try machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 18)
        try machine.store.upgradeMachineUpdateConfigurationEpochStorage(expectedInstalledReleaseDigest: digest)
        try machine.reopen()
        try machine.store.upgradeMachineUpdateConfigurationEpochStorage(expectedInstalledReleaseDigest: digest)
        XCTAssertEqual(try machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 19)
        XCTAssertNil(try machine.store.machineUpdateConfigurationEpoch())
    }

    func testConfigurationEpochRejectsOrdinaryMigrationDuringAnActiveReplacement() throws {
        let f = try Fixture(configurationEpoch: true)
        XCTAssertThrowsError(try f.machine.store.upgradeMachineUpdateConfigurationEpochStorage(
            expectedInstalledReleaseDigest: InstallationInventory.digest(f.oldRelease))) {
            XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
        }
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 18)
        XCTAssertNil(try f.machine.store.machineUpdateConfigurationEpoch())
    }

    private func retainFixtureConfigurationEpoch(_ f: Fixture) throws -> MachineUpdateConfigurationEpochRecord {
        _ = try f.run()
        let previous = try restartSource(f)
        let source = try f.machine.store.upgradeConfigurationEpochForInstalledRecovery(expected: previous,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        let accountID = f.machine.account
        let account = try XCTUnwrap(source.accounts.first { $0.accountID == accountID })
        let foreground = f.machine.f.plan
        let bundle = try RuntimeConfigurationBundle.initial(account: XCTUnwrap(account.preparation),
            initialization: XCTUnwrap(account.initialization), reference: foreground.reference, inventory: source.replacement.inventory)
        let original = RuntimeReleaseConfigurationSource(host: foreground.host, transport: foreground.transport,
            gateway: try XCTUnwrap(foreground.gatewaySettingsHost),
            clients: .init(presence: bundle.presenceClient, pairing: bundle.pairingClient, frontend: bundle.frontendClient))
        let policy = releasePolicySnapshot(f)
        func plan(_ stage: RuntimeReleasePolicyStage) throws -> RuntimeReleaseConfigurationPlan {
            try .init(accountID: accountID, source: source, currentPolicy: policy, candidate: f.newRelease,
                host: original.host, transport: original.transport, gateway: original.gateway, clients: original.clients, stage: stage)
        }
        let startup = try plan(.startup), proposedCompletion = try plan(.completion)
        let completion = f.installedReadiness
            ? try proposedCompletion.selectingInstalledRootReadiness(candidate: f.newRelease) : proposedCompletion
        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(startup.gateway.encoded))
        XCTAssertThrowsError(try TransportPairingStartupConfiguration.decode(startup.transport.canonicalBytes))
        XCTAssertEqual(try RuntimeReleaseConfigurationPlan.decode(startup.encoded).encoded, try startup.encoded)
        let record = try f.machine.store.retainMachineUpdateConfigurationEpoch(expected: source, candidate: f.newRelease,
            policies: source.accounts.map { .init(accountID: $0.accountID, snapshot: $0.accountID == accountID ? policy : nil) },
            configurations: [.init(source: original, startup: startup, completion: completion)],
            directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        let archive = try XCTUnwrap(f.machine.store.machineUpdateConfigurationEpoch())
        XCTAssertEqual(archive.record, record)
        XCTAssertEqual(try archive.configuration(accountID: accountID)?.startup.encoded, try startup.encoded)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().machineUpdateConfigurationEpoch, try record.encoded)
        return record
    }

    private func advanceFixtureConfigurationEpoch(_ f: Fixture, _ record: MachineUpdateConfigurationEpochRecord,
        _ operation: MachineUpdatePublicationOperation) throws -> MachineUpdateConfigurationEpochRecord {
        try f.machine.store.advanceMachineUpdatePublication(record, operation: operation, candidate: f.newRelease,
            directory: f.directory, quiescence: f.quiet, verifyCurrent: { _ in })
    }

    func testConfigurationEpochRetainsTheTypedArchiveAndAdvancesPublication() throws {
        let f = try Fixture(configurationEpoch: true)
        let record = try retainFixtureConfigurationEpoch(f)
        let accountID = f.machine.account
        let writing = try f.machine.store.advanceMachineUpdatePublication(record, operation: .begin, candidate: f.newRelease,
            directory: f.directory, quiescence: f.quiet, verifyCurrent: { _ in })
        XCTAssertNotEqual(writing.revision, record.revision)
        XCTAssertEqual(try writing.publication?.state(accountID: accountID, file: .host), .pending)
        XCTAssertThrowsError(try f.machine.store.advanceMachineUpdatePublication(record, operation: .begin, candidate: f.newRelease,
            directory: f.directory, quiescence: f.quiet, verifyCurrent: { _ in })) {
            XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
        }
        XCTAssertEqual(try f.machine.store.machineUpdateConfigurationEpoch()?.record, writing)
    }

    func testConfigurationWriterRequiresWritingAndRetainsEveryPublishedFileOnReplay() throws {
        let f = try Fixture(configurationEpoch: true)
        var record = try advanceFixtureConfigurationEpoch(f, retainFixtureConfigurationEpoch(f), .begin)
        XCTAssertEqual(chmod(f.files.root.path, 0o755), 0)
        let directory = try ProtectedSetupDirectory(anchor: f.files.root.path, relativePath: "EpochConfiguration",
            owner: getuid(), visibility: .sharedMetadata)
        defer { directory.close() }
        let accountID = f.machine.account
        let owner = try XCTUnwrap(record.accounts.first { $0.accountID == accountID }).ownerUID
        let initial = try XCTUnwrap(f.machine.store.machineUpdateConfigurationEpoch())
        let configuration = try XCTUnwrap(initial.configuration(accountID: accountID))
        let files: [(MachineUpdatePublicationProgress.File, AdministrativeSetupPublication.File)] = [
            (.host, .commandHost), (.transport, .transportConfiguration), (.gateway, .gatewaySettingsHost),
            (.presence, .presenceClient(ownerUID: owner)), (.pairing, .pairingClient(ownerUID: owner)),
            (.frontend, .frontendClient(ownerUID: owner)),
        ]
        for (file, name) in files {
            let url = URL(fileURLWithPath: directory.path).appendingPathComponent(name.name)
            let original = try configuration.bytes(file, target: false)
            let target = try configuration.bytes(file, target: true)
            // The fixture changes only the release-bound files; the client files keep their bytes.
            if [.host, .transport, .gateway].contains(file) { XCTAssertNotEqual(original, target, "\(file)") } else { XCTAssertEqual(original, target, "\(file)") }
            _ = try AdministrativeSetupPublication.publish(original, file: name, directory: directory, owner: getuid())
            let pending = try XCTUnwrap(f.machine.store.machineUpdateConfigurationEpoch())
            XCTAssertThrowsError(try MachineUpdateConfigurationFiles.publishInLease(pending, accountID: accountID,
                file: file, directory: directory, owner: getuid(), verify: { XCTFail("Pending write reached the verifier") })) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertEqual(try Data(contentsOf: url), original)
            record = try advanceFixtureConfigurationEpoch(f, record, .prepare(accountID, file))
            let writing = try XCTUnwrap(f.machine.store.machineUpdateConfigurationEpoch())
            XCTAssertEqual(try writing.record.publication?.state(accountID: accountID, file: file), .writing)
            try MachineUpdateConfigurationFiles.publishInLease(writing, accountID: accountID, file: file,
                directory: directory, owner: getuid(), verify: {})
            XCTAssertEqual(try Data(contentsOf: url), target)
            XCTAssertThrowsError(try MachineUpdateConfigurationFiles.requirePublishedInLease(writing, accountID: accountID,
                file: file, directory: directory, owner: getuid(), verify: {})) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            var first = stat(), replay = stat()
            XCTAssertEqual(lstat(url.path, &first), 0)
            try MachineUpdateConfigurationFiles.publishInLease(writing, accountID: accountID, file: file,
                directory: directory, owner: getuid(), verify: {}, didStage: { _ in
                    XCTFail("Replay staged another file")
                })
            XCTAssertEqual(lstat(url.path, &replay), 0)
            XCTAssertEqual(replay.st_ino, first.st_ino)
            record = try advanceFixtureConfigurationEpoch(f, record, .complete(accountID, file))
            XCTAssertEqual(try f.machine.store.machineUpdateConfigurationEpoch()?.record.publication?.state(accountID: accountID, file: file), .published)
        }
        XCTAssertEqual(record.publication?.complete, true)
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: directory.path)), Set(files.map { $0.1.name }))
        let published = try XCTUnwrap(f.machine.store.machineUpdateConfigurationEpoch())
        for (file, _) in files {
            try MachineUpdateConfigurationFiles.requirePublishedInLease(published, accountID: accountID,
                file: file, directory: directory, owner: getuid(), verify: {})
        }
        let gateway = URL(fileURLWithPath: directory.path).appendingPathComponent(AdministrativeSetupPublication.File.gatewaySettingsHost.name)
        let oldGateway = try configuration.bytes(.gateway, target: false)
        try oldGateway.write(to: gateway)
        XCTAssertThrowsError(try MachineUpdateConfigurationFiles.requirePublishedInLease(published, accountID: accountID,
            file: .gateway, directory: directory, owner: getuid(), verify: {}))
        XCTAssertEqual(try Data(contentsOf: gateway), oldGateway)
    }

    func testConfigurationEpochRejectsATamperedSQLiteOperand() throws {
        let f = try Fixture(configurationEpoch: true)
        let record = try retainFixtureConfigurationEpoch(f)
        XCTAssertEqual(try f.machine.store.machineUpdateConfigurationEpoch()?.record, record)
        try f.machine.sql("UPDATE machine_update_configuration_epoch_v1 SET record=x'00' WHERE kind=1")
        XCTAssertThrowsError(try f.machine.store.machineUpdateConfigurationEpoch()) {
            XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
        }
    }

    func testConfigurationEpochRejectsAnIndependentMachineRowChange() throws {
        let f = try Fixture(configurationEpoch: true, beforeActivation: { files in
            _ = try files.machine.copy()
        })
        let record = try retainFixtureConfigurationEpoch(f)
        let source = try restartSource(f)
        let candidate = f.candidate.preparation.id.uuidString.replacingOccurrences(of: "-", with: "")
        XCTAssertEqual(try f.machine.store.records().count, 2)
        try f.machine.sql("DELETE FROM preparation_intents_v1 WHERE id!=x'\(candidate)'")
        XCTAssertEqual(try f.machine.store.records().count, 1)
        XCTAssertEqual(try restartSource(f), source)
        XCTAssertEqual(try f.machine.store.machineUpdateConfigurationEpoch()?.record, record)
        XCTAssertThrowsError(try f.machine.store.withCurrentMachineUpdateConfigurationEpoch(record,
            directory: f.directory, quiescence: f.quiet) { _ in XCTFail("Changed machine rows reached the verifier") }) {
            XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
        }
    }

    private func publishFixtureConfigurationEpoch(_ f: Fixture, _ record: MachineUpdateConfigurationEpochRecord)
        throws -> MachineUpdateConfigurationEpochRecord {
        func advance(_ previous: MachineUpdateConfigurationEpochRecord, _ operation: MachineUpdatePublicationOperation)
            throws -> MachineUpdateConfigurationEpochRecord {
            try f.machine.store.advanceMachineUpdatePublication(previous, operation: operation, candidate: f.newRelease,
                directory: f.directory, quiescence: f.quiet, verifyCurrent: { _ in })
        }
        var current = try advance(record, .begin)
        for file in MachineUpdatePublicationProgress.File.allCases {
            current = try advance(current, .prepare(f.machine.account, file))
            current = try advance(current, .complete(f.machine.account, file))
        }
        return current
    }

    func testBackendEpochRequiresCompletedConfigurationAndRetainsEmptyCaptures() throws {
        let f = try Fixture(backendEpoch: true)
        let configuration = try retainFixtureConfigurationEpoch(f)
        XCTAssertNil(try f.machine.store.machineUpdateBackendEpoch())
        XCTAssertThrowsError(try f.machine.store.upgradeMachineUpdateBackendEpochStorage(expected: configuration,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})) {
            XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
        }
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 19)
        let published = try publishFixtureConfigurationEpoch(f, configuration)
        let initial = try f.machine.store.upgradeMachineUpdateBackendEpochStorage(expected: published,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        XCTAssertNil(initial.accounts)
        XCTAssertEqual(try f.machine.store.upgradeMachineUpdateBackendEpochStorage(expected: published,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {}), initial)
        let retained = try f.machine.store.retainMachineUpdateBackendEpoch(initial,
            captures: [.init(accountID: f.machine.account, source: nil, startup: nil, completion: nil)],
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        XCTAssertEqual(try f.machine.store.machineUpdateBackendEpoch()?.record, retained)
        XCTAssertNil(try f.machine.store.machineUpdateBackendEpoch()?.capture(accountID: f.machine.account))
        let final = try f.machine.store.advanceMachineUpdateBackendPublication(retained, operation: .begin,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: { _ in })
        XCTAssertEqual(final.publication?.complete, true)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().machineUpdateBackendEpoch, try final.encoded)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 20)
    }

    func testBackendEpochRefusesMigrationWithoutSignedBackendFormats() throws {
        let f = try Fixture(configurationEpoch: true)
        let configuration = try retainFixtureConfigurationEpoch(f)
        let published = try publishFixtureConfigurationEpoch(f, configuration)
        XCTAssertThrowsError(try f.machine.store.upgradeMachineUpdateBackendEpochStorage(expected: published,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 19)
        XCTAssertNil(try f.machine.store.machineUpdateBackendEpoch())
    }

    private func populatedBackendFixture() throws -> (Fixture, GatewayJournalSetupExchangeTests.Fixture) {
        var gatewayFixture: GatewayJournalSetupExchangeTests.Fixture?
        let f = try Fixture(backendEpoch: true, beforeActivation: { files in
            let setup = try GatewayJournalSetupExchangeTests.Fixture(runtime: files.machine.f)
            try setup.retainCompletion(.decode(setup.initialize()))
            let store = files.machine.store
            let activation = try GatewayRuntimeActivationPlan(journal: setup.state(),
                foreground: setup.runtime.plan, inventory: XCTUnwrap(store.inventory()))
            try store.retainGatewayRuntimeActivation(activation)
            try store.markGatewayRuntimePublished(activation)
            _ = try store.enrollGatewayRuntimeActivation(activation)
            try store.markGatewayRuntimeRegistered(activation)
            gatewayFixture = setup
        })
        return (f, try XCTUnwrap(gatewayFixture))
    }

    private func fixtureBackendCapture(_ f: Fixture, foreground: RuntimeActivationPlan,
        activation: GatewayRuntimeActivationPlan, journal: GatewayJournalPreparationState) throws -> MachineUpdateBackendEpoch.Capture {
        let store = f.machine.store, account = f.machine.account
        let archive = try XCTUnwrap(store.machineUpdateConfigurationEpoch())
        let configured = try XCTUnwrap(archive.configuration(accountID: account))
        let machine = try restartSource(f), inventory = machine.replacement.inventory
        let source = try RuntimeReleaseBackendSource(foreground: foreground, activation: activation,
            journal: journal, settings: store.gatewaySettingsTransition(accountID: account), inventory: inventory)
        func plan(_ value: RuntimeReleaseConfigurationPlan) throws -> RuntimeReleaseBackendPlan {
            try .init(configuration: value, source: source, sourceConfiguration: configured.source,
                machine: machine, currentPolicy: releasePolicySnapshot(f), candidate: f.newRelease)
        }
        return try MachineUpdateBackendEpoch.Capture(accountID: account, source: source,
            startup: plan(configured.startup), completion: plan(configured.completion))
    }

    func testGatewayHealthReadsOnlyTheMatchingReleaseBoundPublication() throws {
        let (f, setup) = try populatedBackendFixture()
        _ = try publishFixtureConfigurationEpoch(f, retainFixtureConfigurationEpoch(f))
        let activation = try XCTUnwrap(f.machine.store.gatewayRuntimeActivation(accountID: f.machine.account).plan)
        let capture = try fixtureBackendCapture(f, foreground: setup.runtime.plan, activation: activation, journal: setup.state())
        let startup = try XCTUnwrap(capture.startup), completion = try XCTUnwrap(capture.completion)
        typealias File = AdministrativeSetupPublication.File
        let marker = try capture.bytes(.commit, target: true)
        let role = try capture.bytes(.transport, target: true)
        let gateway = try capture.bytes(.gateway, target: true)
        let files = [File.gatewayRuntimeCommit.name: marker,
            File.transportConfiguration.name: startup.configuration.transport.canonicalBytes,
            File.transportGatewayRuntime.name: role, File.gatewayConfiguration.name: gateway]
        let host = startup.configuration.gateway
        func load(_ overrides: [String: Data] = [:], changed: File? = nil,
                  fence: GatewayRuntimeSettingsFence? = nil, verify: () throws -> Void = {}) throws -> GatewayRuntimeCommit {
            let contents = files.merging(overrides) { _, override in override }
            var reads = [String: Int]()
            return try GatewayRuntimeLoader.loadForUpdateHealth(host: host, readFence: { fence }, read: { file in
                let count = reads[file.name, default: 0] + 1
                reads[file.name] = count
                if file.name == changed?.name, count == 2 { return Data() }
                guard let bytes = contents[file.name] else { throw JournalLeaseError.system(ENOENT) }
                return bytes
            }, verifyCurrent: verify).commit
        }
        func rejects(_ overrides: [String: Data] = [:], changed: File? = nil,
                     fence: GatewayRuntimeSettingsFence? = nil, line: UInt = #line) {
            XCTAssertThrowsError(try load(overrides, changed: changed, fence: fence), line: line) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope, line: line)
            }
        }
        XCTAssertEqual(try load().encoded, marker)
        XCTAssertThrowsError(try GatewayRuntimeLoader.load(target: .transport, read: { file in
            try XCTUnwrap(files[file.name])
        }, verifyCurrent: {}, validate: { _ in }))
        XCTAssertThrowsError(try GatewayRuntimeLoader.loadForUpdateHealth(host: completion.configuration.gateway,
            readFence: { nil }, read: { _ in XCTFail("Completion host read the publication"); return Data() }, verifyCurrent: {}))

        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 1, maxItems: 64)
        guard case .map(var markerFields) = try DeterministicCBOR.decode(marker, limits: limits),
              case .bytes(let oldMarker) = markerFields[14],
              case .map(var oldFields) = try DeterministicCBOR.decode(oldMarker, limits: limits) else {
            return XCTFail("Fixture lacks the release commit")
        }
        var foreignFields = try XCTUnwrap(JSONSerialization.jsonObject(with: startup.binding.encoded) as? [String: Any])
        foreignFields["installedReleaseDigest"] = Data(repeating: 231, count: 32).base64EncodedString()
        let foreignBinding = try RuntimeReleaseBinding.decode(JSONSerialization.data(withJSONObject: foreignFields,
            options: [.sortedKeys, .withoutEscapingSlashes]))
        var foreignCommit = markerFields
        foreignCommit[12] = try .bytes(foreignBinding.encoded)
        rejects([File.gatewayRuntimeCommit.name: try DeterministicCBOR.encode(.map(foreignCommit), limits: limits)])
        let transport = startup.configuration.transport
        let foreignHost = try GatewaySettingsConsumerHostConfiguration(role: .transport, runtime: host.runtime,
            bundlePath: host.bundlePath, codePolicy: host.codePolicy, releaseBinding: foreignBinding, policyStage: .startup)
        let foreignTransport = try TransportPairingStartupConfiguration(transport: transport.transport,
            control: transport.control, wake: transport.wake, relayPort: transport.relayPort, settingsHost: foreignHost)
        rejects([File.transportConfiguration.name: foreignTransport.canonicalBytes])
        let pair = try GatewayRuntimeExtensions(release: startup)
        rejects([File.transportGatewayRuntime.name: try pair.authority.encoded])

        let inventory = try XCTUnwrap(f.machine.store.inventory())
        let endpoint = try XCTUnwrap(startup.gateway.wakeEndpoint)
        let selection = try GatewayRuntimeSettingsSelection(service: startup.gateway.settings,
            activation: .init(wakePollMilliseconds: startup.transportWake.pollMilliseconds,
                              wakeTimeoutMilliseconds: startup.transportWake.wake.timeoutMilliseconds),
            maximumWakeConnections: endpoint.maximumConnections, maximumWakeOperations: endpoint.maximumOperations,
            wakeChallengeLifetimeMilliseconds: endpoint.challengeLifetimeMillis)
        func revision(_ id: UInt8) throws -> GatewayRuntimeSettingsRevision {
            try .init(id: Data(repeating: id, count: 16), selection: selection, activation: activation,
                journal: setup.state(), foreground: setup.runtime.plan, inventory: inventory)
        }
        let retained = try revision(1), foreignRevision = try revision(2)
        oldFields[0] = .unsigned(2)
        oldFields[8] = .unsigned(retained.sequence)
        oldFields[9] = try .bytes(retained.digest)
        oldFields[10] = .bytes(retained.gatewayDigest)
        oldFields[11] = .bytes(retained.activationDigest)
        for index in [UInt64(8), 9, 11] { markerFields[index] = oldFields[index] }
        markerFields[14] = try .bytes(DeterministicCBOR.encode(.map(oldFields), limits: limits))
        let revisionMarker = try DeterministicCBOR.encode(.map(markerFields), limits: limits)
        let withRevision = [File.gatewayRuntimeCommit.name: revisionMarker, File.gatewaySettingsRevision.name: try retained.encoded]
        XCTAssertEqual(try load(withRevision).settingsSequence, retained.sequence)
        rejects([File.gatewayRuntimeCommit.name: revisionMarker])
        rejects([File.gatewayRuntimeCommit.name: revisionMarker, File.gatewaySettingsRevision.name: try foreignRevision.encoded])
        rejects([File.gatewaySettingsRevision.name: try retained.encoded])
        let fence = try GatewayRuntimeSettingsFence(.init(revision: retained, previous: nil, activation: activation,
            journal: setup.state(), foreground: setup.runtime.plan, inventory: inventory))
        rejects(withRevision, fence: fence)
        var verifications = 0
        XCTAssertThrowsError(try load(withRevision, verify: {
            verifications += 1
            if verifications == 2 { throw ReplacementFixtureError.injected }
        })) { XCTAssertTrue($0 is ReplacementFixtureError) }
        XCTAssertEqual(verifications, 2)
        for file in [File.gatewayRuntimeCommit, .transportConfiguration, .transportGatewayRuntime, .gatewayConfiguration, .gatewaySettingsRevision] {
            rejects(withRevision, changed: file)
        }
    }

    func testPopulatedBackendPublicationReplacesOwnedFilesAndHonorsTheSettingsFence() throws {
        let (f, setup) = try populatedBackendFixture()
        let published = try publishFixtureConfigurationEpoch(f, retainFixtureConfigurationEpoch(f))
        let store = f.machine.store, account = f.machine.account
        let configuration = try XCTUnwrap(store.machineUpdateConfigurationEpoch())
        let machine = try restartSource(f), inventory = machine.replacement.inventory
        let activation = try XCTUnwrap(store.gatewayRuntimeActivation(accountID: account).plan)
        let journal = try setup.state()
        let capture = try fixtureBackendCapture(f, foreground: setup.runtime.plan, activation: activation, journal: journal)
        let source = try XCTUnwrap(capture.source)
        let initial = try store.upgradeMachineUpdateBackendEpochStorage(expected: published,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        let retained = try store.retainMachineUpdateBackendEpoch(initial, captures: [capture], candidate: f.newRelease,
            directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        XCTAssertEqual(retained.operands.count, 3)

        // Shared metadata needs a public anchor; the fixture root is private (0700).
        XCTAssertEqual(chmod(f.files.root.path, 0o755), 0)
        let directory = try ProtectedSetupDirectory(anchor: f.files.root.path, relativePath: "BackendPublication",
            owner: getuid(), visibility: .sharedMetadata)
        defer { directory.close() }
        for file in MachineUpdateBackendPublicationProgress.File.allCases {
            _ = try AdministrativeSetupPublication.publish(capture.bytes(file, target: false),
                file: file.artifact, directory: directory, owner: getuid())
        }
        let revision = try GatewayRuntimeSettingsRevision(id: Data(repeating: 1, count: 16),
            selection: .init(service: source.gateway.settings,
                activation: .init(wakePollMilliseconds: 2000, wakeTimeoutMilliseconds: 6000)),
            activation: activation, previous: nil, journal: journal, foreground: setup.runtime.plan, inventory: inventory)
        let fence = try GatewayRuntimeSettingsFence(.init(revision: revision, previous: nil,
            activation: activation, journal: journal, foreground: setup.runtime.plan, inventory: inventory))
        let fenceFile = AdministrativeSetupPublication.File.gatewaySettingsFence
        let fenceURL = URL(fileURLWithPath: directory.path).appendingPathComponent(fenceFile.name)
        func readFence() throws -> GatewayRuntimeSettingsFence? {
            try GatewayRuntimeSettingsFenceReader.load(macID: machine.replacement.inventory.macID, accountID: account, read: {
                try ProtectedServiceConfiguration.readOptional(anchor: directory.path, relativePath: fenceFile.name, owner: getuid())
            }, verifyCurrent: {})
        }
        func verify(_ archive: MachineUpdateBackendEpoch.Archive) throws {
            try MachineUpdateBackendPublicationFiles.requireInLease(archive, configuration: configuration,
                accountID: account, directory: directory, owner: getuid(), readFence: readFence, verifyCurrent: {})
        }
        func advance(_ previous: MachineUpdateBackendEpochRecord, _ operation: MachineUpdateBackendPublicationOperation)
            throws -> MachineUpdateBackendEpochRecord {
            try store.advanceMachineUpdateBackendPublication(previous, operation: operation, candidate: f.newRelease,
                directory: f.directory, quiescence: f.quiet, verifyCurrent: { _ in })
        }
        var record = try advance(retained, .begin)
        XCTAssertThrowsError(try advance(record, .prepare(account, .commit)))
        for file in MachineUpdateBackendPublicationProgress.File.allCases {
            let url = URL(fileURLWithPath: directory.path).appendingPathComponent(file.artifact.name)
            let original = try capture.bytes(file, target: false), target = try capture.bytes(file, target: true)
            let pending = try XCTUnwrap(store.machineUpdateBackendEpoch())
            XCTAssertThrowsError(try MachineUpdateBackendPublicationFiles.publishInLease(pending, configuration: configuration,
                accountID: account, file: file, directory: directory, owner: getuid(), verify: {})) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            record = try advance(record, .prepare(account, file))
            let writing = try XCTUnwrap(store.machineUpdateBackendEpoch())
            if file == .authority {
                _ = try AdministrativeSetupPublication.publish(fence.encoded, file: fenceFile, directory: directory, owner: getuid())
                XCTAssertNotNil(try readFence())
                XCTAssertThrowsError(try MachineUpdateBackendPublicationFiles.publishInLease(writing, configuration: configuration,
                    accountID: account, file: file, directory: directory, owner: getuid(), verify: { try verify(writing) },
                    didStage: { _ in XCTFail("A retained fence reached staging") })) {
                    XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
                }
                XCTAssertEqual(try Data(contentsOf: url), original)
                try FileManager.default.removeItem(at: fenceURL)
            }
            try MachineUpdateBackendPublicationFiles.publishInLease(writing, configuration: configuration,
                accountID: account, file: file, directory: directory, owner: getuid(), verify: { try verify(writing) })
            XCTAssertEqual(try Data(contentsOf: url), target)
            var before = stat(), after = stat()
            XCTAssertEqual(lstat(url.path, &before), 0)
            try MachineUpdateBackendPublicationFiles.publishInLease(writing, configuration: configuration,
                accountID: account, file: file, directory: directory, owner: getuid(), verify: { try verify(writing) },
                didStage: { _ in XCTFail("Replay staged another file") })
            XCTAssertEqual(lstat(url.path, &after), 0)
            XCTAssertEqual(before.st_ino, after.st_ino)
            record = try advance(record, .complete(account, file))
            try verify(XCTUnwrap(store.machineUpdateBackendEpoch()))
        }
        XCTAssertEqual(record.publication?.complete, true)
        let restart = try f.quiet.releaseActivityForRestart(); defer { restart.close() }
        let checking = try store.markMachineUpdateRestartChecking(f.activation, directory: f.directory,
            restart: restart, verifyCurrent: {})
        let current = try store.machineUpdateRestartSource(checking, directory: f.directory)
        let snapshot = try store.machineUpdateRestartSnapshot(expected: current, directory: f.directory, restart: restart)
        let loan = try verifierLoan(f, snapshot: snapshot, restart: restart); defer { loan.close() }
        func verifyBackend(_ selected: Data, _ boundary: () throws -> Void) throws {
            XCTAssertEqual(selected, account)
            try MachineUpdateBackendPublicationFiles.requireInLease(snapshot.backend, configuration: snapshot.configuration,
                accountID: selected, directory: directory, owner: getuid(), readFence: readFence, verifyCurrent: boundary)
        }
        try verifyRestart(f, snapshot: snapshot, loan: loan, backend: verifyBackend)
        func verifyCompletionMetadata() throws {
            try MachineUpdateCompletionPublicationFiles.requireBackendMetadataInLease(snapshot, accountID: account,
                directory: directory, owner: getuid(), readFence: readFence, verifyCurrent: {})
        }
        try verifyCompletionMetadata()
        _ = try AdministrativeSetupPublication.publish(fence.encoded, file: fenceFile, directory: directory, owner: getuid())
        XCTAssertThrowsError(try verifyRestart(f, snapshot: snapshot, loan: loan, backend: verifyBackend)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
        XCTAssertThrowsError(try verifyCompletionMetadata()) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
        try FileManager.default.removeItem(at: fenceURL)
        XCTAssertNil(source.revision)
        _ = try AdministrativeSetupPublication.publish(revision.encoded, file: .gatewaySettingsRevision,
            directory: directory, owner: getuid())
        XCTAssertThrowsError(try verifyCompletionMetadata()) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
    }

    func testBackendPublicationAdvancesOperandsAboveTheOrdinaryRecordLimit() throws {
        var gatewayFixture: GatewayJournalSetupExchangeTests.Fixture?
        let f = try Fixture(backendEpoch: true, beforeActivation: { files in
            let setup = try GatewayJournalSetupExchangeTests.Fixture(runtime: files.machine.f)
            try setup.retainCompletion(.decode(setup.initialize()))
            let store = files.machine.store
            let activation = try GatewayRuntimeActivationPlan(journal: setup.state(),
                foreground: setup.runtime.plan, inventory: XCTUnwrap(store.inventory()))
            try store.retainGatewayRuntimeActivation(activation)
            try store.markGatewayRuntimePublished(activation)
            _ = try store.enrollGatewayRuntimeActivation(activation)
            try store.markGatewayRuntimeRegistered(activation)
            gatewayFixture = setup
        })
        let setup = try XCTUnwrap(gatewayFixture)
        let published = try publishFixtureConfigurationEpoch(f, retainFixtureConfigurationEpoch(f))
        let account = f.machine.account
        let configured = try XCTUnwrap(f.machine.store.machineUpdateConfigurationEpoch()?.configuration(accountID: account))
        let machine = try restartSource(f)
        let source = try RuntimeReleaseBackendSource(foreground: setup.runtime.plan,
            activation: XCTUnwrap(f.machine.store.gatewayRuntimeActivation(accountID: account).plan), journal: setup.state(),
            settings: f.machine.store.gatewaySettingsTransition(accountID: account), inventory: machine.replacement.inventory)
        func plan(_ value: RuntimeReleaseConfigurationPlan) throws -> RuntimeReleaseBackendPlan {
            try .init(configuration: value, source: source, sourceConfiguration: configured.source,
                machine: machine, currentPolicy: releasePolicySnapshot(f), candidate: f.newRelease)
        }
        let capture = try MachineUpdateBackendEpoch.Capture(accountID: account, source: source,
            startup: plan(configured.startup), completion: plan(configured.completion))

        // Valid fixture plans stay far below the 278,528-byte ordinary limit, so the store reopens with a lower one.
        // Every plan row then exceeds the ordinary limit, as a large retained plan would in production.
        let ordinaryLimit: Int32 = 32_768
        XCTAssertGreaterThan(try XCTUnwrap(capture.startup).encoded.count, Int(ordinaryLimit))
        XCTAssertGreaterThan(try XCTUnwrap(capture.completion).encoded.count, Int(ordinaryLimit))
        try f.reopen(inventoryRecordLimit: ordinaryLimit)
        let store = f.machine.store
        let initial = try store.upgradeMachineUpdateBackendEpochStorage(expected: published,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        let retained = try store.retainMachineUpdateBackendEpoch(initial, captures: [capture], candidate: f.newRelease,
            directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        XCTAssertEqual(try store.machineUpdateBackendEpoch()?.record, retained)
        func advance(_ previous: MachineUpdateBackendEpochRecord, _ operation: MachineUpdateBackendPublicationOperation)
            throws -> MachineUpdateBackendEpochRecord {
            try store.advanceMachineUpdateBackendPublication(previous, operation: operation, candidate: f.newRelease,
                directory: f.directory, quiescence: f.quiet, verifyCurrent: { _ in })
        }
        let file = try XCTUnwrap(MachineUpdateBackendPublicationProgress.File.allCases.first)
        var record = try advance(retained, .begin)
        record = try advance(record, .prepare(account, file))
        record = try advance(record, .complete(account, file))
        let archive = try XCTUnwrap(store.machineUpdateBackendEpoch())
        XCTAssertEqual(archive.record, record)
        XCTAssertEqual(archive.record.operands, retained.operands)
        XCTAssertEqual(try archive.capture(accountID: account)?.completion?.encoded, try capture.completion?.encoded)
    }

    private func restartWithRetainedBackend(_ f: Fixture, complete: Bool) throws
        -> (MachineUpdateRestartSource, UpdateRestartAdmissionLease) {
        let configuration = try publishFixtureConfigurationEpoch(f, retainFixtureConfigurationEpoch(f))
        let store = f.machine.store
        let backend = try store.upgradeMachineUpdateBackendEpochStorage(expected: configuration,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        let retained = try store.retainMachineUpdateBackendEpoch(backend,
            captures: [.init(accountID: f.machine.account, source: nil, startup: nil, completion: nil)],
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        if complete {
            _ = try store.advanceMachineUpdateBackendPublication(retained, operation: .begin,
                candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: { _ in })
        }
        let restart = try f.quiet.releaseActivityForRestart()
        do {
            let activation = try store.markMachineUpdateRestartChecking(f.activation, directory: f.directory,
                restart: restart, verifyCurrent: {})
            return (try store.machineUpdateRestartSource(activation, directory: f.directory), restart)
        } catch {
            restart.close()
            throw error
        }
    }

    func testRestartSnapshotRejectsAnIncompleteBackendEpoch() throws {
        let f = try Fixture(backendEpoch: true)
        let (source, restart) = try restartWithRetainedBackend(f, complete: false)
        defer { restart.close() }
        XCTAssertThrowsError(try f.machine.store.machineUpdateRestartSnapshot(expected: source,
            directory: f.directory, restart: restart)) {
            XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
        }
    }

    func testRestartSnapshotScopeExpiresAndRejectsReentry() throws {
        let f = try Fixture(backendEpoch: true)
        let (source, restart) = try restartWithRetainedBackend(f, complete: true)
        defer { restart.close() }
        let store = f.machine.store
        let snapshot = try store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        XCTAssertEqual(snapshot.source, source)
        XCTAssertEqual(snapshot.configuration.record.publication?.complete, true)
        XCTAssertEqual(snapshot.backend.record.publication?.complete, true)
        let escaped = try store.withCurrentMachineUpdateRestartSnapshot(snapshot, directory: f.directory, restart: restart) { scope in
            try scope.read().requireSame(as: snapshot)
            XCTAssertThrowsError(try store.machineUpdateBackendEpoch()) {
                XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
            }
            return scope
        }
        XCTAssertThrowsError(try escaped.read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        let wrong = MachineUpdateRestartSnapshot(source: source,
            configuration: .init(record: snapshot.configuration.record, artifacts: []), backend: snapshot.backend)
        XCTAssertThrowsError(try store.withCurrentMachineUpdateRestartSnapshot(wrong,
            directory: f.directory, restart: restart) { _ in XCTFail("Changed archive reached the reader") }) {
            XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
        }
    }

    func testRestartPlacementRequiresTheObservedOriginalParentsAndBundleIdentities() throws {
        let f = try Fixture(), foreign = try Fixture()
        let record = try f.run().record
        try MachineUpdateRestartPlacement.require(record, installed: f.installed, prepared: f.machine.destination)
        XCTAssertThrowsError(try MachineUpdateRestartPlacement.require(record,
            installed: foreign.installed, prepared: f.machine.destination))
        let moved = f.oldURL.appendingPathExtension("moved")
        try FileManager.default.moveItem(at: f.oldURL, to: moved)
        try FileManager.default.copyItem(at: moved, to: f.oldURL)
        XCTAssertThrowsError(try MachineUpdateRestartPlacement.require(record,
            installed: f.installed, prepared: f.machine.destination)) {
            XCTAssertEqual($0 as? MachineUpdateReplacementError, .changedBinding)
        }
    }

    private func verifierLoan(_ f: Fixture, snapshot: MachineUpdateRestartSnapshot,
        restart: UpdateRestartAdmissionLease) throws -> MachineUpdateRestartReadinessLoan {
        let source = snapshot.source.replacement, activation = source.activation
        let access = try MachineUpdateRestartSharedActivity(restart: restart, activity: f.files.activity(),
            directory: f.directory, expectedMachine: source.admission.machine, macID: activation.macID,
            installationID: activation.installationID, activationAttempt: activation.attemptID)
        return try access.acquireShared()
    }

    private func verifyRestart(_ f: Fixture, snapshot: MachineUpdateRestartSnapshot,
        loan: MachineUpdateRestartReadinessLoan, sourceAccess: MachineUpdateHealthSourceAccess = .init(),
        read: (() throws -> MachineUpdateRestartSnapshot)? = nil, inspect: ((URL) throws -> SignedReleaseEvidence)? = nil,
        configuration: (Data, () throws -> Void) throws -> Void = { _, verify in try verify() },
        backend: (Data, () throws -> Void) throws -> Void = { _, verify in try verify() }) throws {
        let selected = try XCTUnwrap(snapshot.configuration.configuration(accountID: f.machine.account))
        try MachineUpdateNativeRestartVerifier.requireInLease(snapshot, host: selected.startup.host,
            installed: f.installed, prepared: f.machine.destination, loan: loan, sourceAccess: sourceAccess,
            readCurrent: read ?? {
                try f.machine.store.machineUpdateRestartSnapshot(expected: snapshot.source, directory: f.directory, readiness: loan)
            }, inspect: inspect ?? { try f.inspect($0, "", "") }, requireConfiguration: configuration, requireBackend: backend)
    }

    func testRestartResourceOpenUsesTheVerifierBeforeReadingTheSigner() throws {
        let f = try Fixture(backendEpoch: true)
        let (source, restart) = try restartWithRetainedBackend(f, complete: true); defer { restart.close() }
        let snapshot = try f.machine.store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let loan = try verifierLoan(f, snapshot: snapshot, restart: restart); defer { loan.close() }
        let host = try XCTUnwrap(snapshot.configuration.configuration(accountID: f.machine.account)).startup.host
        let shared = SharedRestartSnapshot(value: snapshot), release = Mutex(f.oldRelease), calls = Mutex([String]())
        let verifier = MachineUpdateNativeRestartVerifier(snapshot: snapshot, host: host, sourceAccess: .init(),
            readCurrent: { _ in shared.value }, owned: .init(installed: f.installed, prepared: f.machine.destination,
                inspect: { _ in release.withLock { $0 } },
                requireConfiguration: { _, check in try check() }, requireBackend: { _, check in try check() }))
        let verify = verifier.verification(loan: loan) { calls.withLock { $0.append("verify") } }
        func open(invalidateAfterJournal: Bool = false) throws -> (String, String) {
            try MachineUpdateAuthorityHealthOwner.openVerifiedRestartResources(verify: verify, openJournal: {
                calls.withLock { $0.append("journal") }
                if invalidateAfterJournal { release.withLock { $0 = f.oldRelease } }
                return "journal"
            }, openSigner: {
                calls.withLock { $0.append("signer") }; return "signer"
            }, closeJournal: { journal in
                XCTAssertEqual(journal, "journal")
                calls.withLock { $0.append("close") }
            })
        }
        XCTAssertThrowsError(try open()) { XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongRelease) }
        XCTAssertEqual(calls.withLock { $0 }, ["verify"])
        calls.withLock { $0.removeAll() }
        var dependencies = f.newRelease.dependencyCodeDirectoryHashes
        dependencies["Contents/Frameworks/ForeignFixture"] = Data(repeating: 9, count: 20)
        let invalid = SignedReleaseEvidence(manifest: f.newRelease.manifest,
            codeDirectoryHashes: f.newRelease.codeDirectoryHashes, dependencyCodeDirectoryHashes: dependencies)
        XCTAssertEqual(try DurableReleasePreparation.digest(invalid), snapshot.source.replacement.activation.updateID)
        release.withLock { $0 = invalid }
        XCTAssertThrowsError(try open()) { XCTAssertEqual($0 as? InstallationInventoryError, .releaseMismatch) }
        XCTAssertEqual(calls.withLock { $0 }, ["verify"])
        calls.withLock { $0.removeAll() }
        release.withLock { $0 = f.newRelease }
        XCTAssertThrowsError(try open(invalidateAfterJournal: true)) {
            XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongRelease)
        }
        XCTAssertEqual(calls.withLock { $0 }, ["verify", "journal", "verify", "close"])
        calls.withLock { $0.removeAll() }
        release.withLock { $0 = f.newRelease }
        let (journal, signer) = try open()
        XCTAssertEqual(journal, "journal")
        XCTAssertEqual(signer, "signer")
        XCTAssertEqual(calls.withLock { $0 }, ["verify", "journal", "verify", "signer", "verify"])
    }

    func testRestartVerifierRejectsASwappedPreparedIdentityBeforeInspection() throws {
        let f = try Fixture(backendEpoch: true)
        let (source, restart) = try restartWithRetainedBackend(f, complete: true); defer { restart.close() }
        let snapshot = try f.machine.store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let loan = try verifierLoan(f, snapshot: snapshot, restart: restart); defer { loan.close() }
        let moved = f.preparedURL.appendingPathExtension("moved")
        try FileManager.default.moveItem(at: f.preparedURL, to: moved)
        try FileManager.default.copyItem(at: moved, to: f.preparedURL)
        XCTAssertThrowsError(try verifyRestart(f, snapshot: snapshot, loan: loan, inspect: { _ in
            XCTFail("Changed placement reached signed inspection"); throw ReplacementFixtureError.signature
        })) { XCTAssertEqual($0 as? MachineUpdateReplacementError, .changedBinding) }
    }

    func testRestartVerifierRejectsThePreviousSignedReleaseBeforeReadingPublishedFiles() throws {
        let f = try Fixture(backendEpoch: true)
        let (source, restart) = try restartWithRetainedBackend(f, complete: true); defer { restart.close() }
        let snapshot = try f.machine.store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let loan = try verifierLoan(f, snapshot: snapshot, restart: restart); defer { loan.close() }
        XCTAssertThrowsError(try verifyRestart(f, snapshot: snapshot, loan: loan, inspect: { _ in f.oldRelease },
            configuration: { _, _ in XCTFail("The previous release reached the file reader") })) {
            XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongRelease)
        }
    }

    func testRestartVerifierUsesABorrowedSnapshotAndRejectsChangedPublishedBytes() throws {
        let f = try Fixture(backendEpoch: true)
        let (source, restart) = try restartWithRetainedBackend(f, complete: true); defer { restart.close() }
        let store = f.machine.store
        let snapshot = try store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let loan = try verifierLoan(f, snapshot: snapshot, restart: restart); defer { loan.close() }
        let access = MachineUpdateHealthSourceAccess(), account = f.machine.account
        let configuration = try XCTUnwrap(snapshot.configuration.configuration(accountID: account))
        XCTAssertEqual(chmod(f.files.root.path, 0o755), 0)
        let files = try ProtectedSetupDirectory(anchor: f.files.root.path, relativePath: "VerifierConfiguration",
            owner: getuid(), visibility: .sharedMetadata)
        defer { files.close() }
        _ = try AdministrativeSetupPublication.publish(configuration.bytes(.gateway, target: true),
            file: .gatewaySettingsHost, directory: files, owner: getuid())
        func verifyFiles(_ selected: Data, _ verify: () throws -> Void) throws {
            XCTAssertEqual(selected, account)
            try MachineUpdateConfigurationFiles.requirePublishedInLease(snapshot.configuration, accountID: selected,
                file: .gateway, directory: files, owner: getuid(), verify: verify)
        }
        let escaped = try store.withCurrentMachineUpdateRestartSnapshot(snapshot, directory: f.directory, readiness: loan) { scope in
            try access.withScope(scope, expected: snapshot) {
                try verifyRestart(f, snapshot: snapshot, loan: loan, sourceAccess: access, read: {
                    XCTFail("The verifier reentered the machine store"); throw ReplacementFixtureError.injected
                }, configuration: verifyFiles)
            }
            return scope
        }
        XCTAssertThrowsError(try access.withScope(escaped, expected: snapshot) {
            XCTFail("Expired scope reached the verifier")
        }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        let previous = try configuration.bytes(.gateway, target: false)
        let file = URL(fileURLWithPath: files.path).appendingPathComponent(AdministrativeSetupPublication.File.gatewaySettingsHost.name)
        try previous.write(to: file)
        XCTAssertThrowsError(try verifyRestart(f, snapshot: snapshot, loan: loan, configuration: verifyFiles)) {
            XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
        }
        XCTAssertEqual(try Data(contentsOf: file), previous)
    }

    func testRestartHealthSelectsExactForegroundCodeKeysAndEpochs() throws {
        let f = try Fixture(backendEpoch: true, beforeActivation: { files in
            try files.machine.store.markRuntimeJobsRegistered(files.machine.f.plan)
        })
        let (source, restart) = try restartWithRetainedBackend(f, complete: true)
        defer { restart.close() }
        let snapshot = try f.machine.store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let plan = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: f.newRelease)
        let account = f.machine.account, reference = f.machine.f.plan.reference
        let (configuration, authority) = try plan.select(accountID: account, role: .authority)
        let (_, transport) = try plan.select(accountID: account, role: .transport)
        XCTAssertEqual(plan.requirements.map(\.role), [.authority, .transport])
        XCTAssertEqual(authority.executionUID, 0)
        XCTAssertEqual(authority.publicKey, reference.services.authorityPublicKey)
        XCTAssertEqual(transport.executionUID, try XCTUnwrap(reference.services.claims.first { $0.role == .transport }).number)
        XCTAssertEqual(transport.publicKey, try reference.transportPublicKeyX963)
        for requirement in [authority, transport] {
            XCTAssertEqual(requirement.binding, configuration.configuration.binding)
            XCTAssertEqual(requirement.configurationEpoch, snapshot.configuration.record.id)
            XCTAssertEqual(requirement.configurationRevision, snapshot.configuration.record.revision)
            XCTAssertEqual(requirement.backendEpoch, snapshot.backend.record.id)
            XCTAssertEqual(requirement.backendRevision, snapshot.backend.record.revision)
            XCTAssertEqual(requirement.code, configuration.configuration.host.codePolicy.entries.first {
                $0.role == requirement.role && $0.active
            })
        }
        XCTAssertThrowsError(try plan.select(accountID: account, role: .notificationGateway))
        XCTAssertThrowsError(try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: f.oldRelease))
        let selected = try MachineUpdateAuthorityHealthOwner.RestartSelection(snapshot: snapshot, candidate: f.newRelease,
            accountID: account)
        XCTAssertEqual(selected.requirement, authority)
        XCTAssertEqual(selected.host.canonicalBytes, configuration.configuration.host.canonicalBytes)
        XCTAssertEqual(selected.policy, try snapshot.configuration.policy(accountID: account))
        XCTAssertNil(selected.gateway)
        XCTAssertThrowsError(try MachineUpdateAuthorityHealthOwner.RestartSelection(snapshot: snapshot, candidate: f.newRelease,
            accountID: Data(repeating: 99, count: 16)))
    }

    private struct CompletionFixture {
        let files: UpdateCandidateStorageFixture
        var machine: PreparationIntentStore { files.store }
        let directory: ReleaseDestinationLease
        let restart: UpdateRestartAdmissionLease
        let snapshot: MachineUpdateRestartSnapshot
        let candidate: SignedReleaseEvidence
        let previousRelease: SignedReleaseEvidence
        let inventory: MachineUpdateHealthInventory
        let boundary: AuthorityJournal.MachineUpdatePolicyBoundary

        func openPolicyPair(readOnly: Bool) throws -> AuthorityJournal {
            let account = try XCTUnwrap(snapshot.source.accounts.first { $0.accountID == boundary.accountID })
            let initial = try XCTUnwrap(account.initialization)
            let fixture = files.f.f
            let prefix = fixture.root.path + "/"
            let journalPath = (initial.journalPath as NSString).deletingLastPathComponent
            let continuityPath = (initial.continuityPath as NSString).deletingLastPathComponent
            guard journalPath.hasPrefix(prefix), continuityPath.hasPrefix(prefix) else {
                throw ReplacementFixtureError.injected
            }
            let journal = String(journalPath.dropFirst(prefix.count))
            let continuity = String(continuityPath.dropFirst(prefix.count))
            let storage = try Self.openPolicyStorage(anchor: fixture.root.path, journal: journal,
                continuity: continuity, macID: initial.macID, accountID: initial.accountID, limits: fixture.limits, readOnly: readOnly)
            if readOnly { return try AuthorityJournal(updateHealthStorage: storage, validateSelf: { _ in }) }
            return try AuthorityJournal(updateCompletionStorage: storage, validateSelf: { _ in })
        }

        private static func openPolicyStorage(anchor: String, journal: String, continuity: String, macID: Data, accountID: Data,
            limits: CBORLimits, readOnly: Bool) throws -> sending AuthorityStorage {
            try AuthorityStorage(openJournal: {
                try JournalDatabase(lease: .init(anchor: anchor, relativeDirectory: journal, owner: getuid()),
                    macID: macID, accountID: accountID, recordLimits: limits,
                    descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 10,
                    busyMilliseconds: 100, initialize: false, readOnlyForCutover: readOnly)
            }, openContinuity: { excluded in
                try ContinuityStore(lease: .init(anchor: anchor, relativeDirectory: continuity,
                    owner: getuid(), excludingDirectory: excluded), macID: macID,
                    accountID: accountID, initialize: nil, readOnlyForCutover: readOnly)
            })
        }

        func intent(revision: UInt8 = 249) throws -> MachineUpdateCompletionIntentArchive {
            try MachineUpdateCompletionIntentProposal.make(snapshot: snapshot, candidate: candidate, inventory: inventory,
                policies: [boundary], targetRevision: Data(repeating: revision, count: 16))
        }

        func committedBoundary(for pending: MachineUpdateCompletionIntentArchive,
            changeLedger: Bool = false) throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
            let row = try XCTUnwrap(pending.policies.first)
            let target = try AuthorityCodePolicy.decode(row.completionPolicy)
            let policy = boundary.policy
            let roles = try Dictionary(uniqueKeysWithValues: zip(policy.policy.entries, target.entries).map { previous, current in
                (current.role, previous == current ? try XCTUnwrap(policy.roleRevisions[current.role]) : UUID())
            })
            let written = AuthorityCodePolicySnapshot(revision: UUID(), policy: target, roleRevisions: roles)
            let checkpoint = boundary.checkpoint
            let successor = try checkpoint.successor(authorityDigest: Data(repeating: 9, count: 32),
                ledgerDigest: changeLedger ? Data(repeating: 99, count: 32) : checkpoint.ledgerDigest,
                journalEpoch: checkpoint.journalEpoch, journalHead: checkpoint.journalHead)
            return .init(macID: boundary.macID, accountID: boundary.accountID, policy: written, checkpoint: successor)
        }

        func recorded(revision: UInt8 = 249) throws -> MachineUpdateCompletionIntentArchive {
            let pending = try intent(revision: revision).preparingWrite(accountID: boundary.accountID, expected: boundary)
            return try pending.recordingRecoveredBoundary(committedBoundary(for: pending))
        }

        func plan(_ intent: MachineUpdateCompletionIntentArchive) throws -> MachineUpdateCompletionPublicationPlan {
            try .init(retainedConfiguration: snapshot.configuration, retainedBackend: snapshot.backend,
                intent: intent, candidate: candidate)
        }
    }

    private func withCompletionFixture(installedReadiness: Bool = false, actualPolicyPair: Bool = false,
        _ body: (CompletionFixture) throws -> Void) throws {
        let f = try Fixture(backendEpoch: true, installedReadiness: installedReadiness, completionIntent: true, beforeActivation: { files in
            try files.machine.store.markRuntimeJobsRegistered(files.machine.f.plan)
        })
        let (source, restart) = try restartWithRetainedBackend(f, complete: true)
        defer { restart.close() }
        let snapshot = try f.machine.store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let inventory = try MachineUpdateHealthInventory(plan: .init(snapshot: snapshot, candidate: f.newRelease))
        let account = f.machine.account
        let policy = try XCTUnwrap(snapshot.configuration.policy(accountID: account))
        let checkpoint = try ContinuityCheckpoint(generation: 1, authorityDigest: Data(repeating: 2, count: 32),
            ledgerDigest: Data(repeating: 3, count: 32), journalEpoch: Data(repeating: 4, count: 16), journalHead: 0)
        let boundary = AuthorityJournal.MachineUpdatePolicyBoundary(macID: source.replacement.inventory.macID,
            accountID: account, policy: policy, checkpoint: checkpoint)
        var fixture = CompletionFixture(files: f.machine, directory: f.directory, restart: restart, snapshot: snapshot,
            candidate: f.newRelease, previousRelease: f.oldRelease, inventory: inventory, boundary: boundary)
        if actualPolicyPair {
            let reader = try fixture.openPolicyPair(readOnly: true)
            defer { try? reader.close() }
            let actual = try reader.captureMachineUpdatePolicyBoundaryForRecoveryRead()
            try reader.close()
            XCTAssertEqual(actual.policy, policy)
            fixture = .init(files: f.machine, directory: f.directory, restart: restart, snapshot: snapshot,
                candidate: f.newRelease, previousRelease: f.oldRelease, inventory: inventory, boundary: actual)
        }
        try body(fixture)
    }

    func testCompletionIntentRetentionRollsBackAndRecoversOnlyTheExactArchive() throws {
        try withCompletionFixture { fixture in
            let archive = try fixture.intent()
            let store = fixture.machine
            XCTAssertNil(try store.machineUpdateCompletionIntent())
            var expired: PreparationIntentStore.CompletionPreparationScope?
            func retain(_ expected: MachineUpdateCompletionIntentArchive, failAfterMutation: Bool = false) throws
                -> MachineUpdateCompletionIntentArchive {
                try store.retainMachineUpdateCompletionIntent(expected, snapshot: fixture.snapshot,
                    candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { stage, scope in
                    let preparation = try scope.read()
                    XCTAssertEqual(preparation.proposal, expected)
                    if stage == .afterMutation {
                        XCTAssertTrue(preparation.intentRetained)
                        XCTAssertEqual(preparation.runtime.schemaVersion, 21)
                        if failAfterMutation { throw ReplacementFixtureError.injected }
                    }
                    expired = scope
                }
            }
            XCTAssertThrowsError(try retain(archive, failAfterMutation: true)) {
                XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
            }
            XCTAssertNil(try store.machineUpdateCompletionIntent())
            XCTAssertEqual(try store.retainedRuntimeCompatibilityInputs().schemaVersion, 20)

            XCTAssertEqual(try retain(archive), archive)
            XCTAssertEqual(try retain(archive), archive)
            XCTAssertEqual(try store.machineUpdateCompletionIntent(), archive)
            let actual = try store.machineUpdateCompletionRecoverySnapshot(candidate: fixture.candidate, directory: fixture.directory)
            try actual.requireSame(as: .init(restart: fixture.snapshot, intent: archive))
            XCTAssertThrowsError(try XCTUnwrap(expired).read()) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            let other = try fixture.intent(revision: 248)
            XCTAssertThrowsError(try retain(other)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(try store.machineUpdateCompletionIntent(), archive)
        }
    }

    func testCompletionStoragePreservesOnlyCommittedProgressWhenVerificationFails() throws {
        try withCompletionFixture { fixture in
            typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
            let archive = try fixture.intent()
            let writing = try archive.preparingWrite(accountID: fixture.boundary.accountID, expected: fixture.boundary)
            func retain(_ expected: MachineUpdateCompletionIntentArchive, failure: Stage) throws {
                _ = try fixture.machine.retainMachineUpdateCompletionIntent(expected, snapshot: fixture.snapshot,
                    candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { stage, scope in
                        _ = try scope.read()
                        if stage == failure { throw ReplacementFixtureError.injected }
                    }
            }
            func authorize(failure: Stage) throws {
                _ = try fixture.machine.authorizeMachineUpdatePolicyWrite(expected: archive, accountID: fixture.boundary.accountID,
                    boundary: fixture.boundary, snapshot: fixture.snapshot, candidate: fixture.candidate,
                    directory: fixture.directory, restart: fixture.restart, readBoundary: { _ in fixture.boundary }) { stage, scope in
                        _ = try scope.read()
                        if stage == failure { throw ReplacementFixtureError.injected }
                    }
            }

            XCTAssertThrowsError(try retain(writing, failure: .beforeTransaction)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            for stage in [Stage.beforeTransaction, .inTransaction, .afterMutation] {
                XCTAssertThrowsError(try retain(archive, failure: stage)) {
                    XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
                }
                XCTAssertNil(try fixture.machine.machineUpdateCompletionIntent())
            }
            XCTAssertThrowsError(try retain(archive, failure: .afterCommit)) {
                XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
            }
            XCTAssertThrowsError(try fixture.machine.machineUpdateCompletionIntent()) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
            try fixture.files.reopen()
            XCTAssertEqual(try fixture.machine.machineUpdateCompletionIntent(), archive)

            for stage in [Stage.beforeTransaction, .inTransaction, .afterMutation] {
                XCTAssertThrowsError(try authorize(failure: stage)) {
                    XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
                }
                XCTAssertEqual(try fixture.machine.machineUpdateCompletionIntent(), archive)
            }
            XCTAssertThrowsError(try authorize(failure: .afterCommit)) {
                XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
            }
            XCTAssertThrowsError(try fixture.machine.machineUpdateCompletionIntent()) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
            try fixture.files.reopen()
            let retained = try XCTUnwrap(fixture.machine.machineUpdateCompletionIntent())
            XCTAssertEqual(retained.policies.first?.phase, .writing)
            let recovered = try MachineUpdateCompletionRecoverySequence.reconcileConclusive(retained,
                snapshot: fixture.snapshot, candidate: fixture.candidate, machine: fixture.machine,
                directory: fixture.directory, restart: fixture.restart, verify: { _, scope in _ = try scope.read() },
                boundary: { _, _ in fixture.boundary })
            XCTAssertEqual(recovered, retained)
        }
    }

    func testCompletionPermitRejectsAnotherThreadAndConsumesAFailedAttempt() throws {
        try withCompletionFixture { fixture in
            let archive = try fixture.intent()
            let machine = fixture.machine
            _ = try machine.retainMachineUpdateCompletionIntent(archive, snapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { _, scope in
                    _ = try scope.read()
                }
            let authorized = try machine.authorizeMachineUpdatePolicyWrite(expected: archive, accountID: fixture.boundary.accountID,
                boundary: fixture.boundary, snapshot: fixture.snapshot, candidate: fixture.candidate,
                directory: fixture.directory, restart: fixture.restart, readBoundary: { _ in fixture.boundary }) { _, scope in
                    _ = try scope.read()
                }
            let permit = authorized.permit
            let finished = DispatchSemaphore(value: 0)
            try machine.withCurrentMachineUpdateCompletionSnapshot(expected: authorized.archive, restartSnapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { scope in
                    DispatchQueue.global().async {
                        defer { finished.signal() }
                        do {
                            _ = try permit.consume(in: scope)
                            XCTFail("A foreign thread consumed the policy permit")
                        } catch {
                            XCTAssertEqual(error as? JournalLeaseError, .invalidated)
                        }
                    }
                    XCTAssertEqual(finished.wait(timeout: .now() + .seconds(5)), .success)
                    if getuid() != 0 || geteuid() != 0 {
                        XCTAssertThrowsError(try MachineUpdateCompletionPolicyRead.readNative(accountID: fixture.boundary.accountID,
                            scope: scope, verifyCurrent: { XCTFail("An unprivileged caller reached native verification") })) {
                            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                        }
                    }
                }
            let actual = try fixture.committedBoundary(for: authorized.archive)
            let recorded = try MachineUpdateCompletionRecoverySequence.reconcileConclusive(authorized.archive,
                snapshot: fixture.snapshot, candidate: fixture.candidate, machine: machine, directory: fixture.directory,
                restart: fixture.restart, verify: { _, scope in _ = try scope.read() }, boundary: { _, _ in actual })
            XCTAssertTrue(recorded.policyMarkersRecorded)
            try machine.withCurrentMachineUpdateCompletionSnapshot(expected: recorded, restartSnapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { scope in
                    XCTAssertThrowsError(try permit.consume(in: scope)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                    }
                    XCTAssertThrowsError(try permit.consume(in: scope)) {
                        XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                    }
                }
        }
    }

    func testCompletionAuthorizationRereadsThePairBeforeWritingTheMarker() throws {
        try withCompletionFixture { fixture in
            let archive = try fixture.intent()
            let machine = fixture.machine
            _ = try machine.retainMachineUpdateCompletionIntent(archive, snapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { _, scope in
                    _ = try scope.read()
                }
            let changed = try fixture.committedBoundary(for: archive)
            var reads = 0
            XCTAssertThrowsError(try machine.authorizeMachineUpdatePolicyWrite(expected: archive,
                accountID: fixture.boundary.accountID, boundary: fixture.boundary, snapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart,
                readBoundary: { scope in
                    XCTAssertEqual(try scope.read().intent, archive)
                    reads += 1
                    return reads == 1 ? fixture.boundary : changed
                }) { _, scope in _ = try scope.read() }) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(reads, 2)
            XCTAssertEqual(try machine.machineUpdateCompletionIntent(), archive)
        }
    }

    func testCompletionRecoveryDoesNotRepeatAnUnresolvedPolicyWrite() throws {
        try withCompletionFixture { fixture in
            let archive = try fixture.intent()
            let machine = fixture.machine
            _ = try machine.retainMachineUpdateCompletionIntent(archive, snapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { _, scope in
                    _ = try scope.read()
                }
            let authorized = try machine.authorizeMachineUpdatePolicyWrite(expected: archive, accountID: fixture.boundary.accountID,
                boundary: fixture.boundary, snapshot: fixture.snapshot, candidate: fixture.candidate,
                directory: fixture.directory, restart: fixture.restart, readBoundary: { _ in fixture.boundary }) { _, scope in
                    _ = try scope.read()
                }
            let writing = authorized.archive
            XCTAssertEqual(writing.policies.first?.phase, .writing)
            for (expected, error) in [(writing, PreparationStoreError.invalidTransition), (archive, .staleRevision)] {
                XCTAssertThrowsError(try machine.authorizeMachineUpdatePolicyWrite(expected: expected,
                    accountID: fixture.boundary.accountID, boundary: fixture.boundary, snapshot: fixture.snapshot,
                    candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart,
                    readBoundary: { _ in
                        XCTFail("An unresolved marker reached the boundary reader")
                        return fixture.boundary
                    }) { _, _ in XCTFail("An unresolved marker reached the authorizer") }) {
                    XCTAssertEqual($0 as? PreparationStoreError, error)
                }
            }
            XCTAssertEqual(try machine.machineUpdateCompletionIntent(), writing)
            try machine.withCurrentMachineUpdateCompletionSnapshot(expected: writing, restartSnapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { scope in
                    XCTAssertEqual(try authorized.permit.consume(in: scope), writing.policies.first)
                    XCTAssertThrowsError(try authorized.permit.consume(in: scope)) {
                        XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                    }
                }
            func recover(_ current: MachineUpdateCompletionIntentArchive,
                read: (PreparationIntentStore.CompletionIntentStorageStage?) -> AuthorityJournal.MachineUpdatePolicyBoundary) throws
                -> MachineUpdateCompletionIntentArchive {
                var phase: PreparationIntentStore.CompletionIntentStorageStage?
                return try MachineUpdateCompletionRecoverySequence.reconcileConclusive(current, snapshot: fixture.snapshot,
                    candidate: fixture.candidate, machine: machine, directory: fixture.directory, restart: fixture.restart,
                    verify: { stage, scope in phase = stage; _ = try scope.read() },
                    boundary: { id, _ in
                        XCTAssertEqual(id, fixture.boundary.accountID)
                        return read(phase)
                    })
            }

            XCTAssertEqual(try recover(writing) { _ in fixture.boundary }, writing)
            XCTAssertEqual(try machine.machineUpdateCompletionIntent(), writing)
            XCTAssertThrowsError(try MachineUpdateCompletionRecoverySequence.resumePrepared(writing,
                snapshot: fixture.snapshot, candidate: fixture.candidate, machine: machine, directory: fixture.directory,
                restart: fixture.restart, verify: { _, scope in _ = try scope.read() },
                boundary: { _, _ in fixture.boundary },
                commit: { _, _ in
                    XCTFail("An unresolved marker reached the writer")
                    throw ReplacementFixtureError.injected
                })) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
            XCTAssertEqual(try machine.machineUpdateCompletionIntent(), writing)
            let committed = try fixture.committedBoundary(for: writing)
            XCTAssertThrowsError(try recover(writing) { $0 == .afterMutation ? fixture.boundary : committed }) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(try machine.machineUpdateCompletionIntent(), writing)
            let recorded = try recover(writing) { _ in committed }
            XCTAssertTrue(recorded.policyMarkersRecorded)
            XCTAssertEqual(try recover(recorded) { _ in committed }, recorded)
            XCTAssertEqual(try machine.machineUpdateCompletionIntent(), recorded)
            XCTAssertThrowsError(try machine.authorizeMachineUpdatePolicyWrite(expected: archive,
                accountID: fixture.boundary.accountID, boundary: fixture.boundary, snapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart,
                readBoundary: { _ in fixture.boundary }) { _, _ in
                    XCTFail("A stale archive reached the policy writer")
                }) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
        }
    }

    func testCompletionRecoveryReopensBothStoresAfterTheWriterLosesItsReceipt() throws {
        try withCompletionFixture(actualPolicyPair: true) { fixture in
            let archive = try fixture.intent()
            XCTAssertNotEqual(try XCTUnwrap(archive.policies.first).completionPolicy,
                try fixture.boundary.policy.policy.bytes)
            _ = try fixture.machine.retainMachineUpdateCompletionIntent(archive, snapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { _, scope in
                    _ = try scope.read()
                }
            let authorized = try fixture.machine.authorizeMachineUpdatePolicyWrite(expected: archive,
                accountID: fixture.boundary.accountID, boundary: fixture.boundary, snapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart,
                readBoundary: { _ in
                    let pair = try fixture.openPolicyPair(readOnly: true)
                    defer { try? pair.close() }
                    return try pair.captureMachineUpdatePolicyBoundaryForRecoveryRead()
                }) { _, scope in _ = try scope.read() }
            let writing = authorized.archive
            let readOnly = try fixture.openPolicyPair(readOnly: true)
            defer { try? readOnly.close() }
            try fixture.machine.withCurrentMachineUpdateCompletionSnapshot(expected: writing, restartSnapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { scope in
                    XCTAssertThrowsError(try readOnly.commitMachineUpdateCompletionPolicy(authorized.permit,
                        scope: scope, candidate: fixture.candidate, verifyNative: { _ in XCTFail("A read-only pair reached the writer") })) {
                        XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
                    }
                }
            XCTAssertEqual(try readOnly.captureMachineUpdatePolicyBoundaryForRecoveryRead(), fixture.boundary)
            try readOnly.close()

            let writer = try fixture.openPolicyPair(readOnly: false)
            defer { try? writer.close() }
            try fixture.machine.withCurrentMachineUpdateCompletionSnapshot(expected: writing, restartSnapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { scope in
                    var sawCommit = false
                    XCTAssertThrowsError(try writer.commitMachineUpdateCompletionPolicy(authorized.permit,
                        scope: scope, candidate: fixture.candidate) { stage in
                            if stage == .afterCommit { sawCommit = true; throw ReplacementFixtureError.injected }
                        }) { XCTAssertEqual($0 as? ReplacementFixtureError, .injected) }
                    XCTAssertTrue(sawCommit)
                    XCTAssertThrowsError(try writer.commitMachineUpdateCompletionPolicy(authorized.permit,
                        scope: scope, candidate: fixture.candidate, verifyNative: { _ in XCTFail("The used permit reached the writer") })) {
                        XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                    }
                }
            try writer.close()
            try fixture.files.reopen()
            XCTAssertEqual(try fixture.machine.machineUpdateCompletionIntent(), writing)

            func read() throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
                let pair = try fixture.openPolicyPair(readOnly: true)
                defer { try? pair.close() }
                return try pair.captureMachineUpdatePolicyBoundaryForRecoveryRead()
            }
            let before = try read()
            XCTAssertNotEqual(before, fixture.boundary)
            let recovered = try MachineUpdateCompletionRecoverySequence.resumePrepared(writing, snapshot: fixture.snapshot,
                candidate: fixture.candidate, machine: fixture.machine, directory: fixture.directory, restart: fixture.restart,
                verify: { _, scope in _ = try scope.read() }, boundary: { _, _ in try read() }, commit: { _, _ in
                    XCTFail("A conclusive commit reached the writer again")
                    throw ReplacementFixtureError.injected
                })
            XCTAssertTrue(recovered.policyMarkersRecorded)
            XCTAssertEqual(try read(), before)
            try fixture.files.reopen()
            XCTAssertEqual(try fixture.machine.machineUpdateCompletionIntent(), recovered)
        }
    }

    func testCompletionPublicationStorageRetainsOnlyTheExactRecordedPlan() throws {
        try withCompletionFixture(installedReadiness: true) { fixture in
            let prepared = try fixture.intent()
            let snapshot = fixture.snapshot
            let candidate = fixture.candidate
            let directory = fixture.directory
            let restart = fixture.restart
            let account = fixture.boundary.accountID
            _ = try fixture.machine.retainMachineUpdateCompletionIntent(prepared, snapshot: snapshot,
                candidate: candidate, directory: directory, restart: restart) { _, scope in _ = try scope.read() }
            let authorized = try fixture.machine.authorizeMachineUpdatePolicyWrite(expected: prepared, accountID: account,
                boundary: fixture.boundary, snapshot: snapshot, candidate: candidate, directory: directory,
                restart: restart, readBoundary: { _ in fixture.boundary }) { _, scope in _ = try scope.read() }
            let boundary = try fixture.committedBoundary(for: authorized.archive)
            let recorded = try MachineUpdateCompletionRecoverySequence.reconcileConclusive(authorized.archive,
                snapshot: snapshot, candidate: candidate, machine: fixture.machine, directory: directory, restart: restart,
                verify: { _, scope in _ = try scope.read() }, boundary: { _, _ in boundary })
            let plan = try MachineUpdateCompletionPublicationPlan(snapshot: .init(restart: snapshot, intent: recorded),
                candidate: candidate, currentSourceDigest: snapshot.backend.record.currentSourceDigest, boundaries: [boundary])
            let publication = try MachineUpdateCompletionPublicationRecord(plan: plan)
            XCTAssertEqual(publication.formatVersion, 2)
            typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
            var escaped: PreparationIntentStore.CompletionPublicationScope?
            func retain(failure: Stage? = nil) throws -> MachineUpdateCompletionPublicationRecord {
                try fixture.machine.retainMachineUpdateCompletionPublication(publication, plan: plan, expected: recorded,
                    restartSnapshot: snapshot, candidate: candidate, directory: directory, restart: restart) { stage, scope in
                        let actual = try scope.read()
                        XCTAssertEqual(actual.completion.intent, recorded)
                        if stage == failure { throw ReplacementFixtureError.injected }
                        escaped = scope
                    }
            }

            XCTAssertNil(try fixture.machine.machineUpdateCompletionPublication())
            for stage in [Stage.beforeTransaction, .inTransaction, .afterMutation] {
                XCTAssertThrowsError(try retain(failure: stage)) {
                    XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
                }
                XCTAssertEqual(try fixture.machine.retainedRuntimeCompatibilityInputs().schemaVersion, 21)
                XCTAssertNil(try fixture.machine.machineUpdateCompletionPublication())
            }
            XCTAssertThrowsError(try retain(failure: .afterCommit)) {
                XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
            }
            try fixture.files.reopen()
            XCTAssertEqual(try fixture.machine.machineUpdateCompletionPublication(), publication)
            XCTAssertEqual(try retain(), publication)
            XCTAssertEqual(try retain(), publication)
            XCTAssertThrowsError(try XCTUnwrap(escaped).read()) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            let actual = try fixture.machine.machineUpdateCompletionPublicationRecoverySnapshot(candidate: candidate, directory: directory)
            try actual.requireSame(as: .init(completion: .init(restart: snapshot, intent: recorded),
                publication: publication, candidate: candidate))

            let file = try XCTUnwrap(plan.entries.first?.file)
            let other = try XCTUnwrap(plan.entries.last?.file)
            func advance(_ publication: MachineUpdateCompletionPublicationRecord,
                _ operation: PreparationIntentStore.CompletionPublicationOperation, failure: Stage? = nil) throws
                -> MachineUpdateCompletionPublicationRecord {
                try fixture.machine.advanceMachineUpdateCompletionPublication(publication, operation: operation,
                    plan: plan, expected: recorded, restartSnapshot: snapshot, candidate: candidate, directory: directory,
                    restart: restart) { stage, scope in
                        _ = try scope.read()
                        if stage == failure { throw ReplacementFixtureError.injected }
                    }
            }
            XCTAssertNotEqual(file, other)
            XCTAssertThrowsError(try advance(publication, .prepare(account, other))) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            for stage in [Stage.beforeTransaction, .inTransaction] {
                XCTAssertThrowsError(try advance(publication, .prepare(account, file), failure: stage)) {
                    XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
                }
                XCTAssertEqual(try fixture.machine.machineUpdateCompletionPublication(), publication)
            }
            XCTAssertThrowsError(try advance(publication, .prepare(account, file), failure: .afterCommit)) {
                XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
            }
            try fixture.files.reopen()
            let writing = try XCTUnwrap(fixture.machine.machineUpdateCompletionPublication())
            XCTAssertEqual(try writing.state(accountID: account, file: file), .writing)
            XCTAssertThrowsError(try advance(publication, .prepare(account, file))) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            let root = fixture.files.f.f.root.path
            XCTAssertEqual(chmod(root, 0o755), 0)
            let files = try ProtectedSetupDirectory(anchor: root, relativePath: "CompletionPublication",
                owner: getuid(), visibility: .sharedMetadata)
            defer { files.close() }
            for entry in plan.entries {
                _ = try AdministrativeSetupPublication.publish(entry.startup, file: entry.artifact, directory: files, owner: getuid())
            }
            let first = try XCTUnwrap(plan.entries.first)
            XCTAssertNotEqual(first.startup, first.completion)
            let path = URL(fileURLWithPath: files.path).appendingPathComponent(first.artifact.name)
            let staging = URL(fileURLWithPath: files.path).appendingPathComponent(
                ".remozio-completion-" + publication.id.uuidString.lowercased() + "-" + first.artifact.name)
            let orphan = staging.appendingPathComponent("payload")
            func leaveOrphan(_ bytes: Data) throws {
                if !FileManager.default.fileExists(atPath: staging.path) {
                    try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false,
                        attributes: [.posixPermissions: 0o700])
                }
                try bytes.write(to: orphan)
                XCTAssertEqual(chmod(orphan.path, 0o600), 0)
            }
            XCTAssertThrowsError(try MachineUpdateCompletionPublicationFiles.publishInLease(plan, publication: publication,
                accountID: first.accountID, file: first.file, directory: files, owner: getuid(), verifyCurrent: {})) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try leaveOrphan(first.completion.prefix(8))
            XCTAssertEqual(try Data(contentsOf: path), first.startup)
            func publish(_ current: MachineUpdateCompletionPublicationRecord, stopAfterSwap: Bool,
                loseFirstAcknowledgment: Bool = false) throws -> MachineUpdateCompletionPublicationRecord {
                try MachineUpdateCompletionFileCoordinator.publish(current, plan: plan, expected: recorded,
                    restart: snapshot, candidate: candidate, machine: fixture.machine, directory: directory,
                    admission: restart, validate: { scope in
                        let publication = try XCTUnwrap(scope.read().publication)
                        try MachineUpdateCompletionPublicationFiles.requireInLeases(plan, publication: publication,
                            owner: getuid(), directory: { _ in files }, verifyCurrent: { _ = try scope.read() })
                    }, publishFile: { publication, entry, scope, didStage in
                        try MachineUpdateCompletionPublicationFiles.publishInLease(plan, publication: publication,
                            accountID: entry.accountID, file: entry.file, directory: files, owner: getuid(),
                            verifyCurrent: { _ = try scope.read() }, didStage: didStage)
                    }, didStore: { stage, scope in
                        guard loseFirstAcknowledgment, stage == .afterCommit,
                              let stored = try scope.read().publication,
                              try stored.state(accountID: account, file: file) == .published else { return }
                        throw ReplacementFixtureError.injected
                    }, didStage: { stage in
                        if stopAfterSwap, case .published = stage { throw ReplacementFixtureError.injected }
                    })
            }
            try Data("foreign contents".utf8).write(to: path)
            XCTAssertThrowsError(try publish(writing, stopAfterSwap: false)) {
                XCTAssertEqual($0 as? InstalledAuthorityCommandError, .changedConfiguration)
            }
            XCTAssertEqual(try fixture.machine.machineUpdateCompletionPublication(), writing)
            try first.startup.write(to: path)
            XCTAssertEqual(chmod(path.path, 0o666), 0)
            XCTAssertThrowsError(try publish(writing, stopAfterSwap: false)) {
                XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
            }
            XCTAssertThrowsError(try fixture.machine.machineUpdateCompletionPublication()) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
            XCTAssertEqual(chmod(path.path, first.artifact.mode), 0)
            try fixture.files.reopen()
            XCTAssertEqual(try fixture.machine.machineUpdateCompletionPublication(), writing)
            XCTAssertThrowsError(try publish(writing, stopAfterSwap: true)) {
                XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
            }
            XCTAssertEqual(try Data(contentsOf: path), first.completion)
            var swapped = stat()
            XCTAssertEqual(lstat(path.path, &swapped), 0)
            try fixture.files.reopen()
            let recoverable = try XCTUnwrap(fixture.machine.machineUpdateCompletionPublication())
            XCTAssertEqual(recoverable, writing)
            try leaveOrphan(first.startup)
            XCTAssertThrowsError(try publish(recoverable, stopAfterSwap: false, loseFirstAcknowledgment: true)) {
                XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: staging.path))
            try fixture.files.reopen()
            let acknowledged = try XCTUnwrap(fixture.machine.machineUpdateCompletionPublication())
            XCTAssertEqual(try acknowledged.state(accountID: account, file: file), .published)
            let published = try publish(acknowledged, stopAfterSwap: false)
            var replayed = stat()
            XCTAssertEqual(lstat(path.path, &replayed), 0)
            XCTAssertEqual(swapped.st_ino, replayed.st_ino)
            XCTAssertTrue(published.filesPublished)
            XCTAssertEqual(published.inventoryState, .pending)
            XCTAssertEqual(try fixture.machine.inventory(), snapshot.source.replacement.inventory)
            let retained = try fixture.machine.machineUpdateCompletionPublicationRecoverySnapshot(candidate: candidate, directory: directory)
            let installed = try MachineUpdateInstalledReleaseEpoch.Archive(snapshot: retained, candidate: candidate,
                currentSourceDigest: snapshot.backend.record.currentSourceDigest, boundaries: [boundary])
            func finalize(failure: Stage? = nil) throws -> MachineUpdateFinalizationSnapshot {
                try fixture.machine.finalizeMachineUpdateCompletion(installed, publication: published, plan: plan,
                    expected: recorded, restartSnapshot: snapshot, candidate: candidate, directory: directory, restart: restart,
                    ownedFileDirectory: { _ in files }) { stage, scope in
                        switch try scope.read() {
                        case .publication(let current):
                            XCTAssertEqual(current.publication, published)
                        case .installed(let current):
                            XCTAssertEqual(current.activation.phase, .finishing)
                            XCTAssertFalse(current.candidate.selected)
                            XCTAssertEqual(current.inventory, plan.inventory)
                        }
                        if stage == failure { throw ReplacementFixtureError.injected }
                    }
            }
            try Data("unrelated file contents".utf8).write(to: path)
            XCTAssertThrowsError(try finalize()) {
                XCTAssertEqual($0 as? InstalledAuthorityCommandError, .changedConfiguration)
            }
            XCTAssertEqual(try fixture.machine.machineUpdateCompletionPublication(), published)
            XCTAssertEqual(try fixture.machine.inventory(), snapshot.source.replacement.inventory)
            try first.completion.write(to: path)
            for stage in [Stage.beforeTransaction, .inTransaction, .afterMutation] {
                XCTAssertThrowsError(try finalize(failure: stage)) {
                    XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
                }
                XCTAssertEqual(try fixture.machine.inventory(), snapshot.source.replacement.inventory)
                XCTAssertEqual(try fixture.machine.machineUpdateCompletionPublication(), published)
            }
            XCTAssertThrowsError(try finalize(failure: .afterCommit)) {
                XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
            }
            try fixture.files.reopen()
            let finishing = try fixture.machine.machineUpdateFinalizationSnapshot(candidate: candidate, directory: directory)
            XCTAssertEqual(finishing.activation.phase, .finishing)
            XCTAssertEqual(finishing.installed.record, installed.record)
            XCTAssertEqual(finishing.inventory, plan.inventory)
            XCTAssertThrowsError(try fixture.machine.retainedRuntimeCompatibilityInputs()) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try fixture.machine.withCurrentMachineUpdateFinalization(candidate: candidate, directory: directory, restart: restart) { scope in
                guard case .installed(let current) = try scope.read() else { return XCTFail("Missing finishing frame") }
                try current.requireSame(as: finishing)
            }
            try restart.validate()
            XCTAssertThrowsError(try fixture.machine.begin(parent: fixture.files.destination.path,
                ancestry: fixture.files.destination.preparationAncestry())) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }

            func checkCorruptFrame(edit: String, restore: String) throws {
                try fixture.machine.close()
                try fixture.files.sql(edit)
                try fixture.files.reopen()
                XCTAssertThrowsError(try fixture.machine.machineUpdateFinalizationSnapshot(candidate: candidate, directory: directory)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
                try fixture.machine.close()
                try fixture.files.sql(restore)
                try fixture.files.reopen()
                let restored = try fixture.machine.machineUpdateFinalizationSnapshot(candidate: candidate, directory: directory)
                try restored.requireSame(as: finishing)
            }
            try checkCorruptFrame(edit: "UPDATE installed_release_state_v1 SET record=CAST(record || X'01' AS BLOB) WHERE kind=1",
                restore: "UPDATE installed_release_state_v1 SET record=substr(record,1,length(record)-1) WHERE kind=1")
            try checkCorruptFrame(edit: "INSERT INTO machine_update_completion_publication_v1 VALUES(1,zeroblob(16),zeroblob(16),X'01')",
                restore: "DELETE FROM machine_update_completion_publication_v1 WHERE singleton=1")
        }
    }

    func testCompletionStorageRefusesAnUnknownSchemaAndRetainsItsArchive() throws {
        try withCompletionFixture { fixture in
            let archive = try fixture.intent()
            _ = try fixture.machine.retainMachineUpdateCompletionIntent(archive, snapshot: fixture.snapshot,
                candidate: fixture.candidate, directory: fixture.directory, restart: fixture.restart) { _, scope in
                    _ = try scope.read()
                }
            try fixture.machine.close()
            // 22 is supported, but this store has no completion publication table. 24 is unsupported.
            for version in [22, 24] {
                try fixture.files.sql("PRAGMA user_version=\(version)")
                XCTAssertThrowsError(try fixture.files.reopen()) {
                    XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                }
                XCTAssertEqual(try fixture.files.f.f.sql("PRAGMA user_version"), Int64(version))
            }
            try fixture.files.sql("PRAGMA user_version=21")
            try fixture.files.reopen()
            XCTAssertEqual(try fixture.machine.machineUpdateCompletionIntent(), archive)
        }
    }

    func testCompletionIntentBindsTheRestartSnapshotAndExactPolicyRows() throws {
        try withCompletionFixture { fixture in
            let archive = try fixture.intent()
            let record = try MachineUpdateCompletionIntentRecord.decode(archive.record.encoded)
            let row = try MachineUpdatePolicyIntentRecord.decode(XCTUnwrap(archive.policies.first).encoded)
            XCTAssertEqual(try MachineUpdateCompletionIntentArchive(record: record, policies: [row]), archive)
            XCTAssertEqual(row.phase, .prepared)
            try archive.requireSnapshot(fixture.snapshot, candidate: fixture.candidate,
                currentSourceDigest: fixture.snapshot.backend.record.currentSourceDigest)
            XCTAssertThrowsError(try archive.requireSnapshot(fixture.snapshot, candidate: fixture.candidate,
                currentSourceDigest: Data(repeating: 249, count: 32))) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try MachineUpdateCompletionIntentArchive(record: record, policies: [])) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            XCTAssertThrowsError(try MachineUpdateCompletionIntentProposal.make(snapshot: fixture.snapshot, candidate: fixture.candidate,
                inventory: fixture.inventory, policies: [fixture.boundary, fixture.boundary], targetRevision: Data(repeating: 249, count: 16))) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testCompletionIntentRejectsAnotherSnapshotCandidateAndTargetRevision() throws {
        try withCompletionFixture { fixture in
            let intent = try fixture.intent(), snapshot = fixture.snapshot
            let digest = snapshot.backend.record.currentSourceDigest
            XCTAssertThrowsError(try intent.requireSnapshot(snapshot, candidate: fixture.previousRelease, currentSourceDigest: digest))
            XCTAssertThrowsError(try MachineUpdateCompletionIntentProposal.make(snapshot: snapshot, candidate: fixture.candidate,
                inventory: fixture.inventory, policies: [fixture.boundary],
                targetRevision: snapshot.source.replacement.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try withCompletionFixture { other in
                XCTAssertNotEqual(snapshot.configuration.record.id, other.snapshot.configuration.record.id)
                XCTAssertThrowsError(try intent.requireSnapshot(other.snapshot, candidate: other.candidate, currentSourceDigest: digest)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
        }
    }

    func testCompletionIntentKeepsAnUnresolvedWriteAndRejectsChangedLedgerFacts() throws {
        try withCompletionFixture { fixture in
            let archive = try fixture.intent(), boundary = fixture.boundary
            let pending = try archive.preparingWrite(accountID: boundary.accountID, expected: boundary)
            XCTAssertEqual(pending.policies.first?.phase, .writing)
            let reopened = try MachineUpdateCompletionIntentArchive(record: .decode(pending.record.encoded),
                policies: pending.policies.map { try .decode($0.encoded) })
            XCTAssertEqual(reopened, pending)
            XCTAssertThrowsError(try pending.preparingWrite(accountID: boundary.accountID, expected: boundary)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertThrowsError(try pending.recordingRecoveredBoundary(boundary)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertThrowsError(try pending.recordingRecoveredBoundary(fixture.committedBoundary(for: pending, changeLedger: true))) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            XCTAssertThrowsError(try fixture.plan(pending)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            let ready = try pending.recordingRecoveredBoundary(fixture.committedBoundary(for: pending))
            XCTAssertTrue(ready.policyMarkersRecorded)
            XCTAssertEqual(pending.policies.first?.phase, .writing)
        }
    }

    func testInstalledReleaseArchiveRequiresAllFilesAndFreshPairedPolicy() throws {
        try withCompletionFixture { fixture in
            let writing = try fixture.intent().preparingWrite(accountID: fixture.boundary.accountID, expected: fixture.boundary)
            let boundary = try fixture.committedBoundary(for: writing)
            let recorded = try writing.recordingRecoveredBoundary(boundary)
            let restart = fixture.snapshot
            let candidate = fixture.candidate
            let sourceDigest = restart.backend.record.currentSourceDigest
            let completion = MachineUpdateCompletionSnapshot(restart: restart, intent: recorded)
            let plan = try fixture.plan(recorded)
            var publication = try MachineUpdateCompletionPublicationRecord(plan: plan)

            func build(boundaries: [AuthorityJournal.MachineUpdatePolicyBoundary]) throws -> MachineUpdateInstalledReleaseEpoch.Archive {
                let snapshot = try MachineUpdateCompletionPublicationSnapshot(completion: completion,
                    publication: publication, candidate: candidate)
                return try .init(snapshot: snapshot, candidate: candidate, currentSourceDigest: sourceDigest, boundaries: boundaries)
            }
            XCTAssertThrowsError(try build(boundaries: [boundary])) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            for file in plan.entries {
                publication = try publication.advancing(accountID: file.accountID, file: file.file, to: .writing)
                publication = try publication.advancing(accountID: file.accountID, file: file.file, to: .published)
            }
            XCTAssertThrowsError(try build(boundaries: [fixture.boundary])) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }

            let archive = try build(boundaries: [boundary])
            let encoded = try archive.record.encoded
            let reopened = try MachineUpdateInstalledReleaseEpoch.Archive.decode(record: encoded,
                artifacts: archive.artifacts, candidate: candidate)
            XCTAssertEqual(reopened.record, archive.record)
            XCTAssertEqual(try reopened.inventory(), plan.inventory)
            XCTAssertEqual(try reopened.completionIntent(), recorded)
            XCTAssertEqual(try reopened.publicationSource(), publication)

            var tampered = archive.artifacts
            let index = try XCTUnwrap(tampered.firstIndex { $0.kind == 300 })
            let policy = tampered[index]
            var bytes = policy.bytes
            bytes[bytes.startIndex] ^= 1
            tampered[index] = .init(kind: policy.kind, accountID: policy.accountID, bytes: bytes)
            XCTAssertThrowsError(try MachineUpdateInstalledReleaseEpoch.Archive.decode(record: encoded,
                artifacts: tampered, candidate: candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
        }
    }

    func testCompletionPublicationProgressCannotSkipOrRewindAWrite() throws {
        try withCompletionFixture { fixture in
            let plan = try fixture.plan(fixture.recorded())
            let initial = try MachineUpdateCompletionPublicationRecord(plan: plan)
            let first = try XCTUnwrap(plan.entries.first)
            let bytes = try initial.encoded
            try MachineUpdateCompletionPublicationRecord.decode(bytes).requirePlan(plan)
            XCTAssertThrowsError(try MachineUpdateCompletionPublicationRecord.decode(bytes + Data([0x20]))) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            try initial.requireInventory(fixture.snapshot.source.replacement.inventory.canonicalBytes)
            XCTAssertThrowsError(try initial.requireInventory(plan.inventory.canonicalBytes)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            let second = try XCTUnwrap(plan.entries.dropFirst().first)
            XCTAssertThrowsError(try initial.advancing(accountID: second.accountID, file: second.file, to: .writing)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertThrowsError(try initial.advancingInventory(to: .writing)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertThrowsError(try initial.advancing(accountID: first.accountID, file: first.file, to: .published)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }

            var progress = initial
            for entry in plan.entries {
                progress = try progress.advancing(accountID: entry.accountID, file: entry.file, to: .writing)
                progress = try progress.advancing(accountID: entry.accountID, file: entry.file, to: .published)
            }
            XCTAssertThrowsError(try progress.advancing(accountID: first.accountID, file: first.file, to: .pending)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertTrue(progress.filesPublished)
            XCTAssertFalse(progress.complete)
            progress = try progress.advancingInventory(to: .writing)
            let sourceBytes = fixture.snapshot.source.replacement.inventory.canonicalBytes
            try progress.requireInventory(sourceBytes)
            try progress.requireInventory(plan.inventory.canonicalBytes)
            progress = try progress.advancingInventory(to: .published)
            XCTAssertTrue(progress.complete)
            XCTAssertThrowsError(try progress.requireInventory(sourceBytes)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testCompletionPublicationPinsRetainedOperandsAndPermitsOnlyExpectedBytes() throws {
        try withCompletionFixture { fixture in
            let archive = try fixture.recorded()
            let plan = try fixture.plan(archive)
            let retained = try MachineUpdateCompletionIntentArchive(record: .decode(archive.record.encoded),
                policies: archive.policies.map { try .decode($0.encoded) })
            let reconstructed = try fixture.plan(retained)
            XCTAssertEqual(try reconstructed.fingerprint, try plan.fingerprint)
            XCTAssertEqual(reconstructed.entries, plan.entries)

            let record = try MachineUpdateCompletionPublicationRecord(plan: plan)
            let other = try fixture.plan(fixture.recorded(revision: 248))
            XCTAssertThrowsError(try record.requirePlan(other)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            let entry = try XCTUnwrap(plan.entries.first(where: { $0.startup != $0.completion }))
            try entry.requireActual(entry.startup, state: .pending)
            try entry.requireActual(entry.startup, state: .writing)
            try entry.requireActual(entry.completion, state: .writing)
            try entry.requireActual(entry.completion, state: .published)
            for (bytes, state) in [(entry.completion, MachineUpdatePublicationProgress.State.pending),
                                   (Data([0]), .writing), (entry.startup, .published)] {
                XCTAssertThrowsError(try entry.requireActual(bytes, state: state)) {
                    XCTAssertEqual($0 as? InstalledAuthorityCommandError, .changedConfiguration)
                }
            }
        }
    }

    func testCompletionIntentRetainsOutsideInventoryAccountsAndRejectsForeignPolicyRows() throws {
        try withCompletionFixture { fixture in
            let archive = try fixture.intent(), policy = try XCTUnwrap(archive.policies.first)
            let bytes = try archive.record.encoded
            let original = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let originalRows = try XCTUnwrap(original["accounts"] as? [[String: Any]])
            let first = try XCTUnwrap(originalRows.first)
            let account = try XCTUnwrap(archive.record.accounts.first)
            var outsideID = Data(repeating: 250, count: 16)
            if outsideID == account.accountID { outsideID = Data(repeating: 251, count: 16) }
            let otherUID: UInt32 = account.ownerUID == 20010 ? 20011 : 20010
            let outside: [String: Any] = ["accountID": outsideID.base64EncodedString(), "ownerUID": otherUID,
                "sourceDigest": Data(repeating: 7, count: 32).base64EncodedString(), "inInventory": false]
            func record(_ rows: [[String: Any]]) throws -> MachineUpdateCompletionIntentRecord {
                var fields = original
                fields["accounts"] = rows
                return try MachineUpdateCompletionIntentRecord.decode(JSONSerialization.data(withJSONObject: fields,
                    options: [.sortedKeys, .withoutEscapingSlashes]))
            }
            let retained = try record(account.accountID.lexicographicallyPrecedes(outsideID) ? [first, outside] : [outside, first])
            let expanded = try MachineUpdateCompletionIntentArchive(record: retained, policies: [policy])
            XCTAssertEqual(expanded.record.accounts.count, 2)
            XCTAssertEqual(expanded.record.accounts.first(where: { !$0.inInventory })?.accountID, outsideID)

            var duplicateOwner = outside
            duplicateOwner["ownerUID"] = account.ownerUID
            let duplicateRows = account.accountID.lexicographicallyPrecedes(outsideID)
                ? [first, duplicateOwner] : [duplicateOwner, first]
            XCTAssertThrowsError(try record(duplicateRows)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            for (key, value) in [("policyRecordID", UUID().uuidString),
                                 ("policyRecordDigest", Data(repeating: 13, count: 32).base64EncodedString())] {
                var changed = first
                changed[key] = value
                let tampered = try record([changed])
                XCTAssertThrowsError(try MachineUpdateCompletionIntentArchive(record: tampered, policies: [policy])) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
            }
        }
    }

    func testCompletionIntentCannotDecodeAnArchiveWithTwoWritingAccounts() throws {
        try withCompletionFixture { fixture in
            let account = fixture.boundary.accountID
            let pending = try fixture.intent().preparingWrite(accountID: account, expected: fixture.boundary)
            let first = try XCTUnwrap(pending.policies.first)
            var policy = try XCTUnwrap(JSONSerialization.jsonObject(with: first.encoded) as? [String: Any])
            var binding = try XCTUnwrap(policy["binding"] as? [String: Any])
            let other = Data(repeating: account.first == 251 ? 250 : 251, count: 16)
            let identifier = UUID()
            binding["accountID"] = other.base64EncodedString()
            policy["binding"] = binding
            policy["id"] = identifier.uuidString
            let second = try MachineUpdatePolicyIntentRecord.decode(JSONSerialization.data(withJSONObject: policy,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            XCTAssertEqual(second.phase, .writing)
            var header = try XCTUnwrap(JSONSerialization.jsonObject(with: pending.record.encoded) as? [String: Any])
            let rows = try XCTUnwrap(header["accounts"] as? [[String: Any]])
            let original = try XCTUnwrap(rows.first)
            let owner = try XCTUnwrap(pending.record.accounts.first?.ownerUID)
            let added: [String: Any] = ["accountID": other.base64EncodedString(), "ownerUID": owner == 20010 ? 20011 : 20010,
                "sourceDigest": second.binding.sourceAccountDigest.base64EncodedString(), "inInventory": false,
                "policyRecordID": identifier.uuidString,
                "policyRecordDigest": try MachineUpdateActivationRecord.digest(second.encoded).base64EncodedString()]
            header["accounts"] = account.lexicographicallyPrecedes(other) ? [original, added] : [added, original]
            let record = try MachineUpdateCompletionIntentRecord.decode(JSONSerialization.data(withJSONObject: header,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            XCTAssertThrowsError(try MachineUpdateCompletionIntentArchive(record: record, policies: [first, second])) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testCompletionReconciliationRecordsAnUnchangedTargetOnlyWhenItIsTheSourcePolicy() throws {
        try withCompletionFixture { fixture in
            let archive = try fixture.intent(), first = try XCTUnwrap(archive.policies.first)
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: first.encoded) as? [String: Any])
            var binding = try XCTUnwrap(fields["binding"] as? [String: Any])
            let target = try fixture.boundary.policy.policy.bytes
            binding["completionPolicyDigest"] = MachineUpdateActivationRecord.digest(target).base64EncodedString()
            fields["completionPolicy"] = target.base64EncodedString()
            fields["binding"] = binding
            let noOp = try MachineUpdatePolicyIntentRecord.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            let writing = try noOp.preparingWrite(expected: fixture.boundary)
            guard case .recorded(let recorded) = try writing.reconciling(fixture.boundary) else {
                return XCTFail("An exact no-op did not record its retained boundary")
            }
            XCTAssertEqual(recorded.phase, .recorded)
            XCTAssertEqual(recorded.committedCheckpoint, try fixture.boundary.checkpoint.bytes)
        }
    }

    func testCompletionProfileClassifiesOnlyExactRetainedBoundaries() throws {
        try withCompletionFixture { fixture in
            let prepared = try fixture.intent(), source = fixture.boundary
            let writing = try prepared.preparingWrite(accountID: source.accountID, expected: source)
            let commit = try fixture.committedBoundary(for: writing)
            let recorded = try writing.recordingRecoveredBoundary(commit)
            let digest = fixture.snapshot.backend.record.currentSourceDigest
            func snapshot(_ intent: MachineUpdateCompletionIntentArchive) -> MachineUpdateCompletionSnapshot {
                .init(restart: fixture.snapshot, intent: intent)
            }
            func classify(_ intent: MachineUpdateCompletionIntentArchive, _ boundary: AuthorityJournal.MachineUpdatePolicyBoundary)
                throws -> MachineUpdateCompletionPolicyProfile.State {
                let profile = try MachineUpdateCompletionPolicyProfile(snapshot: snapshot(intent),
                    candidate: fixture.candidate, currentSourceDigest: digest)
                let accounts = try profile.requireBoundaries([boundary])
                return try XCTUnwrap(accounts.first).state
            }
            XCTAssertEqual(try classify(prepared, source), .prepared)
            XCTAssertEqual(try classify(writing, source), .unresolvedSource)
            XCTAssertEqual(try classify(writing, commit), .unrecordedCommit)
            XCTAssertEqual(try classify(recorded, commit), .recorded)

            let wrongPolicy = AuthorityJournal.MachineUpdatePolicyBoundary(macID: commit.macID, accountID: commit.accountID,
                policy: source.policy, checkpoint: commit.checkpoint)
            let wrongCheckpoint = AuthorityJournal.MachineUpdatePolicyBoundary(macID: commit.macID, accountID: commit.accountID,
                policy: commit.policy, checkpoint: source.checkpoint)
            let wrongMac = AuthorityJournal.MachineUpdatePolicyBoundary(macID: Data(repeating: 200, count: 16), accountID: commit.accountID,
                policy: commit.policy, checkpoint: commit.checkpoint)
            let unknownAccount = AuthorityJournal.MachineUpdatePolicyBoundary(macID: commit.macID, accountID: Data(repeating: 200, count: 16),
                policy: commit.policy, checkpoint: commit.checkpoint)
            for (intent, boundary) in [(prepared, commit), (writing, wrongCheckpoint), (recorded, wrongPolicy),
                                       (recorded, wrongCheckpoint), (recorded, wrongMac), (recorded, unknownAccount)] {
                XCTAssertThrowsError(try classify(intent, boundary)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
            XCTAssertThrowsError(try MachineUpdateCompletionPolicyProfile(snapshot: snapshot(prepared),
                candidate: fixture.candidate, currentSourceDigest: Data(repeating: 199, count: 32))) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testCompletionProfileRefusesDuplicateAndPartiallyRecordedTwoAccountSets() throws {
        try withCompletionFixture { fixture in
            let prepared = try fixture.intent(), first = try XCTUnwrap(prepared.policies.first)
            let writing = try prepared.preparingWrite(accountID: first.binding.accountID, expected: fixture.boundary)
            let committed = try fixture.committedBoundary(for: writing)
            let recorded = try writing.recordingRecoveredBoundary(committed)
            let other = Data(repeating: first.binding.accountID.first == 250 ? 251 : 250, count: 16)
            let id = UUID()
            var row = try XCTUnwrap(JSONSerialization.jsonObject(with: first.encoded) as? [String: Any])
            var binding = try XCTUnwrap(row["binding"] as? [String: Any])
            binding["accountID"] = other.base64EncodedString()
            row["binding"] = binding
            row["id"] = id.uuidString
            let otherPolicy = try MachineUpdatePolicyIntentRecord.decode(JSONSerialization.data(withJSONObject: row,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            var header = try XCTUnwrap(JSONSerialization.jsonObject(with: recorded.record.encoded) as? [String: Any])
            let rows = try XCTUnwrap(header["accounts"] as? [[String: Any]])
            let original = try XCTUnwrap(rows.first)
            let owner = try XCTUnwrap(recorded.record.accounts.first?.ownerUID)
            let added: [String: Any] = ["accountID": other.base64EncodedString(), "ownerUID": owner == 20010 ? 20011 : 20010,
                "sourceDigest": otherPolicy.binding.sourceAccountDigest.base64EncodedString(), "inInventory": false,
                "policyRecordID": id.uuidString,
                "policyRecordDigest": try MachineUpdateActivationRecord.digest(otherPolicy.encoded).base64EncodedString()]
            header["accounts"] = first.binding.accountID.lexicographicallyPrecedes(other) ? [original, added] : [added, original]
            let record = try MachineUpdateCompletionIntentRecord.decode(JSONSerialization.data(withJSONObject: header,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            let archive = try MachineUpdateCompletionIntentArchive(record: record, policies: recorded.policies + [otherPolicy])
            let profile = try MachineUpdateCompletionPolicyProfile(archive: archive)
            let otherSource = AuthorityJournal.MachineUpdatePolicyBoundary(macID: fixture.boundary.macID, accountID: other,
                policy: fixture.boundary.policy, checkpoint: fixture.boundary.checkpoint)
            XCTAssertEqual(try profile.requireBoundaries([committed, otherSource]).first(where: { $0.accountID == other })?.state, .prepared)
            XCTAssertThrowsError(try profile.requireBoundaries([committed, committed])) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try profile.requireRecorded([committed, otherSource])) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            let unresolved = try archive.preparingWrite(accountID: other, expected: otherSource)
            let unresolvedProfile = try MachineUpdateCompletionPolicyProfile(archive: unresolved)
            XCTAssertEqual(try unresolvedProfile.requireBoundaries([committed, otherSource]).first(where: {
                $0.accountID == other
            })?.state, .unresolvedSource)
            XCTAssertThrowsError(try unresolvedProfile.requireRecorded([committed, otherSource])) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
        }
    }

    func testCompletionPublicationSnapshotPinsItsIntentAndPlan() throws {
        try withCompletionFixture { fixture in
            let recorded = try fixture.recorded()
            let completion = MachineUpdateCompletionSnapshot(restart: fixture.snapshot, intent: recorded)
            let plan = try fixture.plan(recorded)
            let progress = try MachineUpdateCompletionPublicationRecord(plan: plan)
            let pending = try MachineUpdateCompletionPublicationSnapshot(completion: completion, publication: nil,
                candidate: fixture.candidate)
            let retained = try MachineUpdateCompletionPublicationSnapshot(completion: completion, publication: progress,
                candidate: fixture.candidate)
            try retained.requireSame(as: retained)
            XCTAssertThrowsError(try retained.requireSame(as: pending)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            let otherIntent = try fixture.recorded(revision: 248)
            let other = MachineUpdateCompletionSnapshot(restart: fixture.snapshot, intent: otherIntent)
            XCTAssertThrowsError(try completion.requireSame(as: other)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try MachineUpdateCompletionPublicationSnapshot(completion: other, publication: progress,
                candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: progress.encoded) as? [String: Any])
            fields["planFingerprint"] = Data(repeating: 97, count: 32).base64EncodedString()
            let changed = try MachineUpdateCompletionPublicationRecord.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            XCTAssertThrowsError(try MachineUpdateCompletionPublicationSnapshot(completion: completion, publication: changed,
                candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try withCompletionFixture { different in
                let foreign = MachineUpdateCompletionSnapshot(restart: different.snapshot, intent: recorded)
                XCTAssertThrowsError(try completion.requireSame(as: foreign)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertThrowsError(try MachineUpdateCompletionPublicationPlan(snapshot: foreign, candidate: different.candidate,
                    currentSourceDigest: fixture.snapshot.backend.record.currentSourceDigest, boundaries: [])) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
        }
    }

    func testCompletionPublicationRequiresFreshRecordedPolicyBoundaries() throws {
        try withCompletionFixture { fixture in
            let source = fixture.boundary, digest = fixture.snapshot.backend.record.currentSourceDigest
            let prepared = try fixture.intent()
            let pending = try prepared.preparingWrite(accountID: source.accountID, expected: source)
            let committed = try fixture.committedBoundary(for: pending)
            let recorded = try pending.recordingRecoveredBoundary(committed)
            func build(_ intent: MachineUpdateCompletionIntentArchive, _ facts: [AuthorityJournal.MachineUpdatePolicyBoundary],
                       digest: Data) throws -> MachineUpdateCompletionPublicationPlan {
                let snapshot = MachineUpdateCompletionSnapshot(restart: fixture.snapshot, intent: intent)
                return try .init(snapshot: snapshot, candidate: fixture.candidate, currentSourceDigest: digest, boundaries: facts)
            }
            let plan = try build(recorded, [committed], digest: digest)
            XCTAssertEqual(try plan.fingerprint, try fixture.plan(recorded).fingerprint)
            for (intent, boundary) in [(prepared, source), (pending, source), (pending, committed)] {
                XCTAssertThrowsError(try build(intent, [boundary], digest: digest)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                }
            }
            XCTAssertThrowsError(try build(recorded, [source], digest: digest)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try build(recorded, [], digest: digest)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try build(recorded, [committed], digest: Data(repeating: 211, count: 32))) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testCompletionPublicationRecordsReadinessJobInVersionTwo() throws {
        try withCompletionFixture(installedReadiness: true) { fixture in
            let plan = try fixture.plan(fixture.recorded())
            let job = try XCTUnwrap(plan.entries.first(where: { $0.file == .authorityJob }))
            let account = try XCTUnwrap(fixture.snapshot.configuration.configuration(accountID: job.accountID))
            XCTAssertFalse(account.startup.host.installedReadinessEnabled)
            XCTAssertTrue(account.completion.host.installedReadinessEnabled)
            XCTAssertNotEqual(job.startup, job.completion)
            let record = try MachineUpdateCompletionPublicationRecord(plan: plan)
            XCTAssertEqual(record.formatVersion, 2)
            try MachineUpdateCompletionPublicationRecord.decode(record.encoded).requirePlan(plan)
            let formats = try MachineUpdateCompletionPublicationRecord.requirements.filter {
                $0.name == MachineUpdateCompletionPublicationRecord.formatName
            }
            XCTAssertEqual(formats.count, 2)
            for format in formats {
                XCTAssertEqual(format.readVersions, [1, 2])
                XCTAssertEqual(format.writeVersions, [1, 2])
            }
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: record.encoded) as? [String: Any])
            fields["formatVersion"] = 1
            XCTAssertThrowsError(try MachineUpdateCompletionPublicationRecord.decode(JSONSerialization.data(
                withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testCompletionReconciliationRefusesForeignPolicyAndCheckpointChanges() throws {
        try withCompletionFixture { fixture in
            let source = fixture.boundary
            let pending = try fixture.intent().preparingWrite(accountID: source.accountID, expected: source)
            let valid = try fixture.committedBoundary(for: pending)
            let checkpoint = valid.checkpoint
            let foreignPolicy = AuthorityCodePolicySnapshot(revision: UUID(), policy: source.policy.policy,
                roleRevisions: source.policy.roleRevisions)
            let staleRoles = AuthorityCodePolicySnapshot(revision: valid.policy.revision, policy: valid.policy.policy,
                roleRevisions: source.policy.roleRevisions)
            for policy in [foreignPolicy, staleRoles] {
                let wrong = AuthorityJournal.MachineUpdatePolicyBoundary(macID: valid.macID, accountID: valid.accountID,
                    policy: policy, checkpoint: checkpoint)
                XCTAssertThrowsError(try pending.recordingRecoveredBoundary(wrong)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
            }
            let authority = checkpoint.currentAuthorityGeneration
            let cases = [
                (checkpoint.generation + 1, authority, checkpoint.journalEpoch, checkpoint.journalHead),
                (checkpoint.generation, authority + 1, checkpoint.journalEpoch, checkpoint.journalHead),
                (checkpoint.generation, authority, Data(repeating: 99, count: 16), checkpoint.journalHead),
                (checkpoint.generation, authority, checkpoint.journalEpoch, checkpoint.journalHead + 1)
            ]
            for (generation, authorityGeneration, epoch, head) in cases {
                let wrong = try AuthorityJournal.MachineUpdatePolicyBoundary(macID: valid.macID, accountID: valid.accountID,
                    policy: valid.policy, checkpoint: .init(generation: generation, authorityDigest: checkpoint.authorityDigest,
                        ledgerDigest: checkpoint.ledgerDigest, journalEpoch: epoch, journalHead: head,
                        authorityGeneration: authorityGeneration))
                XCTAssertThrowsError(try pending.recordingRecoveredBoundary(wrong)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
            }
            XCTAssertTrue(try pending.recordingRecoveredBoundary(valid).policyMarkersRecorded)
        }
    }

    func testRestartHealthPlanRejectsACandidateWithoutTheSelectedConsumerFormat() throws {
        let f = try Fixture(backendEpoch: true, beforeActivation: { files in
            try files.machine.store.markRuntimeJobsRegistered(files.machine.f.plan)
        })
        let (source, restart) = try restartWithRetainedBackend(f, complete: true)
        defer { restart.close() }
        let snapshot = try f.machine.store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let components = try f.newRelease.manifest.components.map { component in
            guard component.role == .transport else { return component }
            return try ReleaseComponent(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                teamID: component.teamID, formats: component.formats.filter { $0.name != MachineUpdateConsumerHealthReleaseValidation.formatName },
                requests: component.requests)
        }
        let manifest = try ReleaseManifest(release: f.newRelease.manifest.release,
            build: f.newRelease.manifest.build, components: components)
        let missing = SignedReleaseEvidence(manifest: manifest, codeDirectoryHashes: f.newRelease.codeDirectoryHashes)
        let current = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: f.newRelease)
        let (selected, _) = try current.select(accountID: f.machine.account, role: .transport)
        XCTAssertThrowsError(try MachineUpdateConsumerHealthReleaseValidation.validateDeclarations(missing,
            policy: selected.configuration.host.codePolicy, consumer: .transport)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
        // Changing a signed declaration also changes the release identity retained by the restart snapshot.
        XCTAssertThrowsError(try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: missing)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testRestartHealthPreservesAnUnregisteredAccount() throws {
        var reserved: Data?
        let f = try Fixture(backendEpoch: true, beforeActivation: { files in
            reserved = try self.reserveRestartAccount(files).accountID
        })
        let (source, restart) = try restartWithRetainedBackend(f, complete: true)
        defer { restart.close() }
        let snapshot = try f.machine.store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let plan = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: f.newRelease)
        let account = try XCTUnwrap(reserved)
        XCTAssertTrue(plan.preservedAccounts.contains(account))
        XCTAssertFalse(plan.requirements.contains { $0.binding.accountID == account })
        XCTAssertThrowsError(try plan.select(accountID: account, role: .authority))
    }

    func testRestartHealthSelectsTheRegisteredGatewayFromTheRetainedBackend() throws {
        let (f, setup) = try populatedBackendFixture()
        let published = try publishFixtureConfigurationEpoch(f, retainFixtureConfigurationEpoch(f))
        let store = f.machine.store, account = f.machine.account
        let activation = try XCTUnwrap(store.gatewayRuntimeActivation(accountID: account).plan)
        let capture = try fixtureBackendCapture(f, foreground: setup.runtime.plan, activation: activation, journal: setup.state())
        let initial = try store.upgradeMachineUpdateBackendEpochStorage(expected: published,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        let retained = try store.retainMachineUpdateBackendEpoch(initial, captures: [capture], candidate: f.newRelease,
            directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        func advance(_ previous: MachineUpdateBackendEpochRecord, _ operation: MachineUpdateBackendPublicationOperation)
            throws -> MachineUpdateBackendEpochRecord {
            try store.advanceMachineUpdateBackendPublication(previous, operation: operation, candidate: f.newRelease,
                directory: f.directory, quiescence: f.quiet, verifyCurrent: { _ in })
        }
        var record = try advance(retained, .begin)
        for file in MachineUpdateBackendPublicationProgress.File.allCases {
            record = try advance(record, .prepare(account, file))
            record = try advance(record, .complete(account, file))
        }
        let restart = try f.quiet.releaseActivityForRestart()
        defer { restart.close() }
        let checking = try store.markMachineUpdateRestartChecking(f.activation, directory: f.directory,
            restart: restart, verifyCurrent: {})
        let source = try store.machineUpdateRestartSource(checking, directory: f.directory)
        let snapshot = try store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let plan = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: f.newRelease)
        XCTAssertEqual(plan.requirements.map(\.role), [.authority, .transport, .notificationGateway])
        let (selected, gateway) = try plan.select(accountID: account, role: .notificationGateway)
        let startup = try XCTUnwrap(capture.startup)
        XCTAssertEqual(try selected.backend?.encoded, try startup.encoded)
        XCTAssertEqual(gateway.executionUID, startup.gateway.serviceUID)
        XCTAssertEqual(gateway.publicKey, startup.gateway.receiptPublicKey)
        XCTAssertEqual(gateway.backendRevision, record.revision)
        let gatewayInput = try MachineUpdateNativeRestartHealth.consumerInputs(account: selected, requirement: gateway)
        XCTAssertEqual(gatewayInput.host, selected.configuration.gateway)
        XCTAssertEqual(gatewayInput.registration, startup.gateway.registration)
        let (_, transport) = try plan.select(accountID: account, role: .transport)
        let transportInput = try MachineUpdateNativeRestartHealth.consumerInputs(account: selected, requirement: transport)
        XCTAssertEqual(transportInput.host, selected.configuration.transport.settingsHost)
        XCTAssertNil(transportInput.registration)
        let (_, authority) = try plan.select(accountID: account, role: .authority)
        XCTAssertThrowsError(try MachineUpdateNativeRestartHealth.consumerInputs(account: selected, requirement: authority)) {
            XCTAssertEqual($0 as? MachineUpdateHealthCoordinatorError, .invalidInventory)
        }
        let selection = try MachineUpdateAuthorityHealthOwner.RestartSelection(snapshot: snapshot, candidate: f.newRelease,
            accountID: account)
        XCTAssertEqual(selection.gateway?.requirement, gateway)
        XCTAssertEqual(selection.gateway?.registration, startup.gateway.registration)
        XCTAssertNotNil(selection.gatewayPolicy)
        XCTAssertThrowsError(try MachineUpdateGatewayPairedHealthReader.RestartSelection(snapshot: snapshot,
            candidate: f.newRelease, accountID: account)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testHealthInventoryRejectsDuplicateRolesAndSplitForegroundPairs() throws {
        let f = try Fixture(backendEpoch: true, beforeActivation: { files in
            try files.machine.store.markRuntimeJobsRegistered(files.machine.f.plan)
        })
        let (source, restart) = try restartWithRetainedBackend(f, complete: true)
        defer { restart.close() }
        let snapshot = try f.machine.store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let plan = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: f.newRelease)
        let account = f.machine.account
        let (_, authority) = try plan.select(accountID: account, role: .authority)
        let (_, transport) = try plan.select(accountID: account, role: .transport)
        let preserved = Data(repeating: 91, count: 16)
        let inventory = try MachineUpdateHealthInventory(requirements: [transport, authority], preservedAccounts: [preserved])
        XCTAssertEqual(inventory.accountIDs, [account])
        XCTAssertEqual(inventory.requirements(accountID: account), [authority, transport])
        XCTAssertEqual(inventory.preservedAccounts, [preserved])
        for (requirements, preservedAccounts) in [
            ([authority], []), ([authority, transport, authority], []), ([authority, transport], [account]),
        ] {
            XCTAssertThrowsError(try MachineUpdateHealthInventory(requirements: requirements, preservedAccounts: preservedAccounts)) {
                XCTAssertEqual($0 as? MachineUpdateHealthCoordinatorError, .invalidInventory)
            }
        }
    }

    func testHealthInventoryRejectsMixedEpochRevisions() throws {
        let f = try Fixture(backendEpoch: true, beforeActivation: { files in
            try files.machine.store.markRuntimeJobsRegistered(files.machine.f.plan)
        })
        let (source, restart) = try restartWithRetainedBackend(f, complete: true)
        defer { restart.close() }
        let snapshot = try f.machine.store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let plan = try MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: f.newRelease)
        let (_, authority) = try plan.select(accountID: f.machine.account, role: .authority)
        let (_, transport) = try plan.select(accountID: f.machine.account, role: .transport)
        let changed = MachineUpdateRestartHealthPlan.Requirement(binding: transport.binding,
            configurationEpoch: transport.configurationEpoch, configurationRevision: transport.configurationRevision,
            backendEpoch: transport.backendEpoch, backendRevision: UUID(), role: transport.role,
            executionUID: transport.executionUID, code: transport.code, publicKey: transport.publicKey)
        XCTAssertThrowsError(try MachineUpdateHealthInventory(requirements: [authority, changed], preservedAccounts: [])) {
            XCTAssertEqual($0 as? MachineUpdateHealthCoordinatorError, .invalidInventory)
        }
    }

    func testHealthSourceBorrowPreventsReentryAndClearsAfterAnError() throws {
        let f = try Fixture(backendEpoch: true)
        let (source, restart) = try restartWithRetainedBackend(f, complete: true)
        defer { restart.close() }
        let store = f.machine.store
        let snapshot = try store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        let access = MachineUpdateHealthSourceAccess()
        var freshReads = 0
        func fresh() throws -> MachineUpdateRestartSnapshot {
            freshReads += 1
            return try store.machineUpdateRestartSnapshot(expected: source, directory: f.directory, restart: restart)
        }
        try access.requireCurrent(snapshot, read: fresh)
        XCTAssertEqual(freshReads, 1)
        try store.withCurrentMachineUpdateRestartSnapshot(snapshot, directory: f.directory, restart: restart) { scope in
            XCTAssertThrowsError(try access.withScope(scope, expected: snapshot) {
                try access.requireCurrent(snapshot, read: fresh)
                XCTAssertEqual(freshReads, 1)
                XCTAssertThrowsError(try access.withScope(scope, expected: snapshot) {}) {
                    XCTAssertEqual($0 as? MachineUpdateHealthCoordinatorError, .busy)
                }
                throw ReplacementFixtureError.injected
            }) { XCTAssertTrue($0 is ReplacementFixtureError) }
            try access.withScope(scope, expected: snapshot) {
                try access.requireCurrent(snapshot, read: fresh)
            }
        }
        try access.requireCurrent(snapshot, read: fresh)
        XCTAssertEqual(freshReads, 2)
    }

    func testHealthSourceRefusesCrossThreadBorrowAndRecoversAfterItEnds() throws {
        let f = try Fixture(backendEpoch: true)
        let (source, restart) = try restartWithRetainedBackend(f, complete: true); defer { restart.close() }
        let store = f.machine.store, directory = f.directory
        let snapshot = try store.machineUpdateRestartSnapshot(expected: source, directory: directory, restart: restart)
        let shared = SharedRestartSnapshot(value: snapshot), access = MachineUpdateHealthSourceAccess()
        let finished = DispatchSemaphore(value: 0)
        try store.withCurrentMachineUpdateRestartSnapshot(snapshot, directory: directory, restart: restart) { scope in
            try access.withScope(scope, expected: snapshot) {
                DispatchQueue.global().async {
                    defer { finished.signal() }
                    do {
                        try access.requireCurrent(shared.value, read: {
                            XCTFail("The off-thread reader attempted to enter the open transaction")
                            throw ReplacementFixtureError.injected
                        })
                        XCTFail("The off-thread reader accepted the borrowed scope")
                    } catch {
                        XCTAssertEqual(error as? MachineUpdateHealthSourceError, .busy)
                    }
                }
                XCTAssertEqual(finished.wait(timeout: .now() + .seconds(5)), .success)
                try access.requireCurrent(snapshot, read: { throw ReplacementFixtureError.injected })
            }
        }
        XCTAssertThrowsError(try access.requireCurrent(snapshot, read: { throw UpdateAdmissionBarrierError.busy })) {
            XCTAssertEqual($0 as? MachineUpdateHealthSourceError, .busy)
        }
        XCTAssertThrowsError(try access.requireCurrent(snapshot, read: { throw PreparationStoreError.transactionActive })) {
            XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
        }
        try access.requireCurrent(snapshot, read: {
            try store.machineUpdateRestartSnapshot(expected: source, directory: directory, restart: restart)
        })
    }

    func testHealthSnapshotUsesTheOriginalReadinessLoan() throws {
        let f = try Fixture(backendEpoch: true)
        let (source, restart) = try restartWithRetainedBackend(f, complete: true)
        defer { restart.close() }
        let store = f.machine.store, directory = f.directory
        let snapshot = try store.machineUpdateRestartSnapshot(expected: source, directory: directory, restart: restart)
        let activation = source.replacement.activation
        let access = try MachineUpdateRestartSharedActivity(restart: restart, activity: f.files.activity(), directory: directory,
            expectedMachine: source.replacement.admission.machine, macID: activation.macID,
            installationID: activation.installationID, activationAttempt: activation.attemptID)
        defer { access.close() }
        let loan = try access.acquireShared(); defer { loan.close() }
        XCTAssertThrowsError(try store.machineUpdateRestartSnapshot(expected: source, directory: directory, restart: restart)) {
            XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
        }
        let fresh = try store.machineUpdateRestartSnapshot(expected: source, directory: directory, readiness: loan)
        try fresh.requireSame(as: snapshot)
        let borrowed = MachineUpdateHealthSourceAccess()
        let scope = try store.withCurrentMachineUpdateRestartSnapshot(snapshot, directory: directory, readiness: loan) { scope in
            try borrowed.withScope(scope, expected: snapshot) {
                try borrowed.requireCurrent(snapshot) {
                    XCTFail("A callback must use the existing machine snapshot")
                    throw ReplacementFixtureError.injected
                }
            }
            return scope
        }
        XCTAssertThrowsError(try scope.read())
        access.close()
        XCTAssertThrowsError(try store.machineUpdateRestartSnapshot(expected: source, directory: directory, readiness: loan))
    }

    func testReleaseBoundGatewayCommitStaysOutOfOrdinaryReader() throws {
        let f = try Fixture(); _ = try f.run()
        let binding = try releaseBinding(f, source: restartSource(f), policy: releasePolicySnapshot(f))
        let digest = Data(repeating: 3, count: 32)
        var fields: [UInt64: CBORValue] = [0: .unsigned(1), 1: .text("remozio-gateway-runtime-commit"),
            2: .bytes(f.machine.account), 3: .bytes(digest), 4: .bytes(digest), 5: .bytes(digest),
            6: .bytes(digest), 7: .bytes(digest)]
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 1, maxItems: 33)
        let original = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertEqual(try GatewayRuntimeCommit.decode(original).encoded, original)
        fields[0] = .unsigned(3)
        fields[8] = .null; fields[9] = .null; fields[10] = .bytes(digest); fields[11] = .null
        fields[12] = .bytes(try binding.encoded); fields[13] = .unsigned(RuntimeReleasePolicyStage.startup.rawValue)
        fields[14] = .bytes(original); fields[15] = .bytes(digest)
        let bytes = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertThrowsError(try GatewayRuntimeCommit.decode(bytes))
        let commit = try GatewayRuntimeCommit.decodeForReleaseArchive(bytes)
        try commit.requireRelease(binding: binding, stage: .startup)
        XCTAssertThrowsError(try commit.requireRelease(binding: binding, stage: .completion))
        XCTAssertEqual(try commit.encoded, bytes)
    }

    func testReleaseBindingKeepsHistoricalMaterialSeparateFromTheInstalledRelease() throws {
        let f = try Fixture(); _ = try f.run(); let source = try restartSource(f), policy = releasePolicySnapshot(f)
        let before = try f.machine.store.retainedRuntimeCompatibilityInputs(), reference = source.replacement.runtime.runtimes[0].reference
        let bytes = try reference.encoded, value = try releaseBinding(f, source: source, policy: policy)
        XCTAssertEqual(value.previousInstalledReleaseDigest, source.replacement.inventory.releaseDigest)
        XCTAssertEqual(value.installedReleaseDigest, try InstallationInventory.digest(f.newRelease))
        XCTAssertNotEqual(value.installedReleaseDigest, value.previousInstalledReleaseDigest)
        XCTAssertEqual(try reference.encoded, bytes); XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs(), before)
    }

    func testReleaseBindingPinsTheAccountAttemptCandidateAndAdmission() throws {
        let f = try Fixture(); _ = try f.run(); let source = try restartSource(f)
        let value = try releaseBinding(f, source: source, policy: releasePolicySnapshot(f))
        XCTAssertEqual(value.accountID, f.machine.account); XCTAssertEqual(value.macID, f.activation.macID)
        XCTAssertEqual(value.installationID, f.activation.installationID); XCTAssertEqual(value.activationAttempt, f.activation.attemptID)
        XCTAssertEqual(value.candidateDigest, f.activation.candidateDigest); XCTAssertEqual(value.sourceInventoryDigest, f.activation.inventoryDigest)
        XCTAssertEqual(value.admissionDigest, f.activation.admissionDigest); XCTAssertEqual(value.updateID, f.activation.updateID)
    }

    func testReleaseBindingIsDeterministicForTheSameRetainedSource() throws {
        let f = try Fixture(); _ = try f.run(); let source = try restartSource(f), policy = releasePolicySnapshot(f)
        let first = try releaseBinding(f, source: source, policy: policy), second = try releaseBinding(f, source: source, policy: policy)
        XCTAssertEqual(first, second); XCTAssertEqual(try first.encoded, try second.encoded)
        XCTAssertEqual(try RuntimeReleaseBinding.decode(first.encoded), first)
    }

    func testReleaseBindingRejectsAnAccountWithoutARetainedRuntime() throws {
        var reserved: AccountPreparationIntent?
        let f = try Fixture(beforeActivation: { reserved = try self.reserveRestartAccount($0) })
        _ = try f.run(); let source = try restartSource(f), pending = try XCTUnwrap(reserved)
        XCTAssertTrue(source.accounts.contains { $0.accountID == pending.accountID })
        XCTAssertThrowsError(try RuntimeReleaseBinding(accountID: pending.accountID, source: source, candidate: f.newRelease,
            policy: MachineUpdatePolicyPlan(source: releasePolicySnapshot(f), candidate: f.newRelease))) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testReleaseBindingRejectsAnUnrelatedAccountEvenWithTheSamePolicy() throws {
        let f = try Fixture(), other = try Fixture(); _ = try f.run(); let source = try restartSource(f)
        XCTAssertThrowsError(try RuntimeReleaseBinding(accountID: other.machine.account, source: source, candidate: f.newRelease,
            policy: MachineUpdatePolicyPlan(source: releasePolicySnapshot(f), candidate: f.newRelease))) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testReleaseBindingRejectsAnObservedReplacementFromAnotherAttempt() throws {
        let f = try Fixture(), other = try Fixture(); _ = try f.run(); _ = try other.run()
        let source = try restartSource(f), foreign = try XCTUnwrap(restartSource(other).replacement.replacement)
        XCTAssertEqual(foreign.phase, .observed); XCTAssertNotEqual(foreign.activationAttempt, f.activation.attemptID)
        let context = source.replacement
        let forged = MachineUpdateRestartSource(replacement: .init(activation: context.activation, inventory: context.inventory,
            candidate: context.candidate, admission: context.admission, replacement: foreign, runtime: context.runtime),
            accounts: source.accounts, provisioningHistory: source.provisioningHistory)
        let policy = releasePolicySnapshot(f)
        XCTAssertNoThrow(try releaseBinding(f, source: source, policy: policy))
        XCTAssertThrowsError(try releaseBinding(f, source: forged, policy: policy)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        let binding = try releaseBinding(f, source: source, policy: policy)
        XCTAssertThrowsError(try binding.requireSourceForPublication(forged, currentPolicy: policy, candidate: f.newRelease)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testReleaseBindingRejectsAChangedPolicyRevisionBeforePublication() throws {
        let f = try Fixture(); _ = try f.run(); let source = try restartSource(f), policy = releasePolicySnapshot(f)
        let value = try releaseBinding(f, source: source, policy: policy)
        let changed = AuthorityCodePolicySnapshot(revision: UUID(), policy: policy.policy, roleRevisions: policy.roleRevisions)
        XCTAssertThrowsError(try value.requireSourceForPublication(source, currentPolicy: changed, candidate: f.newRelease)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testReleaseBindingRejectsAChangedRoleTokenBeforePublication() throws {
        let f = try Fixture(); _ = try f.run(); let source = try restartSource(f), policy = releasePolicySnapshot(f)
        let value = try releaseBinding(f, source: source, policy: policy); var tokens = policy.roleRevisions; tokens[.authority] = UUID()
        let changed = AuthorityCodePolicySnapshot(revision: policy.revision, policy: policy.policy, roleRevisions: tokens)
        XCTAssertThrowsError(try value.requireSourceForPublication(source, currentPolicy: changed, candidate: f.newRelease)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testReleaseBindingRejectsADifferentFreshSignedRelease() throws {
        let f = try Fixture(); _ = try f.run(); let source = try restartSource(f), policy = releasePolicySnapshot(f)
        let value = try releaseBinding(f, source: source, policy: policy)
        XCTAssertThrowsError(try value.requireSourceForPublication(source, currentPolicy: policy, candidate: f.oldRelease)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testReleaseBindingRejectsAChangedHistoricalAccountOwner() throws {
        let f = try Fixture(); _ = try f.run(); let source = try restartSource(f), policy = releasePolicySnapshot(f)
        let value = try releaseBinding(f, source: source, policy: policy)
        let changed = MachineUpdateRestartSource(replacement: source.replacement, accounts: source.accounts.map {
            .init(accountID: $0.accountID, ownerUID: $0.ownerUID + 1, preparation: $0.preparation,
                initialization: $0.initialization, services: $0.services, servicesComplete: $0.servicesComplete)
        })
        XCTAssertThrowsError(try value.requireSourceForPublication(changed, currentPolicy: policy, candidate: f.newRelease)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }

    func testReleaseBindingRequiresAcknowledgedReplacementRecovery() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .immediatelyAfterExchange { throw ReplacementFixtureError.injected } }))
        let source = try restartSource(f); XCTAssertEqual(source.replacement.replacement?.phase, .prepared)
        XCTAssertThrowsError(try releaseBinding(f, source: source, policy: releasePolicySnapshot(f))) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        try f.assertAfter()
    }

    func testReleaseBindingKeepsItsSourceAcrossTheLegalRestartPhaseTransition() throws {
        let f = try Fixture(); _ = try f.run(); let source = try restartSource(f), policy = releasePolicySnapshot(f)
        let value = try releaseBinding(f, source: source, policy: policy)
        let restart = try f.quiet.releaseActivityForRestart(); defer { restart.close() }
        let checking = try f.machine.store.markMachineUpdateRestartChecking(f.activation, directory: f.directory,
            restart: restart, verifyCurrent: {})
        let current = try f.machine.store.machineUpdateRestartSource(checking, directory: f.directory)
        XCTAssertNoThrow(try value.requireSourceForPublication(current, currentPolicy: policy, candidate: f.newRelease))
    }

    func testReleaseBindingSeparatesStartupPolicyFromTheCompletionFloor() throws {
        let f = try Fixture(); _ = try f.run(); let source = try restartSource(f), policy = releasePolicySnapshot(f)
        let plan = try MachineUpdatePolicyPlan(source: policy, candidate: f.newRelease)
        let value = try releaseBinding(f, source: source, policy: policy)
        XCTAssertNoThrow(try value.requireStartupPolicy(plan.startupPolicy))
        XCTAssertNoThrow(try value.requireCompletionPolicy(plan.completionPolicy))
        XCTAssertThrowsError(try value.requireStartupPolicy(plan.completionPolicy))
        XCTAssertThrowsError(try value.requireCompletionPolicy(plan.startupPolicy))
    }

    func testReleaseBindingRejectsNoncanonicalAndOversizedRecords() throws {
        let f = try Fixture(); _ = try f.run(); let value = try releaseBinding(f, source: restartSource(f), policy: releasePolicySnapshot(f))
        XCTAssertThrowsError(try RuntimeReleaseBinding.decode(value.encoded + Data([0x20])))
        XCTAssertThrowsError(try RuntimeReleaseBinding.decode(Data(repeating: 0, count: RuntimeReleaseBinding.maximumBytes + 1)))
    }

    func testReleaseBindingRejectsAnAlteredIdentityLength() throws {
        let f = try Fixture(); _ = try f.run(); let value = try releaseBinding(f, source: restartSource(f), policy: releasePolicySnapshot(f))
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: value.encoded) as? [String: Any])
        fields["accountID"] = Data(repeating: 1, count: 15).base64EncodedString()
        let bytes = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
        XCTAssertThrowsError(try RuntimeReleaseBinding.decode(bytes))
    }

    func testReleaseBindingDescriptionsRedactItsRetainedScope() throws {
        let f = try Fixture(); _ = try f.run(); let value = try releaseBinding(f, source: restartSource(f), policy: releasePolicySnapshot(f))
        XCTAssertEqual(value.description, "RuntimeReleaseBinding(redacted)"); XCTAssertEqual(value.debugDescription, value.description)
    }

}
