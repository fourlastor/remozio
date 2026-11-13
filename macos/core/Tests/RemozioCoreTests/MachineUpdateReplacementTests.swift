import CryptoKit
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
    let readinessAlreadyEnabled: Bool
    let enableSecondReadiness: Bool
    var quiet: UpdateQuiescenceLease
    let oldIdentity: PreparationFileIdentity
    let newIdentity: PreparationFileIdentity
    var oldURL: URL { URL(fileURLWithPath: installed.path).appendingPathComponent("Remozio.app") }
    var preparedURL: URL { URL(fileURLWithPath: machine.destination.path).appendingPathComponent(candidate.preparation.bundleName) }
    init(configurationEpoch: Bool = false, backendEpoch: Bool = false, installedReadiness: Bool = false,
         completionIntent: Bool = false, admitEveryAccount: Bool = false, readinessAlreadyEnabled: Bool = false,
         stableFormats: Bool = false, policyReaderFormats: Bool = false, completionReaderFormats: Bool = false, promotionReaderFormats: Bool = false, readinessReaderFormats: Bool = false, retainedPolicySourceFormats: Bool = false, promotionProposalFormats: Bool = false,
         enableSecondReadiness: Bool = false,
         beforeActivation: (BoundAdmissionRegistrationFixture) throws -> Void = { _ in }) throws {
        self.installedReadiness = installedReadiness
        self.readinessAlreadyEnabled = readinessAlreadyEnabled
        self.enableSecondReadiness = enableSecondReadiness
        files = try .init(machine: UpdateCandidateStorageFixture(admission: true, activation: true,
            replacement: true, ownedInstalledBundle: true, installedReadiness: readinessAlreadyEnabled))
        try beforeActivation(files)
        var registration = try files.prepare()
        if admitEveryAccount {
            let inventory = try XCTUnwrap(files.machine.store.inventory())
            for account in inventory.accounts where account.accountID != files.machine.account {
                registration = try files.prepare(accountID: account.accountID, replacing: registration)
            }
        }
        oldRelease = files.machine.release
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
            if stableFormats { requiredFormats += try MachineUpdateStableReleaseRecord.requirements }
            if policyReaderFormats { requiredFormats += try MachineUpdateRetainedSetupPolicyStorage.readerRequirements }
            if retainedPolicySourceFormats {
                requiredFormats += try RuntimeRetainedSetupReleaseBinding.requirements
                    + MachineUpdatePreflightCompatibility.retainedSetupActivationRequirements
            }
            if completionReaderFormats { requiredFormats += try MachineUpdateRetainedSetupCompletionStorage.readerRequirements }
            if promotionReaderFormats { requiredFormats += try MachineUpdateRetainedSetupPromotionStorage.readerRequirements }
            if readinessReaderFormats { requiredFormats += try MachineUpdateRetainedSetupPromotionReadyStorage.readerRequirements }
            if promotionProposalFormats {
                requiredFormats += try RuntimeRetainedSetupCompletionBinding.completedHostRequirements
                for role in [AuthorityCodeRole.authority, .setupController] {
                    requiredFormats.append(try .init(role: role, name: "authority.installation-preparation",
                        readVersions: [24, 25, 26, 27], writeVersions: [25, 26, 27]))
                    for (name, version) in [
                        (MachineUpdateRetainedSetupPolicyIntentRecord.formatName, MachineUpdateRetainedSetupPolicyIntentRecord.currentFormatVersion),
                        (MachineUpdateRetainedSetupCompletionIntentRecord.formatName, MachineUpdateRetainedSetupCompletionIntentRecord.currentFormatVersion),
                        (MachineUpdateRetainedSetupPromotionIntentRecord.formatName, MachineUpdateRetainedSetupPromotionIntentRecord.currentFormatVersion)
                    ] {
                        requiredFormats.append(try .init(role: role, name: name, readVersions: [version],
                            writeVersions: name != MachineUpdateRetainedSetupPromotionIntentRecord.formatName || role == .setupController ? [version] : []))
                    }
                }
            }
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

    private func retainFixtureConfigurationEpoch(_ f: Fixture, additionalForeground: [RuntimeActivationPlan] = []) throws
        -> MachineUpdateConfigurationEpochRecord {
        _ = try f.run()
        let previous = try restartSource(f)
        let source = try f.machine.store.upgradeConfigurationEpochForInstalledRecovery(expected: previous,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        let accountID = f.machine.account
        let policies = try f.machine.policyCaptures(for: source).map { capture in
            if additionalForeground.isEmpty && capture.accountID == accountID {
                return MachineUpdateConfigurationEpoch.PolicyCapture(accountID: accountID, snapshot: releasePolicySnapshot(f))
            }
            return capture
        }
        let configurations: [MachineUpdateConfigurationEpoch.Configuration] = try ([f.machine.f.plan] + additionalForeground).map { foreground in
            let account = try XCTUnwrap(source.accounts.first { $0.accountID == foreground.accountID })
            let bundle = try RuntimeConfigurationBundle.initial(account: XCTUnwrap(account.preparation),
                initialization: XCTUnwrap(account.initialization), reference: foreground.reference, inventory: source.replacement.inventory)
            let host = f.readinessAlreadyEnabled && account.accountID == accountID
                ? try foreground.host.enablingInstalledReadiness(release: f.oldRelease) : foreground.host
            let original = RuntimeReleaseConfigurationSource(host: host, transport: foreground.transport,
                gateway: try XCTUnwrap(foreground.gatewaySettingsHost),
                clients: .init(presence: bundle.presenceClient, pairing: bundle.pairingClient, frontend: bundle.frontendClient))
            let policy = try XCTUnwrap(policies.first { $0.accountID == account.accountID }?.snapshot)
            func plan(_ stage: RuntimeReleasePolicyStage) throws -> RuntimeReleaseConfigurationPlan {
                try .init(accountID: account.accountID, source: source, currentPolicy: policy, candidate: f.newRelease,
                    host: original.host, transport: original.transport, gateway: original.gateway, clients: original.clients, stage: stage)
            }
            let startup = try plan(.startup), proposedCompletion = try plan(.completion)
            let completion = f.installedReadiness && (account.accountID == accountID || f.enableSecondReadiness)
                ? try proposedCompletion.selectingInstalledRootReadiness(candidate: f.newRelease) : proposedCompletion
            XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(startup.gateway.encoded))
            XCTAssertThrowsError(try TransportPairingStartupConfiguration.decode(startup.transport.canonicalBytes))
            XCTAssertEqual(try RuntimeReleaseConfigurationPlan.decode(startup.encoded).encoded, try startup.encoded)
            return .init(source: original, startup: startup, completion: completion)
        }
        let record = try f.machine.store.retainMachineUpdateConfigurationEpoch(expected: source, candidate: f.newRelease,
            policies: policies, configurations: configurations, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        let archive = try XCTUnwrap(f.machine.store.machineUpdateConfigurationEpoch())
        XCTAssertEqual(archive.record, record)
        for configuration in configurations {
            let startup = configuration.startup
            XCTAssertEqual(try archive.configuration(accountID: startup.binding.accountID)?.startup.encoded, try startup.encoded)
        }
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

    /// Borrows actual owned files and a held machine store. This fixture grants no native writer authority.
    static func withOwnedConfigurationPublicationLockFixture(_ body: (ConfigurationPublicationLockFixture) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testConfigurationWriterRequiresWritingAndRetainsEveryPublishedFileOnReplay"))
        let f = try Fixture(configurationEpoch: true)
        var record = try suite.advanceFixtureConfigurationEpoch(f, suite.retainFixtureConfigurationEpoch(f), .begin)
        let account = f.machine.account
        record = try suite.advanceFixtureConfigurationEpoch(f, record, .prepare(account, .host))
        let archive = try XCTUnwrap(f.machine.store.machineUpdateConfigurationEpoch())
        let configuration = try XCTUnwrap(archive.configuration(accountID: account))
        XCTAssertEqual(chmod(f.files.root.path, 0o755), 0)
        let directory = try ProtectedSetupDirectory(anchor: f.files.root.path, relativePath: "OwnedConfigurationLock",
            owner: getuid(), visibility: .sharedMetadata)
        defer { directory.close() }
        _ = try AdministrativeSetupPublication.publish(configuration.bytes(.host, target: false), file: .commandHost,
            directory: directory, owner: getuid())
        try body(.init(archive: archive, accountID: account, directory: directory, machine: f.machine.store,
            lockPath: f.machine.f.f.root.path + "/machine/writer.lock", openSecond: { try f.machine.f.f.open() }))
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
        for account in record.accounts where account.configurationPublished {
            for file in MachineUpdatePublicationProgress.File.allCases {
                current = try advance(current, .prepare(account.accountID, file))
                current = try advance(current, .complete(account.accountID, file))
            }
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

    private func withInstalledBackendSettingsFixture(_ body: (RuntimeReleaseBackendPlan, RuntimeReleaseBackendPlan,
        SignedReleaseEvidence, GatewayRuntimeSettingsRevision, GatewayRuntimeSettingsRevision) throws -> Void) throws {
        let (f, setup) = try populatedBackendFixture()
        _ = try publishFixtureConfigurationEpoch(f, retainFixtureConfigurationEpoch(f))
        let store = f.machine.store, journal = try setup.state()
        let activation = try XCTUnwrap(store.gatewayRuntimeActivation(accountID: f.machine.account).plan)
        let capture = try fixtureBackendCapture(f, foreground: setup.runtime.plan, activation: activation, journal: journal)
        let startup = try XCTUnwrap(capture.startup), completion = try XCTUnwrap(capture.completion)
        let selection = try GatewayRuntimeSettingsSelection(activation: activation, journal: journal,
            foreground: setup.runtime.plan, inventory: completion.source.inventory)
        let first = try GatewayRuntimeSettingsRevision(id: Data(repeating: 181, count: 16), selection: selection,
            activation: activation, journal: journal, foreground: setup.runtime.plan, inventory: completion.source.inventory)
        let second = try GatewayRuntimeSettingsRevision(id: Data(repeating: 182, count: 16), selection: selection,
            activation: activation, previous: first, journal: journal, foreground: setup.runtime.plan,
            inventory: completion.source.inventory)
        let before = try store.retainedRuntimeCompatibilityInputs()
        try body(startup, completion, f.newRelease, first, second)
        XCTAssertEqual(try store.retainedRuntimeCompatibilityInputs(), before)
    }

    func testInstalledSettingsPublicationKeepsTheReleaseBindingAndExactOldAndNewMarkers() throws {
        try withInstalledBackendSettingsFixture { startup, backend, candidate, first, second in
            let plan = try GatewayRuntimeSettingsPublicationPlan(installed: backend, revision: first,
                previous: nil, candidate: candidate)
            let oldPair = try GatewayRuntimeExtensions(release: backend)
            let oldCommit = try GatewayRuntimeCommit(release: backend, pair: oldPair)
            XCTAssertEqual(plan.artifacts.count, 5)
            XCTAssertEqual(plan.artifacts.last?.file.name, AdministrativeSetupPublication.File.gatewayRuntimeCommit.name)
            XCTAssertEqual(plan.artifacts.last?.previous, try oldCommit.encoded)
            XCTAssertEqual(plan.artifacts.last?.selected, try plan.commit.encoded)
            XCTAssertEqual(try plan.activation.encoded, try backend.source.activation.encoded)
            try plan.commit.requireRelease(binding: backend.binding, stage: .completion)
            let next = try GatewayRuntimeSettingsPublicationPlan(installed: backend, revision: second,
                previous: first, candidate: candidate)
            XCTAssertEqual(next.artifacts.last?.previous, try plan.commit.encoded)
            XCTAssertNotEqual(next.artifacts.last?.selected, plan.artifacts.last?.selected)
            XCTAssertThrowsError(try GatewayRuntimeSettingsPublicationPlan(installed: backend, revision: first,
                previous: first, candidate: candidate)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            XCTAssertThrowsError(try GatewayRuntimeSettingsPublicationPlan(installed: startup, revision: first,
                previous: nil, candidate: candidate)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
        }
    }

    func testInstalledSettingsStartupRequiresTheCompletionHostAndPreservesTheRecoveryFloor() throws {
        try withInstalledBackendSettingsFixture { startup, backend, candidate, first, _ in
            let plan = try AuthorityGatewaySettingsStartupPlan(installed: backend, authority: backend.configuration.host)
            let pair = try GatewayRuntimeExtensions(release: backend)
            let commit = try GatewayRuntimeCommit(release: backend, pair: pair)
            XCTAssertEqual(plan.accountID, backend.binding.accountID)
            XCTAssertEqual(plan.activeCommitDigest, try commit.observationDigest)
            XCTAssertNil(plan.pendingChange)
            XCTAssertFalse(plan.requiresConsumerRecovery)
            XCTAssertTrue(plan.allowsInitialInstallation(commitDigest: try commit.observationDigest))
            XCTAssertThrowsError(try AuthorityGatewaySettingsStartupPlan(installed: startup,
                authority: startup.configuration.host)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            XCTAssertThrowsError(try AuthorityGatewaySettingsStartupPlan(installed: backend,
                authority: startup.configuration.host)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            let settled = try backend.projectingSettledInstalledSettings(.init(active: first, pending: nil, phase: nil),
                candidate: candidate)
            let recovery = try AuthorityGatewaySettingsStartupPlan(installed: settled, authority: settled.configuration.host)
            XCTAssertTrue(recovery.requiresConsumerRecovery)
            XCTAssertFalse(recovery.allowsInitialInstallation(commitDigest: recovery.activeCommitDigest))
        }
    }

    func testInstalledSettingsChangeReadsReleaseMarkersAndKeepsTheOrdinaryDecoderClosed() throws {
        try withInstalledBackendSettingsFixture { _, backend, candidate, first, _ in
            let publication = try GatewayRuntimeSettingsPublicationPlan(installed: backend, revision: first,
                previous: nil, candidate: candidate)
            let marker = try XCTUnwrap(publication.artifacts.last)
            let previous = try XCTUnwrap(marker.previous)
            let change = try AuthorityPhonePushSettingsChange(installed: publication)
            let old = try GatewayRuntimeCommit.decodeForReleaseArchive(previous)
            let selected = try GatewayRuntimeCommit.decodeForReleaseArchive(marker.selected)
            try old.requireRelease(binding: backend.binding, stage: .completion)
            try selected.requireRelease(binding: backend.binding, stage: .completion)
            XCTAssertEqual(change.previousCommitDigest, try old.observationDigest)
            XCTAssertEqual(change.selectedCommitDigest, try selected.observationDigest)
            XCTAssertEqual(change.revisionDigest, try first.digest)
            XCTAssertGreaterThan(marker.selected.count, 1024)
            XCTAssertThrowsError(try GatewayRuntimeCommit.decode(marker.selected))
            XCTAssertThrowsError(try AuthorityPhonePushSettingsChange(publication))
        }
    }

    func testInstalledSettingsChangeRefusesAnOrdinaryPublicationAndPreservesItsExistingEntry() throws {
        try withInstalledBackendSettingsFixture { _, backend, _, first, _ in
            let source = backend.source
            let ordinary = try GatewayRuntimeSettingsPublicationPlan(revision: first, previous: nil,
                activation: source.activation, journal: source.journal, foreground: source.foreground, inventory: source.inventory)
            XCTAssertNil(ordinary.commit.release)
            XCTAssertNoThrow(try AuthorityPhonePushSettingsChange(ordinary))
            XCTAssertThrowsError(try AuthorityPhonePushSettingsChange(installed: ordinary)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
        }
    }

    func testInstalledSettingsStartupKeepsPendingChangesFencedForEveryHistoricalPhase() throws {
        try withInstalledBackendSettingsFixture { _, backend, candidate, first, second in
            let authority = backend.configuration.host
            let empty = try AuthorityGatewaySettingsStartupPlan(installed: backend, authority: authority,
                state: .empty, candidate: candidate)
            XCTAssertNil(empty.pendingChange)
            XCTAssertFalse(empty.requiresConsumerRecovery)
            let settled = try AuthorityGatewaySettingsStartupPlan(installed: backend, authority: authority,
                state: .init(active: first, pending: nil, phase: nil), candidate: candidate)
            XCTAssertTrue(settled.requiresConsumerRecovery)
            XCTAssertFalse(settled.allowsInitialInstallation(commitDigest: settled.activeCommitDigest))
            for phase in GatewayRuntimeSettingsPhase.allCases {
                let pending = try AuthorityGatewaySettingsStartupPlan(installed: backend, authority: authority,
                    state: .init(active: first, pending: second, phase: phase), candidate: candidate)
                let publication = try GatewayRuntimeSettingsPublicationPlan(installed: backend, revision: second,
                    previous: first, candidate: candidate)
                XCTAssertEqual(pending.pendingChange, try AuthorityPhonePushSettingsChange(installed: publication))
                XCTAssertEqual(pending.activeCommitDigest, settled.activeCommitDigest)
                XCTAssertTrue(pending.requiresFreshQuiescence)
                XCTAssertFalse(pending.requiresConsumerRecovery)
                XCTAssertFalse(pending.allowsInitialInstallation(commitDigest: pending.activeCommitDigest))
            }
            for state in [GatewayRuntimeSettingsState(active: nil, pending: first, phase: nil),
                .init(active: first, pending: nil, phase: .retained),
                .init(active: first, pending: first, phase: .retained)] {
                XCTAssertThrowsError(try AuthorityGatewaySettingsStartupPlan(installed: backend, authority: authority,
                    state: state, candidate: candidate)) {
                    XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
                }
            }
        }
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

    private func restartWithRetainedBackend(_ f: Fixture, complete: Bool,
        gateway: GatewayJournalSetupExchangeTests.Fixture? = nil, additionalForeground: [RuntimeActivationPlan] = []) throws
        -> (MachineUpdateRestartSource, UpdateRestartAdmissionLease) {
        let configuration = try publishFixtureConfigurationEpoch(f,
            retainFixtureConfigurationEpoch(f, additionalForeground: additionalForeground))
        let store = f.machine.store
        let account = f.machine.account
        let capture: MachineUpdateBackendEpoch.Capture
        if let gateway {
            let activation = try XCTUnwrap(store.gatewayRuntimeActivation(accountID: account).plan)
            capture = try fixtureBackendCapture(f, foreground: gateway.runtime.plan, activation: activation, journal: gateway.state())
        } else {
            capture = .init(accountID: account, source: nil, startup: nil, completion: nil)
        }
        let backend = try store.upgradeMachineUpdateBackendEpochStorage(expected: configuration,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        let captures = [capture] + additionalForeground.map {
            MachineUpdateBackendEpoch.Capture(accountID: $0.accountID, source: nil, startup: nil, completion: nil)
        }
        let retained = try store.retainMachineUpdateBackendEpoch(backend, captures: captures,
            candidate: f.newRelease, directory: f.directory, quiescence: f.quiet, verifyCurrent: {})
        if complete {
            func advance(_ previous: MachineUpdateBackendEpochRecord, _ operation: MachineUpdateBackendPublicationOperation)
                throws -> MachineUpdateBackendEpochRecord {
                try store.advanceMachineUpdateBackendPublication(previous, operation: operation, candidate: f.newRelease,
                    directory: f.directory, quiescence: f.quiet, verifyCurrent: { _ in })
            }
            var record = try advance(retained, .begin)
            if gateway != nil {
                for file in MachineUpdateBackendPublicationProgress.File.allCases {
                    record = try advance(record, .prepare(account, file))
                    record = try advance(record, .complete(account, file))
                }
            }
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

        func openPolicyPair(readOnly: Bool, accountID: Data? = nil) throws -> AuthorityJournal {
            let storage = try policyStorage(readOnly: readOnly, accountID: accountID)
            if readOnly { return try AuthorityJournal(updateHealthStorage: storage, validateSelf: { _ in }) }
            return try AuthorityJournal(updateCompletionStorage: storage, validateSelf: { _ in })
        }

        func policyStorage(readOnly: Bool, accountID: Data?) throws -> sending AuthorityStorage {
            let account = try XCTUnwrap(snapshot.source.accounts.first { $0.accountID == (accountID ?? boundary.accountID) })
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
            return try Self.openPolicyStorage(anchor: fixture.root.path, journal: journal,
                continuity: continuity, macID: initial.macID, accountID: initial.accountID, limits: fixture.limits, readOnly: readOnly)
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

    private func prepareSecondForeground(_ files: BoundAdmissionRegistrationFixture, offset: UInt32 = 1000,
        firstServiceUID: UInt32 = 20002, didPrepareMaterial: (RuntimePreparationMaterial) -> Void = { _ in })
        throws -> (account: AccountPreparationIntent, reference: RuntimeMaterialReference) {
        let store = files.machine.store
        let account = try reserveRestartAccount(files, offset: offset, complete: true)
        let services = try ServiceAccountPlan(account: account, planID: AccountPreparationIntent.randomID(), claims: [
            .init(accountID: account.accountID, role: .transport, number: firstServiceUID, userID: UUID(), groupID: UUID()),
            .init(accountID: account.accountID, role: .gateway, number: firstServiceUID + 1, userID: UUID(), groupID: UUID())])
        try store.retainServiceAccountPlan(services)
        try store.completeServiceAccountPlan(services)
        let activity = try ServiceReleaseActivityReference(services: services,
            identities: [.transport: .init(device: 1, inode: 102), .gateway: .init(device: 1, inode: 103)])
        let now = Date()
        let material = try RuntimePreparationMaterial.create(services: services, notValidBefore: now.addingTimeInterval(-60),
            notValidAfter: now.addingTimeInterval(600), serviceActivity: activity, auditDeliveryVersion: 1)
        let reference = try material.reference
        try store.retainRuntimeMaterial(reference)
        didPrepareMaterial(material)
        return (account, reference)
    }

    private func registerSecondForeground(_ files: BoundAdmissionRegistrationFixture,
        didPrepareMaterial: (RuntimePreparationMaterial) -> Void) throws -> RuntimeActivationPlan {
        let store = files.machine.store
        let (account, reference) = try prepareSecondForeground(files, didPrepareMaterial: didPrepareMaterial)
        try store.completeRuntimePublication(reference)
        let plan = try RuntimeActivationPlan(account: account,
            initialization: XCTUnwrap(store.initialization(accountID: account.accountID)),
            runtime: store.runtimePreparation(accountID: account.accountID), inventory: XCTUnwrap(store.inventory()),
            gatewaySettingsRelease: files.machine.release)
        try store.retainRuntimeActivation(plan)
        _ = try store.enrollRuntimeActivation(plan)
        try store.markRuntimeJobsRegistered(plan)
        return plan
    }

    private func withCompletionFixture(installedReadiness: Bool = false, actualPolicyPair: Bool = false,
        registerForeground: Bool = true, registerGateway: Bool = false, registerSecondForeground: Bool = false,
        readinessAlreadyEnabled: Bool = false, publishGatewayWithoutRegistration: Bool = false, stableFormats: Bool = false,
        policyReaderFormats: Bool = false, completionReaderFormats: Bool = false, promotionReaderFormats: Bool = false, readinessReaderFormats: Bool = false, retainedPolicySourceFormats: Bool = false, promotionProposalFormats: Bool = false,
        enableSecondReadiness: Bool = false, didPrepareSecondMaterial: (RuntimePreparationMaterial) -> Void = { _ in },
        beforeActivation: (BoundAdmissionRegistrationFixture) throws -> Void = { _ in },
        _ body: (CompletionFixture) throws -> Void) throws {
        var gateway: GatewayJournalSetupExchangeTests.Fixture?
        var additionalForeground: [RuntimeActivationPlan] = []
        let f = try Fixture(backendEpoch: true, installedReadiness: installedReadiness, completionIntent: true,
            admitEveryAccount: registerSecondForeground, readinessAlreadyEnabled: readinessAlreadyEnabled,
            stableFormats: stableFormats, policyReaderFormats: policyReaderFormats, completionReaderFormats: completionReaderFormats, promotionReaderFormats: promotionReaderFormats, readinessReaderFormats: readinessReaderFormats, retainedPolicySourceFormats: retainedPolicySourceFormats, promotionProposalFormats: promotionProposalFormats,
            enableSecondReadiness: enableSecondReadiness, beforeActivation: { files in
            if registerSecondForeground {
                additionalForeground = [try self.registerSecondForeground(files, didPrepareMaterial: didPrepareSecondMaterial)]
            }
            let store = files.machine.store
            if registerForeground { try store.markRuntimeJobsRegistered(files.machine.f.plan) }
            if registerGateway || publishGatewayWithoutRegistration {
                let setup = try GatewayJournalSetupExchangeTests.Fixture(runtime: files.machine.f)
                try setup.retainCompletion(.decode(setup.initialize()))
                let activation = try GatewayRuntimeActivationPlan(journal: setup.state(),
                    foreground: setup.runtime.plan, inventory: XCTUnwrap(store.inventory()))
                try store.retainGatewayRuntimeActivation(activation)
                try store.markGatewayRuntimePublished(activation)
                _ = try store.enrollGatewayRuntimeActivation(activation)
                if registerGateway { try store.markGatewayRuntimeRegistered(activation) }
                gateway = setup
            }
            try beforeActivation(files)
        })
        let (source, restart) = try restartWithRetainedBackend(f, complete: true, gateway: gateway,
            additionalForeground: additionalForeground)
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

    private func withFinishingFixture(registerForeground: Bool = true, registerGateway: Bool = false,
        registerSecondForeground: Bool = false, publishGatewayWithoutRegistration: Bool = false, stableFormats: Bool = false,
        policyReaderFormats: Bool = false, completionReaderFormats: Bool = false, promotionReaderFormats: Bool = false, readinessReaderFormats: Bool = false, retainedPolicySourceFormats: Bool = false, promotionProposalFormats: Bool = false,
        enableSecondReadiness: Bool = false, publishCompletionFiles: Bool = false,
        didPrepareSecondMaterial: (RuntimePreparationMaterial) -> Void = { _ in },
        beforeActivation: (BoundAdmissionRegistrationFixture) throws -> Void = { _ in },
        _ body: (CompletionFixture, MachineUpdateFinalizationSnapshot, AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Void) throws {
        try withCompletionFixture(installedReadiness: true, actualPolicyPair: true,
            registerForeground: registerForeground, registerGateway: registerGateway,
            registerSecondForeground: registerSecondForeground, publishGatewayWithoutRegistration: publishGatewayWithoutRegistration,
            stableFormats: stableFormats, policyReaderFormats: policyReaderFormats, completionReaderFormats: completionReaderFormats, promotionReaderFormats: promotionReaderFormats, readinessReaderFormats: readinessReaderFormats, retainedPolicySourceFormats: retainedPolicySourceFormats, promotionProposalFormats: promotionProposalFormats,
            enableSecondReadiness: enableSecondReadiness, didPrepareSecondMaterial: didPrepareSecondMaterial, beforeActivation: beforeActivation) { fixture in
            let machine = fixture.machine, snapshot = fixture.snapshot, candidate = fixture.candidate
            let directory = fixture.directory, restart = fixture.restart
            func readPair(_ accountID: Data) throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
                let journal = try fixture.openPolicyPair(readOnly: true, accountID: accountID)
                defer { try? journal.close() }
                let value = try journal.captureMachineUpdatePolicyBoundaryForRecoveryRead()
                try journal.close()
                return value
            }
            let accounts = snapshot.configuration.record.accounts.filter(\.configurationPublished).map(\.accountID)
            let prepared = try MachineUpdateCompletionIntentProposal.make(snapshot: snapshot, candidate: candidate,
                inventory: fixture.inventory, policies: accounts.map(readPair), targetRevision: Data(repeating: 249, count: 16))
            _ = try machine.retainMachineUpdateCompletionIntent(prepared, snapshot: snapshot, candidate: candidate,
                directory: directory, restart: restart) { _, scope in _ = try scope.read() }
            let recorded = try MachineUpdateCompletionRecoverySequence.resumePrepared(prepared, snapshot: snapshot,
                candidate: candidate, machine: machine, directory: directory, restart: restart,
                verify: { _, scope in _ = try scope.read() }, boundary: { accountID, _ in try readPair(accountID) }, commit: { permit, scope in
                    let writer = try fixture.openPolicyPair(readOnly: false, accountID: permit.accountID)
                    defer { try? writer.close() }
                    let result = try writer.commitMachineUpdateCompletionPolicy(permit, scope: scope, candidate: candidate,
                        verifyNative: { _ in _ = try scope.read() })
                    try writer.close()
                    return result
                })
            let boundaries = try accounts.map(readPair)
            let boundary = try XCTUnwrap(boundaries.first { $0.accountID == fixture.boundary.accountID })
            let completion = MachineUpdateCompletionSnapshot(restart: snapshot, intent: recorded)
            let plan = try MachineUpdateCompletionPublicationPlan(snapshot: completion, candidate: candidate,
                currentSourceDigest: snapshot.backend.record.currentSourceDigest, boundaries: boundaries)
            let publication = try MachineUpdateCompletionPublicationRecord(plan: plan)
            let root = fixture.files.f.f.root.path
            XCTAssertEqual(chmod(root, 0o755), 0)
            var directories: [Data: ProtectedSetupDirectory] = [:]
            defer { directories.values.forEach { $0.close() } }
            for accountID in accounts {
                let suffix = accountID.map { String(format: "%02x", $0) }.joined()
                directories[accountID] = try ProtectedSetupDirectory(anchor: root, relativePath: "CompletionPublication-" + suffix,
                    owner: getuid(), visibility: .sharedMetadata)
            }
            func files(_ entry: MachineUpdateCompletionPublicationPlan.Entry) throws -> ProtectedSetupDirectory {
                try XCTUnwrap(directories[entry.accountID])
            }
            var published = try machine.retainMachineUpdateCompletionPublication(publication, plan: plan, expected: recorded,
                restartSnapshot: snapshot, candidate: candidate, directory: directory, restart: restart) { _, scope in _ = try scope.read() }
            if publishCompletionFiles {
                XCTAssertEqual(accounts.count, 2)
                XCTAssertEqual(Set(directories.values.map(\.path)).count, 2)
                for entry in plan.entries {
                    _ = try AdministrativeSetupPublication.publish(entry.startup, file: entry.artifact, directory: files(entry), owner: getuid())
                }
                var acknowledgments: [Data: Set<MachineUpdateCompletionPublicationPlan.File>] = [:]
                // The coordinator checks the store scope around each step. Check the completed file set once below.
                published = try MachineUpdateCompletionFileCoordinator.publish(published, plan: plan, expected: recorded,
                    restart: snapshot, candidate: candidate, machine: machine, directory: directory, admission: restart,
                    validate: { _ in }, publishFile: { current, entry, _, didStage in
                        try MachineUpdateCompletionPublicationFiles.publishInLease(plan, publication: current,
                            accountID: entry.accountID, file: entry.file, directory: files(entry), owner: getuid(),
                            verifyCurrent: {}, didStage: didStage)
                    }, didStage: { stage in
                        if case .acknowledged(let account, let file) = stage {
                            XCTAssertTrue(acknowledgments[account, default: []].insert(file).inserted)
                        }
                    })
                XCTAssertTrue(published.filesPublished)
                XCTAssertEqual(Set(acknowledgments.keys), Set(accounts))
                XCTAssertEqual(try machine.machineUpdateCompletionPublication(), published)
                for entry in plan.entries {
                    XCTAssertTrue(acknowledgments[entry.accountID, default: []].contains(entry.file))
                }
                try MachineUpdateCompletionPublicationFiles.requireInLeases(plan, publication: published,
                    owner: getuid(), directory: files, verifyCurrent: {})
            } else {
                // Other finishing tests start with completed files and a matching record.
                for entry in plan.entries {
                    published = try published.advancing(accountID: entry.accountID, file: entry.file, to: .writing)
                    _ = try AdministrativeSetupPublication.publish(entry.completion, file: entry.artifact, directory: files(entry), owner: getuid())
                    published = try published.advancing(accountID: entry.accountID, file: entry.file, to: .published)
                }
                try machine.close()
                let revision = published.revision.uuidString.replacingOccurrences(of: "-", with: "")
                let record = try published.encoded.map { String(format: "%02x", $0) }.joined()
                try fixture.files.sql("UPDATE machine_update_completion_publication_v1 SET revision=X'\(revision)',record=X'\(record)' WHERE singleton=1")
                try fixture.files.reopen()
            }

            let retained = try fixture.machine.machineUpdateCompletionPublicationRecoverySnapshot(candidate: candidate, directory: directory)
            let installed = try MachineUpdateInstalledReleaseEpoch.Archive(snapshot: retained, candidate: candidate,
                currentSourceDigest: snapshot.backend.record.currentSourceDigest, boundaries: boundaries)
            let finishing = try fixture.machine.finalizeMachineUpdateCompletion(installed, publication: published, plan: plan,
                expected: recorded, restartSnapshot: snapshot, candidate: candidate, directory: directory, restart: restart,
                ownedFileDirectory: files) { _, scope in _ = try scope.read() }
            try body(fixture, finishing, boundary)
        }
    }

    func testInstalledRuntimeSourceBindsHistoryAndRejectsMachineReentry() throws {
        try withFinishingFixture { fixture, finishing, _ in
            let source = try fixture.machine.installedRuntimeSource(candidate: fixture.candidate, directory: fixture.directory)
            try source.actual.requireSame(as: finishing)
            XCTAssertEqual(source.historicalInventory, fixture.snapshot.source.replacement.inventory)
            XCTAssertEqual(source.historicalSchemaVersion, 20)
            XCTAssertEqual(source.historicalSourceDigest, fixture.snapshot.backend.record.currentSourceDigest)
            let expired = try fixture.machine.withCurrentMachineUpdateFinalization(candidate: fixture.candidate,
                directory: fixture.directory, restart: fixture.restart) { scope in
                    try scope.readRetainedSource().requireSame(as: source)
                    XCTAssertThrowsError(try fixture.machine.installedRuntimeSource(candidate: fixture.candidate,
                        directory: fixture.directory)) {
                            XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                        }
                    return scope
                }
            XCTAssertThrowsError(try expired.readRetainedSource()) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
        }
    }

    func testInstalledRuntimeSourceRejectsChangedRuntimeAndExtraPreparationRows() throws {
        try withFinishingFixture { fixture, finishing, _ in
            let candidate = fixture.candidate, directory = fixture.directory
            let source = try fixture.machine.installedRuntimeSource(candidate: candidate, directory: directory)
            func reject(_ edit: String, undo: String) throws {
                try fixture.machine.close()
                try fixture.files.sql(edit)
                try fixture.files.reopen()
                try fixture.machine.machineUpdateFinalizationSnapshot(candidate: candidate, directory: directory).requireSame(as: finishing)
                XCTAssertThrowsError(try fixture.machine.installedRuntimeSource(candidate: candidate, directory: directory)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                try fixture.machine.close()
                try fixture.files.sql(undo)
                try fixture.files.reopen()
                try fixture.machine.installedRuntimeSource(candidate: candidate, directory: directory).requireSame(as: source)
            }
            let flip = "UPDATE runtime_activation_v1 SET registered=1-registered"
            try reject(flip, undo: flip)
            let extra = try PreparationIntentRecord(id: UUID(), revision: UUID(), parent: fixture.files.destination.path,
                ancestry: fixture.files.destination.preparationAncestry(), phase: .abandoned)
            let id = extra.id.uuidString.replacingOccurrences(of: "-", with: "")
            let revision = extra.revision.uuidString.replacingOccurrences(of: "-", with: "")
            let bytes = try extra.encoded.map { String(format: "%02x", $0) }.joined()
            try reject("INSERT INTO preparation_intents_v1 VALUES(x'\(id)',x'\(revision)',x'\(bytes)')",
                undo: "DELETE FROM preparation_intents_v1 WHERE id=x'\(id)'")
        }
    }

    func testInstalledRuntimeSourceRejectsAnUnsupportedRetainedSchema() throws {
        try withFinishingFixture { fixture, finishing, _ in
            let archive = finishing.installed
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: archive.artifact(4)) as? [String: Any])
            fields["sourceSchemaVersion"] = 21
            let bytes = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
            let intent = try MachineUpdateCompletionIntentRecord.decode(bytes)
            XCTAssertEqual(intent.sourceSchemaVersion, 21)
            let changedIntent = try MachineUpdateCompletionIntentArchive(record: intent, policies: archive.completionIntent().policies)
            let plan = try MachineUpdateCompletionPublicationPlan(retainedConfiguration: archive.configuration(),
                retainedBackend: archive.backend(), intent: changedIntent, candidate: fixture.candidate)
            var publicationFields = try XCTUnwrap(JSONSerialization.jsonObject(with: archive.artifact(5)) as? [String: Any])
            publicationFields["intentDigest"] = try plan.completionIntentDigest.base64EncodedString()
            publicationFields["planFingerprint"] = try plan.fingerprint.base64EncodedString()
            let publicationBytes = try JSONSerialization.data(withJSONObject: publicationFields,
                options: [.sortedKeys, .withoutEscapingSlashes])
            let publication = try MachineUpdateCompletionPublicationRecord.decode(publicationBytes)
            try publication.requirePlan(plan)
            let artifacts = archive.artifacts.map { operand in
                let replacements: [Int64: Data] = [4: bytes, 5: publicationBytes]
                return MachineUpdateInstalledReleaseEpoch.Artifact(kind: operand.kind, accountID: operand.accountID,
                    bytes: replacements[operand.kind] ?? operand.bytes)
            }
            let header = try MachineUpdateInstalledReleaseRecord(sourceSchemaVersion: archive.record.sourceSchemaVersion,
                activationAttempt: finishing.activation.attemptID, inventory: finishing.inventory,
                publication: publication, artifacts: artifacts)
            func replace(_ kind: Int64, _ bytes: Data) throws {
                let hex = bytes.map { String(format: "%02x", $0) }.joined()
                try fixture.files.sql("UPDATE installed_release_state_v1 SET record=x'\(hex)' WHERE kind=\(kind)")
            }
            try fixture.machine.close()
            try replace(4, bytes)
            try replace(5, publicationBytes)
            try replace(0, header.encoded)
            try fixture.files.reopen()
            let frame = try fixture.machine.machineUpdateFinalizationSnapshot(candidate: fixture.candidate, directory: fixture.directory)
            XCTAssertEqual(try frame.installed.completionIntent().record.sourceSchemaVersion, 21)
            XCTAssertThrowsError(try fixture.machine.installedRuntimeSource(candidate: fixture.candidate, directory: fixture.directory)) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
        }
    }

    func testInstalledPolicyReadUsesThePairedJournalsAndClosesThem() throws {
        try withFinishingFixture { fixture, _, boundary in
            try fixture.machine.withCurrentMachineUpdateFinalization(candidate: fixture.candidate,
                directory: fixture.directory, restart: fixture.restart) { scope in
                    let reader = try fixture.openPolicyPair(readOnly: true)
                    defer { try? reader.close() }
                    let paired = try MachineUpdateInstalledPolicyRead.read(scope: scope, candidate: fixture.candidate,
                        verifyCurrent: { _ = try scope.read() }, openReadOnly: { selected in
                            XCTAssertEqual(selected.accountID, boundary.accountID)
                            XCTAssertEqual(selected.service.macID, boundary.macID)
                            return reader
                        })
                    XCTAssertEqual(paired, [boundary])
                    XCTAssertThrowsError(try reader.captureMachineUpdatePolicyBoundaryForRecoveryRead()) {
                        XCTAssertEqual($0 as? ContinuityStoreError, .closed)
                    }
                    let candidate = fixture.candidate
                    let wrongRelease = try SignedReleaseEvidence(manifest: .init(release: "fixture-wrong-candidate",
                        build: candidate.manifest.build, components: candidate.manifest.components, dependencies: candidate.manifest.dependencies),
                        codeDirectoryHashes: candidate.codeDirectoryHashes, dependencyCodeDirectoryHashes: candidate.dependencyCodeDirectoryHashes)
                    var opened = false
                    XCTAssertThrowsError(try MachineUpdateInstalledPolicyRead.read(scope: scope, candidate: wrongRelease,
                        verifyCurrent: { _ = try scope.read() }, openReadOnly: { _ in
                            opened = true
                            throw ReplacementFixtureError.injected
                        })) {
                            XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                        }
                    XCTAssertFalse(opened)
                    let writer = try fixture.openPolicyPair(readOnly: false)
                    defer { try? writer.close() }
                    XCTAssertThrowsError(try MachineUpdateInstalledPolicyRead.read(scope: scope, candidate: fixture.candidate,
                        verifyCurrent: { _ = try scope.read() }, openReadOnly: { _ in writer })) {
                            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
                        }
                    XCTAssertThrowsError(try writer.read { _ in true }) {
                        XCTAssertEqual($0 as? ContinuityStoreError, .closed)
                    }
                    let reopened = try fixture.openPolicyPair(readOnly: true)
                    defer { try? reopened.close() }
                    XCTAssertEqual(try reopened.captureMachineUpdatePolicyBoundaryForRecoveryRead(), boundary)
                }
        }
    }

    func testInstalledCompatibilityKeepsTheHistoricalRuntimeAndSelectsTheCompletionPlan() throws {
        try withFinishingFixture { fixture, finishing, boundary in
            XCTAssertThrowsError(try fixture.machine.retainedRuntimeCompatibilityInputs()) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try fixture.machine.withCurrentMachineUpdateFinalization(candidate: fixture.candidate,
                directory: fixture.directory, restart: fixture.restart) { scope in
                    let compatibility = try scope.readCompatibility()
                    XCTAssertEqual(compatibility.runtime.inputs.schemaVersion, 23)
                    XCTAssertEqual(compatibility.runtime.inputs.inventory, finishing.inventory.canonicalBytes)
                    let view = try MachineUpdateInstalledRuntimeView(compatibility: compatibility, candidate: fixture.candidate)
                    let selected = try view.account(boundary.accountID)
                    XCTAssertEqual(view.sourceInventory, fixture.snapshot.source.replacement.inventory)
                    XCTAssertEqual(view.installedInventory, finishing.inventory)
                    XCTAssertEqual(selected.configuration?.policyStage, .completion)
                    XCTAssertEqual(selected.provisioning?.reference.services.releaseDigest, view.sourceInventory.releaseDigest)
                    XCTAssertThrowsError(try view.account(Data(repeating: 255, count: 16))) {
                        XCTAssertEqual($0 as? PreparationStoreError, .notFound)
                    }
                    try view.requireCurrent(scope: scope, candidate: fixture.candidate)
                }
        }
    }

    private func restoreFinalizationOwner(_ finishing: MachineUpdateFinalizationSnapshot, fixture: CompletionFixture) throws
        -> (MachineUpdateFinalizationRecoveryOwner, UpdateAdmissionBarrier) {
        let state = try fixture.machine.updateAdmissionState()
        let macID = finishing.inventory.macID, anchor = fixture.files.f.f.root.path
        try fixture.machine.close()
        fixture.restart.close()
        let coordinator = try UpdateActivationAdmission(anchor: anchor, relativeDirectory: "machine",
            owner: getuid(), expected: finishing.admission.machine)
        let recovery = try MachineUpdateAdmissionRecovery(initial: state, macID: macID,
            installationID: finishing.inventory.installationID, accountID: fixture.boundary.accountID,
            coordinator: coordinator, readCurrent: {
                let store = try PreparationIntentStore(lease: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
                    macID: macID, maximumRecords: 64, initialize: false)
                defer { try? store.close() }
                return try store.updateAdmissionState()
            })
        defer { recovery.close() }
        let gate = try UpdateAdmissionBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
            owner: getuid(), expected: finishing.admission.machine)
        let drain = try recovery.takeRestoredDrain(expected: finishing.activation)
        return (MachineUpdateFinalizationRecoveryOwner(snapshot: finishing, candidate: fixture.candidate, drain: drain), gate)
    }

    func testFinalizationRecoveryWaitsForActivityAndClosesTheWriterBeforeTransfer() throws {
        try withFinishingFixture { fixture, finishing, _ in
            let source = try fixture.machine.installedRuntimeSource(candidate: fixture.candidate, directory: fixture.directory)
            let (owner, ordinary) = try restoreFinalizationOwner(finishing, fixture: fixture)
            defer { owner.close() }
            let existing = try ReleaseActivityBarrier(directory: .init(anchor: fixture.files.f.f.root.path,
                relativeDirectory: "machine", owner: getuid()), owner: getuid()).acquireShared()
            defer { existing.close() }
            try fixture.files.reopen()
            var stages: [MachineUpdateFinalizationRecoveryOwner.Stage] = []
            func verifyStage(_ stage: MachineUpdateFinalizationRecoveryOwner.Stage) throws {
                stages.append(stage)
                try owner.validateAdmission(directory: fixture.directory)
                XCTAssertThrowsError(try ordinary.acquireAdmission()) {
                    XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
                }
                if stage == .writerClosed || stage == .admissionTransferred {
                    XCTAssertThrowsError(try fixture.machine.inventory()) {
                        XCTAssertEqual($0 as? PreparationStoreError, .closed)
                    }
                }
            }
            XCTAssertFalse(try owner.resumeInLease(machine: fixture.machine, directory: fixture.directory, verifyStage: verifyStage))
            XCTAssertEqual(stages, [.beforeQuiescence])
            XCTAssertEqual(try fixture.machine.inventory(), finishing.inventory)
            existing.close()
            stages.removeAll()
            XCTAssertTrue(try owner.resumeInLease(machine: fixture.machine, directory: fixture.directory, verifyStage: verifyStage))
            XCTAssertEqual(stages, [.beforeQuiescence, .withQuiescence, .writerClosed, .admissionTransferred])
            try fixture.files.reopen()
            let escaped = try owner.withSnapshotInLease(machine: fixture.machine, directory: fixture.directory) { scope in
                try scope.readRetainedSource().requireSame(as: source)
                XCTAssertThrowsError(try owner.withSnapshotInLease(machine: fixture.machine, directory: fixture.directory) { _ in
                    XCTFail("Reentrant owner lent another finishing scope")
                }) {
                    XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
                }
                return scope
            }
            XCTAssertThrowsError(try escaped.read()) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
        }
    }

    func testFinalizationRecoveryRetainsAdmissionAfterEitherTransferFailure() throws {
        for failure in [MachineUpdateFinalizationRecoveryOwner.Stage.writerClosed, .admissionTransferred] {
            try withFinishingFixture { fixture, finishing, _ in
                let (owner, ordinary) = try restoreFinalizationOwner(finishing, fixture: fixture)
                defer { owner.close() }
                try fixture.files.reopen()
                XCTAssertThrowsError(try owner.resumeInLease(machine: fixture.machine, directory: fixture.directory) { stage in
                    guard stage == failure else { return }
                    XCTAssertThrowsError(try fixture.machine.inventory()) {
                        XCTAssertEqual($0 as? PreparationStoreError, .closed)
                    }
                    throw ReplacementFixtureError.injected
                }) {
                    XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
                }
                try owner.validateAdmission(directory: fixture.directory)
                XCTAssertThrowsError(try ordinary.acquireAdmission()) {
                    XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
                }
                try fixture.files.reopen()
                XCTAssertThrowsError(try owner.resumeInLease(machine: fixture.machine, directory: fixture.directory) { _ in
                    XCTFail("Retired owner ran another recovery stage")
                }) {
                    XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                }
                XCTAssertThrowsError(try owner.withSnapshotInLease(machine: fixture.machine, directory: fixture.directory) { _ in
                    XCTFail("Retired owner lent another finishing scope")
                }) {
                    XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                }
                try fixture.machine.machineUpdateFinalizationSnapshot(candidate: fixture.candidate, directory: fixture.directory).requireSame(as: finishing)
                owner.close()
                let rawAdmission = try ordinary.acquireAdmission()
                rawAdmission.close()
                XCTAssertEqual(try fixture.machine.machineUpdateActivation()?.phase, .finishing)
            }
        }
    }

    func testNativeFinishingRefusesOrdinaryIdentityAndLeavesTheOwnerUsable() throws {
        try XCTSkipIf(getuid() == 0 || geteuid() == 0, "Requires an ordinary user to check the native identity guard")
        try withFinishingFixture { fixture, finishing, _ in
            let (owner, _) = try restoreFinalizationOwner(finishing, fixture: fixture)
            defer { owner.close() }
            try fixture.files.reopen()
            XCTAssertTrue(try owner.resumeInLease(machine: fixture.machine, directory: fixture.directory) { _ in })
            try fixture.files.reopen()
            XCTAssertThrowsError(try owner.captureNativeFinalization(configurationPath: "/nonexistent-finishing-host",
                machine: fixture.machine, directory: fixture.directory)) {
                    XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                }
            XCTAssertThrowsError(try owner.makeNativeSettlementOwner(configurationPath: "/nonexistent-finishing-host",
                machine: fixture.machine, directory: fixture.directory)) {
                    XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                }
            try owner.validateAdmission(directory: fixture.directory)
            try owner.withSnapshotInLease(machine: fixture.machine, directory: fixture.directory) { scope in
                let current = try scope.read()
                XCTAssertThrowsError(try MachineUpdateNativeFinalization.capture(
                    configurationPath: "/nonexistent-finishing-host", scope: scope)) {
                        XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                    }
                XCTAssertThrowsError(try MachineUpdateInstalledPolicyRead.readNative(scope: scope,
                    candidate: fixture.candidate, verifyCurrent: { XCTFail("Ordinary user reached native policy verification") })) {
                        XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                    }
                try scope.read().requireSame(as: current)
            }
            try fixture.machine.machineUpdateFinalizationSnapshot(candidate: fixture.candidate, directory: fixture.directory).requireSame(as: finishing)
        }
    }

    func testInstalledReadinessPreservesUnregisteredAccountsAndSelectsCompletedRoles() throws {
        var pending: AccountPreparationIntent?
        try withFinishingFixture(registerGateway: true, beforeActivation: { pending = try self.reserveRestartAccount($0) }) {
            fixture, _, boundary in
            let unregistered = try XCTUnwrap(pending)
            let account = boundary.accountID, candidate = fixture.candidate
            let (readiness, expired) = try fixture.machine.withCurrentMachineUpdateFinalization(candidate: candidate,
                directory: fixture.directory, restart: fixture.restart) { scope in
                    let readiness = try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: candidate)
                    let (active, _) = try readiness.select(accountID: account, role: .authority)
                    let transport = try XCTUnwrap(active.configuration.transport.settingsHost)
                    let gateway = try XCTUnwrap(active.backend).gateway
                    let roles = readiness.inventory.requirements
                    XCTAssertEqual(roles.map(\.role), [.authority, .transport, .notificationGateway])
                    XCTAssertEqual(roles.map(\.executionUID), [0, transport.serviceUID, gateway.serviceUID])
                    XCTAssertEqual(roles.map(\.publicKey), [transport.runtime.services.authorityPublicKey,
                        try transport.runtime.transportPublicKeyX963, gateway.receiptPublicKey])
                    let configuration = fixture.snapshot.configuration.record, backend = fixture.snapshot.backend.record
                    for role in roles {
                        XCTAssertEqual(role.binding, active.configuration.binding)
                        XCTAssertEqual(role.code, active.configuration.host.codePolicy.entries.first { $0.role == role.role && $0.active })
                        XCTAssertEqual(role.configurationEpoch, configuration.id)
                        XCTAssertEqual(role.configurationRevision, configuration.revision)
                        XCTAssertEqual(role.backendEpoch, backend.id)
                        XCTAssertEqual(role.backendRevision, backend.revision)
                    }
                    XCTAssertEqual(readiness.inventory.accountIDs, [account])
                    XCTAssertEqual(readiness.inventory.preservedAccounts, fixture.inventory.preservedAccounts)
                    XCTAssertEqual(readiness.inventory.preservedAccounts, [unregistered.accountID])
                    let retained = try readiness.view.account(unregistered.accountID)
                    XCTAssertFalse(retained.scope.inInventory)
                    XCTAssertEqual(retained.preparation, unregistered)
                    XCTAssertThrowsError(try readiness.select(accountID: unregistered.accountID, role: .authority)) {
                        XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                    }
                    let selected = try MachineUpdateNativeFinalization.selectReadiness(host: active.configuration.host,
                        compatibility: readiness.view.compatibility, scope: scope, candidate: candidate)
                    XCTAssertEqual(selected?.focusedAccountID, account)
                    XCTAssertEqual(selected?.inventory.requirements, roles)
                    try readiness.requireCurrent(scope: scope, candidate: candidate)
                    return (readiness, scope)
                }
            XCTAssertThrowsError(try readiness.requireCurrent(scope: expired, candidate: candidate)) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            try fixture.machine.withCurrentMachineUpdateFinalization(candidate: candidate,
                directory: fixture.directory, restart: fixture.restart) { scope in
                    try readiness.requireCurrent(scope: scope, candidate: candidate)
                }
        }
    }

    func testNativeFinishingReadinessSelectionRejectsItsOwnPreservedHost() throws {
        try withFinishingFixture(registerForeground: false) { fixture, _, boundary in
            let configuration = try XCTUnwrap(fixture.snapshot.configuration.configuration(accountID: boundary.accountID))
            let host = configuration.completion.host
            XCTAssertTrue(host.installedReadinessEnabled)
            try fixture.machine.withCurrentMachineUpdateFinalization(candidate: fixture.candidate,
                directory: fixture.directory, restart: fixture.restart) { scope in
                    let compatibility = try scope.readCompatibility()
                    XCTAssertNil(try MachineUpdateNativeFinalization.selectReadiness(host: configuration.startup.host,
                        compatibility: compatibility, scope: scope, candidate: fixture.candidate))
                    let plan = try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: fixture.candidate)
                    XCTAssertEqual(plan.inventory.preservedAccounts, [boundary.accountID])
                    XCTAssertThrowsError(try MachineUpdateNativeFinalization.selectReadiness(host: host,
                        compatibility: compatibility, scope: scope, candidate: fixture.candidate)) {
                            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                        }
                }
        }
    }

    func testNativeFinishingReadinessSelectsItsHostAmongTwoRegisteredHostsWithMixedReadiness() throws {
        try withFinishingFixture(registerSecondForeground: true) { fixture, finishing, boundary in
            let candidate = fixture.candidate
            let enabledID = boundary.accountID
            let disabledID = try XCTUnwrap(finishing.inventory.accounts.first { $0.accountID != enabledID }).accountID
            XCTAssertEqual(finishing.inventory.accounts.count, 2)
            XCTAssertEqual(Set(fixture.inventory.accountIDs), Set([enabledID, disabledID]))
            try fixture.machine.withCurrentMachineUpdateFinalization(candidate: candidate,
                directory: fixture.directory, restart: fixture.restart) { scope in
                    let compatibility = try scope.readCompatibility()
                    let view = try MachineUpdateInstalledRuntimeView(compatibility: compatibility, candidate: candidate)
                    let enabled = try XCTUnwrap(view.account(enabledID).configuration).host
                    let disabled = try XCTUnwrap(view.account(disabledID).configuration).host
                    XCTAssertTrue(enabled.installedReadinessEnabled)
                    XCTAssertFalse(disabled.installedReadinessEnabled)
                    XCTAssertEqual(try view.account(enabledID).provisioning?.jobsRegistered, true)
                    XCTAssertEqual(try view.account(disabledID).provisioning?.jobsRegistered, true)
                    let selected = try XCTUnwrap(MachineUpdateNativeFinalization.selectReadiness(host: enabled,
                        compatibility: compatibility, scope: scope, candidate: candidate))
                    XCTAssertEqual(selected.focusedAccountID, enabledID)
                    XCTAssertEqual(selected.inventory.accountIDs, [enabledID])
                    XCTAssertTrue(selected.inventory.preservedAccounts.isEmpty)
                    XCTAssertEqual(selected.unselectedRegisteredAccounts, [disabledID])
                    XCTAssertThrowsError(try MachineUpdateInstalledTerminalReadBridge(plan: selected, candidate: candidate,
                        readFinishing: { XCTFail("A focused plan reached the finishing reader"); throw ReplacementFixtureError.injected },
                        readStable: { XCTFail("A focused plan reached the stable reader"); throw ReplacementFixtureError.injected })) {
                            XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                        }
                    try selected.requireCurrent(scope: scope, candidate: candidate)
                    XCTAssertNil(try MachineUpdateNativeFinalization.selectReadiness(host: disabled,
                        compatibility: compatibility, scope: scope, candidate: candidate))
                    XCTAssertThrowsError(try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: candidate)) {
                        XCTAssertEqual($0 as? MachineUpdateHealthCoordinatorError, .installedReadinessDisabled)
                    }
                }
        }
    }

    func testCompletionFileCoordinatorPublishesBothAccounts() throws {
        try withFinishingFixture(registerSecondForeground: true, publishCompletionFiles: true) { _, finishing, _ in
            XCTAssertEqual(finishing.inventory.accounts.count, 2)
        }
    }

    private final class InstalledActivity: OwnedReleaseActivity {
        let closed = Mutex(false)
        func validate() throws {
            guard !closed.withLock({ $0 }) else { throw JournalLeaseError.invalidated }
        }
        func close() { closed.withLock { $0 = true } }
    }

    private final class InstalledAccount: OwnedMachineUpdateInstalledReadinessAccount {
        let accountID: Data
        let replies: [MachineUpdateAuthenticatedRoleReply]
        let ordinary = Mutex(true)
        let closes = Mutex(0)
        let beforeProof: @Sendable () async throws -> Void

        init(accountID: Data, replies: [MachineUpdateAuthenticatedRoleReply] = [],
            beforeProof: @escaping @Sendable () async throws -> Void = {}) {
            self.accountID = accountID
            self.replies = replies
            self.beforeProof = beforeProof
        }
        func check() async throws -> [MachineUpdateAuthenticatedRoleReply] {
            try await beforeProof()
            return replies
        }
        func validate() throws {}
        func validateOrdinaryReadiness() throws {
            guard ordinary.withLock({ $0 }) else { throw JournalLeaseError.invalidated }
        }
        func close() async throws { closes.withLock { $0 += 1 } }
    }

    private func installedReadinessFixture(twoAccounts: Bool = false, gateway: Bool = false) throws
        -> (MachineUpdateInstalledReadinessPlan, SignedReleaseEvidence, [Data: [MachineUpdateAuthenticatedRoleReply]]) {
        var second: RuntimePreparationMaterial?
        var result: (MachineUpdateInstalledReadinessPlan, SignedReleaseEvidence, [Data: [MachineUpdateAuthenticatedRoleReply]])?
        try withFinishingFixture(registerGateway: gateway, registerSecondForeground: twoAccounts, enableSecondReadiness: twoAccounts,
            didPrepareSecondMaterial: { second = $0 }) { fixture, _, _ in
                let plan = try fixture.machine.withCurrentMachineUpdateFinalization(candidate: fixture.candidate,
                    directory: fixture.directory, restart: fixture.restart) {
                        try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: fixture.candidate)
                    }
                let runtime = fixture.files.f
                var replies: [Data: [MachineUpdateAuthenticatedRoleReply]] = [:]
                if !gateway {
                    let limits = try CBORLimits(maxBytes: 16_384, maxDepth: 1, maxItems: 9)
                    for requirement in plan.inventory.requirements {
                        let account = requirement.binding.accountID
                        let key: P256.Signing.PrivateKey
                        if requirement.role == .authority {
                            key = runtime.f.signingKey
                        } else {
                            XCTAssertEqual(requirement.role, .transport)
                            let material = account == runtime.account.accountID ? runtime.material : try XCTUnwrap(second)
                            guard case .map(let fields) = try DeterministicCBOR.decode(material.transportIdentity, limits: limits),
                                  case .bytes(let privateKey) = fields[2] else { throw ReplacementFixtureError.signature }
                            key = try .init(x963Representation: privateKey)
                        }
                        let challenge = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
                        let reply = try MachineUpdateRoleChallengeSession.answer(challenge.request, expected: requirement,
                            verifyCurrent: {}, sign: { try key.signature(for: $0).rawRepresentation })
                        replies[account, default: []].append(try challenge.accept(reply, authenticatePeer: { _ in }))
                    }
                }
                result = (plan, fixture.candidate, replies)
            }
        return try XCTUnwrap(result)
    }

    func testInstalledReadinessChecksBothAccountsConcurrentlyAndLendsTheProofOnce() async throws {
        let (plan, candidate, replies) = try installedReadinessFixture(twoAccounts: true)
        let activity = InstalledActivity()
        let terminal = try MachineUpdateInstalledTerminalReadBridge(plan: plan, candidate: candidate,
            readFinishing: { plan }, readStable: { throw ReplacementFixtureError.injected })
        let started = Mutex(0)
        let owners = try plan.inventory.accountIDs.map { account in
            InstalledAccount(accountID: account, replies: try XCTUnwrap(replies[account]), beforeProof: {
                try activity.validate()
                started.withLock { $0 += 1 }
                let clock = ContinuousClock()
                let deadline = clock.now + .seconds(2)
                while started.withLock({ $0 }) < 2 {
                    guard clock.now < deadline else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
                    try await Task.sleep(for: .milliseconds(10))
                }
            })
        }
        XCTAssertEqual(owners.count, 2)
        let coordinator = try MachineUpdateInstalledReadinessCoordinator(plan: plan, candidate: candidate,
            terminal: terminal, activity: activity, makeAccount: { account, _ in
                try XCTUnwrap(owners.first { $0.accountID == account })
            })
        let expired = try await coordinator.withVerifiedReadiness { scope in
            XCTAssertEqual(scope.inventory.accountIDs, plan.inventory.accountIDs)
            XCTAssertFalse(scope.isExpired)
            try scope.validate()
            try activity.validate()
            XCTAssertEqual(owners.map { $0.closes.withLock { $0 } }, [0, 0])
            return scope
        }
        XCTAssertTrue(expired.isExpired)
        XCTAssertEqual(owners.map { $0.closes.withLock { $0 } }, [0, 0])
        XCTAssertFalse(activity.closed.withLock { $0 })
        do {
            try await coordinator.withVerifiedReadiness { _ in XCTFail("Readiness scope was reused") }
            XCTFail("The coordinator lent readiness twice")
        } catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .busy) }
        try await coordinator.close()
        XCTAssertEqual(owners.map { $0.closes.withLock { $0 } }, [1, 1])
        XCTAssertTrue(activity.closed.withLock { $0 })
    }

    func testInstalledReadinessWrapperRejectsAnUnboundPlanAndAChangedRead() async throws {
        let (plan, candidate, _) = try installedReadinessFixture()
        let (other, otherCandidate, _) = try installedReadinessFixture()
        let reads = Mutex(0)
        let terminal = try MachineUpdateInstalledTerminalReadBridge(plan: plan, candidate: candidate,
            readFinishing: {
                reads.withLock { $0 += 1 }
                return other
            }, readStable: { throw ReplacementFixtureError.injected })
        let activity = InstalledActivity()
        let makeAccount: @Sendable (Data, [MachineUpdateHealthInventory.Requirement]) async throws -> any OwnedMachineUpdateInstalledReadinessAccount = { _, _ in
            XCTFail("A changed plan reached the peer owner")
            throw ReplacementFixtureError.injected
        }
        XCTAssertThrowsError(try MachineUpdateInstalledReadinessCoordinator(plan: other, candidate: otherCandidate,
            terminal: terminal, activity: activity, makeAccount: makeAccount)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        XCTAssertEqual(reads.withLock { $0 }, 0)
        let coordinator = try MachineUpdateInstalledReadinessCoordinator(plan: plan, candidate: candidate,
            terminal: terminal, activity: activity, makeAccount: makeAccount)
        do {
            try await coordinator.withVerifiedReadiness { _ in XCTFail("A changed plan verified") }
            XCTFail("The coordinator accepted a changed plan")
        } catch { XCTAssertEqual(error as? PreparationStoreError, .staleRevision) }
        XCTAssertEqual(reads.withLock { $0 }, 1)
        try await coordinator.close()
        XCTAssertTrue(activity.closed.withLock { $0 })
    }

    func testInstalledReadinessRevalidatesOrdinaryOwnersBeforeReturning() async throws {
        let (plan, candidate, replies) = try installedReadinessFixture()
        let account = try XCTUnwrap(plan.inventory.accountIDs.first)
        let owner = InstalledAccount(accountID: account, replies: try XCTUnwrap(replies[account]))
        let activity = InstalledActivity()
        let terminal = try MachineUpdateInstalledTerminalReadBridge(plan: plan, candidate: candidate,
            readFinishing: { plan }, readStable: { throw ReplacementFixtureError.injected })
        let coordinator = try MachineUpdateRestartHealthCoordinator(plan: plan, candidate: candidate,
            terminal: terminal, activity: activity, makeAccount: { _, _ in owner })
        do {
            try await coordinator.withVerifiedInstalledReadiness { scope in
                try scope.validate()
                owner.ordinary.withLock { $0 = false }
            }
            XCTFail("Unavailable ordinary runtime verified")
        } catch { XCTAssertEqual(error as? JournalLeaseError, .invalidated) }
        XCTAssertEqual(owner.closes.withLock { $0 }, 1)
        XCTAssertTrue(activity.closed.withLock { $0 })
    }

    func testInstalledReadinessCannotRecoverAGatewayJournal() async throws {
        let (plan, candidate, _) = try installedReadinessFixture(gateway: true)
        let account = try XCTUnwrap(plan.inventory.accountIDs.first)
        XCTAssertTrue(plan.inventory.requirements(accountID: account).contains { $0.role == .notificationGateway })
        let owner = InstalledAccount(accountID: account, beforeProof: {
            throw MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired
        })
        let activity = InstalledActivity()
        let terminal = try MachineUpdateInstalledTerminalReadBridge(plan: plan, candidate: candidate,
            readFinishing: { plan }, readStable: { throw ReplacementFixtureError.injected })
        let coordinator = try MachineUpdateRestartHealthCoordinator(plan: plan, candidate: candidate,
            terminal: terminal, activity: activity, makeAccount: { _, _ in owner })
        do {
            try await coordinator.withVerifiedInstalledReadiness { _ in XCTFail("Unready Gateway verified") }
            XCTFail("Unready Gateway returned")
        } catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .installedGatewayRecoveryRequired) }
        XCTAssertEqual(owner.closes.withLock { $0 }, 1)
        XCTAssertTrue(activity.closed.withLock { $0 })
        try await coordinator.close()
        XCTAssertEqual(owner.closes.withLock { $0 }, 1)
    }

    func testInstalledNativeOwnerSelectionUsesOnlyRegisteredCompletionPeers() throws {
        for registered in [false, true] {
            try withFinishingFixture(registerGateway: registered, publishGatewayWithoutRegistration: !registered) { fixture, _, boundary in
                try fixture.machine.withCurrentMachineUpdateFinalization(candidate: fixture.candidate,
                    directory: fixture.directory, restart: fixture.restart) { scope in
                        let plan = try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: fixture.candidate)
                        let selected = try MachineUpdateNativeInstalledReadiness.select(accountID: boundary.accountID, plan: plan)
                        XCTAssertEqual(selected.authority, try plan.selectAuthority(host: selected.host))
                        XCTAssertEqual(selected.transport.policyStage, .completion)
                        XCTAssertEqual(selected.transport.releaseBinding, selected.authority.binding)
                        if registered {
                            let (account, _) = try plan.select(accountID: boundary.accountID, role: .notificationGateway)
                            let gateway = try XCTUnwrap(account.backend).gateway
                            XCTAssertEqual(selected.gateway, account.configuration.gateway)
                            XCTAssertEqual(selected.registration, gateway.registration)
                        } else {
                            let retained = try plan.view.account(boundary.accountID)
                            XCTAssertEqual(retained.gateway?.configurationPublished, true)
                            XCTAssertEqual(retained.gateway?.jobRegistered, false)
                            XCTAssertNil(selected.gateway)
                            XCTAssertNil(selected.registration)
                        }
                        XCTAssertThrowsError(try MachineUpdateNativeInstalledReadiness.select(
                            accountID: Data(repeating: 255, count: 16), plan: plan)) {
                                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                            }
                    }
            }
        }
    }

    func testStableReleaseRecordBindsTheFinishingArchiveAndRejectsFocusedReadiness() throws {
        try withFinishingFixture { fixture, finishing, boundary in
            let candidate = fixture.candidate
            try fixture.machine.withCurrentMachineUpdateFinalization(candidate: candidate,
                directory: fixture.directory, restart: fixture.restart) { scope in
                    let plan = try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: candidate)
                    let completed = try finishing.activation.completing()
                    let proposal = try MachineUpdateStableReleaseRecord(readiness: plan, completed: completed, candidate: candidate)
                    let decoded = try MachineUpdateStableReleaseRecord.decode(proposal.encoded)
                    XCTAssertEqual(try decoded.encoded, try proposal.encoded)
                    XCTAssertEqual(decoded.completed, completed)
                    XCTAssertEqual(decoded.finishing, finishing.activation)
                    XCTAssertEqual(decoded.historicalSourceDigest, fixture.snapshot.backend.record.currentSourceDigest)
                    try decoded.requireCurrentInventory(finishing.inventory, epoch: finishing.installed, candidate: candidate)
                    XCTAssertThrowsError(try decoded.requireCurrentInventory(fixture.snapshot.source.replacement.inventory,
                        epoch: finishing.installed, candidate: candidate)) {
                            XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                        }
                    let focused = try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: candidate,
                        focusedAccountID: boundary.accountID)
                    XCTAssertThrowsError(try MachineUpdateStableReleaseRecord(readiness: focused, completed: completed, candidate: candidate)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                    }
                    XCTAssertThrowsError(try MachineUpdateStableReleaseRecord.requireFormats(candidate)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                    }
                    try scope.readRetainedSource().actual.requireSame(as: finishing)
                }
        }
    }

    private func stableFixtureAccess(_ fixture: CompletionFixture, finishing: MachineUpdateFinalizationSnapshot)
        throws -> MachineUpdateRestartSharedActivity {
        let anchor = fixture.files.f.f.root.path
        let activity = try ReleaseActivityBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
            owner: getuid())
        return try MachineUpdateRestartSharedActivity(restart: fixture.restart, activity: activity,
            directory: fixture.directory, expectedMachine: finishing.admission.machine, macID: finishing.inventory.macID,
            installationID: finishing.inventory.installationID, activationAttempt: finishing.activation.attemptID)
    }

    private func stableFixtureLoan(_ fixture: CompletionFixture, finishing: MachineUpdateFinalizationSnapshot)
        throws -> MachineUpdateRestartReadinessLoan {
        try stableFixtureAccess(fixture, finishing: finishing).acquireShared()
    }

    func testStableSetupSelectsTheUnconfiguredRetainedAccountAndItsOriginalInventory() throws {
        var reserved: AccountPreparationIntent?
        try withFinishingFixture(stableFormats: true, beforeActivation: { reserved = try self.reserveRestartAccount($0) }) {
            fixture, finishing, boundary in
            let preparation = try XCTUnwrap(reserved)
            let machine = fixture.machine, candidate = fixture.candidate, directory = fixture.directory
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try machine.withCurrentMachineUpdateReadiness(candidate: candidate, directory: directory, loan: loan) {
                try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: candidate)
            }
            XCTAssertThrowsError(try machine.stableRuntimeSource(candidate: candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            _ = try machine.commitStableMachineUpdate(expected: plan, candidate: candidate, directory: directory, loan: loan) { _, _ in }
            let owner = LocalAccountIdentity(uid: preparation.ownerUID, primaryGroupID: preparation.ownerUID,
                directoryID: preparation.directoryID)
            let setup = try machine.stableAccountSetupSnapshot(owner: owner, candidate: candidate)
            XCTAssertEqual(setup.preparation, preparation)
            XCTAssertEqual(setup.account?.origin, .retained)
            XCTAssertEqual(setup.account?.inInventory, false)
            let source = setup.source
            XCTAssertEqual(try source.unconfiguredRetainedAccount(accountID: preparation.accountID, ownerUID: owner.uid).accountID,
                preparation.accountID)
            XCTAssertEqual(try source.provisioningInventory(accountID: preparation.accountID, ownerUID: owner.uid,
                releaseDigest: preparation.releaseDigest), fixture.snapshot.source.replacement.inventory)
            XCTAssertThrowsError(try source.account(preparation.accountID, ownerUID: owner.uid)) {
                XCTAssertEqual($0 as? PreparationStoreError, .notFound)
            }
            XCTAssertThrowsError(try machine.stableRuntimePreparationSnapshot(owner: owner, candidate: candidate)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .incomplete)
            }
            let current = try XCTUnwrap(source.accounts.first { $0.accountID == boundary.accountID })
            let active = try XCTUnwrap(current.preparation)
            let activeOwner = LocalAccountIdentity(uid: active.ownerUID, primaryGroupID: active.ownerUID,
                directoryID: active.directoryID)
            let runtime = try machine.stableRuntimePreparationSnapshot(owner: activeOwner, candidate: candidate)
            XCTAssertEqual(runtime.preparation, active)
            XCTAssertTrue(runtime.state.configurationPublished)
            XCTAssertEqual(runtime.plan, runtime.state.reference?.services)
            try runtime.requireCurrent(machine: machine, candidate: candidate)
            XCTAssertThrowsError(try machine.retainedSetupPolicyMaterial(owner: activeOwner, candidate: candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertThrowsError(try source.unconfiguredRetainedAccount(accountID: current.accountID, ownerUID: current.ownerUID)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            let foreign = LocalAccountIdentity(uid: owner.uid, primaryGroupID: owner.primaryGroupID, directoryID: UUID())
            XCTAssertThrowsError(try machine.stableAccountSetupSnapshot(owner: foreign, candidate: candidate)) {
                XCTAssertEqual($0 as? LocalAccountLookupError, .ownershipChanged)
            }
            try setup.requireCurrent(machine: machine, candidate: candidate)
            try loan.validate()
        }
    }

    /// Supplies immutable stable values only. It grants no reservation writer or native authority.
    static func withStableAccountReservationValues(_ body: (MachineUpdateStableRuntimeSource, SignedReleaseEvidence) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testStableActivationSnapshotReadsTheExactInstalledSelectionWithoutWriting"))
        try suite.withStableActivationReadFixture { fixture, _, snapshot in
            try body(snapshot.runtime.setup.source, fixture.candidate)
        }
    }

    /// Supplies a real owned store and machine admission. It grants no installed caller or native credential authority.
    static func withStableAccountReservationWriterFixture(_ body: (StableAccountReservationWriterFixture) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testStableActivationSnapshotReadsTheExactInstalledSelectionWithoutWriting"))
        try suite.withFinishingFixture(stableFormats: true) { fixture, finishing, _ in
            let loan = try suite.stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try fixture.machine.withCurrentMachineUpdateReadiness(candidate: fixture.candidate,
                directory: fixture.directory, loan: loan) {
                    try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: fixture.candidate)
                }
            _ = try fixture.machine.commitStableMachineUpdate(expected: plan, candidate: fixture.candidate,
                directory: fixture.directory, loan: loan) { _, _ in }
            loan.close(); fixture.restart.close()
            let anchor = fixture.files.f.f.root.path
            let activity = try ReleaseActivityBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
                owner: getuid())
            let gate = try UpdateAdmissionBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
                owner: getuid(), expected: finishing.admission.machine)
            let admittedDirectory = try ReleaseDestinationLease(anchor: anchor, relativeDirectory: "machine", owner: getuid())
            let admission = try UpdateOrdinaryAdmissionLease(activity: activity, admission: gate,
                directory: admittedDirectory, expected: finishing.admission.machine)
            defer { admission.close() }
            let source = try fixture.machine.stableRuntimeSource(candidate: fixture.candidate)
            let uid = try XCTUnwrap(source.accounts.map(\.ownerUID).max()) + 1
            let owner = LocalAccountIdentity(uid: uid, primaryGroupID: uid, directoryID: UUID())
            let template = try XCTUnwrap(source.preparations.first).initialAuthority
            let retained = try XCTUnwrap(source.accounts.first { $0.origin == .retained }?.preparation)
            let retainedOwner = LocalAccountIdentity(uid: retained.ownerUID, primaryGroupID: getgid(), directoryID: retained.directoryID)
            let policy = try AuthorityCodePolicy(entries: template.codePolicy.entries.map { entry in
                let component = try XCTUnwrap(fixture.candidate.manifest.components.first { $0.role == entry.role })
                return try .init(role: entry.role, teamID: XCTUnwrap(component.teamID), identifier: component.identifier,
                    installedGeneration: component.generation, minimumGeneration: component.generation,
                    codeDirectoryHash: XCTUnwrap(fixture.candidate.codeDirectoryHashes[entry.role]), active: entry.active)
            })
            try body(.init(machine: { fixture.machine }, owner: owner, retainedOwner: retainedOwner, candidate: fixture.candidate,
                directory: fixture.directory, admission: admission, gate: gate, activity: activity, initial: { mac, account in
                    let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
                    let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                        0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(AccountPreparationIntent.randomID()),
                        4: .unsigned(1), 5: .unsigned(AuditEpochCause.initial.rawValue), 6: .null, 7: .null, 8: .null]),
                        limits: limits), limits: limits)
                    return AuthorityJournalInitialization(descriptor: descriptor, codePolicy: policy,
                        capabilities: template.capabilities, allowedContracts: template.allowedContracts)
                }, reopen: { hook in try fixture.files.reopen(hook: hook) }, mutate: { sql in
                    try fixture.machine.close(); try fixture.files.sql(sql); try fixture.files.reopen()
                }, scalar: { try fixture.files.f.f.sql($0) }))
        }
    }

    /// Uses owned metadata fixtures. These reads prove no current files, native health, or writer authority.
    /// Supplies owned installed metadata only. The callback grants no native identity, file custody, or startup authority.
    static func withInstalledRetainedRuntimeViewFixture(_ body: (PreparationIntentStore, SignedReleaseEvidence,
        MachineUpdateStableRuntimePreparationSnapshot) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testStableActivationSnapshotReadsTheExactInstalledSelectionWithoutWriting"))
        try suite.withStableActivationReadFixture { fixture, _, snapshot in
            let before = try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)
            try body(fixture.machine, fixture.candidate, snapshot.runtime)
            try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate).requireSame(as: before)
        }
    }

    private func withStableActivationReadFixture(registerSecondForeground: Bool = false,
        _ body: (CompletionFixture, LocalAccountIdentity, MachineUpdateStableRuntimeActivationSnapshot) throws -> Void) throws {
        try withFinishingFixture(registerSecondForeground: registerSecondForeground, stableFormats: true,
            enableSecondReadiness: registerSecondForeground) {
            fixture, finishing, boundary in
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try fixture.machine.withCurrentMachineUpdateReadiness(candidate: fixture.candidate,
                directory: fixture.directory, loan: loan) { try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: fixture.candidate) }
            _ = try fixture.machine.commitStableMachineUpdate(expected: plan, candidate: fixture.candidate,
                directory: fixture.directory, loan: loan) { _, _ in }
            let stable = try fixture.machine.stableRuntimeSource(candidate: fixture.candidate)
            let account = try XCTUnwrap(stable.accounts.first { $0.accountID == boundary.accountID }?.preparation)
            let owner = LocalAccountIdentity(uid: account.ownerUID, primaryGroupID: getgid(), directoryID: account.directoryID)
            let snapshot = try fixture.machine.stableRuntimeActivationSnapshot(owner: owner, candidate: fixture.candidate)
            try body(fixture, owner, snapshot)
        }
    }

    func testStableActivationSnapshotReadsTheExactInstalledSelectionWithoutWriting() throws {
        try withStableActivationReadFixture { fixture, owner, snapshot in
            let before = try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)
            let runtime = try fixture.machine.stableRuntimePreparationSnapshot(owner: owner, candidate: fixture.candidate)
            let state = try fixture.machine.runtimeActivation(accountID: runtime.preparation.accountID)
            try snapshot.runtime.requireSame(as: runtime)
            try snapshot.requireState(state)
            try snapshot.requireCurrent(machine: fixture.machine, candidate: fixture.candidate)
            XCTAssertEqual(snapshot.origin, .retained)
            let installed = try XCTUnwrap(snapshot.installed)
            XCTAssertEqual(try installed.encoded,
                try before.installed.configuration().configuration(accountID: runtime.preparation.accountID)?.completion.encoded)
            XCTAssertEqual(snapshot.selectedHost?.canonicalBytes, installed.host.canonicalBytes)
            XCTAssertNil(installed.gateway.retainedSetupBinding)
            XCTAssertNil(installed.gateway.retainedSetupCompletionBinding)
            XCTAssertNotEqual(installed.gateway.installedReleaseDigest, runtime.plan.releaseDigest)
            XCTAssertThrowsError(try installed.gateway.validate(account: runtime.preparation, inventory: before.inventory)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            XCTAssertNoThrow(try installed.gateway.validateRelease(fixture.candidate))
            XCTAssertNoThrow(try installed.binding.requirePolicy(installed.gateway.codePolicy, stage: .completion))
            XCTAssertFalse(snapshot.requiresRetainedMaterialCustody)
            XCTAssertEqual(try snapshot.progress, try SetupActivationProgress(account: runtime.preparation,
                runtime: runtime.state, state: state))
            XCTAssertEqual(snapshot.description, "MachineUpdateStableRuntimeActivationSnapshot(redacted)")
            XCTAssertEqual(snapshot.debugDescription, snapshot.description)
            XCTAssertThrowsError(try fixture.machine.writeInventory(before.inventory, expectedRevision: before.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate).requireSame(as: before)
        }
    }

    func testStableActivationSnapshotRequiresExactStateAndFreshMachineFacts() throws {
        try withStableActivationReadFixture { fixture, owner, snapshot in
            XCTAssertTrue(snapshot.state.jobsRegistered)
            let plan = try XCTUnwrap(snapshot.state.plan)
            XCTAssertNoThrow(try snapshot.requireState(.init(plan: plan, jobsRegistered: true)))
            for changed in [RuntimeActivationState(plan: plan, jobsRegistered: false), .init(plan: nil, jobsRegistered: true)] {
                XCTAssertThrowsError(try snapshot.requireState(changed)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
            let withoutPlan = try MachineUpdateStableRuntimeActivationSnapshot(runtime: snapshot.runtime,
                state: .init(plan: nil, jobsRegistered: false), candidate: fixture.candidate)
            XCTAssertNoThrow(try withoutPlan.requireSame(as: withoutPlan))
            XCTAssertThrowsError(try withoutPlan.requireSame(as: snapshot)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try MachineUpdateStableRuntimeActivationSnapshot(runtime: snapshot.runtime,
                state: .init(plan: nil, jobsRegistered: true), candidate: fixture.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
                }
            let account = snapshot.runtime.preparation.accountID.map { String(format: "%02x", $0) }.joined()
            try fixture.machine.close()
            try fixture.files.sql("UPDATE runtime_activation_v1 SET registered=0 WHERE account=X'\(account)'")
            try fixture.files.reopen()
            let changed = try fixture.machine.stableRuntimeActivationSnapshot(owner: owner, candidate: fixture.candidate)
            XCTAssertFalse(changed.state.jobsRegistered)
            XCTAssertEqual(try changed.state.plan?.encoded, try snapshot.state.plan?.encoded)
            XCTAssertThrowsError(try snapshot.requireCurrent(machine: fixture.machine, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    static func withRetainedMaterialValueFixture(_ body: (PreparationIntentStore, SignedReleaseEvidence,
        MachineUpdateRetainedSetupMaterialSnapshot) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testStableActivationSnapshotSeparatesUnpublishedMaterialFromPublishedFacts"))
        try suite.withUnpublishedActivationReadFixture { fixture, owner, _ in
            let runtime = try fixture.machine.stableRuntimePreparationSnapshot(owner: owner, candidate: fixture.candidate)
            let actual = try MachineUpdateRetainedSetupMaterialSnapshot(runtime: runtime,
                activation: fixture.machine.runtimeActivation(accountID: runtime.preparation.accountID))
            try body(fixture.machine, fixture.candidate, actual)
            try actual.requireCurrent(machine: fixture.machine, candidate: fixture.candidate)
        }
    }

    private func withUnpublishedActivationReadFixture(policySourceFormats: Bool = false, completionReaderFormats: Bool = false, promotionProposalFormats: Bool = false,
        didPrepareMaterial: (RuntimePreparationMaterial) -> Void = { _ in },
        additionalBeforeActivation: (BoundAdmissionRegistrationFixture) throws -> Void = { _ in },
        _ body: (CompletionFixture, LocalAccountIdentity, MachineUpdateRetainedSetupPolicyMaterial) throws -> Void) throws {
        var retained: AccountPreparationIntent?
        try withFinishingFixture(stableFormats: true, policyReaderFormats: policySourceFormats,
            completionReaderFormats: completionReaderFormats, promotionReaderFormats: completionReaderFormats,
            readinessReaderFormats: completionReaderFormats, retainedPolicySourceFormats: policySourceFormats, promotionProposalFormats: promotionProposalFormats,
            beforeActivation: {
                retained = try self.prepareSecondForeground($0, didPrepareMaterial: didPrepareMaterial).account
                try additionalBeforeActivation($0)
            }) { fixture, finishing, _ in
            let account = try XCTUnwrap(retained)
            let owner = LocalAccountIdentity(uid: account.ownerUID, primaryGroupID: getgid(), directoryID: account.directoryID)
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try fixture.machine.withCurrentMachineUpdateReadiness(candidate: fixture.candidate,
                directory: fixture.directory, loan: loan) { try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: fixture.candidate) }
            _ = try fixture.machine.commitStableMachineUpdate(expected: plan, candidate: fixture.candidate,
                directory: fixture.directory, loan: loan) { _, _ in }
            try body(fixture, owner, fixture.machine.retainedSetupPolicyMaterial(owner: owner, candidate: fixture.candidate))
        }
    }

    func testStableActivationSnapshotSeparatesUnpublishedMaterialFromPublishedFacts() throws {
        try withUnpublishedActivationReadFixture { fixture, owner, material in
            let state = RuntimeActivationState(plan: nil, jobsRegistered: false)
            let snapshot = try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(
                runtime: material.runtime, state: state, candidate: fixture.candidate)
            XCTAssertEqual(snapshot.origin, .retained)
            XCTAssertNil(snapshot.installed)
            XCTAssertNil(snapshot.selectedHost)
            XCTAssertTrue(snapshot.requiresRetainedMaterialCustody)
            XCTAssertNoThrow(try snapshot.requireSame(as: snapshot))
            XCTAssertThrowsError(try snapshot.progress) { XCTAssertEqual($0 as? RuntimeActivationError, .incomplete) }
            XCTAssertThrowsError(try fixture.machine.stableRuntimeActivationSnapshot(owner: owner, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            XCTAssertThrowsError(try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(
                runtime: material.runtime, state: .init(plan: nil, jobsRegistered: true), candidate: fixture.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
                }
            let missingReference = try MachineUpdateStableRuntimePreparationSnapshot(setup: material.runtime.setup,
                services: .init(plan: material.runtime.plan, complete: true),
                state: .init(reference: nil, configurationPublished: false), reservedNumbers: material.runtime.reservedNumbers)
            XCTAssertThrowsError(try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(
                runtime: missingReference, state: state, candidate: fixture.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
                }
        }
    }

    func testStableActivationSnapshotRejectsUnpublishedMaterialAfterInventoryEnrollment() throws {
        try withUnpublishedActivationReadFixture { fixture, owner, material in
            let state = RuntimeActivationState(plan: nil, jobsRegistered: false)
            XCTAssertNoThrow(try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(
                runtime: material.runtime, state: state, candidate: fixture.candidate))
            let source = material.runtime.setup.source, actual = source.actual, inventory = actual.inventory
            let account = try InstallationAccount(accountID: material.runtime.preparation.accountID, ownerUID: owner.uid)
            let enrolled = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID,
                revision: AccountPreparationIntent.randomID(), bundlePath: inventory.bundlePath, releaseDigest: inventory.releaseDigest,
                accounts: inventory.accounts + [account], services: inventory.services, formatVersion: inventory.formatVersion)
            let frame = MachineUpdateStableReleaseSnapshot(schemaVersion: actual.schemaVersion, inventory: enrolled,
                activation: actual.activation, admission: actual.admission, candidate: actual.candidate,
                installed: actual.installed, seal: actual.seal, currentRowsDigest: actual.currentRowsDigest)
            let enrolledSource = try MachineUpdateStableRuntimeSource(actual: frame, preparations: source.preparations,
                initializations: source.initializations, candidate: fixture.candidate)
            let setup = try MachineUpdateStableAccountSetupSnapshot(source: enrolledSource, owner: owner)
            let runtime = try MachineUpdateStableRuntimePreparationSnapshot(setup: setup,
                services: .init(plan: material.runtime.plan, complete: true), state: material.runtime.state,
                reservedNumbers: material.runtime.reservedNumbers)
            XCTAssertEqual(runtime.setup.account?.inInventory, true)
            XCTAssertThrowsError(try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(
                runtime: runtime, state: state, candidate: fixture.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
                }
        }
    }

    func testStableActivationSnapshotRejectsAnotherValidAccountsPlan() throws {
        try withStableActivationReadFixture(registerSecondForeground: true) { fixture, _, snapshot in
            let other = try XCTUnwrap(snapshot.runtime.setup.source.accounts.first {
                $0.accountID != snapshot.runtime.preparation.accountID && $0.inInventory
            }?.preparation)
            let owner = LocalAccountIdentity(uid: other.ownerUID, primaryGroupID: getgid(), directoryID: other.directoryID)
            let foreign = try fixture.machine.stableRuntimeActivationSnapshot(owner: owner, candidate: fixture.candidate)
            XCTAssertNoThrow(try foreign.requireCurrent(machine: fixture.machine, candidate: fixture.candidate))
            XCTAssertNotNil(foreign.state.plan)
            XCTAssertThrowsError(try MachineUpdateStableRuntimeActivationSnapshot(runtime: snapshot.runtime,
                state: foreign.state, candidate: fixture.candidate)) {
                    XCTAssertEqual($0 as? ServiceAccountProvisioningError, .changedScope)
                }
        }
    }

    private func replacingStableActivationInventory(_ inventory: InstallationInventory,
        in snapshot: MachineUpdateStableRuntimeActivationSnapshot, owner: LocalAccountIdentity,
        candidate: SignedReleaseEvidence) throws -> MachineUpdateStableRuntimePreparationSnapshot {
        let original = snapshot.runtime.setup.source, actual = original.actual
        let frame = MachineUpdateStableReleaseSnapshot(schemaVersion: actual.schemaVersion, inventory: inventory,
            activation: actual.activation, admission: actual.admission, candidate: actual.candidate,
            installed: actual.installed, seal: actual.seal, currentRowsDigest: actual.currentRowsDigest)
        let source = try MachineUpdateStableRuntimeSource(actual: frame, preparations: original.preparations,
            initializations: original.initializations, candidate: candidate)
        let setup = try MachineUpdateStableAccountSetupSnapshot(source: source, owner: owner)
        return try .init(setup: setup, services: .init(plan: snapshot.runtime.plan, complete: true),
            state: snapshot.runtime.state, reservedNumbers: snapshot.runtime.reservedNumbers)
    }

    func testStableActivationSnapshotRequiresBothInstalledHostDeclarations() throws {
        try withStableActivationReadFixture { fixture, owner, snapshot in
            let actual = snapshot.runtime.setup.source.actual, inventory = actual.inventory
            let host = try XCTUnwrap(snapshot.installed).host
            let control = try replacingStableActivationInventory(inventory, in: snapshot, owner: owner, candidate: fixture.candidate)
            XCTAssertNoThrow(try MachineUpdateStableRuntimeActivationSnapshot(runtime: control,
                state: snapshot.state, candidate: fixture.candidate))
            for role in [AuthorityCodeRole.authority, .transport] {
                let declaration = try XCTUnwrap(inventory.services.first {
                    $0.accountID == snapshot.runtime.preparation.accountID && $0.role == role
                })
                let services: [InstallationService]
                if role == .authority {
                    let other = try InstallationService(role: declaration.role, kind: declaration.kind,
                        domainUID: declaration.domainUID, executionUID: declaration.executionUID,
                        label: declaration.label + ".other", plistName: declaration.plistName, accountID: declaration.accountID)
                    services = inventory.services.map { $0 == declaration ? other : $0 }
                    XCTAssertEqual(services.count, inventory.services.count)
                } else {
                    services = inventory.services.filter { $0 != declaration }
                    XCTAssertEqual(services.count, inventory.services.count - 1)
                }
                let changed = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID,
                    revision: inventory.revision, bundlePath: inventory.bundlePath, releaseDigest: inventory.releaseDigest,
                    accounts: inventory.accounts, services: services, formatVersion: inventory.formatVersion)
                XCTAssertNoThrow(try actual.seal.requireCurrentInventory(changed, epoch: actual.installed, candidate: fixture.candidate))
                let runtime = try replacingStableActivationInventory(changed, in: snapshot, owner: owner, candidate: fixture.candidate)
                XCTAssertEqual(runtime.setup.account?.inInventory, true)
                XCTAssertThrowsError(try host.validate(inventory: changed, release: fixture.candidate, bundlePath: changed.bundlePath)) {
                    XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongInstallation)
                }
                XCTAssertThrowsError(try MachineUpdateStableRuntimeActivationSnapshot(runtime: runtime,
                    state: snapshot.state, candidate: fixture.candidate)) {
                        XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongInstallation)
                    }
            }
        }
    }

    func testStableActivationSnapshotRejectsAValidPlanForAnotherBundlePath() throws {
        try withStableActivationReadFixture { fixture, _, snapshot in
            let runtime = snapshot.runtime, source = runtime.setup.source, inventory = source.historicalInventory
            let initial = try XCTUnwrap(runtime.setup.account?.initialization)
            let control = try RuntimeActivationPlan(account: runtime.preparation, initialization: initial,
                runtime: runtime.state, inventory: inventory, gatewaySettingsRelease: fixture.previousRelease)
            XCTAssertNoThrow(try control.validate(account: runtime.preparation, reference: XCTUnwrap(runtime.state.reference)))
            XCTAssertNoThrow(try MachineUpdateStableRuntimeActivationSnapshot(runtime: runtime,
                state: .init(plan: control, jobsRegistered: false), candidate: fixture.candidate))
            let changed = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID,
                revision: inventory.revision, bundlePath: "/private/tmp/OtherRemozio.app", releaseDigest: inventory.releaseDigest,
                accounts: inventory.accounts, services: inventory.services, formatVersion: inventory.formatVersion)
            let plan = try RuntimeActivationPlan(account: runtime.preparation, initialization: initial,
                runtime: runtime.state, inventory: changed, gatewaySettingsRelease: fixture.previousRelease)
            XCTAssertNoThrow(try plan.validate(account: runtime.preparation, reference: XCTUnwrap(runtime.state.reference)))
            XCTAssertNotEqual(plan.bundlePath, source.actual.inventory.bundlePath)
            XCTAssertThrowsError(try MachineUpdateStableRuntimeActivationSnapshot(runtime: runtime,
                state: .init(plan: plan, jobsRegistered: false), candidate: fixture.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
                }
        }
    }

    func testStableActivationSnapshotRejectsAValidPlanBeforeRetainedPublication() throws {
        try withUnpublishedActivationReadFixture { fixture, _, material in
            let runtime = material.runtime, state = RuntimeActivationState(plan: nil, jobsRegistered: false)
            XCTAssertNoThrow(try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(
                runtime: runtime, state: state, candidate: fixture.candidate))
            let inventory = try runtime.setup.source.provisioningInventory(accountID: runtime.preparation.accountID,
                ownerUID: runtime.preparation.ownerUID, releaseDigest: runtime.preparation.releaseDigest)
            // The proposed values are local controls. The stored publication marker remains false.
            let published = RuntimePreparationState(reference: material.reference, configurationPublished: true)
            let plan = try RuntimeActivationPlan(account: runtime.preparation, initialization: material.initialization,
                runtime: published, inventory: inventory, gatewaySettingsRelease: fixture.previousRelease)
            XCTAssertNoThrow(try plan.validate(account: runtime.preparation, reference: material.reference))
            XCTAssertEqual(plan.bundlePath, runtime.setup.source.actual.inventory.bundlePath)
            XCTAssertFalse(runtime.state.configurationPublished)
            XCTAssertThrowsError(try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(
                runtime: runtime, state: .init(plan: plan, jobsRegistered: false), candidate: fixture.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
                }
        }
    }

    func testStableActivationSnapshotRejectsAValidForeignMaterialReference() throws {
        try withStableActivationReadFixture { fixture, _, snapshot in
            let runtime = snapshot.runtime, state = RuntimeActivationState(plan: nil, jobsRegistered: false)
            XCTAssertNoThrow(try MachineUpdateStableRuntimeActivationSnapshot(runtime: runtime, state: state, candidate: fixture.candidate))
            let original = try XCTUnwrap(runtime.state.reference), now = Date()
            let material = try RuntimePreparationMaterial.create(services: runtime.plan,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600),
                serviceActivity: original.serviceActivity, auditDeliveryVersion: original.auditDeliveryVersion)
            let reference = try material.reference
            XCTAssertNoThrow(try reference.validate(account: runtime.preparation, services: runtime.plan))
            XCTAssertNotEqual(reference, original)
            let changed = try MachineUpdateStableRuntimePreparationSnapshot(setup: runtime.setup,
                services: .init(plan: runtime.plan, complete: true),
                state: .init(reference: reference, configurationPublished: true), reservedNumbers: runtime.reservedNumbers)
            XCTAssertThrowsError(try MachineUpdateStableRuntimeActivationSnapshot(runtime: changed, state: state, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }

    /// Uses owned policy commits and injected rows. It proves no native publication or current file custody.
    /// Exposes owned read values only. The callback grants no native custody, publication, or dispatch authority.
    static func withRetainedInitialConfigurationValueFixture(recorded: Bool = true,
        _ body: (MachineUpdateRetainedSetupPolicySnapshot, AuthorityJournal.MachineUpdatePolicyBoundary,
            SignedReleaseEvidence, AuthorityCodePolicy, () throws -> Void) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testRetainedConfigurationInitialPreservesBindingAndLeavesMetadataUnchanged"))
        try suite.withRetainedPolicySourceFixture(recorded: recorded) { fixture, owner, source, snapshot, current in
            let before = try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)
            func verifyUnchanged() throws {
                try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate).requireSame(as: before)
                try fixture.machine.retainedSetupPolicySnapshot(owner: owner, candidate: fixture.candidate).requireSame(as: snapshot)
            }
            try body(snapshot, current, fixture.candidate, source.policy.source.policy, verifyUnchanged)
            try verifyUnchanged()
        }
    }

    private func withRetainedPolicySourceFixture(recorded: Bool = false, completionReaderFormats: Bool = false, promotionProposalFormats: Bool = false,
        didPrepareMaterial: (RuntimePreparationMaterial) -> Void = { _ in },
        additionalBeforeActivation: (BoundAdmissionRegistrationFixture) throws -> Void = { _ in },
        _ body: (CompletionFixture, LocalAccountIdentity, MachineUpdateRetainedSetupActivationSource,
            MachineUpdateRetainedSetupPolicySnapshot, AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Void) throws {
        try withUnpublishedActivationReadFixture(policySourceFormats: true, completionReaderFormats: completionReaderFormats, promotionProposalFormats: promotionProposalFormats, didPrepareMaterial: didPrepareMaterial, additionalBeforeActivation: additionalBeforeActivation) { fixture, owner, material in
            try withRetainedPolicyAfterStable(fixture: fixture, owner: owner, material: material,
                recorded: recorded, body)
        }
    }

    private func withRetainedPolicyAfterStable(fixture: CompletionFixture, owner: LocalAccountIdentity,
        material: MachineUpdateRetainedSetupPolicyMaterial, recorded: Bool,
        _ body: (CompletionFixture, LocalAccountIdentity, MachineUpdateRetainedSetupActivationSource,
            MachineUpdateRetainedSetupPolicySnapshot, AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Void) throws {
        let account = material.runtime.preparation.accountID
        let reader = try fixture.openPolicyPair(readOnly: true, accountID: account)
        defer { try? reader.close() }
        let source = try MachineUpdateRetainedSetupActivationSource.capture(owner: owner, machine: fixture.machine,
            journal: reader, candidate: fixture.candidate)
        let prepared = try MachineUpdateRetainedSetupPolicyIntentRecord(source: source)
        let empty = try fixture.machine.retainedSetupPolicySnapshot(owner: owner, candidate: fixture.candidate)
        XCTAssertNil(empty.intent)
        XCTAssertNoThrow(try prepared.requireSnapshot(empty.activation, candidate: fixture.candidate))
        try reader.close()
        let intent: MachineUpdateRetainedSetupPolicyIntentRecord
        let current: AuthorityJournal.MachineUpdatePolicyBoundary
        if recorded {
            let storage = try fixture.policyStorage(readOnly: false, accountID: account)
            defer { try? storage.close() }
            let commits = CheckpointedJournal(journal: storage.journal, continuity: storage.continuity)
            XCTAssertNotEqual(source.policy.startupPolicy, source.policy.source.policy)
            let policy = try commits.write(epoch: source.accountPolicy.checkpoint.journalEpoch) {
                try $0.installCodePolicy(source.policy.startupPolicy, expectedRevision: source.policy.source.revision)
            }
            let checkpoint = try storage.continuity.read().committed
            try storage.close()
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.encoded) as? [String: Any])
            fields["phase"] = MachineUpdateRetainedSetupPolicyIntentRecord.Phase.recorded.rawValue
            fields["committedPolicy"] = ["revision": policy.revision.uuidString, "bytes": try policy.storedBytes.base64EncodedString()]
            fields["committedCheckpoint"] = try checkpoint.bytes.base64EncodedString()
            intent = try .decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
            let fresh = try fixture.openPolicyPair(readOnly: true, accountID: account)
            defer { try? fresh.close() }
            current = try fresh.captureRetainedSetupPolicyBoundary(expected: material.initialization)
            XCTAssertEqual(current.policy, policy); XCTAssertEqual(current.checkpoint, checkpoint)
            try fresh.close()
        } else { intent = prepared; current = source.accountPolicy }
        func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
        let id = intent.id.uuidString.replacingOccurrences(of: "-", with: "")
        let revision = intent.revision.uuidString.replacingOccurrences(of: "-", with: "")
        let bytes = try hex(intent.encoded)
        try fixture.machine.close()
        if empty.activation.runtime.setup.source.actual.schemaVersion == 24 {
            try fixture.files.sql(MachineUpdateRetainedSetupPolicyStorage.createSQL)
        }
        try fixture.files.sql("PRAGMA user_version=25")
        try fixture.files.sql("INSERT INTO retained_setup_policy_intents_v1 VALUES(X'\(hex(account))',X'\(id)',X'\(revision)',X'\(bytes)')")
        try fixture.files.reopen()
        let snapshot = try fixture.machine.retainedSetupPolicySnapshot(owner: owner, candidate: fixture.candidate)
        XCTAssertEqual(snapshot.intent, intent)
        try body(fixture, owner, source, snapshot, current)
    }

    func testRetainedPolicySnapshotReconstructsTheExactPublicV2DigestAndRevision() throws {
        try withRetainedPolicySourceFixture { fixture, owner, source, snapshot, _ in
            let runtime = source.runtime, original = source.original
            let initialization = try XCTUnwrap(runtime.setup.account?.initialization)
            let reference = try XCTUnwrap(runtime.state.reference), policy = source.policy
            let checkpoint = source.accountPolicy.checkpoint
            let actual = runtime.setup.source.actual
            var fields: [UInt64: CBORValue] = [
                0: .text("remozio/retained-setup-activation-source/v2"),
                1: .bytes(actual.inventory.canonicalBytes), 2: .bytes(try actual.seal.encoded),
                3: .bytes(original.sourceDigest), 4: .bytes(try runtime.preparation.bytes),
                5: .bytes(try initialization.bytes), 6: .bytes(try runtime.plan.encoded), 7: .bytes(try reference.encoded),
                8: .bytes(try policy.source.storedBytes), 9: .bytes(try checkpoint.bytes),
                10: .bytes(try policy.startupPolicy.bytes), 11: .bytes(try policy.completionPolicy.bytes),
                12: .text(policy.source.revision.uuidString.lowercased())
            ]
            let limits = try CBORLimits(maxBytes: 1_048_576, maxDepth: 3, maxItems: 40)
            let expected = MachineUpdateActivationRecord.digest(try DeterministicCBOR.encode(.map(fields), limits: limits))
            XCTAssertEqual(expected, source.digest)
            XCTAssertEqual(try MachineUpdateRetainedSetupActivationSource.retainedScopeDigest(snapshot: snapshot.activation,
                sourcePolicy: policy.source, sourceCheckpoint: checkpoint, candidate: fixture.candidate), expected)
            let material = try fixture.machine.retainedSetupPolicyMaterial(owner: owner, candidate: fixture.candidate)
            XCTAssertEqual(try material.scopeDigest(policy: policy, checkpoint: checkpoint), expected)
            fields[0] = .text("remozio/retained-setup-activation-source/v1"); fields[12] = nil
            XCTAssertNotEqual(MachineUpdateActivationRecord.digest(try DeterministicCBOR.encode(.map(fields), limits: limits)), expected)
            let revised = AuthorityCodePolicySnapshot(revision: UUID(), policy: policy.source.policy, roleRevisions: policy.source.roleRevisions)
            XCTAssertEqual(try revised.storedBytes, try policy.source.storedBytes)
            XCTAssertNotEqual(try MachineUpdateRetainedSetupActivationSource.retainedScopeDigest(snapshot: snapshot.activation,
                sourcePolicy: revised, sourceCheckpoint: checkpoint, candidate: fixture.candidate), expected)
            let intent = try XCTUnwrap(snapshot.intent)
            var record = try XCTUnwrap(JSONSerialization.jsonObject(with: intent.encoded) as? [String: Any])
            record["sourcePolicy"] = ["revision": revised.revision.uuidString, "bytes": try revised.storedBytes.base64EncodedString()]
            let changed = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(
                JSONSerialization.data(withJSONObject: record, options: [.sortedKeys, .withoutEscapingSlashes]))
            XCTAssertNoThrow(try intent.requireSnapshot(snapshot.activation, candidate: fixture.candidate))
            XCTAssertThrowsError(try changed.requireSnapshot(snapshot.activation, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            let recordFields = try XCTUnwrap(JSONSerialization.jsonObject(with: intent.encoded) as? [String: Any])
            for (name, value): (String, Any) in [
                ("macID", Data(repeating: 61, count: 16).base64EncodedString()),
                ("installationID", Data(repeating: 62, count: 16).base64EncodedString()),
                ("accountID", Data(repeating: 63, count: 16).base64EncodedString()),
                ("ownerUID", owner.uid + 1),
                ("initializationDigest", Data(repeating: 64, count: 32).base64EncodedString()),
                ("sourceDigest", Data(repeating: 65, count: 32).base64EncodedString()),
                ("installedReleaseDigest", Data(repeating: 66, count: 32).base64EncodedString()),
            ] {
                var edited = recordFields; edited[name] = value
                let other = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(
                    JSONSerialization.data(withJSONObject: edited, options: [.sortedKeys, .withoutEscapingSlashes]))
                XCTAssertThrowsError(try other.requireSnapshot(snapshot.activation, candidate: fixture.candidate), name) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
        }
    }

    func testRetainedPolicyRecordedScopeRequiresObservedAccountsAndServicesToRemainCurrent() throws {
        try withRetainedPolicySourceFixture { fixture, owner, source, snapshot, _ in
            let runtime = snapshot.activation.runtime, inventory = runtime.setup.source.actual.inventory
            func digest(_ runtime: MachineUpdateStableRuntimePreparationSnapshot, _ observed: InstallationInventory) throws -> Data {
                try MachineUpdateRetainedSetupActivationSource.recordedScopeDigest(runtime: runtime,
                    observedInventory: observed, sourcePolicy: source.policy.source,
                    sourceCheckpoint: source.accountPolicy.checkpoint, candidate: fixture.candidate)
            }
            XCTAssertEqual(try digest(runtime, inventory), source.digest)
            let account = try InstallationAccount(accountID: runtime.preparation.accountID, ownerUID: owner.uid)
            let enrolled = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID,
                revision: AccountPreparationIntent.randomID(), bundlePath: inventory.bundlePath, releaseDigest: inventory.releaseDigest,
                accounts: inventory.accounts + [account], services: inventory.services, formatVersion: inventory.formatVersion)
            let afterEnrollment = try replacingStableActivationInventory(enrolled, in: snapshot.activation,
                owner: owner, candidate: fixture.candidate)
            XCTAssertEqual(afterEnrollment.setup.account?.inInventory, true)
            XCTAssertEqual(try digest(afterEnrollment, inventory), source.digest)
            XCTAssertNotEqual(try digest(afterEnrollment, enrolled), source.digest)
            XCTAssertThrowsError(try digest(runtime, enrolled)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            let declaration = try XCTUnwrap(inventory.services.first { $0.role == .authority && $0.kind == .daemon })
            let replacement = try InstallationService(role: declaration.role, kind: declaration.kind,
                domainUID: declaration.domainUID, executionUID: declaration.executionUID, label: declaration.label + ".other",
                plistName: declaration.plistName, accountID: declaration.accountID)
            let changed = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID,
                revision: inventory.revision, bundlePath: inventory.bundlePath, releaseDigest: inventory.releaseDigest,
                accounts: inventory.accounts, services: inventory.services.map { $0 == declaration ? replacement : $0 },
                formatVersion: inventory.formatVersion)
            XCTAssertNoThrow(try runtime.setup.source.actual.seal.requireCurrentInventory(changed,
                epoch: runtime.setup.source.actual.installed, candidate: fixture.candidate))
            XCTAssertEqual(changed.accounts, inventory.accounts)
            XCTAssertThrowsError(try digest(runtime, changed)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }

    func testRetainedPolicyRecordedScopeRequiresTheOriginalPolicyAndCheckpoint() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, source, snapshot, current in
            let runtime = snapshot.activation.runtime, inventory = runtime.setup.source.actual.inventory
            func digest(_ policy: AuthorityCodePolicySnapshot, _ checkpoint: ContinuityCheckpoint) throws -> Data {
                try MachineUpdateRetainedSetupActivationSource.recordedScopeDigest(runtime: runtime,
                    observedInventory: inventory, sourcePolicy: policy, sourceCheckpoint: checkpoint, candidate: fixture.candidate)
            }
            XCTAssertEqual(try digest(source.policy.source, source.accountPolicy.checkpoint), source.digest)
            XCTAssertNotEqual(current.policy.policy, source.policy.source.policy)
            XCTAssertThrowsError(try digest(current.policy, source.accountPolicy.checkpoint)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertNotEqual(current.checkpoint, source.accountPolicy.checkpoint)
            XCTAssertThrowsError(try digest(source.policy.source, current.checkpoint)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }

    func testRetainedPolicySnapshotReadsActualMetadataWithoutGrantingWrites() throws {
        try withRetainedPolicySourceFixture { fixture, owner, _, snapshot, _ in
            let before = try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)
            let current = try fixture.machine.retainedSetupPolicySnapshot(owner: owner, candidate: fixture.candidate)
            XCTAssertNoThrow(try current.requireSame(as: snapshot))
            XCTAssertEqual(try fixture.machine.retainedSetupPolicyIntent(owner: owner, candidate: fixture.candidate), snapshot.intent)
            XCTAssertTrue(snapshot.activation.requiresRetainedMaterialCustody)
            XCTAssertThrowsError(try fixture.machine.writeInventory(before.inventory, expectedRevision: before.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate).requireSame(as: before)
            let empty = try MachineUpdateRetainedSetupPolicySnapshot(activation: snapshot.activation, intent: nil, candidate: fixture.candidate)
            XCTAssertThrowsError(try snapshot.requireSame(as: empty)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testRetainedPolicySnapshotRequiresTheExactStoredRecordIdentityColumns() throws {
        try withRetainedPolicySourceFixture { fixture, owner, _, snapshot, _ in
            let intent = try XCTUnwrap(snapshot.intent)
            for (column, id) in [("id", intent.id), ("revision", intent.revision)] {
                XCTAssertNoThrow(try fixture.machine.retainedSetupPolicySnapshot(owner: owner, candidate: fixture.candidate))
                try fixture.machine.close()
                try fixture.files.sql("UPDATE retained_setup_policy_intents_v1 SET \(column)=zeroblob(16)")
                try fixture.files.reopen()
                XCTAssertThrowsError(try fixture.machine.retainedSetupPolicySnapshot(owner: owner, candidate: fixture.candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
                try fixture.machine.close()
                let hex = id.uuidString.replacingOccurrences(of: "-", with: "")
                try fixture.files.sql("UPDATE retained_setup_policy_intents_v1 SET \(column)=X'\(hex)'")
                try fixture.files.reopen()
                XCTAssertNoThrow(try fixture.machine.retainedSetupPolicySnapshot(owner: owner, candidate: fixture.candidate))
            }
        }
    }

    func testRetainedReleaseBindingRequiresTheExactRecordedPairAndCurrentSource() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, source, snapshot, current in
            let binding = try RuntimeRetainedSetupReleaseBinding(snapshot: snapshot, current: current, candidate: fixture.candidate)
            XCTAssertEqual(try RuntimeRetainedSetupReleaseBinding.decode(binding.encoded), binding)
            XCTAssertEqual(binding.retainedSourceDigest, source.digest)
            XCTAssertEqual(binding.preparationDigest, try MachineUpdateActivationRecord.digest(source.runtime.preparation.bytes))
            XCTAssertNoThrow(try binding.requireSourceForPublication(snapshot, current: current, candidate: fixture.candidate))
            XCTAssertNoThrow(try binding.requirePreparation(source.runtime.preparation))
            XCTAssertNoThrow(try binding.requireHistoricalRuntime(XCTUnwrap(source.runtime.state.reference)))
            XCTAssertNoThrow(try binding.requireRecordedBoundary(current))
            let empty = try MachineUpdateRetainedSetupPolicySnapshot(activation: snapshot.activation, intent: nil, candidate: fixture.candidate)
            XCTAssertThrowsError(try RuntimeRetainedSetupReleaseBinding(snapshot: empty, current: current, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            let recordedIntent = try XCTUnwrap(snapshot.intent)
            var preparedFields = try XCTUnwrap(JSONSerialization.jsonObject(with: recordedIntent.encoded) as? [String: Any])
            preparedFields["phase"] = MachineUpdateRetainedSetupPolicyIntentRecord.Phase.prepared.rawValue
            preparedFields["committedPolicy"] = nil; preparedFields["committedCheckpoint"] = nil
            let prepared = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(
                JSONSerialization.data(withJSONObject: preparedFields, options: [.sortedKeys, .withoutEscapingSlashes]))
            let unrecorded = try MachineUpdateRetainedSetupPolicySnapshot(activation: snapshot.activation, intent: prepared, candidate: fixture.candidate)
            XCTAssertThrowsError(try RuntimeRetainedSetupReleaseBinding(snapshot: unrecorded, current: current, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            let otherAccount = try XCTUnwrap(source.runtime.setup.source.accounts.first { $0.accountID != source.runtime.preparation.accountID }?.preparation)
            XCTAssertThrowsError(try binding.requirePreparation(otherAccount)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            let otherPolicy = AuthorityJournal.MachineUpdatePolicyBoundary(macID: current.macID, accountID: current.accountID,
                policy: source.policy.source, checkpoint: current.checkpoint)
            XCTAssertThrowsError(try binding.requireRecordedBoundary(otherPolicy)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            let otherCheckpoint = AuthorityJournal.MachineUpdatePolicyBoundary(macID: current.macID, accountID: current.accountID,
                policy: current.policy, checkpoint: source.accountPolicy.checkpoint)
            XCTAssertThrowsError(try binding.requireRecordedBoundary(otherCheckpoint)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            var mac = current.macID; mac[mac.startIndex] ^= 1
            let other = AuthorityJournal.MachineUpdatePolicyBoundary(macID: mac, accountID: current.accountID,
                policy: current.policy, checkpoint: current.checkpoint)
            XCTAssertThrowsError(try binding.requireRecordedBoundary(other)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            let revised = AuthorityCodePolicySnapshot(revision: UUID(), policy: current.policy.policy, roleRevisions: current.policy.roleRevisions)
            XCTAssertEqual(try revised.storedBytes, try current.policy.storedBytes)
            let changedRevision = AuthorityJournal.MachineUpdatePolicyBoundary(macID: current.macID, accountID: current.accountID,
                policy: revised, checkpoint: current.checkpoint)
            // Encoded policy bytes omit the global revision. The enclosing exact receipt check retains it.
            XCTAssertNoThrow(try binding.requireRecordedBoundary(changedRevision))
            XCTAssertThrowsError(try binding.requireSourceForPublication(snapshot, current: changedRevision, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: binding.encoded) as? [String: Any])
            fields["retainedSourceDigest"] = Data(repeating: 42, count: 32).base64EncodedString()
            let changed = try RuntimeRetainedSetupReleaseBinding.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            XCTAssertNotEqual(changed, binding)
            XCTAssertThrowsError(try changed.requireSourceForPublication(snapshot, current: current, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }

    func testRetainedReleaseBindingRequiresEverySelectedReaderAndWriterFormat() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, _, snapshot, current in
            let candidate = fixture.candidate
            XCTAssertNoThrow(try RuntimeRetainedSetupReleaseBinding(snapshot: snapshot, current: current, candidate: candidate))
            for requirement in try RuntimeRetainedSetupReleaseBinding.requirements {
                for dropWriter in requirement.writeVersions.isEmpty ? [false] : [false, true] {
                    let components = try candidate.manifest.components.map { component in
                        var formats = component.formats
                        if component.role == requirement.role {
                            let index = try XCTUnwrap(formats.firstIndex { $0.name == requirement.name })
                            if dropWriter {
                                formats[index] = try .init(name: formats[index].name, readers: formats[index].readers, writers: [])
                            } else { formats.remove(at: index) }
                        }
                        return try ReleaseComponent(role: component.role, identifier: component.identifier,
                            generation: component.generation, relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                            build: component.build, teamID: component.teamID, formats: formats, requests: component.requests)
                    }
                    let missing = try SignedReleaseEvidence(manifest: .init(release: candidate.manifest.release,
                        build: candidate.manifest.build, components: components, dependencies: candidate.manifest.dependencies),
                        codeDirectoryHashes: candidate.codeDirectoryHashes, dependencyCodeDirectoryHashes: candidate.dependencyCodeDirectoryHashes)
                    XCTAssertThrowsError(try RuntimeRetainedSetupReleaseBinding.requireFormats(missing)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                    }
                }
            }
        }
    }

    /// The published flag is an injected value. No file publication or native custody is claimed.
    private func retainedConfigurationPublishedValue(_ runtime: MachineUpdateStableRuntimePreparationSnapshot) throws
        -> MachineUpdateStableRuntimePreparationSnapshot {
        try .init(setup: runtime.setup, services: .init(plan: runtime.plan, complete: true),
            state: .init(reference: runtime.state.reference, configurationPublished: true), reservedNumbers: runtime.reservedNumbers)
    }

    private func retainedConfigurationChanging(_ bytes: Data, key: UInt64, value: CBORValue) throws -> Data {
        let limits = try CBORLimits(maxBytes: 262144, maxDepth: 16, maxItems: 8192)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else {
            throw RuntimePreparationError.invalidRecord
        }
        fields[key] = value
        return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }

    func testRetainedConfigurationInitialPreservesBindingAndLeavesMetadataUnchanged() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, owner, _, snapshot, current in
            let before = try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)
            let runtime = snapshot.activation.runtime, inventory = runtime.setup.source.actual.inventory
            let binding = try RuntimeRetainedSetupReleaseBinding(snapshot: snapshot, current: current, candidate: fixture.candidate)
            let presence = try PresenceConfiguration(idleMilliseconds: 123000,
                observationLifetimeMilliseconds: 9000, unavailableGraceMilliseconds: 41000)
            let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy,
                presencePolicyOverride: presence, relayPortOverride: 45678)
            let transport = try XCTUnwrap(bundle.transport.settingsHost), gateway = try XCTUnwrap(bundle.gatewaySettingsHost)
            XCTAssertEqual(transport.retainedSetupBinding, binding)
            XCTAssertEqual(gateway.retainedSetupBinding, binding)
            XCTAssertEqual(transport.policyStage, .startup); XCTAssertEqual(gateway.policyStage, .startup)
            XCTAssertEqual(transport.runtime, runtime.state.reference)
            XCTAssertEqual(gateway.installedReleaseDigest, inventory.releaseDigest)
            XCTAssertNotEqual(gateway.runtime.services.releaseDigest, inventory.releaseDigest)
            XCTAssertEqual(bundle.command.presence.presence.policy.idleMilliseconds, presence.idleMilliseconds)
            XCTAssertEqual(bundle.command.presence.presence.policy.observationLifetimeMilliseconds, presence.observationLifetimeMilliseconds)
            XCTAssertEqual(bundle.command.presence.presence.policy.unavailableGraceMilliseconds, presence.unavailableGraceMilliseconds)
            XCTAssertEqual(bundle.transport.relayPort, 45678)
            let hosts = try GatewaySettingsNativeHostPlan(host: transport)
            XCTAssertEqual(hosts.gateway, gateway); XCTAssertEqual(hosts.transport, transport)
            XCTAssertNoThrow(try hosts.validateRelease(fixture.candidate))
            XCTAssertNoThrow(try transport.requireConfigurationScope(account: runtime.preparation, inventory: inventory))
            // Value selection does not open either ordinary decoder or the existing startup validator.
            XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(transport.encoded))
            XCTAssertThrowsError(try TransportPairingStartupConfiguration.decode(bundle.transport.canonicalBytes))
            XCTAssertThrowsError(try transport.validate(account: runtime.preparation, inventory: inventory)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            XCTAssertEqual(RuntimeActivationPlan.supportedVersions, [1, 2, 3, 4, 5])
            XCTAssertEqual(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(gateway.encoded), gateway)
            try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate).requireSame(as: before)
            try fixture.machine.retainedSetupPolicySnapshot(owner: owner, candidate: fixture.candidate).requireSame(as: snapshot)
        }
    }

    func testRetainedConfigurationInitialRequiresRecordedPolicyAndTheExactStartupCode() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, source, snapshot, current in
            XCTAssertNoThrow(try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy))
            XCTAssertThrowsError(try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: source.policy.source.policy)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            let changed = AuthorityJournal.MachineUpdatePolicyBoundary(macID: current.macID, accountID: current.accountID,
                policy: .init(revision: UUID(), policy: current.policy.policy, roleRevisions: current.policy.roleRevisions),
                checkpoint: current.checkpoint)
            XCTAssertThrowsError(try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: changed,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
        try withRetainedPolicySourceFixture { fixture, _, _, snapshot, current in
            XCTAssertEqual(snapshot.intent?.phase, .prepared)
            XCTAssertThrowsError(try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
        }
    }

    func testRetainedConfigurationInitialRejectsAnAlreadyPublishedValue() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, _, snapshot, current in
            XCTAssertNoThrow(try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy))
            let runtime = try retainedConfigurationPublishedValue(snapshot.activation.runtime)
            let activation = try MachineUpdateStableRuntimeActivationSnapshot(runtime: runtime,
                state: snapshot.activation.state, candidate: fixture.candidate)
            let published = try MachineUpdateRetainedSetupPolicySnapshot(activation: activation,
                intent: snapshot.intent, candidate: fixture.candidate)
            XCTAssertNoThrow(try RuntimeRetainedSetupReleaseBinding(snapshot: published, current: current, candidate: fixture.candidate))
            XCTAssertThrowsError(try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: published, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
        }
    }

    func testRetainedConfigurationCompletedPreservesEveryClientAndCommandTunable() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, _, snapshot, current in
            let original = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy, relayPortOverride: 45678)
            let runtime = try retainedConfigurationPublishedValue(snapshot.activation.runtime)
            let reference = try XCTUnwrap(runtime.state.reference)
            let command = try AuthorityCommandStartupConfiguration.decode(retainedConfigurationChanging(
                original.command.canonicalBytes, key: 7, value: .unsigned(17)))
            let presence = try AuthorityPresenceClientConfiguration.decode(retainedConfigurationChanging(
                original.presenceClient.canonicalBytes, key: 8, value: .unsigned(9000)))
            let pairing = try TransportPairingControlConfiguration.decode(retainedConfigurationChanging(
                original.pairingClient.canonicalBytes, key: 11, value: .unsigned(7000)))
            let frontend = try CommandFrontendConfiguration.decode(retainedConfigurationChanging(
                original.frontendClient.canonicalBytes, key: 10,
                value: .map([0: .unsigned(9000), 1: .unsigned(50), 2: .unsigned(500), 3: .unsigned(1000)])))
            let clients = RuntimeActivationClients(presence: presence, pairing: pairing, frontend: frontend)
            let completed = try RuntimeConfigurationBundle.stableCompleted(snapshot: runtime, reference: reference,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy,
                command: command, transport: original.transport, clients: clients)
            XCTAssertNotEqual(command.canonicalBytes, original.command.canonicalBytes)
            XCTAssertNotEqual(presence.canonicalBytes, original.presenceClient.canonicalBytes)
            XCTAssertNotEqual(pairing.canonicalBytes, original.pairingClient.canonicalBytes)
            XCTAssertNotEqual(frontend.canonicalBytes, original.frontendClient.canonicalBytes)
            XCTAssertEqual(completed.command.canonicalBytes, command.canonicalBytes)
            XCTAssertEqual(completed.transport.canonicalBytes, original.transport.canonicalBytes)
            XCTAssertEqual(completed.presenceClient.canonicalBytes, presence.canonicalBytes)
            XCTAssertEqual(completed.pairingClient.canonicalBytes, pairing.canonicalBytes)
            XCTAssertEqual(completed.frontendClient.canonicalBytes, frontend.canonicalBytes)
            XCTAssertEqual(try completed.gatewaySettingsHost, try original.gatewaySettingsHost)
            XCTAssertFalse(snapshot.activation.runtime.state.configurationPublished)
        }
    }

    func testRetainedConfigurationCompletedRejectsEachValidForeignClient() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, _, snapshot, current in
            let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy)
            let runtime = try retainedConfigurationPublishedValue(snapshot.activation.runtime)
            let reference = try XCTUnwrap(runtime.state.reference)
            let clients = RuntimeActivationClients(presence: bundle.presenceClient,
                pairing: bundle.pairingClient, frontend: bundle.frontendClient)
            func completed(_ clients: RuntimeActivationClients) throws -> RuntimeConfigurationBundle {
                try .stableCompleted(snapshot: runtime, reference: reference, candidate: fixture.candidate,
                    currentCodePolicy: current.policy.policy, command: bundle.command, transport: bundle.transport, clients: clients)
            }
            XCTAssertNoThrow(try completed(clients))
            let foreign = CBORValue.bytes(AccountPreparationIntent.randomID())
            let presence = try AuthorityPresenceClientConfiguration.decode(retainedConfigurationChanging(
                clients.presence.canonicalBytes, key: 2, value: foreign))
            let pairing = try TransportPairingControlConfiguration.decode(retainedConfigurationChanging(
                clients.pairing.canonicalBytes, key: 2, value: foreign))
            let frontend = try CommandFrontendConfiguration.decode(retainedConfigurationChanging(
                clients.frontend.canonicalBytes, key: 2, value: foreign))
            for changed in [RuntimeActivationClients(presence: presence, pairing: clients.pairing, frontend: clients.frontend),
                            .init(presence: clients.presence, pairing: clients.pairing, frontend: frontend)] {
                XCTAssertThrowsError(try completed(changed)) { XCTAssertEqual($0 as? RuntimeActivationError, .changedScope) }
            }
            XCTAssertThrowsError(try completed(.init(presence: clients.presence, pairing: pairing, frontend: clients.frontend))) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
        }
    }

    func testRetainedConfigurationCompletedRequiresPublicationAndTheExactMaterialReference() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, _, snapshot, current in
            let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy)
            let runtime = try retainedConfigurationPublishedValue(snapshot.activation.runtime)
            let reference = try XCTUnwrap(runtime.state.reference)
            let clients = RuntimeActivationClients(presence: bundle.presenceClient,
                pairing: bundle.pairingClient, frontend: bundle.frontendClient)
            func completed(_ runtime: MachineUpdateStableRuntimePreparationSnapshot,
                _ reference: RuntimeMaterialReference) throws -> RuntimeConfigurationBundle {
                try .stableCompleted(snapshot: runtime, reference: reference, candidate: fixture.candidate,
                    currentCodePolicy: current.policy.policy, command: bundle.command, transport: bundle.transport, clients: clients)
            }
            XCTAssertNoThrow(try completed(runtime, reference))
            XCTAssertThrowsError(try completed(snapshot.activation.runtime, reference)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            let now = Date()
            let material = try RuntimePreparationMaterial.create(services: runtime.plan,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600),
                serviceActivity: reference.serviceActivity, auditDeliveryVersion: reference.auditDeliveryVersion)
            let foreign = try material.reference
            XCTAssertNoThrow(try foreign.validate(account: runtime.preparation, services: runtime.plan))
            XCTAssertNotEqual(foreign, reference)
            XCTAssertThrowsError(try completed(runtime, foreign)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
        }
    }

    func testRetainedConfigurationHostSelectionRejectsAnotherValidBinding() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, _, snapshot, current in
            let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy)
            let runtime = snapshot.activation.runtime, host = try XCTUnwrap(bundle.transport.settingsHost)
            let hosts = try GatewaySettingsNativeHostPlan(host: host)
            XCTAssertNoThrow(try hosts.selecting(bundle.transport))
            let binding = try XCTUnwrap(host.retainedSetupBinding)
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: binding.encoded) as? [String: Any])
            fields["retainedSourceDigest"] = Data(repeating: 76, count: 32).base64EncodedString()
            let changed = try RuntimeRetainedSetupReleaseBinding.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            let other = try GatewaySettingsNativeHostPlan(reference: XCTUnwrap(runtime.state.reference),
                bundlePath: host.bundlePath, policy: current.policy.policy, retainedSetupBinding: changed)
            let transport = try TransportPairingStartupConfiguration(transport: bundle.transport.transport,
                control: bundle.transport.control, wake: bundle.transport.wake, relayPort: bundle.transport.relayPort,
                settingsHost: other.transport)
            XCTAssertNotEqual(other.transport, host)
            XCTAssertThrowsError(try hosts.selecting(transport)) { XCTAssertEqual($0 as? GatewayPreparationError, .changedScope) }
        }
    }

    func testRetainedConfigurationValueScopeRejectsEachValidForeignInventoryField() throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, _, snapshot, current in
            let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy)
            let runtime = snapshot.activation.runtime, inventory = runtime.setup.source.actual.inventory
            let host = try XCTUnwrap(bundle.transport.settingsHost)
            XCTAssertNoThrow(try host.requireConfigurationScope(account: runtime.preparation, inventory: inventory))
            func inventoryValue(macID: Data? = nil, installationID: Data? = nil, releaseDigest: Data? = nil,
                bundlePath: String? = nil) throws -> InstallationInventory {
                try .init(macID: macID ?? inventory.macID, installationID: installationID ?? inventory.installationID,
                    revision: inventory.revision, bundlePath: bundlePath ?? inventory.bundlePath,
                    releaseDigest: releaseDigest ?? inventory.releaseDigest, accounts: inventory.accounts,
                    services: inventory.services, formatVersion: inventory.formatVersion)
            }
            for changed in [try inventoryValue(macID: AccountPreparationIntent.randomID()),
                            try inventoryValue(installationID: AccountPreparationIntent.randomID()),
                            try inventoryValue(releaseDigest: Data(repeating: 79, count: 32)),
                            try inventoryValue(bundlePath: "/private/tmp/OtherRemozio.app")] {
                XCTAssertThrowsError(try host.requireConfigurationScope(account: runtime.preparation, inventory: changed)) {
                    XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
                }
            }
        }
    }

    private func withRetainedPlanValueFixture(
        _ body: (CompletionFixture, MachineUpdateRetainedSetupPolicySnapshot,
            AuthorityJournal.MachineUpdatePolicyBoundary, RuntimeConfigurationBundle, RuntimeRetainedSetupActivationPlan) throws -> Void) throws {
        try withRetainedPolicySourceFixture(recorded: true) { fixture, _, _, snapshot, current in
            let runtime = snapshot.activation.runtime, inventory = runtime.setup.source.actual.inventory
            let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy)
            let binding = try RuntimeRetainedSetupReleaseBinding(snapshot: snapshot, current: current, candidate: fixture.candidate)
            let label = try RuntimePreparationPaths(accountID: runtime.preparation.accountID).namespace + ".authority"
            let host = try InstalledAuthorityCommandConfiguration(machineDirectory: MachineBootstrap.machineDirectory,
                installationID: inventory.installationID, releaseDigest: inventory.releaseDigest,
                codePolicy: current.policy.policy, command: bundle.command, label: label, plistName: label + ".plist",
                jobPlacement: .systemAccount, gatewaySettingsControlEnabled: true)
            let archive = try RuntimeRetainedSetupActivationArchive(reference: XCTUnwrap(runtime.state.reference),
                bundlePath: inventory.bundlePath, host: host, transport: bundle.transport,
                gatewaySettingsHost: XCTUnwrap(bundle.gatewaySettingsHost), phoneRoutingVersion: nil,
                phoneAuditVersion: 1, phoneUpdateSchedulingVersion: nil, binding: binding, inventory: inventory)
            try body(fixture, snapshot, current, bundle, RuntimeRetainedSetupActivationPlan(archive: archive))
        }
    }

    func testRetainedPlanValueConfigurationRequiresExactPreparationInitializationAndClients() throws {
        try withRetainedPlanValueFixture { fixture, snapshot, _, bundle, plan in
            let runtime = snapshot.activation.runtime, account = runtime.preparation
            let initial = try XCTUnwrap(runtime.setup.account?.initialization)
            let inventory = runtime.setup.source.actual.inventory
            let clients = RuntimeActivationClients(presence: bundle.presenceClient,
                pairing: bundle.pairingClient, frontend: bundle.frontendClient)
            let before = try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)
            XCTAssertNoThrow(try plan.validate(account: account, reference: XCTUnwrap(runtime.state.reference)))
            let restored = try plan.configurationBundle(account: account, initialization: initial, inventory: inventory, clients: clients)
            XCTAssertEqual(restored.command.canonicalBytes, bundle.command.canonicalBytes)
            XCTAssertEqual(restored.transport.canonicalBytes, bundle.transport.canonicalBytes)
            XCTAssertEqual(restored.presenceClient.canonicalBytes, clients.presence.canonicalBytes)
            XCTAssertEqual(restored.pairingClient.canonicalBytes, clients.pairing.canonicalBytes)
            XCTAssertEqual(restored.frontendClient.canonicalBytes, clients.frontend.canonicalBytes)
            XCTAssertEqual(try restored.gatewaySettingsHost, try bundle.gatewaySettingsHost)
            let other = try XCTUnwrap(runtime.setup.source.accounts.first { $0.accountID != account.accountID }?.initialization)
            XCTAssertThrowsError(try plan.configurationBundle(account: account, initialization: other, inventory: inventory, clients: clients)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            let frontend = try CommandFrontendConfiguration.decode(retainedConfigurationChanging(
                clients.frontend.canonicalBytes, key: 2, value: .bytes(AccountPreparationIntent.randomID())))
            XCTAssertThrowsError(try plan.configurationBundle(account: account, initialization: initial, inventory: inventory,
                clients: .init(presence: clients.presence, pairing: clients.pairing, frontend: frontend))) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            let reference = plan.reference, now = Date()
            let material = try RuntimePreparationMaterial.create(services: runtime.plan,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600),
                serviceActivity: reference.serviceActivity, auditDeliveryVersion: reference.auditDeliveryVersion)
            let foreign = try material.reference
            XCTAssertNoThrow(try foreign.validate(account: account, services: runtime.plan))
            XCTAssertThrowsError(try plan.validate(account: account, reference: foreign)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate).requireSame(as: before)
            XCTAssertFalse(runtime.state.configurationPublished)
        }
    }

    func testRetainedPlanValueRequiresAuditDeliveryAndEveryDeclaredReaderWriter() throws {
        try withRetainedPlanValueFixture { fixture, _, _, _, plan in
            let archive = plan.archive
            XCTAssertEqual(archive.reference.auditDeliveryVersion, 1)
            XCTAssertEqual(plan.phoneAuditVersion, 1)
            XCTAssertNoThrow(try RuntimeRetainedSetupActivationPlan.requireFormats(fixture.candidate))
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive(reference: archive.reference,
                bundlePath: archive.bundlePath, host: archive.host, transport: archive.transport,
                gatewaySettingsHost: archive.gatewaySettingsHost, phoneRoutingVersion: nil, phoneAuditVersion: nil,
                phoneUpdateSchedulingVersion: nil, binding: archive.binding, inventory: archive.inventory)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
            }
            for requirement in try RuntimeRetainedSetupActivationPlan.requirements {
                for dropWriter in requirement.writeVersions.isEmpty ? [false] : [false, true] {
                    let components = try fixture.candidate.manifest.components.map { component in
                        var formats = component.formats
                        if component.role == requirement.role {
                            let index = try XCTUnwrap(formats.firstIndex { $0.name == requirement.name })
                            let format = formats[index]
                            if dropWriter {
                                formats[index] = try .init(name: format.name, readers: format.readers,
                                    writers: format.writers.subtracting(requirement.writeVersions))
                            } else { formats.remove(at: index) }
                        }
                        return try ReleaseComponent(role: component.role, identifier: component.identifier,
                            generation: component.generation, relativePath: component.relativePath,
                            codeDirectoryHash: component.codeDirectoryHash, build: component.build, teamID: component.teamID,
                            formats: formats, requests: component.requests)
                    }
                    let missing = try SignedReleaseEvidence(manifest: .init(release: fixture.candidate.manifest.release,
                        build: fixture.candidate.manifest.build, components: components, dependencies: fixture.candidate.manifest.dependencies),
                        codeDirectoryHashes: fixture.candidate.codeDirectoryHashes,
                        dependencyCodeDirectoryHashes: fixture.candidate.dependencyCodeDirectoryHashes)
                    XCTAssertThrowsError(try RuntimeRetainedSetupActivationPlan.requireFormats(missing)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                    }
                }
            }
        }
    }

    /// Owns injected file bytes and SQLite metadata. It proves no protected placement or native file custody.
    private struct RetainedSelectionFixture {
        let fixture: CompletionFixture
        let owner: LocalAccountIdentity
        let snapshot: MachineUpdateRetainedSetupPolicySnapshot
        let unpublished: MachineUpdateRetainedSetupPolicySnapshot
        let current: AuthorityJournal.MachineUpdatePolicyBoundary
        let material: RuntimePreparationMaterial
        let bundle: RuntimeConfigurationBundle
        let journal: AuthorityJournal
        let initialization: AuthorityInitializationIntent
        let artifacts: [String: RuntimePublishedArtifactValidation.Artifact]

        func boundary() throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
            try journal.captureRetainedSetupPolicyBoundary(expected: initialization)
        }
        func verifyMarker() throws {
            let state = try fixture.machine.stableRuntimePreparationSnapshot(owner: owner, candidate: fixture.candidate).state
            guard state.configurationPublished, state.reference == snapshot.activation.runtime.state.reference else {
                throw RuntimeActivationError.changedScope
            }
        }
        func read(_ artifact: RuntimePublishedArtifactValidation.Artifact) throws -> Data {
            guard let expected = artifacts[artifact.path], expected.access == artifact.access else {
                throw RuntimePreparationError.invalidRecord
            }
            return expected.bytes
        }
        func capture() throws -> RuntimeRetainedSetupPublishedSelection {
            try .capture(snapshot: snapshot, readPolicyBoundary: boundary, material: material,
                candidate: fixture.candidate, currentCodePolicy: current.policy.policy, verifyCurrent: verifyMarker, read: read)
        }
    }

    private func withRetainedSelectionFixture(completionReaderFormats: Bool = false, promotionProposalFormats: Bool = false,
        additionalBeforeActivation: (BoundAdmissionRegistrationFixture) throws -> Void = { _ in },
        _ body: (RetainedSelectionFixture) throws -> Void) throws {
        var material: RuntimePreparationMaterial?
        try withRetainedPolicySourceFixture(recorded: true, completionReaderFormats: completionReaderFormats, promotionProposalFormats: promotionProposalFormats, didPrepareMaterial: { material = $0 }, additionalBeforeActivation: additionalBeforeActivation) {
            fixture, owner, _, unpublished, current in
            try withRetainedSelectionAfterPolicy(fixture: fixture, owner: owner, unpublished: unpublished,
                current: current, retainedMaterial: XCTUnwrap(material), body)
        }
    }

    private func withRetainedSelectionAfterPolicy(fixture: CompletionFixture, owner: LocalAccountIdentity,
        unpublished: MachineUpdateRetainedSetupPolicySnapshot, current: AuthorityJournal.MachineUpdatePolicyBoundary,
        retainedMaterial: RuntimePreparationMaterial, _ body: (RetainedSelectionFixture) throws -> Void) throws {
        let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: unpublished, current: current,
            candidate: fixture.candidate, currentCodePolicy: current.policy.policy)
        let account = unpublished.activation.runtime.preparation.accountID
        let hex = account.map { String(format: "%02x", $0) }.joined()
        // This owned row injection is not a production publication API or a proof of installed files.
        try fixture.machine.close()
        try fixture.files.sql("UPDATE runtime_preparation_v1 SET complete=1 WHERE account=X'\(hex)' AND complete=0")
        try fixture.files.reopen()
        let snapshot = try fixture.machine.retainedSetupPolicySnapshot(owner: owner, candidate: fixture.candidate)
        XCTAssertTrue(snapshot.activation.runtime.state.configurationPublished)
        let initialization = try XCTUnwrap(snapshot.activation.runtime.setup.account?.initialization)
        let journal = try fixture.openPolicyPair(readOnly: true, accountID: account)
        defer { try? journal.close() }
        let files = try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: retainedMaterial)
        let artifacts = Dictionary(uniqueKeysWithValues: files.map { ($0.path, $0) })
        XCTAssertEqual(artifacts.count, 8)
        try body(.init(fixture: fixture, owner: owner, snapshot: snapshot, unpublished: unpublished,
            current: current, material: retainedMaterial, bundle: bundle, journal: journal,
            initialization: initialization, artifacts: artifacts))
    }

    private func withStablePublishedSelectionFixture(_ body: (RetainedSelectionFixture,
        MachineUpdateStableRuntimePreparationSnapshot, MachineUpdateStableRuntimeView) throws -> Void) throws {
        try withRetainedSelectionFixture { f in
            let snapshot = try f.fixture.machine.stableRuntimePreparationSnapshot(owner: f.owner, candidate: f.fixture.candidate)
            let inputs = try f.fixture.machine.stableRuntimeViewInputs(expected: snapshot.setup.source,
                retained: [], candidate: f.fixture.candidate)
            let view = try MachineUpdateStableRuntimeView(compatibility: inputs, candidate: f.fixture.candidate)
            try body(f, snapshot, view)
        }
    }

    func testStablePublishedSelectionReusesRetainedValidationAndRereadsEveryExactArtifact() throws {
        try withStablePublishedSelectionFixture { f, snapshot, view in
            let before = try f.fixture.machine.stableMachineUpdateSnapshot(candidate: f.fixture.candidate)
            var events: [String] = []
            func verify() throws {
                events.append("verify")
                try f.verifyMarker()
                try snapshot.requireCurrent(machine: f.fixture.machine, candidate: f.fixture.candidate)
                try view.requireCurrent(machine: f.fixture.machine, candidate: f.fixture.candidate)
            }
            func read(_ artifact: RuntimePublishedArtifactValidation.Artifact) throws -> Data {
                events.append("read"); return try f.read(artifact)
            }
            let selected = try MachineUpdateStableRuntimePublishedSelection.capture(snapshot: snapshot, view: view,
                material: f.material, candidate: f.fixture.candidate, currentCodePolicy: f.current.policy.policy,
                retained: f.snapshot, readPolicyBoundary: { events.append("pair"); return try f.boundary() },
                verifyCurrent: verify, read: read)
            XCTAssertEqual(Set(selected.artifacts.map(\.path)), Set(f.artifacts.keys))
            for artifact in selected.artifacts {
                let expected = try XCTUnwrap(f.artifacts[artifact.path])
                XCTAssertEqual(artifact.bytes, expected.bytes)
                XCTAssertEqual(artifact.access, expected.access)
            }
            XCTAssertEqual(selected.bundle.command.canonicalBytes, f.bundle.command.canonicalBytes)
            XCTAssertEqual(selected.bundle.transport.canonicalBytes, f.bundle.transport.canonicalBytes)
            XCTAssertEqual(selected.description, "MachineUpdateStableRuntimePublishedSelection(redacted)")
            XCTAssertEqual(selected.debugDescription, selected.description)
            try selected.validate(readPolicyBoundary: f.boundary, verifyCurrent: verify, read: read)
            for index in events.indices where events[index] == "read" {
                guard index > 0, index + 1 < events.count else { return XCTFail("Missing read boundary") }
                XCTAssertEqual(events[index - 1], "verify")
                XCTAssertEqual(events[index + 1], "verify")
            }
            try f.fixture.machine.stableMachineUpdateSnapshot(candidate: f.fixture.candidate).requireSame(as: before)
        }
    }

    func testStablePublishedSelectionRequiresRecordedPolicyAtCaptureAndEveryLaterRead() throws {
        try withStablePublishedSelectionFixture { f, snapshot, view in
            var reads = 0
            XCTAssertThrowsError(try MachineUpdateStableRuntimePublishedSelection.capture(snapshot: snapshot, view: view,
                material: f.material, candidate: f.fixture.candidate, currentCodePolicy: f.current.policy.policy,
                verifyCurrent: f.verifyMarker, read: { reads += 1; return try f.read($0) })) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            XCTAssertEqual(reads, 0)
            let selected = try MachineUpdateStableRuntimePublishedSelection.capture(snapshot: snapshot, view: view,
                material: f.material, candidate: f.fixture.candidate, currentCodePolicy: f.current.policy.policy,
                retained: f.snapshot, readPolicyBoundary: f.boundary, verifyCurrent: f.verifyMarker, read: f.read)
            XCTAssertThrowsError(try selected.validate(verifyCurrent: f.verifyMarker,
                read: { reads += 1; return try f.read($0) })) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            XCTAssertEqual(reads, 0)
            let revised = AuthorityJournal.MachineUpdatePolicyBoundary(macID: f.current.macID, accountID: f.current.accountID,
                policy: .init(revision: UUID(), policy: f.current.policy.policy, roleRevisions: f.current.policy.roleRevisions),
                checkpoint: f.current.checkpoint)
            for changedAfter in 0...selected.artifacts.count {
                reads = 0
                XCTAssertThrowsError(try selected.validate(readPolicyBoundary: {
                    if reads >= changedAfter { return revised }
                    return try f.boundary()
                }, verifyCurrent: f.verifyMarker, read: { reads += 1; return try f.read($0) })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertEqual(reads, changedAfter)
            }
            try selected.validate(readPolicyBoundary: f.boundary, verifyCurrent: f.verifyMarker, read: f.read)
        }
    }

    func testStablePublishedSelectionRejectsChangedBytesAndPropagatesTheOwnerFailure() throws {
        try withStablePublishedSelectionFixture { f, snapshot, view in
            let selected = try MachineUpdateStableRuntimePublishedSelection.capture(snapshot: snapshot, view: view,
                material: f.material, candidate: f.fixture.candidate, currentCodePolicy: f.current.policy.policy,
                retained: f.snapshot, readPolicyBoundary: f.boundary, verifyCurrent: f.verifyMarker, read: f.read)
            for target in selected.artifacts {
                XCTAssertThrowsError(try selected.validate(readPolicyBoundary: f.boundary, verifyCurrent: f.verifyMarker,
                    read: { artifact in
                        let bytes = try f.read(artifact)
                        return artifact.path == target.path ? bytes + Data([0]) : bytes
                    })) {
                    XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
                }
            }
            for beforeRead in [true, false] {
                var reads = 0
                XCTAssertThrowsError(try selected.validate(readPolicyBoundary: f.boundary, verifyCurrent: {
                    try f.verifyMarker()
                    if beforeRead || reads > 0 { throw RuntimeActivationError.unavailable }
                }, read: { reads += 1; return try f.read($0) })) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .unavailable)
                }
                XCTAssertEqual(reads, beforeRead ? 0 : 1)
            }
            try selected.validate(readPolicyBoundary: f.boundary, verifyCurrent: f.verifyMarker, read: f.read)
        }
    }

    func testRetainedSelectionReadsOnlyScopedInjectedFilesAndPreservesTheirBytes() throws {
        try withRetainedSelectionFixture { f in
            let before = try f.fixture.machine.stableMachineUpdateSnapshot(candidate: f.fixture.candidate)
            let retained = try f.fixture.machine.stableRuntimePreparationSnapshot(owner: f.owner, candidate: f.fixture.candidate)
            XCTAssertEqual(retained.state, f.snapshot.activation.runtime.state)
            XCTAssertThrowsError(try f.fixture.machine.runtimePreparation(accountID: retained.preparation.accountID)) {
                XCTAssertEqual($0 as? ServiceAccountProvisioningError, .changedScope)
            }
            var events: [String] = [], reads: [String] = []
            let selected = try RuntimeRetainedSetupPublishedSelection.capture(snapshot: f.snapshot,
                readPolicyBoundary: { events.append("pair"); return try f.boundary() }, material: f.material,
                candidate: f.fixture.candidate, currentCodePolicy: f.current.policy.policy,
                verifyCurrent: { events.append("verify"); try f.verifyMarker() }, read: { artifact in
                    events.append("read"); reads.append(artifact.path); return try f.read(artifact)
                })
            XCTAssertEqual(reads.count, 13); XCTAssertEqual(Set(reads), Set(f.artifacts.keys))
            for i in events.indices where events[i] == "read" {
                guard i > 0, i + 1 < events.count else { return XCTFail("Missing read boundary") }
                XCTAssertEqual(events[i - 1], "verify"); XCTAssertEqual(events[i + 1], "verify")
            }
            XCTAssertEqual(selected.bundle.command.canonicalBytes, f.bundle.command.canonicalBytes)
            XCTAssertEqual(selected.bundle.transport.canonicalBytes, f.bundle.transport.canonicalBytes)
            XCTAssertEqual(selected.bundle.presenceClient.canonicalBytes, f.bundle.presenceClient.canonicalBytes)
            XCTAssertEqual(selected.bundle.pairingClient.canonicalBytes, f.bundle.pairingClient.canonicalBytes)
            XCTAssertEqual(selected.bundle.frontendClient.canonicalBytes, f.bundle.frontendClient.canonicalBytes)
            XCTAssertEqual(try selected.bundle.gatewaySettingsHost, try f.bundle.gatewaySettingsHost)
            XCTAssertEqual(selected.host.command.canonicalBytes, f.bundle.command.canonicalBytes)
            XCTAssertTrue(selected.host.gatewaySettingsControlEnabled)
            XCTAssertEqual(selected.description, "RuntimeRetainedSetupPublishedSelection(redacted)")
            XCTAssertEqual(selected.debugDescription, selected.description)
            try f.fixture.machine.stableMachineUpdateSnapshot(candidate: f.fixture.candidate).requireSame(as: before)
        }
    }

    func testRetainedSelectionRejectsAGlobalPolicyRevisionChangeAfterEveryRead() throws {
        try withRetainedSelectionFixture { f in
            XCTAssertNoThrow(try f.capture())
            let revised = AuthorityJournal.MachineUpdatePolicyBoundary(macID: f.current.macID, accountID: f.current.accountID,
                policy: .init(revision: UUID(), policy: f.current.policy.policy, roleRevisions: f.current.policy.roleRevisions),
                checkpoint: f.current.checkpoint)
            XCTAssertEqual(try revised.policy.storedBytes, try f.current.policy.storedBytes)
            let binding = try f.capture().binding
            XCTAssertNoThrow(try binding.requireRecordedBoundary(revised))
            for changedAfter in 0...13 {
                var reads = 0
                XCTAssertThrowsError(try RuntimeRetainedSetupPublishedSelection.capture(snapshot: f.snapshot,
                    readPolicyBoundary: {
                        if reads >= changedAfter { return revised }
                        return try f.boundary()
                    }, material: f.material,
                    candidate: f.fixture.candidate, currentCodePolicy: f.current.policy.policy,
                    verifyCurrent: f.verifyMarker, read: { artifact in reads += 1; return try f.read(artifact) })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertEqual(reads, changedAfter)
            }
        }
    }

    func testRetainedSelectionPropagatesOwnerFailureBeforeAndAfterARead() throws {
        try withRetainedSelectionFixture { f in
            XCTAssertNoThrow(try f.capture())
            for failBeforeRead in [true, false] {
                var reads = 0
                XCTAssertThrowsError(try RuntimeRetainedSetupPublishedSelection.capture(snapshot: f.snapshot,
                    readPolicyBoundary: f.boundary, material: f.material, candidate: f.fixture.candidate,
                    currentCodePolicy: f.current.policy.policy, verifyCurrent: {
                        if failBeforeRead || reads > 0 { throw RuntimeActivationError.unavailable }
                        try f.verifyMarker()
                    }, read: { artifact in reads += 1; return try f.read(artifact) })) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .unavailable)
                }
                XCTAssertEqual(reads, failBeforeRead ? 0 : 1)
            }
        }
    }

    func testRetainedSelectionRejectsDifferentValidMaterialBeforeReadingFiles() throws {
        try withRetainedSelectionFixture { f in
            XCTAssertNoThrow(try f.capture())
            let reference = try f.material.reference, now = Date()
            let other = try RuntimePreparationMaterial.create(services: f.material.services,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600),
                serviceActivity: reference.serviceActivity, auditDeliveryVersion: reference.auditDeliveryVersion)
            XCTAssertNotEqual(try other.reference, reference)
            XCTAssertNoThrow(try other.reference.validate(account: f.snapshot.activation.runtime.preparation, services: f.material.services))
            var reads = 0
            XCTAssertThrowsError(try RuntimeRetainedSetupPublishedSelection.capture(snapshot: f.snapshot,
                readPolicyBoundary: f.boundary, material: other, candidate: f.fixture.candidate,
                currentCodePolicy: f.current.policy.policy, verifyCurrent: f.verifyMarker,
                read: { artifact in reads += 1; return try f.read(artifact) })) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertEqual(reads, 0)
        }
    }

    func testRetainedSelectionRejectsChangedCommandAndIdentityBytesDuringVerification() throws {
        try withRetainedSelectionFixture { f in
            XCTAssertNoThrow(try f.capture())
            let paths = f.bundle.paths
            let command = try AuthorityCommandStartupConfiguration.decode(retainedConfigurationChanging(
                f.bundle.command.canonicalBytes, key: 7, value: .unsigned(17)))
            XCTAssertNotEqual(command.canonicalBytes, f.bundle.command.canonicalBytes)
            var identity = f.material.transportIdentity; identity[identity.startIndex] ^= 1
            for (path, bytes) in [(paths.commandConfiguration, command.canonicalBytes), (paths.transportIdentity, identity)] {
                XCTAssertThrowsError(try RuntimeRetainedSetupPublishedSelection.capture(snapshot: f.snapshot,
                    readPolicyBoundary: f.boundary, material: f.material, candidate: f.fixture.candidate,
                    currentCodePolicy: f.current.policy.policy, verifyCurrent: f.verifyMarker, read: { artifact in
                        if artifact.path == path, !artifact.bytes.isEmpty { return bytes }
                        return try f.read(artifact)
                    })) { XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration) }
            }
        }
    }

    func testRetainedSelectionProposalKeepsTheTypedV6BoundaryAndDoesNotWriteMetadata() throws {
        try withRetainedSelectionFixture { f in
            let selected = try f.capture(), before = try f.fixture.machine.stableMachineUpdateSnapshot(candidate: f.fixture.candidate)
            let proposal = try RuntimeRetainedSetupActivationPlan.retainingRetainedSetup(snapshot: f.snapshot,
                selection: selected, current: f.current, candidate: f.fixture.candidate)
            XCTAssertEqual(proposal.retainedSetupBinding, selected.binding)
            XCTAssertEqual(proposal.retainedSetupInventory, f.snapshot.activation.runtime.setup.source.actual.inventory)
            XCTAssertEqual(proposal.host.canonicalBytes, selected.host.canonicalBytes)
            XCTAssertEqual(proposal.transport.canonicalBytes, selected.bundle.transport.canonicalBytes)
            XCTAssertEqual(try RuntimeRetainedSetupActivationPlan.decode(proposal.encoded).encoded, try proposal.encoded)
            XCTAssertThrowsError(try RuntimeActivationPlan.decode(proposal.encoded))
            XCTAssertThrowsError(try RuntimeActivationState.Plan(encoded: proposal.encoded))
            let state = try f.fixture.machine.runtimeActivation(accountID: proposal.accountID)
            XCTAssertNil(state.plan); XCTAssertFalse(state.jobsRegistered)
            try f.fixture.machine.stableMachineUpdateSnapshot(candidate: f.fixture.candidate).requireSame(as: before)
        }
    }

    func testRetainedSelectionProposalRejectsAChangedReceiptAndAnotherValidSelection() throws {
        try withRetainedSelectionFixture { f in
            let selected = try f.capture()
            XCTAssertNoThrow(try RuntimeRetainedSetupActivationPlan.retainingRetainedSetup(snapshot: f.snapshot,
                selection: selected, current: f.current, candidate: f.fixture.candidate))
            let revised = AuthorityJournal.MachineUpdatePolicyBoundary(macID: f.current.macID, accountID: f.current.accountID,
                policy: .init(revision: UUID(), policy: f.current.policy.policy, roleRevisions: f.current.policy.roleRevisions),
                checkpoint: f.current.checkpoint)
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationPlan.retainingRetainedSetup(snapshot: f.snapshot,
                selection: selected, current: revised, candidate: f.fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try withRetainedSelectionFixture { other in
                let otherSelection = try other.capture()
                XCTAssertNoThrow(try RuntimeRetainedSetupActivationPlan.retainingRetainedSetup(snapshot: other.snapshot,
                    selection: otherSelection, current: other.current, candidate: other.fixture.candidate))
                XCTAssertThrowsError(try RuntimeRetainedSetupActivationPlan.retainingRetainedSetup(snapshot: other.snapshot,
                    selection: selected, current: other.current, candidate: other.fixture.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
                }
            }
        }
    }

    func testRetainedSelectionRefusesUnpublishedMetadataBeforeReadingFiles() throws {
        try withRetainedSelectionFixture { f in
            XCTAssertNoThrow(try f.capture())
            XCTAssertFalse(f.unpublished.activation.runtime.state.configurationPublished)
            var reads = 0
            XCTAssertThrowsError(try RuntimeRetainedSetupPublishedSelection.capture(snapshot: f.unpublished,
                readPolicyBoundary: f.boundary, material: f.material, candidate: f.fixture.candidate,
                currentCodePolicy: f.current.policy.policy, verifyCurrent: f.verifyMarker,
                read: { artifact in reads += 1; return try f.read(artifact) })) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertEqual(reads, 0)
        }
    }

    func testRetainedSelectionRejectsAnotherValidTransportBinding() throws {
        try withRetainedSelectionFixture { f in
            let selected = try f.capture(), binding = selected.binding
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: binding.encoded) as? [String: Any])
            fields["retainedSourceDigest"] = Data(repeating: 99, count: 32).base64EncodedString()
            let changed = try RuntimeRetainedSetupReleaseBinding.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            let original = try XCTUnwrap(f.bundle.transport.settingsHost)
            let host = try GatewaySettingsConsumerHostConfiguration.retainedSetup(role: .transport,
                runtime: original.runtime, bundlePath: original.bundlePath, codePolicy: original.codePolicy, binding: changed)
            let transport = try TransportPairingStartupConfiguration(transport: f.bundle.transport.transport,
                control: f.bundle.transport.control, wake: f.bundle.transport.wake, relayPort: f.bundle.transport.relayPort, settingsHost: host)
            XCTAssertNoThrow(try TransportPairingStartupConfiguration.decodeForReleaseArchive(transport.canonicalBytes))
            XCTAssertNotEqual(changed, binding)
            XCTAssertThrowsError(try RuntimeRetainedSetupPublishedSelection.capture(snapshot: f.snapshot,
                readPolicyBoundary: f.boundary, material: f.material, candidate: f.fixture.candidate,
                currentCodePolicy: f.current.policy.policy, verifyCurrent: f.verifyMarker, read: { artifact in
                    if artifact.path == f.bundle.paths.transportConfiguration { return transport.canonicalBytes }
                    return try f.read(artifact)
                })) { XCTAssertEqual($0 as? RuntimeActivationError, .changedScope) }
        }
    }

    func testRetainedSelectionRejectsValidForeignPairingAndFrontendClients() throws {
        try withRetainedSelectionFixture { f in
            XCTAssertNoThrow(try f.capture())
            let owner = f.snapshot.activation.runtime.preparation.ownerUID
            let foreign = CBORValue.bytes(AccountPreparationIntent.randomID())
            let pairing = try TransportPairingControlConfiguration.decode(retainedConfigurationChanging(
                f.bundle.pairingClient.canonicalBytes, key: 2, value: foreign))
            let frontend = try CommandFrontendConfiguration.decode(retainedConfigurationChanging(
                f.bundle.frontendClient.canonicalBytes, key: 2, value: foreign))
            for (file, bytes, pairingCase) in [(AdministrativeSetupPublication.File.pairingClient(ownerUID: owner), pairing.canonicalBytes, true),
                (.frontendClient(ownerUID: owner), frontend.canonicalBytes, false)] {
                let path = RuntimePreparationPaths.sharedDirectory + "/" + file.name
                XCTAssertThrowsError(try RuntimeRetainedSetupPublishedSelection.capture(snapshot: f.snapshot,
                    readPolicyBoundary: f.boundary, material: f.material, candidate: f.fixture.candidate,
                    currentCodePolicy: f.current.policy.policy, verifyCurrent: f.verifyMarker, read: { artifact in
                        if artifact.path == path { return bytes }
                        return try f.read(artifact)
                    })) {
                    if pairingCase { XCTAssertEqual($0 as? GatewayPreparationError, .changedScope) }
                    else { XCTAssertEqual($0 as? RuntimeActivationError, .changedScope) }
                }
            }
        }
    }

    /// Reuses owned records for compatibility tests in their separate class.
    static func withRetainedRuntimeCompatibilityFixture(_ body: (RetainedRuntimeCompatibilityFixture) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testRetainedActivationSQLReadsV6AndTheOrdinaryStateReaderStillRejectsIt"))
        try suite.withRetainedActivationValueFixture { f, _, plan in
            try body(suite.compatibilityFixture(f, plan: plan))
        }
    }

    private func compatibilityFixture(_ f: RetainedSelectionFixture,
        plan: RuntimeRetainedSetupActivationPlan) -> RetainedRuntimeCompatibilityFixture {
        return .init(readMachine: { f.fixture.machine }, candidate: f.fixture.candidate,
                owner: f.owner, plan: plan, injectRow: { bytes, material, digest, registered in
                    try self.injectRetainedActivationRow(f, bytes: bytes, materialID: material,
                        digest: digest, registered: registered)
                }, createImportJournal: {
                    let inventory = try XCTUnwrap(f.fixture.machine.inventory()), anchor = f.fixture.files.f.f.root.path
                    let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: "machine/SharedSetupImport",
                        owner: getuid(), createIfMissing: true)
                    defer { directory.close() }
                    _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .sharedSetupImport, owner: getuid())
                    let lease = try ProtectedStorageLease(anchor: anchor, relativeDirectory: "machine/SharedSetupImport",
                        owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite")
                    let journal = try SharedSetupImportJournal(lease: lease, owner: getuid(), macID: inventory.macID,
                        installationID: inventory.installationID, initialize: true)
                    try journal.close()
                })
    }

    static func withTwoRetainedRuntimeCompatibilityFixtures(_ body: ([RetainedRuntimeCompatibilityFixture]) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testRetainedActivationSQLReadsV6AndTheOrdinaryStateReaderStillRejectsIt"))
        var third: AccountPreparationIntent?, thirdMaterial: RuntimePreparationMaterial?
        try suite.withRetainedSelectionFixture(additionalBeforeActivation: { files in
            third = try suite.prepareSecondForeground(files, offset: 1001, firstServiceUID: 20004,
                didPrepareMaterial: { thirdMaterial = $0 }).account
        }) { first in
            let account = try XCTUnwrap(third), material = try XCTUnwrap(thirdMaterial)
            let owner = LocalAccountIdentity(uid: account.ownerUID, primaryGroupID: getgid(), directoryID: account.directoryID)
            let preparation = try first.fixture.machine.retainedSetupPolicyMaterial(owner: owner, candidate: first.fixture.candidate)
            try suite.withRetainedPolicyAfterStable(fixture: first.fixture, owner: owner, material: preparation,
                recorded: true) { fixture, owner, _, unpublished, current in
                try suite.withRetainedSelectionAfterPolicy(fixture: fixture, owner: owner, unpublished: unpublished,
                    current: current, retainedMaterial: material) { second in
                    var values: [RetainedRuntimeCompatibilityFixture] = []
                    for original in [first, second] {
                        let snapshot = try original.fixture.machine.retainedSetupPolicySnapshot(owner: original.owner,
                            candidate: original.fixture.candidate)
                        let refreshed = RetainedSelectionFixture(fixture: original.fixture, owner: original.owner,
                            snapshot: snapshot, unpublished: original.unpublished, current: original.current,
                            material: original.material, bundle: original.bundle, journal: original.journal,
                            initialization: original.initialization, artifacts: original.artifacts)
                        let selected = try refreshed.capture()
                        let plan = try RuntimeRetainedSetupActivationPlan.retainingRetainedSetup(snapshot: snapshot,
                            selection: selected, current: refreshed.boundary(), candidate: original.fixture.candidate)
                        try suite.injectRetainedActivationRow(refreshed, bytes: plan.encoded, materialID: plan.reference.materialID)
                        values.append(suite.compatibilityFixture(refreshed, plan: plan))
                    }
                    try body(values)
                }
            }
        }
    }

    private func withRetainedActivationValueFixture(completionReaderFormats: Bool = false, promotionProposalFormats: Bool = false, _ body: (RetainedSelectionFixture,
        MachineUpdateRetainedSetupActivationSnapshot, RuntimeRetainedSetupActivationPlan) throws -> Void) throws {
        try withRetainedSelectionFixture(completionReaderFormats: completionReaderFormats, promotionProposalFormats: promotionProposalFormats) { f in
            let selected = try f.capture()
            let plan = try RuntimeRetainedSetupActivationPlan.retainingRetainedSetup(snapshot: f.snapshot,
                selection: selected, current: f.current, candidate: f.fixture.candidate)
            let snapshot = try f.fixture.machine.retainedSetupActivationSnapshot(owner: f.owner, candidate: f.fixture.candidate)
            try body(f, snapshot, plan)
        }
    }

    /// Injects an owned test row. This helper grants no production writer or native authority.
    private func injectRetainedActivationRow(_ f: RetainedSelectionFixture, bytes: Data, materialID: Data,
        digest: Data? = nil, registered: Int = 0) throws {
        func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
        let account = f.snapshot.activation.runtime.preparation.accountID
        try f.fixture.machine.close()
        try f.fixture.files.sql("DELETE FROM runtime_activation_v1 WHERE account=X'\(hex(account))'")
        try f.fixture.files.sql("INSERT INTO runtime_activation_v1 VALUES(X'\(hex(account))',X'\(hex(materialID))',X'\(hex(digest ?? MachineUpdateActivationRecord.digest(bytes)))',\(registered),X'\(hex(bytes))')")
        try f.fixture.files.reopen()
    }

    /// Constructs value operands only. It does not enroll the account in the actual machine store.
    private func retainedActivationRuntime(_ f: RetainedSelectionFixture, inventory: InstallationInventory,
        reservedNumbers: Set<UInt32>? = nil, rowsDigest: Data = Data(repeating: 88, count: 32), schemaVersion: Int64? = nil) throws
        -> MachineUpdateStableRuntimePreparationSnapshot {
        let runtime = f.snapshot.activation.runtime, source = runtime.setup.source, actual = source.actual
        let changed = MachineUpdateStableReleaseSnapshot(schemaVersion: schemaVersion ?? actual.schemaVersion, inventory: inventory,
            activation: actual.activation, admission: actual.admission, candidate: actual.candidate,
            installed: actual.installed, seal: actual.seal, currentRowsDigest: rowsDigest)
        let selected = try MachineUpdateStableRuntimeSource(actual: changed, preparations: source.preparations,
            initializations: source.initializations, candidate: f.fixture.candidate)
        let setup = try MachineUpdateStableAccountSetupSnapshot(source: selected, owner: f.owner)
        return try .init(setup: setup, services: .init(plan: runtime.plan, complete: true), state: runtime.state,
            reservedNumbers: reservedNumbers ?? runtime.reservedNumbers)
    }

    func testRetainedActivationCaptureReadsTheExactPolicyAndUnactivatedStateWithoutWriting() throws {
        try withRetainedActivationValueFixture { f, snapshot, plan in
            let before = try f.fixture.machine.stableMachineUpdateSnapshot(candidate: f.fixture.candidate)
            XCTAssertNil(snapshot.state.plan); XCTAssertFalse(snapshot.state.jobsRegistered)
            XCTAssertEqual(snapshot.intent, f.snapshot.intent)
            try snapshot.requirePair(f.boundary()); try snapshot.requirePlan(plan, candidate: f.fixture.candidate)
            try snapshot.requireCurrent(machine: f.fixture.machine, candidate: f.fixture.candidate)
            XCTAssertEqual(snapshot.description, "MachineUpdateRetainedSetupActivationSnapshot(redacted)")
            XCTAssertEqual(snapshot.debugDescription, snapshot.description)
            XCTAssertThrowsError(try MachineUpdateRetainedSetupActivationSnapshot(runtime: f.unpublished.activation.runtime,
                state: .init(plan: nil, jobsRegistered: false), intent: snapshot.intent, candidate: f.fixture.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationState(plan: nil, jobsRegistered: true)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            try f.fixture.machine.stableMachineUpdateSnapshot(candidate: f.fixture.candidate).requireSame(as: before)
        }
    }

    func testRetainedActivationSQLReadsV6AndTheOrdinaryStateReaderStillRejectsIt() throws {
        try withRetainedActivationValueFixture { f, before, plan in
            try injectRetainedActivationRow(f, bytes: plan.encoded, materialID: plan.reference.materialID)
            let actual = try f.fixture.machine.retainedSetupActivationSnapshot(owner: f.owner, candidate: f.fixture.candidate)
            XCTAssertEqual(try actual.state.plan?.encoded, try plan.encoded)
            XCTAssertFalse(actual.state.jobsRegistered)
            try actual.requireRetention(plan, from: before)
            try actual.requirePair(f.boundary()); try actual.requireCurrent(machine: f.fixture.machine, candidate: f.fixture.candidate)
            XCTAssertThrowsError(try before.requireCurrent(machine: f.fixture.machine, candidate: f.fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try actual.requireRetention(plan, from: actual)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertThrowsError(try f.fixture.machine.runtimeActivation(accountID: plan.accountID)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testRetainedActivationSQLRejectsAValidOrdinaryPlanThatTheOrdinaryReaderAccepts() throws {
        try withRetainedActivationValueFixture { f, _, retained in
            let runtime = f.snapshot.activation.runtime, account = runtime.preparation
            let provisioning = try runtime.setup.source.provisioningInventory(accountID: account.accountID,
                ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
            let ordinary = try RuntimeActivationPlan(account: account, initialization: f.initialization,
                runtime: runtime.state, inventory: provisioning, gatewaySettingsRelease: f.fixture.previousRelease)
            XCTAssertTrue(RuntimeActivationPlan.supportedVersions.contains(ordinary.formatVersion))
            XCTAssertEqual(try RuntimeActivationPlan.decode(ordinary.encoded).encoded, try ordinary.encoded)
            try injectRetainedActivationRow(f, bytes: ordinary.encoded, materialID: ordinary.reference.materialID)
            XCTAssertEqual(try f.fixture.machine.runtimeActivation(accountID: retained.accountID).plan?.encoded, try ordinary.encoded)
            XCTAssertThrowsError(try f.fixture.machine.retainedSetupActivationSnapshot(owner: f.owner, candidate: f.fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testRetainedActivationSQLRequiresTheExactMaterialAndDigestColumns() throws {
        try withRetainedActivationValueFixture { f, _, plan in
            try injectRetainedActivationRow(f, bytes: plan.encoded, materialID: plan.reference.materialID)
            XCTAssertNoThrow(try f.fixture.machine.retainedSetupActivationSnapshot(owner: f.owner, candidate: f.fixture.candidate))
            for wrongMaterial in [true, false] {
                try injectRetainedActivationRow(f, bytes: plan.encoded,
                    materialID: wrongMaterial ? AccountPreparationIntent.randomID() : plan.reference.materialID,
                    digest: wrongMaterial ? nil : Data(repeating: 0, count: 32))
                XCTAssertThrowsError(try f.fixture.machine.retainedSetupActivationSnapshot(owner: f.owner, candidate: f.fixture.candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
            }
            try injectRetainedActivationRow(f, bytes: plan.encoded, materialID: plan.reference.materialID, registered: 1)
            XCTAssertThrowsError(try f.fixture.machine.retainedSetupActivationSnapshot(owner: f.owner, candidate: f.fixture.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }

    func testRetainedActivationRuntimeChecksTheFullReceiptAroundEveryInjectedRead() throws {
        try withRetainedActivationValueFixture { f, snapshot, plan in
            var reads = 0
            try snapshot.validateRuntime(plan: plan, material: f.material, readPolicyBoundary: f.boundary,
                candidate: f.fixture.candidate, verifyCurrent: {
                    try snapshot.requireCurrent(machine: f.fixture.machine, candidate: f.fixture.candidate)
                }, read: { artifact in reads += 1; return try f.read(artifact) })
            XCTAssertEqual(reads, 11)
            let revised = AuthorityJournal.MachineUpdatePolicyBoundary(macID: f.current.macID, accountID: f.current.accountID,
                policy: .init(revision: UUID(), policy: f.current.policy.policy, roleRevisions: f.current.policy.roleRevisions),
                checkpoint: f.current.checkpoint)
            for changedAfter in 0...11 {
                reads = 0
                XCTAssertThrowsError(try snapshot.validateRuntime(plan: plan, material: f.material, readPolicyBoundary: {
                    if reads >= changedAfter { return revised }
                    return try f.boundary()
                }, candidate: f.fixture.candidate, verifyCurrent: f.verifyMarker,
                    read: { artifact in reads += 1; return try f.read(artifact) })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertEqual(reads, changedAfter)
            }
        }
    }

    func testRetainedActivationOwnerVerificationDetectsAnIntentChangeAfterARead() throws {
        try withRetainedActivationValueFixture { f, snapshot, plan in
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: snapshot.intent.encoded) as? [String: Any])
            fields["revision"] = UUID().uuidString
            let changed = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            XCTAssertNotEqual(changed, snapshot.intent)
            try changed.requireRecorded(f.boundary())
            var reads = 0
            XCTAssertThrowsError(try snapshot.validateRuntime(plan: plan, material: f.material, readPolicyBoundary: f.boundary,
                candidate: f.fixture.candidate, verifyCurrent: {
                    try snapshot.requireCurrent(machine: f.fixture.machine, candidate: f.fixture.candidate)
                }, read: { artifact in
                    reads += 1
                    if reads == 1 {
                        func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
                        let revision = changed.revision.uuidString.replacingOccurrences(of: "-", with: "")
                        try f.fixture.machine.close()
                        try f.fixture.files.sql("UPDATE retained_setup_policy_intents_v1 SET revision=X'\(revision)',record=X'\(try hex(changed.encoded))' WHERE account=X'\(hex(changed.accountID))'")
                        try f.fixture.files.reopen()
                    }
                    return try f.read(artifact)
                })) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            XCTAssertEqual(reads, 1)
            XCTAssertNoThrow(try f.verifyMarker())
        }
    }

    func testRetainedActivationRejectsAnotherValidPlanAndDifferentValidMaterial() throws {
        try withRetainedActivationValueFixture { f, snapshot, plan in
            try snapshot.requirePlan(plan, candidate: f.fixture.candidate)
            let reference = try f.material.reference, now = Date()
            let other = try RuntimePreparationMaterial.create(services: f.material.services,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600),
                serviceActivity: reference.serviceActivity, auditDeliveryVersion: reference.auditDeliveryVersion)
            var reads = 0
            XCTAssertThrowsError(try snapshot.validateRuntime(plan: plan, material: other, readPolicyBoundary: f.boundary,
                candidate: f.fixture.candidate, verifyCurrent: f.verifyMarker,
                read: { artifact in reads += 1; return try f.read(artifact) })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertEqual(reads, 0)
            try withRetainedActivationValueFixture { otherFixture, otherSnapshot, otherPlan in
                try otherSnapshot.requirePlan(otherPlan, candidate: otherFixture.fixture.candidate)
                XCTAssertThrowsError(try snapshot.requirePlan(otherPlan, candidate: f.fixture.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
                }
            }
        }
    }

    func testRetainedActivationEnrollmentAndRegistrationCompareOnlyTheAllowedValues() throws {
        try withRetainedActivationValueFixture { f, snapshot, plan in
            let retained = try MachineUpdateRetainedSetupActivationSnapshot(runtime: snapshot.runtime,
                state: .init(plan: plan, jobsRegistered: false), intent: snapshot.intent, candidate: f.fixture.candidate)
            try retained.requireRetention(plan, from: snapshot)
            let proposed = try plan.enrolledInventory(snapshot.runtime.setup.source.actual.inventory)
            let inventory = try InstallationInventory(macID: proposed.macID, installationID: proposed.installationID,
                revision: AccountPreparationIntent.randomID(), bundlePath: proposed.bundlePath, releaseDigest: proposed.releaseDigest,
                accounts: proposed.accounts, services: proposed.services, formatVersion: proposed.formatVersion)
            let runtime = try retainedActivationRuntime(f, inventory: inventory)
            let enrolled = try MachineUpdateRetainedSetupActivationSnapshot(runtime: runtime,
                state: retained.state, intent: retained.intent, candidate: f.fixture.candidate)
            try enrolled.requireInventoryEnrollment(plan, from: retained)
            XCTAssertThrowsError(try enrolled.requireInventoryEnrollment(plan, from: enrolled)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            let registeredRuntime = try retainedActivationRuntime(f, inventory: inventory, rowsDigest: Data(repeating: 89, count: 32))
            let registered = try MachineUpdateRetainedSetupActivationSnapshot(runtime: registeredRuntime,
                state: .init(plan: plan, jobsRegistered: true), intent: enrolled.intent, candidate: f.fixture.candidate)
            try registered.requireRegistrationMarker(plan, from: enrolled)
            XCTAssertThrowsError(try registered.requireRegistrationMarker(plan, from: registered)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertThrowsError(try enrolled.requireSame(as: registered)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertNil(try f.fixture.machine.runtimeActivation(accountID: plan.accountID).plan)
        }
    }

    func testRetainedActivationRetentionRejectsAValidUnrelatedServiceReservationChange() throws {
        try withRetainedActivationValueFixture { f, before, plan in
            let valid = try MachineUpdateRetainedSetupActivationSnapshot(runtime: before.runtime,
                state: .init(plan: plan, jobsRegistered: false), intent: before.intent, candidate: f.fixture.candidate)
            try valid.requireRetention(plan, from: before)
            let runtime = try retainedActivationRuntime(f, inventory: before.runtime.setup.source.actual.inventory,
                reservedNumbers: before.runtime.reservedNumbers.union([29999]))
            let changed = try MachineUpdateRetainedSetupActivationSnapshot(runtime: runtime,
                state: valid.state, intent: valid.intent, candidate: f.fixture.candidate)
            XCTAssertThrowsError(try changed.requireRetention(plan, from: before)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }


    /// Creates checked values only. The actual machine store has no enrollment or registration producer in this slice.
    private func withRetainedCompletionValueFixture(promotionProposalFormats: Bool = false, _ body: (RetainedSelectionFixture,
        MachineUpdateRetainedSetupActivationSnapshot, RuntimeRetainedSetupActivationPlan,
        MachineUpdateRetainedSetupCompletionIntentRecord) throws -> Void) throws {
        try withRetainedActivationValueFixture(completionReaderFormats: true, promotionProposalFormats: promotionProposalFormats) { f, before, plan in
            let proposed = try plan.enrolledInventory(before.runtime.setup.source.actual.inventory)
            let inventory = try InstallationInventory(macID: proposed.macID, installationID: proposed.installationID,
                revision: AccountPreparationIntent.randomID(), bundlePath: proposed.bundlePath, releaseDigest: proposed.releaseDigest,
                accounts: proposed.accounts, services: proposed.services, formatVersion: proposed.formatVersion)
            let runtime = try retainedActivationRuntime(f, inventory: inventory, schemaVersion: 26)
            let activation = try MachineUpdateRetainedSetupActivationSnapshot(runtime: runtime,
                state: .init(plan: plan, jobsRegistered: true), intent: before.intent, candidate: f.fixture.candidate)
            let prepared = try MachineUpdateRetainedSetupCompletionIntentRecord(snapshot: activation,
                source: f.boundary(), candidate: f.fixture.candidate)
            try body(f, activation, plan, prepared)
        }
    }

    private func retainedCompletionActivation(_ f: RetainedSelectionFixture,
        from before: MachineUpdateRetainedSetupActivationSnapshot, schema: Int64,
        rowsDigest: Data = Data(repeating: 88, count: 32), reservedNumbers: Set<UInt32>? = nil)
        throws -> MachineUpdateRetainedSetupActivationSnapshot {
        let runtime = try retainedActivationRuntime(f, inventory: before.runtime.setup.source.actual.inventory,
            reservedNumbers: reservedNumbers, rowsDigest: rowsDigest, schemaVersion: schema)
        return try .init(runtime: runtime, state: before.state, intent: before.intent, candidate: f.fixture.candidate)
    }

    /// Commits only to the owned fixture pair. This does not mint a production permit or a commit receipt.
    private func retainedCompletionBoundary(_ f: RetainedSelectionFixture,
        record: MachineUpdateRetainedSetupCompletionIntentRecord) throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
        try f.journal.close()
        let storage = try f.fixture.policyStorage(readOnly: false, accountID: record.binding.accountID)
        defer { try? storage.close() }
        let commits = CheckpointedJournal(journal: storage.journal, continuity: storage.continuity)
        let plan = try record.completionPlan(candidate: f.fixture.candidate)
        _ = try commits.write(epoch: f.current.checkpoint.journalEpoch) {
            try $0.installCodePolicy(plan.completionPolicy, expectedRevision: plan.source.revision)
        }
        try storage.close()
        let fresh = try f.fixture.openPolicyPair(readOnly: true, accountID: record.binding.accountID)
        defer { try? fresh.close() }
        return try fresh.captureRetainedSetupPolicyBoundary(expected: f.initialization)
    }

    private func retainedCompletionProposal(_ writing: MachineUpdateRetainedSetupCompletionIntentRecord,
        boundary: AuthorityJournal.MachineUpdatePolicyBoundary) throws -> MachineUpdateRetainedSetupCompletionIntentRecord {
        switch try writing.reconciling(boundary) {
        case .recorded(let value): return value
        case .sourceUnchanged: throw PreparationStoreError.invalidTransition
        }
    }

    private func injectRetainedCompletionRow(_ f: RetainedSelectionFixture,
        record: MachineUpdateRetainedSetupCompletionIntentRecord) throws {
        func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
        try f.fixture.machine.close()
        try f.fixture.files.sql(MachineUpdateRetainedSetupCompletionStorage.createSQL)
        try f.fixture.files.sql("PRAGMA user_version=26")
        try f.fixture.files.sql("INSERT INTO retained_setup_completion_intents_v1 VALUES(X'\(hex(record.binding.accountID))',X'\(record.id.uuidString.replacingOccurrences(of: "-", with: ""))',X'\(record.revision.uuidString.replacingOccurrences(of: "-", with: ""))',X'\(try hex(record.encoded))')")
        try f.fixture.files.reopen()
    }

    func testRetainedCompletionCaptureRejectsTheActualUnregisteredMachine() throws {
        try withRetainedActivationValueFixture(completionReaderFormats: true) { f, activation, _ in
            let before = try f.fixture.machine.stableMachineUpdateSnapshot(candidate: f.fixture.candidate)
            XCTAssertNil(try f.fixture.machine.retainedSetupCompletionIntent(accountID: activation.intent.accountID,
                ownerUID: f.owner.uid, candidate: f.fixture.candidate))
            XCTAssertThrowsError(try f.fixture.machine.retainedSetupCompletionSnapshot(owner: f.owner, candidate: f.fixture.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            try f.fixture.machine.stableMachineUpdateSnapshot(candidate: f.fixture.candidate).requireSame(as: before)
        }
    }

    func testRetainedCompletionPreparedRecordBindsTheExactCheckedValuesAndCanonicalBytes() throws {
        try withRetainedCompletionValueFixture { f, activation, plan, prepared in
            XCTAssertEqual(prepared.phase, .prepared)
            XCTAssertEqual(try prepared.startupIntent.encoded, try activation.intent.encoded)
            XCTAssertEqual(prepared.binding, plan.retainedSetupBinding)
            XCTAssertEqual(prepared.activationPlanDigest, try MachineUpdateActivationRecord.digest(plan.encoded))
            XCTAssertEqual(prepared.inventoryDigest, MachineUpdateActivationRecord.digest(activation.runtime.setup.source.actual.inventory.canonicalBytes))
            XCTAssertEqual(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(prepared.encoded), prepared)
            XCTAssertEqual(prepared.description, "MachineUpdateRetainedSetupCompletionIntentRecord(redacted)")
            XCTAssertEqual(prepared.debugDescription, prepared.description)
            try prepared.requireSnapshot(activation, candidate: f.fixture.candidate)
            try prepared.requirePlan(prepared.completionPlan(candidate: f.fixture.candidate))
            XCTAssertThrowsError(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(prepared.encoded + Data([10]))) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testRetainedCompletionSchema25AllowsAbsenceButRejectsACompletionRow() throws {
        try withRetainedCompletionValueFixture { f, activation, _, prepared in
            let schema25 = try retainedCompletionActivation(f, from: activation, schema: 25)
            let empty = try MachineUpdateRetainedSetupCompletionSnapshot(activation: schema25, intent: nil, candidate: f.fixture.candidate)
            XCTAssertEqual(try empty.classifyPair(f.boundary()), .startup)
            XCTAssertThrowsError(try MachineUpdateRetainedSetupCompletionSnapshot(activation: schema25,
                intent: prepared, candidate: f.fixture.candidate)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            for schema in [Int64(26), 27, 28] {
                let current = try retainedCompletionActivation(f, from: activation, schema: schema)
                XCTAssertNoThrow(try MachineUpdateRetainedSetupCompletionSnapshot(activation: current,
                    intent: prepared, candidate: f.fixture.candidate))
            }
        }
    }

    func testRetainedCompletionPreparationRejectsUnregisteredAndUnenrolledValues() throws {
        try withRetainedActivationValueFixture(completionReaderFormats: true) { f, before, plan in
            XCTAssertThrowsError(try MachineUpdateRetainedSetupCompletionIntentRecord(snapshot: before,
                source: f.boundary(), candidate: f.fixture.candidate)) { XCTAssertEqual($0 as? RuntimeActivationError, .incomplete) }
            let proposed = try plan.enrolledInventory(before.runtime.setup.source.actual.inventory)
            let runtime = try retainedActivationRuntime(f, inventory: proposed, schemaVersion: 26)
            let enrolled = try MachineUpdateRetainedSetupActivationSnapshot(runtime: runtime,
                state: .init(plan: plan, jobsRegistered: false), intent: before.intent, candidate: f.fixture.candidate)
            XCTAssertThrowsError(try MachineUpdateRetainedSetupCompletionIntentRecord(snapshot: enrolled,
                source: f.boundary(), candidate: f.fixture.candidate)) { XCTAssertEqual($0 as? RuntimeActivationError, .incomplete) }
        }
    }

    func testRetainedCompletionPreparedSourceRequiresTheExactGlobalRevisionAndAccount() throws {
        try withRetainedCompletionValueFixture { f, _, _, prepared in
            let source = try f.boundary()
            try prepared.requireSource(source)
            for foreignAccount in [false, true] {
                let changed = AuthorityJournal.MachineUpdatePolicyBoundary(macID: source.macID,
                    accountID: foreignAccount ? AccountPreparationIntent.randomID() : source.accountID,
                    policy: foreignAccount ? source.policy : .init(revision: UUID(), policy: source.policy.policy,
                        roleRevisions: source.policy.roleRevisions), checkpoint: source.checkpoint)
                XCTAssertThrowsError(try prepared.preparingWrite(expected: changed)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
        }
    }

    func testRetainedCompletionWritingWithAnUnchangedPairGrantsNoRetry() throws {
        try withRetainedCompletionValueFixture { f, _, _, prepared in
            let source = try f.boundary(), writing = try prepared.preparingWrite(expected: source)
            XCTAssertEqual(writing.phase, .writing); XCTAssertNotEqual(writing.revision, prepared.revision)
            XCTAssertEqual(writing.id, prepared.id); XCTAssertEqual(writing.startupIntent, prepared.startupIntent)
            try writing.requireTransition(from: prepared)
            XCTAssertEqual(try writing.reconciling(source), .sourceUnchanged)
            XCTAssertThrowsError(try writing.preparingWrite(expected: source)) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
            XCTAssertThrowsError(try prepared.reconciling(source)) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
            XCTAssertThrowsError(try writing.requireTransition(from: writing)) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
        }
    }

    func testRetainedCompletionRecoveredOwnedPairProposesAnExactSeparateReceipt() throws {
        try withRetainedCompletionValueFixture { f, activation, _, prepared in
            let writing = try prepared.preparingWrite(expected: f.boundary())
            let boundary = try retainedCompletionBoundary(f, record: writing)
            let recorded = try retainedCompletionProposal(writing, boundary: boundary)
            XCTAssertEqual(recorded.phase, .recorded); XCTAssertEqual(recorded.id, prepared.id)
            XCTAssertNotEqual(recorded.revision, writing.revision)
            XCTAssertEqual(try recorded.startupIntent.encoded, try prepared.startupIntent.encoded)
            try recorded.requireRecorded(boundary); try recorded.requireTransition(from: writing)
            try recorded.requireSnapshot(activation, candidate: f.fixture.candidate)
            XCTAssertEqual(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(recorded.encoded), recorded)
            XCTAssertThrowsError(try recorded.requireTransition(from: prepared)) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
            let snapshot = try MachineUpdateRetainedSetupCompletionSnapshot(activation: activation, intent: writing, candidate: f.fixture.candidate)
            guard case .completionReceiptPending(let proposal) = try snapshot.classifyPair(boundary) else { return XCTFail("Missing recovered proposal") }
            XCTAssertEqual(proposal.committedPolicy, recorded.committedPolicy)
            XCTAssertEqual(proposal.committedCheckpoint, recorded.committedCheckpoint)
            let settled = try MachineUpdateRetainedSetupCompletionSnapshot(activation: activation, intent: recorded, candidate: f.fixture.candidate)
            XCTAssertEqual(try settled.classifyPair(boundary), .completionRecorded(recorded))
            XCTAssertEqual(try writing.startupIntent.encoded, try activation.intent.encoded)
        }
    }

    func testRetainedCompletionRecoveryRejectsAnotherGlobalRevisionAndRoleRevision() throws {
        try withRetainedCompletionValueFixture { f, _, _, prepared in
            let source = try f.boundary(), writing = try prepared.preparingWrite(expected: source)
            let valid = try retainedCompletionBoundary(f, record: writing)
            _ = try retainedCompletionProposal(writing, boundary: valid)
            var roles = valid.policy.roleRevisions
            let changedRole = try XCTUnwrap(source.policy.policy.entries.first { old in
                !valid.policy.policy.entries.contains(old)
            })
            roles[changedRole.role] = try XCTUnwrap(source.policy.roleRevisions[changedRole.role])
            for policy in [AuthorityCodePolicySnapshot(revision: source.policy.revision, policy: valid.policy.policy,
                roleRevisions: valid.policy.roleRevisions), .init(revision: valid.policy.revision,
                    policy: valid.policy.policy, roleRevisions: roles)] {
                let changed = AuthorityJournal.MachineUpdatePolicyBoundary(macID: valid.macID, accountID: valid.accountID,
                    policy: policy, checkpoint: valid.checkpoint)
                XCTAssertThrowsError(try writing.reconciling(changed)) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
            }
        }
    }

    func testRetainedCompletionRecoveryRejectsASecondCheckpointAndForeignAccount() throws {
        try withRetainedCompletionValueFixture { f, _, _, prepared in
            let writing = try prepared.preparingWrite(expected: f.boundary())
            let valid = try retainedCompletionBoundary(f, record: writing)
            _ = try retainedCompletionProposal(writing, boundary: valid)
            let next = try valid.checkpoint.successor(authorityDigest: Data(repeating: 91, count: 32),
                ledgerDigest: valid.checkpoint.ledgerDigest, journalEpoch: valid.checkpoint.journalEpoch, journalHead: valid.checkpoint.journalHead)
            XCTAssertThrowsError(try writing.reconciling(.init(macID: valid.macID, accountID: valid.accountID,
                policy: valid.policy, checkpoint: next))) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
            XCTAssertThrowsError(try writing.reconciling(.init(macID: valid.macID, accountID: AccountPreparationIntent.randomID(),
                policy: valid.policy, checkpoint: valid.checkpoint))) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
        }
    }

    func testRetainedCompletionSnapshotsSeparateExactRowsFromAllowedMetadataTransitions() throws {
        try withRetainedCompletionValueFixture { f, activation, _, prepared in
            let beforeActivation = try retainedCompletionActivation(f, from: activation, schema: 25)
            let before = try MachineUpdateRetainedSetupCompletionSnapshot(activation: beforeActivation, intent: nil, candidate: f.fixture.candidate)
            let current = try MachineUpdateRetainedSetupCompletionSnapshot(activation: activation, intent: prepared, candidate: f.fixture.candidate)
            try current.requireRetention(prepared, from: before)
            try current.requireHealthContinuation(from: before, candidate: f.fixture.candidate)
            let changedActivation = try retainedCompletionActivation(f, from: activation, schema: 26, rowsDigest: Data(repeating: 89, count: 32))
            let writing = try prepared.preparingWrite(expected: f.boundary())
            let changed = try MachineUpdateRetainedSetupCompletionSnapshot(activation: changedActivation, intent: writing, candidate: f.fixture.candidate)
            try changed.requireTransition(writing, from: current)
            try changed.requireHealthContinuation(from: current, candidate: f.fixture.candidate)
            XCTAssertThrowsError(try changed.requireSame(as: current)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            XCTAssertThrowsError(try current.requireRetention(prepared, from: current)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            XCTAssertThrowsError(try current.requireHealthContinuation(from: changed, candidate: f.fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testRetainedCompletionMetadataTransitionsRejectUnrelatedReservations() throws {
        try withRetainedCompletionValueFixture { f, activation, _, prepared in
            let before = try MachineUpdateRetainedSetupCompletionSnapshot(activation: activation, intent: prepared, candidate: f.fixture.candidate)
            let writing = try prepared.preparingWrite(expected: f.boundary())
            let changedActivation = try retainedCompletionActivation(f, from: activation, schema: 26,
                reservedNumbers: activation.runtime.reservedNumbers.union([29999]))
            let changed = try MachineUpdateRetainedSetupCompletionSnapshot(activation: changedActivation, intent: writing, candidate: f.fixture.candidate)
            XCTAssertThrowsError(try changed.requireTransition(writing, from: before)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            XCTAssertThrowsError(try changed.requireHealthContinuation(from: before, candidate: f.fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testRetainedCompletionRecordedMetadataAllowsOnlyTheDeclaredSchemaSteps() throws {
        try withRetainedCompletionValueFixture { f, activation, _, prepared in
            let writing = try prepared.preparingWrite(expected: f.boundary())
            let recorded = try retainedCompletionProposal(writing, boundary: retainedCompletionBoundary(f, record: writing))
            let schema26 = try MachineUpdateRetainedSetupCompletionSnapshot(activation: activation, intent: recorded, candidate: f.fixture.candidate)
            let schema27 = try MachineUpdateRetainedSetupCompletionSnapshot(activation: retainedCompletionActivation(f, from: activation, schema: 27),
                intent: recorded, candidate: f.fixture.candidate)
            let schema28 = try MachineUpdateRetainedSetupCompletionSnapshot(activation: retainedCompletionActivation(f, from: activation, schema: 28),
                intent: recorded, candidate: f.fixture.candidate)
            try schema27.requirePromotionMetadataChange(from: schema26)
            try schema28.requireReadinessMetadataChange(from: schema27)
            XCTAssertThrowsError(try schema28.requirePromotionMetadataChange(from: schema26)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            XCTAssertThrowsError(try schema28.requireReadinessMetadataChange(from: schema26)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            XCTAssertThrowsError(try schema26.requirePromotionMetadataChange(from: schema27)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
        }
    }

    func testRetainedCompletionRuntimeChecksEveryInjectedReadAgainstTheExactPair() throws {
        try withRetainedCompletionValueFixture { f, activation, plan, prepared in
            let completion = try MachineUpdateRetainedSetupCompletionSnapshot(activation: activation, intent: prepared, candidate: f.fixture.candidate)
            var reads = 0
            try activation.validateCompletionRuntime(plan: plan, material: f.material, completion: completion,
                readPolicyBoundary: f.boundary, candidate: f.fixture.candidate, verifyCurrent: f.verifyMarker,
                read: { artifact in reads += 1; return try f.read(artifact) })
            XCTAssertEqual(reads, 11)
            let changed = AuthorityJournal.MachineUpdatePolicyBoundary(macID: f.current.macID, accountID: f.current.accountID,
                policy: .init(revision: UUID(), policy: f.current.policy.policy, roleRevisions: f.current.policy.roleRevisions), checkpoint: f.current.checkpoint)
            for changedAfter in 0...11 {
                reads = 0
                XCTAssertThrowsError(try activation.validateCompletionRuntime(plan: plan, material: f.material, completion: completion,
                    readPolicyBoundary: { if reads >= changedAfter { return changed }; return try f.boundary() },
                    candidate: f.fixture.candidate, verifyCurrent: f.verifyMarker,
                    read: { artifact in reads += 1; return try f.read(artifact) })) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
                XCTAssertEqual(reads, changedAfter)
            }
        }
    }

    func testRetainedCompletionFilesRequireTheExactActivationFrameAndAllArtifactBytes() throws {
        try withRetainedCompletionValueFixture { f, activation, plan, prepared in
            let completion = try MachineUpdateRetainedSetupCompletionSnapshot(activation: activation, intent: prepared, candidate: f.fixture.candidate)
            var reads = 0
            try activation.validateCompletionFiles(plan: plan, material: f.material, completion: completion,
                candidate: f.fixture.candidate, verifyCurrent: f.verifyMarker, read: { reads += 1; return try f.read($0) })
            XCTAssertEqual(reads, 11)
            let other = try retainedCompletionActivation(f, from: activation, schema: 26, rowsDigest: Data(repeating: 90, count: 32))
            reads = 0
            XCTAssertThrowsError(try other.validateCompletionFiles(plan: plan, material: f.material, completion: completion,
                candidate: f.fixture.candidate, verifyCurrent: f.verifyMarker, read: { reads += 1; return try f.read($0) })) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(reads, 0)
            XCTAssertThrowsError(try activation.validateCompletionFiles(plan: plan, material: f.material, completion: completion,
                candidate: f.fixture.candidate, verifyCurrent: f.verifyMarker, read: { _ in Data() }))
        }
    }

    func testRetainedCompletionSQLUsesTheExactEmbeddedStartupReceipt() throws {
        try withRetainedCompletionValueFixture { f, activation, _, prepared in
            try injectRetainedCompletionRow(f, record: prepared)
            XCTAssertEqual(try f.fixture.machine.retainedSetupCompletionIntent(accountID: prepared.binding.accountID,
                ownerUID: f.owner.uid, candidate: f.fixture.candidate), prepared)
            XCTAssertThrowsError(try f.fixture.machine.retainedSetupCompletionSnapshot(owner: f.owner, candidate: f.fixture.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: activation.intent.encoded) as? [String: Any])
            fields["revision"] = UUID().uuidString
            let changed = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            try changed.requireRecorded(f.boundary())
            XCTAssertNotEqual(changed, prepared.startupIntent)
            func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
            try f.fixture.machine.close()
            try f.fixture.files.sql("UPDATE retained_setup_policy_intents_v1 SET revision=X'\(changed.revision.uuidString.replacingOccurrences(of: "-", with: ""))',record=X'\(try hex(changed.encoded))'")
            try f.fixture.files.reopen()
            // An intentional corrupt-record read is the last operation on this store.
            XCTAssertThrowsError(try f.fixture.machine.retainedSetupCompletionIntent(accountID: prepared.binding.accountID,
                ownerUID: f.owner.uid, candidate: f.fixture.candidate)) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
        }
    }


    /// Contains checked values and an owned pair only. It provides no actual enrollment, file publication or native health.
    private struct RetainedPromotionFixture {
        let source: RetainedSelectionFixture
        let completion: MachineUpdateRetainedSetupCompletionSnapshot
        let current: AuthorityJournal.MachineUpdatePolicyBoundary
        let publication: RuntimeRetainedSetupCompletionPublication
        let prepared: MachineUpdateRetainedSetupPromotionIntentRecord
        var candidate: SignedReleaseEvidence { source.fixture.candidate }
        func observation(selected: Set<UInt64> = []) -> RuntimeRetainedSetupCompletionPublication.Observation {
            .init(verify: {}, read: { selected.contains($0.kind.rawValue) ? $0.selected : $0.previous })
        }
    }

    /// Exposes owned value operands only. The machine store still has no completed retained registration.
    static func withRetainedPromotionNativeContextFixture(_ body: (RetainedPromotionNativeContextFixture) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testRetainedPromotionCaptureRequiresRecordedCompletionAndActualRegistration"))
        try suite.withRetainedPromotionValueFixture { f in
            try body(.init(completion: f.completion, candidate: f.candidate, material: f.source.material,
                machine: f.source.fixture.machine, changingFrame: { schema, digest, reservations in
                    try suite.retainedPromotionCompletion(f, schema: schema, rowsDigest: digest, reservedNumbers: reservations)
                }, policy: f.current.policy.policy))
        }
    }

    /// Exposes an actual owned pair and source byte controls. The machine still has no retained completion producer.
    static func withRetainedPromotionSourceValidationFixture(_ body: (RetainedPromotionSourceValidationFixture) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testRetainedPromotionCaptureRequiresRecordedCompletionAndActualRegistration"))
        try suite.withRetainedPromotionValueFixture { f in
            let initial = try XCTUnwrap(f.completion.activation.runtime.setup.account?.initialization)
            let journal = try f.source.fixture.openPolicyPair(readOnly: true, accountID: initial.accountID)
            defer { try? journal.close() }
            let plan = try XCTUnwrap(f.completion.activation.state.plan)
            let paths = try RuntimePreparationPaths(accountID: plan.accountID)
            var files = f.source.artifacts
            let host = paths.privateDirectory + "/" + AdministrativeSetupPublication.File.commandHost.name
            files[host] = .init(path: host, bytes: plan.host.canonicalBytes, access: .privateRoot)
            for job in [plan.authorityJob, plan.transportJob] {
                files[job.path] = .init(path: job.path, bytes: job.bytes, access: .publicRoot)
            }
            let material = paths.privateDirectory + "/" + AdministrativeSetupPublication.File.runtimeRecord.name
            files[material] = try .init(path: material, bytes: f.source.material.encoded, access: .privateRoot)
            try body(.init(completion: f.completion, candidate: f.candidate, material: f.source.material, plan: plan,
                publication: f.publication, files: files,
                boundary: { try journal.captureRetainedSetupPolicyBoundary(expected: initial) }, verifyCurrent: f.source.verifyMarker))
        }
    }

    /// Opens the actual owned schema 26 catalog. It supplies no completed registration or native proof.
    static func withRetainedPromotionSchema26SQLFixture(_ body: (String, PreparationIntentStore,
        MachineUpdateRetainedSetupPromotionIntentRecord, MachineUpdateRetainedSetupPromotionIntentRecord,
        MachineUpdateRetainedSetupPromotionIntentRecord) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testRetainedPromotionCaptureRequiresRecordedCompletionAndActualRegistration"))
        try suite.withRetainedPromotionValueFixture { f in
            try f.source.fixture.machine.close()
            try f.source.fixture.files.sql(MachineUpdateRetainedSetupCompletionStorage.createSQL)
            try f.source.fixture.files.sql("PRAGMA user_version=26")
            try f.source.fixture.files.reopen()
            let before = try f.source.fixture.machine.stableMachineUpdateSnapshot(candidate: f.candidate)
            XCTAssertEqual(before.schemaVersion, 26)
            let path = f.source.fixture.files.f.f.root.appendingPathComponent("machine/installation.sqlite").path
            let publishing = try f.prepared.beginningPublication(snapshot: f.completion, current: f.current, candidate: f.candidate)
            let published = try publishing.recordingPublishedFiles(snapshot: f.completion, current: f.current,
                candidate: f.candidate, observation: f.observation(selected: Set(UInt64(1)...6)))
            try body(path, f.source.fixture.machine, f.prepared, publishing, published)
            try f.source.fixture.machine.stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before)
        }
    }

    /// Supplies canonical publication values only. It grants no native file access or completed-store proof.
    static func withRetainedPromotionFilePublicationFixture(_ body: (RuntimeRetainedSetupCompletionPublication) throws -> Void) throws {
        let suite = MachineUpdateReplacementTests(selector: NSSelectorFromString(
            "testRetainedPromotionCaptureRequiresRecordedCompletionAndActualRegistration"))
        try suite.withRetainedPromotionValueFixture { try body($0.publication) }
    }

    private func withRetainedPromotionValueFixture(_ body: (RetainedPromotionFixture) throws -> Void) throws {
        try withRetainedCompletionValueFixture(promotionProposalFormats: true) { f, activation, _, prepared in
            let writing = try prepared.preparingWrite(expected: f.boundary())
            let current = try retainedCompletionBoundary(f, record: writing)
            let recorded = try retainedCompletionProposal(writing, boundary: current)
            let completion = try MachineUpdateRetainedSetupCompletionSnapshot(activation: activation, intent: recorded,
                candidate: f.fixture.candidate)
            let clients = RuntimeActivationClients(presence: f.bundle.presenceClient, pairing: f.bundle.pairingClient,
                frontend: f.bundle.frontendClient)
            let configuration = try RuntimeRetainedSetupCompletionConfiguration(snapshot: completion, current: current,
                candidate: f.fixture.candidate, clients: clients)
            let publication = try RuntimeRetainedSetupCompletionPublication(configuration: configuration, sourceClients: clients)
            let promotion = try MachineUpdateRetainedSetupPromotionIntentRecord(publication: publication,
                snapshot: completion, current: current, candidate: f.fixture.candidate)
            try body(.init(source: f, completion: completion, current: current, publication: publication, prepared: promotion))
        }
    }

    private func retainedPromotionCompletion(_ f: RetainedPromotionFixture, schema: Int64,
        rowsDigest: Data = Data(repeating: 88, count: 32), reservedNumbers: Set<UInt32>? = nil)
        throws -> MachineUpdateRetainedSetupCompletionSnapshot {
        let activation = try retainedCompletionActivation(f.source, from: f.completion.activation, schema: schema,
            rowsDigest: rowsDigest, reservedNumbers: reservedNumbers)
        return try .init(activation: activation, intent: f.completion.intent, candidate: f.candidate)
    }

    private func retainedPromotionCandidate(_ candidate: SignedReleaseEvidence, removing role: AuthorityCodeRole,
        name: String, version: UInt64, writer: Bool, replacementWriterVersion: UInt64? = nil) throws -> SignedReleaseEvidence {
        let components = try candidate.manifest.components.map { component in
            let formats = try component.formats.compactMap { format -> ReleaseFormat? in
                guard component.role == role, format.name == name else { return format }
                var readers = writer ? format.readers : format.readers.subtracting([version])
                var writers = format.writers.subtracting([version])
                if let replacementWriterVersion {
                    guard writer else { throw ReplacementFixtureError.injected }
                    readers.insert(replacementWriterVersion); writers.insert(replacementWriterVersion)
                }
                if readers.isEmpty { return nil }
                return try .init(name: format.name, readers: readers, writers: writers,
                    migrations: format.migrations.filter { $0.value != version })
            }
            return try ReleaseComponent(role: component.role, identifier: component.identifier,
                generation: component.generation, relativePath: component.relativePath,
                codeDirectoryHash: component.codeDirectoryHash, build: component.build, teamID: component.teamID,
                formats: formats, requests: component.requests)
        }
        return try .init(manifest: .init(release: candidate.manifest.release, build: candidate.manifest.build,
            components: components, dependencies: candidate.manifest.dependencies),
            codeDirectoryHashes: candidate.codeDirectoryHashes, dependencyCodeDirectoryHashes: candidate.dependencyCodeDirectoryHashes)
    }

    func testRetainedPromotionCaptureRequiresRecordedCompletionAndActualRegistration() throws {
        try withRetainedPromotionValueFixture { f in
            let valid = try MachineUpdateRetainedSetupPromotionSnapshot(completion: f.completion, intent: nil, candidate: f.candidate)
            try valid.requireSame(as: valid)
            let before = try f.source.fixture.machine.stableMachineUpdateSnapshot(candidate: f.candidate)
            XCTAssertThrowsError(try f.source.fixture.machine.retainedSetupPromotionSnapshot(owner: f.source.owner, candidate: f.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            try f.source.fixture.machine.stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before)
            let withoutReceipt = try MachineUpdateRetainedSetupCompletionSnapshot(activation: f.completion.activation,
                intent: nil, candidate: f.candidate)
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionSnapshot(completion: withoutReceipt, intent: nil, candidate: f.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
        }
    }

    func testRetainedPromotionSnapshotPinsTheExactCompletionReceiptAndCanonicalOperands() throws {
        try withRetainedPromotionValueFixture { f in
            let completion = try retainedPromotionCompletion(f, schema: 27)
            let snapshot = try MachineUpdateRetainedSetupPromotionSnapshot(completion: completion, intent: f.prepared, candidate: f.candidate)
            try snapshot.requireSame(as: snapshot); try f.prepared.requireSnapshot(completion, candidate: f.candidate)
            XCTAssertEqual(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.prepared.encoded), f.prepared)
            XCTAssertEqual(try f.prepared.publication().encoded, try f.publication.encoded)
            XCTAssertEqual(f.prepared.description, "MachineUpdateRetainedSetupPromotionIntentRecord(redacted)")
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(completion.intent).encoded) as? [String: Any])
            fields["revision"] = UUID().uuidString
            let changed = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            try changed.requireRecorded(f.current)
            let other = try MachineUpdateRetainedSetupCompletionSnapshot(activation: completion.activation, intent: changed, candidate: f.candidate)
            XCTAssertThrowsError(try f.prepared.requireSnapshot(other, candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testRetainedPromotionSchemaRetentionAndPhaseProposalsKeepEveryOperand() throws {
        try withRetainedPromotionValueFixture { f in
            let before = try MachineUpdateRetainedSetupPromotionSnapshot(completion: f.completion, intent: nil, candidate: f.candidate)
            let completion = try retainedPromotionCompletion(f, schema: 27)
            let retained = try MachineUpdateRetainedSetupPromotionSnapshot(completion: completion, intent: f.prepared, candidate: f.candidate)
            try retained.requireRetention(f.prepared, from: before)
            let publishing = try f.prepared.beginningPublication(snapshot: completion, current: f.current, candidate: f.candidate)
            let pending = try MachineUpdateRetainedSetupPromotionSnapshot(completion: completion, intent: publishing, candidate: f.candidate)
            try pending.requireTransition(publishing, from: retained)
            let selected = Set(f.publication.artifacts.map { $0.kind.rawValue })
            let published = try publishing.recordingPublishedFiles(snapshot: completion, current: f.current,
                candidate: f.candidate, observation: f.observation(selected: selected))
            let after = try MachineUpdateRetainedSetupPromotionSnapshot(completion: completion, intent: published, candidate: f.candidate)
            try after.requireTransition(published, from: pending)
            XCTAssertEqual(published.id, f.prepared.id); XCTAssertNotEqual(published.revision, publishing.revision)
            XCTAssertEqual(published.publicationBytes, f.prepared.publicationBytes)
            XCTAssertThrowsError(try published.requireTransition(from: f.prepared)) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
            XCTAssertThrowsError(try pending.requireTransition(publishing, from: pending)) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionSnapshot(completion: f.completion,
                intent: f.prepared, candidate: f.candidate)) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
        }
    }

    func testRetainedPromotionReadObservationClassifiesSourceMixedAndSelectedBytes() throws {
        try withRetainedPromotionValueFixture { f in
            let changed = f.publication.artifacts.filter { $0.previous != $0.selected }
            XCTAssertGreaterThan(changed.count, 1)
            XCTAssertEqual(try f.publication.progress(observation: f.observation()), .source)
            let first = try XCTUnwrap(changed.first)
            XCTAssertEqual(try f.publication.progress(observation: f.observation(selected: [first.kind.rawValue])), .mixed)
            let all = Set(f.publication.artifacts.map { $0.kind.rawValue })
            XCTAssertEqual(try f.publication.progress(observation: f.observation(selected: all)), .selected)
            XCTAssertEqual(f.publication.artifacts.count, 6)
        }
    }

    func testRetainedPromotionObservationRejectsUnknownBytesAndEverySourceFenceFailure() throws {
        try withRetainedPromotionValueFixture { f in
            XCTAssertEqual(try f.publication.progress(observation: f.observation()), .source)
            XCTAssertThrowsError(try f.publication.progress(observation: .init(verify: {}, read: { _ in Data() }))) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            for failAt in 0..<12 {
                var checks = 0, reads = 0
                XCTAssertThrowsError(try f.publication.progress(observation: .init(verify: {
                    defer { checks += 1 }
                    if checks == failAt { throw ReplacementFixtureError.injected }
                }, read: { artifact in reads += 1; return artifact.previous }))) {
                    XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
                }
                XCTAssertEqual(reads, (failAt + 1) / 2)
            }
        }
    }

    func testRetainedPromotionFilesReceiptRequiresEverySelectedByteAndTheExactPair() throws {
        try withRetainedPromotionValueFixture { f in
            let publishing = try f.prepared.beginningPublication(snapshot: f.completion, current: f.current, candidate: f.candidate)
            XCTAssertThrowsError(try publishing.recordingPublishedFiles(snapshot: f.completion, current: f.current,
                candidate: f.candidate, observation: f.observation())) { XCTAssertEqual($0 as? RuntimeActivationError, .incomplete) }
            let all = Set(f.publication.artifacts.map { $0.kind.rawValue })
            let published = try publishing.recordingPublishedFiles(snapshot: f.completion, current: f.current,
                candidate: f.candidate, observation: f.observation(selected: all))
            XCTAssertEqual(published.phase, .filesPublished)
            XCTAssertEqual(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(published.encoded), published)
            XCTAssertThrowsError(try published.recordingPublishedFiles(snapshot: f.completion, current: f.current,
                candidate: f.candidate, observation: f.observation(selected: all))) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            let changed = AuthorityJournal.MachineUpdatePolicyBoundary(macID: f.current.macID, accountID: f.current.accountID,
                policy: .init(revision: UUID(), policy: f.current.policy.policy, roleRevisions: f.current.policy.roleRevisions), checkpoint: f.current.checkpoint)
            XCTAssertThrowsError(try f.prepared.beginningPublication(snapshot: f.completion, current: changed, candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testRetainedPromotionProducerRequirementsRemainSeparateAndComplete() throws {
        try withRetainedPromotionValueFixture { f in
            try MachineUpdateRetainedSetupPromotionStorage.requireProposalFormats(f.candidate)
            var requirements: [(AuthorityCodeRole, String, UInt64, Bool)] = []
            for role in [AuthorityCodeRole.authority, .setupController] {
                requirements.append((role, "authority.installation-preparation", 24, false))
                for version in [UInt64(25), 26, 27] {
                    requirements.append((role, "authority.installation-preparation", version, false))
                    requirements.append((role, "authority.installation-preparation", version, true))
                }
                for (name, version) in [
                    (MachineUpdateRetainedSetupPolicyIntentRecord.formatName, MachineUpdateRetainedSetupPolicyIntentRecord.currentFormatVersion),
                    (MachineUpdateRetainedSetupCompletionIntentRecord.formatName, MachineUpdateRetainedSetupCompletionIntentRecord.currentFormatVersion),
                    (MachineUpdateRetainedSetupPromotionIntentRecord.formatName, MachineUpdateRetainedSetupPromotionIntentRecord.currentFormatVersion)
                ] {
                    requirements.append((role, name, version, false))
                    if name != MachineUpdateRetainedSetupPromotionIntentRecord.formatName || role == .setupController {
                        requirements.append((role, name, version, true))
                    }
                }
            }
            for requirement in try RuntimeRetainedSetupCompletionBinding.completedHostRequirements {
                for version in requirement.readVersions { requirements.append((requirement.role, requirement.name, version, false)) }
                for version in requirement.writeVersions { requirements.append((requirement.role, requirement.name, version, true)) }
            }
            for (role, name, version, writer) in requirements {
                let missing = try retainedPromotionCandidate(f.candidate, removing: role, name: name, version: version, writer: writer)
                if writer { XCTAssertNoThrow(try MachineUpdateRetainedSetupPromotionStorage.requireReaderFormats(missing)) }
                XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionStorage.requireProposalFormats(missing)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                }
            }
        }
    }

    func testRetainedPromotionProducerDeclarationsMatchCanonicalRecordVersions() throws {
        try withRetainedPromotionValueFixture { f in
            let policyBytes = try f.completion.activation.intent.encoded
            let policy = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(policyBytes)
            let completionBytes = try XCTUnwrap(f.completion.intent).encoded
            let completion = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(completionBytes)
            let promotionBytes = try f.prepared.encoded
            let limits = try CBORLimits(maxBytes: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes,
                maxDepth: 1, maxItems: 13)
            guard case .map(let fields) = try DeterministicCBOR.decode(promotionBytes, limits: limits),
                  case .unsigned(let promotionVersion) = fields[0] else {
                return XCTFail("The canonical promotion record must contain its codec version.")
            }
            let versions = [(MachineUpdateRetainedSetupPolicyIntentRecord.formatName, policy.formatVersion),
                (MachineUpdateRetainedSetupCompletionIntentRecord.formatName, completion.formatVersion),
                (MachineUpdateRetainedSetupPromotionIntentRecord.formatName, promotionVersion)]
            for role in [AuthorityCodeRole.authority, .setupController] {
                let component = try XCTUnwrap(f.candidate.manifest.components.first { $0.role == role })
                for (name, version) in versions {
                    let declaration = try XCTUnwrap(component.formats.first { $0.name == name })
                    XCTAssertTrue(declaration.readers.contains(version))
                    if name != MachineUpdateRetainedSetupPromotionIntentRecord.formatName || role == .setupController {
                        XCTAssertTrue(declaration.writers.contains(version))
                    }
                    if name == MachineUpdateRetainedSetupPolicyIntentRecord.formatName {
                        XCTAssertFalse(declaration.writers.contains(1))
                    }
                }
            }
            try MachineUpdateRetainedSetupPromotionStorage.requireProposalFormats(f.candidate)
        }
    }

    func testRetainedPromotionProducerRejectsLegacyPolicyWritersAndWrongRoleDeclarations() throws {
        try withRetainedPromotionValueFixture { f in
            try MachineUpdateRetainedSetupPromotionStorage.requireProposalFormats(f.candidate)
            let replacementVersions: [UInt64?] = [nil, 1]
            for role in [AuthorityCodeRole.authority, .setupController] {
                for replacement in replacementVersions {
                    let changed = try retainedPromotionCandidate(f.candidate, removing: role,
                        name: MachineUpdateRetainedSetupPolicyIntentRecord.formatName,
                        version: MachineUpdateRetainedSetupPolicyIntentRecord.currentFormatVersion,
                        writer: true, replacementWriterVersion: replacement)
                    XCTAssertNoThrow(try MachineUpdateRetainedSetupPromotionStorage.requireReaderFormats(changed))
                    XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionStorage.requireProposalFormats(changed)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                    }
                }
            }
        }
    }

    func testRetainedPromotionRejectsAnotherIndependentlyValidPublication() throws {
        try withRetainedPromotionValueFixture { first in
            try first.prepared.requireSnapshot(first.completion, candidate: first.candidate)
            try withRetainedPromotionValueFixture { second in
                try second.prepared.requireSnapshot(second.completion, candidate: second.candidate)
                let completion = try retainedPromotionCompletion(first, schema: 27)
                XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionSnapshot(completion: completion,
                    intent: second.prepared, candidate: first.candidate)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            }
        }
    }

    func testRetainedPromotionRetentionPinsOtherMetadataButPermitsItsOwnRowDigestChange() throws {
        try withRetainedPromotionValueFixture { f in
            let before = try MachineUpdateRetainedSetupPromotionSnapshot(completion: f.completion, intent: nil, candidate: f.candidate)
            let completion = try retainedPromotionCompletion(f, schema: 27)
            let retained = try MachineUpdateRetainedSetupPromotionSnapshot(completion: completion, intent: f.prepared, candidate: f.candidate)
            try retained.requireRetention(f.prepared, from: before)
            let rowChanged = try MachineUpdateRetainedSetupPromotionSnapshot(completion: retainedPromotionCompletion(f, schema: 27,
                rowsDigest: Data(repeating: 90, count: 32)), intent: f.prepared, candidate: f.candidate)
            try rowChanged.requireRetention(f.prepared, from: before)
            XCTAssertThrowsError(try rowChanged.requireSame(as: retained)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            let other = try MachineUpdateRetainedSetupPromotionSnapshot(completion: retainedPromotionCompletion(f, schema: 27,
                reservedNumbers: completion.activation.runtime.reservedNumbers.union([29999])), intent: f.prepared, candidate: f.candidate)
            XCTAssertThrowsError(try other.requireRetention(f.prepared, from: before)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
        }
    }

    func testRetainedPromotionSQLKeepsTheExactEmbeddedCompletionReceipt() throws {
        try withRetainedPromotionValueFixture { f in
            let files = f.source.fixture.files
            let completion = try XCTUnwrap(f.completion.intent)
            try injectRetainedCompletionRow(f.source, record: completion)
            func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
            try f.source.fixture.machine.close(); try files.sql(MachineUpdateRetainedSetupPromotionStorage.createSQL)
            try files.sql("PRAGMA user_version=27")
            try files.sql("INSERT INTO retained_setup_promotion_intents_v1 VALUES(X'\(hex(completion.binding.accountID))',X'\(f.prepared.id.uuidString.replacingOccurrences(of: "-", with: ""))',X'\(f.prepared.revision.uuidString.replacingOccurrences(of: "-", with: ""))',X'\(try hex(f.prepared.encoded))')")
            try files.reopen()
            XCTAssertEqual(try f.source.fixture.machine.retainedSetupPromotionIntent(accountID: completion.binding.accountID,
                ownerUID: f.source.owner.uid, candidate: f.candidate), f.prepared)
            XCTAssertThrowsError(try f.source.fixture.machine.retainedSetupPromotionSnapshot(owner: f.source.owner, candidate: f.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: completion.encoded) as? [String: Any])
            fields["revision"] = UUID().uuidString
            let changed = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            try changed.requireRecorded(f.current)
            try f.source.fixture.machine.close()
            try files.sql("UPDATE retained_setup_completion_intents_v1 SET revision=X'\(changed.revision.uuidString.replacingOccurrences(of: "-", with: ""))',record=X'\(try hex(changed.encoded))'")
            try files.reopen()
            // This intentional corruption is the last operation on the store.
            XCTAssertThrowsError(try f.source.fixture.machine.retainedSetupPromotionIntent(accountID: completion.binding.accountID,
                ownerUID: f.source.owner.uid, candidate: f.candidate)) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
        }
    }

    func testRetainedSetupPolicyReadsSchema25WithoutGrantingWritesOrSettlementAdoption() throws {
        var retained: AccountPreparationIntent?
        try withFinishingFixture(stableFormats: true, policyReaderFormats: true,
            beforeActivation: { retained = try self.prepareSecondForeground($0).account }) { fixture, finishing, _ in
            let account = try XCTUnwrap(retained)
            let candidate = fixture.candidate
            let owner = LocalAccountIdentity(uid: account.ownerUID, primaryGroupID: getgid(), directoryID: account.directoryID)
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try fixture.machine.withCurrentMachineUpdateReadiness(candidate: candidate, directory: fixture.directory, loan: loan) {
                try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: candidate)
            }
            let receipt = try fixture.machine.commitStableMachineUpdate(expected: plan, candidate: candidate,
                directory: fixture.directory, loan: loan) { _, _ in }
            let initial = try receipt.read()
            XCTAssertEqual(initial.schemaVersion, 24)
            XCTAssertNil(try fixture.machine.retainedSetupPolicyIntent(owner: owner, candidate: candidate))

            let journal = try fixture.openPolicyPair(readOnly: true, accountID: account.accountID)
            defer { try? journal.close() }
            let source = try MachineUpdateRetainedSetupActivationSource.capture(owner: owner, machine: fixture.machine,
                journal: journal, candidate: candidate)
            let intent = try MachineUpdateRetainedSetupPolicyIntentRecord(source: source)
            try journal.close()

            let storage = MachineUpdateRetainedSetupPolicyStorage.self
            let table = storage.tableName
            try fixture.machine.close()
            try fixture.files.sql(storage.createSQL)
            try fixture.files.sql("PRAGMA user_version=\(storage.schemaVersion)")
            try fixture.files.reopen()
            XCTAssertNil(try fixture.machine.retainedSetupPolicyIntent(owner: owner, candidate: candidate))
            let empty = try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate)
            XCTAssertEqual(empty.schemaVersion, storage.schemaVersion)
            XCTAssertEqual(try empty.seal.encoded, try initial.seal.encoded)
            XCTAssertThrowsError(try fixture.machine.adoptStableMachineUpdate(expected: plan, candidate: candidate,
                directory: fixture.directory, loan: loan) { _, _ in XCTFail("Schema 25 reached settlement adoption") }) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }

            func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
            let id = intent.id.uuidString.replacingOccurrences(of: "-", with: "")
            let revision = intent.revision.uuidString.replacingOccurrences(of: "-", with: "")
            let record = try hex(intent.encoded)
            try fixture.machine.close()
            try fixture.files.sql("INSERT INTO \(table) VALUES(X'\(hex(intent.accountID))',X'\(id)',X'\(revision)',X'\(record)')")
            try fixture.files.reopen()
            let current = try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate)
            XCTAssertNotEqual(current.currentRowsDigest, empty.currentRowsDigest)
            XCTAssertEqual(try fixture.machine.retainedSetupPolicyIntent(owner: owner, candidate: candidate), intent)
            XCTAssertThrowsError(try fixture.machine.writeInventory(current.inventory, expectedRevision: current.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertEqual(try fixture.machine.retainedSetupPolicyIntent(owner: owner, candidate: candidate), intent)

            let components = try candidate.manifest.components.map { component in
                guard component.role == .setupController else { return component }
                return try ReleaseComponent(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: component.formats.filter {
                        $0.name != MachineUpdateRetainedSetupPolicyIntentRecord.formatName
                    }, requests: component.requests)
            }
            let missingReader = try SignedReleaseEvidence(manifest: .init(release: candidate.manifest.release,
                build: candidate.manifest.build, components: components, dependencies: candidate.manifest.dependencies),
                codeDirectoryHashes: candidate.codeDirectoryHashes, dependencyCodeDirectoryHashes: candidate.dependencyCodeDirectoryHashes)
            XCTAssertThrowsError(try fixture.machine.stableMachineUpdateSnapshot(candidate: missingReader)) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }

            func replacingLastByte(_ bytes: Data, by offset: UInt8 = 1) -> Data {
                var result = bytes
                result[result.index(before: result.endIndex)] &+= offset
                return result
            }
            let originalFields = try XCTUnwrap(JSONSerialization.jsonObject(with: intent.encoded) as? [String: Any])
            func editedRecord(_ fields: [String: String]) throws -> Data {
                var edited = originalFields
                for (name, value) in fields { edited[name] = value }
                let bytes = try JSONSerialization.data(withJSONObject: edited, options: [.sortedKeys, .withoutEscapingSlashes])
                _ = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(bytes)
                return bytes
            }
            func requireCorruptRow(_ update: String, restoring original: String, field: String) throws {
                try fixture.machine.close()
                try fixture.files.sql("UPDATE \(table) SET \(update)")
                try fixture.files.reopen()
                XCTAssertThrowsError(try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate), field) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord, field)
                }
                try fixture.machine.close()
                try fixture.files.sql("UPDATE \(table) SET \(original)")
            }
            try requireCorruptRow("account=X'\(hex(replacingLastByte(intent.accountID)))'",
                restoring: "account=X'\(hex(intent.accountID))'", field: "account column")
            try requireCorruptRow("id=zeroblob(16)", restoring: "id=X'\(id)'", field: "ID column")
            try requireCorruptRow("revision=zeroblob(16)", restoring: "revision=X'\(revision)'", field: "revision column")
            for (field, value) in [("macID", intent.macID), ("installationID", intent.installationID)] {
                let foreign = try editedRecord([field: replacingLastByte(value).base64EncodedString()])
                try requireCorruptRow("record=X'\(hex(foreign))'", restoring: "record=X'\(record)'", field: field)
            }

            // Each synthetic row is canonical and has its own account and ID. Only the last insert exceeds the cap.
            let rows = try (1...64).map { offset in
                let account = replacingLastByte(intent.accountID, by: UInt8(offset))
                let rowID = UUID().uuidString
                let bytes = try editedRecord(["accountID": account.base64EncodedString(), "id": rowID])
                let rowIDHex = rowID.replacingOccurrences(of: "-", with: "")
                return "(X'\(hex(account))',X'\(rowIDHex)',X'\(revision)',X'\(hex(bytes))')"
            }
            try fixture.files.sql("INSERT INTO \(table) VALUES \(rows.dropLast().joined(separator: ","))")
            try fixture.files.reopen()
            let atCapacity = try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate)
            XCTAssertNotEqual(atCapacity.currentRowsDigest, current.currentRowsDigest)
            try fixture.machine.close()
            try fixture.files.sql("INSERT INTO \(table) VALUES \(try XCTUnwrap(rows.last))")
            try fixture.files.reopen()
            XCTAssertThrowsError(try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    /// Links owned machine rows to decoded archive operands. It proves no live publication or startup.
    private func withPromotionReaderFixture(readinessReaderFormats: Bool = false, published: Bool = false,
        didPrepareMaterial: (RuntimePreparationMaterial) -> Void = { _ in },
        _ body: (CompletionFixture, AccountPreparationIntent,
        MachineUpdateRetainedSetupCompletionIntentRecord, MachineUpdateRetainedSetupPromotionIntentRecord) throws -> Void) throws {
        var retained: AccountPreparationIntent?
        try withFinishingFixture(stableFormats: true, policyReaderFormats: true, completionReaderFormats: true, promotionReaderFormats: true,
            readinessReaderFormats: readinessReaderFormats,
            beforeActivation: { retained = try self.prepareSecondForeground($0, didPrepareMaterial: didPrepareMaterial).account }) { fixture, finishing, _ in
            let account = try XCTUnwrap(retained)
            let candidate = fixture.candidate
            let owner = LocalAccountIdentity(uid: account.ownerUID, primaryGroupID: getgid(), directoryID: account.directoryID)
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try fixture.machine.withCurrentMachineUpdateReadiness(candidate: candidate, directory: fixture.directory, loan: loan) {
                try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: candidate)
            }
            _ = try fixture.machine.commitStableMachineUpdate(expected: plan, candidate: candidate,
                directory: fixture.directory, loan: loan) { _, _ in }
            XCTAssertNil(try fixture.machine.retainedSetupCompletionIntent(accountID: account.accountID, ownerUID: owner.uid, candidate: candidate))
            let reader = try fixture.openPolicyPair(readOnly: true, accountID: account.accountID)
            defer { try? reader.close() }
            let source = try MachineUpdateRetainedSetupActivationSource.capture(owner: owner, machine: fixture.machine,
                journal: reader, candidate: candidate)
            let prepared = try MachineUpdateRetainedSetupPolicyIntentRecord(source: source)
            try reader.close()

            let storage = try fixture.policyStorage(readOnly: false, accountID: account.accountID)
            defer { try? storage.close() }
            let commits = CheckpointedJournal(journal: storage.journal, continuity: storage.continuity)
            let startupPolicy = try commits.write(epoch: source.accountPolicy.checkpoint.journalEpoch) {
                try $0.installCodePolicy(source.policy.startupPolicy, expectedRevision: source.policy.source.revision)
            }
            let checkpoint = try storage.continuity.read().committed
            let completionPolicy = try commits.write(epoch: checkpoint.journalEpoch) {
                try $0.installCodePolicy(source.policy.completionPolicy, expectedRevision: startupPolicy.revision)
            }
            let completionCheckpoint = try storage.continuity.read().committed
            XCTAssertNotEqual(completionPolicy.revision, startupPolicy.revision)
            XCTAssertEqual(completionCheckpoint.generation, checkpoint.generation + 1)
            XCTAssertEqual(completionCheckpoint.authorityGeneration, checkpoint.currentAuthorityGeneration + 1)
            for (before, after) in zip(startupPolicy.policy.entries, completionPolicy.policy.entries) {
                XCTAssertEqual(before == after, startupPolicy.roleRevisions[before.role] == completionPolicy.roleRevisions[after.role])
            }
            try storage.close()
            func json(_ fields: [String: Any]) throws -> Data {
                try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
            }
            var startup = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.encoded) as? [String: Any])
            startup["phase"] = MachineUpdateRetainedSetupPolicyIntentRecord.Phase.recorded.rawValue
            startup["committedPolicy"] = [
                "revision": startupPolicy.revision.uuidString, "bytes": try startupPolicy.storedBytes.base64EncodedString()
            ]
            startup["committedCheckpoint"] = try checkpoint.bytes.base64EncodedString()
            let startupRecord = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(json(startup))
            func digest(_ bytes: Data) -> String { MachineUpdateActivationRecord.digest(bytes).base64EncodedString() }
            let syntheticDigest = digest(Data("archive fixture".utf8))
            // The row reader binds the two archives. It does not open an activation plan or prove native startup.
            var binding: [String: Any] = [
                "formatVersion": 1, "macID": account.macID.base64EncodedString(), "installationID": account.installationID.base64EncodedString(),
                "accountID": account.accountID.base64EncodedString(), "ownerUID": owner.uid, "activationAttempt": finishing.activation.attemptID.uuidString,
                "initializationDigest": startupRecord.initializationDigest.base64EncodedString(),
                "provisioningReleaseDigest": account.releaseDigest.base64EncodedString(),
                "installedReleaseDigest": startupRecord.installedReleaseDigest.base64EncodedString(),
                "retainedSourceDigest": startupRecord.sourceDigest.base64EncodedString(), "policyIntentDigest": try digest(startupRecord.encoded),
                "sourcePolicyDigest": try digest(source.policy.source.storedBytes), "sourceCheckpointDigest": digest(startupRecord.sourceCheckpoint),
                "startupPolicyDigest": digest(startupRecord.startupPolicy), "startupPolicySnapshotDigest": try digest(startupPolicy.storedBytes),
                "startupCheckpointDigest": try digest(checkpoint.bytes), "completionPolicyDigest": digest(startupRecord.completionPolicy),
            ]
            for name in ["candidateDigest", "admissionDigest", "updateID", "stableSealDigest", "installedEpochDigest", "sealedInventoryDigest",
                         "sourceAccountDigest", "preparationDigest", "provisioningInventoryDigest", "previousInstalledReleaseDigest", "runtimeReferenceDigest"] {
                binding[name] = syntheticDigest
            }
            let reference = try XCTUnwrap(source.runtime.state.reference)
            binding["runtimeReferenceDigest"] = try digest(reference.encoded)
            let historical = try source.runtime.setup.source.provisioningInventory(accountID: account.accountID,
                ownerUID: owner.uid, releaseDigest: account.releaseDigest)
            let initialization = try XCTUnwrap(source.runtime.setup.account?.initialization)
            let bundle = try RuntimeConfigurationBundle.initial(account: account, initialization: initialization,
                reference: reference, inventory: historical)
            let installedInventory = source.runtime.setup.source.actual.inventory
            let limits = try CBORLimits(maxBytes: 4_194_304, maxDepth: 4, maxItems: 4096)
            func encode(_ fields: [UInt64: CBORValue]) throws -> Data {
                try DeterministicCBOR.encode(.map(fields), limits: limits)
            }
            func host(_ policy: AuthorityCodePolicy) throws -> InstalledAuthorityCommandConfiguration {
                let label = bundle.paths.namespace + ".authority"
                return try .init(machineDirectory: MachineBootstrap.machineDirectory,
                    installationID: account.installationID, releaseDigest: installedInventory.releaseDigest,
                    codePolicy: policy, command: bundle.command, label: label, plistName: label + ".plist",
                    jobPlacement: .systemAccount, gatewaySettingsControlEnabled: true)
            }
            func consumer(_ role: GatewaySettingsConsumerRole, policy: AuthorityCodePolicy,
                          binding: Data, completed: Bool) throws -> GatewaySettingsConsumerHostConfiguration {
                let base = try GatewaySettingsConsumerHostConfiguration(role: role, runtime: reference,
                    bundlePath: installedInventory.bundlePath, codePolicy: policy)
                guard case .map(var fields) = try DeterministicCBOR.decode(base.encoded, limits: limits) else {
                    throw RuntimeActivationError.invalidPlan
                }
                fields[0] = .unsigned(completed ? 4 : 3); fields[6] = .bytes(binding)
                fields[7] = .unsigned(completed ? RuntimeReleasePolicyStage.completion.rawValue : RuntimeReleasePolicyStage.startup.rawValue)
                return try .decodeForReleaseArchive(encode(fields))
            }
            func transport(_ settings: GatewaySettingsConsumerHostConfiguration) throws -> TransportPairingStartupConfiguration {
                try .init(transport: bundle.transport.transport, control: bundle.transport.control,
                    wake: bundle.transport.wake, relayPort: bundle.transport.relayPort, settingsHost: settings)
            }
            let startupBinding = try json(binding)
            let startupHost = try host(startupPolicy.policy)
            let startupGateway = try consumer(.gateway, policy: startupPolicy.policy, binding: startupBinding, completed: false)
            let startupTransport = try transport(consumer(.transport, policy: startupPolicy.policy, binding: startupBinding, completed: false))
            let activation = try encode([0: .unsigned(6), 1: .bytes(reference.encoded), 2: .text(installedInventory.bundlePath),
                3: .bytes(startupHost.canonicalBytes), 4: .bytes(startupTransport.canonicalBytes), 5: .bytes(startupGateway.encoded),
                6: .null, 7: .unsigned(1), 8: .null, 9: .bytes(startupBinding), 10: .bytes(installedInventory.canonicalBytes)])
            _ = try RuntimeRetainedSetupActivationArchive.decode(activation)
            let enrolled = try InstallationAccount(accountID: account.accountID, ownerUID: account.ownerUID)
            let service = try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
                label: startupHost.label, plistName: startupHost.plistName, accountID: account.accountID)
            let recordedInventory = try InstallationInventory(macID: installedInventory.macID,
                installationID: installedInventory.installationID, revision: installedInventory.revision,
                bundlePath: installedInventory.bundlePath, releaseDigest: installedInventory.releaseDigest,
                accounts: installedInventory.accounts + [enrolled], services: installedInventory.services + [service], formatVersion: 2)
            let completionFields: [String: Any] = [
                "formatVersion": 1, "id": UUID().uuidString, "revision": UUID().uuidString, "phase": 3,
                "startupIntent": startup, "binding": binding, "activationPlanDigest": digest(activation),
                "inventoryDigest": digest(recordedInventory.canonicalBytes),
                "committedPolicy": ["revision": completionPolicy.revision.uuidString, "bytes": try completionPolicy.storedBytes.base64EncodedString()],
                "committedCheckpoint": try completionCheckpoint.bytes.base64EncodedString(),
            ]
            let completion = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(json(completionFields))
            let completedBinding = try json([
                "formatVersion": 1, "startupBinding": binding, "recordedCompletionDigest": try digest(completion.encoded),
                "activationPlanDigest": digest(activation), "recordedInventoryDigest": digest(recordedInventory.canonicalBytes),
                "completionPolicyRevision": completionPolicy.revision.uuidString,
                "completionPolicySnapshotDigest": try digest(completionPolicy.storedBytes),
                "completionCheckpointDigest": try digest(completionCheckpoint.bytes),
            ])
            let archive = try encode([0: .unsigned(1), 1: .text("retained-setup-completion-archive"),
                2: .bytes(completedBinding), 3: .bytes(activation), 4: .bytes(completion.encoded),
                5: .bytes(recordedInventory.canonicalBytes)])
            let completedHost = try host(completionPolicy.policy)
            let completedGateway = try consumer(.gateway, policy: completionPolicy.policy, binding: completedBinding, completed: true)
            let completedTransport = try transport(consumer(.transport, policy: completionPolicy.policy, binding: completedBinding, completed: true))
            let clients = RuntimeActivationClients(presence: bundle.presenceClient, pairing: bundle.pairingClient, frontend: bundle.frontendClient)
            let sourceDigest = try RuntimeReleaseConfigurationSource(host: startupHost, transport: startupTransport,
                gateway: startupGateway, clients: clients).digest
            let configuration = try encode([0: .unsigned(1), 1: .text("runtime.retained-setup-completion-configuration"),
                2: .bytes(archive), 3: .bytes(sourceDigest), 4: .bytes(completedHost.canonicalBytes),
                5: .bytes(completedTransport.canonicalBytes), 6: .bytes(completedGateway.encoded),
                7: .bytes(clients.presence.canonicalBytes), 8: .bytes(clients.pairing.canonicalBytes), 9: .bytes(clients.frontend.canonicalBytes)])
            let publication = try encode([0: .unsigned(1), 1: .text("runtime.retained-setup-completion-publication"),
                2: .bytes(configuration), 3: .bytes(clients.presence.canonicalBytes),
                4: .bytes(clients.pairing.canonicalBytes), 5: .bytes(clients.frontend.canonicalBytes)])
            let id = UUID(), revision = UUID()
            func bytes(_ id: UUID) -> Data { var value = id.uuid; return withUnsafeBytes(of: &value) { Data($0) } }
            let promotion = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(encode([
                0: .unsigned(1), 1: .text(MachineUpdateRetainedSetupPromotionIntentRecord.formatName),
                2: .bytes(bytes(id)), 3: .bytes(bytes(revision)), 4: .unsigned(published ? 3 : 1), 5: .bytes(publication)]))
            func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
            func row(_ id: UUID, _ revision: UUID, _ data: Data) -> String {
                "(X'\(hex(account.accountID))',X'\(hex(bytes(id)))',X'\(hex(bytes(revision)))',X'\(hex(data))')"
            }
            try fixture.machine.close()
            try fixture.files.sql(MachineUpdateRetainedSetupPolicyStorage.createSQL)
            try fixture.files.sql(MachineUpdateRetainedSetupCompletionStorage.createSQL)
            try fixture.files.sql(MachineUpdateRetainedSetupPromotionStorage.createSQL)
            try fixture.files.sql("PRAGMA user_version=27")
            try fixture.files.sql("INSERT INTO retained_setup_policy_intents_v1 VALUES \(try row(startupRecord.id, startupRecord.revision, startupRecord.encoded))")
            try fixture.files.sql("INSERT INTO retained_setup_completion_intents_v1 VALUES \(try row(completion.id, completion.revision, completion.encoded))")
            try fixture.files.sql("INSERT INTO retained_setup_promotion_intents_v1 VALUES \(try row(promotion.id, promotion.revision, promotion.encoded))")
            try fixture.files.reopen()
            try body(fixture, account, completion, promotion)
        }
    }

    private func readinessReaderRecord(_ promotion: MachineUpdateRetainedSetupPromotionIntentRecord,
        rootKey: P256.Signing.PrivateKey, transportKey: P256.Signing.PrivateKey,
        ownerUID: UInt32? = nil) throws -> MachineUpdateRetainedSetupPromotionReadyRecord {
        let publication = try promotion.publication(), archive = publication.configuration.archive
        let original = try archive.originalActivation(), completion = try archive.completionIntent()
        let binding: RuntimeRetainedSetupReleaseBinding
        if let ownerUID {
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: original.binding.encoded) as? [String: Any])
            fields["ownerUID"] = ownerUID
            binding = try .decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
        } else { binding = original.binding }
        let policy = try XCTUnwrap(completion.committedPolicy?.snapshot())
        let checkpoint = try XCTUnwrap(completion.committedCheckpoint)
        func uuid(_ id: UUID) -> Data { var raw = id.uuid; return withUnsafeBytes(of: &raw) { Data($0) } }
        let limits = try CBORLimits(maxBytes: 4_194_304, maxDepth: 4, maxItems: 4096)
        func encode(_ fields: [UInt64: CBORValue]) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: limits) }
        let boundary = try encode([0: .bytes(completion.startupIntent.macID), 1: .bytes(completion.startupIntent.accountID),
            2: .bytes(policy.storedBytes), 3: .bytes(checkpoint), 4: .bytes(uuid(policy.revision))])
        let boundaryDigest = MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupCompletionHealthBoundary/v2\0".utf8) + boundary)
        let promotionDigest = try MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupPromotionHealthScope/v3\0".utf8) + promotion.encoded)
        let transport = try XCTUnwrap(publication.configuration.transport.settingsHost)
        let rootCode = try XCTUnwrap(publication.configuration.host.codePolicy.entries.first { $0.role == .authority && $0.active })
        XCTAssertEqual(rootKey.publicKey.x963Representation, original.reference.services.authorityPublicKey)
        XCTAssertEqual(transportKey.publicKey.x963Representation, try original.reference.transportPublicKeyX963)
        func requirement(_ role: AuthorityCodeRole) throws -> Data {
            try MachineUpdateRetainedSetupHealthEvidence.Requirement(binding: binding,
                activationPlanDigest: MachineUpdateActivationRecord.digest(archive.originalActivationBytes),
                inventoryDigest: MachineUpdateActivationRecord.digest(archive.recordedInventoryBytes), role: role,
                executionUID: role == .authority ? 0 : transport.serviceUID,
                code: role == .authority ? rootCode : transport.consumerCode,
                publicKey: role == .authority ? rootKey.publicKey.x963Representation : transportKey.publicKey.x963Representation,
                completionBoundaryDigest: boundaryDigest, promotionDigest: promotionDigest).encoded
        }
        let request = try encode([0: .unsigned(1), 1: .text("retained-setup-health-challenge"),
            2: .bytes(Data(repeating: 9, count: 32)), 3: .bytes(requirement(.authority))])
        let nonce = MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupTransportNonce/v1\0".utf8) + request)
        let child = try encode([0: .unsigned(1), 1: .text("retained-setup-health-challenge"),
            2: .bytes(nonce), 3: .bytes(requirement(.transport))])
        let childSignature = try transportKey.signature(for: Data("Remozio/RetainedSetupHealthReply/v1\0".utf8) + child).rawRepresentation
        let childReply = try encode([0: .unsigned(1), 1: .text("retained-setup-health-reply"),
            2: .bytes(child), 3: .bytes(childSignature)])
        let digest = try MachineUpdateRetainedSetupJointHealthPacket.transportDigest(request: child, reply: childReply)
        let signature = try rootKey.signature(for: Data("Remozio/RetainedSetupJointRootReply/v1\0".utf8) + digest + request).rawRepresentation
        let rootReply = try encode([0: .unsigned(1), 1: .text("retained-setup-joint-root-reply"),
            2: .bytes(request), 3: .bytes(digest), 4: .bytes(signature)])
        let packet = try MachineUpdateRetainedSetupJointHealthPacket(rootReply: rootReply, transportRequest: child, transportReply: childReply).encoded
        return try .decode(encode([0: .unsigned(1), 1: .text(MachineUpdateRetainedSetupPromotionReadyRecord.formatName),
            2: .bytes(uuid(UUID())), 3: .bytes(uuid(UUID())), 4: .bytes(uuid(promotion.id)),
            5: .bytes(uuid(promotion.revision)), 6: .bytes(promotionDigest), 7: .bytes(request), 8: .bytes(packet)]))
    }

    /// Uses owned fixture keys and a historical exchange. It proves no native peer or fresh readiness.
    private func withReadinessReaderFixture(readerFormats: Bool = true, differentOwnerUID: Bool = false,
        _ body: (CompletionFixture, AccountPreparationIntent, MachineUpdateRetainedSetupCompletionIntentRecord,
            MachineUpdateRetainedSetupPromotionIntentRecord, MachineUpdateRetainedSetupPromotionReadyRecord) throws -> Void) throws {
        var material: RuntimePreparationMaterial?
        try withPromotionReaderFixture(readinessReaderFormats: readerFormats, published: true,
            didPrepareMaterial: { material = $0 }) { fixture, account, completion, promotion in
            let material = try XCTUnwrap(material)
            guard case .map(let identity) = try DeterministicCBOR.decode(material.transportIdentity,
                limits: CBORLimits(maxBytes: 16384, maxDepth: 1, maxItems: 9)),
                  case .bytes(let key) = identity[2] else { throw ReplacementFixtureError.injected }
            let ready = try readinessReaderRecord(promotion, rootKey: fixture.files.f.f.signingKey,
                transportKey: P256.Signing.PrivateKey(x963Representation: key),
                ownerUID: differentOwnerUID ? account.ownerUID + 1 : nil)
            XCTAssertNoThrow(try ready.requirePublishedIntent(promotion))
            if differentOwnerUID {
                XCTAssertThrowsError(try ready.requirePublication(promotion)) {
                    XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope)
                }
            } else { XCTAssertNoThrow(try ready.requirePublication(promotion)) }
            XCTAssertNil(try fixture.machine.retainedSetupPromotionReady(accountID: account.accountID,
                ownerUID: account.ownerUID, candidate: fixture.candidate))
            func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
            let id = ready.id.uuidString.replacingOccurrences(of: "-", with: "")
            let revision = ready.revision.uuidString.replacingOccurrences(of: "-", with: "")
            let record = try hex(ready.encoded)
            try fixture.machine.close()
            try fixture.files.sql(MachineUpdateRetainedSetupPromotionReadyStorage.createSQL)
            try fixture.files.sql("PRAGMA user_version=28")
            try fixture.files.sql("INSERT INTO retained_setup_promotion_ready_v1 VALUES(X'\(hex(account.accountID))',X'\(id)',X'\(revision)',X'\(record)')")
            try fixture.files.reopen()
            try body(fixture, account, completion, promotion, ready)
        }
    }

    func testRetainedSetupReadinessReadsSchema28AndRejectsOrdinaryWrites() throws {
        try withReadinessReaderFixture { fixture, account, completion, promotion, ready in
            let snapshot = try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)
            XCTAssertEqual(snapshot.schemaVersion, 28)
            XCTAssertEqual(try fixture.machine.retainedSetupPromotionReady(accountID: account.accountID,
                ownerUID: account.ownerUID, candidate: fixture.candidate), ready)
            XCTAssertEqual(try fixture.machine.retainedSetupPromotionIntent(accountID: account.accountID,
                ownerUID: account.ownerUID, candidate: fixture.candidate), promotion)
            XCTAssertEqual(try fixture.machine.retainedSetupCompletionIntent(accountID: account.accountID,
                ownerUID: account.ownerUID, candidate: fixture.candidate), completion)
            XCTAssertNil(try fixture.machine.retainedSetupPromotionReady(accountID: Data(repeating: 0, count: 16),
                ownerUID: account.ownerUID, candidate: fixture.candidate))
            XCTAssertThrowsError(try fixture.machine.retainedSetupPromotionReady(accountID: account.accountID,
                ownerUID: account.ownerUID + 1, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try fixture.machine.writeInventory(snapshot.inventory, expectedRevision: snapshot.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try fixture.machine.close()
            try fixture.files.sql("DELETE FROM retained_setup_promotion_ready_v1")
            try fixture.files.reopen()
            XCTAssertNil(try fixture.machine.retainedSetupPromotionReady(accountID: account.accountID,
                ownerUID: account.ownerUID, candidate: fixture.candidate))
            XCTAssertNotEqual(try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate).currentRowsDigest,
                snapshot.currentRowsDigest)
        }
    }

    func testRetainedSetupReadinessRequiresExactColumnsAndTheActualPublishedPromotion() throws {
        try withReadinessReaderFixture { fixture, account, _, promotion, ready in
            func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
            let accountHex = hex(account.accountID)
            let id = ready.id.uuidString.replacingOccurrences(of: "-", with: "")
            let revision = ready.revision.uuidString.replacingOccurrences(of: "-", with: "")
            let record = try hex(ready.encoded)
            func readRejected(_ expected: PreparationStoreError = .corruptRecord) {
                XCTAssertThrowsError(try fixture.machine.retainedSetupPromotionReady(accountID: account.accountID,
                    ownerUID: account.ownerUID, candidate: fixture.candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, expected)
                }
            }
            for mutation in ["account=zeroblob(16)", "id=zeroblob(16)", "revision=zeroblob(16)", "record=X'01'"] {
                try fixture.machine.close()
                try fixture.files.sql("UPDATE retained_setup_promotion_ready_v1 SET \(mutation)")
                try fixture.files.reopen(); readRejected()
                try fixture.machine.close()
                try fixture.files.sql("UPDATE retained_setup_promotion_ready_v1 SET account=X'\(accountHex)',id=X'\(id)',revision=X'\(revision)',record=X'\(record)'")
                try fixture.files.reopen()
                XCTAssertEqual(try fixture.machine.retainedSetupPromotionReady(accountID: account.accountID,
                    ownerUID: account.ownerUID, candidate: fixture.candidate), ready)
            }
            let limits = try CBORLimits(maxBytes: 4_194_304, maxDepth: 1, maxItems: 64)
            guard case .map(let original) = try DeterministicCBOR.decode(promotion.encoded, limits: limits) else {
                throw ReplacementFixtureError.injected
            }
            func replacePromotion(_ fields: [UInt64: CBORValue]?) throws {
                try fixture.machine.close()
                try fixture.files.sql("DELETE FROM retained_setup_promotion_intents_v1")
                if let fields {
                    let bytes = try DeterministicCBOR.encode(.map(fields), limits: limits)
                    let value = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(bytes)
                    let id = value.id.uuidString.replacingOccurrences(of: "-", with: "")
                    let revision = value.revision.uuidString.replacingOccurrences(of: "-", with: "")
                    try fixture.files.sql("INSERT INTO retained_setup_promotion_intents_v1 VALUES(X'\(accountHex)',X'\(id)',X'\(revision)',X'\(hex(bytes))')")
                }
                try fixture.files.reopen()
            }
            for key in [UInt64(2), 3, 4] {
                var fields = original
                if key == 4 { fields[key] = .unsigned(1) }
                else { fields[key] = .bytes(Data(repeating: 42, count: 16)) }
                try replacePromotion(fields); readRejected(key == 2 ? .corruptRecord : .staleRevision)
                try replacePromotion(original)
                XCTAssertEqual(try fixture.machine.retainedSetupPromotionReady(accountID: account.accountID,
                    ownerUID: account.ownerUID, candidate: fixture.candidate), ready)
            }
            try replacePromotion(nil); readRejected()
            try replacePromotion(original)
            try fixture.machine.close()
            try fixture.files.sql("DELETE FROM retained_setup_completion_intents_v1")
            try fixture.files.reopen(); readRejected()
        }
    }

    func testRetainedSetupReadinessRejectsOnlyTheDifferentSignedBindingOwner() throws {
        try withReadinessReaderFixture(differentOwnerUID: true) { fixture, account, _, promotion, ready in
            let binding = try MachineUpdateRetainedSetupHealthEvidence.decodeRequestedRequirement(ready.request).binding
            let selected = try promotion.publication().configuration.archive.binding.startupBinding
            XCTAssertEqual(binding.macID, selected.macID)
            XCTAssertEqual(binding.installationID, selected.installationID)
            XCTAssertEqual(binding.accountID, selected.accountID)
            XCTAssertEqual(binding.accountID, account.accountID)
            XCTAssertEqual(binding.ownerUID, account.ownerUID + 1)
            XCTAssertNotEqual(binding.ownerUID, selected.ownerUID)
            XCTAssertNoThrow(try ready.requirePublishedIntent(promotion))
            XCTAssertEqual(try MachineUpdateRetainedSetupPromotionReadyRecord.decode(ready.encoded), ready)
            XCTAssertThrowsError(try fixture.machine.retainedSetupPromotionReady(accountID: account.accountID,
                ownerUID: account.ownerUID, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testRetainedSetupReadinessRejectsAValidForeignSignedRecord() throws {
        try withReadinessReaderFixture { fixture, account, _, _, _ in
            let foreign = try RetainedSetupReadinessArchiveTests.Fixture()
            let ready = try MachineUpdateRetainedSetupPromotionReadyRecord.decode(foreign.encode(foreign.readyFields()))
            XCTAssertNoThrow(try ready.requirePublication(foreign.promotion))
            let binding = try MachineUpdateRetainedSetupHealthEvidence.decodeRequestedRequirement(ready.request).binding
            XCTAssertNotEqual(binding.accountID, account.accountID)
            func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
            let id = ready.id.uuidString.replacingOccurrences(of: "-", with: "")
            let revision = ready.revision.uuidString.replacingOccurrences(of: "-", with: "")
            let record = try hex(ready.encoded)
            try fixture.machine.close()
            try fixture.files.sql("DELETE FROM retained_setup_promotion_ready_v1")
            try fixture.files.sql("INSERT INTO retained_setup_promotion_ready_v1 VALUES(X'\(hex(binding.accountID))',X'\(id)',X'\(revision)',X'\(record)')")
            try fixture.files.reopen()
            XCTAssertThrowsError(try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testRetainedSetupReadinessRequiresTheNewReaderFormats() throws {
        try withReadinessReaderFixture(readerFormats: false) { fixture, account, _, _, _ in
            XCTAssertNoThrow(try MachineUpdateRetainedSetupPromotionStorage.requireReaderFormats(fixture.candidate))
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionReadyStorage.requireReaderFormats(fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            XCTAssertThrowsError(try fixture.machine.retainedSetupPromotionReady(accountID: account.accountID,
                ownerUID: account.ownerUID, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
        }
    }

    func testRetainedSetupReadinessRequiresItsExactTableDeclaration() throws {
        try withReadinessReaderFixture { fixture, _, _, _, _ in
            try fixture.machine.close()
            try fixture.files.sql("ALTER TABLE retained_setup_promotion_ready_v1 RENAME TO replaced_ready")
            try fixture.files.sql("CREATE TABLE retained_setup_promotion_ready_v1(account BLOB PRIMARY KEY,id BLOB,revision BLOB,record BLOB) STRICT")
            try fixture.files.sql("DROP TABLE replaced_ready")
            XCTAssertThrowsError(try fixture.files.reopen()) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
        }
    }

    func testRetainedSetupPromotionReadsSchema27AndRejectsOrdinaryWrites() throws {
        try withPromotionReaderFixture { fixture, account, completion, promotion in
            let recordBytes = try promotion.encoded
            // This fixture fits the ordinary cell bound. It does not prove acceptance above that bound.
            XCTAssertLessThanOrEqual(recordBytes.count, 278_528,
                "The fixture exceeds the ordinary cell bound. Update its declared coverage before accepting this test.")
            let snapshot = try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)
            XCTAssertEqual(snapshot.schemaVersion, 27)
            XCTAssertEqual(try fixture.machine.retainedSetupPromotionIntent(accountID: account.accountID,
                ownerUID: account.ownerUID, candidate: fixture.candidate), promotion)
            XCTAssertEqual(try fixture.machine.retainedSetupCompletionIntent(accountID: account.accountID,
                ownerUID: account.ownerUID, candidate: fixture.candidate), completion)
            XCTAssertNil(try fixture.machine.retainedSetupPromotionIntent(accountID: Data(repeating: 0, count: 16),
                ownerUID: account.ownerUID, candidate: fixture.candidate))
            XCTAssertThrowsError(try fixture.machine.retainedSetupPromotionIntent(accountID: account.accountID,
                ownerUID: account.ownerUID + 1, candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try fixture.machine.writeInventory(snapshot.inventory, expectedRevision: snapshot.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            let table = MachineUpdateRetainedSetupPromotionStorage.tableName
            try fixture.machine.close()
            try fixture.files.sql("DELETE FROM \(table)")
            try fixture.files.reopen()
            XCTAssertNil(try fixture.machine.retainedSetupPromotionIntent(accountID: account.accountID,
                ownerUID: account.ownerUID, candidate: fixture.candidate))
            XCTAssertNotEqual(try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate).currentRowsDigest,
                snapshot.currentRowsDigest)
        }
    }

    func testRetainedSetupPromotionRequiresExactColumnsAndTheActualCompletionRow() throws {
        try withPromotionReaderFixture { fixture, account, completion, promotion in
            func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
            let accountHex = hex(account.accountID)
            let id = promotion.id.uuidString.replacingOccurrences(of: "-", with: "")
            let revision = promotion.revision.uuidString.replacingOccurrences(of: "-", with: "")
            let record = try hex(promotion.encoded)
            func reject(_ update: String) throws {
                try fixture.machine.close()
                try fixture.files.sql("UPDATE retained_setup_promotion_intents_v1 SET \(update)")
                try fixture.files.reopen()
                XCTAssertThrowsError(try fixture.machine.retainedSetupPromotionIntent(accountID: account.accountID,
                    ownerUID: account.ownerUID, candidate: fixture.candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
                try fixture.machine.close()
                try fixture.files.sql("UPDATE retained_setup_promotion_intents_v1 SET account=X'\(accountHex)',id=X'\(id)',revision=X'\(revision)',record=X'\(record)'")
            }
            try reject("account=zeroblob(16)")
            try reject("id=zeroblob(16)")
            try reject("revision=zeroblob(16)")
            try reject("record=X'01'")
            try reject("record=zeroblob(\(MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes))")
            var different = try XCTUnwrap(JSONSerialization.jsonObject(with: completion.encoded) as? [String: Any])
            let differentRevision = UUID()
            different["revision"] = differentRevision.uuidString
            let differentBytes = try JSONSerialization.data(withJSONObject: different, options: [.sortedKeys, .withoutEscapingSlashes])
            let decoded = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(differentBytes)
            XCTAssertNotEqual(decoded, completion)
            let differentID = differentRevision.uuidString.replacingOccurrences(of: "-", with: "")
            try fixture.files.sql("UPDATE retained_setup_completion_intents_v1 SET revision=X'\(differentID)',record=X'\(hex(differentBytes))'")
            try fixture.files.reopen()
            XCTAssertThrowsError(try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            try fixture.machine.close()
            try fixture.files.sql("DELETE FROM retained_setup_completion_intents_v1")
            try fixture.files.reopen()
            XCTAssertThrowsError(try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testRetainedSetupPromotionRejectsAValidForeignPublication() throws {
        try withPromotionReaderFixture { fixture, account, _, _ in
            let foreign = try RetainedSetupPromotionArchiveTests.Fixture()
            let record = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(foreign.record())
            let binding = try record.publication().configuration.archive.binding.startupBinding
            XCTAssertNotEqual(binding.accountID, account.accountID)
            func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
            try fixture.machine.close()
            try fixture.files.sql("DELETE FROM retained_setup_promotion_intents_v1")
            let id = record.id.uuidString.replacingOccurrences(of: "-", with: "")
            let revision = record.revision.uuidString.replacingOccurrences(of: "-", with: "")
            try fixture.files.sql("INSERT INTO retained_setup_promotion_intents_v1 VALUES(X'\(hex(binding.accountID))',X'\(id)',X'\(revision)',X'\(try hex(record.encoded))')")
            try fixture.files.reopen()
            // The foreign account and missing completion row both reject this valid archive.
            XCTAssertThrowsError(try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testRetainedSetupPromotionRequiresItsExactTableDeclaration() throws {
        try withPromotionReaderFixture { fixture, _, _, _ in
            try fixture.machine.close()
            try fixture.files.sql("ALTER TABLE retained_setup_promotion_intents_v1 RENAME TO replaced_promotion")
            try fixture.files.sql("CREATE TABLE retained_setup_promotion_intents_v1(account BLOB PRIMARY KEY,id BLOB,revision BLOB,record BLOB) STRICT")
            try fixture.files.sql("DROP TABLE replaced_promotion")
            XCTAssertThrowsError(try fixture.files.reopen()) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
        }
    }

    func testRetainedSetupCompletionReadsSchema26AndRequiresTheExactStartupRow() throws {
        var retained: AccountPreparationIntent?
        try withFinishingFixture(stableFormats: true, policyReaderFormats: true, completionReaderFormats: true,
            beforeActivation: { retained = try self.prepareSecondForeground($0).account }) { fixture, finishing, _ in
            let account = try XCTUnwrap(retained)
            let candidate = fixture.candidate
            let owner = LocalAccountIdentity(uid: account.ownerUID, primaryGroupID: getgid(), directoryID: account.directoryID)
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try fixture.machine.withCurrentMachineUpdateReadiness(candidate: candidate, directory: fixture.directory, loan: loan) {
                try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: candidate)
            }
            _ = try fixture.machine.commitStableMachineUpdate(expected: plan, candidate: candidate,
                directory: fixture.directory, loan: loan) { _, _ in }
            XCTAssertNil(try fixture.machine.retainedSetupCompletionIntent(accountID: account.accountID, ownerUID: owner.uid, candidate: candidate))
            let reader = try fixture.openPolicyPair(readOnly: true, accountID: account.accountID)
            defer { try? reader.close() }
            let source = try MachineUpdateRetainedSetupActivationSource.capture(owner: owner, machine: fixture.machine,
                journal: reader, candidate: candidate)
            let prepared = try MachineUpdateRetainedSetupPolicyIntentRecord(source: source)
            try reader.close()

            let storage = try fixture.policyStorage(readOnly: false, accountID: account.accountID)
            defer { try? storage.close() }
            let commits = CheckpointedJournal(journal: storage.journal, continuity: storage.continuity)
            let startupPolicy = try commits.write(epoch: source.accountPolicy.checkpoint.journalEpoch) {
                try $0.installCodePolicy(source.policy.startupPolicy, expectedRevision: source.policy.source.revision)
            }
            let checkpoint = try storage.continuity.read().committed
            let completionPolicy = try commits.write(epoch: checkpoint.journalEpoch) {
                try $0.installCodePolicy(source.policy.completionPolicy, expectedRevision: startupPolicy.revision)
            }
            let completionCheckpoint = try storage.continuity.read().committed
            XCTAssertNotEqual(completionPolicy.revision, startupPolicy.revision)
            XCTAssertEqual(completionCheckpoint.generation, checkpoint.generation + 1)
            XCTAssertEqual(completionCheckpoint.authorityGeneration, checkpoint.currentAuthorityGeneration + 1)
            for (before, after) in zip(startupPolicy.policy.entries, completionPolicy.policy.entries) {
                XCTAssertEqual(before == after, startupPolicy.roleRevisions[before.role] == completionPolicy.roleRevisions[after.role])
            }
            try storage.close()
            func json(_ fields: [String: Any]) throws -> Data {
                try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
            }
            var startup = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.encoded) as? [String: Any])
            startup["phase"] = MachineUpdateRetainedSetupPolicyIntentRecord.Phase.recorded.rawValue
            startup["committedPolicy"] = [
                "revision": startupPolicy.revision.uuidString, "bytes": try startupPolicy.storedBytes.base64EncodedString()
            ]
            startup["committedCheckpoint"] = try checkpoint.bytes.base64EncodedString()
            let startupRecord = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(json(startup))
            func digest(_ bytes: Data) -> String { MachineUpdateActivationRecord.digest(bytes).base64EncodedString() }
            let syntheticDigest = digest(Data("archive fixture".utf8))
            // The row reader binds the two archives. It does not open an activation plan or prove native startup.
            var binding: [String: Any] = [
                "formatVersion": 1, "macID": account.macID.base64EncodedString(), "installationID": account.installationID.base64EncodedString(),
                "accountID": account.accountID.base64EncodedString(), "ownerUID": owner.uid, "activationAttempt": finishing.activation.attemptID.uuidString,
                "initializationDigest": startupRecord.initializationDigest.base64EncodedString(),
                "provisioningReleaseDigest": account.releaseDigest.base64EncodedString(),
                "installedReleaseDigest": startupRecord.installedReleaseDigest.base64EncodedString(),
                "retainedSourceDigest": startupRecord.sourceDigest.base64EncodedString(), "policyIntentDigest": try digest(startupRecord.encoded),
                "sourcePolicyDigest": try digest(source.policy.source.storedBytes), "sourceCheckpointDigest": digest(startupRecord.sourceCheckpoint),
                "startupPolicyDigest": digest(startupRecord.startupPolicy), "startupPolicySnapshotDigest": try digest(startupPolicy.storedBytes),
                "startupCheckpointDigest": try digest(checkpoint.bytes), "completionPolicyDigest": digest(startupRecord.completionPolicy),
            ]
            for name in ["candidateDigest", "admissionDigest", "updateID", "stableSealDigest", "installedEpochDigest", "sealedInventoryDigest",
                         "sourceAccountDigest", "preparationDigest", "provisioningInventoryDigest", "previousInstalledReleaseDigest", "runtimeReferenceDigest"] {
                binding[name] = syntheticDigest
            }
            var completionFields: [String: Any] = [
                "formatVersion": 1, "id": UUID().uuidString, "revision": UUID().uuidString, "phase": 1,
                "startupIntent": startup, "binding": binding, "activationPlanDigest": syntheticDigest, "inventoryDigest": syntheticDigest,
            ]
            let preparedCompletion = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(json(completionFields))
            XCTAssertEqual(try RuntimeRetainedSetupReleaseBinding.decode(preparedCompletion.binding.encoded), preparedCompletion.binding)
            XCTAssertEqual(preparedCompletion.startupIntent, startupRecord)
            completionFields["phase"] = MachineUpdateRetainedSetupCompletionIntentRecord.Phase.recorded.rawValue
            XCTAssertThrowsError(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(json(completionFields))) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }

            completionFields["committedPolicy"] = [
                "revision": completionPolicy.revision.uuidString, "bytes": try completionPolicy.storedBytes.base64EncodedString()
            ]
            completionFields["committedCheckpoint"] = try completionCheckpoint.bytes.base64EncodedString()
            let record = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(json(completionFields))
            XCTAssertEqual(record.phase, .recorded)
            XCTAssertEqual(try record.committedPolicy?.snapshot(), completionPolicy)
            XCTAssertEqual(record.committedCheckpoint, try completionCheckpoint.bytes)

            let completionBinding = try RuntimeRetainedSetupCompletionBinding.decode(json([
                "formatVersion": 1, "startupBinding": binding,
                "recordedCompletionDigest": try digest(record.encoded), "activationPlanDigest": syntheticDigest,
                "recordedInventoryDigest": syntheticDigest, "completionPolicyRevision": completionPolicy.revision.uuidString,
                "completionPolicySnapshotDigest": try digest(completionPolicy.storedBytes),
                "completionCheckpointDigest": try digest(completionCheckpoint.bytes),
            ]))
            let completionBoundary = AuthorityJournal.MachineUpdatePolicyBoundary(macID: account.macID,
                accountID: account.accountID, policy: completionPolicy, checkpoint: completionCheckpoint)
            XCTAssertNoThrow(try completionBinding.requireRecordedBoundary(completionBoundary))
            XCTAssertNotEqual(try startupPolicy.policy.bytes, try completionPolicy.policy.bytes)
            XCTAssertNoThrow(try completionBinding.requireCompletionPolicy(completionPolicy.policy))
            XCTAssertThrowsError(try completionBinding.requireCompletionPolicy(startupPolicy.policy)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            let otherRevision = AuthorityCodePolicySnapshot(revision: UUID(), policy: completionPolicy.policy,
                roleRevisions: completionPolicy.roleRevisions)
            XCTAssertEqual(try otherRevision.storedBytes, try completionPolicy.storedBytes)
            let otherRoleRevisions = Dictionary(uniqueKeysWithValues: completionPolicy.roleRevisions.keys.map { ($0, UUID()) })
            let otherSnapshot = AuthorityCodePolicySnapshot(revision: completionPolicy.revision,
                policy: completionPolicy.policy, roleRevisions: otherRoleRevisions)
            XCTAssertNotEqual(try otherSnapshot.storedBytes, try completionPolicy.storedBytes)
            for wrong in [
                AuthorityJournal.MachineUpdatePolicyBoundary(macID: account.macID, accountID: account.accountID,
                    policy: otherRevision, checkpoint: completionCheckpoint),
                .init(macID: account.macID, accountID: account.accountID, policy: otherSnapshot, checkpoint: completionCheckpoint),
                .init(macID: account.macID, accountID: account.accountID, policy: startupPolicy, checkpoint: completionCheckpoint),
                .init(macID: account.macID, accountID: account.accountID, policy: completionPolicy, checkpoint: checkpoint),
                .init(macID: Data(repeating: 0, count: 16), accountID: account.accountID,
                    policy: completionPolicy, checkpoint: completionCheckpoint),
                .init(macID: account.macID, accountID: Data(repeating: 0, count: 16),
                    policy: completionPolicy, checkpoint: completionCheckpoint),
            ] {
                XCTAssertThrowsError(try completionBinding.requireRecordedBoundary(wrong)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
                }
            }

            // Use the same real boundary at all three phases to exercise a no-op completion receipt.
            let unchangedPolicy = try completionPolicy.policy.bytes
            let unchangedCheckpoint = try completionCheckpoint.bytes
            var unchangedStartup = startup
            unchangedStartup["sourcePolicy"] = completionFields["committedPolicy"]
            unchangedStartup["committedPolicy"] = completionFields["committedPolicy"]
            unchangedStartup["sourceCheckpoint"] = unchangedCheckpoint.base64EncodedString()
            unchangedStartup["committedCheckpoint"] = unchangedCheckpoint.base64EncodedString()
            unchangedStartup["startupPolicy"] = unchangedPolicy.base64EncodedString()
            unchangedStartup["completionPolicy"] = unchangedPolicy.base64EncodedString()
            var unchangedBinding = binding
            unchangedBinding["policyIntentDigest"] = try digest(json(unchangedStartup))
            let unchangedSnapshotDigest = try digest(completionPolicy.storedBytes)
            unchangedBinding["sourcePolicyDigest"] = unchangedSnapshotDigest
            unchangedBinding["startupPolicySnapshotDigest"] = unchangedSnapshotDigest
            unchangedBinding["sourceCheckpointDigest"] = digest(unchangedCheckpoint)
            unchangedBinding["startupCheckpointDigest"] = digest(unchangedCheckpoint)
            unchangedBinding["startupPolicyDigest"] = digest(unchangedPolicy)
            unchangedBinding["completionPolicyDigest"] = digest(unchangedPolicy)
            var unchangedCompletion = completionFields
            unchangedCompletion["startupIntent"] = unchangedStartup
            unchangedCompletion["binding"] = unchangedBinding
            let noOp = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(json(unchangedCompletion))
            XCTAssertEqual(noOp.phase, .recorded)
            XCTAssertEqual(try noOp.committedPolicy?.snapshot(), completionPolicy)
            XCTAssertEqual(noOp.committedCheckpoint, unchangedCheckpoint)
            unchangedCompletion["committedCheckpoint"] = try checkpoint.bytes.base64EncodedString()
            XCTAssertThrowsError(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(json(unchangedCompletion))) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }

            let policyTable = MachineUpdateRetainedSetupPolicyStorage.tableName
            let completionTable = MachineUpdateRetainedSetupCompletionStorage.tableName
            func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
            func row(accountID: Data, id: UUID, revision: UUID, bytes: Data) -> String {
                let id = id.uuidString.replacingOccurrences(of: "-", with: "")
                let revision = revision.uuidString.replacingOccurrences(of: "-", with: "")
                return "(X'\(hex(accountID))',X'\(id)',X'\(revision)',X'\(hex(bytes))')"
            }
            try fixture.machine.close()
            try fixture.files.sql(MachineUpdateRetainedSetupPolicyStorage.createSQL)
            try fixture.files.sql(MachineUpdateRetainedSetupCompletionStorage.createSQL)
            try fixture.files.sql("PRAGMA user_version=26")
            try fixture.files.sql("INSERT INTO \(policyTable) VALUES \(try row(accountID: account.accountID, id: startupRecord.id, revision: startupRecord.revision, bytes: startupRecord.encoded))")
            try fixture.files.reopen()
            let empty = try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate)
            XCTAssertEqual(empty.schemaVersion, 26)
            try fixture.machine.close()
            try fixture.files.sql("INSERT INTO \(completionTable) VALUES \(try row(accountID: account.accountID, id: record.id, revision: record.revision, bytes: record.encoded))")
            try fixture.files.reopen()
            let actual = try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate)
            XCTAssertNotEqual(actual.currentRowsDigest, empty.currentRowsDigest)
            XCTAssertEqual(try fixture.machine.retainedSetupCompletionIntent(accountID: account.accountID, ownerUID: owner.uid, candidate: candidate), record)
            XCTAssertThrowsError(try fixture.machine.retainedSetupCompletionIntent(accountID: account.accountID,
                ownerUID: owner.uid + 1, candidate: candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            XCTAssertThrowsError(try fixture.machine.writeInventory(actual.inventory, expectedRevision: actual.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }

            func changed(_ value: Data, offset: UInt8 = 1) -> Data {
                var result = value
                result[result.index(before: result.endIndex)] &+= offset
                return result
            }
            func requireCorruptRows(_ description: String) throws {
                try fixture.files.reopen()
                XCTAssertThrowsError(try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate), description) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord, description)
                }
                try fixture.machine.close()
            }
            func rejectCompletionUpdate(_ update: String, restoring original: String, field: String) throws {
                try fixture.machine.close()
                try fixture.files.sql("UPDATE \(completionTable) SET \(update)")
                try requireCorruptRows(field)
                try fixture.files.sql("UPDATE \(completionTable) SET \(original)")
            }
            let recordID = record.id.uuidString.replacingOccurrences(of: "-", with: "")
            let revision = record.revision.uuidString.replacingOccurrences(of: "-", with: "")
            try rejectCompletionUpdate("account=X'\(hex(changed(account.accountID)))'",
                restoring: "account=X'\(hex(account.accountID))'", field: "completion account column")
            try rejectCompletionUpdate("id=zeroblob(16)", restoring: "id=X'\(recordID)'", field: "completion ID column")
            try rejectCompletionUpdate("revision=zeroblob(16)", restoring: "revision=X'\(revision)'", field: "completion revision column")

            func archivePair(changing field: String, to value: Data, newIDs: Bool = false)
                throws -> (MachineUpdateRetainedSetupPolicyIntentRecord, MachineUpdateRetainedSetupCompletionIntentRecord) {
                var policy = startup
                var operands = binding
                var completion = completionFields
                policy[field] = value.base64EncodedString()
                operands[field] = policy[field]
                if newIDs {
                    policy["id"] = UUID().uuidString
                    completion["id"] = UUID().uuidString
                }
                let policyBytes = try json(policy)
                let policyRecord = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(policyBytes)
                operands["policyIntentDigest"] = digest(policyBytes)
                completion["startupIntent"] = policy
                completion["binding"] = operands
                return (policyRecord, try MachineUpdateRetainedSetupCompletionIntentRecord.decode(json(completion)))
            }
            let originalRecord = try hex(record.encoded)
            // The namespace checks provide defense in depth. These rows also fail the startup row match.
            for (field, value) in [("macID", account.macID), ("installationID", account.installationID)] {
                let (_, foreign) = try archivePair(changing: field, to: changed(value))
                try rejectCompletionUpdate("record=X'\(try hex(foreign.encoded))'",
                    restoring: "record=X'\(originalRecord)'", field: field)
            }

            let startupRow = try row(accountID: account.accountID, id: startupRecord.id,
                revision: startupRecord.revision, bytes: startupRecord.encoded)
            try fixture.files.sql("DELETE FROM \(policyTable)")
            try requireCorruptRows("missing startup row")
            var changedStartupFields = startup
            changedStartupFields["revision"] = UUID().uuidString
            let changedStartup = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(json(changedStartupFields))
            let changedStartupRow = try row(accountID: account.accountID, id: changedStartup.id,
                revision: changedStartup.revision, bytes: changedStartup.encoded)
            try fixture.files.sql("INSERT INTO \(policyTable) VALUES \(changedStartupRow)")
            try requireCorruptRows("different startup row")
            try fixture.files.sql("DELETE FROM \(policyTable)")
            try fixture.files.sql("INSERT INTO \(policyTable) VALUES \(startupRow)")

            var policyRows: [String] = []
            var completionRows: [String] = []
            for offset in 1...63 {
                let other = changed(account.accountID, offset: UInt8(offset))
                let (policy, completion) = try archivePair(changing: "accountID", to: other, newIDs: true)
                policyRows.append(try row(accountID: other, id: policy.id, revision: policy.revision, bytes: policy.encoded))
                completionRows.append(try row(accountID: other, id: completion.id, revision: completion.revision, bytes: completion.encoded))
            }
            try fixture.files.sql("INSERT INTO \(policyTable) VALUES \(policyRows.joined(separator: ","))")
            try fixture.files.sql("INSERT INTO \(completionTable) VALUES \(completionRows.joined(separator: ","))")
            try fixture.files.reopen()
            let atCapacity = try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate)
            XCTAssertNotEqual(atCapacity.currentRowsDigest, actual.currentRowsDigest)
            try fixture.machine.close()

            // The row cap provides defense in depth. A valid startup table has only 64 rows.
            // Drop the fixture's completion primary key to add a duplicate at position 65.
            // The duplicate also violates the account uniqueness check.
            let copy = "fixture_completion_rows"
            try fixture.files.sql("ALTER TABLE \(completionTable) RENAME TO \(copy)")
            try fixture.files.sql("CREATE TABLE \(completionTable) AS SELECT * FROM \(copy)")
            try fixture.files.sql("DROP TABLE \(copy)")
            try fixture.files.sql("INSERT INTO \(completionTable) SELECT * FROM \(completionTable) ORDER BY account DESC LIMIT 1")
            try requireCorruptRows("65th completion row")
        }
    }

    func testRetainedSetupPolicyObservesTheOriginalPairAndItsStartupSuccessor() throws {
        var retained: AccountPreparationIntent?
        try withFinishingFixture(stableFormats: true,
            beforeActivation: { retained = try self.prepareSecondForeground($0).account }) { fixture, finishing, _ in
            let account = try XCTUnwrap(retained)
            let machine = fixture.machine, candidate = fixture.candidate, directory = fixture.directory
            let owner = LocalAccountIdentity(uid: account.ownerUID, primaryGroupID: getgid(), directoryID: account.directoryID)
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try machine.withCurrentMachineUpdateReadiness(candidate: candidate, directory: directory, loan: loan) {
                try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: candidate)
            }
            _ = try machine.commitStableMachineUpdate(expected: plan, candidate: candidate, directory: directory, loan: loan) { _, _ in }
            let material = try machine.retainedSetupPolicyMaterial(owner: owner, candidate: candidate)
            XCTAssertEqual(material.runtime.preparation, account)
            XCTAssertFalse(material.runtime.state.configurationPublished)

            let stableSource = material.runtime.setup.source
            let stable = stableSource.actual
            let inventory = stable.inventory
            let enrolled = try InstallationAccount(accountID: account.accountID, ownerUID: account.ownerUID)
            let enrolledInventory = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID,
                revision: AccountPreparationIntent.randomID(), bundlePath: inventory.bundlePath, releaseDigest: inventory.releaseDigest,
                accounts: inventory.accounts + [enrolled], services: inventory.services, formatVersion: inventory.formatVersion)
            let enrolledStable = MachineUpdateStableReleaseSnapshot(schemaVersion: stable.schemaVersion,
                inventory: enrolledInventory, activation: stable.activation,
                admission: stable.admission, candidate: stable.candidate, installed: stable.installed, seal: stable.seal,
                currentRowsDigest: stable.currentRowsDigest)
            let enrolledSource = try MachineUpdateStableRuntimeSource(actual: enrolledStable, preparations: stableSource.preparations,
                initializations: stableSource.initializations, candidate: candidate)
            let enrolledSetup = try MachineUpdateStableAccountSetupSnapshot(source: enrolledSource, owner: owner)
            let enrolledRuntime = try MachineUpdateStableRuntimePreparationSnapshot(setup: enrolledSetup,
                services: .init(plan: material.runtime.plan, complete: true), state: material.runtime.state,
                reservedNumbers: material.runtime.reservedNumbers)
            XCTAssertEqual(enrolledSetup.account?.inInventory, true)
            XCTAssertEqual(try enrolledSource.unconfiguredRetainedAccount(accountID: account.accountID, ownerUID: owner.uid),
                material.original)
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPolicyMaterial(runtime: enrolledRuntime,
                activation: .init(plan: nil, jobsRegistered: false))) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }

            let original = try fixture.openPolicyPair(readOnly: true, accountID: account.accountID)
            defer { try? original.close() }
            let source = try MachineUpdateRetainedSetupActivationSource.capture(owner: owner, machine: machine,
                journal: original, candidate: candidate)
            let prepared = try MachineUpdateRetainedSetupPolicyIntentRecord(source: source)
            XCTAssertEqual(try MachineUpdateRetainedSetupPolicyIntentRecord.decode(prepared.encoded), prepared)
            XCTAssertNotEqual(source.policy.startupPolicy, source.policy.source.policy)
            XCTAssertEqual(try prepared.observe(owner: owner, machine: machine, journal: original, candidate: candidate), .sourceUnchanged)

            func recordBytes(_ fields: [String: Any]) throws -> Data {
                try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
            }
            let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.encoded) as? [String: Any])
            var writingFields = fields
            writingFields["phase"] = MachineUpdateRetainedSetupPolicyIntentRecord.Phase.writing.rawValue
            let writing = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(recordBytes(writingFields))
            XCTAssertEqual(try writing.observe(owner: owner, machine: machine, journal: original, candidate: candidate), .sourceUnchanged)
            try original.close()

            let storage = try fixture.policyStorage(readOnly: false, accountID: account.accountID)
            defer { try? storage.close() }
            let commits = CheckpointedJournal(journal: storage.journal, continuity: storage.continuity)
            let committed = try commits.write(epoch: source.accountPolicy.checkpoint.journalEpoch) {
                try $0.installCodePolicy(source.policy.startupPolicy, expectedRevision: source.policy.source.revision)
            }
            let checkpoint = try storage.continuity.read().committed
            try storage.close()

            let current = try fixture.openPolicyPair(readOnly: true, accountID: account.accountID)
            defer { try? current.close() }
            XCTAssertThrowsError(try prepared.observe(owner: owner, machine: machine, journal: current, candidate: candidate)) {
                XCTAssertEqual($0 as? AuthorityInitializationError, .invalidBoundary)
            }
            XCTAssertEqual(try writing.observe(owner: owner, machine: machine, journal: current, candidate: candidate), .startupBoundary)

            var recordedFields = writingFields
            recordedFields["phase"] = MachineUpdateRetainedSetupPolicyIntentRecord.Phase.recorded.rawValue
            recordedFields["committedPolicy"] = [
                "revision": committed.revision.uuidString, "bytes": try committed.storedBytes.base64EncodedString()
            ]
            recordedFields["committedCheckpoint"] = try checkpoint.bytes.base64EncodedString()
            let recorded = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(recordBytes(recordedFields))
            XCTAssertEqual(try recorded.observe(owner: owner, machine: machine, journal: current, candidate: candidate), .startupBoundary)

            var sourceFields = try XCTUnwrap(recordedFields["sourcePolicy"] as? [String: Any])
            sourceFields["revision"] = UUID().uuidString
            recordedFields["sourcePolicy"] = sourceFields
            let stale = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(recordBytes(recordedFields))
            XCTAssertThrowsError(try stale.observe(owner: owner, machine: machine, journal: current, candidate: candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            let authority = try XCTUnwrap(source.policy.source.policy.entries.first { $0.role == .authority })
            let singleRole = try AuthorityCodePolicy(entries: [authority])
            let limits = try CBORLimits(maxBytes: AuthorityCodePolicy.maximumBytes, maxDepth: 3, maxItems: 64)
            guard case .map(var policyFields) = try DeterministicCBOR.decode(singleRole.bytes, limits: limits) else {
                return XCTFail("Expected a policy map")
            }
            policyFields[0] = .unsigned(1)
            let rawLegacy = try DeterministicCBOR.encode(.map(policyFields), limits: limits)
            let legacy = try AuthorityCodePolicySnapshot.decodeStored(rawLegacy, revision: source.policy.source.revision)
            let legacyPlan = try MachineUpdatePolicyPlan(source: legacy, candidate: candidate)
            XCTAssertEqual(legacy.policy.formatVersion, 1)
            XCTAssertEqual(legacyPlan.startupPolicy.formatVersion, 1)
            XCTAssertEqual(legacyPlan.completionPolicy.formatVersion, 1)

            var legacyFields = fields
            var legacyPolicy = try XCTUnwrap(fields["sourcePolicy"] as? [String: Any])
            legacyPolicy["bytes"] = try legacy.storedBytes.base64EncodedString()
            legacyFields["sourcePolicy"] = legacyPolicy
            legacyFields["startupPolicy"] = try legacyPlan.startupPolicy.bytes.base64EncodedString()
            legacyFields["completionPolicy"] = try legacyPlan.completionPolicy.bytes.base64EncodedString()
            XCTAssertNoThrow(try MachineUpdateRetainedSetupPolicyIntentRecord.decode(recordBytes(legacyFields)))

            legacyPolicy["bytes"] = rawLegacy.base64EncodedString()
            legacyFields["sourcePolicy"] = legacyPolicy
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPolicyIntentRecord.decode(recordBytes(legacyFields))) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testStableMachineCommitRollsBackAndLendsAnAcknowledgedReceipt() throws {
        try withFinishingFixture(stableFormats: true) { fixture, finishing, _ in
            let machine = fixture.machine, candidate = fixture.candidate, directory = fixture.directory
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try machine.withCurrentMachineUpdateReadiness(candidate: candidate, directory: directory, loan: loan) { scope in
                try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: candidate)
            }
            let anchor = fixture.files.f.f.root.path
            let ordinary = try UpdateAdmissionBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
                owner: getuid(), expected: finishing.admission.machine)
            typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
            for failure in [Stage.beforeTransaction, .inTransaction, .afterMutation] {
                XCTAssertThrowsError(try machine.commitStableMachineUpdate(expected: plan, candidate: candidate,
                    directory: directory, loan: loan) { stage, _ in
                        if stage == failure { throw ReplacementFixtureError.injected }
                    }) {
                        XCTAssertEqual($0 as? ReplacementFixtureError, .injected)
                    }
                try machine.machineUpdateFinalizationSnapshot(candidate: candidate, directory: directory).requireSame(as: finishing)
            }
            var observed: [Stage] = []
            var escaped: PreparationIntentStore.StableCompletionScope?
            let receipt = try machine.commitStableMachineUpdate(expected: plan, candidate: candidate, directory: directory, loan: loan) {
                stage, scope in
                observed.append(stage)
                escaped = scope
                XCTAssertThrowsError(try ordinary.acquireAdmission()) {
                    XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
                }
                switch try scope.read() {
                case .finishing(let actual):
                    XCTAssertTrue(stage == .beforeTransaction || stage == .inTransaction)
                    try actual.requireSame(as: plan)
                case .stable(let actual):
                    XCTAssertTrue(stage == .afterMutation || stage == .afterCommit)
                    try actual.requireInitialTransition(from: plan, release: candidate)
                }
            }
            XCTAssertEqual(observed, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertThrowsError(try XCTUnwrap(escaped).read()) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            try receipt.requireSource(plan, candidate: candidate)
            try receipt.requireCurrent(machine: machine, candidate: candidate)
            XCTAssertEqual(try receipt.read().activation.phase, .completed)
            XCTAssertThrowsError(try machine.begin(parent: fixture.files.destination.path,
                ancestry: fixture.files.destination.preparationAncestry())) {
                    XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                }
            loan.close()
            XCTAssertThrowsError(try ordinary.acquireAdmission()) {
                XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
            }
            fixture.restart.close()
            let admitted = try ordinary.acquireAdmission()
            admitted.close()
        }
    }

    func testStableMachineCommitRecoversTheReceiptAfterLostAcknowledgment() throws {
        try withFinishingFixture(stableFormats: true) { fixture, finishing, _ in
            let machine = fixture.machine, candidate = fixture.candidate, directory = fixture.directory
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try machine.withCurrentMachineUpdateReadiness(candidate: candidate, directory: directory, loan: loan) { scope in
                try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: candidate)
            }
            XCTAssertThrowsError(try machine.commitStableMachineUpdate(expected: plan, candidate: candidate,
                directory: directory, loan: loan) { stage, scope in
                    if stage == .afterCommit {
                        guard case .stable = try scope.read() else { throw ReplacementFixtureError.signature }
                        throw CancellationError()
                    }
                }) {
                    XCTAssertEqual($0 as? PreparationStoreError, .stableCommitUnconfirmed)
                }
            XCTAssertThrowsError(try machine.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try fixture.files.reopen()
            let stable = try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate)
            try stable.requireInitialTransition(from: plan, release: candidate)
            XCTAssertEqual(stable.activation.phase, .completed)
            var observed: [PreparationIntentStore.CompletionIntentStorageStage] = []
            let receipt = try fixture.machine.adoptStableMachineUpdate(expected: plan, candidate: candidate,
                directory: directory, loan: loan) { stage, scope in
                observed.append(stage)
                guard case .stable(let current) = try scope.read() else { return XCTFail("Missing stable frame") }
                try current.requireSame(as: stable)
            }
            XCTAssertEqual(observed, [.afterCommit])
            try receipt.requireSource(plan, candidate: candidate)
            try receipt.requireCurrent(machine: fixture.machine, candidate: candidate)
            XCTAssertThrowsError(try fixture.machine.machineUpdateFinalizationSnapshot(candidate: candidate, directory: directory)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertThrowsError(try fixture.machine.commitStableMachineUpdate(expected: plan, candidate: candidate,
                directory: directory, loan: loan) { _, _ in XCTFail("The settled attempt ran again") }) {
                    XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                }
            try loan.validate()
            try fixture.machine.close()
            func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
            var revision = finishing.activation.revision.uuid
            let rowRevision = withUnsafeBytes(of: &revision) { hex(Data($0)) }
            let rowRecord = try hex(finishing.activation.encoded)
            try fixture.files.sql("UPDATE machine_update_activation_v1 SET revision=X'\(rowRevision)',record=X'\(rowRecord)' WHERE id=1")
            try fixture.files.reopen()
            XCTAssertThrowsError(try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testStableProjectionKeepsTheSealAndRejectsChangedRowsForReceiptAdoption() throws {
        try withFinishingFixture(stableFormats: true) { fixture, finishing, _ in
            let machine = fixture.machine, candidate = fixture.candidate, directory = fixture.directory
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let plan = try machine.withCurrentMachineUpdateReadiness(candidate: candidate, directory: directory, loan: loan) {
                try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: candidate)
            }
            let receipt = try machine.commitStableMachineUpdate(expected: plan, candidate: candidate, directory: directory,
                loan: loan) { _, _ in }
            let initial = try receipt.read()
            XCTAssertEqual(initial.currentRowsDigest, initial.seal.historicalSourceDigest)
            try machine.close()
            try fixture.files.sql("UPDATE runtime_activation_v1 SET registered=1-registered")
            try fixture.files.reopen()
            let changed = try fixture.machine.stableMachineUpdateSnapshot(candidate: candidate)
            XCTAssertEqual(try changed.seal.encoded, try initial.seal.encoded)
            XCTAssertNotEqual(changed.currentRowsDigest, initial.currentRowsDigest)
            XCTAssertThrowsError(try changed.requireSame(as: initial)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try fixture.machine.adoptStableMachineUpdate(expected: plan, candidate: candidate,
                directory: directory, loan: loan) { _, _ in XCTFail("A changed frame reached live receipt validation") }) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
        }
    }

    /// The bridge serializes the fixture reader and the writer on the same thread.
    private final class TerminalBridgeFixtureReader: @unchecked Sendable {
        let fixture: CompletionFixture
        let loan: MachineUpdateRestartReadinessLoan
        let reads = Mutex<[String]>([])

        init(fixture: CompletionFixture, loan: MachineUpdateRestartReadinessLoan) {
            self.fixture = fixture
            self.loan = loan
        }

        func finishing() throws -> MachineUpdateInstalledReadinessPlan {
            reads.withLock { $0.append("finishing") }
            return try fixture.machine.withCurrentMachineUpdateReadiness(candidate: fixture.candidate,
                directory: fixture.directory, loan: loan) { scope in
                    try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: fixture.candidate)
                }
        }

        func stable() throws -> MachineUpdateStableReleaseSnapshot {
            reads.withLock { $0.append("stable") }
            return try fixture.machine.stableMachineUpdateSnapshot(candidate: fixture.candidate)
        }
    }

    func testTerminalReadBridgeUsesTheWriterFrameUntilItAdoptsTheReceipt() throws {
        try withFinishingFixture(stableFormats: true) { fixture, finishing, _ in
            let loan = try stableFixtureLoan(fixture, finishing: finishing)
            defer { loan.close() }
            let reader = TerminalBridgeFixtureReader(fixture: fixture, loan: loan)
            let plan = try reader.finishing()
            let candidate = fixture.candidate
            let bridge = try MachineUpdateInstalledTerminalReadBridge(plan: plan, candidate: candidate,
                readFinishing: { try reader.finishing() }, readStable: { try reader.stable() })
            defer { bridge.close() }
            try bridge.requireCurrent()
            var peerChecks = 0
            let receipt = try bridge.settle(verifyLive: {
                peerChecks += 1
                try bridge.requireCurrent()
                let acquire = MachineUpdateNativeInstalledReadiness.coordinatedActivity(terminal: bridge) {
                    XCTFail("Settlement called the activity factory")
                    throw ReplacementFixtureError.injected
                }
                XCTAssertThrowsError(try acquire()) {
                    XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                }
                XCTAssertEqual(reader.reads.withLock { $0 }, ["finishing", "finishing", "finishing"])
            }, write: { verify in
                let machine = fixture.machine
                let receipt = try machine.commitStableMachineUpdate(expected: plan, candidate: candidate,
                    directory: fixture.directory, loan: loan, verifyScoped: verify)
                try machine.close()
                try fixture.files.reopen()
                return receipt
            })
            XCTAssertEqual(peerChecks, 4)
            XCTAssertEqual(reader.reads.withLock { $0 }, ["finishing", "finishing", "finishing", "stable"])
            try bridge.requireCurrent()
            try receipt.requireCurrent(machine: fixture.machine, candidate: candidate)
            XCTAssertThrowsError(try bridge.settle(verifyLive: { XCTFail("Acknowledged settlement ran again") },
                write: { _ in throw ReplacementFixtureError.injected })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                }
        }
    }

    func testPeerLoanWaitsForCurrentFinishingRead() throws {
        try withFinishingFixture(stableFormats: true) { fixture, finishing, _ in
            let access = try stableFixtureAccess(fixture, finishing: finishing)
            let readLoan = try access.acquireShared()
            defer { readLoan.close(); access.close() }
            let reader = TerminalBridgeFixtureReader(fixture: fixture, loan: readLoan)
            let plan = try reader.finishing()
            let reading = DispatchSemaphore(value: 0), continueRead = DispatchSemaphore(value: 0)
            let contended = DispatchSemaphore(value: 0), finishedAcquiring = DispatchSemaphore(value: 0)
            let readActive = Mutex(false)
            let bridge = try MachineUpdateInstalledTerminalReadBridge(plan: plan, candidate: fixture.candidate,
                readFinishing: {
                    try readLoan.withClosedAdmission {
                        readActive.withLock { $0 = true }
                        defer { readActive.withLock { $0 = false } }
                        reading.signal()
                        guard continueRead.wait(timeout: .now() + 5) == .success else { throw ReplacementFixtureError.injected }
                        return plan
                    }
                }, readStable: { try reader.stable() }, onActivityContention: { contended.signal() })
            defer { bridge.close() }
            let finishedReading = DispatchSemaphore(value: 0)
            let errors = Mutex<[String]>([])
            DispatchQueue.global().async {
                defer { finishedReading.signal() }
                do { try bridge.requireCurrent() }
                catch { errors.withLock { $0.append("read: \(error)") } }
            }
            XCTAssertEqual(reading.wait(timeout: .now() + 2), .success)
            // The original admission owner refuses an uncoordinated acquisition while the read is active.
            XCTAssertThrowsError(try access.acquireShared()) {
                XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy)
            }
            let acquire = MachineUpdateNativeInstalledReadiness.coordinatedActivity(terminal: bridge) {
                guard !readActive.withLock({ $0 }) else { throw ReplacementFixtureError.injected }
                return try access.acquireShared()
            }
            DispatchQueue.global().async {
                defer { finishedAcquiring.signal() }
                do {
                    let peer = try acquire()
                    defer { peer.close() }
                    try peer.validate()
                } catch { errors.withLock { $0.append("acquire: \(error)") } }
            }
            XCTAssertEqual(contended.wait(timeout: .now() + 2), .success)
            continueRead.signal()
            XCTAssertEqual(finishedReading.wait(timeout: .now() + 2), .success)
            XCTAssertEqual(finishedAcquiring.wait(timeout: .now() + 2), .success)
            XCTAssertEqual(errors.withLock { $0 }, [])
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
            // The archive has neither the schema 22 publication table nor the schema 24 stable record.
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

    func testCompletionPublicationKeepsAnAlreadyEnabledReadinessJob() throws {
        try withCompletionFixture(installedReadiness: true, readinessAlreadyEnabled: true) { fixture in
            let accountID = fixture.boundary.accountID
            let configuration = try XCTUnwrap(fixture.snapshot.configuration.configuration(accountID: accountID))
            XCTAssertTrue(configuration.startup.host.installedReadinessEnabled)
            XCTAssertTrue(configuration.completion.host.installedReadinessEnabled)
            let plan = try fixture.plan(fixture.recorded())
            XCTAssertTrue(plan.entries.contains { $0.accountID == accountID && $0.file == .host })
            XCTAssertFalse(plan.entries.contains { $0.file == .authorityJob })
            let record = try MachineUpdateCompletionPublicationRecord(plan: plan)
            XCTAssertEqual(record.formatVersion, 1)
            try MachineUpdateCompletionPublicationRecord.decode(record.encoded).requirePlan(plan)
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
