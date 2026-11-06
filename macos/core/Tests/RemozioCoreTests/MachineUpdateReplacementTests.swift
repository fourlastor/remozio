import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

private enum ReplacementFixtureError: Error { case injected, signature }

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
    var quiet: UpdateQuiescenceLease
    let oldIdentity: PreparationFileIdentity
    let newIdentity: PreparationFileIdentity
    var oldURL: URL { URL(fileURLWithPath: installed.path).appendingPathComponent("Remozio.app") }
    var preparedURL: URL { URL(fileURLWithPath: machine.destination.path).appendingPathComponent(candidate.preparation.bundleName) }
    init(beforeActivation: (BoundAdmissionRegistrationFixture) throws -> Void = { _ in }) throws {
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
            try .init(role: c.role, identifier: c.identifier, generation: c.generation + 1, relativePath: c.relativePath,
                codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: c.formats, requests: c.requests)
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
    func reopen() throws {
        quiet.close(); try machine.reopen()
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
