import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MachineUpdateActivationFixture {
    let files: BoundAdmissionRegistrationFixture
    let registration: UpdateAdmissionRegistrationRecord
    var machine: UpdateCandidateStorageFixture { files.machine }
    let candidate: UpdateSchedulingCandidateRecord
    init(enable: Bool = true, candidateRelease: SignedReleaseEvidence? = nil) throws {
        files = try .init(machine: UpdateCandidateStorageFixture(admission: true, activation: true)); registration = try files.prepare()
        if enable {
            try MachineUpdateActivationStorage.enableInLease(installedRelease: files.machine.release,
                policy: files.machine.policy, store: files.machine.store)
        }
        candidate = try files.machine.select(files.machine.copy(release: candidateRelease))
    }
    func admission() throws -> UpdateActivationAdmission {
        try .init(anchor: files.root.path, relativeDirectory: "machine", owner: getuid(), expected: registration.machine)
    }
    func begin(_ drain: UpdateAdmissionDrain, replacing old: MachineUpdateActivationRecord? = nil,
        verify: () throws -> Void = {}) throws -> MachineUpdateActivationRecord {
        let directory = try files.directory(); defer { directory.close() }
        return try machine.store.beginMachineUpdateActivation(candidate: candidate, registration: registration,
            runtime: machine.store.retainedRuntimeCompatibilityInputs(), replacing: old,
            directory: directory, drain: drain, verifyCurrent: verify)
    }
    func start(_ record: MachineUpdateActivationRecord, _ quiet: UpdateQuiescenceLease,
        preflight: MachineUpdatePolicyPreflight? = nil, verify: () throws -> Void = {}) throws -> MachineUpdateActivationRecord {
        let directory = try files.directory(); defer { directory.close() }
        let checked = try preflight ?? machine.policyPreflight(record, directory: directory, quiet: quiet)
        return try machine.store.markMachineUpdateActivationStarted(record, preflight: checked, directory: directory,
            quiescence: quiet, verifyCurrent: verify)
    }
}

final class MachineUpdateActivationTests: XCTestCase {
    private enum Fault: Error { case injected }
    private typealias Fixture = MachineUpdateActivationFixture
    func testStorageUpgradeIsExplicitAndReadsPreserveTheOldSchema() throws {
        let f = try Fixture(enable: false)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 16)
        XCTAssertNil(try f.machine.store.machineUpdateActivation())
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 16)
        try MachineUpdateActivationStorage.enableInLease(installedRelease: f.machine.release, policy: f.machine.policy, store: f.machine.store)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 17)
        XCTAssertEqual(try f.machine.store.updateCandidate(), f.candidate)
        XCTAssertEqual(try f.machine.store.updateAdmissionRegistration(), f.registration)
    }
    func testMissingReaderDeclarationsAndWrongReleaseCannotEnableStorage() throws {
        for role in [AuthorityCodeRole.authority, .setupController] {
            let f = try Fixture(enable: false)
            let missing = try f.machine.editedRelease { component in
                try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: component.formats.filter {
                        component.role != role || $0.name != MachineUpdateActivationRecord.formatName
                    })
            }
            XCTAssertThrowsError(try MachineUpdateActivationStorage.enableInLease(installedRelease: missing,
                policy: f.machine.policy, store: f.machine.store))
            XCTAssertThrowsError(try f.machine.store.upgradeMachineUpdateActivationStorage(
                expectedInstalledReleaseDigest: Data(repeating: 99, count: 32)))
            XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 16)
        }
    }
    func testAnEmptySchemaSeventeenStoreStillRequiresTheActivationReaders() throws {
        let f = try Fixture(), snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine.store)
        XCTAssertNil(snapshot.inputs.machineUpdateActivation)
        for role in [AuthorityCodeRole.authority, .setupController] {
            XCTAssertTrue(try XCTUnwrap(snapshot.requirements.formats.first {
                $0.role == role && $0.name == "authority.installation-preparation"
            }).readVersions.contains(17))
            XCTAssertEqual(try XCTUnwrap(snapshot.requirements.formats.first {
                $0.role == role && $0.name == MachineUpdateActivationRecord.formatName
            }).readVersions, [1])
        }
    }
    func testTheRetainedPhaseSurvivesReopenAndPinsTheExactScope() throws {
        let f = try Fixture(), drain = try f.admission().beginDrain(); defer { drain.close() }
        let record = try f.begin(drain); XCTAssertEqual(record.phase, .draining)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().machineUpdateActivation, try record.encoded)
        try f.machine.reopen(); XCTAssertEqual(try f.machine.store.machineUpdateActivation(), record)
        XCTAssertEqual(try MachineUpdateActivationRecord.decode(record.encoded), record)
        XCTAssertEqual(record.description, "MachineUpdateActivationRecord(redacted)")
        XCTAssertEqual(record.debugDescription, record.description)
        XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(record.encoded + Data([0x20])))
    }
    func testAnActivePhaseRejectsCandidateInventoryAndPreparationWrites() throws {
        let f = try Fixture(), drain = try f.admission().beginDrain(); defer { drain.close() }
        let record = try f.begin(drain), inventory = try XCTUnwrap(f.machine.store.inventory())
        XCTAssertThrowsError(try f.machine.store.retireUpdateCandidate(f.candidate)) {
            XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
        }
        XCTAssertThrowsError(try f.machine.select(f.candidate.preparation, replacing: f.candidate))
        XCTAssertThrowsError(try f.machine.store.writeInventory(inventory, expectedRevision: inventory.revision))
        XCTAssertThrowsError(try f.machine.store.begin(parent: f.machine.destination.path,
            ancestry: f.machine.destination.preparationAncestry()))
        XCTAssertEqual(try f.machine.store.machineUpdateActivation(), record)
        XCTAssertEqual(try f.machine.store.updateCandidate(), f.candidate)
    }
    func testCancellationBeforeTheBoundaryReleasesOnlyTheMetadataFence() throws {
        let f = try Fixture(), drain = try f.admission().beginDrain(), record = try f.begin(drain)
        let directory = try f.files.directory(); defer { directory.close(); drain.close() }
        let cancelled = try f.machine.store.cancelMachineUpdateActivation(record, directory: directory, drain: drain, verifyCurrent: {})
        XCTAssertEqual(cancelled.phase, .cancelled)
        XCTAssertThrowsError(try UpdateAdmissionBarrier(directory: f.files.directory(), owner: getuid(),
            expected: f.registration.machine).acquireAdmission())
        let retired = try f.machine.store.retireUpdateCandidate(f.candidate); XCTAssertFalse(retired.selected)
        drain.close()
        let open = try UpdateAdmissionBarrier(directory: f.files.directory(), owner: getuid(),
            expected: f.registration.machine).acquireAdmission(); open.close()
    }
    func testAnActiveAttemptCannotBeOverwrittenEvenWithItsExpectedRecord() throws {
        let f = try Fixture(), drain = try f.admission().beginDrain(); defer { drain.close() }
        let record = try f.begin(drain)
        XCTAssertThrowsError(try f.begin(drain, replacing: record))
        XCTAssertEqual(try f.machine.store.machineUpdateActivation(), record)
    }
    func testAStaleExpectedRevisionCannotAdvanceThePhase() throws {
        let f = try Fixture(), drain = try f.admission().beginDrain(), record = try f.begin(drain)
        let quiet = try XCTUnwrap(drain.acquireQuiescence()); defer { quiet.close() }
        let started = try f.start(record, quiet)
        XCTAssertThrowsError(try f.start(record, quiet)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
        XCTAssertEqual(try f.machine.store.machineUpdateActivation(), started)
    }
    func testTheIrreversibleMarkerRequiresActualQuiescence() throws {
        let f = try Fixture(), work = try f.files.activity().acquireShared(), drain = try f.admission().beginDrain()
        defer { work.close(); drain.close() }; let record = try f.begin(drain)
        XCTAssertNil(try drain.acquireQuiescence()); XCTAssertEqual(try f.machine.store.machineUpdateActivation(), record)
        work.close(); let quiet = try XCTUnwrap(drain.acquireQuiescence()); defer { quiet.close() }
        XCTAssertEqual(try f.start(record, quiet).phase, .activationStarted)
    }
    func testCancellationIsTooLateAfterTheIrreversibleMarker() throws {
        let f = try Fixture(), drain = try f.admission().beginDrain(), record = try f.begin(drain)
        let quiet = try XCTUnwrap(drain.acquireQuiescence()); defer { quiet.close() }
        let started = try f.start(record, quiet), directory = try f.files.directory(); defer { directory.close() }
        XCTAssertThrowsError(try f.machine.store.cancelMachineUpdateActivation(started, directory: directory,
            quiescence: quiet, verifyCurrent: {})) { XCTAssertEqual($0 as? MachineUpdateActivationError, .tooLate) }
        XCTAssertEqual(try f.machine.store.machineUpdateActivation(), started)
    }
    func testRestartPhaseKeepsClosedAdmissionWhileSharedHealthActivityIsPossible() throws {
        let f = try Fixture(), drain = try f.admission().beginDrain(), record = try f.begin(drain)
        let quiet = try XCTUnwrap(drain.acquireQuiescence()), started = try f.start(record, quiet)
        let restart = try quiet.releaseActivityForRestart(); defer { restart.close() }
        let directory = try f.files.directory(); defer { directory.close() }
        let checking = try f.machine.store.markMachineUpdateRestartChecking(started, directory: directory,
            restart: restart, verifyCurrent: {})
        XCTAssertEqual(checking.phase, .restartChecking)
        let health = try f.files.activity().acquireShared(); health.close()
        XCTAssertThrowsError(try UpdateAdmissionBarrier(directory: f.files.directory(), owner: getuid(),
            expected: f.registration.machine).acquireAdmission())
    }
    func testAnotherMachinesDrainCannotCreateTheRecord() throws {
        let f = try Fixture(), other = try Fixture(), foreign = try other.admission().beginDrain(); defer { foreign.close() }
        XCTAssertThrowsError(try f.begin(foreign, verify: { XCTFail("Foreign gate reached copy validation") }))
        XCTAssertNil(try f.machine.store.machineUpdateActivation())
    }
    func testAnotherMachinesQuiescenceCannotCrossTheBoundary() throws {
        let f = try Fixture(), other = try Fixture(), drain = try f.admission().beginDrain(); defer { drain.close() }
        let record = try f.begin(drain), foreign = try XCTUnwrap(other.admission().automatic()); defer { foreign.close() }
        XCTAssertThrowsError(try f.start(record, foreign))
        try f.machine.reopen(); XCTAssertEqual(try f.machine.store.machineUpdateActivation(), record)
    }
    func testAnUnknownPhaseCommitRequiresReopenAndRetainsTheActualRecord() throws {
        let f = try Fixture(); try f.machine.reopen(hook: { throw Fault.injected })
        let drain = try f.admission().beginDrain(); defer { drain.close() }
        XCTAssertThrowsError(try f.begin(drain)); XCTAssertThrowsError(try f.machine.store.machineUpdateActivation())
        try f.machine.reopen(); XCTAssertEqual(try f.machine.store.machineUpdateActivation()?.phase, .draining)
        XCTAssertThrowsError(try f.machine.store.retireUpdateCandidate(f.candidate))
    }
    func testPostCommitFileReplacementRetiresTheWriterWithoutAdoptingTheReplacement() throws {
        let f = try Fixture(); try f.machine.reopen(hook: { try f.files.replace(f.files.path(.machine)) })
        let drain = try f.admission().beginDrain(); defer { drain.close() }
        XCTAssertThrowsError(try f.begin(drain)); XCTAssertThrowsError(try f.machine.store.machineUpdateActivation())
        try f.machine.reopen(); let saved = try XCTUnwrap(f.machine.store.machineUpdateActivation())
        XCTAssertEqual(saved.machineAdmission, f.registration.machine)
    }
    func testValidationCallbacksCannotReenterOrCloseTheMachineWriter() throws {
        let f = try Fixture(), drain = try f.admission().beginDrain(); defer { drain.close() }; var checks = 0
        _ = try f.begin(drain, verify: {
            checks += 1
            XCTAssertThrowsError(try f.machine.store.machineUpdateActivation()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            XCTAssertThrowsError(try f.machine.store.close()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
        })
        XCTAssertGreaterThanOrEqual(checks, 3)
    }
    func testASavedRecordDoesNotSupplyALiveKernelBoundary() throws {
        let f = try Fixture(), drain = try f.admission().beginDrain(), record = try f.begin(drain); drain.close()
        let admission = try UpdateAdmissionBarrier(directory: f.files.directory(), owner: getuid(),
            expected: f.registration.machine).acquireAdmission(); admission.close()
        XCTAssertEqual(try f.machine.store.machineUpdateActivation(), record)
        XCTAssertThrowsError(try f.machine.store.retireUpdateCandidate(f.candidate))
    }

}
