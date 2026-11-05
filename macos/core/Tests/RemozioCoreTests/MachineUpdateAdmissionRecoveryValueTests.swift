import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class MachineUpdateAdmissionRecoveryValueTests: XCTestCase {
    private enum Fault: Error { case injected }
    private final class Snapshot: @unchecked Sendable {
        var value: MachineUpdateAdmissionState
        var hook: (() throws -> Void)?
        var reads = 0
        init(_ value: MachineUpdateAdmissionState) { self.value = value }
        func read() throws -> MachineUpdateAdmissionState {
            reads += 1
            let result = value
            try hook?()
            return result
        }
    }
    private final class Fixture {
        let files: UpdateAdmissionTestFixture
        let account = Data(repeating: 3, count: 16)
        let inventory: InstallationInventory
        let registration: UpdateAdmissionRegistrationRecord
        let record: MachineUpdateActivationRecord
        let snapshot: Snapshot
        init() throws {
            files = try .init()
            let mac = Data(repeating: 1, count: 16), installation = Data(repeating: 2, count: 16)
            let (_, accountIdentity) = try files.provisionAccount(account)
            let service = try InstallationService(role: .authority, kind: .daemon, domainUID: nil,
                executionUID: 0, label: "dev.sebastiano.remozio.macos.authority",
                plistName: "dev.sebastiano.remozio.macos.authority.plist", accountID: account)
            inventory = try .init(macID: mac, installationID: installation,
                revision: Data(repeating: 4, count: 16), bundlePath: "/Applications/Remozio.app",
                releaseDigest: Data(repeating: 5, count: 32),
                accounts: [.init(accountID: account, ownerUID: getuid())], services: [service])
            registration = try .init(macID: mac, installationID: installation, machine: files.identity,
                accounts: [.init(accountID: account, identity: accountIdentity)], designatedOwner: nil)
            let preparation = try PreparationIntentRecord(id: UUID(), revision: UUID(),
                parent: files.activity.directory.path, ancestry: [.init(device: 1, inode: 10)],
                phase: .copyRecorded, copyIdentity: .init(device: 1, inode: 11), copyDigest: Data(repeating: 6, count: 32))
            let candidate = try UpdateSchedulingCandidateRecord(macID: mac, installationID: installation,
                inventoryRevision: inventory.revision, preparation: preparation, generation: 7)
            record = try .init(candidate: candidate, inventory: inventory, admission: registration)
            snapshot = .init(.init(inventory: inventory, registration: registration, activation: nil))
        }
        func state(_ activation: MachineUpdateActivationRecord?) -> MachineUpdateAdmissionState {
            .init(inventory: inventory, registration: registration, activation: activation)
        }
        func coordinator() throws -> UpdateActivationAdmission {
            try .init(anchor: files.activity.root.path, relativeDirectory: "Machine", owner: getuid(), expected: files.identity)
        }
        func recovery() throws -> MachineUpdateAdmissionRecovery {
            let snapshot = snapshot
            return try .init(initial: snapshot.value, macID: inventory.macID, installationID: inventory.installationID,
                accountID: account, coordinator: coordinator(), readCurrent: { try snapshot.read() })
        }
        func boundary(_ recovery: MachineUpdateAdmissionRecovery) throws -> UpdateAdmissionBoundary {
            let account = try XCTUnwrap(registration.accounts.first)
            let gate = try UpdateAdmissionBarrier(directory: ReleaseDestinationLease(anchor: files.activity.root.path,
                relativeDirectory: "Machine", owner: getuid()), owner: getuid(), expected: account.identity,
                scope: .account(account.accountID))
            return try .init(machine: files.open(), account: gate, verifyAdmission: { try recovery.prepareAdmission() })
        }
    }

    func testEveryBlockingPhaseRestoresTheActualGateWithoutAnActivityExclusion() throws {
        for phase in 0..<4 {
            let f = try Fixture()
            let started = try f.record.starting(policyPreflightDigest: Data(repeating: 9, count: 32))
            let checking = try started.advancing(to: .restartChecking)
            let values = [f.record, started, checking, try checking.finalizing()]
            f.snapshot.value = f.state(values[phase])
            let recovery = try f.recovery(); defer { recovery.close() }
            XCTAssertThrowsError(try f.files.open().acquireAdmission())
            let health = try f.files.activity.open().acquireShared(); health.close()
            XCTAssertThrowsError(try recovery.prepareAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        }
    }
    func testAnOpenSnapshotAllowsAdmissionWithoutRetainingAnyDrain() throws {
        let f = try Fixture(), recovery = try f.recovery(); defer { recovery.close() }
        let token = try f.boundary(recovery).acquireAdmission(); try token.validate(); token.close()
        let drain = try f.coordinator().beginDrain(); drain.close()
        XCTAssertEqual(f.snapshot.reads, 2)
    }
    func testLosingAnUpdaterRestoresOnlyAdmissionAndPreservesExistingWork() throws {
        let f = try Fixture(), work = try f.files.activity.open().acquireShared()
        defer { work.close() }
        f.snapshot.value = f.state(f.record)
        let recovery = try f.recovery(); defer { recovery.close() }
        let drain = try recovery.takeRestoredDrain(expected: f.record); defer { drain.close() }
        XCTAssertNil(try drain.acquireQuiescence())
        try work.validate()
        work.close()
        let quiet = try XCTUnwrap(drain.acquireQuiescence()); quiet.close()
    }
    func testACommittedCancellationReleasesTheRecoveredGateOnTheNextRead() throws {
        let f = try Fixture(); f.snapshot.value = f.state(f.record)
        let recovery = try f.recovery(); defer { recovery.close() }
        XCTAssertThrowsError(try f.files.open().acquireAdmission())
        f.snapshot.value = f.state(try f.record.advancing(to: .cancelled))
        let token = try f.boundary(recovery).acquireAdmission(); token.close()
    }
    func testAnotherOwnersLiveDrainIsNeverReturnedAsThisRecoveryCapability() throws {
        let f = try Fixture(), updater = try f.coordinator().beginDrain(); defer { updater.close() }
        f.snapshot.value = f.state(f.record)
        let recovery = try f.recovery(); defer { recovery.close() }
        XCTAssertThrowsError(try recovery.takeRestoredDrain(expected: f.record)) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        try updater.withClosedAdmission {}
        updater.close()
        let recovered = try recovery.takeRestoredDrain(expected: f.record); recovered.close()
    }
    func testAStaleAttemptCannotTakeOrReleaseTheRestoredGate() throws {
        let f = try Fixture(); f.snapshot.value = f.state(f.record)
        let recovery = try f.recovery(); defer { recovery.close() }
        let stale = try f.record.starting(policyPreflightDigest: Data(repeating: 9, count: 32))
        XCTAssertThrowsError(try recovery.takeRestoredDrain(expected: stale)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
        XCTAssertThrowsError(try f.files.open().acquireAdmission())
        let actual = try recovery.takeRestoredDrain(expected: f.record); actual.close()
    }
    func testTheSecondReadDetectsADurableDrainAfterTheFirstSnapshot() throws {
        let f = try Fixture(), recovery = try f.recovery(); defer { recovery.close() }
        f.snapshot.hook = { f.snapshot.value = f.state(f.record) }
        XCTAssertThrowsError(try f.boundary(recovery).acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        XCTAssertEqual(f.snapshot.reads, 2)
        f.snapshot.hook = nil
        XCTAssertThrowsError(try recovery.prepareAdmission())
        XCTAssertThrowsError(try f.files.open().acquireAdmission())
    }
    func testUnreadableStateRejectsAdmissionWithoutLeakingASharedToken() throws {
        let f = try Fixture(), recovery = try f.recovery(); defer { recovery.close() }
        f.snapshot.hook = { throw Fault.injected }
        XCTAssertThrowsError(try f.boundary(recovery).acquireAdmission()) { XCTAssertEqual($0 as? Fault, .injected) }
        let drain = try f.coordinator().beginDrain(); drain.close()
    }
    func testReaderReentryFailsPromptlyWithoutDeadlock() throws {
        let f = try Fixture(), recovery = try f.recovery(); defer { recovery.close() }
        f.snapshot.hook = {
            XCTAssertThrowsError(try recovery.prepareAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        }
        defer { f.snapshot.hook = nil }
        let token = try f.boundary(recovery).acquireAdmission(); token.close()
    }
    func testCloseDuringTheReaderCallbackRevokesTheResult() throws {
        let f = try Fixture(), recovery = try f.recovery(); defer { recovery.close() }
        f.snapshot.hook = { recovery.close() }; defer { f.snapshot.hook = nil }
        XCTAssertThrowsError(try f.boundary(recovery).acquireAdmission()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertThrowsError(try recovery.validate())
        let drain = try f.coordinator().beginDrain(); drain.close()
    }
    func testAChangedRegistrationScopeCannotReleaseTheOldGate() throws {
        let f = try Fixture(); f.snapshot.value = f.state(f.record)
        let recovery = try f.recovery(); defer { recovery.close() }
        let foreign = try UpdateAdmissionRegistrationRecord(macID: f.inventory.macID,
            installationID: f.inventory.installationID,
            // A fresh inode distinct from every registered file; inode ^ 1 can equal the account file's inode.
            machine: .init(device: f.files.identity.device,
                inode: ([f.files.identity.inode] + f.registration.accounts.map(\.identity.inode)).max()! + 1),
            accounts: f.registration.accounts, designatedOwner: nil)
        f.snapshot.value = .init(inventory: f.inventory, registration: foreign, activation: nil)
        XCTAssertThrowsError(try recovery.prepareAdmission()) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
        XCTAssertThrowsError(try f.files.open().acquireAdmission())
    }
    func testAReplacedAdmissionFileCannotBeAdoptedDuringRecovery() throws {
        let f = try Fixture(); f.snapshot.value = f.state(f.record)
        let recovery = try f.recovery(); defer { recovery.close() }
        XCTAssertEqual(rename(f.files.path, f.files.path + ".old"), 0)
        let fd = Darwin.open(f.files.path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(fd, 0)
        if fd >= 0 { Darwin.close(fd) }
        XCTAssertThrowsError(try recovery.prepareAdmission())
        XCTAssertThrowsError(try recovery.takeRestoredDrain(expected: f.record))
    }
}
