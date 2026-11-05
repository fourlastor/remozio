import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Actual same-owner files and synthetic release evidence. This fixture grants no installed Root authority.
final class BoundAdmissionRegistrationFixture {
    let machine: UpdateCandidateStorageFixture
    var root: URL { machine.f.f.root }
    var machinePath: String { root.appendingPathComponent("machine").path }
    init(machine: UpdateCandidateStorageFixture? = nil, enable: Bool = true) throws {
        self.machine = try machine ?? .init(admission: true)
        if enable { try UpdateAdmissionRegistrationStorage.enableInLease(installedRelease: self.machine.release, policy: self.machine.policy, store: self.machine.store) }
        let existing = try activity(); try existing.validate()
    }
    func directory() throws -> ReleaseDestinationLease { try .init(anchor: root.path, relativeDirectory: "machine", owner: getuid()) }
    func activity() throws -> ReleaseActivityBarrier { try .init(directory: directory(), owner: getuid()) }
    func path(_ scope: UpdateAdmissionScope) throws -> String { try machinePath + "/" + scope.fileName }
    func prepare(accountID: Data? = nil, replacing expected: UpdateAdmissionRegistrationRecord? = nil,
        ownerSelection: UpdateAdmissionOwnerSelection = .retain, verify: @escaping () throws -> Void = {},
        stage: (UpdateAdmissionFileProvisioning.Stage) throws -> Void = { _ in }) throws -> UpdateAdmissionRegistrationRecord {
        let owner = try activity(), token = try owner.acquireExclusive(), directory = try directory()
        defer { token.close(); directory.close() }
        return try UpdateAdmissionRegistrationProvisioning.prepareInLease(directory: directory, owner: getuid(), macID: machine.mac,
            accountID: accountID ?? machine.account, activity: token, store: machine.store, installedRelease: machine.release,
            policy: machine.policy, replacing: expected, ownerSelection: ownerSelection, openDirectory: self.directory,
            verifyCurrent: verify, didStage: stage)
    }
    func addAccount(_ accountID: Data) throws {
        let previous = try XCTUnwrap(machine.store.inventory())
        let account = try InstallationAccount(accountID: accountID, ownerUID: previous.accounts[0].ownerUID + 2000)
        let next = try InstallationInventory(macID: previous.macID, installationID: previous.installationID, revision: previous.revision,
            bundlePath: previous.bundlePath, releaseDigest: previous.releaseDigest, accounts: previous.accounts + [account],
            services: previous.services, formatVersion: previous.formatVersion)
        _ = try machine.store.writeInventory(next, expectedRevision: previous.revision)
    }
    func replace(_ path: String) throws {
        try FileManager.default.moveItem(atPath: path, toPath: path + ".old")
        let fd = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }; Darwin.close(fd)
    }
}

final class UpdateAdmissionRegistrationProvisioningTests: XCTestCase {
    private enum Fault: Error { case injected }
    func testActualFilesAreRetainedAndReopenPreservesTheExactRegistrationWithoutChoosingAnOwner() throws {
        let f = try BoundAdmissionRegistrationFixture(), first = try f.prepare()
        XCTAssertNil(first.designatedOwner); XCTAssertEqual(first.accounts.map(\.accountID), [f.machine.account])
        for (scope, identity) in [(UpdateAdmissionScope.machine, first.machine), (.account(f.machine.account), first.accounts[0].identity)] {
            var info = stat(); XCTAssertEqual(lstat(try f.path(scope), &info), 0)
            XCTAssertEqual(info.st_ino, identity.inode); XCTAssertEqual(UInt32(bitPattern: info.st_dev), identity.device)
        }
        try f.machine.reopen()
        XCTAssertEqual(try f.prepare(replacing: first), first)
    }
    func testDesignationIsExplicitAndCannotSwitchToAnotherAccount() throws {
        let f = try BoundAdmissionRegistrationFixture(), first = try f.prepare()
        let owned = try f.prepare(replacing: first, ownerSelection: .designate(f.machine.account))
        XCTAssertEqual(owned.designatedOwner, f.machine.account); XCTAssertEqual(owned.machine, first.machine)
        let other = Data(repeating: 91, count: 16); try f.addAccount(other)
        XCTAssertThrowsError(try f.prepare(accountID: other, replacing: owned, ownerSelection: .designate(other)))
        XCTAssertFalse(FileManager.default.fileExists(atPath: try f.path(.account(other))))
        XCTAssertEqual(try f.machine.store.updateAdmissionRegistration(), owned)
    }
    func testAddingAnotherAccountPreservesTheGlobalAndEarlierAccountIdentities() throws {
        let f = try BoundAdmissionRegistrationFixture(), first = try f.prepare(), other = Data(repeating: 92, count: 16)
        try f.addAccount(other)
        let next = try f.prepare(accountID: other, replacing: first)
        XCTAssertEqual(next.machine, first.machine); XCTAssertTrue(next.accounts.contains(first.accounts[0]))
        XCTAssertEqual(next.accounts.count, 2); XCTAssertNil(next.designatedOwner)
        try f.machine.reopen(); XCTAssertEqual(try f.prepare(replacing: next), next)
    }
    func testForeignStoreDirectoryIsRejectedBeforeCallbacksOrFileCreation() throws {
        let f = try BoundAdmissionRegistrationFixture(), foreign = try BoundAdmissionRegistrationFixture()
        let owner = try f.activity(), token = try owner.acquireExclusive(), directory = try f.directory()
        defer { token.close(); directory.close() }
        XCTAssertThrowsError(try UpdateAdmissionRegistrationProvisioning.prepareInLease(directory: directory, owner: getuid(),
            macID: foreign.machine.mac, accountID: foreign.machine.account, activity: token, store: foreign.machine.store,
            installedRelease: foreign.machine.release, policy: foreign.machine.policy, replacing: nil,
            openDirectory: f.directory, verifyCurrent: { XCTFail("Foreign store reached file preparation") })) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: try f.path(.machine)))
        XCTAssertNil(try foreign.machine.store.updateAdmissionRegistration())
    }
    func testForeignOrSharedActivityCannotReachTheFileOperation() throws {
        let f = try BoundAdmissionRegistrationFixture(), foreign = try BoundAdmissionRegistrationFixture()
        let other = try foreign.activity(), foreignToken = try other.acquireExclusive(), local = try f.activity(), shared = try local.acquireShared()
        let directory = try f.directory(); defer { foreignToken.close(); shared.close(); directory.close() }
        for token in [foreignToken, shared] {
            XCTAssertThrowsError(try UpdateAdmissionRegistrationProvisioning.prepareInLease(directory: directory, owner: getuid(),
                macID: f.machine.mac, accountID: f.machine.account, activity: token, store: f.machine.store,
                installedRelease: f.machine.release, policy: f.machine.policy, replacing: nil,
                openDirectory: f.directory, verifyCurrent: { XCTFail("Wrong activity reached file preparation") }))
        }
        try foreignToken.validateExclusive(); try shared.validate()
        XCTAssertFalse(FileManager.default.fileExists(atPath: try f.path(.machine)))
    }
    func testStaleRegistrationAndUnknownAccountCannotCreateFiles() throws {
        let f = try BoundAdmissionRegistrationFixture(), first = try f.prepare(), other = Data(repeating: 93, count: 16)
        XCTAssertThrowsError(try f.prepare(replacing: nil, verify: { XCTFail("Stale registration reached preparation") }))
        XCTAssertThrowsError(try f.prepare(accountID: other, replacing: first))
        XCTAssertFalse(FileManager.default.fileExists(atPath: try f.path(.account(other))))
        XCTAssertEqual(try f.machine.store.updateAdmissionRegistration(), first)
    }
    func testReadsDoNotEnableStorageAndPreparationCannotMigrateIt() throws {
        let f = try BoundAdmissionRegistrationFixture(enable: false)
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 15)
        XCTAssertThrowsError(try f.prepare())
        XCTAssertFalse(FileManager.default.fileExists(atPath: try f.path(.machine)))
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 15)
    }
    func testFailureAfterPublishingOneFileLeavesNoRegistrationAndCanResumeSafely() throws {
        let f = try BoundAdmissionRegistrationFixture()
        XCTAssertThrowsError(try f.prepare(stage: { stage in if case .published(.machine) = stage { throw Fault.injected } }))
        XCTAssertNil(try f.machine.store.updateAdmissionRegistration())
        XCTAssertTrue(FileManager.default.fileExists(atPath: try f.path(.machine)))
        XCTAssertFalse(FileManager.default.fileExists(atPath: try f.path(.account(f.machine.account))))
        let resumed = try f.prepare(); XCTAssertEqual(try f.machine.store.updateAdmissionRegistration(), resumed)
    }
    func testChangingAnEarlierAccountDuringPublicationRollsBackTheNewRegistration() throws {
        let f = try BoundAdmissionRegistrationFixture(), first = try f.prepare(), other = Data(repeating: 94, count: 16)
        try f.addAccount(other)
        XCTAssertThrowsError(try f.prepare(accountID: other, replacing: first, stage: { stage in
            if case .published(.account(_)) = stage { try f.replace(f.path(.account(f.machine.account))) }
        }))
        try f.machine.reopen(); XCTAssertEqual(try f.machine.store.updateAdmissionRegistration(), first)
        XCTAssertThrowsError(try f.prepare(replacing: first))
    }
    func testAnUnknownCommitRequiresReopenAndReconcilesTheRetainedFiles() throws {
        let f = try BoundAdmissionRegistrationFixture(); try f.machine.reopen(hook: { throw Fault.injected })
        XCTAssertThrowsError(try f.prepare()); XCTAssertThrowsError(try f.machine.store.updateAdmissionRegistration())
        try f.machine.reopen(); let durable = try XCTUnwrap(f.machine.store.updateAdmissionRegistration())
        XCTAssertEqual(try f.prepare(replacing: durable), durable)
    }
    func testPostCommitSubstitutionRetiresTheOwnerAndNeverAdoptsTheReplacement() throws {
        let f = try BoundAdmissionRegistrationFixture()
        try f.machine.reopen(hook: { try f.replace(f.path(.machine)) })
        XCTAssertThrowsError(try f.prepare()); XCTAssertThrowsError(try f.machine.store.updateAdmissionRegistration())
        try f.machine.reopen(); let durable = try XCTUnwrap(f.machine.store.updateAdmissionRegistration())
        var old = stat(); XCTAssertEqual(lstat(try f.path(.machine) + ".old", &old), 0); XCTAssertEqual(old.st_ino, durable.machine.inode)
        XCTAssertThrowsError(try f.prepare(replacing: durable))
    }
    func testFileValidationCannotReenterOrCloseTheWriterIncludingAfterCommit() throws {
        let f = try BoundAdmissionRegistrationFixture(); var checks = 0
        _ = try f.prepare(verify: {
            checks += 1
            XCTAssertThrowsError(try f.machine.store.updateAdmissionRegistration()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            XCTAssertThrowsError(try f.machine.store.close()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
        })
        XCTAssertGreaterThan(checks, 2)
    }
    func testScopedPreparationValidationExpiresBeforeReturning() throws {
        let f = try BoundAdmissionRegistrationFixture(), first = try f.prepare(), directory = try f.directory()
        defer { directory.close() }; var saved: (() throws -> Void)?
        _ = try f.machine.store.prepareUpdateAdmissionRegistration(directory: directory, replacing: first,
            runtime: f.machine.store.retainedRuntimeCompatibilityInputs(), prepare: { value, validate in
                saved = validate; try validate(); return try XCTUnwrap(value)
            }, verifyFiles: { _ in })
        XCTAssertThrowsError(try XCTUnwrap(saved)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertEqual(try f.machine.store.updateAdmissionRegistration(), first)
    }
    func testNativeEntryRefusesOrdinaryIdentityBeforePathsAndCallbacks() throws {
        XCTAssertNotEqual(getuid(), 0); let f = try BoundAdmissionRegistrationFixture(), owner = try f.activity(), token = try owner.acquireExclusive()
        defer { token.close() }
        XCTAssertThrowsError(try UpdateAdmissionRegistrationProvisioning.prepare(machineDirectory: "/missing", macID: f.machine.mac,
            accountID: f.machine.account, activity: token, store: f.machine.store, installedRelease: f.machine.release,
            policy: f.machine.policy, replacing: nil, verifyCurrent: { XCTFail("Ordinary entry reached callbacks") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: try f.path(.machine)))
    }
}
