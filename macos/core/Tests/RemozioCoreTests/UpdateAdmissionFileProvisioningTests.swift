import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class UpdateAdmissionProvisioningFixture {
    let activity: ReleaseActivityFixture
    init() throws { activity = try ReleaseActivityFixture() }
    let account = Data(repeating: 71, count: 16)
    func directory() throws -> ReleaseDestinationLease {
        try .init(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid())
    }
    func path(_ scope: UpdateAdmissionScope) throws -> String {
        try activity.directory.appendingPathComponent(scope.fileName).path
    }
    func prepare(account: Data? = nil, mode: UpdateAdmissionFileProvisioning.Mode = .createIfAbsent,
        expected: [UpdateAdmissionScope: PreparationFileIdentity]? = nil,
        stage: (UpdateAdmissionFileProvisioning.Stage) throws -> Void = { _ in }) throws -> UpdateAdmissionFileProvisioning.Result {
        let barrier = try activity.open(), token = try barrier.acquireExclusive(), directory = try directory()
        defer { token.close(); directory.close() }
        return try UpdateAdmissionFileProvisioning.prepare(directory: directory, owner: getuid(), accountID: account ?? self.account,
            activity: token, mode: mode, expected: expected, verifyCurrent: {}, didStage: stage)
    }
    func open(_ result: UpdateAdmissionFileProvisioning.Result, scope: UpdateAdmissionScope) throws -> UpdateAdmissionBarrier {
        try .init(directory: directory(), owner: getuid(), expected: XCTUnwrap(result.identities[scope]), scope: scope)
    }
}

final class UpdateAdmissionFileProvisioningTests: XCTestCase {
    private struct Failed: Error {}
    func testRootEntryRefusesOrdinaryIdentityBeforeInspectingAnyPath() throws {
        let f = try UpdateAdmissionProvisioningFixture(), barrier = try f.activity.open(), activity = try barrier.acquireExclusive()
        defer { activity.close() }
        XCTAssertNotEqual(getuid(), 0)
        XCTAssertThrowsError(try UpdateAdmissionFileProvisioning.prepare(machineDirectory: "/missing", accountID: f.account,
            activity: activity, mode: .createIfAbsent, expected: nil, verifyCurrent: {})) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testCreatesDistinctPrivateFilesAndPinnedReopenDoesNotReplaceThem() throws {
        let f = try UpdateAdmissionProvisioningFixture(), result = try f.prepare()
        XCTAssertEqual(result.createdScopes, [.machine, .account(f.account)])
        XCTAssertEqual(result.identities.count, 2)
        XCTAssertNotEqual(result.identities[.machine], result.identities[.account(f.account)])
        for scope in result.createdScopes {
            var info = stat(); XCTAssertEqual(lstat(try f.path(scope), &info), 0)
            XCTAssertEqual(info.st_mode & 0o7777, 0o600); XCTAssertEqual(info.st_size, 0); XCTAssertEqual(info.st_nlink, 1)
        }
        let reopened = try f.prepare(mode: .requireExisting, expected: result.identities)
        XCTAssertEqual(reopened.identities, result.identities); XCTAssertTrue(reopened.createdScopes.isEmpty)
    }
    func testKnownMachineFileCanBeReusedForAnotherAccountWithoutReplacingIt() throws {
        let f = try UpdateAdmissionProvisioningFixture(), first = try f.prepare(), other = Data(repeating: 72, count: 16)
        let second = try f.prepare(account: other, expected: [.machine: try XCTUnwrap(first.identities[.machine])])
        XCTAssertEqual(second.createdScopes, [.account(other)])
        XCTAssertEqual(first.identities[.machine], second.identities[.machine])
        XCTAssertNotEqual(first.identities[.account(f.account)], second.identities[.account(other)])
    }
    func testUnknownHeldFileCannotBeAdoptedButPinnedReadersRemainValid() throws {
        let f = try UpdateAdmissionProvisioningFixture(), result = try f.prepare(), barrier = try f.open(result, scope: .machine)
        let admitted = try barrier.acquireAdmission(); defer { admitted.close() }
        XCTAssertThrowsError(try f.prepare()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        let known = try f.prepare(mode: .requireExisting, expected: result.identities)
        XCTAssertEqual(known.identities, result.identities); try admitted.validate()
    }
    func testMissingOrReplacementPinnedFilesAreNeverCreatedOrAdopted() throws {
        let f = try UpdateAdmissionProvisioningFixture(), result = try f.prepare(), path = try f.path(.account(f.account))
        try FileManager.default.moveItem(atPath: path, toPath: path + ".old")
        XCTAssertThrowsError(try f.prepare(expected: result.identities)) {
            XCTAssertEqual($0 as? UpdateAdmissionProvisioningError, .missingFile)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        let fd = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(fd, 0); if fd >= 0 { Darwin.close(fd) }
        XCTAssertThrowsError(try f.prepare(expected: result.identities)) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
    }
    func testUnsafeExistingMetadataIsRefusedWithoutRepair() throws {
        let f = try UpdateAdmissionProvisioningFixture(), result = try f.prepare(), path = try f.path(.machine)
        XCTAssertEqual(chmod(path, 0o644), 0)
        XCTAssertThrowsError(try f.prepare(expected: result.identities))
        var info = stat(); XCTAssertEqual(lstat(path, &info), 0); XCTAssertEqual(info.st_mode & 0o7777, 0o644)
    }
    func testStagingFailureRemovesOnlyTheOwnedTemporaryFileAndPublicationCanResume() throws {
        let f = try UpdateAdmissionProvisioningFixture()
        XCTAssertThrowsError(try f.prepare { stage in if case .staged = stage { throw Failed() } })
        XCTAssertFalse(FileManager.default.fileExists(atPath: try f.path(.machine)))
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: f.activity.directory.path).contains { $0.hasPrefix(".remozio-update-admission-") })
        XCTAssertThrowsError(try f.prepare { stage in if case .published(.machine) = stage { throw Failed() } })
        XCTAssertTrue(FileManager.default.fileExists(atPath: try f.path(.machine)))
        let recovered = try f.prepare()
        XCTAssertEqual(recovered.createdScopes, [.account(f.account)])
        XCTAssertEqual(recovered.identities.count, 2)
    }
    func testFinalValidationDetectsAnEarlierFileSubstitution() throws {
        let f = try UpdateAdmissionProvisioningFixture(), machine = try f.path(.machine)
        XCTAssertThrowsError(try f.prepare { stage in
            if case .published(.account(_)) = stage {
                try FileManager.default.moveItem(atPath: machine, toPath: machine + ".old")
                let fd = Darwin.open(machine, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
                guard fd >= 0 else { throw Failed() }; Darwin.close(fd)
            }
        }) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
    }
    func testSharedActivityAndForeignExpectedScopeCannotProvisionFiles() throws {
        let f = try UpdateAdmissionProvisioningFixture(), owner = try f.activity.open(), shared = try owner.acquireShared(), directory = try f.directory()
        defer { shared.close(); directory.close() }
        XCTAssertThrowsError(try UpdateAdmissionFileProvisioning.prepare(directory: directory, owner: getuid(), accountID: f.account,
            activity: shared, mode: .createIfAbsent, expected: nil, verifyCurrent: {}))
        XCTAssertFalse(FileManager.default.fileExists(atPath: try f.path(.machine)))
        shared.close()
        XCTAssertThrowsError(try f.prepare(expected: [.account(Data(repeating: 73, count: 16)): .init(device: 1, inode: 1)])) {
            XCTAssertEqual($0 as? UpdateAdmissionProvisioningError, .invalidScope)
        }
    }
    func testForeignMachineActivityCannotProvisionThisDirectory() throws {
        let first = try UpdateAdmissionProvisioningFixture(), target = try UpdateAdmissionProvisioningFixture()
        let owner = try first.activity.open(), exclusive = try owner.acquireExclusive(), directory = try target.directory()
        defer { exclusive.close(); directory.close() }
        XCTAssertThrowsError(try UpdateAdmissionFileProvisioning.prepare(directory: directory, owner: getuid(), accountID: target.account,
            activity: exclusive, mode: .createIfAbsent, expected: nil, verifyCurrent: {})) {
            XCTAssertEqual($0 as? JournalLeaseError, .identityChanged)
        }
        try exclusive.validateExclusive()
        XCTAssertFalse(FileManager.default.fileExists(atPath: try target.path(.machine)))
    }
}
