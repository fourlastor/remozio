import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class UpdateAdmissionTestFixture {
    let activity: ReleaseActivityFixture
    let identity: PreparationFileIdentity
    var path: String { activity.directory.appendingPathComponent(UpdateAdmissionBarrier.fileName).path }
    init() throws {
        activity = try ReleaseActivityFixture()
        let path = activity.directory.appendingPathComponent(UpdateAdmissionBarrier.fileName).path
        let fd = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        defer { Darwin.close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw JournalLeaseError.system(errno) }
        identity = .init(device: UInt32(bitPattern: info.st_dev), inode: info.st_ino)
    }
    func provisionAccount(_ id: Data) throws -> (UpdateAdmissionBarrier, PreparationFileIdentity) {
        let scope = UpdateAdmissionScope.account(id)
        let path = activity.directory.appendingPathComponent(try scope.fileName).path
        let fd = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        defer { Darwin.close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw JournalLeaseError.system(errno) }
        let identity = PreparationFileIdentity(device: UInt32(bitPattern: info.st_dev), inode: info.st_ino)
        let directory = try ReleaseDestinationLease(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid())
        return (try .init(directory: directory, owner: getuid(), expected: identity, scope: scope), identity)
    }
    func open(expected: PreparationFileIdentity? = nil) throws -> UpdateAdmissionBarrier {
        try .init(directory: ReleaseDestinationLease(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid()),
            owner: getuid(), expected: expected ?? identity)
    }
}

final class UpdateAdmissionBarrierTests: XCTestCase {
    private enum Fault: Error { case childUnavailable }
    private typealias Fixture = UpdateAdmissionTestFixture
    private func busy<Value>(_ body: () throws -> Value, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy, file: file, line: line)
        }
    }
    func testRootEntryRefusesOrdinaryIdentityBeforeOpeningAnyPath() throws {
        XCTAssertNotEqual(getuid(), 0)
        XCTAssertThrowsError(try UpdateAdmissionBarrier.open(machineDirectory: "/missing", expected: .init(device: 1, inode: 1))) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testEveryInflightAdmissionMustFinishBeforeDrainOwnership() throws {
        let f = try Fixture(), first = try f.open(), second = try f.open(), updater = try f.open()
        let one = try first.acquireAdmission(), two = try first.acquireAdmission(), three = try second.acquireAdmission()
        busy { try updater.beginDrain() }
        one.close(); one.close(); three.close()
        busy { try updater.beginDrain() }
        try two.validate(); two.close()
        let drain = try updater.beginDrain(); try drain.validate(); drain.close()
    }
    func testDrainExcludesIndependentOwnersAndCancellationRestoresAdmission() throws {
        let f = try Fixture(), updater = try f.open(), account = try f.open(), other = try f.open()
        let drain = try updater.beginDrain()
        busy { try account.acquireAdmission() }
        busy { try other.acquireAdmission() }
        busy { try updater.acquireAdmission() }
        busy { try updater.beginDrain() }
        busy { try other.beginDrain() }
        drain.close(); drain.close()
        XCTAssertThrowsError(try drain.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        let resumed = try account.acquireAdmission(); try resumed.validate(); resumed.close()
    }
    func testDrainAllowsExistingWorkButCannotEstablishQuiescence() throws {
        let f = try Fixture(), account = try f.open(), updater = try f.open()
        let workOwner = try f.activity.open(), installer = try f.activity.open()
        let admission = try account.acquireAdmission(), work = try workOwner.acquireShared()
        admission.close()
        let drain = try updater.beginDrain()
        try drain.validate(); try work.validate()
        busy { try account.acquireAdmission() }
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        drain.close()
        let next = try account.acquireAdmission(); try work.validate(); next.close()
        work.close()
        let activity = try installer.acquireExclusive(); try activity.validate(); activity.close()
    }
    func testFailedIdleAttemptReleasesAdmissionWithoutCancellingExistingWork() throws {
        let f = try Fixture(), account = try f.open(), updater = try f.open()
        let workOwner = try f.activity.open(), installer = try f.activity.open(), work = try workOwner.acquireShared()
        XCTAssertThrowsError(try {
            let drain = try updater.beginDrain(); defer { drain.close() }
            _ = try installer.acquireExclusive()
        }())
        let next = try account.acquireAdmission(); try next.validate(); try work.validate()
        next.close(); work.close()
    }
    func testDeinitializationAndDoubleCloseReleaseOnlyTheOwnedReference() throws {
        let f = try Fixture(), account = try f.open(), updater = try f.open()
        var one: UpdateAdmissionToken? = try account.acquireAdmission()
        let two = try account.acquireAdmission()
        XCTAssertNotNil(one); one = nil
        busy { try updater.beginDrain() }
        two.close(); two.close()
        XCTAssertThrowsError(try two.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        var drain: UpdateDrainToken? = try updater.beginDrain()
        XCTAssertNotNil(drain); busy { try account.acquireAdmission() }; drain = nil
        let next = try account.acquireAdmission(); next.close()
    }
    func testPinnedIdentityRefusesAReplacementEvenBeforeTheFirstAcquire() throws {
        let f = try Fixture()
        let wrong = PreparationFileIdentity(device: f.identity.device, inode: f.identity.inode ^ 1)
        XCTAssertThrowsError(try f.open(expected: wrong)) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        let original = try f.open()
        XCTAssertEqual(rename(f.path, f.path + ".old"), 0)
        let replacement = Darwin.open(f.path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(replacement, 0); Darwin.close(replacement)
        XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try original.acquireAdmission()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
    }
    func testRetirementKeepsTheOldFileLockedUntilItsActualDrainHolderCloses() throws {
        let f = try Fixture(), updater = try f.open(), drain = try updater.beginDrain()
        let observer = Darwin.open(f.path, O_RDWR | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(observer, 0); defer { Darwin.close(observer) }
        XCTAssertEqual(rename(f.path, f.path + ".old"), 0)
        let replacement = Darwin.open(f.path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(replacement, 0); Darwin.close(replacement)
        XCTAssertThrowsError(try drain.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try updater.beginDrain()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertEqual(flock(observer, LOCK_SH | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        drain.close(); XCTAssertEqual(flock(observer, LOCK_SH | LOCK_NB), 0)
    }
    func testMissingUnsafeNonemptyLinkedAndSymbolicFilesAreNeverRepaired() throws {
        for mutation in 0..<5 {
            let f = try Fixture()
            if mutation == 0 { XCTAssertEqual(unlink(f.path), 0) }
            else if mutation == 1 { XCTAssertEqual(chmod(f.path, 0o644), 0) }
            else if mutation == 2 { try Data([1]).write(to: URL(fileURLWithPath: f.path)) }
            else if mutation == 3 { XCTAssertEqual(link(f.path, f.path + ".alias"), 0) }
            else {
                XCTAssertEqual(rename(f.path, f.path + ".old"), 0)
                XCTAssertEqual(symlink(f.path + ".old", f.path), 0)
            }
            XCTAssertThrowsError(try f.open())
            if mutation == 0 { XCTAssertFalse(FileManager.default.fileExists(atPath: f.path)) }
        }
    }
    func testParentReplacementRetiresAdmissionAndKeepsItsExistingLock() throws {
        let f = try Fixture(), account = try f.open(), admission = try account.acquireAdmission()
        let observer = Darwin.open(f.path, O_RDWR | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(observer, 0); defer { Darwin.close(observer) }
        let directory = f.activity.directory.path
        XCTAssertEqual(rename(directory, directory + ".old"), 0)
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        XCTAssertThrowsError(try admission.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try f.open(expected: f.identity).beginDrain())
        XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        admission.close(); XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), 0)
    }
    func testAnotherProcessHoldsAdmissionUntilItsOwnDescriptorCloses() throws {
        let f = try Fixture(), updater = try f.open(), child = Process(), input = Pipe(), output = Pipe()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        child.environment = ["PATH": ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin"]
        child.arguments = ["python3", "-I", "-S", "-c", """
            import fcntl, os, sys
            fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            sys.stdout.write('R'); sys.stdout.flush()
            sys.stdin.buffer.read(1)
            os.close(fd)
            """, f.path]
        child.standardInput = input; child.standardOutput = output; child.standardError = FileHandle.nullDevice
        try child.run()
        defer {
            try? input.fileHandleForWriting.close()
            if child.isRunning { child.terminate() }
            child.waitUntilExit()
        }
        var descriptor = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
        guard poll(&descriptor, 1, 3000) == 1, try output.fileHandleForReading.read(upToCount: 1) == Data("R".utf8) else {
            throw Fault.childUnavailable
        }
        busy { try updater.beginDrain() }
        try input.fileHandleForWriting.write(contentsOf: Data([1])); try input.fileHandleForWriting.close()
        child.waitUntilExit(); XCTAssertEqual(child.terminationStatus, 0)
        let drain = try updater.beginDrain(); try drain.validate(); drain.close()
    }

    func testAccountDrainCannotClaimMachineOrAnotherAccountAdmission() throws {
        let f = try Fixture(), firstID = Data(repeating: 1, count: 16), secondID = Data(repeating: 2, count: 16)
        let (first, firstIdentity) = try f.provisionAccount(firstID)
        let (second, secondIdentity) = try f.provisionAccount(secondID)
        let machine = try f.open()
        let directory = try ReleaseDestinationLease(anchor: f.activity.root.path, relativeDirectory: "Machine", owner: getuid())
        let firstPeer = try UpdateAdmissionBarrier(directory: ReleaseDestinationLease(anchor: f.activity.root.path,
            relativeDirectory: "Machine", owner: getuid()), owner: getuid(), expected: firstIdentity, scope: .account(firstID))
        let drain = try first.beginDrain(); defer { drain.close() }
        busy { try firstPeer.acquireAdmission() }
        let other = try second.acquireAdmission(), ordinary = try machine.acquireAdmission()
        defer { other.close(); ordinary.close() }
        try other.validateAccountBoundary(directory: directory, accountID: secondID, expected: secondIdentity)
        try ordinary.validateMachineBoundary(directory: directory, expected: f.identity)
        XCTAssertThrowsError(try drain.validateMachineBoundary(directory: directory, expected: f.identity)) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
        }
        drain.close()
        let resumed = try firstPeer.acquireAdmission(); defer { resumed.close() }
        try resumed.validateAccountBoundary(directory: directory, accountID: firstID, expected: firstIdentity)
    }
    func testScopedAdmissionRejectsCrossedAccountIdentityAndDirectory() throws {
        let f = try Fixture(), foreign = try Fixture(), id = Data(repeating: 3, count: 16)
        let (account, identity) = try f.provisionAccount(id)
        let token = try account.acquireAdmission(); defer { token.close() }
        let directory = try ReleaseDestinationLease(anchor: f.activity.root.path, relativeDirectory: "Machine", owner: getuid())
        let otherDirectory = try ReleaseDestinationLease(anchor: foreign.activity.root.path, relativeDirectory: "Machine", owner: getuid())
        try token.validateAccountBoundary(directory: directory, accountID: id, expected: identity)
        for crossed in [Data(repeating: 4, count: 16), Data(repeating: 3, count: 15)] {
            XCTAssertThrowsError(try token.validateAccountBoundary(directory: directory, accountID: crossed, expected: identity)) {
                XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
            }
        }
        XCTAssertThrowsError(try token.validateAccountBoundary(directory: directory, accountID: id,
            expected: .init(device: identity.device, inode: identity.inode ^ 1))) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
        }
        XCTAssertThrowsError(try token.validateAccountBoundary(directory: otherDirectory, accountID: id, expected: identity)) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
        }
        let machine = try f.open(), ordinary = try machine.acquireAdmission(); defer { ordinary.close() }
        XCTAssertThrowsError(try ordinary.validateAccountBoundary(directory: directory, accountID: id, expected: f.identity)) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
        }
        XCTAssertThrowsError(try account.requireRegisteredIdentity(identity, scope: .machine)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        try account.requireRegisteredIdentity(identity, scope: .account(id))
        XCTAssertThrowsError(try UpdateAdmissionScope.account(Data(repeating: 3, count: 15)).fileName) {
            XCTAssertEqual($0 as? UpdateAdmissionProvisioningError, .invalidScope)
        }
    }

}
