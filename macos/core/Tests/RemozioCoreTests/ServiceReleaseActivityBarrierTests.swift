import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class ServiceReleaseActivityFixture {
    let root: URL
    let directory: URL
    private var identities: [UInt64: PreparationFileIdentity] = [:]
    init() throws {
        guard let path = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
        defer { free(path) }
        root = URL(fileURLWithPath: String(cString: path)).appendingPathComponent("remozio-service-activity-" + UUID().uuidString)
        directory = root.appendingPathComponent("Services")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        for role in ServiceAccountPlan.roles {
            let fd = Darwin.open(file(role), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o440)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            var value = stat()
            guard fchmod(fd, 0o440) == 0, fstat(fd, &value) == 0 else { _ = Darwin.close(fd); throw JournalLeaseError.system(errno) }
            identities[role.rawValue] = .init(device: UInt32(bitPattern: value.st_dev), inode: value.st_ino)
            _ = Darwin.close(fd)
        }
    }
    func file(_ role: ServiceAccountRole = .gateway) -> String { directory.appendingPathComponent(ServiceReleaseActivityBarrier.fileName(role)).path }
    func identity(_ role: ServiceAccountRole = .gateway) -> PreparationFileIdentity { identities[role.rawValue]! }
    func open(role: ServiceAccountRole = .gateway, update: Bool = false, group: gid_t? = nil,
              verify: @escaping @Sendable () throws -> Void = {}) throws -> ServiceReleaseActivityBarrier {
        try .init(directory: ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Services", owner: getuid()),
            role: role, owner: getuid(), group: group ?? getgid(), reader: getuid(), expected: identity(role),
            exclusiveAllowed: update, verifyCurrent: verify)
    }
    deinit { try? FileManager.default.removeItem(at: root) }
}

final class ServiceReleaseActivityBarrierTests: XCTestCase, @unchecked Sendable {
    private struct Rejected: Error {}
    func testReadOnlySharedDescriptionsExcludeAnUpdateUntilEveryReferenceCloses() throws {
        let f = try ServiceReleaseActivityFixture(), first = try f.open(), second = try f.open(), updater = try f.open(update: true)
        let one = try first.acquireShared(), two = try first.acquireShared(), three = try second.acquireShared()
        XCTAssertThrowsError(try first.acquireExclusive()) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try updater.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        one.close(); one.close(); three.close(); XCTAssertThrowsError(try updater.acquireExclusive())
        try two.validate(); two.close()
        let update = try updater.acquireExclusive()
        XCTAssertThrowsError(try first.acquireShared()); XCTAssertThrowsError(try updater.acquireShared()); XCTAssertThrowsError(try updater.acquireExclusive())
        update.close(); let reopened = try first.acquireShared(); try reopened.validate(); reopened.close()
    }
    func testEachRoleHasADistinctFileAndTheUpdaterMustCheckEveryParticipant() throws {
        let f = try ServiceReleaseActivityFixture(), transport = try f.open(role: .transport), gateway = try f.open()
        let transportUpdate = try f.open(role: .transport, update: true), gatewayUpdate = try f.open(update: true)
        XCTAssertNotEqual(f.identity(.transport), f.identity(.gateway))
        let token = try transport.acquireShared(), another = try gateway.acquireShared()
        XCTAssertThrowsError(try transportUpdate.acquireExclusive()); XCTAssertThrowsError(try gatewayUpdate.acquireExclusive())
        token.close(); let first = try transportUpdate.acquireExclusive()
        XCTAssertThrowsError(try gatewayUpdate.acquireExclusive())
        another.close(); let second = try gatewayUpdate.acquireExclusive(); first.close(); second.close()
    }
    func testReplacementCannotBeAdoptedAndTheOldDescriptionRemainsLockedDuringCleanup() throws {
        let f = try ServiceReleaseActivityFixture(), service = try f.open(), token = try service.acquireShared(), path = f.file()
        let observer = Darwin.open(path, O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(observer, 0); defer { _ = Darwin.close(observer) }
        XCTAssertEqual(rename(path, path + ".old"), 0)
        let replacement = Darwin.open(path, O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o440)
        XCTAssertGreaterThanOrEqual(replacement, 0); _ = Darwin.close(replacement)
        XCTAssertThrowsError(try token.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try service.acquireShared()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertThrowsError(try f.open()); XCTAssertThrowsError(try f.open(update: true))
        XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        token.close(); XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), 0)
    }
    func testMissingLinkedSymlinkedNonemptyAndWrongModeFilesAreNeverRepaired() throws {
        for mutation in 0..<5 {
            let f = try ServiceReleaseActivityFixture(), path = f.file()
            if mutation == 0 { XCTAssertEqual(unlink(path), 0) }
            if mutation == 1 { XCTAssertEqual(link(path, path + ".alias"), 0) }
            if mutation == 2 { XCTAssertEqual(rename(path, path + ".original"), 0); XCTAssertEqual(symlink(path + ".original", path), 0) }
            if mutation == 3 {
                XCTAssertEqual(chmod(path, 0o640), 0); try Data([1]).write(to: URL(fileURLWithPath: path)); XCTAssertEqual(chmod(path, 0o440), 0)
            }
            if mutation == 4 { XCTAssertEqual(chmod(path, 0o444), 0) }
            XCTAssertThrowsError(try f.open())
            if mutation == 0 { XCTAssertFalse(FileManager.default.fileExists(atPath: path)) }
        }
        let f = try ServiceReleaseActivityFixture()
        XCTAssertThrowsError(try f.open(group: getgid() + 1))
    }
    func testChangedScopeRetiresAdmissionButCannotUnlockOutstandingWork() throws {
        let f = try ServiceReleaseActivityFixture(), valid = Mutex(true)
        let service = try f.open(verify: { if !valid.withLock({ $0 }) { throw Rejected() } }), updater = try f.open(update: true)
        let token = try service.acquireShared(); valid.withLock { $0 = false }
        XCTAssertThrowsError(try token.validate()) { XCTAssertTrue($0 is Rejected) }
        valid.withLock { $0 = true }
        XCTAssertThrowsError(try service.acquireShared()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertThrowsError(try updater.acquireExclusive()); token.close()
        let update = try updater.acquireExclusive(); update.close()
    }
    func testClosedAndReleasedTokensCannotValidateOrReleaseAnotherOwner() throws {
        let f = try ServiceReleaseActivityFixture(), service = try f.open(), updater = try f.open(update: true)
        var one: ServiceReleaseActivityToken? = try service.acquireShared(); let two = try service.acquireShared()
        XCTAssertNotNil(one); one = nil; XCTAssertThrowsError(try updater.acquireExclusive())
        two.close(); two.close(); XCTAssertThrowsError(try two.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        let update = try updater.acquireExclusive(); update.close()
    }
    func testInheritedDescriptionExcludesUpdatesAfterTheParentTokenCloses() throws {
        let f = try ServiceReleaseActivityFixture(), service = try f.open(role: .transport)
        let updater = try f.open(role: .transport, update: true), token = try service.acquireShared()
        var inherited: Int32 = -1
        defer { if inherited >= 0 { _ = Darwin.close(inherited) }; token.close() }
        inherited = try token.withSharedDescriptorForSpawn { fd in
            XCTAssertGreaterThanOrEqual(fd, 32)
            XCTAssertNotEqual(fcntl(fd, F_GETFD) & FD_CLOEXEC, 0)
            XCTAssertEqual(fcntl(fd, F_GETFL) & O_ACCMODE, O_RDONLY)
            let copied = fcntl(fd, F_DUPFD_CLOEXEC, 32)
            guard copied >= 0 else { throw JournalLeaseError.system(errno) }
            return copied
        }
        token.close()
        XCTAssertThrowsError(try updater.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        let next = try service.acquireShared(); next.close()
        XCTAssertThrowsError(try updater.acquireExclusive())
        XCTAssertEqual(Darwin.close(inherited), 0); inherited = -1
        let update = try updater.acquireExclusive(); update.close()
    }
    func testSpawnCallbackPermitsConcurrentParentReleaseWhileItsCopyStillBlocksUpdates() throws {
        let f = try ServiceReleaseActivityFixture(), service = try f.open(), updater = try f.open(update: true)
        let token = try service.acquireShared(), joined = DispatchGroup(), released = DispatchSemaphore(value: 0)
        let failed = Mutex(false)
        var inherited: Int32 = -1
        defer { if inherited >= 0 { _ = Darwin.close(inherited) }; token.close() }
        inherited = try token.withSharedDescriptorForSpawn { fd in
            joined.enter()
            DispatchQueue.global().async {
                defer { released.signal(); joined.leave() }
                token.close()
                do { let next = try service.acquireShared(); next.close() }
                catch { failed.withLock { $0 = true } }
            }
            XCTAssertEqual(released.wait(timeout: .now() + 2), .success)
            XCTAssertThrowsError(try updater.acquireExclusive())
            let copied = fcntl(fd, F_DUPFD_CLOEXEC, 32)
            guard copied >= 0 else { throw JournalLeaseError.system(errno) }
            return copied
        }
        XCTAssertEqual(joined.wait(timeout: .now() + 5), .success)
        XCTAssertFalse(failed.withLock { $0 })
        XCTAssertThrowsError(try token.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertThrowsError(try updater.acquireExclusive())
        XCTAssertEqual(Darwin.close(inherited), 0); inherited = -1
        let update = try updater.acquireExclusive(); update.close()
    }
    func testEveryInheritedCopyMustCloseBeforeAnUpdateCanProceed() throws {
        let f = try ServiceReleaseActivityFixture(), service = try f.open(), updater = try f.open(update: true)
        let one = try service.acquireShared(), two = try service.acquireShared()
        var copies: [Int32] = []
        defer { for fd in copies where fd >= 0 { _ = Darwin.close(fd) }; one.close(); two.close() }
        for token in [one, two] {
            copies.append(try token.withSharedDescriptorForSpawn { fd in
                let copied = fcntl(fd, F_DUPFD_CLOEXEC, 32)
                guard copied >= 0 else { throw JournalLeaseError.system(errno) }
                return copied
            })
        }
        one.close(); two.close()
        XCTAssertThrowsError(try updater.acquireExclusive())
        XCTAssertEqual(Darwin.close(copies[0]), 0); copies[0] = -1
        XCTAssertThrowsError(try updater.acquireExclusive())
        XCTAssertEqual(Darwin.close(copies[1]), 0); copies[1] = -1
        let update = try updater.acquireExclusive(); update.close()
    }
    func testReleasedExclusiveAndRetiredTokensCannotLendADescriptor() throws {
        let f = try ServiceReleaseActivityFixture(), service = try f.open(), updater = try f.open(update: true)
        let released = try service.acquireShared(); released.close()
        let current = try service.acquireShared()
        XCTAssertThrowsError(try released.withSharedDescriptorForSpawn { _ in XCTFail("Released token lent another holder's descriptor") }) {
            XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
        }
        current.close()
        let exclusive = try updater.acquireExclusive()
        XCTAssertThrowsError(try exclusive.withSharedDescriptorForSpawn { _ in XCTFail("Exclusive update lock reached a child") }) {
            XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
        }
        exclusive.close()
        let valid = Mutex(true)
        let retiring = try f.open(verify: { if !valid.withLock({ $0 }) { throw Rejected() } })
        let token = try retiring.acquireShared(); defer { token.close() }
        valid.withLock { $0 = false }
        XCTAssertThrowsError(try token.withSharedDescriptorForSpawn { _ in XCTFail("Changed scope reached spawn") }) { XCTAssertTrue($0 is Rejected) }
        valid.withLock { $0 = true }
        XCTAssertThrowsError(try token.withSharedDescriptorForSpawn { _ in XCTFail("Retired barrier reached spawn") }) {
            XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
        }
        XCTAssertThrowsError(try updater.acquireExclusive())
        token.close(); let update = try updater.acquireExclusive(); update.close()
    }
    func testSpawnCallbackFailureKeepsTheParentActivityAndAllowsRetry() throws {
        let f = try ServiceReleaseActivityFixture(), service = try f.open(), updater = try f.open(update: true)
        let token = try service.acquireShared(); defer { token.close() }
        XCTAssertThrowsError(try token.withSharedDescriptorForSpawn { _ in throw Rejected() }) { XCTAssertTrue($0 is Rejected) }
        try token.validate()
        XCTAssertThrowsError(try updater.acquireExclusive())
        try token.withSharedDescriptorForSpawn { XCTAssertGreaterThanOrEqual($0, 32) }
        token.close(); let update = try updater.acquireExclusive(); update.close()
    }
    func testNativeFactoriesRefuseTheOrdinaryOwnerBeforeScopeOrPathAccess() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary owner refusal") }
        let f = try GatewaySettingsConsumerControlFixture(), services = f.plan.pair.authority.material.runtime.services
        for role in ServiceAccountPlan.roles {
            let expected = PreparationFileIdentity(device: 1, inode: 1)
            XCTAssertThrowsError(try ServiceReleaseActivityBarrier.open(services: services, role: role, expected: expected,
                verifyCurrent: { XCTFail("Dedicated process check must precede scope access") }))
            XCTAssertThrowsError(try ServiceReleaseActivityBarrier.openForUpdate(services: services, role: role, expected: expected,
                verifyCurrent: { XCTFail("Root guard must precede scope access") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        }
    }
    func testAnIndependentProcessCannotTakeTheReadOnlyLockUntilTheServiceTokenCloses() throws {
        let f = try ServiceReleaseActivityFixture(), service = try f.open(), token = try service.acquireShared()
        defer { token.close() }
        let child = Process(), output = Pipe(), input = Pipe()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        child.arguments = ["-c", """
import fcntl, signal, sys
signal.alarm(5)
with open(sys.argv[1], "rb", buffering=0) as activity:
    try:
        fcntl.flock(activity, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("blocked", flush=True)
    else:
        sys.exit(2)
    if sys.stdin.buffer.read(1) != b"x":
        sys.exit(3)
    fcntl.flock(activity, fcntl.LOCK_EX | fcntl.LOCK_NB)
    print("acquired", flush=True)
""", f.file()]
        child.standardOutput = output; child.standardInput = input; try child.run()
        defer { if child.isRunning { child.terminate() }; child.waitUntilExit() }
        func line() throws -> String {
            var bytes = Data()
            for _ in 0..<32 {
                guard let next = try output.fileHandleForReading.read(upToCount: 1), !next.isEmpty else { throw Rejected() }
                if next == Data([10]) { return String(decoding: bytes, as: UTF8.self) }
                bytes.append(next)
            }
            throw Rejected()
        }
        XCTAssertEqual(try line(), "blocked")
        token.close(); try input.fileHandleForWriting.write(contentsOf: Data("x".utf8)); try input.fileHandleForWriting.close()
        XCTAssertEqual(try line(), "acquired"); child.waitUntilExit(); XCTAssertEqual(child.terminationStatus, 0)
        let updater = try f.open(update: true), update = try updater.acquireExclusive(); update.close()
    }

}
