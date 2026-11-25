import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

extension CommandFilesystemCapture {
    /// Fixture captures use the ordinary test process credentials.
    convenience init(executablePath: Data, directoryPath: Data,
                     deadline: ContinuousClock.Instant = ContinuousClock.now + CommandFilesystemCapture.phaseTimeout,
                     checkProbe: () throws -> Void = {}, checkCancellation: () throws -> Void = {}) throws {
        try self.init(executablePath: executablePath, directoryPath: directoryPath, deadline: deadline,
            caller: CommandFilesystemCaller(userID: geteuid(), groupID: getegid()),
            checkProbe: checkProbe, checkCancellation: checkCancellation)
    }
}

final class CommandFilesystemCaptureTests: XCTestCase {
    private enum Cancelled: Error { case test }
    private final class Fixture {
        let root: String
        var executable: String { root + "/tool" }
        var cwd: String { root + "/cwd" }
        let content: Data
        init(content: Data = Data("#!/bin/sh\nprintf fixture\n".utf8),
             parent: URL = FileManager.default.temporaryDirectory) throws {
            root = parent.appendingPathComponent("remozio-credential-" + UUID().uuidString).path
            self.content = content
            try FileManager.default.createDirectory(atPath: cwd, withIntermediateDirectories: true)
            try content.write(to: URL(fileURLWithPath: executable))
            guard chmod(executable, 0o755) == 0 else { throw CommandFilesystemCaptureError.system(errno) }
        }
        deinit { try? FileManager.default.removeItem(atPath: root) }
        func capture(checkCancellation: () throws -> Void = {}) throws -> CommandFilesystemCapture {
            try CommandFilesystemCapture(executablePath: Data(executable.utf8), directoryPath: Data(cwd.utf8),
                checkCancellation: checkCancellation)
        }
        func overwrite(_ content: Data) throws {
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: executable))
            defer { try? handle.close() }
            try handle.seek(toOffset: 0)
            try handle.write(contentsOf: content)
            try handle.truncate(atOffset: UInt64(content.count))
        }
    }

    private func expectRetired(_ capture: CommandFilesystemCapture, check: () throws -> Void) {
        XCTAssertThrowsError(try check())
        XCTAssertThrowsError(try capture.recheck()) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .closed) }
    }

    func testCapturesOSIdentityAndDigestWithoutChangingPaths() throws {
        let fixture = try Fixture(), capture = try fixture.capture()
        defer { capture.close() }
        var file = stat(), directory = stat()
        XCTAssertEqual(fstatat(AT_FDCWD, fixture.executable, &file, 0), 0)
        XCTAssertEqual(fstatat(AT_FDCWD, fixture.cwd, &directory, 0), 0)
        XCTAssertEqual(capture.executable.path, Data(fixture.executable.utf8))
        XCTAssertEqual(capture.executable.identity.device, UInt64(UInt32(bitPattern: file.st_dev)))
        XCTAssertEqual(capture.executable.identity.inode, file.st_ino)
        XCTAssertEqual(capture.executable.sha256, Data(SHA256.hash(data: fixture.content)))
        XCTAssertEqual(capture.directory.path, Data(fixture.cwd.utf8))
        XCTAssertEqual(capture.directory.identity.inode, directory.st_ino)
        try capture.recheck()
        capture.close(); capture.close()
        XCTAssertThrowsError(try capture.recheck()) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .closed) }
    }

    func testLaunchProofIsBoundToTheOriginalCapture() throws {
        let fixture = try Fixture(), original = try fixture.capture(), other = try fixture.capture()
        let proof = try original.makeRecheck(checkingLaunchPath: true).run(deadline: .now + .seconds(5), checkProbe: {})
        XCTAssertEqual(try original.executableLaunch(from: proof).mode, .pathBound)
        XCTAssertThrowsError(try other.executableLaunch(from: proof)) {
            XCTAssertEqual($0 as? CommandFilesystemCaptureError, .changed)
        }
        original.close()
        XCTAssertThrowsError(try original.executableLaunch(from: proof))
    }

    func testCapturesThroughSearchOnlyDirectories() throws {
        let fixture = try Fixture()
        XCTAssertEqual(chmod(fixture.root, 0o100), 0)
        defer { _ = chmod(fixture.root, 0o700) }
        XCTAssertEqual(chmod(fixture.cwd, 0o100), 0)
        defer { _ = chmod(fixture.cwd, 0o700) }

        let caller = CommandFilesystemCaller(userID: geteuid(), groupID: getegid())
        let capture = try CommandFilesystemCapture(executablePath: Data(fixture.executable.utf8),
            directoryPath: Data(fixture.cwd.utf8), deadline: ContinuousClock.now + .seconds(5), caller: caller)
        XCTAssertEqual(capture.executable.sha256, Data(SHA256.hash(data: fixture.content)))
        try capture.recheck()
        try capture.withBorrowedDirectoryDescriptor { descriptor in
            XCTAssertNotEqual(fcntl(descriptor, F_GETFL) & O_EXEC, 0)
        }
        try CommandFilesystemCaller.requireProcessIdentity()
    }

    func testCallerLookupRejectsReplacementBeforeOpenForHash() throws {
        let fixture = try Fixture()
        let canonical = try XCTUnwrap(realpath(fixture.root, nil))
        defer { free(canonical) }
        let executable = String(cString: canonical) + "/tool"
        let replacement = String(cString: canonical) + "/replacement"
        try FileManager.default.copyItem(atPath: executable, toPath: replacement)
        let beforeOpen = executable.split(separator: "/").count + 2
        var checks = 0
        let caller = CommandFilesystemCaller(userID: geteuid(), groupID: getegid())
        XCTAssertThrowsError(try CommandFilesystemCapture(executablePath: Data(executable.utf8),
            directoryPath: Data(fixture.cwd.utf8), deadline: ContinuousClock.now + .seconds(5), caller: caller,
            checkProbe: {
                checks += 1
                if checks == beforeOpen { XCTAssertEqual(rename(replacement, executable), 0) }
            })) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .changed) }
        XCTAssertEqual(checks, beforeOpen)
        try CommandFilesystemCaller.requireProcessIdentity()
    }

    func testCredentialResetSentinelsMatchDarwin() throws {
        XCTAssertEqual(CommandFilesystemCaller.kauthUIDNone, 0xffff_ff9b)
        XCTAssertEqual(CommandFilesystemCaller.kauthGIDNone, 0xffff_ff9b)

        let environment = ProcessInfo.processInfo.environment
        let uidValue = environment["REMOZIO_CREDENTIAL_FIXTURE_UID"]
        let gidValue = environment["REMOZIO_CREDENTIAL_FIXTURE_GID"]
        if uidValue == nil, gidValue == nil { return }
        let uid = try XCTUnwrap(uidValue.flatMap { uid_t($0) })
        let gid = try XCTUnwrap(gidValue.flatMap { gid_t($0) })
        guard getuid() == 0, geteuid() == 0, uid > 0, gid > 0 else {
            return XCTFail("The privileged fixture requires a separate caller")
        }
        try verifyPrivilegedFilesystemCapture(caller: .init(userID: uid, groupID: gid))
        print("Remozio privileged filesystem fixture passed")
    }

    private func verifyPrivilegedFilesystemCapture(caller: CommandFilesystemCaller) throws {
        let fixture = try Fixture(parent: URL(fileURLWithPath: "/private/tmp", isDirectory: true))
        let executable = fixture.executable, cwd = fixture.cwd
        let missing = fixture.root + "/missing"
        let digest = Data(SHA256.hash(data: fixture.content))
        let denied = fixture.root + "/denied"
        try FileManager.default.createDirectory(atPath: denied, withIntermediateDirectories: false)
        try FileManager.default.copyItem(atPath: fixture.executable, toPath: denied + "/tool")
        XCTAssertEqual(chmod(denied, 0o700), 0)
        XCTAssertEqual(chmod(fixture.root, 0o711), 0)
        XCTAssertEqual(chmod(fixture.cwd, 0o111), 0)
        XCTAssertEqual(chmod(fixture.executable, 0o111), 0)

        let pool = CommandFilesystemProbePool()
        let operation = try pool.start(.admission(caller.userID)) { deadline, checkProbe in
            try caller.withIdentity {
                var observedUID: uid_t = 0, observedGID: gid_t = 0
                XCTAssertEqual(pthread_getugid_np(&observedUID, &observedGID), 0)
                XCTAssertEqual(observedUID, caller.userID)
                XCTAssertEqual(observedGID, caller.groupID)
                let descriptor = Darwin.open(executable, O_RDONLY | O_CLOEXEC)
                let error = errno
                if descriptor >= 0 { _ = Darwin.close(descriptor) }
                XCTAssertEqual(descriptor, -1)
                XCTAssertEqual(error, EACCES)
            }
            try CommandFilesystemCaller.requireProcessIdentity()
            XCTAssertThrowsError(try caller.withIdentity { throw Cancelled.test }) {
                XCTAssertTrue($0 is Cancelled)
            }
            try CommandFilesystemCaller.requireProcessIdentity()

            let capture = try CommandFilesystemCapture(executablePath: Data(executable.utf8),
                directoryPath: Data(cwd.utf8), deadline: deadline, caller: caller, checkProbe: checkProbe)
            defer { capture.close() }
            XCTAssertEqual(capture.executable.sha256, digest)
            try capture.withBorrowedDirectoryDescriptor { descriptor in
                XCTAssertNotEqual(fcntl(descriptor, F_GETFL) & O_EXEC, 0)
            }

            for (path, expected) in [(missing, ENOENT), (denied + "/tool", EACCES)] {
                XCTAssertThrowsError(try CommandFilesystemCapture(executablePath: Data(path.utf8),
                    directoryPath: Data(cwd.utf8), deadline: deadline, caller: caller, checkProbe: checkProbe)) {
                    XCTAssertEqual($0 as? CommandFilesystemCaptureError, .system(expected))
                    XCTAssertEqual(AuthorityJournal.commandCaptureRefusal($0), .invalidRequest)
                }
            }
            try CommandFilesystemCaller.requireProcessIdentity()
        }
        try withExtendedLifetime(fixture) { try operation.wait() }
    }

    func testOrdinaryWorkerRejectsAnotherUIDAndKeepsProcessIdentity() throws {
        guard geteuid() != 0 else { throw XCTSkip("Normal-user credential check") }
        let uid = geteuid(), gid = getegid()
        let other = CommandFilesystemCaller(userID: uid == 1 ? 2 : 1, groupID: gid)
        var entered = false
        XCTAssertThrowsError(try other.withIdentity { entered = true }) {
            XCTAssertEqual($0 as? CommandFilesystemCaptureError, .credentialUnavailable)
        }
        XCTAssertFalse(entered)
        XCTAssertEqual(geteuid(), uid)
        XCTAssertEqual(getegid(), gid)
        try CommandFilesystemCaller.requireProcessIdentity()
    }

    func testCallerScopePropagatesFailureAndLeavesProcessIdentity() throws {
        let caller = CommandFilesystemCaller(userID: geteuid(), groupID: getegid())
        XCTAssertThrowsError(try caller.withIdentity { throw Cancelled.test }) {
            XCTAssertTrue($0 is Cancelled)
        }
        try CommandFilesystemCaller.requireProcessIdentity()
    }

    func testOSCaptureFieldsRoundTripThroughTheCommandWireParser() throws {
        struct Row: Decodable { let hex: String }
        struct Vectors: Decodable { let valid: [Row] }
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        let vectors = try JSONDecoder().decode(Vectors.self,
            from: Data(contentsOf: root.appendingPathComponent("protocol/vectors/command-capture-v1.json")))
        let text = try XCTUnwrap(vectors.valid.first).hex
        var bytes = Data(), index = text.startIndex
        while index < text.endIndex {
            let end = text.index(index, offsetBy: 2)
            bytes.append(try XCTUnwrap(UInt8(text[index..<end], radix: 16)))
            index = end
        }
        let limits = try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024)
        guard case var .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits) else {
            return XCTFail("Expected the command fixture")
        }
        let fixture = try Fixture(), capture = try fixture.capture()
        func identity(_ value: CapturedFileIdentity) -> CBORValue {
            .map([0: .unsigned(value.device), 1: .unsigned(value.inode)])
        }
        fields[1] = .map([0: .bytes(capture.executable.path), 1: identity(capture.executable.identity),
            2: .bytes(capture.executable.sha256)])
        fields[3] = .map([0: .bytes(capture.directory.path), 1: identity(capture.directory.identity)])
        let command = try CommandCapture(canonicalBytes: DeterministicCBOR.encode(.map(fields), limits: limits), limits: limits)
        XCTAssertEqual(command.executable, capture.executable)
        XCTAssertEqual(command.directory, capture.directory)
        try capture.recheck()
    }

    func testStreamsTheEntireExecutableAcrossBufferBoundaries() throws {
        var content = Data(repeating: 0x61, count: 3 * 65_536 + 7)
        content[65_536] = 0xff
        content[content.count - 1] = 0x62
        let fixture = try Fixture(content: content), capture = try fixture.capture()
        XCTAssertEqual(capture.executable.sha256, Data(SHA256.hash(data: content)))
        try capture.recheck()
    }

    func testAllowsOrdinarySymlinksDotComponentsAndWritableUserExecutables() throws {
        let fixture = try Fixture()
        XCTAssertEqual(symlink("tool", fixture.root + "/link"), 0)
        XCTAssertEqual(symlink("cwd", fixture.root + "/cwd-link"), 0)
        XCTAssertEqual(chmod(fixture.executable, 0o777), 0)
        let executable = Data((fixture.root + "/./link").utf8)
        let cwd = Data((fixture.root + "/cwd-link/../cwd-link").utf8)
        let capture = try CommandFilesystemCapture(executablePath: executable, directoryPath: cwd)
        XCTAssertEqual(capture.executable.path, executable)
        let resolved = try XCTUnwrap(realpath(fixture.executable, nil))
        defer { free(resolved) }
        XCTAssertEqual(capture.resolvedExecutablePath, Data(String(cString: resolved).utf8))
        XCTAssertEqual(capture.directory.path, cwd)
        try capture.recheck()
    }

    func testRejectsExecutableSizeAboveLimitBeforeHashing() throws {
        let fixture = try Fixture()
        XCTAssertEqual(truncate(fixture.executable, CommandFilesystemCapture.maximumExecutableBytes + 1), 0)
        var checks = 0
        XCTAssertThrowsError(try fixture.capture {
            checks += 1
        }) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .invalidExecutable) }
        XCTAssertEqual(checks, 1)
    }

    func testExecutableResolvesRelativeAndAbsoluteChainsThroughDirectoryDotDot() throws {
        let fixture = try Fixture()
        let nested = fixture.root + "/nested", deeper = nested + "/deeper"
        try FileManager.default.createDirectory(atPath: deeper, withIntermediateDirectories: true)
        XCTAssertEqual(symlink("nested/deeper", fixture.root + "/directory-link"), 0)
        XCTAssertEqual(symlink("../tool", nested + "/relative-link"), 0)
        XCTAssertEqual(symlink(fixture.root + "/directory-link/../relative-link", fixture.root + "/absolute-link"), 0)
        let requested = Data((fixture.root + "/absolute-link").utf8)
        let capture = try CommandFilesystemCapture(executablePath: requested, directoryPath: Data(fixture.cwd.utf8))
        let resolved = try XCTUnwrap(realpath(fixture.executable, nil))
        defer { free(resolved) }
        XCTAssertEqual(capture.executable.path, requested)
        XCTAssertEqual(capture.resolvedExecutablePath, Data(String(cString: resolved).utf8))
        try capture.recheck()
    }

    func testExecutableResolverRejectsSymlinkCyclesAndSpecialTargets() throws {
        let fixture = try Fixture()
        let link = fixture.root + "/link"
        XCTAssertEqual(symlink("link", link), 0)
        func capture() throws -> CommandFilesystemCapture {
            try CommandFilesystemCapture(executablePath: Data(link.utf8), directoryPath: Data(fixture.cwd.utf8))
        }
        XCTAssertThrowsError(try capture()) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .system(ELOOP)) }
        XCTAssertEqual(mkfifo(fixture.root + "/fifo", 0o700), 0)
        XCTAssertEqual(chmod(fixture.executable, 0o644), 0)
        for target in ["cwd", "fifo", "tool"] {
            XCTAssertEqual(unlink(link), 0)
            XCTAssertEqual(symlink(target, link), 0)
            XCTAssertThrowsError(try capture()) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .invalidExecutable) }
        }
    }

    func testExecutableResolverRejectsDirectoryLinkReplacementDuringWalk() throws {
        let fixture = try Fixture()
        let canonical = try XCTUnwrap(realpath(fixture.root, nil))
        defer { free(canonical) }
        let root = String(cString: canonical)
        for name in ["first", "second"] {
            try FileManager.default.createDirectory(atPath: root + "/" + name, withIntermediateDirectories: false)
            try FileManager.default.copyItem(atPath: fixture.executable, toPath: root + "/" + name + "/tool")
        }
        let link = root + "/walk"
        XCTAssertEqual(symlink("first", link), 0)
        // The initial check and one check per component precede the check after readlinkat.
        let afterReadlink = root.split(separator: "/").count + 3
        var componentsChecked = 0
        XCTAssertThrowsError(try CommandFilesystemCapture(executablePath: Data((link + "/tool").utf8),
            directoryPath: Data(fixture.cwd.utf8), deadline: ContinuousClock.now + .seconds(5), checkProbe: {
                componentsChecked += 1
                if componentsChecked == afterReadlink {
                    XCTAssertEqual(unlink(link), 0)
                    XCTAssertEqual(symlink("second", link), 0)
                }
            })) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .changed) }
        XCTAssertEqual(componentsChecked, afterReadlink)
    }

    func testFinalMetadataCheckRejectsAnAncestorReplacedWithASymlink() throws {
        let fixture = try Fixture()
        let ancestor = fixture.root + "/ancestor"
        let relocated = fixture.root + "/relocated"
        try FileManager.default.createDirectory(atPath: ancestor, withIntermediateDirectories: false)
        let executable = ancestor + "/tool"
        try FileManager.default.copyItem(atPath: fixture.executable, toPath: executable)
        let capture = try CommandFilesystemCapture(executablePath: Data(executable.utf8), directoryPath: Data(fixture.cwd.utf8))
        let probe = try capture.makeRecheck()
        let proof = try probe.run(deadline: ContinuousClock.now + .seconds(5), checkProbe: {})
        try capture.verifyMetadata(proof)

        XCTAssertEqual(rename(ancestor, relocated), 0)
        XCTAssertEqual(symlink("relocated", ancestor), 0)
        // A lookup of the complete path still reaches the original file.
        XCTAssertThrowsError(try capture.verifyMetadata(proof)) {
            XCTAssertEqual($0 as? CommandFilesystemCaptureError, .changed)
        }
    }

    func testExecutableReplacementRetiresTheOriginalCapture() throws {
        let fixture = try Fixture(), capture = try fixture.capture()
        XCTAssertEqual(rename(fixture.executable, fixture.executable + ".old"), 0)
        try fixture.content.write(to: URL(fileURLWithPath: fixture.executable))
        XCTAssertEqual(chmod(fixture.executable, 0o755), 0)
        expectRetired(capture) { try capture.recheck() }
    }

    func testSameSizeInPlaceModificationFailsTheContentCheck() throws {
        let fixture = try Fixture(), capture = try fixture.capture()
        var changed = fixture.content
        changed[changed.count - 2] ^= 1
        try fixture.overwrite(changed)
        XCTAssertThrowsError(try capture.recheck()) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .changed) }
        XCTAssertThrowsError(try capture.recheck()) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .closed) }
    }

    func testSymlinkRetargetingIsDetected() throws {
        let fixture = try Fixture()
        let link = fixture.root + "/link"
        XCTAssertEqual(symlink("tool", link), 0)
        let capture = try CommandFilesystemCapture(executablePath: Data(link.utf8), directoryPath: Data(fixture.cwd.utf8))
        try fixture.content.write(to: URL(fileURLWithPath: fixture.root + "/other"))
        XCTAssertEqual(chmod(fixture.root + "/other", 0o755), 0)
        XCTAssertEqual(unlink(link), 0)
        XCTAssertEqual(symlink("other", link), 0)
        expectRetired(capture) { try capture.recheck() }
    }

    func testDirectoryReplacementAndDeletionAreDetected() throws {
        for replacement in [true, false] {
            let fixture = try Fixture(), capture = try fixture.capture()
            XCTAssertEqual(rename(fixture.cwd, fixture.cwd + ".old"), 0)
            if replacement { try FileManager.default.createDirectory(atPath: fixture.cwd, withIntermediateDirectories: false) }
            expectRetired(capture) { try capture.recheck() }
        }
    }

    func testDirectoryContentsCanChangeWithoutInvalidatingItsIdentity() throws {
        let fixture = try Fixture(), capture = try fixture.capture()
        try Data([1]).write(to: URL(fileURLWithPath: fixture.cwd + "/new-file"))
        try capture.recheck()
    }

    func testRemovedExecutePermissionAndExecutableDeletionRetireCapture() throws {
        for deletion in [true, false] {
            let fixture = try Fixture(), capture = try fixture.capture()
            if deletion { XCTAssertEqual(unlink(fixture.executable), 0) }
            else { XCTAssertEqual(chmod(fixture.executable, 0o644), 0) }
            expectRetired(capture) { try capture.recheck() }
        }
    }

    func testRejectsMalformedPathsAndNonExecutableOrSpecialFiles() throws {
        let fixture = try Fixture()
        for path in [Data(), Data("relative".utf8), Data("/a\0b".utf8), Data(repeating: 0x2f, count: Int(PATH_MAX))] {
            XCTAssertThrowsError(try CommandFilesystemCapture(executablePath: path, directoryPath: Data(fixture.cwd.utf8))) {
                XCTAssertEqual($0 as? CommandFilesystemCaptureError, .invalidPath)
            }
            XCTAssertThrowsError(try CommandFilesystemCapture(executablePath: Data(fixture.executable.utf8), directoryPath: path))
        }
        XCTAssertEqual(chmod(fixture.executable, 0o644), 0)
        XCTAssertThrowsError(try fixture.capture()) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .invalidExecutable) }
        for path in [fixture.cwd, fixture.root + "/fifo"] {
            if path.hasSuffix("fifo") { XCTAssertEqual(mkfifo(path, 0o700), 0) }
            XCTAssertThrowsError(try CommandFilesystemCapture(executablePath: Data(path.utf8), directoryPath: Data(fixture.cwd.utf8))) {
                XCTAssertEqual($0 as? CommandFilesystemCaptureError, .invalidExecutable)
            }
        }
        XCTAssertThrowsError(try CommandFilesystemCapture(executablePath: Data(fixture.executable.utf8), directoryPath: Data(fixture.executable.utf8)))
    }

    func testRawNonUTF8PathReachesTheOSWithoutLossyConversion() throws {
        let fixture = try Fixture()
        var path = Data((fixture.root + "/raw-").utf8)
        path.append(0xff)
        XCTAssertThrowsError(try CommandFilesystemCapture(executablePath: path, directoryPath: Data(fixture.cwd.utf8))) {
            guard case .system = $0 as? CommandFilesystemCaptureError else { return XCTFail("Expected the OS path error") }
        }
    }

    func testCancellationDuringCaptureAndRecheckPropagates() throws {
        let fixture = try Fixture(content: Data(repeating: 1, count: 65_537))
        var calls = 0
        XCTAssertThrowsError(try fixture.capture {
            calls += 1
            if calls == 3 { throw Cancelled.test }
        }) { XCTAssertTrue($0 is Cancelled) }
        let capture = try fixture.capture()
        expectRetired(capture) { try capture.recheck { throw Cancelled.test } }
        try fixture.capture().recheck()
    }

    func testConcurrentGrowthDuringHashingIsRejectedWithoutFollowingTheNewSize() throws {
        let fixture = try Fixture(content: Data(repeating: 1, count: 65_537))
        var calls = 0
        XCTAssertThrowsError(try fixture.capture {
            calls += 1
            if calls == 3 { try fixture.overwrite(Data(repeating: 2, count: 200_000)) }
        }) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .changed) }
        XCTAssertEqual(calls, 4)
    }

    func testDirectoryReplacementDuringFinalHashIsDetected() throws {
        let fixture = try Fixture(content: Data(repeating: 1, count: 65_537)), capture = try fixture.capture()
        var calls = 0
        expectRetired(capture) {
            try capture.recheck {
                calls += 1
                if calls == 3 {
                    XCTAssertEqual(rename(fixture.cwd, fixture.cwd + ".old"), 0)
                    try FileManager.default.createDirectory(atPath: fixture.cwd, withIntermediateDirectories: false)
                }
            }
        }
    }

    func testReplacementDuringFinalHashIsDetected() throws {
        let fixture = try Fixture(content: Data(repeating: 1, count: 65_537)), capture = try fixture.capture()
        var calls = 0
        expectRetired(capture) {
            try capture.recheck {
                calls += 1
                if calls == 3 {
                    XCTAssertEqual(rename(fixture.executable, fixture.executable + ".old"), 0)
                    try fixture.content.write(to: URL(fileURLWithPath: fixture.executable))
                    XCTAssertEqual(chmod(fixture.executable, 0o755), 0)
                }
            }
        }
    }
}
