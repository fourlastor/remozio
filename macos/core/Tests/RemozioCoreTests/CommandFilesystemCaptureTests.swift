import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandFilesystemCaptureTests: XCTestCase {
    private enum Cancelled: Error { case test }
    private final class Fixture {
        let root: String
        var executable: String { root + "/tool" }
        var cwd: String { root + "/cwd" }
        let content: Data
        init(content: Data = Data("#!/bin/sh\nprintf fixture\n".utf8)) throws {
            root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
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
