import Darwin
import Foundation
import RemozioMach
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandDirectoryCredentialTests: XCTestCase {
    private func capture(target: CommandTarget, mode: CommandIOMode = .pipes, mask: UInt32? = nil) throws -> CommandCapture {
        let source = CapturedCommandInput(kind: .pipe, streamBinding: Data(count: 16), observedPath: nil, identity: nil)
        let tty = CapturedCommandInput(kind: .tty, streamBinding: Data(repeating: 9, count: 16), observedPath: nil,
            identity: .init(device: 7, inode: 8))
        let layout = mask.map { mask in CapturedCommandStdioLayout(
            input: .init(source: mask & 1 == 0 ? source : tty, access: .readOnly, flags: []),
            output: .init(source: mask & 2 == 0 ? source : tty, access: .writeOnly, flags: []),
            error: .init(source: mask & 4 == 0 ? source : tty, access: .writeOnly, flags: []),
            terminal: .init(stream: .init(source: tty, access: .readWrite, flags: []), sessionID: 123, terminalDevice: 9),
            ptyMask: mask) }
        return try .init(schemaVersion: mask == nil ? 1 : 3,
            executable: .init(path: Data("/usr/bin/true".utf8), identity: .init(device: 1, inode: 2), sha256: Data(count: 32)),
            arguments: [Data([0xff]), Data(), Data([0xfe, 0x0a])],
            directory: .init(path: Data("/tmp".utf8), identity: .init(device: 1, inode: 3)), target: target,
            environment: [.init(name: Data("RAW".utf8), value: Data([0xff]), source: .requested)],
            input: layout?.input.source ?? source, ioMode: mode, disconnectBehavior: .terminate,
            requester: .init(executablePath: Data("/fixture/caller".utf8), realUID: 501, effectiveUID: 501, pid: 10,
                pidVersion: 11, signing: .init(status: .unsigned, identifier: nil, team: nil, cdHash: nil),
                sessionID: mask == nil ? nil : 123, ttyPath: nil),
            ancestry: .init(completeness: .unavailable, entries: [], reason: .unsupported), unverifiedRationale: nil,
            submission: .init(id: Data(count: 16), nonce: Data(count: 32), callerBinding: Data(count: 16)), stdioLayout: layout,
            limits: .init(maxBytes: 131_072, maxDepth: 16, maxItems: 8192))
    }
    private var fixture: CommandTarget { .init(uid: 1234, gid: 42, supplementaryGroups: [42, 5678], observedName: "fixture") }
    private func frame(_ target: CommandTarget, mode: CommandIOMode = .pipes, mask: UInt32? = nil) throws -> Data {
        try CommandChildLaunchSpecification(capture: capture(target: target, mode: mode, mask: mask),
            preparationMilliseconds: 1000, fileCreationMask: 0o027).canonicalBytes
    }
    private func decoded(_ bytes: Data, inspect: (inout remozio_child_spec_t) throws -> Void) throws {
        var spec = remozio_child_spec_t(); defer { remozio_child_spec_close(&spec) }
        let result = bytes.withUnsafeBytes { remozio_child_spec_decode($0.baseAddress, $0.count, &spec) }
        XCTAssertEqual(result, 0)
        guard result == 0 else { throw CocoaError(.coderReadCorrupt) }
        try inspect(&spec)
    }
    private func executableInfo(_ path: String = "/usr/bin/true") throws -> stat {
        var info = stat()
        guard lstat(path, &info) == 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        return info
    }
    func testProductionFramesBindAccountNameAndAllTerminalLayoutsWithoutChangingCapture() throws {
        let info = try executableInfo()
        for mask in [nil] + (0...7).map({ Optional(UInt32($0)) }) {
            let mode: CommandIOMode = mask == nil ? .pipes : .pty
            let capture = try capture(target: fixture, mode: mode, mask: mask), original = capture.canonicalBytes
            let launch = CommandExecutableLaunch(mode: .protectedPath, info: info)
            let bytes = try CommandChildLaunchSpecification(capture: capture, launch: launch,
                preparationMilliseconds: 1000, fileCreationMask: 0o027).canonicalBytes
            try decoded(bytes) { spec in
                XCTAssertEqual(spec.format_version, 4); XCTAssertEqual(spec.stdio_pty_mask, mask ?? 0)
                XCTAssertEqual(spec.launch_mode, REMOZIO_CHILD_LAUNCH_PROTECTED_PATH)
                XCTAssertEqual(remozio_child_spec_check_executable(&spec), 0)
                XCTAssertEqual(spec.io_mode, mask == nil ? 0 : 2)
                XCTAssertEqual(String(cString: spec.account_name), "fixture")
                XCTAssertEqual(Array(UnsafeBufferPointer(start: spec.groups, count: Int(spec.group_count))), [42, 5678])
                XCTAssertEqual(Data(bytes: spec.arguments[0]!, count: 1), Data([0xff]))
                XCTAssertEqual(remozio_child_account_validate(&spec), ESTALE)
            }
            XCTAssertEqual(capture.canonicalBytes, original)
        }
        try decoded(frame(fixture, mode: .pty)) { spec in
            XCTAssertEqual(spec.format_version, 3); XCTAssertEqual(spec.io_mode, 1); XCTAssertEqual(spec.stdio_pty_mask, 7)
        }
    }
    func testPathBoundFrameChecksExecutableMetadataWithoutReadingOrLaunchingIt() throws {
        let fixture = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data([0x01]).write(to: fixture)
        defer { try? FileManager.default.removeItem(at: fixture) }
        XCTAssertEqual(chmod(fixture.path, 0o100), 0)
        let info = try executableInfo(fixture.path)
        let launch = CommandExecutableLaunch(mode: .pathBound, info: info)
        let bytes = try CommandChildLaunchSpecification(capture: capture(target: self.fixture),
            resolvedExecutablePath: Data(fixture.path.utf8), launch: launch,
            preparationMilliseconds: 1000, fileCreationMask: 0o027).canonicalBytes
        try decoded(bytes) { spec in
            XCTAssertEqual(spec.format_version, 4)
            XCTAssertEqual(spec.launch_mode, REMOZIO_CHILD_LAUNCH_PATH_BOUND)
            XCTAssertEqual(spec.executable_inode, info.st_ino)
            XCTAssertEqual(spec.executable_mtime_s, UInt64(bitPattern: Int64(info.st_mtimespec.tv_sec)))
            XCTAssertEqual(remozio_child_spec_check_executable(&spec), 0)
            var mismatch = spec
            mismatch.executable_inode ^= 1
            for mode in [REMOZIO_CHILD_LAUNCH_PROTECTED_PATH, REMOZIO_CHILD_LAUNCH_PATH_BOUND] {
                mismatch.launch_mode = mode
                XCTAssertEqual(remozio_child_spec_check_executable(&mismatch), ESTALE)
            }
            mismatch = spec
            mismatch.executable_ctime_ns ^= 1
            XCTAssertEqual(remozio_child_spec_check_executable(&mismatch), ESTALE)
        }
        for (offset, invalid): (Int, UInt32) in [(44, 0), (44, 3), (88, 1_000_000_000), (100, 1_000_000_000)] {
            var bad = bytes
            withUnsafeBytes(of: invalid.bigEndian) { bad.replaceSubrange(offset..<offset + 4, with: $0) }
            var spec = remozio_child_spec_t()
            defer { remozio_child_spec_close(&spec) }
            XCTAssertEqual(bad.withUnsafeBytes { remozio_child_spec_decode($0.baseAddress, $0.count, &spec) }, EINVAL)
            XCTAssertNil(spec.storage)
        }
    }

    func testActualDirectorySnapshotsValidateWithoutApplyingCredentialsOrTruncatingRoot() throws {
        for uid in [UInt32(0), getuid()] {
            let target = try CommandTargetResolver.resolve(uid: uid)
            try decoded(frame(target)) { spec in
                XCTAssertEqual(spec.group_count, UInt32(target.supplementaryGroups.count))
                XCTAssertEqual(Array(UnsafeBufferPointer(start: spec.groups, count: Int(spec.group_count))), target.supplementaryGroups)
                XCTAssertEqual(remozio_child_account_validate(&spec), 0)
                var legacyGroups = [UInt32](repeating: 0, count: 16), count: UInt32 = 0
                XCTAssertEqual(remozio_child_spec_groups(&spec, &legacyGroups, &count), EINVAL)
            }
        }
    }
    func testChangedAccountNameUIDGIDOrMembershipCannotValidate() throws {
        let target = try CommandTargetResolver.resolve(uid: getuid())
        try decoded(frame(target)) { spec in
            var changed = spec; changed.uid = UInt32.max
            XCTAssertEqual(remozio_child_account_validate(&changed), EINVAL)
            changed = spec; changed.uid = getuid() == 0 ? 1 : 0
            XCTAssertNotEqual(remozio_child_account_validate(&changed), 0)
            changed = spec; changed.gid = UInt32.max
            XCTAssertEqual(remozio_child_account_validate(&changed), EINVAL)
            "nonexistent-remozio-fixture".withCString { name in
                changed = spec; changed.account_name = UnsafeMutablePointer(mutating: name)
                XCTAssertEqual(remozio_child_account_validate(&changed), ESTALE)
            }
            var groups = target.supplementaryGroups.filter { $0 != target.gid }
            if !groups.isEmpty {
                groups = [target.gid]
                groups.withUnsafeMutableBufferPointer { values in
                    changed = spec; changed.groups = values.baseAddress; changed.group_count = UInt32(values.count)
                    XCTAssertEqual(remozio_child_account_validate(&changed), ESTALE)
                }
            }
        }
    }
    func testOrdinaryAccountCannotApplyEvenAnUnchangedValidSnapshot() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Requires an ordinary process") }
        let uid = getuid(), gid = getgid(), euid = geteuid(), egid = getegid()
        let target = try CommandTargetResolver.resolve(uid: uid)
        try decoded(frame(target)) { spec in XCTAssertEqual(remozio_child_account_apply(&spec), EPERM) }
        XCTAssertEqual(getuid(), uid); XCTAssertEqual(getgid(), gid); XCTAssertEqual(geteuid(), euid); XCTAssertEqual(getegid(), egid)
        XCTAssertEqual(try CommandTargetResolver.resolve(uid: uid), target)
    }
    func testEncoderRefusesMissingNamesNoncanonicalMembershipAndOverflows() throws {
        for target: CommandTarget in [
            .init(uid: 1234, gid: 42, supplementaryGroups: [42], observedName: nil),
            .init(uid: 1234, gid: 42, supplementaryGroups: [42], observedName: ""),
            .init(uid: 1234, gid: 42, supplementaryGroups: [42], observedName: "bad\0name"),
            .init(uid: 1234, gid: 42, supplementaryGroups: [], observedName: "fixture"),
            .init(uid: 1234, gid: 42, supplementaryGroups: [5678], observedName: "fixture"),
            .init(uid: 1234, gid: 42, supplementaryGroups: [5678, 42], observedName: "fixture"),
            .init(uid: 1234, gid: 42, supplementaryGroups: [42, 42], observedName: "fixture"),
            .init(uid: 1234, gid: 42, supplementaryGroups: Array(0...1024), observedName: "fixture")
        ] { XCTAssertThrowsError(try frame(target)) }
        let maximum = CommandTarget(uid: 1234, gid: 42, supplementaryGroups: Array(0..<1024), observedName: "fixture")
        try decoded(frame(maximum)) { spec in XCTAssertEqual(spec.group_count, 1024) }
    }
    func testEveryTruncationTrailingBytesAndLegacyRetagAreRejected() throws {
        let bytes = try frame(fixture)
        for length in 0..<bytes.count {
            var spec = remozio_child_spec_t(); defer { remozio_child_spec_close(&spec) }
            XCTAssertEqual(bytes.prefix(length).withUnsafeBytes { remozio_child_spec_decode($0.baseAddress, $0.count, &spec) }, EINVAL)
            XCTAssertNil(spec.storage)
        }
        for magic: UInt32 in [0x524d4331, 0x524d4332, 0x524d4334] {
            var changed = bytes, big = magic.bigEndian
            withUnsafeBytes(of: &big) { changed.replaceSubrange(0..<4, with: $0) }
            var spec = remozio_child_spec_t(); defer { remozio_child_spec_close(&spec) }
            XCTAssertEqual(changed.withUnsafeBytes { remozio_child_spec_decode($0.baseAddress, $0.count, &spec) }, EINVAL)
        }
        var spec = remozio_child_spec_t(); defer { remozio_child_spec_close(&spec) }
        XCTAssertEqual((bytes + Data([0])).withUnsafeBytes { remozio_child_spec_decode($0.baseAddress, $0.count, &spec) }, EINVAL)
        let legacy = try CommandChildLaunchSpecification(legacyCapture: capture(target: fixture), preparationMilliseconds: 1000, fileCreationMask: 0o027).canonicalBytes
        try decoded(legacy) { value in XCTAssertEqual(remozio_child_account_validate(&value), EINVAL) }
    }
    func testNativeAccountTransitionsFailClosedAtEveryCredentialBoundary() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = root.appendingPathComponent("Sources/RemozioMach")
        let hooks = try XCTUnwrap(Bundle.module.url(forResource: "account-credentials-hooks", withExtension: "h", subdirectory: "Fixtures/command-process"))
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: "account-credentials-controls", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-account-api-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("controls")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-DREMOZIO_ACCOUNT_CREDENTIALS_FIXTURE=1", "-include", hooks.path,
            "-I", native.appendingPathComponent("include").path, native.appendingPathComponent("CommandAccountCredentials.c").path,
            fixture.path, "-o", executable.path]
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let process = Process(); process.executableURL = executable
        let output = Pipe(); process.standardOutput = output
        try process.run(); process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertEqual(String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
            "Credential API controls: 12 passed; no real credential operations.\n")
    }

}
