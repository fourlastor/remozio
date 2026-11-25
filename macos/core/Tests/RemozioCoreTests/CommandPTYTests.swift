import Darwin
import Foundation
import RemozioMach
import XCTest
@testable import RemozioCore

final class CommandPTYTests: XCTestCase {
    private func rawPTY() throws -> RetainedCommandPTY {
        let seed = try RetainedCommandPTY()
        var attributes = termios()
        try seed.withBorrowedSlave { descriptor in
            guard tcgetattr(descriptor, &attributes) == 0 else { throw RetainedCommandPTYError.native(errno) }
        }
        seed.close(); cfmakeraw(&attributes)
        return try RetainedCommandPTY(attributes: attributes, size: winsize(ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0))
    }
    private func awaitBytes(_ pty: RetainedCommandPTY, count: Int) throws -> Data {
        var bytes = Data()
        let deadline = Date().addingTimeInterval(3)
        while bytes.count < count {
            switch try pty.read(maximumBytes: min(64, count - bytes.count)) {
            case .bytes(let value): bytes.append(value)
            case .waiting: usleep(1000)
            case .end: throw RetainedCommandPTYError.native(EIO)
            }
            if Date() > deadline { throw RetainedCommandPTYError.native(ETIMEDOUT) }
        }
        return bytes
    }
    func testPrivateTerminalPreservesOriginalStreamFlagsAndBlockingSlave() throws {
        let before = (0...2).map { fcntl(Int32($0), F_GETFL) }
        let pty = try rawPTY(); defer { pty.close() }
        try pty.withBorrowedSlave { descriptor in
            XCTAssertEqual(isatty(descriptor), 1)
            XCTAssertNotEqual(fcntl(descriptor, F_GETFD) & FD_CLOEXEC, 0)
            XCTAssertEqual(fcntl(descriptor, F_GETFL) & O_NONBLOCK, 0)
            var size = winsize()
            XCTAssertEqual(ioctl(descriptor, TIOCGWINSZ, &size), 0)
            XCTAssertEqual(size.ws_row, 24); XCTAssertEqual(size.ws_col, 80)
        }
        XCTAssertEqual((0...2).map { fcntl(Int32($0), F_GETFL) }, before)
    }
    private func slaveMetadata(_ descriptor: Int32) throws -> stat {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { throw RetainedCommandPTYError.native(errno) }
        return metadata
    }
    private func defaultSlaveMetadata() throws -> stat {
        let pty = try RetainedCommandPTY()
        defer { pty.close() }
        return try pty.withBorrowedSlave { try slaveMetadata($0) }
    }
    func testRootTargetKeepsAllocatorOwnershipAndMode() throws {
        let baseline = try defaultSlaveMetadata()
        let pty = try RetainedCommandPTY(target: (0, getegid()))
        defer { pty.close() }
        let observed = try pty.withBorrowedSlave { try slaveMetadata($0) }
        XCTAssertEqual(observed.st_uid, baseline.st_uid)
        XCTAssertEqual(observed.st_gid, baseline.st_gid)
        XCTAssertEqual(observed.st_mode, baseline.st_mode)
    }
    func testNonRootTargetGetsAnOwnerOnlySlave() throws {
        let uid = geteuid(), gid = getegid()
        guard uid != 0 else { throw XCTSkip("Requires an ordinary allocator") }
        let pty = try RetainedCommandPTY(target: (uid, gid))
        defer { pty.close() }
        let observed = try pty.withBorrowedSlave { try slaveMetadata($0) }
        XCTAssertEqual(observed.st_uid, uid)
        XCTAssertEqual(observed.st_gid, gid)
        XCTAssertEqual(observed.st_mode & 0o7777, 0o600)
    }
    func testDeniedOwnershipReturnsNoPrivateTerminal() throws {
        let uid = geteuid()
        guard uid != 0 else { throw XCTSkip("Requires an ordinary allocator") }
        var handle: OpaquePointer?
        let status = remozio_command_pty_create_for_target(nil, nil, uid == 1 ? 2 : 1, getegid(), &handle)
        defer { remozio_command_pty_close(handle) }
        XCTAssertEqual(status, EPERM)
        XCTAssertNil(handle)
    }
    func testPrivilegedPTYTransfersOwnershipAndTargetCanReopenSlave() throws {
        let environment = ProcessInfo.processInfo.environment
        let uidValue = environment["REMOZIO_CREDENTIAL_FIXTURE_UID"]
        let gidValue = environment["REMOZIO_CREDENTIAL_FIXTURE_GID"]
        guard uidValue != nil || gidValue != nil else { throw XCTSkip("Requires the privileged credential fixture") }
        let uid = try XCTUnwrap(uidValue.flatMap { uid_t($0) })
        let gid = try XCTUnwrap(gidValue.flatMap { gid_t($0) })
        guard getuid() == 0, geteuid() == 0, uid > 0, gid > 0 else {
            return XCTFail("The privileged fixture requires a separate target")
        }
        let baseline = try defaultSlaveMetadata()
        XCTAssertEqual(baseline.st_uid, 0)
        XCTAssertNotEqual(baseline.st_gid, gid)
        let rootPTY = try RetainedCommandPTY(target: (0, gid))
        defer { rootPTY.close() }
        let rootSlave = try rootPTY.withBorrowedSlave { try slaveMetadata($0) }
        XCTAssertEqual(rootSlave.st_uid, baseline.st_uid)
        XCTAssertEqual(rootSlave.st_gid, baseline.st_gid)
        XCTAssertEqual(rootSlave.st_mode, baseline.st_mode)

        let pty = try RetainedCommandPTY(target: (uid, gid))
        defer { pty.close() }
        try pty.withBorrowedSlave { descriptor in
            let original = try slaveMetadata(descriptor)
            XCTAssertEqual(original.st_uid, uid)
            XCTAssertEqual(original.st_gid, gid)
            XCTAssertEqual(original.st_mode & 0o7777, 0o600)
            var path = [CChar](repeating: 0, count: Int(PATH_MAX))
            let status = path.withUnsafeMutableBufferPointer { ttyname_r(descriptor, $0.baseAddress!, $0.count) }
            guard status == 0 else { throw RetainedCommandPTYError.native(status) }
            try CommandFilesystemCaller(userID: uid, groupID: gid).withIdentity {
                let reopened = path.withUnsafeBufferPointer { Darwin.open($0.baseAddress!, O_RDWR | O_NOCTTY | O_CLOEXEC) }
                guard reopened >= 0 else { throw RetainedCommandPTYError.native(errno) }
                defer { _ = Darwin.close(reopened) }
                let metadata = try slaveMetadata(reopened)
                XCTAssertEqual(metadata.st_dev, original.st_dev)
                XCTAssertEqual(metadata.st_ino, original.st_ino)
                XCTAssertEqual(metadata.st_rdev, original.st_rdev)
            }
        }
        try CommandFilesystemCaller.requireProcessIdentity()
    }
    func testForegroundQueryHasNoGroupBeforePrivateSessionOwnershipAndCannotReuseAClosedOwner() throws {
        let pty = try rawPTY()
        let before = (0...2).map { fcntl(Int32($0), F_GETFL) }
        XCTAssertNil(try pty.foregroundGroup())
        XCTAssertEqual((0...2).map { fcntl(Int32($0), F_GETFL) }, before)
        pty.close()
        XCTAssertThrowsError(try pty.foregroundGroup()) { XCTAssertEqual($0 as? RetainedCommandPTYError, .closed) }
    }
    func testBoundedReadWaitsWithoutBlockingAndPreservesRawOutput() throws {
        let pty = try rawPTY(); defer { pty.close() }
        let start = DispatchTime.now().uptimeNanoseconds
        XCTAssertEqual(try pty.read(), .waiting)
        XCTAssertLessThan(DispatchTime.now().uptimeNanoseconds - start, 100_000_000)
        let expected = Data((0..<128).map { UInt8($0) }) + Data([0xff, 0x0a, 0x00, 0x0d])
        try pty.withBorrowedSlave { descriptor in
            XCTAssertEqual(expected.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }, expected.count)
        }
        XCTAssertEqual(try awaitBytes(pty, count: expected.count), expected)
    }
    func testChunkLimitsRejectOversizedWorkBeforeAllocatingOrWriting() throws {
        let pty = try rawPTY(); defer { pty.close() }
        for count in [-1, 0, 65_537] {
            XCTAssertThrowsError(try pty.read(maximumBytes: count)) { XCTAssertEqual($0 as? RetainedCommandPTYError, .invalidChunk) }
        }
        XCTAssertThrowsError(try pty.write(Data(count: 65_537))) { XCTAssertEqual($0 as? RetainedCommandPTYError, .invalidChunk) }
        XCTAssertEqual(try pty.write(Data()), 0)
        XCTAssertEqual(try pty.read(), .waiting)
    }
    func testRawInputWriteReturnsOnlyAcceptedBytesAndOrdinaryBackpressure() throws {
        let pty = try rawPTY(); defer { pty.close() }
        let input = Data((0..<65_536).map { UInt8($0 % 251) })
        let accepted = try pty.write(input)
        XCTAssertGreaterThan(accepted, 0); XCTAssertLessThanOrEqual(accepted, input.count)
        var received = Data()
        try pty.withBorrowedSlave { descriptor in
            let deadline = Date().addingTimeInterval(3)
            while received.count < accepted {
                var readiness = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
                XCTAssertEqual(poll(&readiness, 1, 1000), 1)
                var buffer = [UInt8](repeating: 0, count: min(4096, accepted - received.count))
                let count = Darwin.read(descriptor, &buffer, buffer.count)
                guard count > 0 else { throw RetainedCommandPTYError.native(EIO) }
                received.append(contentsOf: buffer.prefix(count))
                if Date() > deadline { throw RetainedCommandPTYError.native(ETIMEDOUT) }
            }
        }
        XCTAssertEqual(received, input.prefix(accepted))
        var stalled = false
        for _ in 0..<64 {
            if try pty.write(input) == 0 { stalled = true; break }
        }
        XCTAssertTrue(stalled)
    }
    func testResizeChangesOnlyPrivateSlaveIncludingUnknownZeroDimensions() throws {
        let pty = try rawPTY(); defer { pty.close() }
        for (rows, columns): (UInt16, UInt16) in [(53, 143), (0, 0)] {
            try pty.resize(winsize(ws_row: rows, ws_col: columns, ws_xpixel: 0, ws_ypixel: 0))
            try pty.withBorrowedSlave { descriptor in
                var observed = winsize()
                XCTAssertEqual(ioctl(descriptor, TIOCGWINSZ, &observed), 0)
                XCTAssertEqual(observed.ws_row, rows); XCTAssertEqual(observed.ws_col, columns)
            }
        }
    }
    func testSealingAndClosingHaveExplicitStreamOnlyOutcomes() throws {
        let pty = try rawPTY()
        pty.sealSlave(); pty.sealSlave()
        XCTAssertThrowsError(try pty.withBorrowedSlave { _ in () }) { XCTAssertEqual($0 as? RetainedCommandPTYError, .native(EBADF)) }
        XCTAssertEqual(try pty.read(), .end); XCTAssertEqual(try pty.read(), .end)
        XCTAssertThrowsError(try pty.write(Data([1]))) { XCTAssertEqual($0 as? RetainedCommandPTYError, .native(EPIPE)) }
        pty.close(); pty.close()
        XCTAssertThrowsError(try pty.read()) { XCTAssertEqual($0 as? RetainedCommandPTYError, .closed) }
        XCTAssertThrowsError(try pty.write(Data([1]))) { XCTAssertEqual($0 as? RetainedCommandPTYError, .closed) }
        XCTAssertThrowsError(try pty.resize(winsize())) { XCTAssertEqual($0 as? RetainedCommandPTYError, .closed) }
    }
}


extension CommandPTYTests {
    func testCurrentCanonicalEOFSequencePreservesModesAndDoesNotInventRawBytes() throws {
        let pty = try RetainedCommandPTY(); defer { pty.close() }
        try pty.withBorrowedSlave { descriptor in
            var attributes = termios(); XCTAssertEqual(tcgetattr(descriptor, &attributes), 0)
            attributes.c_lflag |= UInt(ICANON); attributes.c_lflag &= ~UInt(ECHO); withUnsafeMutableBytes(of: &attributes.c_cc) { $0[Int(VEOF)] = 4 }
            XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
            XCTAssertEqual(try pty.currentCanonicalEOFSequence(), Data([4, 4]))
            cfmakeraw(&attributes); XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
            XCTAssertNil(try pty.currentCanonicalEOFSequence())
            var after = termios(); XCTAssertEqual(tcgetattr(descriptor, &after), 0)
            XCTAssertEqual(after.c_lflag, attributes.c_lflag); XCTAssertEqual(after.c_iflag, attributes.c_iflag)
            var ready = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            XCTAssertEqual(poll(&ready, 1, 10), 0)
        }
    }
    func testPrivateForegroundSignalRejectsInvalidNumbersAndClosedOwnership() throws {
        let pty = try RetainedCommandPTY()
        for value in [Int32(0), -1, NSIG] {
            XCTAssertThrowsError(try pty.signalForeground(value)) { XCTAssertEqual($0 as? RetainedCommandPTYError, .native(EINVAL)) }
        }
        pty.close()
        XCTAssertThrowsError(try pty.signalForeground(SIGINT)) { XCTAssertEqual($0 as? RetainedCommandPTYError, .closed) }
        XCTAssertThrowsError(try pty.currentCanonicalEOFSequence()) { XCTAssertEqual($0 as? RetainedCommandPTYError, .closed) }
    }
}


extension CommandPTYTests {
    func testEOFDeliveryRechecksRealTerminalModeAndCharacterAfterZeroAndPartialWrites() throws {
        let pty = try RetainedCommandPTY(); defer { pty.close() }
        try pty.withBorrowedSlave { descriptor in
            var attributes = termios(); XCTAssertEqual(tcgetattr(descriptor, &attributes), 0)
            attributes.c_lflag |= UInt(ICANON); attributes.c_lflag &= ~UInt(ECHO)
            withUnsafeMutableBytes(of: &attributes.c_cc) { $0[Int(VEOF)] = 4 }
            XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
            var eof = CommandPTYEOFDelivery()
            XCTAssertFalse(try eof.flush(to: pty) { bytes in XCTAssertEqual(bytes, Data([4, 4])); return 0 })
            cfmakeraw(&attributes); XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
            XCTAssertFalse(try eof.flush(to: pty) { _ in XCTFail("A raw retry must write no cached EOF bytes"); return 0 })
            attributes.c_lflag |= UInt(ICANON)
            withUnsafeMutableBytes(of: &attributes.c_cc) { $0[Int(VEOF)] = 6 }
            XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
            XCTAssertFalse(try eof.flush(to: pty) { bytes in XCTAssertEqual(bytes, Data([6, 6])); return 1 })
            cfmakeraw(&attributes); XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
            XCTAssertFalse(try eof.flush(to: pty) { _ in XCTFail("A partial write must not leak its suffix into raw mode"); return 0 })
            attributes.c_lflag |= UInt(ICANON)
            withUnsafeMutableBytes(of: &attributes.c_cc) { $0[Int(VEOF)] = 7 }
            XCTAssertEqual(tcsetattr(descriptor, TCSANOW, &attributes), 0)
            XCTAssertTrue(try eof.flush(to: pty) { bytes in XCTAssertEqual(bytes, Data([7])); return 1 })
            XCTAssertTrue(try eof.flush(to: pty) { _ in XCTFail("Completed EOF must not repeat"); return 0 })
        }
    }
}
