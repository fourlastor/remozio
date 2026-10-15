import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class BoundedNativeCommandTests: XCTestCase {
    private func ordinary() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Owned ordinary-user process fixture") }
    }
    func testCapturesBothStreamsAndPreservesAnOrdinaryExitCode() throws {
        try ordinary()
        let result = try BoundedNativeCommand.run(executable: "/bin/sh", arguments: ["-c", "printf ok; printf diagnostic >&2; exit 7"])
        XCTAssertEqual(result.exitCode, 7); XCTAssertEqual(result.output, Data("ok".utf8)); XCTAssertEqual(result.errorOutput, Data("diagnostic".utf8))
    }
    func testOutputLimitKillsAndReapsOnlyTheOwnedChild() throws {
        try ordinary()
        XCTAssertThrowsError(try BoundedNativeCommand.run(executable: "/usr/bin/yes", arguments: ["synthetic"], maximumOutputBytes: 1024)) {
            XCTAssertEqual($0 as? BoundedNativeCommand.Failure, .outputLimit)
        }
    }
    func testDeadlineKillsAndReapsTheOwnedSleeperPromptly() throws {
        try ordinary(); let start = DispatchTime.now().uptimeNanoseconds
        XCTAssertThrowsError(try BoundedNativeCommand.run(executable: "/bin/sleep", arguments: ["5"], timeoutMilliseconds: 50)) {
            XCTAssertEqual($0 as? BoundedNativeCommand.Failure, .timedOut)
        }
        XCTAssertLessThan(DispatchTime.now().uptimeNanoseconds - start, 2_000_000_000)
    }
    func testChildCannotInheritACallerDescriptorWithoutCloseOnExec() throws {
        try ordinary()
        let fd = open("/dev/null", O_RDONLY); XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = close(fd) }
        let extra = fcntl(fd, F_DUPFD, 100); XCTAssertGreaterThanOrEqual(extra, 100); defer { _ = close(extra) }
        XCTAssertEqual(fcntl(extra, F_SETFD, 0), 0)
        let result = try BoundedNativeCommand.run(executable: "/bin/sh", arguments: ["-c", "test ! -e /dev/fd/\(extra)"])
        XCTAssertEqual(result.exitCode, 0)
    }
    func testInvalidArgumentsRefuseBeforeSpawn() throws {
        try ordinary()
        XCTAssertThrowsError(try BoundedNativeCommand.run(executable: "relative", arguments: []))
        XCTAssertThrowsError(try BoundedNativeCommand.run(executable: "/bin/echo", arguments: ["a\0b"]))
        XCTAssertThrowsError(try BoundedNativeCommand.run(executable: "/bin/echo", arguments: [], maximumOutputBytes: 0))
    }
}
