import Foundation
import XCTest

final class FrontendTerminalIOTests: XCTestCase {
    @discardableResult
    private func run(_ name: String, wrapper: Bool, arguments: [String] = [], expectedFailure: Int32 = 0) throws -> [String: Any] {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-frontend-io-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "c", subdirectory: "Fixtures/command-process"))
        let terminalSource: URL
        if wrapper {
            terminalSource = directory.appendingPathComponent("terminal-wrapper.c")
            try """
            #include <unistd.h>
            #include <termios.h>
            extern int fixture_fake_foreground;
            static pid_t checked_foreground(int descriptor) {
                return fixture_fake_foreground ? getpgrp() : tcgetpgrp(descriptor);
            }
            #define tcgetpgrp checked_foreground
            #include "\(native.appendingPathComponent("FrontendTerminal.c").path)"
            """.write(to: terminalSource, atomically: false, encoding: .utf8)
        } else { terminalSource = native.appendingPathComponent("FrontendTerminal.c") }
        let driver = directory.appendingPathComponent("driver")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-I", native.appendingPathComponent("include").path, terminalSource.path, fixture.path,
            native.appendingPathComponent("CommandStreamSource.c").path, "-o", driver.path]
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let process = Process(); process.executableURL = driver; process.arguments = arguments
        let output = Pipe(); process.standardOutput = output
        try process.run(); process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        XCTAssertEqual(process.terminationStatus, expectedFailure, String(decoding: data, as: UTF8.self))
        let result = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(result["failure"] as? Int, Int(expectedFailure))
        XCTAssertEqual(result["sessionOwnerReaped"] as? Bool, true)
        if wrapper {
            XCTAssertEqual(result["workerDiagnosticPresent"] as? Bool, true)
            XCTAssertEqual(result["workerStatusKnown"] as? Bool, true)
            XCTAssertEqual(result["workerReaped"] as? Bool, true)
            if expectedFailure != 0 { return result }
            XCTAssertEqual(result["workerExitCode"] as? Int, 0)
            XCTAssertEqual(result["workerSignal"] as? Int, 0)
            XCTAssertEqual(result["cleanupKillAttempted"] as? Bool, false)
            XCTAssertEqual(result["backgroundReadInterrupted"] as? Bool, true)
            XCTAssertEqual(result["queuedInputPreserved"] as? Bool, true)
            XCTAssertEqual(result["restorationRetainedThenCompleted"] as? Bool, true)
        } else {
            XCTAssertEqual(result["outputBackpressureObserved"] as? Bool, true)
            XCTAssertEqual(result["outputMatched"] as? Bool, true)
            XCTAssertEqual(result["exactOutputBytes"] as? Int, 1_048_576)
            XCTAssertEqual(result["binaryInputPreserved"] as? Bool, true)
        }
        return result
    }
    func testActualOwnerPreservesBinaryIOThroughRealTerminalBackpressure() throws {
        try run("frontend-terminal-io", wrapper: false)
    }
    func testActualBackgroundReadRaceRejectsUnsafeSignalsAndPreservesInput() throws {
        try run("frontend-terminal-read-race", wrapper: true)
    }
    func testReadRacePreservesEarlyWorkerExit() throws {
        let result = try run("frontend-terminal-read-race", wrapper: true,
            arguments: ["--worker-exit-before-ready"], expectedFailure: 34)
        XCTAssertEqual(result["supervisorPhase"] as? Int, 2)
        XCTAssertEqual(result["reportReadResult"] as? Int, 0)
        XCTAssertEqual(result["reportReadErrno"] as? Int, 0)
        XCTAssertEqual(result["workerExitCode"] as? Int, 87)
        XCTAssertEqual(result["workerSignal"] as? Int, 0)
    }
    func testReadRacePreservesWorkerSignal() throws {
        let result = try run("frontend-terminal-read-race", wrapper: true,
            arguments: ["--worker-signal-before-ready"], expectedFailure: 34)
        XCTAssertEqual(result["supervisorPhase"] as? Int, 2)
        XCTAssertEqual(result["reportReadResult"] as? Int, 0)
        XCTAssertEqual(result["workerExitCode"] as? Int, -1)
        XCTAssertEqual(result["workerSignal"] as? Int, 15)
    }
    func testReadRaceDistinguishesCleanupKillFromWorkerFailure() throws {
        let result = try run("frontend-terminal-read-race", wrapper: true,
            arguments: ["--worker-invalid-ready"], expectedFailure: 34)
        XCTAssertEqual(result["supervisorPhase"] as? Int, 2)
        XCTAssertEqual(result["reportReadResult"] as? Int, 1)
        XCTAssertEqual(result["reportByte"] as? Int, 88)
        XCTAssertEqual(result["workerExitCode"] as? Int, -1)
        XCTAssertEqual(result["workerSignal"] as? Int, 9)
        XCTAssertEqual(result["statusObservedBeforeCleanup"] as? Bool, false)
        XCTAssertEqual(result["cleanupKillAttempted"] as? Bool, true)
    }

}
