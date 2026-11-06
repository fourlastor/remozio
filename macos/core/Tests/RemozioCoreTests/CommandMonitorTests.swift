import Darwin
import Foundation
import XCTest

final class CommandMonitorTests: XCTestCase {
    private var directory: URL!, child: URL!, monitor: URL!, driver: URL!
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-monitor-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        child = directory.appendingPathComponent("child"); monitor = directory.appendingPathComponent("monitor"); driver = directory.appendingPathComponent("driver")
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let product = core.deletingLastPathComponent().appendingPathComponent("app/CommandMonitor/MonitorMain.c")
        let wrapper = directory.appendingPathComponent("fixture-monitor.c")
        // The test wrapper substitutes only the root guard. It grants no privilege and never enters the bundle.
        try """
        #include <unistd.h>
        static uid_t fixture_root_uid(void) { return 0; }
        #define getuid fixture_root_uid
        #define geteuid fixture_root_uid
        #include "\(product.path)"
        """.write(to: wrapper, atomically: false, encoding: .utf8)
        let childSource = try XCTUnwrap(Bundle.module.url(forResource: "child", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let driverSource = try XCTUnwrap(Bundle.module.url(forResource: "monitor-driver", withExtension: "c", subdirectory: "Fixtures/command-process"))
        try compile([wrapper, native.appendingPathComponent("CommandProcess.c"), native.appendingPathComponent("CommandChildSpecification.c"), native.appendingPathComponent("CommandMonitorProtocol.c")], native: native, output: monitor)
        try compile([childSource, native.appendingPathComponent("CommandChildSpecification.c")], native: native, output: child)
        try compile([driverSource, native.appendingPathComponent("CommandMonitorProtocol.c"), native.appendingPathComponent("CommandPTY.c")], native: native, output: driver)
    }
    override func tearDownWithError() throws { if let directory { try FileManager.default.removeItem(at: directory) } }
    private func compile(_ sources: [URL], native: URL, output: URL) throws {
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", "-I", native.appendingPathComponent("include").path] + sources.map(\.path) + ["-o", output.path]
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
    }
    private func run(_ mode: String, programMode: String = "wait", budget: UInt32 = 5000, large: Bool = false, missing: Bool = false, launcherName: String? = nil, terminal: Bool = false) throws {
        var launchChild = child!
        if let launcherName { launchChild = directory.appendingPathComponent(launcherName); try FileManager.default.copyItem(at: child, to: launchChild) }
        let arguments = [Data([0xff]), Data(), Data([0xfe]), Data(programMode.utf8)]
        var environment = [Data("CWD=\(directory.path)".utf8), Data("EMPTY=".utf8), Data([0x52,0x41,0x57,0x3d,0xfd])]
        if large { environment.insert(Data("BIG=".utf8) + Data(repeating: 0x61, count: 1_048_576), at: 0) }
        var body = Data()
        for value in [Data((missing ? "/nonexistent/remozio-fixture-target" : child.path).utf8)] + arguments + environment {
            var size = UInt32(value.count).bigEndian; withUnsafeBytes(of: &size) { body.append(contentsOf: $0) }; body.append(value)
        }
        var frame = Data()
        for value in [UInt32(0x524d4331), UInt32(body.count), getuid(), getgid(), 0, UInt32(arguments.count), UInt32(environment.count), budget, 0o022, terminal ? 1 : 0] {
            var word = value.bigEndian; withUnsafeBytes(of: &word) { frame.append(contentsOf: $0) }
        }
        frame.append(body)
        let file = directory.appendingPathComponent("frame.bin"); try frame.write(to: file)
        let process = Process(); process.executableURL = driver; process.currentDirectoryURL = directory
        process.arguments = [monitor.path, launchChild.path, file.path, mode]
        let output = Pipe(); process.standardOutput = output
        try process.run(); process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        XCTAssertEqual(process.terminationStatus, 0, String(decoding: data, as: UTF8.self))
        let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(record["failure"] as? Int, 0); XCTAssertEqual(record["monitorReaped"] as? Bool, true)
    }
    func testExactPipeOutputAndUnconsumedInputBeforeRelease() throws { try run("output", programMode: "output") }
    func testLargeConfigurationMakesBoundedProgress() throws { try run("large_configuration", large: true) }
    func testOrdinaryStopResumeKeepsTheMonitorRunningAndReapsTarget() throws { try run("stop_resume", programMode: "plain_stop") }
    func testStoppedCancellationReportsTheActualTargetSignal() throws { try run("stopped_cancel", programMode: "plain_stop") }
    func testOwnedPrivateTerminalPreservesOrdinaryStopResume() throws { try run("pty_stop_resume", programMode: "plain_stop", terminal: true) }
    func testTerminalSuspendCharacterAndPrivateSignalControls() throws { try run("typed_resume", terminal: true) }
    func testCancellationBeforeConfigurationCreatesNoTarget() throws { try run("cancel_before_configuration") }
    func testCancellationAfterPreparationNeverExecutes() throws { try run("prepared_cancel") }
    func testReleaseEOFNeverExecutes() throws { try run("release_eof") }
    func testMalformedReleaseCannotOpenTheTargetGate() throws { try run("bad_release") }
    func testUndeliveredReleaseReportsTheRetiredTargetWithoutAFailure() throws { try run("closed_release", launcherName: "closed-release-child") }
    func testUnsupportedControlVersionCancelsWithoutExecution() throws { try run("bad_control") }
    func testPartialControlEOFRetainsFailureAndActualCleanup() throws { try run("partial_control") }
    func testReplayedControlCannotBecomeAnotherSignal() throws { try run("replayed_control") }
    func testCancellationAfterExecutionReportsTheActualTargetSignal() throws { try run("cancel_after_exec") }
    func testStatusBackpressureDoesNotPreventTargetCleanup() throws { try run("blocked_status") }
    func testBrokenStatusPipeStillCollectsTheTargetExit() throws { try run("broken_status") }
    func testPartialConfigurationEOFReportsNoTarget() throws { try run("partial_configuration") }
    func testMalformedConfigurationReportsNoTarget() throws { try run("malformed_configuration") }
    func testConfigurationDeadlineDoesNotRestartAtSpawn() throws { try run("stalled_configuration", budget: 100) }
    func testStalledLauncherIsCancelledAndReaped() throws { try run("stalled_child", budget: 100, launcherName: "stalled-child") }
    func testMalformedLauncherStatusIsCancelledAndReaped() throws { try run("malformed_child", launcherName: "malformed-child") }
    func testExecFailureRetainsFailureAndActualLauncherWaitStatus() throws { try run("exec_failure", missing: true) }
}
