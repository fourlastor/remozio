import Darwin
import Foundation
import XCTest

final class NativeStdioLayoutTests: XCTestCase {
    private var directory: URL!, child: URL!, monitor: URL!, driver: URL!, target: URL!, standaloneDriver: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-native-stdio-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        child = directory.appendingPathComponent("child")
        monitor = directory.appendingPathComponent("monitor")
        driver = directory.appendingPathComponent("driver")
        target = directory.appendingPathComponent("target")
        standaloneDriver = directory.appendingPathComponent("standalone-driver")
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let app = core.deletingLastPathComponent().appendingPathComponent("app")
        let monitorWrapper = directory.appendingPathComponent("fixture-monitor.c")
        try """
        #include <unistd.h>
        static uid_t fixture_root_uid(void) { return 0; }
        #define getuid fixture_root_uid
        #define geteuid fixture_root_uid
        #include "\(app.appendingPathComponent("CommandMonitor/MonitorMain.c").path)"
        """.write(to: monitorWrapper, atomically: false, encoding: .utf8)
        let childWrapper = directory.appendingPathComponent("fixture-child.c")
        // Only credential operations are mocked. The product framing, descriptors, terminal and exec remain real.
        try """
        #define REMOZIO_OWNED_LIVE_FIXTURE 1
        #include "\(core.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("experiments/command-frontend/live-child.c").path)"
        """.write(to: childWrapper, atomically: false, encoding: .utf8)
        func fixture(_ name: String) throws -> URL {
            try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "c", subdirectory: "Fixtures/command-process"))
        }
        let specification = native.appendingPathComponent("CommandChildSpecification.c")
        let protocolSource = native.appendingPathComponent("CommandMonitorProtocol.c")
        try compile([monitorWrapper, native.appendingPathComponent("CommandProcess.c"), specification, protocolSource], native: native, output: monitor)
        try compile([childWrapper, specification], native: native, output: child)
        try compile([fixture("mapped-target")], native: native, output: target)
        try compile([fixture("mapped-parent"), native.appendingPathComponent("CommandMonitor.c"), specification,
                     protocolSource, native.appendingPathComponent("CommandPTY.c")], native: native, output: driver)
        try compile([fixture("mapped-standalone"), native.appendingPathComponent("CommandProcess.c"), specification,
                     native.appendingPathComponent("CommandPTY.c")], native: native, output: standaloneDriver)
    }

    override func tearDownWithError() throws {
        if let directory { try FileManager.default.removeItem(at: directory) }
    }

    private func compile(_ sources: [URL], native: URL, output: URL) throws {
        let compiler = Process()
        compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
                              "-I", native.path, "-I", native.appendingPathComponent("include").path]
            + sources.map(\.path) + ["-o", output.path]
        try compiler.run()
        compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
    }

    private func run(mask: UInt32, mode: String) throws {
        let arguments = [Data([0xff]), Data(), Data([0xfe]), Data(String(mask).utf8), Data(mode.utf8)]
        let environment = [Data("CWD=\(directory.path)".utf8), Data("EMPTY=".utf8), Data([0x52, 0x41, 0x57, 0x3d, 0xfd])]
        var body = Data()
        func appendWord(_ value: UInt32, to bytes: inout Data) {
            var word = value.bigEndian
            withUnsafeBytes(of: &word) { bytes.append(contentsOf: $0) }
        }
        appendWord(mask, to: &body)
        appendWord(getgid(), to: &body)
        for value in [Data("fixture".utf8), Data(target.path.utf8)] + arguments + environment {
            appendWord(UInt32(value.count), to: &body)
            body.append(value)
        }
        var frame = Data()
        for value in [UInt32(0x524d4333), UInt32(body.count), getuid(), getgid(), 1, UInt32(arguments.count),
                      UInt32(environment.count), 5000, 0o022, 2] {
            appendWord(value, to: &frame)
        }
        frame.append(body)
        let file = directory.appendingPathComponent("frame.bin")
        try frame.write(to: file)
        let process = Process()
        process.executableURL = mode == "standalone" ? standaloneDriver : driver
        process.currentDirectoryURL = directory
        process.arguments = [monitor.path, child.path, file.path, String(mask), mode]
        let output = Pipe()
        process.standardOutput = output
        try process.run()
        process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let diagnostic = String(decoding: data, as: UTF8.self)
        XCTAssertEqual(process.terminationStatus, 0, diagnostic)
        let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(record["failure"] as? Int, 0, diagnostic)
        if mode != "preflight" {
            XCTAssertEqual(record["independentExec"] as? Bool, mode != "prepared_cancel", diagnostic)
            let ownerKey = mode == "standalone" ? "childActuallyReaped" : "monitorActuallyReaped"
            for key in ["independentExit", ownerKey, "terminalEOF"] {
                XCTAssertEqual(record[key] as? Bool, true, diagnostic)
            }
        }
    }

    func testAllEightLayoutsExecuteWithExactBinaryStreamsAndSeparateTerminalControls() throws {
        for mask: UInt32 in 0...7 { try run(mask: mask, mode: "normal") }
    }

    func testStandaloneOwnerKeepsTheTerminalUntilActualChildCleanup() throws {
        for mask: UInt32 in 0...7 { try run(mask: mask, mode: "standalone") }
    }

    func testAllEightLayoutsCancelThroughOwnedMonitor() throws {
        for mask: UInt32 in 0...7 { try run(mask: mask, mode: "cancel") }
    }

    func testAllEightLayoutsCancelBeforeReleaseWithoutExecution() throws {
        for mask: UInt32 in 0...7 { try run(mask: mask, mode: "prepared_cancel") }
    }

    func testActualStopAndContinueWithRedirectedStdin() throws {
        for mask: UInt32 in [0, 5, 7] { try run(mask: mask, mode: "stop") }
    }

    func testAnotherOutputTerminalStaysSeparate() throws {
        try run(mask: 5, mode: "distinct")
    }

    func testVersionAndLayoutRejectionPreserveInputBeforeSpawn() throws {
        for mask: UInt32 in 0...7 { try run(mask: mask, mode: "preflight") }
    }
}
