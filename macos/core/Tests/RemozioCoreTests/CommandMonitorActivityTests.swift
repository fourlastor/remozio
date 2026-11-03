import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class CommandMonitorActivityTests: XCTestCase {
    private func run(_ mode: String) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-monitor-activity-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let monitor = directory.appendingPathComponent("monitor"), child = directory.appendingPathComponent("child")
        let driver = directory.appendingPathComponent("driver"), wrapper = directory.appendingPathComponent("monitor.c")
        try """
        #include <unistd.h>
        static uid_t fixture_root_uid(void) { return 0; }
        #define getuid fixture_root_uid
        #define geteuid fixture_root_uid
        #include "\(core.deletingLastPathComponent().appendingPathComponent("app/CommandMonitor/MonitorMain.c").path)"
        """.write(to: wrapper, atomically: false, encoding: .utf8)
        func fixture(_ name: String) throws -> URL {
            try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "c", subdirectory: "Fixtures/command-process"))
        }
        func compile(_ sources: [URL], _ output: URL) throws {
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
            process.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
                "-I", native.path, "-I", native.appendingPathComponent("include").path] + sources.map(\.path) + ["-o", output.path]
            try process.run(); process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 0)
            guard process.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        }
        let specification = native.appendingPathComponent("CommandChildSpecification.c")
        let monitorProtocol = native.appendingPathComponent("CommandMonitorProtocol.c")
        try compile([wrapper, native.appendingPathComponent("CommandProcess.c"), specification, monitorProtocol], monitor)
        try compile([fixture("child"), specification], child)
        try compile([fixture("monitor-activity-driver"), specification, monitorProtocol, native.appendingPathComponent("CommandPTY.c")], driver)
        let arguments = [Data([0xff]), Data(), Data([0xfe]), Data("sigwait".utf8)]
        let environment = [Data("EMPTY=".utf8), Data([0x52, 0x41, 0x57, 0x3d, 0xfd])]
        let mapped = mode == "mapped-terminal"
        var body = Data()
        if mapped { var mask = UInt32(7).bigEndian; withUnsafeBytes(of: &mask) { body.append(contentsOf: $0) } }
        for bytes in [Data(child.path.utf8)] + arguments + environment {
            var length = UInt32(bytes.count).bigEndian; withUnsafeBytes(of: &length) { body.append(contentsOf: $0) }; body.append(bytes)
        }
        var frame = Data()
        for value in [UInt32(mapped ? 0x524d4332 : 0x524d4331), UInt32(body.count), getuid(), getgid(), 0, UInt32(arguments.count),
                      UInt32(environment.count), 5000, 0o022, mapped ? 2 : mode == "terminal" ? 1 : 0] {
            var word = value.bigEndian; withUnsafeBytes(of: &word) { frame.append(contentsOf: $0) }
        }
        frame.append(body)
        let file = directory.appendingPathComponent("frame.bin"); try frame.write(to: file)
        let process = Process(); process.executableURL = driver; process.currentDirectoryURL = directory
        process.arguments = [monitor.path, child.path, file.path, mode]
        let output = Pipe(); process.standardOutput = output
        try process.run(); process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        XCTAssertEqual(process.terminationStatus, 0, String(decoding: data, as: UTF8.self))
        let result = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(result["failure"] as? Int, 0)
        XCTAssertEqual(result["monitorActuallyReaped"] as? Bool, mode != "invalid")
    }
    func testNativeRetainedCompatibilityRequiresBothSignedMonitorActivityParticipants() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true)
        let policy = f.plan.host.codePolicy
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
        XCTAssertEqual(Set(snapshot.requirements.formats.filter {
            $0.name == CommandMonitorActivityContract.formatName
        }.map(\.role)), [.authority, .commandMonitor])
        try snapshot.validate(XCTUnwrap(f.nativeRelease), policy: policy, machine: f.machine)
        for role in [AuthorityCodeRole.authority, .commandMonitor] {
            let missing = try NativeHostReleaseFixture.make(policy: policy) { component in
                guard component.role == role else { return component }
                return try .init(role: component.role, identifier: component.identifier,
                    generation: component.generation, relativePath: component.relativePath,
                    codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID,
                    formats: component.formats.filter { $0.name != CommandMonitorActivityContract.formatName },
                    requests: component.requests)
            }
            XCTAssertThrowsError(try snapshot.validate(missing, policy: policy, machine: f.machine)) {
                XCTAssertEqual($0 as? ReleaseCompatibilityError,
                    .missingFormat(role, CommandMonitorActivityContract.formatName))
            }
        }
    }
    func testPreparedCancellationKeepsTheMonitorLeaseThroughActualReaping() throws { try run("cancel") }
    func testRootControlEOFWhileTheMonitorIsStoppedRetainsActivityAndClosesTheCommand() throws { try run("eof") }
    func testTerminalCommandReceivesNoActivityDescriptor() throws { try run("terminal") }
    func testMappedTerminalAndActivityDescriptorsRemainSeparate() throws { try run("mapped-terminal") }
    func testMalformedActivityDescriptorsNeverSpawnAMonitor() throws { try run("invalid") }
}
