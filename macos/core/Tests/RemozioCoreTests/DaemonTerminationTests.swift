import Darwin
import Foundation
import XCTest

final class DaemonTerminationTests: XCTestCase {
    private var directory: URL!
    private var executable: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-daemon-stop-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        executable = directory.appendingPathComponent("daemon-child")
        let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Sources")
        let native = source.appendingPathComponent("RemozioMach")
        let testSource = try XCTUnwrap(Bundle.module.url(forResource: "child", withExtension: "swift",
            subdirectory: "Fixtures/daemon-termination"))
        let header = "RemozioDaemonTermination.h"
        try FileManager.default.copyItem(at: native.appendingPathComponent("include/" + header),
            to: directory.appendingPathComponent(header))
        let moduleMap = "module RemozioMach { header \"\(header)\" export * }\n"
        try moduleMap.write(to: directory.appendingPathComponent("module.modulemap"), atomically: true, encoding: .utf8)
        let object = directory.appendingPathComponent("daemon-signal.o")
        try compile(["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-c", native.appendingPathComponent("DaemonTermination.c").path, "-o", object.path])
        try compile(["swiftc", "-target", "arm64-apple-macosx26.0", "-swift-version", "6", "-parse-as-library",
            "-I", directory.path, source.appendingPathComponent("RemozioCore/DaemonTermination.swift").path,
            testSource.path, object.path, "-o", executable.path])
    }

    override func tearDownWithError() throws {
        if let directory { try FileManager.default.removeItem(at: directory) }
    }

    func testSignalBeforeInstallationTakesTheDefaultAction() throws {
        try withChild("default") { child in
            try child.expect(80)
            try child.send(SIGTERM)
            try child.expectExit(.uncaughtSignal, status: SIGTERM)
        }
    }

    func testSignalBeforeWorkerBindingSkipsStartup() throws {
        try withChild("before-bind") { child in
            try child.expect(73)
            try child.send(SIGTERM)
            try child.expect(74)
            try child.expectExit(.exit, status: 0)
        }
    }

    func testSignalDuringStartupWaitsForDrainBeforeExit() throws {
        try withChild("startup") { child in
            try child.expect(79)
            try child.send(SIGTERM)
            try child.expect(68)
            try child.send(SIGTERM)
            XCTAssertTrue(child.process.isRunning)
            try child.releaseDrain()
            try child.expect(74)
            try child.expectExit(.exit, status: 0)
        }
    }

    func testInterruptAfterReadinessCancelsTheRunningWorker() throws {
        try withChild("ready") { child in
            try child.expect(79)
            try child.expect(82)
            try child.send(SIGINT)
            try child.expect(68)
            try child.releaseDrain()
            try child.expect(74)
            try child.expectExit(.exit, status: 0)
        }
    }

    private func compile(_ arguments: [String]) throws {
        let compiler = Process()
        compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = arguments
        try compiler.run()
        compiler.waitUntilExit()
        guard compiler.terminationReason == .exit, compiler.terminationStatus == 0 else {
            throw CocoaError(.executableNotLoadable)
        }
    }

    private func withChild(_ mode: String, _ body: (Child) throws -> Void) throws {
        let child = try Child(executable: executable, mode: mode)
        defer { child.close() }
        try body(child)
    }

    private final class Child {
        let process = Process()
        private let input = Pipe(), output = Pipe()
        private let terminated = DispatchSemaphore(value: 0)

        init(executable: URL, mode: String) throws {
            process.executableURL = executable
            process.arguments = [mode]
            process.standardInput = input
            process.standardOutput = output
            process.terminationHandler = { [terminated] _ in terminated.signal() }
            try process.run()
        }

        func send(_ signal: Int32) throws {
            guard process.isRunning, kill(process.processIdentifier, signal) == 0 else {
                throw CocoaError(.executableRuntimeMismatch)
            }
        }

        func expect(_ expected: UInt8, file: StaticString = #filePath, line: UInt = #line) throws {
            var ready = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
            guard poll(&ready, 1, 5_000) == 1,
                  let received = try output.fileHandleForReading.read(upToCount: 1),
                  received == Data([expected]) else {
                XCTFail("Child did not emit marker \(expected)", file: file, line: line)
                throw CocoaError(.executableRuntimeMismatch)
            }
        }

        func releaseDrain() throws {
            try input.fileHandleForWriting.write(contentsOf: Data([74]))
        }

        func expectExit(_ reason: Process.TerminationReason, status: Int32) throws {
            guard terminated.wait(timeout: .now() + .seconds(5)) == .success else {
                throw CocoaError(.executableRuntimeMismatch)
            }
            XCTAssertEqual(process.terminationReason, reason)
            XCTAssertEqual(process.terminationStatus, status)
        }

        func close() {
            try? input.fileHandleForWriting.close()
            if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
            if process.isRunning { _ = terminated.wait(timeout: .now() + .seconds(5)) }
        }
    }
}
