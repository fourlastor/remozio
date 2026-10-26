import CryptoKit
import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class RelayConnectorProcessTests: XCTestCase, @unchecked Sendable {
    private final class Fixture {
        let files: ServiceReleaseActivityFixture
        let service: ServiceReleaseActivityBarrier
        let updater: ServiceReleaseActivityBarrier
        let token: RelayRunCredentialFile
        let program: String
        init() throws {
            let files = try ServiceReleaseActivityFixture()
            let service = try files.open(role: .transport), updater = try files.open(role: .transport, update: true)
            let tunnel = CloudflareTunnelObservation(accountID: String(repeating: "a", count: 32),
                tunnelID: "12345678-1234-4234-9234-123456789012", name: "disposable")
            let bytes = try JSONSerialization.data(withJSONObject: ["a": tunnel.accountID, "t": tunnel.tunnelID,
                "s": Data(repeating: 0x71, count: 32).base64EncodedString()], options: [.sortedKeys, .withoutEscapingSlashes]).base64EncodedData()
            let path = files.directory.appendingPathComponent("transport-tunnel.token")
            try bytes.write(to: path); XCTAssertEqual(chmod(path.path, 0o600), 0)
            let token = try RelayRunCredentialFile(directory: ReleaseDestinationLease(anchor: files.root.path,
                relativeDirectory: "Services", owner: getuid()), owner: getuid(), group: getgid(), tunnel: tunnel,
                digest: Data(SHA256.hash(data: bytes)))
            let source = try XCTUnwrap(Bundle.module.url(forResource: "worker", withExtension: "c", subdirectory: "Fixtures/relay-connector"))
            let program = files.root.appendingPathComponent("worker").path
            let compile = try BoundedNativeCommand.run(executable: "/usr/bin/xcrun", arguments: ["clang", "-target",
                "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", source.path, "-o", program], timeoutMilliseconds: 30_000)
            guard compile.exitCode == 0 else { XCTFail(String(decoding: compile.errorOutput, as: UTF8.self)); throw RelayConnectorProcess.Failure.invalidConfiguration }
            self.files = files; self.service = service; self.updater = updater; self.token = token; self.program = program
        }
        deinit { token.close() }
        func start(_ mode: String, unrelated: Int32 = -1, options: RelayConnectorProcess.Options = .standard,
                   event: @escaping @Sendable (RelayConnectorProcess.Event) -> Void = { _ in }) throws -> RelayConnectorProcess {
            try RelayConnectorProcess.startForFixture(executable: program,
                arguments: [mode, String(getpgrp()), String(unrelated)], token: token,
                activity: service.acquireShared(), options: options, event: event)
        }
        func assertUpdateAvailable() throws { let update = try updater.acquireExclusive(); update.close() }
    }
    func testGracefulStopJoinsTheChildAndDropsUnrelatedDescriptors() async throws {
        let f = try Fixture(), discovered = expectation(description: "metrics")
        let original = Darwin.open("/dev/null", O_RDONLY)
        XCTAssertGreaterThanOrEqual(original, 0)
        let unrelated = fcntl(original, F_DUPFD, 128); _ = Darwin.close(original)
        XCTAssertGreaterThanOrEqual(unrelated, 0); defer { _ = Darwin.close(unrelated) }
        let process = try f.start("normal", unrelated: unrelated) { if case .discovered = $0 { discovered.fulfill() } }
        await fulfillment(of: [discovered], timeout: 5)
        XCTAssertThrowsError(try f.updater.acquireExclusive())
        let result = await process.stopAndWait()
        XCTAssertEqual(result.termination, .exited(0)); XCTAssertEqual(result.stopCause, .requested)
        XCTAssertEqual(result.discovery?.port, 32123); try f.assertUpdateAvailable()
        let repeated = await process.stopAndWait(); XCTAssertEqual(result, repeated)
    }
    func testIgnoredTerminationEscalatesOnlyForTheOwnedChild() async throws {
        let f = try Fixture(), discovered = expectation(description: "metrics")
        let process = try f.start("ignore", options: .init(gracefulStopMilliseconds: 10)) {
            if case .discovered = $0 { discovered.fulfill() }
        }
        await fulfillment(of: [discovered], timeout: 5)
        let result = await process.stopAndWait()
        XCTAssertEqual(result.termination, .signaled(SIGKILL)); try f.assertUpdateAvailable()
    }
    func testUnexpectedExitIsReapedWithoutAReadinessClaim() async throws {
        let f = try Fixture(), process = try f.start("exit")
        let result = await process.waitForExit()
        XCTAssertEqual(result.termination, .exited(42)); XCTAssertNil(result.discovery); XCTAssertNil(result.stopCause)
        try f.assertUpdateAvailable()
    }
    func testMissingOrWrongDiagnosticsCauseABoundedStop() async throws {
        for mode in ["silent", "invalid"] {
            let f = try Fixture(), process = try f.start(mode, options: .init(startupMilliseconds: 100))
            let result = await process.waitForExit()
            XCTAssertTrue(result.termination.settled); XCTAssertEqual(result.stopCause, .metricsTimeout)
            XCTAssertNil(result.discovery); try f.assertUpdateAvailable()
        }
    }
    func testOutputFloodAndConcurrentStopsRemainBounded() async throws {
        let f = try Fixture(), discovered = expectation(description: "metrics"), discoveries = Mutex(0)
        let process = try f.start("flood") { event in
            if case .discovered = event { discoveries.withLock { $0 += 1 }; discovered.fulfill() }
        }
        await fulfillment(of: [discovered], timeout: 5)
        async let one = process.stopAndWait()
        async let two = process.stopAndWait()
        let results = await (one, two)
        XCTAssertEqual(results.0, results.1); XCTAssertEqual(results.0.termination, .exited(0))
        XCTAssertEqual(discoveries.withLock { $0 }, 1); try f.assertUpdateAvailable()
    }
    func testFailedSpawnReleasesActivityAndLeavesTheTokenReusable() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try RelayConnectorProcess.startForFixture(executable: f.program + ".missing", arguments: [],
            token: f.token, activity: f.service.acquireShared())) {
            XCTAssertEqual($0 as? RelayConnectorProcess.Failure, .system(ENOENT))
        }
        try f.token.validate(); try f.assertUpdateAvailable()
        f.token.close()
        XCTAssertThrowsError(try f.start("normal")) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        try f.assertUpdateAvailable()
    }
    func testDroppingTheOwnerRequestsShutdownAndRetainsActivityUntilCompletion() async throws {
        let f = try Fixture(), discovered = expectation(description: "metrics"), exited = expectation(description: "exit")
        let outcome = Mutex<RelayConnectorProcess.Completion?>(nil)
        var process: RelayConnectorProcess? = try f.start("normal") { event in
            switch event {
            case .discovered: discovered.fulfill()
            case .completed(let value): outcome.withLock { $0 = value }; exited.fulfill()
            }
        }
        XCTAssertNotNil(process)
        await fulfillment(of: [discovered], timeout: 5)
        process = nil
        await fulfillment(of: [exited], timeout: 5)
        XCTAssertEqual(outcome.withLock { $0?.termination }, .exited(0)); try f.assertUpdateAvailable()
    }
}
