import CryptoKit
import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class RelayConnectorProcessTests: XCTestCase, @unchecked Sendable {
    final class Fixture: @unchecked Sendable {
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
        try f.token.validate()
        let deadline = ContinuousClock.now.advanced(by: .seconds(1))
        while true {
            do { try f.assertUpdateAvailable(); break }
            catch ReleaseActivityError.busy {
                guard ContinuousClock.now < deadline else { throw ReleaseActivityError.busy }
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        f.token.close()
        XCTAssertThrowsError(try f.start("normal")) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        try f.assertUpdateAvailable()
    }
    func testPinnedVendorReportsDisconnectedThroughTheProductionProcessAndProbe() async throws {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let environment = ProcessInfo.processInfo.environment
        let override = environment["REMOZIO_CONNECTOR_FIXTURE_PATH"]
        let vendor = override ?? repository.appendingPathComponent(
            ".build/macos-app/DerivedData/Build/Products/Debug/Remozio.app/Contents/Helpers/RemozioCloudflared").path
        guard FileManager.default.isExecutableFile(atPath: vendor) else {
            throw XCTSkip("Build the native app fixture or provide the verified disposable vendor path.")
        }
        if override != nil {
            let expected = try XCTUnwrap(environment["REMOZIO_CONNECTOR_FIXTURE_SHA256"])
            let attributes = try FileManager.default.attributesOfItem(atPath: vendor)
            XCTAssertLessThan(try XCTUnwrap(attributes[.size] as? NSNumber).uint64Value, 100_000_000)
            let actual = SHA256.hash(data: try Data(contentsOf: URL(fileURLWithPath: vendor))).map { String(format: "%02x", $0) }.joined()
            guard actual == expected else { XCTFail("Disposable vendor hash changed"); throw RelayConnectorProcess.Failure.invalidConfiguration }
        }
        let f = try Fixture(), observed = expectation(description: "vendor metrics or completion")
        let observation = Mutex<RelayConnectorDiscovery?>(nil)
        let options = try RelayConnectorProcess.Options(startupMilliseconds: 60_000)
        let arguments = ["-p", "(version 1)(allow default)(deny network-outbound)", vendor,
            "--no-autoupdate", "--config", "/dev/fd/5", "--output", "json", "tunnel", "--edge", "127.0.0.1:7844",
            "--protocol", "http2", "--grace-period", "1s", "--metrics", "127.0.0.1:0", "run", "--token-file", "/dev/fd/4"]
        let process = try RelayConnectorProcess.startForFixture(executable: "/usr/bin/sandbox-exec", arguments: arguments,
            token: f.token, activity: f.service.acquireShared(), options: options) { event in
                switch event {
                case .discovered(let value):
                    observation.withLock { $0 = value }; observed.fulfill()
                case .completed(let value):
                    if value.discovery == nil { observed.fulfill() }
                }
            }
        await fulfillment(of: [observed], timeout: 65)
        guard let value = observation.withLock({ $0 }) else {
            let completion = await process.stopAndWait()
            try f.assertUpdateAvailable()
            XCTFail("The vendor exited before metrics discovery: \(completion.termination), \(String(describing: completion.stopCause)).")
            return
        }
        let result: Result<RelayConnectorReadiness.State, any Error>
        do {
            result = .success(try await RelayConnectorReadiness().probe(value))
        } catch { result = .failure(error) }
        let completion = await process.stopAndWait()
        XCTAssertTrue(completion.termination.settled); try f.assertUpdateAvailable()
        XCTAssertEqual(try result.get(), .disconnected)
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
