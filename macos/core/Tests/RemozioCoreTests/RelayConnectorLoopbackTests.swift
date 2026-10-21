import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Exercises a fixture process and a real loopback readiness client. It does not contact a provider.
final class RelayConnectorLoopbackTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw Failed() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testOwnedProcessSupervisorAndHTTPReadinessSettleTogether() async throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Requires an ordinary-user process.") }
        for mode in ["http-recover", "http-wrong-identity", "http-stall"] {
            let fixture = try RelayConnectorProcessTests.Fixture()
            try fixture.assertUpdateAvailable()
            let accepted = fixture.files.root.appendingPathComponent("accepted-readiness-request")
            let processMode = mode == "http-stall" ? mode + "@" + accepted.path : mode
            let starts = Mutex(0), probes = Mutex(0), allowed = Mutex(true)
            let failures = Mutex<[RelayConnectorReadiness.Failure]>([])
            let readiness = try RelayConnectorReadiness(timeoutSeconds: 2)
            let owner = RelayConnectorSupervisor(options: try .init(retryMilliseconds: 100, probeMilliseconds: 100), operations: .init(start: { event in
                starts.withLock { $0 += 1 }; return try fixture.start(processMode, event: event)
            }, probe: { discovery in
                probes.withLock { $0 += 1 }
                do { return try await readiness.probe(discovery) }
                catch { if let failure = error as? RelayConnectorReadiness.Failure { failures.withLock { $0.append(failure) } }; throw error }
            }, validateCurrent: {
                guard allowed.withLock({ $0 }) else { throw RuntimePreparationError.changedScope }
            }))
            do {
                try await owner.start()
                switch mode {
                case "http-recover":
                    try await waitUntil { await owner.status == .disconnected }
                    XCTAssertThrowsError(try fixture.updater.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
                    try await waitUntil { await owner.status == .connected }
                    XCTAssertGreaterThanOrEqual(probes.withLock { $0 }, 3)
                    XCTAssertEqual(starts.withLock { $0 }, 1)
                    XCTAssertThrowsError(try fixture.updater.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
                case "http-wrong-identity":
                    try await waitUntil { await owner.status == .unavailable && probes.withLock { $0 >= 2 } }
                    XCTAssertEqual(starts.withLock { $0 }, 1)
                    XCTAssertTrue(failures.withLock { $0.contains(.invalidResponse) })
                    allowed.withLock { $0 = false }
                    try await waitUntil { await owner.status == .refused }
                    try fixture.assertUpdateAvailable()
                default:
                    try await waitUntil { (try? Data(contentsOf: accepted)) == Data([1]) }
                    let status = await owner.status
                    XCTAssertEqual(status, .checking)
                    XCTAssertThrowsError(try fixture.updater.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
                }
                async let one = owner.close()
                async let two = owner.close()
                let closed = await (one, two)
                XCTAssertTrue(closed.0); XCTAssertTrue(closed.1)
                let status = await owner.status; XCTAssertEqual(status, .closed)
                try fixture.assertUpdateAvailable()
                XCTAssertEqual(starts.withLock { $0 }, 1)
            } catch { _ = await owner.close(); throw error }
        }
        if let output = ProcessInfo.processInfo.environment["REMOZIO_RELAY_LOOPBACK_EVIDENCE"] {
            let report: [String: Any] = ["schemaVersion": 1, "experiment": "relay-connector-owned-loopback", "status": "passed",
                "osVersion": ProcessInfo.processInfo.operatingSystemVersionString, "hostArchitecture": "arm64",
                "productionSpawnPrimitiveUsed": true, "productionSupervisorUsed": true, "productionHTTPReadinessUsed": true,
                "childBoundOnlyLoopback": true, "disconnectedThenConnectedWithoutReplacement": true,
                "mismatchedConnectorIdentityRefused": true, "scopeInvalidationStopsWithoutReplacement": true,
                "pendingHTTPRequestConfirmedByChild": true, "concurrentCloseJoinedProcessAndProbe": true,
                "updateExcludedBeforeShutdown": true, "updateAllowedAfterSettlement": true,
                "installedNativeFactoryTested": false, "dedicatedAccountAdmissionTested": false, "developerIDPolicyTested": false,
                "realProviderConnectivityQualified": false, "providerAPICalled": false, "servicesInstalled": false,
                "realCredentialUsed": false, "physicalPhoneTested": false]
            try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys, .prettyPrinted]).write(to: URL(fileURLWithPath: output))
        }
    }
}
