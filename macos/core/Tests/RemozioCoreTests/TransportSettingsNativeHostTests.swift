import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class TransportSettingsNativeHostTests: XCTestCase, @unchecked Sendable {
    private final class Counter: Sendable { let value = Mutex(0) }
    private final class Reports: Sendable { let value = Mutex([DirectHostState]()) }
    private struct Failed: Error {}
    private final class Resources: Sendable {
        struct State {
            var startedDirect = 0, startedPairing = 0, retired = 0, relayUpdates = 0
            var closes = [Int: Int](), gates = [Int: CheckedContinuation<Void, Never>]()
            var startGate: CheckedContinuation<Void, Never>?
            var direct = DirectHostState.noEligiblePhones
        }
        let value = Mutex(State())
        let holdStart: Bool, holdClose: Bool
        init(holdStart: Bool = false, holdClose: Bool = false) { self.holdStart = holdStart; self.holdClose = holdClose }
        func operations() -> TransportSettingsForegroundRuntime.Operations {
            .init(startDirect: { [self] in
                value.withLock { $0.startedDirect += 1 }
                if holdStart { await withCheckedContinuation { c in value.withLock { $0.startGate = c } } }
            }, startPairing: { [self] in value.withLock { $0.startedPairing += 1 } },
            directState: { [self] in value.withLock { $0.direct } }, updateRelay: { [self] _ in value.withLock { $0.relayUpdates += 1 } },
            retirePairing: { [self] in value.withLock { $0.retired += 1 } }, closePairing: { [self] in await close(0) },
            closeRelay: { [self] in await close(1) }, closeDirect: { [self] in await close(2) })
        }
        func close(_ id: Int) async {
            value.withLock { $0.closes[id, default: 0] += 1 }
            if holdClose { await withCheckedContinuation { c in value.withLock { $0.gates[id] = c } } }
        }
        func finishStart() { value.withLock { s in let c = s.startGate; s.startGate = nil; return c }?.resume() }
        func finishClose(_ id: Int) { value.withLock { $0.gates.removeValue(forKey: id) }?.resume() }
    }
    private func until(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() { guard ContinuousClock.now < deadline else { throw Failed() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testForegroundStartsDirectBeforePairingAndPollsMeasuredStateWithoutWake() async throws {
        let r = Resources(), reported = Reports()
        let runtime = TransportSettingsForegroundRuntime(operations: r.operations(), verifyCurrent: {}, report: { state in reported.value.withLock { $0.append(state) } })
        try await runtime.start(); try await runtime.poll(); try await runtime.poll()
        XCTAssertEqual(r.value.withLock { $0.startedDirect }, 1); XCTAssertEqual(r.value.withLock { $0.startedPairing }, 1)
        XCTAssertEqual(r.value.withLock { $0.relayUpdates }, 2); XCTAssertEqual(reported.value.withLock { $0 }, [.noEligiblePhones])
        try await runtime.closeAndWait()
    }
    func testRetireDuringHandshakeCannotStartPairingAfterItReturns() async throws {
        let r = Resources(holdStart: true), runtime = TransportSettingsForegroundRuntime(operations: r.operations(), verifyCurrent: {})
        let start = Task { try await runtime.start() }; defer { r.finishStart() }; try await until { r.value.withLock { $0.startGate != nil } }
        runtime.retire(); r.finishStart()
        do { try await start.value; XCTFail() } catch { XCTAssertTrue(error is DirectHostError) }
        XCTAssertEqual(r.value.withLock { $0.startedPairing }, 0); try await runtime.closeAndWait()
    }
    func testAllThreeNativeCleanupOperationsBeginAndConcurrentCancelledClosersJoinThemOnce() async throws {
        let r = Resources(holdClose: true), runtime = TransportSettingsForegroundRuntime(operations: r.operations(), verifyCurrent: {}), done = Counter()
        try await runtime.start()
        let first = Task { try await runtime.closeAndWait(); done.value.withLock { $0 += 1 } }, second = Task { try await runtime.closeAndWait(); done.value.withLock { $0 += 1 } }; first.cancel()
        defer { for id in 0...2 { r.finishClose(id) } }; try await until { r.value.withLock { $0.gates.count == 3 } }
        XCTAssertEqual(done.value.withLock { $0 }, 0)
        r.finishClose(0); r.finishClose(1); try await Task.sleep(for: .milliseconds(10)); XCTAssertEqual(done.value.withLock { $0 }, 0)
        r.finishClose(2); try await first.value; try await second.value
        XCTAssertEqual(r.value.withLock { $0.closes }, [0: 1, 1: 1, 2: 1]); XCTAssertEqual(done.value.withLock { $0 }, 2)
    }
    func testScopeFailureBeforeStartupCreatesNoForegroundActivity() async throws {
        let r = Resources(), runtime = TransportSettingsForegroundRuntime(operations: r.operations(), verifyCurrent: { throw Failed() })
        do { try await runtime.start(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertEqual(r.value.withLock { $0.startedDirect }, 0); try await runtime.closeAndWait()
    }
    func testAuthorityLossUpdatesRelayThenFailsForFreshForegroundRecovery() async throws {
        let r = Resources(), runtime = TransportSettingsForegroundRuntime(operations: r.operations(), verifyCurrent: {})
        try await runtime.start(); r.value.withLock { $0.direct = .authorityUnavailable }
        do { try await runtime.poll(); XCTFail() } catch { XCTAssertTrue(error is DirectHostError) }
        XCTAssertEqual(r.value.withLock { $0.relayUpdates }, 1); try await runtime.closeAndWait()
    }
    func testDroppedForegroundRetainsAllCleanupUntilItSettles() async throws {
        let r = Resources(holdClose: true)
        var runtime: TransportSettingsForegroundRuntime? = .init(operations: r.operations(), verifyCurrent: {})
        try await runtime?.start(); runtime = nil; defer { for id in 0...2 { r.finishClose(id) } }
        try await until { r.value.withLock { $0.gates.count == 3 } }; for id in 0...2 { r.finishClose(id) }
    }
    func testNativeForegroundRejectsOrdinaryAccountBeforeScopeOrPrivateIdentityAccess() throws {
        let f = try TransportConsumerMetadataFixture()
        XCTAssertThrowsError(try TransportSettingsForegroundRuntime(bootstrap: f.bootstrap,
            verifyCurrent: { XCTFail("Native account admission must run first") }, report: { _ in }, reportRelay: { _ in })) {
                XCTAssertEqual($0 as? ApprovalTransportStartupError, .wrongAccount)
            }
    }
    func testNativeFacadeRejectsOrdinaryOwnedBootstrapWithoutChangingIt() throws {
        let f = try TransportConsumerMetadataFixture(), files = try ServiceReleaseActivityFixture()
        let path = files.root.appendingPathComponent("transport-host.cbor"), bytes = f.bootstrap.base.canonicalBytes
        try bytes.write(to: path); try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
        XCTAssertThrowsError(try GatewaySettingsTransportHost.open(path: path.path)); XCTAssertEqual(try Data(contentsOf: path), bytes)
    }
}
