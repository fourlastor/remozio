import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityWakeStartupSettingsTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private typealias Fixture = AuthorityWakeSettingsTests.Fixture
    private typealias Driver = AuthorityWakeSettingsTests.Driver
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw Denied() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testPendingFailureStartsForegroundOnlyAndExactRetryWaitsForFreshQuiescence() async throws {
        let f = try Fixture(install: false), driver = Driver(), service = try f.service([driver]), change = try f.change()
        let before = try f.state()
        do { try await service.restorePhonePushStartup(f.options, commitDigest: f.old, pendingChange: change, verifyCurrent: { throw Denied() }); XCTFail() }
        catch { XCTAssertTrue(error is Denied) }
        try await service.start()
        XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        XCTAssertEqual(f.attempts.withLock { $0 }, 0); XCTAssertEqual(try f.state(), before)
        let initial = try await service.gatewaySettingsObservation(change); XCTAssertEqual(initial, .quiescing)
        do { try await service.installPhonePush(f.options, commitDigest: f.old, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        do { try await service.quiescePhonePushSettings(change, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        try await service.restorePhonePushStartup(f.options, commitDigest: f.old, pendingChange: change, verifyCurrent: {})
        XCTAssertNil(f.capability.publication); XCTAssertEqual(f.attempts.withLock { $0 }, 0)
        do { try await service.acceptPhonePushSettings(change, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        try await service.quiescePhonePushSettings(change, verifyCurrent: {})
        let paused = try await service.gatewaySettingsObservation(change); XCTAssertEqual(paused, .suspended)
        try await service.acceptPhonePushSettings(change, verifyCurrent: {})
        try await waitUntil { await service.wakeStatus == .running }
        try await service.installPhonePush(f.options, commitDigest: f.selected, verifyCurrent: {})
        XCTAssertEqual(f.capability.installedCommitDigest, f.selected); XCTAssertEqual(f.attempts.withLock { $0 }, 1)
        XCTAssertEqual(try f.state(), before); XCTAssertEqual(before.deadlineMilliseconds, 5000)
        XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        try await service.close(); XCTAssertEqual(f.closes.withLock { $0 }, 1)
    }
    func testActiveRestoreFailureKeepsPublicationPausedAndRejectsScopeChangingRetries() async throws {
        let f = try Fixture(install: false), service = try f.service([Driver()]), change = try f.change()
        do { try await service.restorePhonePushStartup(f.options, commitDigest: f.selected, pendingChange: nil, verifyCurrent: { throw Denied() }); XCTFail() } catch {}
        try await service.start(); XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.attempts.withLock { $0 }, 0)
        do { try await service.restorePhonePushStartup(f.options, commitDigest: f.old, pendingChange: change, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        let other = try Fixture(install: false)
        do { try await service.restorePhonePushStartup(other.options, commitDigest: f.selected, pendingChange: nil, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        do { try await service.installPhonePush(f.options, commitDigest: f.selected, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        try await service.restorePhonePushStartup(f.options, commitDigest: f.selected, pendingChange: nil, verifyCurrent: {})
        try await waitUntil { await service.wakeStatus == .running }
        XCTAssertNil(f.capability.publication)
        do { try await service.installPhonePush(f.options, commitDigest: f.old, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        try await service.installPhonePush(f.options, commitDigest: f.selected, verifyCurrent: {})
        XCTAssertEqual(f.capability.installedCommitDigest, f.selected); XCTAssertEqual(f.attempts.withLock { $0 }, 1)
        try await service.close()
    }
    func testSuccessfulPendingRestoreCannotStartTheFirstPublisherBeforeExplicitAcceptance() async throws {
        let f = try Fixture(install: false), service = try f.service([Driver()]), change = try f.change()
        try await service.restorePhonePushStartup(f.options, commitDigest: f.old, pendingChange: change, verifyCurrent: {})
        try await service.start()
        XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.attempts.withLock { $0 }, 0)
        do { try await service.quiescePhonePushSettings(change, verifyCurrent: { throw Denied() }); XCTFail() } catch {}
        let pending = try await service.gatewaySettingsObservation(change); XCTAssertEqual(pending, .quiescing)
        do { try await service.acceptPhonePushSettings(change, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        XCTAssertEqual(f.attempts.withLock { $0 }, 0); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        try await service.quiescePhonePushSettings(change, verifyCurrent: {})
        try await service.acceptPhonePushSettings(change, verifyCurrent: {})
        try await waitUntil { await service.wakeStatus == .running }
        XCTAssertEqual(f.attempts.withLock { $0 }, 1); try await service.close()
    }
    func testOrdinaryRunningServiceRejectsLateStartupWithoutChangingItsPublisher() async throws {
        let f = try Fixture(), service = try f.service([Driver()]), change = try f.change()
        try await service.start(); try await waitUntil { await service.wakeStatus == .running }
        do { try await service.restorePhonePushStartup(f.options, commitDigest: f.old, pendingChange: change, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        let status = await service.wakeStatus; XCTAssertEqual(status, .running)
        XCTAssertEqual(f.capability.installedCommitDigest, f.old); XCTAssertEqual(f.attempts.withLock { $0 }, 1)
        try await service.close()
    }
    func testCloseAfterFailedStartupSettlesForegroundWithoutStartingOptionalWork() async throws {
        let f = try Fixture(install: false), service = try f.service([Driver()]), change = try f.change()
        do { try await service.restorePhonePushStartup(f.options, commitDigest: f.old, pendingChange: change, verifyCurrent: { throw Denied() }); XCTFail() } catch {}
        try await service.start(); try await service.close()
        XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.closes.withLock { $0 }, 1); XCTAssertEqual(f.attempts.withLock { $0 }, 0)
        do { try await service.restorePhonePushStartup(f.options, commitDigest: f.old, pendingChange: change, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        let status = await service.wakeStatus; XCTAssertEqual(status, .closed); XCTAssertNil(f.capability.publication)
    }
}
