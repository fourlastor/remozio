import CryptoKit
import Darwin
import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

final class AuthorityServiceRunnerTests: XCTestCase {
    func testRetryBoundsAndCloseBeforeStart() throws {
        for (initial, maximum) in [(0, 1000), (99, 1000), (60_001, 100_000), (1000, 999), (1000, 300_001)] {
            XCTAssertThrowsError(try AuthorityServiceRunner(initialRetryMilliseconds: initial,
                maximumRetryMilliseconds: maximum, open: { XCTFail("Invalid runner opened"); return {} }, report: { _ in }))
        }
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100,
            open: { XCTFail("Closed runner opened"); return {} }, report: { _ in })
        XCTAssertEqual(runner.status, .idle)
        try runner.close(); try runner.close()
        XCTAssertEqual(runner.status, .closed)
        XCTAssertThrowsError(try runner.start())
    }

    func testTransientFailuresRetryWithCappedBackoffThenOwnOneService() throws {
        let probe = Probe(), running = expectation(description: "running")
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 200, open: {
            switch probe.open() {
            case 1: throw JournalLeaseError.busy
            case 2: throw ContinuityStoreError.storage(SQLITE_BUSY)
            case 3: throw JournalDatabaseError.storage(SQLITE_IOERR)
            case 4: throw AuditJournalError.storage(SQLITE_FULL)
            default: return { probe.close() }
            }
        }, report: {
            probe.record($0)
            if $0 == .running { running.fulfill() }
        })
        try runner.start()
        XCTAssertThrowsError(try runner.start())
        wait(for: [running], timeout: 3)
        XCTAssertEqual(runner.status, .running)
        XCTAssertEqual(probe.statuses.compactMap { status -> Int? in
            if case .waiting(let delay) = status { return delay }; return nil
        }, [100, 200, 200, 200])
        try runner.close(); try runner.close()
        XCTAssertEqual(probe.counts.opens, 5)
        XCTAssertEqual(probe.counts.closes, 1)
        XCTAssertEqual(runner.status, .closed)
    }

    func testPermanentAndHistoryFailuresDoNotScheduleRetries() throws {
        let failures: [any Error] = [JournalDatabaseError.wrongScope, ContinuityStoreError.incompatibleStore,
            JournalLeaseError.unsafeMetadata, AuthorityStorageStartupError.historyRecoveryRequired,
            AuthorityStorageStartupError.repairRequired]
        for failure in failures {
            let probe = Probe(), failed = expectation(description: "terminal failure")
            let repeated = expectation(description: "no repeated attempt")
            repeated.isInverted = true
            let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, open: {
                if probe.open() > 1 { repeated.fulfill() }
                throw failure
            }, report: { if case .failed = $0 { failed.fulfill() } })
            try runner.start()
            wait(for: [failed], timeout: 2)
            wait(for: [repeated], timeout: 0.2)
            XCTAssertEqual(runner.status, .failed(AuthorityStartupFailure(error: failure)))
            XCTAssertThrowsError(try runner.start())
            try runner.close()
            XCTAssertEqual(probe.counts.opens, 1)
        }
    }

    func testCloseCancelsScheduledRetry() throws {
        let probe = Probe(), waiting = DispatchSemaphore(value: 0)
        let repeated = expectation(description: "attempt after close")
        repeated.isInverted = true
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 200, maximumRetryMilliseconds: 200, open: {
            _ = probe.open()
            if probe.counts.closes > 0 { repeated.fulfill() }
            throw JournalLeaseError.busy
        }, report: {
            if case .waiting = $0 { waiting.signal() }
            if $0 == .closed { probe.close() }
        })
        defer { try? runner.close() }
        try runner.start()
        XCTAssertEqual(waiting.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(waiting.wait(timeout: .now() + 2), .success)
        try runner.close()
        let opensAtClose = probe.counts.opens
        XCTAssertGreaterThanOrEqual(opensAtClose, 2)
        wait(for: [repeated], timeout: 0.4)
        XCTAssertEqual(probe.counts.opens, opensAtClose)
        XCTAssertEqual(runner.status, .closed)
    }

    func testCloseWaitsForFactoryAndDisposesItsResultWithoutReportingRunning() throws {
        let probe = Probe(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let closing = DispatchSemaphore(value: 0), closed = DispatchSemaphore(value: 0)
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, open: {
            _ = probe.open(); entered.signal()
            guard release.wait(timeout: .now() + 5) == .success else { throw JournalLeaseError.busy }
            return { probe.close() }
        }, report: { probe.record($0) })
        try runner.start()
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        DispatchQueue.global().async {
            closing.signal()
            do { try runner.close() } catch { XCTFail("Close failed") }
            closed.signal()
        }
        XCTAssertEqual(closing.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(closed.wait(timeout: .now() + 0.05), .timedOut)
        release.signal()
        XCTAssertEqual(closed.wait(timeout: .now() + 2), .success)
        XCTAssertFalse(probe.statuses.contains(.running))
        XCTAssertEqual(probe.counts.opens, 1)
        XCTAssertEqual(probe.counts.closes, 1)
        XCTAssertEqual(runner.status, .closed)
    }

    func testFailedShutdownCanBeRetriedWithoutOpeningAnotherService() throws {
        let probe = Probe(), running = expectation(description: "running")
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, open: {
            _ = probe.open()
            return { if probe.close() == 1 { throw JournalDatabaseError.transactionActive } }
        }, report: { if $0 == .running { running.fulfill() } })
        try runner.start()
        wait(for: [running], timeout: 2)
        XCTAssertThrowsError(try runner.close())
        XCTAssertThrowsError(try runner.start())
        try runner.close()
        XCTAssertEqual(probe.counts.opens, 1)
        XCTAssertEqual(probe.counts.closes, 2)
    }

    private func requestInputs(_ index: UInt8) throws -> AuthorityRequestStartupConfiguration {
        let service = try AuthorityServiceConfiguration(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            journalDirectory: "/Library/Application Support/Remozio/journal", serviceName: "dev.sebastiano.remozio.macos.authority",
            teamID: "ABCDEFGHIJ", transportIdentifier: "dev.sebastiano.remozio.macos.transport", transportHashes: [Data(repeating: index, count: 20)], transportUID: 502,
            continuityDirectory: "/Library/Application Support/Remozio/continuity")
        return try AuthorityRequestStartupConfiguration(service: service, keyRecordPath: "/keys/authority-\(index).cbor",
            authorityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
    }
    func testRequestRetryReloadsInputsAndTransfersOneCompleteService() throws {
        let first = try requestInputs(1), second = try requestInputs(2), probe = Probe()
        let running = expectation(description: "request service running")
        let runner = try AuthorityServiceRunner(requestConfiguration: { probe.open() == 1 ? first : second }, openRequestService: { inputs, _ in
            probe.recordInput(inputs.canonicalBytes)
            if inputs.canonicalBytes == first.canonicalBytes { throw JournalLeaseError.busy }
            return { probe.close() }
        }, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, report: {
            probe.record($0); if $0 == .running { running.fulfill() }
        })
        try runner.start()
        wait(for: [running], timeout: 3)
        XCTAssertEqual(probe.inputs, [first.canonicalBytes, second.canonicalBytes])
        XCTAssertEqual(probe.counts.opens, 2)
        XCTAssertEqual(probe.statuses, [.starting, .waiting(retryMilliseconds: 100), .starting, .running])
        try runner.close(); try runner.close()
        XCTAssertEqual(probe.counts.closes, 1)
    }
    func testInvalidRequestInputsNeverOpenAService() throws {
        let probe = Probe(), failed = expectation(description: "invalid request inputs")
        let runner = try AuthorityServiceRunner(requestConfiguration: {
            _ = probe.open(); throw AuthorityServiceConfigurationError.invalidConfiguration
        }, openRequestService: { _, _ in XCTFail("Invalid inputs opened a service"); return {} },
            initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, report: {
                probe.record($0); if case .failed = $0 { failed.fulfill() }
            })
        try runner.start(); wait(for: [failed], timeout: 2)
        XCTAssertEqual(runner.status, .failed(.configurationFailure))
        XCTAssertEqual(probe.counts.opens, 1)
        XCTAssertFalse(probe.statuses.contains(.running))
        try runner.close()
    }
    func testProtectedRequestRunnerRejectsNormalUserWithoutInvokingRuntimeCallbacks() throws {
        guard geteuid() != 0 else { throw XCTSkip("Requires normal user") }
        let failed = expectation(description: "protected inputs rejected")
        let runner = try AuthorityServiceRunner(requestConfigurationPath: "/Library/Application Support/Remozio/request-startup.cbor",
            routing: { XCTFail("Non-root runner queried presence"); throw AuthorityRequestSignerError.unavailable },
            reconcileExpired: { _ in XCTFail("Non-root runner performed cleanup") },
            initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, report: {
                if case .failed = $0 { failed.fulfill() }
            })
        try runner.start(); wait(for: [failed], timeout: 2)
        XCTAssertEqual(runner.status, .failed(.configurationFailure))
        try runner.close()
    }

    func testRequestKeyFailureNeverReportsTrustOnlySuccessOrRotatesInputs() throws {
        let inputs = try requestInputs(1), probe = Probe(), failed = expectation(description: "request key unavailable")
        let runner = try AuthorityServiceRunner(requestConfiguration: { _ = probe.open(); return inputs }, openRequestService: { inputs, _ in
            probe.recordInput(inputs.canonicalBytes); throw AuthorityRequestSignerError.unavailable
        }, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, report: {
            probe.record($0); if case .failed = $0 { failed.fulfill() }
        })
        try runner.start(); wait(for: [failed], timeout: 2)
        XCTAssertEqual(runner.status, .failed(.configurationFailure))
        XCTAssertEqual(probe.inputs, [inputs.canonicalBytes]); XCTAssertEqual(probe.counts.opens, 1)
        XCTAssertEqual(probe.statuses, [.starting, .failed(.configurationFailure)])
        try runner.close()
    }

    func testEarlyRequestRetirementNeverReportsRunning() throws {
        let inputs = try requestInputs(1), probe = Probe(), retired = expectation(description: "early retirement")
        let runner = try AuthorityServiceRunner(requestConfiguration: { _ = probe.open(); return inputs },
            openRequestService: { _, retirement in retirement(); return { probe.close() } },
            initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, report: {
                probe.record($0); if $0 == .retired { retired.fulfill() }
            })
        try runner.start(); wait(for: [retired], timeout: 2)
        XCTAssertEqual(runner.status, .retired)
        XCTAssertEqual(probe.statuses, [.starting, .retired])
        XCTAssertThrowsError(try runner.start())
        try runner.close()
        XCTAssertEqual(probe.counts.closes, 1)
    }
    func testAsynchronousRequestRetirementReportsOnceWithoutReopeningService() throws {
        let inputs = try requestInputs(1), probe = Probe()
        let running = expectation(description: "running before retirement"), retired = expectation(description: "retired")
        retired.assertForOverFulfill = true
        let runner = try AuthorityServiceRunner(requestConfiguration: { _ = probe.open(); return inputs }, openRequestService: { _, retirement in
            probe.retainRetirement(retirement); return { probe.close() }
        }, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, report: {
            probe.record($0)
            if $0 == .running { running.fulfill() }
            if $0 == .retired { retired.fulfill() }
        })
        try runner.start(); wait(for: [running], timeout: 2)
        probe.fireRetirement(0); probe.fireRetirement(0)
        wait(for: [retired], timeout: 2)
        XCTAssertEqual(runner.status, .retired)
        XCTAssertEqual(probe.statuses, [.starting, .running, .retired])
        XCTAssertEqual(probe.counts.opens, 1)
        try runner.close(); try runner.close()
        XCTAssertEqual(probe.counts.closes, 1)
    }
    func testRetirementFromFailedAttemptCannotRetireReplacement() throws {
        let inputs = try requestInputs(1), probe = Probe()
        let running = expectation(description: "replacement running"), retired = expectation(description: "no stale retirement")
        retired.isInverted = true
        let runner = try AuthorityServiceRunner(requestConfiguration: { _ = probe.open(); return inputs }, openRequestService: { _, retirement in
            probe.retainRetirement(retirement)
            if probe.counts.opens == 1 { throw JournalLeaseError.busy }
            return { probe.close() }
        }, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, report: {
            probe.record($0); if $0 == .running { running.fulfill() }; if $0 == .retired { retired.fulfill() }
        })
        try runner.start(); wait(for: [running], timeout: 3)
        probe.fireRetirement(0)
        wait(for: [retired], timeout: 0.2)
        XCTAssertEqual(runner.status, .running)
        XCTAssertEqual(probe.counts.opens, 2)
        try runner.close()
        XCTAssertEqual(probe.counts.closes, 1)
    }
    func testRequestRetirementAfterCloseCannotChangeClosedStatus() throws {
        let inputs = try requestInputs(1), probe = Probe()
        let running = expectation(description: "request service running"), retired = expectation(description: "no retirement after close")
        retired.isInverted = true
        let runner = try AuthorityServiceRunner(requestConfiguration: { _ = probe.open(); return inputs }, openRequestService: { _, retirement in
            probe.retainRetirement(retirement); return { probe.close() }
        }, initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, report: {
            if $0 == .running { running.fulfill() }; if $0 == .retired { retired.fulfill() }
        })
        try runner.start(); wait(for: [running], timeout: 2)
        try runner.close(); probe.fireRetirement(0)
        wait(for: [retired], timeout: 0.2)
        XCTAssertEqual(runner.status, .closed)
        XCTAssertEqual(probe.counts.closes, 1)
    }

    private final class Probe: @unchecked Sendable {
        private let lock = NSLock()
        private var opens = 0, closes = 0
        private var events: [AuthorityServiceRunner.Status] = []
        private var loadedInputs: [Data] = []
        private var retirements: [AuthorityServiceRunner.Retirement] = []
        func open() -> Int { lock.withLock { opens += 1; return opens } }
        @discardableResult func close() -> Int { lock.withLock { closes += 1; return closes } }
        func retainRetirement(_ callback: @escaping AuthorityServiceRunner.Retirement) { lock.withLock { retirements.append(callback) } }
        func fireRetirement(_ index: Int) {
            let callback: AuthorityServiceRunner.Retirement = lock.withLock { retirements[index] }
            callback()
        }
        func recordInput(_ bytes: Data) { lock.withLock { loadedInputs.append(bytes) } }
        var inputs: [Data] { lock.withLock { loadedInputs } }
        func record(_ status: AuthorityServiceRunner.Status) { lock.withLock { events.append(status) } }
        var counts: (opens: Int, closes: Int) { lock.withLock { (opens, closes) } }
        var statuses: [AuthorityServiceRunner.Status] { lock.withLock { events } }
    }
}
