import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayJournalSetupChannelTests: XCTestCase, @unchecked Sendable {
    private static let id = Data(repeating: 1, count: 16)
    private static let digest = Data(repeating: 2, count: 32)
    private static let nonce = Data(repeating: 3, count: 32)
    private final class Driver: GatewayJournalSetupDriver {
        struct Value {
            var calls: [GatewayJournalSetupCall] = []
            var version: UInt64 = 1
            var started = 0
            var closeDuringStart = false
            var reportIssued = false
            var lost: (@Sendable () -> Void)?
            var closed = 0
            var holdHello = false
            var holdPrepare = false
            var failed = false
            var response: Data?
            var onHello: (@Sendable () -> Void)?
            var onPrepare: (@Sendable () -> Void)?
            var reply: (@Sendable (GatewayJournalSetupReply) -> Void)?
        }
        let value = Mutex(Value())
        func start(closed: @escaping @Sendable () -> Void) {
            let lose = value.withLock { $0.started += 1; $0.lost = closed; return $0.closeDuringStart }
            if lose { closed() }
        }
        func disconnect() { value.withLock { $0.lost }?() }
        func invoke(_ call: GatewayJournalSetupCall, reply: @escaping @Sendable (GatewayJournalSetupReply) -> Void) {
            let result: GatewayJournalSetupReply? = value.withLock { state in
                state.calls.append(call)
                if state.failed { return .failed }
                switch call {
                case .hello:
                    state.onHello?()
                    if state.holdHello { state.reply = reply; return nil }
                    return .version(state.version)
                case .prepare(_, let challenge):
                    state.onPrepare?()
                    if state.holdPrepare { state.reply = reply; return nil }
                    state.reportIssued = true
                    if let response = state.response { return .report(response) }
                    let report = try! GatewayJournalSetupReport(intentID: GatewayJournalSetupChannelTests.id, scopeDigest: GatewayJournalSetupChannelTests.digest, created: true)
                    return .report(try! GatewayJournalSetupResponse.encode(report: report, challenge: challenge))
                }
            }
            if let result { reply(result) }
        }
        func close() { value.withLock { $0.closed += 1 } }
    }
    private func channel(_ driver: Driver, timeout: UInt64 = 1000,
                         verifyAccount: @escaping @Sendable () throws -> Void = {},
                         verifyPending: @escaping @Sendable () throws -> Void = {},
                         challenge: @escaping @Sendable () throws -> Data = { GatewayJournalSetupChannelTests.nonce }) throws -> GatewayJournalSetupChannel {
        try GatewayJournalSetupChannel(driver: driver, intentID: Self.id, scopeDigest: Self.digest, timeoutMilliseconds: timeout,
            verifyAccount: verifyAccount, verifyPending: verifyPending, challenge: challenge)
    }
    func testHandshakePrecedesTheBoundRequestAndSuccessfulExchangeClosesTheChannel() async throws {
        let driver = Driver(), channel = try channel(driver)
        let report = try await channel.prepare(); XCTAssertTrue(report.created)
        let calls = driver.value.withLock { $0.calls }; XCTAssertEqual(calls.count, 2)
        guard case .hello = calls[0], case .prepare(let digest, let nonce) = calls[1] else { return XCTFail() }
        XCTAssertEqual(digest, Self.digest); XCTAssertEqual(nonce, Self.nonce)
        do { _ = try await channel.prepare(); XCTFail() } catch { XCTAssertEqual(error as? GatewayJournalSetupChannelError, .closed) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
    }
    func testUnknownVersionNeverSendsInitialization() async throws {
        let driver = Driver(); driver.value.withLock { $0.version = 2 }
        let channel = try channel(driver)
        do { _ = try await channel.prepare(); XCTFail() } catch { XCTAssertEqual(error as? GatewayJournalSetupChannelError, .unsupportedVersion) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 1)
    }
    func testWrongAccountAndCompletedPendingStateNeverActivateTheConnection() async throws {
        for account in [false, true] {
            let driver = Driver(), channel = try channel(driver,
                verifyAccount: { if account { throw JournalLeaseError.rootRequired } },
                verifyPending: { if !account { throw GatewayPreparationError.changedScope } })
            do { _ = try await channel.prepare(); XCTFail() } catch {}
            XCTAssertEqual(driver.value.withLock { $0.started }, 0)
            XCTAssertEqual(driver.value.withLock { $0.calls.count }, 0)
        }
    }
    func testChangedPendingStateAfterHandshakeOrBeforeCommitRejectsTheExchange() async throws {
        for afterPrepare in [false, true] {
            let allowed = Mutex(true), driver = Driver()
            driver.value.withLock { value in
                if afterPrepare { value.onPrepare = { allowed.withLock { $0 = false } } }
                else { value.onHello = { allowed.withLock { $0 = false } } }
            }
            let channel = try channel(driver, verifyPending: {
                guard allowed.withLock({ $0 }) else { throw GatewayPreparationError.changedScope }
            })
            do { _ = try await channel.prepare(); XCTFail() } catch { XCTAssertEqual(error as? GatewayPreparationError, .changedScope) }
            XCTAssertEqual(driver.value.withLock { $0.calls.count }, afterPrepare ? 2 : 1)
        }
    }
    func testReplayMalformedReplyAndInvalidChallengeRetireTheChannel() async throws {
        for mode in 0...3 {
            let driver = Driver()
            if mode == 0 {
                let report = try GatewayJournalSetupReport(intentID: Self.id, scopeDigest: Self.digest, created: true)
                driver.value.withLock { $0.response = try! GatewayJournalSetupResponse.encode(report: report, challenge: Data(repeating: 4, count: 32)) }
            } else if mode == 1 { driver.value.withLock { $0.response = Data(repeating: 0, count: 1025) } }
            else if mode == 2 { driver.value.withLock { $0.failed = true } }
            let channel = try channel(driver, challenge: { mode == 3 ? Data() : Self.nonce })
            do { _ = try await channel.prepare(); XCTFail() } catch {}
            let count = driver.value.withLock { $0.calls.count }
            do { _ = try await channel.prepare(); XCTFail() } catch { XCTAssertEqual(error as? GatewayJournalSetupChannelError, .closed) }
            XCTAssertEqual(driver.value.withLock { $0.calls.count }, count)
        }
    }
    func testTimeoutAndLateHelloCannotStartInitialization() async throws {
        let driver = Driver(); driver.value.withLock { $0.holdHello = true }
        let channel = try channel(driver, timeout: 20)
        do { _ = try await channel.prepare(); XCTFail() } catch { XCTAssertEqual(error as? GatewayJournalSetupChannelError, .timedOut) }
        driver.value.withLock { $0.reply }?(.version(1))
        do { _ = try await channel.prepare(); XCTFail() } catch {}
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 1)
    }
    func testCancellationWhilePreparingClosesAndIgnoresTheLateReply() async throws {
        let driver = Driver(), started = expectation(description: "preparing")
        driver.value.withLock { $0.holdPrepare = true; $0.onPrepare = { started.fulfill() } }
        let channel = try channel(driver), task = Task { try await channel.prepare() }
        await fulfillment(of: [started], timeout: 2); task.cancel()
        do { _ = try await task.value; XCTFail() } catch {}
        driver.value.withLock { $0.reply }?(.report(Data()))
        do { _ = try await channel.prepare(); XCTFail() } catch {}
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
    }
    func testConnectionLossDuringStartDoesNotSendEvenTheHello() async throws {
        let driver = Driver(); driver.value.withLock { $0.closeDuringStart = true }
        let channel = try channel(driver)
        do { _ = try await channel.prepare(); XCTFail() } catch { XCTAssertEqual(error as? GatewayJournalSetupChannelError, .closed) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 0)
        XCTAssertGreaterThan(driver.value.withLock { $0.closed }, 0)
    }
    func testConnectionLossAfterHelloCannotSendPreparationBeforeTheActorReceivesClose() async throws {
        let driver = Driver()
        let channel = try channel(driver, challenge: { driver.disconnect(); return Self.nonce })
        do { _ = try await channel.prepare(); XCTFail() } catch { XCTAssertEqual(error as? GatewayJournalSetupChannelError, .closed) }
        let calls = driver.value.withLock { $0.calls }
        XCTAssertEqual(calls.count, 1)
        guard case .hello = try XCTUnwrap(calls.first) else { return XCTFail() }
    }
    func testConnectionLossDuringFinalScopeCheckCannotAcceptTheReport() async throws {
        let driver = Driver()
        let channel = try channel(driver, verifyPending: {
            if driver.value.withLock({ $0.reportIssued }) { driver.disconnect() }
        })
        do { _ = try await channel.prepare(); XCTFail("A lost connection must not establish completion") }
        catch { XCTAssertEqual(error as? GatewayJournalSetupChannelError, .closed) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
    }
    func testSetupAddressesSeparateAccountsAndIntentsFromPermanentGatewayServices() throws {
        let first = try GatewayJournalSetupAddress.serviceName(accountID: Self.id, intentID: Self.id)
        XCTAssertNotEqual(first, try GatewayJournalSetupAddress.serviceName(accountID: Data(repeating: 4, count: 16), intentID: Self.id))
        XCTAssertNotEqual(first, try GatewayJournalSetupAddress.serviceName(accountID: Self.id, intentID: Data(repeating: 4, count: 16)))
        XCTAssertNotEqual(first, try RuntimePreparationPaths(accountID: Self.id).gatewayService)
        XCTAssertFalse(first.contains("/")); XCTAssertLessThan(first.utf8.count, 256)
        XCTAssertThrowsError(try GatewayJournalSetupAddress.serviceName(accountID: Self.id, intentID: Data()))
    }
}
