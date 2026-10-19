import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsControlChannelTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private final class Driver: GatewaySettingsControlDriver {
        struct State {
            var hello = 0, controls = 0, closes = 0
            var version: UInt64 = 1
            var holdHello = false, holdControl = false, failAfterHello = false, loseAfterHello = false
            var held: (@Sendable (GatewaySettingsControlReply) -> Void)?
            var lost: (@Sendable () -> Void)?
            var request: GatewaySettingsControlRequest?
            var onHello: (@Sendable () -> Void)?
            var onControl: (@Sendable () -> Void)?
            var changeReply: (@Sendable (GatewaySettingsControlRequest) throws -> Data)?
        }
        let state = Mutex(State())
        let binding: GatewaySettingsControlBinding
        init(_ binding: GatewaySettingsControlBinding) { self.binding = binding }
        func start(closed: @escaping @Sendable () -> Void) { state.withLock { $0.lost = closed } }
        func invoke(_ call: GatewaySettingsControlCall, reply: @escaping @Sendable (GatewaySettingsControlReply) -> Void) {
            do {
                switch call {
                case .hello:
                    let held = state.withLock { $0.hello += 1; if $0.holdHello { $0.held = reply; return true }; return false }
                    if held { return }
                    let hook = state.withLock { $0.onHello }; hook?()
                    reply(.greeting(state.withLock { $0.version }, try binding.encoded))
                    if state.withLock({ $0.failAfterHello }) { reply(.failed) }
                    if state.withLock({ $0.loseAfterHello }) { state.withLock { $0.lost }?() }
                case .control(let bytes):
                    let request = try GatewaySettingsControlRequest.decode(bytes)
                    let held = state.withLock { $0.controls += 1; $0.request = request; if $0.holdControl { $0.held = reply; return true }; return false }
                    if held { return }
                    let hook = state.withLock { $0.onControl }; hook?()
                    let edit = state.withLock { $0.changeReply }
                    let observation: GatewaySettingsControlObservation = request.action == .accept ? .accepted : .suspended
                    reply(.response(try edit?(request) ?? GatewaySettingsControlResponse(request: request, observation: observation).encoded))
                }
            } catch { reply(.failed) }
        }
        func close() { state.withLock { $0.closes += 1 } }
    }
    private final class WeakDriver { weak var value: Driver?; init(_ value: Driver?) { self.value = value } }
    private func binding(_ account: UInt8 = 1, epoch: UUID = UUID()) throws -> GatewaySettingsControlBinding {
        try .init(accountID: Data(repeating: account, count: 16), rootEpoch: epoch)
    }
    private func change() throws -> AuthorityPhonePushSettingsChange {
        try .init(revisionDigest: Data(repeating: 2, count: 32), previousCommitDigest: Data(repeating: 3, count: 32),
            selectedCommitDigest: Data(repeating: 4, count: 32))
    }
    private func channel(_ driver: Driver, account: Data? = nil, epoch: UUID? = nil, timeout: UInt64 = 1000,
                         verify: @escaping @Sendable () throws -> Void = {}, nonce: Int = 32) throws -> GatewaySettingsControlChannel {
        try .init(driver: driver, accountID: account ?? driver.binding.accountID, expectedRootEpoch: epoch, timeoutMilliseconds: timeout,
            verifyCurrent: verify, challenge: { Data(repeating: 5, count: nonce) })
    }
    private func waitUntil(_ body: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !body() { guard ContinuousClock.now < deadline else { throw Denied() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testOneActionUsesTheFreshHandshakeAndClosesBeforeReturning() async throws {
        let binding = try binding(), driver = Driver(binding), channel = try channel(driver)
        let result = try await channel.execute(change(), action: .quiesce)
        XCTAssertEqual(result.request.binding, binding); XCTAssertEqual(result.request.challenge, Data(repeating: 5, count: 32))
        XCTAssertEqual(result.observation, .suspended); XCTAssertEqual(driver.state.withLock { $0.controls }, 1)
        XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        do { _ = try await channel.execute(change(), action: .quiesce); XCTFail() }
        catch { XCTAssertEqual(error as? GatewaySettingsControlChannelError, .closed) }
        XCTAssertEqual(driver.state.withLock { $0.controls }, 1)
    }
    func testAcceptRequiresThePreviouslyObservedRootEpochBeforeAnyConnectionStarts() async throws {
        let binding = try binding(), missing = Driver(binding), allowed = Driver(binding)
        do { _ = try await channel(missing).execute(change(), action: .accept); XCTFail() }
        catch { XCTAssertEqual(error as? GatewaySettingsControlChannelError, .changedScope) }
        XCTAssertEqual(missing.state.withLock { $0.hello }, 0); XCTAssertEqual(missing.state.withLock { $0.controls }, 0)
        let result = try await channel(allowed, epoch: binding.rootEpoch).execute(change(), action: .accept)
        XCTAssertEqual(result.observation, .accepted)
    }
    func testUnsupportedOrStaleHandshakeCannotSendAControl() async throws {
        let binding = try binding()
        for mode in 0..<4 {
            let driver = Driver(binding)
            if mode < 2 { driver.state.withLock { $0.version = mode == 0 ? 0 : 2 } }
            let channel = try channel(driver, account: mode == 2 ? Data(repeating: 99, count: 16) : nil,
                epoch: mode == 3 ? UUID() : nil)
            do { _ = try await channel.execute(change(), action: .quiesce); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.controls }, 0); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        }
    }
    func testSynchronousLossOrFailureRetiresTheLifetimeBeforeQueuedHelloSuccessCanDispatch() async throws {
        for lost in [false, true] {
            let driver = Driver(try binding())
            driver.state.withLock { $0.loseAfterHello = lost; $0.failAfterHello = !lost }
            do { _ = try await channel(driver).execute(change(), action: .quiesce); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.controls }, 0); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        }
    }
    func testAReplyForAnotherChallengeCannotCompleteTheAction() async throws {
        let driver = Driver(try binding())
        driver.state.withLock { $0.changeReply = { request in
            let other = try GatewaySettingsControlRequest(binding: request.binding, change: request.change, action: request.action,
                challenge: Data(repeating: 99, count: 32))
            return try GatewaySettingsControlResponse(request: other, observation: .suspended).encoded
        } }
        do { _ = try await channel(driver).execute(change(), action: .quiesce); XCTFail() } catch {}
        XCTAssertEqual(driver.state.withLock { $0.controls }, 1); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
    }
    func testTimeoutDoesNotRepeatAnUncertainActionOrAcceptItsLateReply() async throws {
        for hello in [false, true] {
            let driver = Driver(try binding()), channel = try channel(driver, timeout: 50)
            driver.state.withLock { $0.holdHello = hello; $0.holdControl = !hello }
            do { _ = try await channel.execute(change(), action: .quiesce); XCTFail() }
            catch { XCTAssertEqual(error as? GatewaySettingsControlChannelError, .timedOut) }
            let reply = try XCTUnwrap(driver.state.withLock { $0.held })
            reply(.greeting(1, try driver.binding.encoded)); reply(.failed)
            do { _ = try await channel.execute(change(), action: .quiesce); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.controls }, hello ? 0 : 1); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        }
    }
    func testCancellationStopsTheConnectionAndCannotTurnALateReplyIntoSuccess() async throws {
        let driver = Driver(try binding()), channel = try channel(driver), change = try change()
        driver.state.withLock { $0.holdControl = true }
        let operation = Task { try await channel.execute(change, action: .quiesce) }
        try await waitUntil { driver.state.withLock { $0.held != nil } }
        operation.cancel()
        do { _ = try await operation.value; XCTFail() } catch {}
        try XCTUnwrap(driver.state.withLock { $0.held })(.failed)
        XCTAssertEqual(driver.state.withLock { $0.controls }, 1); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
    }
    func testAConcurrentCallerCannotConsumeOrCloseTheFirstExchange() async throws {
        let driver = Driver(try binding()), channel = try channel(driver), change = try change()
        driver.state.withLock { $0.holdHello = true }
        let first = Task { try await channel.execute(change, action: .quiesce) }
        try await waitUntil { driver.state.withLock { $0.held != nil } }
        do { _ = try await channel.execute(change, action: .quiesce); XCTFail() }
        catch { XCTAssertEqual(error as? GatewaySettingsControlChannelError, .busy) }
        XCTAssertEqual(driver.state.withLock { $0.closes }, 0)
        try XCTUnwrap(driver.state.withLock { $0.held })(.greeting(1, try driver.binding.encoded))
        let completed = try await first.value; XCTAssertEqual(completed.observation, .suspended)
        XCTAssertEqual(driver.state.withLock { $0.controls }, 1); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
    }
    func testChangedScopeBeforeDispatchOrAfterReplyNeverReportsSuccess() async throws {
        for beforeControl in [false, true] {
            let driver = Driver(try binding()), valid = Mutex(true)
            driver.state.withLock { state in
                if beforeControl { state.onHello = { valid.withLock { $0 = false } } }
                else { state.onControl = { valid.withLock { $0 = false } } }
            }
            do { _ = try await channel(driver, verify: { guard valid.withLock({ $0 }) else { throw Denied() } }).execute(change(), action: .quiesce); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.controls }, beforeControl ? 0 : 1)
        }
    }
    func testRetainedCloseAndReplyCallbacksDoNotKeepTheDriverAliveAfterSettlement() async throws {
        var driver: Driver? = Driver(try binding()), channel: GatewaySettingsControlChannel? = try channel(XCTUnwrap(driver), timeout: 20)
        let weakDriver = WeakDriver(driver)
        driver?.state.withLock { $0.holdHello = true }
        do { _ = try await channel?.execute(change(), action: .quiesce); XCTFail() } catch {}
        let reply = try XCTUnwrap(driver?.state.withLock { $0.held })
        driver = nil; channel = nil; XCTAssertNil(weakDriver.value)
        reply(.failed)
    }
    func testInvalidNonceAndBoundsFailBeforeSensitiveDispatch() async throws {
        let driver = Driver(try binding())
        do { _ = try await channel(driver, nonce: 31).execute(change(), action: .quiesce); XCTFail() } catch {}
        XCTAssertEqual(driver.state.withLock { $0.controls }, 0)
        for timeout: UInt64 in [0, 60_001, .max] {
            XCTAssertThrowsError(try channel(driver, timeout: timeout))
        }
        XCTAssertThrowsError(try GatewaySettingsControlAddress.serviceName(accountID: Data()))
        XCTAssertNotEqual(try GatewaySettingsControlAddress.serviceName(accountID: Data(repeating: 1, count: 16)),
            try GatewaySettingsControlAddress.serviceName(accountID: Data(repeating: 2, count: 16)))
    }
}
