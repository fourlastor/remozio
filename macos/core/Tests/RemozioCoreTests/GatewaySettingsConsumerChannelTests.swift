import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsConsumerChannelTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private let fixture = try! GatewaySettingsConsumerControlFixture()
    private final class Driver: GatewaySettingsControlDriver {
        struct State {
            var hello = 0, controls = 0, closes = 0
            var version: UInt64 = 1
            var greetingBytes: Data?
            var holdHello = false, holdControl = false, failAfterHello = false, loseAfterHello = false
            var held: (@Sendable (GatewaySettingsControlReply) -> Void)?
            var lost: (@Sendable () -> Void)?
            var request: GatewaySettingsConsumerRequest?
            var onHello: (@Sendable () -> Void)?
            var onControl: (@Sendable () -> Void)?
            var changeReply: (@Sendable (GatewaySettingsConsumerRequest) throws -> Data)?
        }
        let state = Mutex(State())
        let binding: GatewaySettingsConsumerBinding
        init(_ binding: GatewaySettingsConsumerBinding) { self.binding = binding }
        func start(closed: @escaping @Sendable () -> Void) { state.withLock { $0.lost = closed } }
        func invoke(_ call: GatewaySettingsControlCall, reply: @escaping @Sendable (GatewaySettingsControlReply) -> Void) {
            do {
                switch call {
                case .hello:
                    let held = state.withLock { $0.hello += 1; if $0.holdHello { $0.held = reply; return true }; return false }
                    if held { return }
                    let hook = state.withLock { $0.onHello }; hook?()
                    reply(.greeting(state.withLock { $0.version }, try state.withLock { $0.greetingBytes } ?? binding.encoded))
                    if state.withLock({ $0.failAfterHello }) { reply(.failed) }
                    if state.withLock({ $0.loseAfterHello }) { state.withLock { $0.lost }?() }
                case .control(let bytes):
                    let request = try GatewaySettingsConsumerRequest.decode(bytes)
                    let held = state.withLock { $0.controls += 1; $0.request = request; if $0.holdControl { $0.held = reply; return true }; return false }
                    if held { return }
                    let hook = state.withLock { $0.onControl }; hook?()
                    let edit = state.withLock { $0.changeReply }
                    let observation: GatewaySettingsConsumerObservation = request.action == .accept ? .accepted : .paused
                    reply(.response(try edit?(request) ?? GatewaySettingsConsumerResponse(request: request, observation: observation).encoded))
                }
            } catch { reply(.failed) }
        }
        func close() { state.withLock { $0.closes += 1 } }
    }
    private final class WeakDriver { weak var value: Driver?; init(_ value: Driver?) { self.value = value } }
    private func binding(_ account: UInt8 = 1, epoch: UUID = UUID()) throws -> GatewaySettingsConsumerBinding {
        try .init(role: .gateway, macID: fixture.fence.macID, accountID: account == 1 ? fixture.fence.accountID : Data(repeating: account, count: 16), generation: epoch)
    }
    private func change() throws -> GatewayRuntimeSettingsFence { fixture.fence }
    private func channel(_ driver: Driver, account: Data? = nil, epoch: UUID? = nil, timeout: UInt64 = 1000,
                         role: GatewaySettingsConsumerRole? = nil, macID: Data? = nil,
                         verify: @escaping @Sendable () throws -> Void = {}, nonce: Int = 32) throws -> GatewaySettingsConsumerChannel {
        try .init(driver: driver, role: role ?? driver.binding.role, macID: macID ?? driver.binding.macID,
            accountID: account ?? driver.binding.accountID, expectedGeneration: epoch, timeoutMilliseconds: timeout,
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
        XCTAssertEqual(result.observation, .paused); XCTAssertEqual(driver.state.withLock { $0.controls }, 1)
        XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        do { _ = try await channel.execute(change(), action: .quiesce); XCTFail() }
        catch { XCTAssertEqual(error as? GatewaySettingsControlChannelError, .closed) }
        XCTAssertEqual(driver.state.withLock { $0.controls }, 1)
    }
    func testAcceptRequiresThePreviouslyObservedConsumerGenerationBeforeAnyConnectionStarts() async throws {
        let binding = try binding(), missing = Driver(binding), allowed = Driver(binding)
        do { _ = try await channel(missing).execute(change(), action: .accept); XCTFail() }
        catch { XCTAssertEqual(error as? GatewaySettingsControlChannelError, .changedScope) }
        XCTAssertEqual(missing.state.withLock { $0.hello }, 0); XCTAssertEqual(missing.state.withLock { $0.controls }, 0)
        let result = try await channel(allowed, epoch: binding.generation).execute(change(), action: .accept)
        XCTAssertEqual(result.observation, .accepted)
    }
    func testUnsupportedOrStaleHandshakeCannotSendAControl() async throws {
        let binding = try binding()
        for mode in 0..<6 {
            let driver = Driver(binding)
            if mode < 2 { driver.state.withLock { $0.version = mode == 0 ? 0 : 2 } }
            let channel = try channel(driver, account: mode == 2 ? Data(repeating: 99, count: 16) : nil,
                epoch: mode == 3 ? UUID() : nil, role: mode == 4 ? .transport : nil,
                macID: mode == 5 ? Data(repeating: 99, count: 16) : nil)
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
        let driver = Driver(try binding()), fence = fixture.fence
        driver.state.withLock { $0.changeReply = { request in
            let other = try GatewaySettingsConsumerRequest(binding: request.binding, fence: fence, action: request.action,
                challenge: Data(repeating: 99, count: 32))
            return try GatewaySettingsConsumerResponse(request: other, observation: .paused).encoded
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
        let completed = try await first.value; XCTAssertEqual(completed.observation, .paused)
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
        var driver: Driver? = Driver(try binding()), channel: GatewaySettingsConsumerChannel? = try channel(XCTUnwrap(driver), timeout: 20)
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
        XCTAssertThrowsError(try GatewaySettingsConsumerRole.gateway.serviceName(accountID: Data()))
        XCTAssertNotEqual(try GatewaySettingsConsumerRole.gateway.serviceName(accountID: Data(repeating: 1, count: 16)),
            try GatewaySettingsConsumerRole.gateway.serviceName(accountID: Data(repeating: 2, count: 16)))
    }
    func testRootControlBindingCannotSelectACompanionDespiteTheSameVersionNumber() async throws {
        let driver = Driver(try binding())
        let root = try GatewaySettingsControlBinding(accountID: driver.binding.accountID, rootEpoch: driver.binding.generation)
        driver.state.withLock { $0.greetingBytes = try? root.encoded }
        do { _ = try await channel(driver).execute(change(), action: .quiesce); XCTFail() } catch {}
        XCTAssertEqual(driver.state.withLock { $0.controls }, 0)
        XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
    }

}
