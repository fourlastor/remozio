import Darwin
import Foundation
import Security
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayActivationXPCTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private final class Invocation: @unchecked Sendable {
        let invoking = Mutex(false)
        let rights = Mutex(0)
        let denied: Bool
        init(denied: Bool = false) { self.denied = denied }
        func endpoint(_ owner: SetupAccountOwner) -> AdministrativeSetupXPCEndpoint {
            .init(owner: owner, verify: { [self] in XCTAssertTrue(invoking.withLock { $0 }); return getuid() },
                authorize: { [self] _ in
                    XCTAssertTrue(invoking.withLock { $0 }); rights.withLock { $0 += 1 }
                    if denied { throw Denied() }
                }, invalidate: {})
        }
    }
    private final class Driver: SetupClientDriver, @unchecked Sendable {
        let endpoint: AdministrativeSetupXPCEndpoint
        let invocation: Invocation
        let calls = Mutex(0)
        let actionReply: SetupClientReply?
        let beforeReply: (@Sendable () -> Void)?
        init(endpoint: AdministrativeSetupXPCEndpoint, invocation: Invocation, actionReply: SetupClientReply? = nil,
             beforeReply: (@Sendable () -> Void)? = nil) {
            self.endpoint = endpoint; self.invocation = invocation; self.actionReply = actionReply; self.beforeReply = beforeReply
        }
        func start(closed: @escaping @Sendable () -> Void) {}
        func close() { endpoint.close() }
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            calls.withLock { $0 += 1 }; invocation.invoking.withLock { $0 = true }
            defer { invocation.invoking.withLock { $0 = false } }
            switch call {
            case .gatewayActivationHello: endpoint.gatewayActivationHello { reply(.version($0)) }
            case .gatewayActivationProgress: endpoint.gatewayActivationProgress { reply(.progress($0)) }
            case .activateGateway(let expected, let settings, let form):
                if let actionReply { reply(actionReply); return }
                do { endpoint.activateGateway(try expected.bytes, settings: try settings.bytes, authorization: form) { [self] in
                    beforeReply?(); reply(.progress($0))
                } } catch { reply(.failed) }
            default: reply(.failed)
            }
        }
    }
    private var form: Data { Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size) }
    private func handshake(_ endpoint: AdministrativeSetupXPCEndpoint, version: Int) {
        switch version {
        case 1: endpoint.hello { _ in }
        case 2: endpoint.enrollmentHello { _ in }
        case 3: endpoint.serviceAccountsHello { _ in }
        case 4: endpoint.runtimeHello { _ in }
        case 5: endpoint.activationHello { _ in }
        default: endpoint.gatewayHello { _ in }
        }
    }
    func testVersionSevenReadsWithoutRightsAndImportsRightsBeforeAsyncActivation() async throws {
        let h = try GatewayActivationAsyncOwnerTests.Harness(), invocation = Invocation()
        let driver = Driver(endpoint: invocation.endpoint(h.owner), invocation: invocation)
        let client = AdministrativeSetupChannel(driver: driver, gatewayActivation: true); try await client.start()
        let pending = try await client.gatewayActivationProgress(), expected = try XCTUnwrap(pending)
        XCTAssertEqual(invocation.rights.withLock { $0 }, 0)
        let result = try await client.activateGateway(expected, settings: h.settings, authorization: form)
        XCTAssertTrue(result.jobRegistered); XCTAssertEqual(result.settings, h.settings)
        XCTAssertEqual(invocation.rights.withLock { $0 }, 1)
        for _ in 0..<4 { let next = try await client.gatewayActivationProgress(); XCTAssertEqual(next, result) }
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 1); await client.close()
    }
    func testDeniedRightsCannotStartTheActivationBackend() async throws {
        let h = try GatewayActivationAsyncOwnerTests.Harness(), expected = try h.read(), invocation = Invocation(denied: true)
        let driver = Driver(endpoint: invocation.endpoint(h.owner), invocation: invocation)
        let client = AdministrativeSetupChannel(driver: driver, gatewayActivation: true); try await client.start()
        do { _ = try await client.activateGateway(expected, settings: h.settings, authorization: form); XCTFail() } catch {}
        XCTAssertEqual(invocation.rights.withLock { $0 }, 1); XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        XCTAssertFalse(try h.read().filesPublished)
    }
    func testVersionsOneThroughSixCannotInvokeActivationOrImportRights() async throws {
        for version in 1...6 {
            let h = try GatewayActivationAsyncOwnerTests.Harness(), expected = try h.read()
            let endpoint = AdministrativeSetupXPCEndpoint(owner: h.owner, verify: { getuid() }, authorize: { _ in XCTFail() }, invalidate: {})
            handshake(endpoint, version: version)
            let bytes: Data? = await withCheckedContinuation { continuation in
                endpoint.activateGateway(try! expected.bytes, settings: try! h.settings.bytes, authorization: form) { continuation.resume(returning: $0) }
            }
            XCTAssertNil(bytes); XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        }
    }
    private final class OldPeer: SetupClientDriver, @unchecked Sendable {
        let sensitiveCalls = Mutex(0)
        func start(closed: @escaping @Sendable () -> Void) {}
        func close() {}
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            if case .gatewayActivationHello = call { reply(.version(6)); return }
            sensitiveCalls.withLock { $0 += 1 }; reply(.failed)
        }
    }
    func testClientRejectsAnOldPeerBeforeSendingAdministratorBytes() async throws {
        let h = try GatewayActivationAsyncOwnerTests.Harness(), peer = OldPeer(), expected = try h.read()
        let client = AdministrativeSetupChannel(driver: peer, gatewayActivation: true)
        do { try await client.start(); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .unsupportedVersion) }
        do { _ = try await client.activateGateway(expected, settings: h.settings, authorization: form); XCTFail() } catch {}
        XCTAssertEqual(peer.sensitiveCalls.withLock { $0 }, 0)
    }
    func testNilEmptyOversizedOrIncompleteCompletionRetiresTheClient() async throws {
        let h = try GatewayActivationAsyncOwnerTests.Harness(), expected = try h.read()
        for response in [SetupClientReply.progress(nil), .progress(Data()), .progress(Data(repeating: 0, count: 1281)), .progress(try expected.bytes)] {
            let invocation = Invocation(), driver = Driver(endpoint: invocation.endpoint(h.owner), invocation: invocation, actionReply: response)
            let client = AdministrativeSetupChannel(driver: driver, gatewayActivation: true); try await client.start()
            do { _ = try await client.activateGateway(expected, settings: h.settings, authorization: form); XCTFail() }
            catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .invalidMessage) }
            let calls = driver.calls.withLock { $0 }
            do { _ = try await client.gatewayActivationProgress(); XCTFail() } catch {}
            XCTAssertEqual(driver.calls.withLock { $0 }, calls)
        }
    }
    func testMalformedSettingsAndAuthorizationFailBeforeImportingRights() async throws {
        for badSettings in [false, true] {
            let h = try GatewayActivationAsyncOwnerTests.Harness(), expected = try h.read(), rights = Mutex(0)
            let endpoint = AdministrativeSetupXPCEndpoint(owner: h.owner, verify: { getuid() }, authorize: { _ in rights.withLock { $0 += 1 } }, invalidate: {})
            endpoint.gatewayActivationHello { _ in }
            let selected = badSettings ? Data() : try h.settings.bytes, authorization = badSettings ? form : Data([1])
            let bytes: Data? = await withCheckedContinuation { continuation in
                endpoint.activateGateway(try! expected.bytes, settings: selected, authorization: authorization) { continuation.resume(returning: $0) }
            }
            XCTAssertNil(bytes); XCTAssertEqual(rights.withLock { $0 }, 0); XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        }
    }
    func testCancellationRetainsNativeActivityUntilTheAdmittedBackendSettles() async throws {
        let h = try GatewayActivationAsyncOwnerTests.Harness(), expected = try h.read(), invocation = Invocation()
        let gate = GatewayActivationAsyncOwnerTests.Gate(), started = expectation(description: "backend entered")
        h.hold(gate, started)
        let driver = Driver(endpoint: invocation.endpoint(h.owner), invocation: invocation)
        let client = AdministrativeSetupChannel(driver: driver, gatewayActivation: true); try await client.start()
        let task = Task { try await client.activateGateway(expected, settings: h.settings, authorization: form) }
        await fulfillment(of: [started], timeout: 5); task.cancel()
        do { _ = try await task.value; XCTFail() }
        catch { XCTAssertTrue(error is CancellationError || error as? AdministrativeSetupChannelError == .closed) }
        let installer = try h.activity.open()
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        await gate.release(); try await h.owner.closeWhenIdle()
        let update = try installer.acquireExclusive(); update.close()
    }
    func testShutdownCannotReleaseNativeScopeWhileSuccessfulReplyIsBlocked() async throws {
        let h = try GatewayActivationAsyncOwnerTests.Harness(), expected = try h.read(), invocation = Invocation()
        let entered = expectation(description: "reply entered"), release = DispatchSemaphore(value: 0)
        let driver = Driver(endpoint: invocation.endpoint(h.owner), invocation: invocation, beforeReply: { entered.fulfill(); release.wait() })
        let client = AdministrativeSetupChannel(driver: driver, gatewayActivation: true); try await client.start()
        let task = Task { try await client.activateGateway(expected, settings: h.settings, authorization: form) }
        await fulfillment(of: [entered], timeout: 10)
        let installer = try h.activity.open(), closed = Mutex(false)
        let closing = Task { try await h.owner.closeWhenIdle(); closed.withLock { $0 = true } }
        await Task.yield(); XCTAssertFalse(closed.withLock { $0 })
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        release.signal(); let done = try await task.value; XCTAssertTrue(done.jobRegistered)
        try await closing.value; XCTAssertTrue(closed.withLock { $0 })
        let update = try installer.acquireExclusive(); update.close(); await client.close()
    }
}
