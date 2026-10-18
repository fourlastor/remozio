import Darwin
import Foundation
import RemozioProtocol
import Security
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySetupXPCTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private final class Driver: SetupClientDriver, @unchecked Sendable {
        let endpoint: AdministrativeSetupXPCEndpoint
        let invocation: InvocationState
        let journalReplies = Mutex(0)
        init(endpoint: AdministrativeSetupXPCEndpoint, invocation: InvocationState) { self.endpoint = endpoint; self.invocation = invocation }
        func start(closed: @escaping @Sendable () -> Void) {}
        func close() { endpoint.close() }
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            invocation.invoking.withLock { $0 = true }; defer { invocation.invoking.withLock { $0 = false } }
            switch call {
            case .gatewayHello: endpoint.gatewayHello { reply(.version($0)) }
            case .gatewayProgress: endpoint.gatewayProgress { reply(.progress($0)) }
            case .prepareGateway(let progress, let choices, let form):
                do { endpoint.prepareGateway(try progress.bytes, choices: try choices.bytes, authorization: form) { reply(.progress($0)) } }
                catch { reply(.failed) }
            case .resumeGatewayJournal(let progress, let form):
                do { endpoint.resumeGatewayJournal(try progress.bytes, authorization: form) { [self] in journalReplies.withLock { $0 += 1 }; reply(.progress($0)) } }
                catch { reply(.failed) }
            default: reply(.failed)
            }
        }
    }
    private final class InvocationState: @unchecked Sendable {
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
    private var form: Data { Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size) }
    func testVersionSixReadsWithoutRightsAndAuthorizesBeforeAsyncWorkThenAllowsImmediateReads() async throws {
        let h = try GatewaySetupAsyncOwnerTests.Harness(), invocation = InvocationState()
        let driver = Driver(endpoint: invocation.endpoint(h.owner), invocation: invocation)
        let client = AdministrativeSetupChannel(driver: driver, gateway: true)
        try await client.start()
        let read = try await client.gatewayProgress(), pending = try XCTUnwrap(read)
        XCTAssertEqual(invocation.rights.withLock { $0 }, 0)
        let result = try await client.resumeGatewayJournal(pending, authorization: form)
        XCTAssertTrue(result.progress.journalInitialized); XCTAssertEqual(invocation.rights.withLock { $0 }, 1)
        // A reply releases endpoint admission first. The next request must not encounter a stale busy marker.
        for _ in 0..<8 { let next = try await client.gatewayProgress(); XCTAssertEqual(next, result.progress) }
        XCTAssertEqual(driver.journalReplies.withLock { $0 }, 1)
        await client.close()
    }
    func testDeniedRightsCannotEnterTheBackend() async throws {
        let h = try GatewaySetupAsyncOwnerTests.Harness(), invocation = InvocationState(denied: true)
        let driver = Driver(endpoint: invocation.endpoint(h.owner), invocation: invocation)
        let client = AdministrativeSetupChannel(driver: driver, gateway: true); try await client.start()
        let pending = try h.read()
        do { _ = try await client.resumeGatewayJournal(pending, authorization: form); XCTFail() } catch {}
        XCTAssertEqual(invocation.rights.withLock { $0 }, 1); XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        XCTAssertFalse(try h.read().journalInitialized)
    }
    func testOldHandshakesCannotInvokeGatewaySetupOrImportRights() async throws {
        for version in 1...5 {
            let h = try GatewaySetupAsyncOwnerTests.Harness()
            let endpoint = AdministrativeSetupXPCEndpoint(owner: h.owner, verify: { getuid() }, authorize: { _ in XCTFail() }, invalidate: {})
            switch version {
            case 1: endpoint.hello { _ in }
            case 2: endpoint.enrollmentHello { _ in }
            case 3: endpoint.serviceAccountsHello { _ in }
            case 4: endpoint.runtimeHello { _ in }
            default: endpoint.activationHello { _ in }
            }
            endpoint.resumeGatewayJournal(try h.read().bytes, authorization: form) { XCTAssertNil($0) }
            XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        }
    }
    func testMalformedAndForeignProgressAreRejectedBeforeImportingRights() throws {
        let h = try GatewaySetupAsyncOwnerTests.Harness(), valid = try h.read().bytes
        let limits = try CBORLimits(maxBytes: 2048, maxDepth: 2, maxItems: 64)
        guard case .map(let original) = try DeterministicCBOR.decode(valid, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (6, .unsigned(UInt64(getuid() + 1))), (10, .null)] {
            let endpoint = AdministrativeSetupXPCEndpoint(owner: h.owner, verify: { getuid() }, authorize: { _ in XCTFail() }, invalidate: {})
            endpoint.gatewayHello { XCTAssertEqual($0, 6) }
            var changed = original; changed[key] = value
            endpoint.resumeGatewayJournal(try DeterministicCBOR.encode(.map(changed), limits: limits), authorization: form) { XCTAssertNil($0) }
        }
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
    }
    func testClosingTheClientSuppressesLateRepliesAndRetainsResourcesUntilTheBackendSettles() async throws {
        let h = try GatewaySetupAsyncOwnerTests.Harness(), invocation = InvocationState()
        let gate = GatewaySetupAsyncOwnerTests.Gate(), entered = expectation(description: "backend entered")
        h.hold(gate, entered); h.backend.state.withLock { $0.checkCancellation = true }
        let driver = Driver(endpoint: invocation.endpoint(h.owner), invocation: invocation)
        let client = AdministrativeSetupChannel(driver: driver, gateway: true), expected = try h.read(), installer = try h.activity.open()
        try await client.start()
        let task = Task { try await client.resumeGatewayJournal(expected, authorization: form) }
        await fulfillment(of: [entered], timeout: 5); await client.close()
        do { _ = try await task.value; XCTFail() } catch {}
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        await gate.release()
        // Owner shutdown waits for the endpoint's actual operation to release the machine scope.
        try await h.owner.closeWhenIdle()
        XCTAssertEqual(driver.journalReplies.withLock { $0 }, 0)
        let update = try installer.acquireExclusive(); update.close()
    }
    func testShutdownAlsoWaitsForTheReplyAfterTheMachineOperationCompletes() async throws {
        let h = try GatewaySetupAsyncOwnerTests.Harness(), entered = expectation(description: "reply entered")
        let release = DispatchSemaphore(value: 0), finished = Mutex(false), installer = try h.activity.open()
        defer { release.signal() }
        let endpoint = AdministrativeSetupXPCEndpoint(owner: h.owner, verify: { getuid() }, authorize: { _ in }, invalidate: {})
        endpoint.gatewayHello { XCTAssertEqual($0, 6) }
        endpoint.resumeGatewayJournal(try h.read().bytes, authorization: form) { bytes in
            XCTAssertNotNil(bytes); entered.fulfill()
            XCTAssertEqual(release.wait(timeout: .now() + 5), .success)
        }
        await fulfillment(of: [entered], timeout: 5)
        let closing = Task { try await h.owner.closeWhenIdle(); finished.withLock { $0 = true } }
        await Task.yield()
        XCTAssertFalse(finished.withLock { $0 })
        let machine = try h.fixture.runtime.f.open(); try machine.close()
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        release.signal(); try await closing.value
        XCTAssertTrue(finished.withLock { $0 })
        let update = try installer.acquireExclusive(); update.close()
    }
    func testMalformedChoicesAreRejectedBeforeNativeAuthorization() throws {
        let h = try GatewaySetupAsyncOwnerTests.Harness()
        let endpoint = AdministrativeSetupXPCEndpoint(owner: h.owner, verify: { getuid() }, authorize: { _ in XCTFail() }, invalidate: {})
        endpoint.gatewayHello { XCTAssertEqual($0, 6) }
        endpoint.prepareGateway(try h.read().bytes, choices: Data([0]), authorization: form) { XCTAssertNil($0) }
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
    }
    private final class PausedDriver: SetupClientDriver, @unchecked Sendable {
        let version: UInt64
        let calls = Mutex([String]())
        let retained = Mutex<(@Sendable (SetupClientReply) -> Void)?>(nil)
        init(version: UInt64 = 6) { self.version = version }
        func start(closed: @escaping @Sendable () -> Void) {}
        func close() {}
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            switch call {
            case .gatewayHello: calls.withLock { $0.append("hello") }; reply(.version(version))
            case .resumeGatewayJournal: calls.withLock { $0.append("journal") }; retained.withLock { $0 = reply }
            default: calls.withLock { $0.append("unexpected") }; reply(.failed)
            }
        }
        func lateReply() { retained.withLock { $0 }?(.progress(Data())) }
    }
    func testOldServerVersionIsRejectedBeforeSendingGatewayScopeOrRights() async throws {
        let driver = PausedDriver(version: 5), client = AdministrativeSetupChannel(driver: driver, gateway: true)
        do { try await client.start(); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .unsupportedVersion) }
        XCTAssertEqual(driver.calls.withLock { $0 }, ["hello"])
    }
    func testGatewayOperationUsesItsOwnTimeoutAndIgnoresLateReplies() async throws {
        let h = try GatewaySetupAsyncOwnerTests.Harness(), driver = PausedDriver()
        let client = AdministrativeSetupChannel(driver: driver, gateway: true, gatewayOperationTimeoutMilliseconds: 1, timeoutMilliseconds: 5000)
        try await client.start()
        do { _ = try await client.resumeGatewayJournal(h.read(), authorization: form); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .timedOut) }
        XCTAssertEqual(driver.calls.withLock { $0 }, ["hello", "journal"])
        driver.lateReply()
        do { _ = try await client.gatewayProgress(); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
    }
}
