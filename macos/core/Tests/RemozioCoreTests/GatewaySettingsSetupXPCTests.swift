import Darwin
import Foundation
import Security
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsSetupXPCTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private final class Invocation: @unchecked Sendable {
        let invoking = Mutex(false), rights = Mutex(0)
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
        init(_ owner: SetupAccountOwner, invocation: Invocation, actionReply: SetupClientReply? = nil,
             beforeReply: (@Sendable () -> Void)? = nil) {
            self.invocation = invocation; endpoint = invocation.endpoint(owner)
            self.actionReply = actionReply; self.beforeReply = beforeReply
        }
        func start(closed: @escaping @Sendable () -> Void) {}
        func close() { endpoint.close() }
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            calls.withLock { $0 += 1 }; invocation.invoking.withLock { $0 = true }
            defer { invocation.invoking.withLock { $0 = false } }
            switch call {
            case .gatewaySettingsHello: endpoint.gatewaySettingsHello { reply(.version($0)) }
            case .gatewaySettingsProgress: endpoint.gatewaySettingsProgress { reply(.progress($0)) }
            case .retainGatewaySettings(let expected, let selection, let form):
                if let actionReply { reply(actionReply); return }
                do { endpoint.retainGatewaySettings(try expected.bytes, selection: try selection.bytes, authorization: form) { reply(.progress($0)) } }
                catch { reply(.failed) }
            case .resumeGatewaySettings(let expected, let form):
                if let actionReply { reply(actionReply); return }
                do { endpoint.resumeGatewaySettings(try expected.bytes, authorization: form) { [self] in beforeReply?(); reply(.progress($0)) } }
                catch { reply(.failed) }
            default: reply(.failed)
            }
        }
    }
    private var form: Data { Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size) }
    func testLegacySettingsReadbackRefusesMutationBeforeAnotherCallOrRightsImport() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(native: false), invocation = Invocation()
        let driver = Driver(h.owner, invocation: invocation), client = AdministrativeSetupChannel(driver: driver, gatewaySettings: true)
        try await client.start()
        let response = try await client.gatewaySettingsProgress(), before = try XCTUnwrap(response)
        XCTAssertFalse(before.supportsSettingsChanges)
        let calls = driver.calls.withLock { $0 }
        do { _ = try await client.retainGatewaySettings(before, selection: h.selection, authorization: form); XCTFail() } catch {}
        XCTAssertEqual(driver.calls.withLock { $0 }, calls)
        XCTAssertEqual(invocation.rights.withLock { $0 }, 0)
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        XCTAssertEqual(try h.read(), before); await client.close()
    }
    func testVersionEightReadsWithoutRightsAndRequiresExplicitRetentionAndResume() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), invocation = Invocation(), driver = Driver(h.owner, invocation: invocation)
        let client = AdministrativeSetupChannel(driver: driver, gatewaySettings: true); try await client.start()
        let readEmpty = try await client.gatewaySettingsProgress()
        let empty = try XCTUnwrap(readEmpty)
        XCTAssertEqual(invocation.rights.withLock { $0 }, 0)
        let pending = try await client.retainGatewaySettings(empty, selection: h.selection, authorization: form)
        XCTAssertEqual(pending.stage, .retained); XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        let done = try await client.resumeGatewaySettings(pending, authorization: form)
        XCTAssertEqual(try done.activeDigest, try pending.pendingDigest)
        XCTAssertEqual(invocation.rights.withLock { $0 }, 2)
        let read = try await client.gatewaySettingsProgress(); XCTAssertEqual(read, done)
        XCTAssertEqual(invocation.rights.withLock { $0 }, 2); await client.close()
    }
    func testDeniedRetentionCannotMigrateOrCallTheBackend() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), invocation = Invocation(denied: true)
        let driver = Driver(h.owner, invocation: invocation), expected = try h.read()
        let client = AdministrativeSetupChannel(driver: driver, gatewaySettings: true); try await client.start()
        do { _ = try await client.retainGatewaySettings(expected, selection: h.selection, authorization: form); XCTFail() } catch {}
        XCTAssertEqual(invocation.rights.withLock { $0 }, 1)
        XCTAssertEqual(try h.ready.fixture.runtime.f.sql("PRAGMA user_version"), 10)
        XCTAssertEqual(try h.read(), expected); XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
    }
    func testDeniedResumeLeavesTheExactPendingRevisionIntact() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), pending = try h.retain(), invocation = Invocation(denied: true)
        let client = AdministrativeSetupChannel(driver: Driver(h.owner, invocation: invocation), gatewaySettings: true); try await client.start()
        do { _ = try await client.resumeGatewaySettings(pending, authorization: form); XCTFail() } catch {}
        XCTAssertEqual(try h.read(), pending); XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
    }
    func testVersionsOneThroughSevenCannotImportSettingsRights() async throws {
        for version in 1...7 {
            let h = try GatewaySettingsSetupOwnerTests.Harness(), rights = Mutex(0)
            let endpoint = AdministrativeSetupXPCEndpoint(owner: h.owner, verify: { getuid() }, authorize: { _ in rights.withLock { $0 += 1 } }, invalidate: {})
            switch version {
            case 1: endpoint.hello { _ in }
            case 2: endpoint.enrollmentHello { _ in }
            case 3: endpoint.serviceAccountsHello { _ in }
            case 4: endpoint.runtimeHello { _ in }
            case 5: endpoint.activationHello { _ in }
            case 6: endpoint.gatewayHello { _ in }
            default: endpoint.gatewayActivationHello { _ in }
            }
            let expected = try h.read(), selected = try h.selection.bytes, bytes = try expected.bytes, form = form
            let result: Data? = await withCheckedContinuation { continuation in
                endpoint.retainGatewaySettings(bytes, selection: selected, authorization: form) { continuation.resume(returning: $0) }
            }
            XCTAssertNil(result); XCTAssertEqual(rights.withLock { $0 }, 0); XCTAssertEqual(try h.read(), expected)
        }
    }
    private final class OldPeer: SetupClientDriver, @unchecked Sendable {
        let sensitiveCalls = Mutex(0)
        func start(closed: @escaping @Sendable () -> Void) {}
        func close() {}
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            if case .gatewaySettingsHello = call { reply(.version(7)); return }
            sensitiveCalls.withLock { $0 += 1 }; reply(.failed)
        }
    }
    func testOldPeersAreRejectedBeforeAnyAdministratorBytesAreSent() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), peer = OldPeer(), expected = try h.read()
        let client = AdministrativeSetupChannel(driver: peer, gatewaySettings: true)
        do { try await client.start(); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .unsupportedVersion) }
        do { _ = try await client.retainGatewaySettings(expected, selection: h.selection, authorization: form); XCTFail() } catch {}
        XCTAssertEqual(peer.sensitiveCalls.withLock { $0 }, 0)
    }
    func testMalformedInputsFailBeforeImportingRights() async throws {
        for bad in 0...2 {
            let h = try GatewaySettingsSetupOwnerTests.Harness(), expected = try h.read(), rights = Mutex(0)
            let endpoint = AdministrativeSetupXPCEndpoint(owner: h.owner, verify: { getuid() }, authorize: { _ in rights.withLock { $0 += 1 } }, invalidate: {})
            endpoint.gatewaySettingsHello { _ in }
            let bytes = bad == 0 ? Data() : try expected.bytes, selected = bad == 1 ? Data() : try h.selection.bytes
            let form = bad == 2 ? Data() : self.form
            let result: Data? = await withCheckedContinuation { continuation in
                endpoint.retainGatewaySettings(bytes, selection: selected, authorization: form) { continuation.resume(returning: $0) }
            }
            XCTAssertNil(result); XCTAssertEqual(rights.withLock { $0 }, 0); XCTAssertEqual(try h.read(), expected)
        }
    }
    func testInvalidOrUncommittedRepliesRetireTheClient() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), pending = try h.retain()
        for response in [SetupClientReply.progress(nil), .progress(Data()), .progress(Data(repeating: 0, count: SetupGatewaySettingsProgress.maximumByteCount + 1)), .progress(try pending.bytes)] {
            let driver = Driver(h.owner, invocation: Invocation(), actionReply: response)
            let client = AdministrativeSetupChannel(driver: driver, gatewaySettings: true); try await client.start()
            do { _ = try await client.resumeGatewaySettings(pending, authorization: form); XCTFail() } catch {}
            let calls = driver.calls.withLock { $0 }
            do { _ = try await client.gatewaySettingsProgress(); XCTFail() } catch {}
            XCTAssertEqual(driver.calls.withLock { $0 }, calls)
        }
    }
    func testRetentionReplyCannotSubstituteDifferentSelectedSettings() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), empty = try h.read(), pending = try h.retain()
        let different = try GatewayRuntimeSettingsSelection(service: h.selection.service,
            activation: .init(wakePollMilliseconds: 3000, wakeTimeoutMilliseconds: 6000))
        let driver = Driver(h.owner, invocation: Invocation(), actionReply: .progress(try pending.bytes))
        let client = AdministrativeSetupChannel(driver: driver, gatewaySettings: true); try await client.start()
        do { _ = try await client.retainGatewaySettings(empty, selection: different, authorization: form); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .invalidMessage) }
        let calls = driver.calls.withLock { $0 }
        do { _ = try await client.gatewaySettingsProgress(); XCTFail() } catch {}
        XCTAssertEqual(driver.calls.withLock { $0 }, calls)
    }
    func testCancellationCannotReleaseActivityBeforeTheBackendSettles() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), pending = try h.retain()
        let gate = GatewaySettingsSetupOwnerTests.Gate(), started = expectation(description: "settings backend entered")
        h.hold(gate, started)
        let client = AdministrativeSetupChannel(driver: Driver(h.owner, invocation: Invocation()), gatewaySettings: true); try await client.start()
        let task = Task { try await client.resumeGatewaySettings(pending, authorization: form) }
        await fulfillment(of: [started], timeout: 5); task.cancel()
        do { _ = try await task.value; XCTFail() } catch {}
        let installer = try h.activity.open()
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        await gate.release(); try await h.owner.closeWhenIdle()
        let update = try installer.acquireExclusive(); update.close()
    }
    func testShutdownKeepsActivityUntilTheSuccessfulReplyReturns() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), pending = try h.retain()
        let entered = expectation(description: "reply entered"), release = DispatchSemaphore(value: 0)
        let driver = Driver(h.owner, invocation: Invocation(), beforeReply: { entered.fulfill(); release.wait() })
        let client = AdministrativeSetupChannel(driver: driver, gatewaySettings: true); try await client.start()
        let task = Task { try await client.resumeGatewaySettings(pending, authorization: form) }
        await fulfillment(of: [entered], timeout: 10)
        let installer = try h.activity.open(), closed = Mutex(false)
        let closing = Task { try await h.owner.closeWhenIdle(); closed.withLock { $0 = true } }
        await Task.yield(); XCTAssertFalse(closed.withLock { $0 })
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        release.signal(); let done = try await task.value; XCTAssertNil(try done.pendingDigest)
        try await closing.value; let update = try installer.acquireExclusive(); update.close(); await client.close()
    }
}
