import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsControlEndpointTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private func request(_ action: GatewaySettingsControlAction = .quiesce, binding: GatewaySettingsControlBinding? = nil) throws -> GatewaySettingsControlRequest {
        try .init(binding: binding ?? .init(accountID: Data(repeating: 1, count: 16), rootEpoch: UUID()),
            change: .init(revisionDigest: Data(repeating: 2, count: 32), previousCommitDigest: Data(repeating: 3, count: 32),
                selectedCommitDigest: Data(repeating: 4, count: 32)), action: action, challenge: Data(repeating: 5, count: 32))
    }
    private func hello(_ endpoint: GatewaySettingsControlXPCEndpoint, binding: GatewaySettingsControlBinding) {
        endpoint.hello { version, bytes in
            XCTAssertEqual(version, 1); XCTAssertEqual(try? bytes.map(GatewaySettingsControlBinding.decode), binding)
        }
    }
    private func waitUntil(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !condition() {
            guard ContinuousClock.now < deadline else { throw Denied() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testHandshakeAndOneControlVerifyOnTheOriginalInvocationStack() async throws {
        let request = try request(), verifications = Mutex(0), executions = Mutex(0), reply = Mutex<Data?>(nil)
        let endpoint = GatewaySettingsControlXPCEndpoint(binding: request.binding, verify: {
            XCTAssertEqual(Thread.current.threadDictionary["remozio-control-invocation"] as? Bool, true)
            verifications.withLock { $0 += 1 }
        }, verifyCurrent: {}, budget: try .init(maximum: 1), invalidate: {}, execute: { received in
            XCTAssertEqual(try received.encoded, try request.encoded); executions.withLock { $0 += 1 }; return .suspended
        })
        defer { endpoint.close() }
        func invoke(_ body: () throws -> Void) rethrows {
            Thread.current.threadDictionary["remozio-control-invocation"] = true
            defer { Thread.current.threadDictionary.removeObject(forKey: "remozio-control-invocation") }
            try body()
        }
        try invoke {
            hello(endpoint, binding: request.binding)
            endpoint.control(try request.encoded) { bytes in reply.withLock { $0 = bytes } }
        }; try await waitUntil { reply.withLock { $0 != nil } }
        XCTAssertEqual(verifications.withLock { $0 }, 2); XCTAssertEqual(executions.withLock { $0 }, 1)
        XCTAssertEqual(try GatewaySettingsControlResponse.decode(XCTUnwrap(reply.withLock { $0 }), expected: request).observation, .suspended)
        try invoke { endpoint.control(try request.encoded) { XCTAssertNil($0) } }
        XCTAssertEqual(verifications.withLock { $0 }, 3); XCTAssertEqual(executions.withLock { $0 }, 1)
    }
    func testMissingHandshakeWrongBindingsAndRepeatedHelloCannotStartWork() throws {
        let request = try request(), executions = Mutex(0)
        for mode in 0..<3 {
            let endpoint = GatewaySettingsControlXPCEndpoint(binding: request.binding, verify: {}, verifyCurrent: {},
                budget: try .init(maximum: 1), invalidate: {}, execute: { _ in executions.withLock { $0 += 1 }; return .suspended })
            defer { endpoint.close() }
            if mode == 0 { endpoint.control(try request.encoded) { XCTAssertNil($0) } }
            if mode == 1 {
                hello(endpoint, binding: request.binding)
                endpoint.control(try self.request().encoded) { XCTAssertNil($0) }
            }
            if mode == 2 {
                hello(endpoint, binding: request.binding)
                endpoint.hello { version, bytes in XCTAssertEqual(version, 0); XCTAssertNil(bytes) }
                endpoint.control(try request.encoded) { XCTAssertNil($0) }
            }
        }
        XCTAssertEqual(executions.withLock { $0 }, 0)
    }
    func testInvocationRejectionBeforeAdmissionDoesNotConsumeTheGlobalWorkBudget() throws {
        let request = try request(), budget = try AuthorityXPCWorkBudget(maximum: 1), reject = Mutex(false)
        let endpoint = GatewaySettingsControlXPCEndpoint(binding: request.binding, verify: {
            if reject.withLock({ $0 }) { throw Denied() }
        }, verifyCurrent: {}, budget: budget, invalidate: {}, execute: { _ in XCTFail(); return .suspended })
        hello(endpoint, binding: request.binding); reject.withLock { $0 = true }
        endpoint.control(try request.encoded) { XCTAssertNil($0) }
        XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testDisconnectRetainsTheBudgetAndReleaseLeaseUntilAdmittedWorkActuallySettles() async throws {
        let request = try request(), fixture = try ReleaseActivityFixture(), activity = try fixture.open(), installer = try fixture.open()
        let budget = try AuthorityXPCWorkBudget(maximum: 1), gate = Mutex<CheckedContinuation<Void, Never>?>(nil), replied = Mutex(false)
        let endpoint = GatewaySettingsControlXPCEndpoint(binding: request.binding, verify: {}, verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: budget, invalidate: {}, execute: { _ in
                await withCheckedContinuation { continuation in gate.withLock { $0 = continuation } }
                return .suspended
            })
        hello(endpoint, binding: request.binding)
        endpoint.control(try request.encoded) { _ in replied.withLock { $0 = true } }
        try await waitUntil { gate.withLock { $0 != nil } }
        endpoint.close(); XCTAssertFalse(budget.acquire()); XCTAssertThrowsError(try installer.acquireExclusive())
        gate.withLock { let pending = $0; $0 = nil; pending?.resume() }
        try await waitUntil { if budget.acquire() { budget.release(); return true }; return false }
        let update = try installer.acquireExclusive(); update.close(); XCTAssertFalse(replied.withLock { $0 })
    }
    func testTheCompletionReplyRunsOnlyAfterTheOwnedReleaseLeaseHasClosed() async throws {
        let request = try request(), fixture = try ReleaseActivityFixture(), activity = try fixture.open(), installer = try fixture.open()
        let replies = Mutex(0)
        let endpoint = GatewaySettingsControlXPCEndpoint(binding: request.binding, verify: {}, verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: try .init(maximum: 1), invalidate: {}, execute: { _ in .suspended })
        defer { endpoint.close() }
        hello(endpoint, binding: request.binding)
        endpoint.control(try request.encoded) { bytes in
            XCTAssertNotNil(bytes)
            do { let update = try installer.acquireExclusive(); update.close() }
            catch { XCTFail("The completed operation still holds its release lease: \(error)") }
            replies.withLock { $0 += 1 }
        }
        try await waitUntil { replies.withLock { $0 == 1 } }
    }
    func testChangedScopeAfterAwaitAndInvalidHandlerStageCannotProduceASuccessfulReply() async throws {
        for invalidStage in [false, true] {
            let request = try request(), valid = Mutex(true), replies = Mutex(0), budget = try AuthorityXPCWorkBudget(maximum: 1)
            let endpoint = GatewaySettingsControlXPCEndpoint(binding: request.binding, verify: {}, verifyCurrent: {
                guard valid.withLock({ $0 }) else { throw Denied() }
            }, budget: budget, invalidate: {}, execute: { _ in
                if !invalidStage { valid.withLock { $0 = false } }
                return invalidStage ? .quiescing : .suspended
            })
            defer { endpoint.close() }
            hello(endpoint, binding: request.binding)
            endpoint.control(try request.encoded) { bytes in XCTAssertNil(bytes); replies.withLock { $0 += 1 } }
            try await waitUntil { replies.withLock { $0 == 1 } }
            XCTAssertTrue(budget.acquire()); budget.release()
        }
    }
    func testMalformedPayloadClosesBeforeAnOperationStarts() throws {
        let request = try request(), executions = Mutex(0)
        for bytes in [Data(), Data(repeating: 0, count: 513), try request.encoded + Data([0])] {
            let endpoint = GatewaySettingsControlXPCEndpoint(binding: request.binding, verify: {}, verifyCurrent: {},
                budget: try .init(maximum: 1), invalidate: {}, execute: { _ in executions.withLock { $0 += 1 }; return .suspended })
            hello(endpoint, binding: request.binding); endpoint.control(bytes) { XCTAssertNil($0) }; endpoint.close()
        }
        XCTAssertEqual(executions.withLock { $0 }, 0)
    }
    func testNativeAccessUsesTheExistingServiceAndReportsProviderInstallationSeparately() async throws {
        let f = try AuthorityWakeSettingsTests.Fixture()
        let binding = try GatewaySettingsControlBinding(accountID: f.h.registration.accountID, rootEpoch: f.h.clock)
        let service = try f.service([.init(), .init()], binding: binding)
        let access = try AuthorityGatewaySettingsAccess(service: service, binding: binding, verifyCurrent: {})
        func request(_ action: GatewaySettingsControlAction) throws -> GatewaySettingsControlRequest {
            try .init(binding: binding, change: f.change(), action: action, challenge: Data(repeating: 8, count: 32))
        }
        try await service.start()
        let before = try f.state()
        let unknown = try await access.execute(request(.observe)); XCTAssertEqual(unknown, .unknown)
        let paused = try await access.execute(request(.quiesce)); XCTAssertEqual(paused, .suspended)
        XCTAssertEqual(try f.state(), before); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        let accepted = try await access.execute(request(.accept)); XCTAssertEqual(accepted, .accepted)
        try await service.installPhonePush(f.options, commitDigest: f.selected, verifyCurrent: {})
        let installed = try await access.execute(request(.observe)); XCTAssertEqual(installed, .providerInstalled)
        XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(try f.state(), before)
        try await service.close()
    }
    func testAccessRejectsAnotherAccountEpochOrAnOlderServiceWithoutTheControlBinding() async throws {
        let f = try AuthorityWakeSettingsTests.Fixture(), account = f.h.registration.accountID
        let binding = try GatewaySettingsControlBinding(accountID: account, rootEpoch: f.h.clock)
        let service = try f.service([.init()], binding: binding)
        for wrong in [try GatewaySettingsControlBinding(accountID: Data(repeating: 99, count: 16), rootEpoch: f.h.clock),
                      try GatewaySettingsControlBinding(accountID: account, rootEpoch: UUID())] {
            XCTAssertThrowsError(try AuthorityGatewaySettingsAccess(service: service, binding: wrong, verifyCurrent: {}))
        }
        let legacy = try f.service([.init()])
        XCTAssertThrowsError(try AuthorityGatewaySettingsAccess(service: legacy, binding: binding, verifyCurrent: {}))
        let access = try AuthorityGatewaySettingsAccess(service: service, binding: binding, verifyCurrent: {})
        do { _ = try await access.execute(request(.observe)); XCTFail() } catch {}
        try await service.close(); try await legacy.close()
    }
    func testAccessDoesNotKeepAnUnstartedServiceAlive() async throws {
        let f = try AuthorityWakeSettingsTests.Fixture()
        let binding = try GatewaySettingsControlBinding(accountID: f.h.registration.accountID, rootEpoch: f.h.clock)
        var service: AuthorityWakeService? = try f.service([.init()], binding: binding)
        final class WeakService { weak var value: AuthorityWakeService?; init(_ service: AuthorityWakeService?) { value = service } }
        let released = WeakService(service)
        let access = try AuthorityGatewaySettingsAccess(service: XCTUnwrap(service), binding: binding, verifyCurrent: {})
        service = nil; XCTAssertNil(released.value)
        do { _ = try await access.execute(request(.observe, binding: binding)); XCTFail() } catch {}
    }
}
