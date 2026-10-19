import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsConsumerEndpointTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private let fixture = try! GatewaySettingsConsumerControlFixture()
    private func request(_ action: GatewaySettingsControlAction = .quiesce) throws -> GatewaySettingsConsumerRequest {
        try .init(binding: fixture.binding(), fence: fixture.fence, action: action, challenge: Data(repeating: 5, count: 32))
    }
    private func hello(_ endpoint: GatewaySettingsConsumerXPCEndpoint, binding: GatewaySettingsConsumerBinding) {
        endpoint.hello { version, bytes in
            XCTAssertEqual(version, 1); XCTAssertEqual(try? bytes.map(GatewaySettingsConsumerBinding.decode), binding)
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
        let endpoint = GatewaySettingsConsumerXPCEndpoint(binding: request.binding, verify: {
            XCTAssertEqual(Thread.current.threadDictionary["remozio-consumer-invocation"] as? Bool, true)
            verifications.withLock { $0 += 1 }
        }, verifyCurrent: {}, budget: try .init(maximum: 1), invalidate: {}, execute: { received in
            XCTAssertEqual(try received.encoded, try request.encoded); executions.withLock { $0 += 1 }; return .paused
        })
        defer { endpoint.close() }
        func invoke(_ body: () throws -> Void) rethrows {
            Thread.current.threadDictionary["remozio-consumer-invocation"] = true
            defer { Thread.current.threadDictionary.removeObject(forKey: "remozio-consumer-invocation") }
            try body()
        }
        try invoke {
            hello(endpoint, binding: request.binding)
            endpoint.control(try request.encoded) { bytes in reply.withLock { $0 = bytes } }
        }; try await waitUntil { reply.withLock { $0 != nil } }
        XCTAssertEqual(verifications.withLock { $0 }, 2); XCTAssertEqual(executions.withLock { $0 }, 1)
        XCTAssertEqual(try GatewaySettingsConsumerResponse.decode(XCTUnwrap(reply.withLock { $0 }), expected: request).observation, .paused)
        try invoke { endpoint.control(try request.encoded) { XCTAssertNil($0) } }
        XCTAssertEqual(verifications.withLock { $0 }, 3); XCTAssertEqual(executions.withLock { $0 }, 1)
    }
    func testMissingHandshakeWrongBindingsAndRepeatedHelloCannotStartWork() throws {
        let request = try request(), executions = Mutex(0)
        for mode in 0..<3 {
            let endpoint = GatewaySettingsConsumerXPCEndpoint(binding: request.binding, verify: {}, verifyCurrent: {},
                budget: try .init(maximum: 1), invalidate: {}, execute: { _ in executions.withLock { $0 += 1 }; return .paused })
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
        let endpoint = GatewaySettingsConsumerXPCEndpoint(binding: request.binding, verify: {
            if reject.withLock({ $0 }) { throw Denied() }
        }, verifyCurrent: {}, budget: budget, invalidate: {}, execute: { _ in XCTFail(); return .paused })
        hello(endpoint, binding: request.binding); reject.withLock { $0 = true }
        endpoint.control(try request.encoded) { XCTAssertNil($0) }
        XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testDisconnectRetainsTheBudgetAndReleaseLeaseUntilAdmittedWorkActuallySettles() async throws {
        let request = try request(), fixture = try ReleaseActivityFixture(), activity = try fixture.open(), installer = try fixture.open()
        let budget = try AuthorityXPCWorkBudget(maximum: 1), gate = Mutex<CheckedContinuation<Void, Never>?>(nil), replied = Mutex(false)
        let endpoint = GatewaySettingsConsumerXPCEndpoint(binding: request.binding, verify: {}, verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: budget, invalidate: {}, execute: { _ in
                await withCheckedContinuation { continuation in gate.withLock { $0 = continuation } }
                return .paused
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
        let endpoint = GatewaySettingsConsumerXPCEndpoint(binding: request.binding, verify: {}, verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: try .init(maximum: 1), invalidate: {}, execute: { _ in .paused })
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
            let endpoint = GatewaySettingsConsumerXPCEndpoint(binding: request.binding, verify: {}, verifyCurrent: {
                guard valid.withLock({ $0 }) else { throw Denied() }
            }, budget: budget, invalidate: {}, execute: { _ in
                if !invalidStage { valid.withLock { $0 = false } }
                return invalidStage ? .quiescing : .paused
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
        for bytes in [Data(), Data(repeating: 0, count: 769), try request.encoded + Data([0])] {
            let endpoint = GatewaySettingsConsumerXPCEndpoint(binding: request.binding, verify: {}, verifyCurrent: {},
                budget: try .init(maximum: 1), invalidate: {}, execute: { _ in executions.withLock { $0 += 1 }; return .paused })
            hello(endpoint, binding: request.binding); endpoint.control(bytes) { XCTAssertNil($0) }; endpoint.close()
        }
        XCTAssertEqual(executions.withLock { $0 }, 0)
    }
}
