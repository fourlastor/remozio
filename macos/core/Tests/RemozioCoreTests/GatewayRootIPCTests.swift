import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayRootIPCTests: XCTestCase, @unchecked Sendable {
    private final class State: Sendable {
        struct Value { var verified = 0; var closed = 0; var handled = 0; var allowed = true }
        let value = Mutex(Value())
    }
    private func snapshot(sequence: UInt64 = 1, phones: [UInt8] = [2, 1]) throws -> GatewayHostSnapshot {
        let id = Data(repeating: 1, count: 16)
        let registration = try GatewayRegistrationIdentity(ownerID: id, macID: id, accountID: id, gatewayID: id,
            lifecycleEpoch: id, rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        return try GatewayHostSnapshot(registration: registration, rootEpoch: UUID(), sequence: sequence, observedAtMilliseconds: 100,
            leaseDeadlineMilliseconds: 200, enrollments: phones.map {
                try GatewayPhoneEnrollment(phoneID: Data(repeating: $0, count: 16), epoch: Data(repeating: 3, count: 16),
                    tag: Data(repeating: 4, count: 32), active: true)
            }, active: true, phoneRouting: true)
    }
    func testSnapshotRejectsUnknownFieldsVersionsDuplicatesAndUnsortedEnrollments() throws {
        let original = try snapshot()
        let decoded = try GatewayHostSnapshot.decode(original.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
        XCTAssertEqual(decoded.enrollments.first?.phoneID, Data(repeating: 1, count: 16))
        XCTAssertThrowsError(try snapshot(sequence: 0))
        XCTAssertThrowsError(try snapshot(phones: [1, 1]))
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: GatewayHostSnapshot.limits) else { return XCTFail() }
        var changes: [[UInt64: CBORValue]] = []
        var next = fields; next[0] = .unsigned(2); changes.append(next)
        next = fields; next[9] = .boolean(true); changes.append(next)
        next = fields; next[1] = .bytes(Data(repeating: 1, count: 15)); changes.append(next)
        if case .array(let phones) = fields[5] { next = fields; next[5] = .array(phones.reversed()); changes.append(next) }
        for changed in changes {
            XCTAssertThrowsError(try GatewayHostSnapshot.decode(DeterministicCBOR.encode(.map(changed), limits: GatewayHostSnapshot.limits)))
        }
    }
    func testCommandRoundTripKeepsOriginalWakeScopeAndTimes() throws {
        let delivery = PhoneRequestDelivery(id: UUID(), recipient: DeliveryRecipient(phoneID: Data(repeating: 1, count: 16),
            enrollmentEpoch: Data(repeating: 2, count: 16)), requestID: Data(repeating: 3, count: 16),
            admittedAt: AuthorityMoment(epoch: UUID(), milliseconds: 100), deadlineMilliseconds: 200)
        let encoded = try GatewayRootCommand.wake(delivery).encode()
        guard case .wake(let result) = try GatewayRootCommand.decode(encoded) else { return XCTFail() }
        XCTAssertEqual(result, delivery)
        XCTAssertThrowsError(try GatewayRootCommand.probe(operationID: Data(), phoneID: Data(repeating: 1, count: 16)).encode())
        XCTAssertThrowsError(try GatewayRootCommand.head(Data(repeating: 1, count: 1025)).encode())
        for fields: [CBORValue] in [[.unsigned(2), .unsigned(0), .bytes(Data([1]))],
                                   [.unsigned(1), .unsigned(99), .bytes(Data([1]))],
                                   [.unsigned(1), .unsigned(0), .bytes(Data([1])), .null]] {
            XCTAssertThrowsError(try GatewayRootCommand.decode(DeterministicCBOR.encode(.array(fields), limits: GatewayRootCommand.limits)))
        }
    }
    private func endpoint(_ state: State, budget: AuthorityXPCWorkBudget? = nil,
                          execute: (@Sendable (GatewayRootCommand) async throws -> Data)? = nil) throws -> GatewayXPCEndpoint {
        GatewayXPCEndpoint(verify: {
            try state.value.withLock { value in
                value.verified += 1
                guard value.allowed else { throw GatewayServiceError.wrongAccount }
            }
        }, budget: try budget ?? AuthorityXPCWorkBudget(maximum: 1), invalidate: {
            state.value.withLock { $0.closed += 1 }
        }, synchronize: { _ in state.value.withLock { $0.handled += 1 } }, execute: execute ?? { _ in
            state.value.withLock { $0.handled += 1 }; return Data([1])
        })
    }
    func testRejectedOptionalInnerQueryDoesNotCloseTheAuthenticatedEndpoint() async throws {
        let state = State(), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let endpoint = try endpoint(state, budget: budget, execute: { command in
            guard case .head(let query) = command else { throw GatewayServiceError.invalidMessage }
            state.value.withLock { $0.handled += 1 }
            if query == Data([2]) { throw GatewayHeadReplyError.unsupportedVersion }
            return Data([1])
        })
        endpoint.hello { XCTAssertEqual($0, 3) }
        let rejected = expectation(description: "optional query rejected")
        endpoint.command(try GatewayRootCommand.head(Data([2])).encode()) { XCTAssertNil($0); rejected.fulfill() }
        await fulfillment(of: [rejected], timeout: 2)
        let accepted = expectation(description: "legacy command remains usable")
        endpoint.command(try GatewayRootCommand.head(Data([1])).encode()) { XCTAssertEqual($0, Data([1])); accepted.fulfill() }
        await fulfillment(of: [accepted], timeout: 2)
        XCTAssertEqual(state.value.withLock { $0.closed }, 0)
        XCTAssertEqual(state.value.withLock { $0.handled }, 2)
        XCTAssertTrue(budget.acquire()); budget.release(); endpoint.close()
    }
    func testRejectsSensitiveCallsBeforeHandshakeWithoutRunningHandler() throws {
        let state = State(), endpoint = try endpoint(state)
        endpoint.synchronize(try snapshot().canonicalBytes) { XCTAssertFalse($0) }
        XCTAssertEqual(state.value.withLock { $0.verified }, 1)
        XCTAssertEqual(state.value.withLock { $0.handled }, 0)
        XCTAssertEqual(state.value.withLock { $0.closed }, 1)
    }
    func testRechecksInvocationAfterHelloBeforeAsynchronousWork() async throws {
        let state = State(), endpoint = try endpoint(state)
        endpoint.hello { XCTAssertEqual($0, 3) }
        let done = expectation(description: "synchronized")
        endpoint.synchronize(try snapshot().canonicalBytes) { XCTAssertTrue($0); done.fulfill() }
        await fulfillment(of: [done], timeout: 2)
        XCTAssertEqual(state.value.withLock { $0.verified }, 2)
        XCTAssertEqual(state.value.withLock { $0.handled }, 1)
        state.value.withLock { $0.allowed = false }
        endpoint.command(try GatewayRootCommand.head(Data([1])).encode()) { XCTAssertNil($0) }
        XCTAssertEqual(state.value.withLock { $0.verified }, 3)
        XCTAssertEqual(state.value.withLock { $0.handled }, 1)
        XCTAssertEqual(state.value.withLock { $0.closed }, 1)
    }
    private actor Gate {
        private var continuation: CheckedContinuation<Data, Never>?
        func run(started: XCTestExpectation) async -> Data {
            await withCheckedContinuation { continuation in self.continuation = continuation; started.fulfill() }
        }
        func release() { continuation?.resume(returning: Data([1])); continuation = nil }
    }
    func testDisconnectSuppressesLateReplyAndReleasesSharedWorkBudget() async throws {
        let state = State(), gate = Gate(), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let started = expectation(description: "started"), late = expectation(description: "no late success")
        late.isInverted = true
        let endpoint = try endpoint(state, budget: budget, execute: { _ in await gate.run(started: started) })
        endpoint.hello { XCTAssertEqual($0, 3) }
        endpoint.command(try GatewayRootCommand.head(Data([1])).encode()) { _ in late.fulfill() }
        await fulfillment(of: [started], timeout: 2)
        XCTAssertFalse(budget.acquire())
        endpoint.close(); endpoint.close()
        await gate.release()
        await fulfillment(of: [late], timeout: 0.1)
        XCTAssertEqual(state.value.withLock { $0.closed }, 1)
        XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testSubmissionRequiresVersionTwoAndExactBoundedFields() throws {
        let command = GatewayRootCommand.submission(payload: Data([1]), signature: Data(repeating: 2, count: 64), wireVersion: 1)
        let encoded = try command.encode()
        XCTAssertEqual(command.protocolVersion, 2)
        guard case .submission(let payload, let signature, let wireVersion) = try GatewayRootCommand.decode(encoded) else { return XCTFail() }
        XCTAssertEqual(payload, Data([1])); XCTAssertEqual(signature.count, 64); XCTAssertEqual(wireVersion, 1)
        for fields: [CBORValue] in [
            [.unsigned(1), .unsigned(7), .bytes(payload), .bytes(signature), .unsigned(1)],
            [.unsigned(3), .unsigned(7), .bytes(payload), .bytes(signature), .unsigned(1)],
            [.unsigned(2), .unsigned(7), .bytes(payload), .bytes(Data(repeating: 2, count: 63)), .unsigned(1)],
            [.unsigned(2), .unsigned(7), .bytes(payload), .bytes(signature), .unsigned(1), .null]
        ] {
            XCTAssertThrowsError(try GatewayRootCommand.decode(DeterministicCBOR.encode(.array(fields), limits: GatewayRootCommand.limits)))
        }
    }

    func testRootDeliveryRegistrationRequiresVersionThree() throws {
        let delivery = PhoneRequestDelivery(id: UUID(), recipient: DeliveryRecipient(phoneID: Data(repeating: 1, count: 16),
            enrollmentEpoch: Data(repeating: 2, count: 16)), requestID: Data(repeating: 3, count: 16),
            admittedAt: AuthorityMoment(epoch: UUID(), milliseconds: 100), deadlineMilliseconds: 200)
        let command = GatewayRootCommand.registerWake(delivery)
        XCTAssertEqual(command.protocolVersion, 3)
        guard case .registerWake(let decoded) = try GatewayRootCommand.decode(command.encode()) else { return XCTFail() }
        XCTAssertEqual(decoded, delivery)
        guard case .array(var fields) = try DeterministicCBOR.decode(command.encode(), limits: GatewayRootCommand.limits) else { return XCTFail() }
        for version: UInt64 in [0, 1, 2, 4] {
            fields[0] = .unsigned(version)
            XCTAssertThrowsError(try GatewayRootCommand.decode(DeterministicCBOR.encode(.array(fields), limits: GatewayRootCommand.limits)))
        }
    }

}
