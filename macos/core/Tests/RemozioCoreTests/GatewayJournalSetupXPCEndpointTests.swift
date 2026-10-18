import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayJournalSetupXPCEndpointTests: XCTestCase, @unchecked Sendable {
    private static let id = Data(repeating: 1, count: 16)
    private static let digest = Data(repeating: 2, count: 32)
    private static let challenge = Data(repeating: 3, count: 32)
    private final class State: Sendable {
        struct Value { var allowed = true; var verified = 0; var handled = 0; var closed = 0 }
        let value = Mutex(Value())
    }
    private func endpoint(_ state: State, budget: AuthorityXPCWorkBudget? = nil,
                          execute: (@Sendable () async throws -> Data)? = nil) throws -> GatewayJournalSetupXPCEndpoint {
        try GatewayJournalSetupXPCEndpoint(intentID: Self.id, scopeDigest: Self.digest, verify: {
            try state.value.withLock { value in
                value.verified += 1
                guard value.allowed else { throw GatewayServiceError.wrongAccount }
            }
        }, budget: budget ?? AuthorityXPCWorkBudget(maximum: 1), invalidate: { state.value.withLock { $0.closed += 1 } },
            execute: execute ?? {
                state.value.withLock { $0.handled += 1 }
                return try GatewayJournalSetupReport(intentID: Self.id, scopeDigest: Self.digest, created: true).encoded
            })
    }
    private actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        func run(started: XCTestExpectation) async {
            await withCheckedContinuation { continuation in self.continuation = continuation; started.fulfill() }
        }
        func release() { continuation?.resume(); continuation = nil }
    }
    func testRequiresHandshakeAndRechecksInvocationIdentity() throws {
        let state = State(), first = try endpoint(state)
        first.prepare(Self.digest, challenge: Self.challenge) { XCTAssertNil($0) }
        XCTAssertEqual(state.value.withLock { $0.handled }, 0)
        XCTAssertEqual(state.value.withLock { $0.closed }, 1)
        let secondState = State(), second = try endpoint(secondState)
        second.hello { XCTAssertEqual($0, 1) }
        secondState.value.withLock { $0.allowed = false }
        second.prepare(Self.digest, challenge: Self.challenge) { XCTAssertNil($0) }
        XCTAssertEqual(secondState.value.withLock { $0.verified }, 2)
        XCTAssertEqual(secondState.value.withLock { $0.handled }, 0)
    }
    func testAllowsOneOperationAndBindsItsReplyToTheIntentAndFreshChallenge() async throws {
        let state = State(), endpoint = try endpoint(state), response = Mutex<Data?>(nil)
        endpoint.hello { XCTAssertEqual($0, 1) }
        let done = expectation(description: "prepared")
        endpoint.prepare(Self.digest, challenge: Self.challenge) { value in response.withLock { $0 = value }; done.fulfill() }
        await fulfillment(of: [done], timeout: 2)
        let bytes = try XCTUnwrap(response.withLock { $0 })
        let report = try GatewayJournalSetupResponse.decode(bytes, challenge: Self.challenge, intentID: Self.id, scopeDigest: Self.digest)
        XCTAssertTrue(report.created)
        XCTAssertThrowsError(try GatewayJournalSetupResponse.decode(bytes, challenge: Data(repeating: 4, count: 32), intentID: Self.id, scopeDigest: Self.digest))
        XCTAssertThrowsError(try GatewayJournalSetupResponse.decode(bytes, challenge: Self.challenge, intentID: Data(repeating: 4, count: 16), scopeDigest: Self.digest))
        endpoint.prepare(Self.digest, challenge: Self.challenge) { XCTAssertNil($0) }
        XCTAssertEqual(state.value.withLock { $0.handled }, 1)
        endpoint.close(); XCTAssertEqual(state.value.withLock { $0.closed }, 1)
    }
    func testWrongScopeAndMalformedChallengesCannotAcquireOrReleaseAnotherOperationBudget() throws {
        for mode in 0...3 {
            let state = State(), budget = try AuthorityXPCWorkBudget(maximum: 1), endpoint = try endpoint(state, budget: budget)
            endpoint.hello { XCTAssertEqual($0, 1) }
            XCTAssertTrue(budget.acquire())
            let digest = mode == 0 ? Data(repeating: 9, count: 32) : Self.digest
            let challenge = mode == 1 ? Data(repeating: 9, count: 31) : mode == 2 ? Data(repeating: 9, count: 33) : Self.challenge
            endpoint.prepare(digest, challenge: challenge) { XCTAssertNil($0) }
            XCTAssertEqual(state.value.withLock { $0.handled }, 0)
            XCTAssertFalse(budget.acquire()); budget.release()
            XCTAssertTrue(budget.acquire()); budget.release()
        }
    }
    func testWrongOrMalformedInitializerReportsCannotBecomeSuccessfulReplies() async throws {
        for mode in 0...2 {
            let state = State(), budget = try AuthorityXPCWorkBudget(maximum: 1)
            let endpoint = try endpoint(state, budget: budget, execute: {
                if mode == 0 { return Data(repeating: 0, count: 513) }
                return try GatewayJournalSetupReport(intentID: mode == 1 ? Data(repeating: 9, count: 16) : Self.id,
                    scopeDigest: mode == 2 ? Data(repeating: 9, count: 32) : Self.digest, created: false).encoded
            })
            endpoint.hello { XCTAssertEqual($0, 1) }
            let done = expectation(description: "rejected")
            endpoint.prepare(Self.digest, challenge: Self.challenge) { XCTAssertNil($0); done.fulfill() }
            await fulfillment(of: [done], timeout: 2)
            XCTAssertTrue(budget.acquire()); budget.release(); endpoint.close()
        }
    }
    func testConnectionLossSuppressesLateReplyAndRetainsBudgetUntilWorkEnds() async throws {
        let state = State(), budget = try AuthorityXPCWorkBudget(maximum: 1), gate = Gate()
        let started = expectation(description: "started"), late = expectation(description: "late response")
        late.isInverted = true
        let endpoint = try endpoint(state, budget: budget, execute: {
            await gate.run(started: started)
            return try GatewayJournalSetupReport(intentID: Self.id, scopeDigest: Self.digest, created: true).encoded
        })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.prepare(Self.digest, challenge: Self.challenge) { _ in late.fulfill() }
        await fulfillment(of: [started], timeout: 2)
        XCTAssertFalse(budget.acquire()); endpoint.close(); endpoint.close()
        XCTAssertFalse(budget.acquire()); await gate.release()
        await fulfillment(of: [late], timeout: 0.1)
        XCTAssertTrue(budget.acquire()); budget.release()
        XCTAssertEqual(state.value.withLock { $0.closed }, 1)
    }
    func testRepeatedHandshakeRefusesWithoutStartingInitialization() throws {
        let state = State(), endpoint = try endpoint(state)
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.hello { XCTAssertEqual($0, 0) }
        endpoint.prepare(Self.digest, challenge: Self.challenge) { XCTAssertNil($0) }
        XCTAssertEqual(state.value.withLock { $0.handled }, 0)
        XCTAssertEqual(state.value.withLock { $0.closed }, 1)
    }
    func testResponseCodecRejectsUnknownVersionsUnknownFieldsAndOversizeInput() throws {
        let report = try GatewayJournalSetupReport(intentID: Self.id, scopeDigest: Self.digest, created: true).encoded
        let limits = try CBORLimits(maxBytes: 2048, maxDepth: 2, maxItems: 16)
        for fields: [UInt64: CBORValue] in [
            [0: .unsigned(2), 1: .bytes(Self.challenge), 2: .bytes(report)],
            [0: .unsigned(1), 1: .bytes(Self.challenge), 2: .bytes(report), 3: .boolean(true)]
        ] {
            let bytes = try DeterministicCBOR.encode(.map(fields), limits: limits)
            XCTAssertThrowsError(try GatewayJournalSetupResponse.decode(bytes, challenge: Self.challenge, intentID: Self.id, scopeDigest: Self.digest))
        }
        XCTAssertThrowsError(try GatewayJournalSetupResponse.decode(Data(repeating: 0, count: 1025), challenge: Self.challenge, intentID: Self.id, scopeDigest: Self.digest))
    }
}
