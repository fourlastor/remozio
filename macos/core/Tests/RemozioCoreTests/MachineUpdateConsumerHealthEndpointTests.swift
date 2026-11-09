import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

enum MachineUpdateOwnedHealthFailure: Error { case denied, timeout, closeFailed }

final class MachineUpdateOwnedHealthAnswerer: MachineUpdateConsumerHealthAnswering, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let answerOperation: @Sendable (Data) throws -> Data
    private let closeOperation: @Sendable () throws -> Void
    private var closed = false
    let answers = Mutex(0)
    let closeAttempts = Mutex(0)
    var isClosed: Bool { lock.withLock { closed } }
    init(answer: @escaping @Sendable (Data) throws -> Data, close: @escaping @Sendable () throws -> Void = {}) {
        answerOperation = answer; closeOperation = close
    }
    func answer(_ bytes: Data) throws -> Data {
        try lock.withLock {
            guard !closed else { throw MachineUpdateOwnedHealthFailure.denied }
            answers.withLock { $0 += 1 }; return try answerOperation(bytes)
        }
    }
    func close() throws {
        try lock.withLock {
            guard !closed else { return }
            closeAttempts.withLock { $0 += 1 }; try closeOperation(); closed = true
        }
    }
}

final class MachineUpdateOwnedHealthEndpointFixture: @unchecked Sendable {
    let challenge: MachineUpdateRoleChallengeTests.Fixture
    let requirement: MachineUpdateRestartHealthPlan.Requirement
    let hello = Data("synthetic-health-bootstrap".utf8)
    init() throws {
        let challenge = MachineUpdateRoleChallengeTests.Fixture()
        self.challenge = challenge
        requirement = try challenge.requirement(role: .transport, uid: 20000)
    }
    func peer(authenticate: @escaping @Sendable () throws -> Void = {},
        verify: @escaping @Sendable () throws -> Void = {}) -> MachineUpdateConsumerHealthPeer {
        .owned(expected: requirement, authenticateInvocation: authenticate, verifyPeer: {}, verifyCurrent: verify)
    }
    func session() throws -> MachineUpdateRoleChallengeSession {
        try .init(requirement: requirement, verifyCurrent: {})
    }
    func owner(close: @escaping @Sendable () throws -> Void = {}) -> MachineUpdateOwnedHealthAnswerer {
        .init(answer: { [self] in try challenge.answer($0, expected: requirement) }, close: close)
    }
}

final class MachineUpdateConsumerHealthEndpointTests: XCTestCase, @unchecked Sendable {
    private final class TestState<Value: Sendable>: Sendable {
        let lock: Mutex<Value>
        init(_ value: Value) { lock = Mutex(value) }
    }

    private func waitUntil(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !condition() {
            guard ContinuousClock.now < deadline else { throw MachineUpdateOwnedHealthFailure.timeout }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    private func hello(_ endpoint: MachineUpdateConsumerHealthXPCEndpoint, fixture: MachineUpdateOwnedHealthEndpointFixture) {
        endpoint.healthHello { version, bytes in XCTAssertEqual(version, 1); XCTAssertEqual(bytes, fixture.hello) }
    }
    private func installedPacket(_ request: MachineUpdateConsumerHealthRequest,
        fixture: MachineUpdateOwnedHealthEndpointFixture) throws -> Data {
        try request.claim(); try request.validate()
        return try MachineUpdateConsumerHealthPacket(
            roleReply: fixture.challenge.answer(request.bytes, expected: fixture.requirement), gatewayHead: nil).encoded
    }
    func testInstalledCallbackAuthenticatesBothInvocationsBeforeUsingTheRuntime() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture(), activity = try files.open()
        let authentications = TestState(0), callbacks = TestState(0), response = TestState<Data?>(nil)
        let peer = fixture.peer(authenticate: {
            XCTAssertEqual(Thread.current.threadDictionary["remozio-installed-invocation"] as? Bool, true)
            authentications.lock.withLock { $0 += 1 }
        })
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: peer, helloBytes: fixture.hello,
            verifyCurrent: {}, acquireActivity: { try activity.acquireShared() }, budget: try .init(maximum: 1),
            invalidate: {}, answerInstalledReadiness: { request in
                XCTAssertEqual(authentications.lock.withLock { $0 }, 2)
                callbacks.lock.withLock { $0 += 1 }; return try self.installedPacket(request, fixture: fixture)
            })
        let session = try fixture.session()
        func invoke(_ body: () throws -> Void) rethrows {
            Thread.current.threadDictionary["remozio-installed-invocation"] = true
            defer { Thread.current.threadDictionary.removeObject(forKey: "remozio-installed-invocation") }
            try body()
        }
        try invoke {
            hello(endpoint, fixture: fixture)
            endpoint.checkUpdateHealth(try session.request) { bytes in response.lock.withLock { $0 = bytes } }
        }
        try await waitUntil { response.lock.withLock { $0 != nil } }
        let packet = try MachineUpdateConsumerHealthPacket.decode(XCTUnwrap(response.lock.withLock { $0 }))
        XCTAssertNil(packet.gatewayHead)
        XCTAssertEqual(try session.accept(packet.roleReply, authenticatePeer: { _ in }).requirement, fixture.requirement)
        XCTAssertEqual(callbacks.lock.withLock { $0 }, 1)
        try await endpoint.closeAndWait()
    }
    func testInstalledReplyCannotAnswerAnotherRequestOrReplayItsPacket() throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture()
        let session = try fixture.session(), bytes = try session.request
        let peer = fixture.peer(), request = try peer.accept(bytes)
        defer { peer.close() }
        let packet = try installedPacket(request, fixture: fixture)
        let once = try MachineUpdateInstalledReadinessReply(request: request, packet: packet)
        XCTAssertEqual(try once.answer(bytes), packet)
        XCTAssertThrowsError(try once.answer(bytes))
        let otherBytes = try fixture.session().request
        let otherPeer = fixture.peer(), otherRequest = try otherPeer.accept(otherBytes)
        defer { otherPeer.close() }
        XCTAssertThrowsError(try MachineUpdateInstalledReadinessReply(request: otherRequest, packet: packet)) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .invalidMessage)
        }
        let mismatch = try MachineUpdateInstalledReadinessReply(request: request, packet: packet)
        XCTAssertThrowsError(try mismatch.answer(otherBytes))
        XCTAssertThrowsError(try mismatch.answer(bytes))
        let closed = try MachineUpdateInstalledReadinessReply(request: request, packet: packet)
        closed.close(); XCTAssertThrowsError(try closed.answer(bytes))
    }
    func testInstalledReplyRejectsMalformedPacketsAndRevokedRequests() throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), session = try fixture.session()
        let peer = fixture.peer(), request = try peer.accept(session.request)
        XCTAssertThrowsError(try MachineUpdateInstalledReadinessReply(request: request, packet: Data([0])))
        let packet = try installedPacket(request, fixture: fixture)
        let reply = try MachineUpdateInstalledReadinessReply(request: request, packet: packet)
        peer.close(); XCTAssertThrowsError(try reply.answer(request.bytes))
        XCTAssertThrowsError(try MachineUpdateInstalledReadinessReply(request: request, packet: packet))
    }
    func testInstalledCallbackCannotRunAfterInvocationAuthenticationFails() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture(), activity = try files.open()
        let allowed = TestState(true), callbacks = TestState(0), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(authenticate: {
            guard allowed.lock.withLock({ $0 }) else { throw MachineUpdateOwnedHealthFailure.denied }
        }), helloBytes: fixture.hello, verifyCurrent: {}, acquireActivity: { try activity.acquireShared() },
            budget: budget, invalidate: {}, answerInstalledReadiness: { request in
                callbacks.lock.withLock { $0 += 1 }; return try self.installedPacket(request, fixture: fixture)
            })
        hello(endpoint, fixture: fixture); allowed.lock.withLock { $0 = false }
        endpoint.checkUpdateHealth(try fixture.session().request) { XCTAssertNil($0) }
        try await endpoint.closeAndWait()
        XCTAssertEqual(callbacks.lock.withLock { $0 }, 0); XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testInstalledDisconnectJoinsTheRuntimeCallbackBeforeReleasingActivity() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture()
        let activity = try files.open(), installer = try files.open(), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let gate = TestState<CheckedContinuation<Void, Never>?>(nil), replied = TestState(false), joined = TestState(false)
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello,
            verifyCurrent: {}, acquireActivity: { try activity.acquireShared() }, budget: budget, invalidate: {},
            answerInstalledReadiness: { request in
                let packet = try self.installedPacket(request, fixture: fixture)
                await withCheckedContinuation { continuation in gate.lock.withLock { $0 = continuation } }
                return packet
            })
        defer { gate.lock.withLock { let old = $0; $0 = nil; old?.resume() }; endpoint.close() }
        hello(endpoint, fixture: fixture)
        endpoint.checkUpdateHealth(try fixture.session().request) { _ in replied.lock.withLock { $0 = true } }
        try await waitUntil { gate.lock.withLock { $0 != nil } }; endpoint.close()
        let joining = Task { try await endpoint.closeAndWait(); joined.lock.withLock { $0 = true } }
        try await Task.sleep(for: .milliseconds(25))
        XCTAssertFalse(joined.lock.withLock { $0 }); XCTAssertFalse(budget.acquire())
        XCTAssertThrowsError(try installer.acquireExclusive())
        gate.lock.withLock { let old = $0; $0 = nil; old?.resume() }; try await joining.value
        XCTAssertTrue(joined.lock.withLock { $0 }); XCTAssertFalse(replied.lock.withLock { $0 })
        let exclusive = try installer.acquireExclusive(); exclusive.close()
        XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testInstalledCallbackResultIsDiscardedWhenItsScopeChanges() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture(), activity = try files.open()
        let valid = TestState(true), responses = TestState(0)
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello, verifyCurrent: {
            guard valid.lock.withLock({ $0 }) else { throw MachineUpdateOwnedHealthFailure.denied }
        }, acquireActivity: { try activity.acquireShared() }, budget: try .init(maximum: 1), invalidate: {},
            answerInstalledReadiness: { request in
                let packet = try self.installedPacket(request, fixture: fixture)
                valid.lock.withLock { $0 = false }; return packet
            })
        hello(endpoint, fixture: fixture)
        endpoint.checkUpdateHealth(try fixture.session().request) { bytes in
            XCTAssertNil(bytes); responses.lock.withLock { $0 += 1 }
        }
        try await waitUntil { responses.lock.withLock { $0 == 1 } }; try await endpoint.closeAndWait()
    }

    func testBothInvocationsAuthenticateBeforeTheOwnerOpens() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture(), activity = try files.open()
        let authentications = TestState(0), opens = TestState(0), answer = TestState<Data?>(nil), owner = fixture.owner()
        let peer = fixture.peer(authenticate: {
            XCTAssertEqual(Thread.current.threadDictionary["remozio-health-invocation"] as? Bool, true)
            authentications.lock.withLock { $0 += 1 }
        })
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: peer, helloBytes: fixture.hello, verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: try .init(maximum: 1), invalidate: {}, makeOwner: { request in
                try request.claim(); opens.lock.withLock { $0 += 1 }; return owner
            })
        let session = try fixture.session()
        func invoke(_ body: () throws -> Void) rethrows {
            Thread.current.threadDictionary["remozio-health-invocation"] = true
            defer { Thread.current.threadDictionary.removeObject(forKey: "remozio-health-invocation") }
            try body()
        }
        try invoke {
            hello(endpoint, fixture: fixture)
            endpoint.checkUpdateHealth(try session.request) { bytes in answer.lock.withLock { $0 = bytes } }
        }
        try await waitUntil { answer.lock.withLock { $0 != nil } }
        XCTAssertEqual(try session.accept(XCTUnwrap(answer.lock.withLock { $0 }), authenticatePeer: { _ in }).requirement, fixture.requirement)
        XCTAssertEqual(authentications.lock.withLock { $0 }, 2); XCTAssertEqual(opens.lock.withLock { $0 }, 1)
        XCTAssertTrue(owner.isClosed); try await endpoint.closeAndWait()
    }
    func testMissingOrRepeatedHandshakeCannotOpenAnOwner() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture(), activity = try files.open(), opens = TestState(0)
        for repeated in [false, true] {
            let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello, verifyCurrent: {},
                acquireActivity: { try activity.acquireShared() }, budget: try .init(maximum: 1), invalidate: {}, makeOwner: { _ in
                    opens.lock.withLock { $0 += 1 }; return fixture.owner()
                })
            if repeated {
                hello(endpoint, fixture: fixture)
                endpoint.healthHello { version, bytes in XCTAssertEqual(version, 0); XCTAssertNil(bytes) }
            }
            endpoint.checkUpdateHealth(try fixture.session().request) { XCTAssertNil($0) }
            try await endpoint.closeAndWait()
        }
        XCTAssertEqual(opens.lock.withLock { $0 }, 0)
    }
    func testRejectedInvocationCannotParseOrConsumeTheWorkBudget() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture(), activity = try files.open()
        let denied = TestState(false), opens = TestState(0), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(authenticate: {
            if denied.lock.withLock({ $0 }) { throw MachineUpdateOwnedHealthFailure.denied }
        }), helloBytes: fixture.hello, verifyCurrent: {}, acquireActivity: { try activity.acquireShared() }, budget: budget,
            invalidate: {}, makeOwner: { _ in opens.lock.withLock { $0 += 1 }; return fixture.owner() })
        hello(endpoint, fixture: fixture); denied.lock.withLock { $0 = true }
        let rejected = fixture.peer(authenticate: { throw MachineUpdateOwnedHealthFailure.denied })
        XCTAssertThrowsError(try rejected.accept(Data([0]))) {
            guard case .denied? = $0 as? MachineUpdateOwnedHealthFailure else { return XCTFail("Payload parsed before authentication") }
        }
        endpoint.checkUpdateHealth(Data([0])) { XCTAssertNil($0) }
        try await endpoint.closeAndWait()
        XCTAssertEqual(opens.lock.withLock { $0 }, 0); XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testDisconnectJoinsAFactoryThatIgnoresCancellation() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture()
        let activity = try files.open(), installer = try files.open(), owner = fixture.owner(), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let gate = TestState<CheckedContinuation<Void, Never>?>(nil), replied = TestState(false), joined = TestState(false)
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello, verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: budget, invalidate: {}, makeOwner: { _ in
                await withCheckedContinuation { continuation in gate.lock.withLock { $0 = continuation } }; return owner
            })
        defer { gate.lock.withLock { let old = $0; $0 = nil; old?.resume() }; endpoint.close() }
        hello(endpoint, fixture: fixture); endpoint.checkUpdateHealth(try fixture.session().request) { _ in replied.lock.withLock { $0 = true } }
        try await waitUntil { gate.lock.withLock { $0 != nil } }; endpoint.close()
        let joining = Task { try await endpoint.closeAndWait(); joined.lock.withLock { $0 = true } }
        try await Task.sleep(for: .milliseconds(25))
        XCTAssertFalse(joined.lock.withLock { $0 }); XCTAssertFalse(budget.acquire()); XCTAssertThrowsError(try installer.acquireExclusive())
        gate.lock.withLock { let old = $0; $0 = nil; old?.resume() }; try await joining.value
        XCTAssertTrue(owner.isClosed); XCTAssertEqual(owner.answers.withLock { $0 }, 0); XCTAssertFalse(replied.lock.withLock { $0 })
        let exclusive = try installer.acquireExclusive(); exclusive.close(); XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testFailedOwnerCloseRetainsActivityAndBudgetUntilARetrySucceeds() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture()
        let activity = try files.open(), installer = try files.open(), allowed = TestState(false), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let owner = fixture.owner(close: { guard allowed.lock.withLock({ $0 }) else { throw MachineUpdateOwnedHealthFailure.closeFailed } })
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello, verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: budget, invalidate: {}, makeOwner: { _ in owner })
        hello(endpoint, fixture: fixture); endpoint.checkUpdateHealth(try fixture.session().request) { XCTFail("Failed cleanup cannot return a reply: \(String(describing: $0))") }
        try await waitUntil { owner.closeAttempts.withLock { $0 > 0 } }
        do { try await endpoint.closeAndWait(); XCTFail("The failed owner must remain retained") } catch {}
        XCTAssertFalse(budget.acquire()); XCTAssertThrowsError(try installer.acquireExclusive()); XCTAssertFalse(owner.isClosed)
        allowed.lock.withLock { $0 = true }; try await endpoint.closeAndWait()
        XCTAssertTrue(owner.isClosed); let exclusive = try installer.acquireExclusive(); exclusive.close()
        XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testChangedScopeAfterOpeningCannotReturnASuccessfulReply() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture(), activity = try files.open()
        let valid = TestState(true), replies = TestState(0), owner = fixture.owner()
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello, verifyCurrent: {
            guard valid.lock.withLock({ $0 }) else { throw MachineUpdateOwnedHealthFailure.denied }
        }, acquireActivity: { try activity.acquireShared() }, budget: try .init(maximum: 1), invalidate: {}, makeOwner: { _ in
            valid.lock.withLock { $0 = false }; return owner
        })
        hello(endpoint, fixture: fixture); endpoint.checkUpdateHealth(try fixture.session().request) { bytes in
            XCTAssertNil(bytes); replies.lock.withLock { $0 += 1 }
        }
        try await waitUntil { replies.lock.withLock { $0 == 1 } }; XCTAssertTrue(owner.isClosed)
        XCTAssertEqual(owner.answers.withLock { $0 }, 0); try await endpoint.closeAndWait()
    }
    func testReplyFollowsOwnerClosureAndActivityRelease() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture()
        let activity = try files.open(), installer = try files.open(), owner = fixture.owner(), replies = TestState(0)
        let budget = try AuthorityXPCWorkBudget(maximum: 1)
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello, verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: budget, invalidate: {}, makeOwner: { _ in owner })
        hello(endpoint, fixture: fixture); endpoint.checkUpdateHealth(try fixture.session().request) { bytes in
            XCTAssertNotNil(bytes); XCTAssertTrue(owner.isClosed)
            do { let exclusive = try installer.acquireExclusive(); exclusive.close() } catch { XCTFail("Activity remains held") }
            XCTAssertTrue(budget.acquire()); budget.release(); replies.lock.withLock { $0 += 1 }
        }
        try await waitUntil { replies.lock.withLock { $0 == 1 } }; try await endpoint.closeAndWait()
    }
    private final class HotGatewayStore: @unchecked Sendable {
        let fixture: MachineUpdateGatewayHealthOwnerTests.Fixture
        init(_ fixture: MachineUpdateGatewayHealthOwnerTests.Fixture) { self.fixture = fixture }
        func openForHealth() throws -> GatewayDatabase {
            let limits = try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128)
            return try GatewayDatabase(lease: fixture.files.lease(), identity: fixture.configuration.registration,
                payloadLimits: limits, signingLimits: limits, maximumOperations: 10, maximumPendingPerEnrollment: 2,
                maximumLifetimeMillis: 1000, clockEpoch: UUID(), busyMilliseconds: 100, initialize: false,
                readOnlyForUpdateHealth: true)
        }
    }

    func testEndpointReportsTheRealHotGatewayJournalWithoutChangingItsBytes() async throws {
        try await checkHotGatewayJournal(revokePeer: false)
    }

    func testEndpointSuppressesHotGatewaySignalWhenTheAdmittedPeerChanges() async throws {
        try await checkHotGatewayJournal(revokePeer: true)
    }

    private func checkHotGatewayJournal(revokePeer: Bool) async throws {
        let fixture = try MachineUpdateGatewayHealthOwnerTests.Fixture(ordinary: true)
        try fixture.database.close()
        let crashed = try fixture.files.plantHotJournal(), store = HotGatewayStore(fixture)
        let files = try ReleaseActivityFixture(), activity = try files.open(), replies = TestState(0)
        let currentPeer = TestState(true)
        let peer = MachineUpdateConsumerHealthPeer.owned(expected: fixture.requirement,
            authenticateInvocation: {}, verifyPeer: {
                guard currentPeer.lock.withLock({ $0 }) else { throw MachineUpdateOwnedHealthFailure.denied }
            }, verifyCurrent: {})
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: peer, helloBytes: Data([1]), verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: try .init(maximum: 1), invalidate: {}, makeOwner: { request in
                let owner = try MachineUpdateGatewayHealthOwner.openAdmitted(request: request) {
                    do {
                        let unexpected = try store.openForHealth()
                        try unexpected.close()
                        throw MachineUpdateOwnedHealthFailure.denied
                    } catch GatewayDatabaseError.updateHealthRecoveryRequired {
                        if revokePeer { currentPeer.lock.withLock { $0 = false } }
                        throw GatewayDatabaseError.updateHealthRecoveryRequired
                    }
                }
                return MachineUpdateGatewayHealthReply(owner: owner)
            })
        endpoint.healthHello { version, bytes in XCTAssertEqual(version, 1); XCTAssertEqual(bytes, Data([1])) }
        let session = try MachineUpdateRoleChallengeSession(requirement: fixture.requirement, verifyCurrent: {})
        endpoint.checkUpdateHealth(try session.request) { bytes in
            XCTAssertEqual(bytes, revokePeer ? nil : MachineUpdateGatewayRecoverySignal.bytes)
            replies.lock.withLock { $0 += 1 }
        }
        try await waitUntil { replies.lock.withLock { $0 == 1 } }
        try await endpoint.closeAndWait()
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: fixture.files.path)), crashed.database)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: fixture.files.path + "-journal")), crashed.journal)
    }

    func testScopeChangeDuringSettlementSuppressesTheReply() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture()
        let activity = try files.open(), valid = TestState(true), replies = TestState(0)
        let owner = fixture.owner(close: { valid.lock.withLock { $0 = false } })
        let endpoint = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello,
            verifyCurrent: {
                guard valid.lock.withLock({ $0 }) else { throw MachineUpdateOwnedHealthFailure.denied }
            }, acquireActivity: { try activity.acquireShared() }, budget: try .init(maximum: 1),
            invalidate: {}, makeOwner: { _ in owner })
        hello(endpoint, fixture: fixture)
        endpoint.checkUpdateHealth(try fixture.session().request) { bytes in
            XCTAssertNil(bytes); XCTAssertTrue(owner.isClosed); replies.lock.withLock { $0 += 1 }
        }
        try await waitUntil { replies.lock.withLock { $0 == 1 } }
        try await endpoint.closeAndWait()
    }

    func testASecondConnectionCannotOpenWhileDisconnectedWorkStillRuns() async throws {
        let fixture = try MachineUpdateOwnedHealthEndpointFixture(), files = try ReleaseActivityFixture(), activity = try files.open()
        let budget = try AuthorityXPCWorkBudget(maximum: 1), opens = TestState(0), gate = TestState<CheckedContinuation<Void, Never>?>(nil)
        let first = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello, verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: budget, invalidate: {}, makeOwner: { _ in
                opens.lock.withLock { $0 += 1 }; await withCheckedContinuation { continuation in gate.lock.withLock { $0 = continuation } }
                return fixture.owner()
            })
        let second = MachineUpdateConsumerHealthXPCEndpoint(peer: fixture.peer(), helloBytes: fixture.hello, verifyCurrent: {},
            acquireActivity: { try activity.acquireShared() }, budget: budget, invalidate: {}, makeOwner: { _ in
                opens.lock.withLock { $0 += 1 }; return fixture.owner()
            })
        defer { gate.lock.withLock { let old = $0; $0 = nil; old?.resume() }; first.close(); second.close() }
        hello(first, fixture: fixture); first.checkUpdateHealth(try fixture.session().request) { _ in XCTFail() }
        try await waitUntil { gate.lock.withLock { $0 != nil } }; first.close()
        let acquired = budget.acquire()
        XCTAssertFalse(acquired)
        if acquired { budget.release() }
        hello(second, fixture: fixture); second.checkUpdateHealth(try fixture.session().request) { XCTAssertNil($0) }
        XCTAssertEqual(opens.lock.withLock { $0 }, 1)
        gate.lock.withLock { let old = $0; $0 = nil; old?.resume() }
        try await first.closeAndWait(); try await second.closeAndWait()
    }
}
