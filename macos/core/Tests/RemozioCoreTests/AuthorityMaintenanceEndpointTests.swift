import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceEndpointTests: XCTestCase, @unchecked Sendable {
    private typealias Request = AuthorityMaintenanceChannelRequest
    private typealias Response = AuthorityMaintenanceChannelResponse
    private enum Fault: Error { case denied, timeout }
    private final class Pause: Sendable {
        private struct State { var continuation: CheckedContinuation<Void, Never>?; var resumed = false }
        private let state = Mutex(State())
        func wait() async {
            await withCheckedContinuation { c in
                let resumed = state.withLock { if $0.resumed { return true }; $0.continuation = c; return false }
                if resumed { c.resume() }
            }
        }
        func resume() { let c = state.withLock { $0.resumed = true; let c = $0.continuation; $0.continuation = nil; return c }; c?.resume() }
        var entered: Bool { state.withLock { $0.continuation != nil } }
    }
    private final class Fixture: Sendable {
        let admission: AuthorityMaintenancePairingAdmission
        let valid = Mutex(true), failCapture = Mutex(false), pauseObserve = Mutex(false)
        let armFailureMode = Mutex(0), postReleaseChecks = Mutex(0)
        let replacement = Mutex<AuthorityMaintenanceBinding?>(nil), requiredArmedDuringRelease = Mutex<AuthorityMaintenanceBinding?>(nil)
        let checks = Mutex(0), captures = Mutex(0), acquisitions = Mutex(0), handshakes = Mutex(0), invalidations = Mutex(0)
        let pause = Pause()
        let activity: ReleaseActivityBarrier?
        init(activity: ReleaseActivityBarrier? = nil) throws {
            admission = try .init(accountID: Data(repeating: 1, count: 16), incarnation: Data(repeating: 4, count: 16))
            self.activity = activity
        }
        func access() throws -> AuthorityMaintenanceChannelAccess {
            try .openOwned(admission: admission, acquireActivity: { [self] in
                acquisitions.withLock { $0 += 1 }; return try activity?.acquireShared()
            }, check: { [self] q in
                checks.withLock { $0 += 1 }; guard valid.withLock({ $0 }) else { throw Fault.denied }
                if [.cancel, .reopen].contains(q.action), let b = requiredArmedDuringRelease.withLock({ $0 }),
                   (try? admission.shutdownBinding(matching: b)) == nil {
                    postReleaseChecks.withLock { $0 += 1 }; throw Fault.denied
                }
            }, observe: { [self] q in
                captures.withLock { $0 += 1 }
                if failCapture.withLock({ $0 }) { throw Fault.denied }
                if q.action == .arm, armFailureMode.withLock({ $0 }) != 0 {
                    let binding = try XCTUnwrap(q.binding)
                    let armed = try admission.shutdownBinding(matching: binding)
                    if armFailureMode.withLock({ $0 }) == 2 {
                        try armed.cancel(matching: binding)
                        let next = try admission.openConnection(attemptID: q.attemptID, revision: q.revision)
                        _ = try next.blockNewStages(matching: next.binding); _ = try next.transferToShutdown(matching: next.binding)
                        replacement.withLock { $0 = next.binding }; next.close()
                    }
                    throw Fault.denied
                }
                if q.action == .observe && pauseObserve.withLock({ $0 }) { await pause.wait() }
                return try .init(journal: .init(requests: .init(liveRequests: 0, commandCaptures: 0, activityOwners: 0),
                    exchanges: .init(active: 0, stopped: false), nativeExecutions: 0, executionActivityOwners: 0),
                    execution: .init(started: true, stopping: false, failed: false, queuedTurns: 0, rejectedTurns: 0),
                    pairing: .init(ready: true, stagedAttempts: admission.stagedReservations(), activityOwners: 0, operationActive: false))
            })
        }
        func endpoint(budget: AuthorityXPCWorkBudget? = nil, verify: @escaping () throws -> Void = {}) throws -> AuthorityMaintenanceXPCEndpoint {
            try .openOwned(access: access(), budget: budget ?? .init(maximum: 1), verify: verify,
                invalidate: { [self] in invalidations.withLock { $0 += 1 } },
                onHandshake: { [self] in handshakes.withLock { $0 += 1 } })
        }
    }
    private func bytes(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func request(_ action: Request.Action, binding: AuthorityMaintenanceBinding? = nil,
                         installation: UInt8 = 7, inode: UInt64 = 9, challenge: UInt8 = 6) throws -> Request {
        try .init(action: action, accountID: binding?.accountID ?? bytes(1), attemptID: binding?.attemptID ?? bytes(2),
            revision: binding?.revision ?? bytes(3), installationID: bytes(installation), gate: .init(device: 8, inode: inode),
            binding: binding, challenge: bytes(challenge, 32))
    }
    private func invoke(_ e: AuthorityMaintenanceXPCEndpoint, _ data: Data, _ reply: @escaping @Sendable (Data?) -> Void) {
        Thread.current.threadDictionary["remozio-maintenance-invocation"] = true
        defer { Thread.current.threadDictionary.removeObject(forKey: "remozio-maintenance-invocation") }
        e.exchange(data, reply: reply)
    }
    private func waitUntil(_ body: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !body() { guard ContinuousClock.now < deadline else { throw Fault.timeout }; try await Task.sleep(for: .milliseconds(2)) }
    }
    private func rawCall(_ e: AuthorityMaintenanceXPCEndpoint, _ q: Request) async throws -> Data? {
        let result = Mutex<(Bool, Data?)>((false, nil))
        invoke(e, try q.encoded) { b in result.withLock { $0 = (true, b) } }
        try await waitUntil { result.withLock { $0.0 } && e.pendingOperations() == 0 }
        return result.withLock { $0.1 }
    }
    private func call(_ e: AuthorityMaintenanceXPCEndpoint, _ q: Request) async throws -> Response {
        let bytes = try await rawCall(e, q); return try Response.decode(XCTUnwrap(bytes), expected: q)
    }
    private func open(_ e: AuthorityMaintenanceXPCEndpoint) async throws -> AuthorityMaintenanceBinding {
        let r = try await call(e, request(.open)); XCTAssertEqual(r.outcome, .applied); return r.binding
    }
    func testOriginalInvocationChecksAndRepeatedObservationsKeepOneExactBinding() async throws {
        let f = try Fixture(), verifications = Mutex(0)
        let e = try f.endpoint(verify: {
            XCTAssertEqual(Thread.current.threadDictionary["remozio-maintenance-invocation"] as? Bool, true)
            verifications.withLock { $0 += 1 }
        })
        defer { e.close() }
        let b = try await open(e)
        for n: UInt8 in [10, 11, 12] {
            let r = try await call(e, request(.observe, binding: b, challenge: n))
            XCTAssertEqual(r.binding, b); XCTAssertEqual(r.outcome, .applied); XCTAssertNotNil(r.work)
        }
        XCTAssertEqual(f.handshakes.withLock { $0 }, 1); XCTAssertEqual(verifications.withLock { $0 }, 4)
        XCTAssertEqual(try f.admission.connectionReservations(), 1)
        await e.closeAndWait(); XCTAssertEqual(try f.admission.connectionReservations(), 0)
    }
    func testInvocationRejectionPrecedesProtectedReadsActivityBudgetAndConnectionOwnership() throws {
        let f = try Fixture(), budget = try AuthorityXPCWorkBudget(maximum: 1), replies = Mutex(0)
        let e = try f.endpoint(budget: budget, verify: { throw Fault.denied })
        invoke(e, try request(.open).encoded) { b in XCTAssertNil(b); replies.withLock { $0 += 1 } }
        XCTAssertEqual(replies.withLock { $0 }, 1); XCTAssertEqual(f.checks.withLock { $0 }, 0)
        XCTAssertEqual(f.captures.withLock { $0 }, 0); XCTAssertEqual(f.acquisitions.withLock { $0 }, 0)
        XCTAssertEqual(try f.admission.connectionReservations(), 0); XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testMalformedMessagesCannotReadOrReserveAnything() throws {
        for data in [Data(), Data(repeating: 0, count: 513), try request(.open).encoded + Data([0])] {
            let f = try Fixture(), e = try f.endpoint(), replies = Mutex(0)
            invoke(e, data) { b in XCTAssertNil(b); replies.withLock { $0 += 1 } }
            XCTAssertEqual(replies.withLock { $0 }, 1); XCTAssertEqual(f.checks.withLock { $0 }, 0)
            XCTAssertEqual(f.acquisitions.withLock { $0 }, 0); XCTAssertEqual(try f.admission.connectionReservations(), 0)
        }
    }
    func testRefusedOpenCreatesOnlyMetadataAndFreshOpenStillSucceeds() async throws {
        let f = try Fixture(), e = try f.endpoint(), q = try request(.open)
        f.valid.withLock { $0 = false }
        let denied = try await call(e, q)
        XCTAssertEqual(denied.outcome, .refused); XCTAssertNil(denied.work)
        XCTAssertEqual(denied.binding.accountID, q.accountID); XCTAssertEqual(denied.binding.attemptID, q.attemptID)
        XCTAssertEqual(denied.binding.revision, q.revision); XCTAssertEqual(try f.admission.connectionReservations(), 0)
        XCTAssertEqual(f.captures.withLock { $0 }, 0)
        let stage = try f.admission.reserveStage(); stage.close()
        f.valid.withLock { $0 = true }; let fresh = try f.endpoint(); _ = try await open(fresh)
        XCTAssertEqual(try f.admission.connectionReservations(), 1); await fresh.closeAndWait()
    }
    func testOpenCaptureFailureCannotCreateAConnectionOrRestriction() async throws {
        let f = try Fixture(), e = try f.endpoint(); f.failCapture.withLock { $0 = true }
        let r = try await call(e, request(.open)); XCTAssertEqual(r.outcome, .refused)
        XCTAssertEqual(try f.admission.connectionReservations(), 0)
        XCTAssertThrowsError(try f.admission.shutdownBinding(matching: r.binding))
        let stage = try f.admission.reserveStage(); stage.close()
        f.failCapture.withLock { $0 = false }; let fresh = try f.endpoint(); _ = try await open(fresh); await fresh.closeAndWait()
    }
    func testLiveStageReportsPendingAndActualTransferSurvivesDisconnectUntilExactReopen() async throws {
        let f = try Fixture(), stage = try f.admission.reserveStage(), e = try f.endpoint(), b = try await open(e)
        for n: UInt8 in [20, 21] {
            let r = try await call(e, request(.arm, binding: b, challenge: n))
            XCTAssertEqual(r.outcome, .stagesPending); XCTAssertEqual(r.work?.pairing.stagedAttempts, 1)
            XCTAssertThrowsError(try f.admission.reserveStage()); XCTAssertEqual(try f.admission.connectionReservations(), 1)
        }
        stage.close(); let armed = try await call(e, request(.arm, binding: b))
        XCTAssertEqual(armed.outcome, .applied); XCTAssertEqual(try f.admission.shutdownBinding(matching: b).binding, b)
        await e.closeAndWait(); XCTAssertThrowsError(try f.admission.reserveStage())
        let fresh = try f.endpoint(), other = try await open(fresh); XCTAssertNotEqual(b.connectionID, other.connectionID)
        let reopened = try await call(fresh, request(.reopen, binding: b)); XCTAssertEqual(reopened.outcome, .applied)
        XCTAssertNil(reopened.work); let next = try f.admission.reserveStage(); next.close()
    }
    func testClosedAdmissionReportsRefusedWithoutInventingWorkOrRetry() async throws {
        let f = try Fixture(), e = try f.endpoint(), b = try await open(e); f.admission.close()
        let r = try await call(e, request(.arm, binding: b))
        XCTAssertEqual(r.outcome, .refused); XCTAssertNil(r.work); XCTAssertEqual(f.captures.withLock { $0 }, 1)
        XCTAssertThrowsError(try f.admission.stagedReservations())
    }
    func testForeignBlockerReportsRefusedAndRetainsTheForeignRestriction() async throws {
        let f = try Fixture(), e = try f.endpoint(), b = try await open(e)
        let foreign = try f.admission.openConnection(attemptID: bytes(2), revision: bytes(3))
        XCTAssertEqual(try foreign.blockNewStages(matching: foreign.binding), 0)
        let r = try await call(e, request(.arm, binding: b)); XCTAssertEqual(r.outcome, .refused); XCTAssertNil(r.work)
        XCTAssertThrowsError(try f.admission.reserveStage()); XCTAssertEqual(f.captures.withLock { $0 }, 1)
        try foreign.releaseUnarmed(matching: foreign.binding)
    }
    func testWrongReopenCannotAcknowledgeOrReleaseAnotherArmedBinding() async throws {
        let f = try Fixture(), first = try f.endpoint(), b = try await open(first)
        let armed = try await call(first, request(.arm, binding: b)); XCTAssertEqual(armed.outcome, .applied); await first.closeAndWait()
        let second = try f.endpoint(), wrong = try await open(second)
        let r = try await call(second, request(.reopen, binding: wrong)); XCTAssertEqual(r.outcome, .refused)
        XCTAssertThrowsError(try f.admission.reserveStage())
        let third = try f.endpoint(); _ = try await open(third)
        let cancelled = try await call(third, request(.cancel, binding: b)); XCTAssertEqual(cancelled.outcome, .applied)
        let stage = try f.admission.reserveStage(); stage.close()
    }
    func testChangedInstallationGateAndAllBindingFieldsCannotRetargetTheConnection() async throws {
        for field in 0..<7 {
            let f = try Fixture(), e = try f.endpoint(), b = try await open(e)
            var v = [b.accountID, b.attemptID, b.revision, b.incarnation, b.connectionID]
            if field < 5 { v[field] = bytes(99) }
            let other = try AuthorityMaintenanceBinding(accountID: v[0], attemptID: v[1], revision: v[2], incarnation: v[3], connectionID: v[4])
            let q = try request(.observe, binding: other, installation: field == 5 ? 99 : 7, inode: field == 6 ? 99 : 9)
            let r = try await call(e, q); XCTAssertEqual(r.outcome, .refused); XCTAssertNil(r.work)
            XCTAssertEqual(f.captures.withLock { $0 }, 1); XCTAssertEqual(try f.admission.connectionReservations(), 0)
        }
    }
    func testDisconnectJoinsRealWorkAndRetainsItsActivityAndBudgetUntilSettlement() async throws {
        let activity = try ReleaseActivityFixture(), f = try Fixture(activity: activity.open()), installer = try activity.open()
        let budget = try AuthorityXPCWorkBudget(maximum: 1), e = try f.endpoint(budget: budget), b = try await open(e)
        f.pauseObserve.withLock { $0 = true }; defer { f.pause.resume(); e.close() }
        let replies = Mutex(0), joined = Mutex(false), joining = Mutex(false)
        invoke(e, try request(.observe, binding: b).encoded) { _ in replies.withLock { $0 += 1 } }
        try await waitUntil { f.pause.entered }; e.close()
        let join = Task { joining.withLock { $0 = true }; await e.closeAndWait(); joined.withLock { $0 = true } }
        try await waitUntil { joining.withLock { $0 } }
        XCTAssertFalse(joined.withLock { $0 }); XCTAssertFalse(budget.acquire()); XCTAssertThrowsError(try installer.acquireExclusive())
        f.pause.resume(); await join.value
        XCTAssertEqual(e.pendingOperations(), 0); XCTAssertTrue(budget.acquire()); budget.release()
        let token = try installer.acquireExclusive(); token.close(); XCTAssertEqual(replies.withLock { $0 }, 0)
    }
    func testReplyReleasesActivityAndBudgetButRuntimeJoinWaitsForTheReply() async throws {
        let activity = try ReleaseActivityFixture(), f = try Fixture(activity: activity.open()), installer = try activity.open()
        let budget = try AuthorityXPCWorkBudget(maximum: 1), e = try f.endpoint(budget: budget)
        let entered = Mutex(false), joining = Mutex(false), joined = Mutex(false), resume = DispatchSemaphore(value: 0)
        defer { resume.signal(); e.close() }
        invoke(e, try request(.open).encoded) { data in
            XCTAssertNotNil(data); XCTAssertTrue(budget.acquire()); budget.release()
            do { let token = try installer.acquireExclusive(); token.close() } catch { XCTFail("Activity remained held") }
            entered.withLock { $0 = true }; XCTAssertEqual(resume.wait(timeout: .now() + 3), .success)
        }
        try await waitUntil { entered.withLock { $0 } }
        let join = Task { joining.withLock { $0 = true }; await e.closeAndWait(); joined.withLock { $0 = true } }
        try await waitUntil { joining.withLock { $0 } }; XCTAssertFalse(joined.withLock { $0 })
        resume.signal(); await join.value; XCTAssertTrue(joined.withLock { $0 })
    }
    func testImmediateNextInvocationCannotReleaseTheNewOperationsBudget() async throws {
        let f = try Fixture(), budget = try AuthorityXPCWorkBudget(maximum: 1), e = try f.endpoint(budget: budget)
        f.pauseObserve.withLock { $0 = true }; defer { f.pause.resume(); e.close() }
        let q = try request(.open), replies = Mutex(0)
        invoke(e, try q.encoded) { [self] data in
            do {
                let b = try Response.decode(XCTUnwrap(data), expected: q).binding
                invoke(e, try request(.observe, binding: b).encoded) { data in XCTAssertNotNil(data); replies.withLock { $0 += 1 } }
            } catch { XCTFail("The first response failed: \(error)") }
        }
        try await waitUntil { f.pause.entered }; XCTAssertFalse(budget.acquire())
        f.pause.resume(); try await waitUntil { replies.withLock { $0 == 1 } && e.pendingOperations() == 0 }
        XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testScopeRevocationAfterAwaitCannotProduceAppliedOrInventAZeroSnapshot() async throws {
        let f = try Fixture(), e = try f.endpoint(), b = try await open(e)
        f.pauseObserve.withLock { $0 = true }; defer { f.pause.resume(); e.close() }
        let q = try request(.observe, binding: b), result = Mutex<Data?>(nil)
        invoke(e, try q.encoded) { data in result.withLock { $0 = data } }
        try await waitUntil { f.pause.entered }; f.valid.withLock { $0 = false }; f.pause.resume()
        try await waitUntil { result.withLock { $0 != nil } && e.pendingOperations() == 0 }
        let r = try Response.decode(XCTUnwrap(result.withLock { $0 }), expected: q)
        XCTAssertEqual(r.outcome, .refused); XCTAssertNil(r.work); XCTAssertEqual(try f.admission.connectionReservations(), 0)
    }
}

extension AuthorityMaintenanceEndpointTests {
    func testActualInvocationGuardRejectsAnOffStackCallBeforeProtectedAccess() throws {
        let f = try Fixture(), listener = NSXPCListener.anonymous(), connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        defer { connection.invalidate(); listener.invalidate() }
        let policy = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.sebastiano.remozio.macos.setup",
            approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: getuid())
        let native = XPCInvocationGuard(connection: connection, policy: policy), replies = Mutex(0)
        let e = try f.endpoint(verify: { _ = try native.verifyInvocation() })
        invoke(e, try request(.open).encoded) { data in XCTAssertNil(data); replies.withLock { $0 += 1 } }
        XCTAssertEqual(replies.withLock { $0 }, 1); XCTAssertEqual(f.checks.withLock { $0 }, 0)
        XCTAssertEqual(f.acquisitions.withLock { $0 }, 0); XCTAssertEqual(try f.admission.connectionReservations(), 0)
    }
    func testNativeConstructorRefusesOrdinaryIdentityBeforeAccessOrExport() throws {
        XCTAssertNotEqual(getuid(), 0)
        let f = try Fixture(), listener = NSXPCListener.anonymous(), c = NSXPCConnection(listenerEndpoint: listener.endpoint)
        defer { c.invalidate(); listener.invalidate() }
        let code = try AuthorityCodeEntry(role: .setupController, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.setup",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 1, count: 20), active: true)
        XCTAssertThrowsError(try AuthorityMaintenanceXPCEndpoint(connection: c, setupCode: code, access: f.access(),
            budget: .init(maximum: 1), onHandshake: {}, onClose: {})) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        XCTAssertNil(c.exportedObject); XCTAssertEqual(f.checks.withLock { $0 }, 0)
    }
    private final class Bridge: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        let endpoint: AuthorityMaintenanceXPCEndpoint
        private let connectionLock = NSLock()
        private var connections: [NSXPCConnection] = []
        init(_ endpoint: AuthorityMaintenanceXPCEndpoint) { self.endpoint = endpoint }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
            c.exportedInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self); c.exportedObject = endpoint
            c.invalidationHandler = { [weak endpoint] in endpoint?.close() }; c.interruptionHandler = { [weak endpoint] in endpoint?.close() }
            connectionLock.withLock { connections.append(c) }; c.activate(); return true
        }
        func close() { let held = connectionLock.withLock { let held = connections; connections = []; return held }; held.forEach { $0.invalidate() }; endpoint.close() }
    }
    /// Real anonymous XPC transport with owned peer controls. Installed Root peer authentication remains unqualified.
    func testAnonymousXPCDisconnectAfterArmingRetainsTheExactBlock() async throws {
        let f = try Fixture(), e = try f.endpoint(), bridge = Bridge(e), listener = NSXPCListener.anonymous()
        listener.delegate = bridge; listener.activate()
        let client = NSXPCConnection(listenerEndpoint: listener.endpoint)
        client.remoteObjectInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self); client.activate()
        defer { client.invalidate(); bridge.close(); listener.invalidate() }
        let failure = Mutex<String?>(nil)
        let proxy = try XCTUnwrap(client.remoteObjectProxyWithErrorHandler { error in failure.withLock { $0 = String(describing: error) } } as? any AuthorityMaintenanceXPCProtocol)
        func nativeCall(_ q: Request) async throws -> Response {
            let result = Mutex<Data?>(nil), done = expectation(description: "Owned native maintenance response")
            proxy.exchange(try q.encoded) { bytes in result.withLock { $0 = bytes }; done.fulfill() }
            await fulfillment(of: [done], timeout: 3)
            XCTAssertNil(failure.withLock { $0 })
            return try Response.decode(XCTUnwrap(result.withLock { $0 }), expected: q)
        }
        let opened = try await nativeCall(request(.open)); XCTAssertEqual(opened.outcome, .applied)
        let armed = try await nativeCall(request(.arm, binding: opened.binding)); XCTAssertEqual(armed.outcome, .applied)
        client.invalidate(); try await waitUntil { f.invalidations.withLock { $0 > 0 } }
        await e.closeAndWait(); XCTAssertThrowsError(try f.admission.reserveStage())
        let target = try f.admission.shutdownBinding(matching: opened.binding)
        XCTAssertEqual(target.binding, opened.binding); try target.reopen(matching: opened.binding)
        let stage = try f.admission.reserveStage(); stage.close()
    }
}

extension AuthorityMaintenanceEndpointTests {
    func testPostTransferCaptureFailureRollsBackWithoutAnOrphanAndAFreshConnectionCanArm() async throws {
        let f = try Fixture(), e = try f.endpoint(), b = try await open(e)
        f.armFailureMode.withLock { $0 = 1 }
        let refused = try await call(e, request(.arm, binding: b))
        XCTAssertEqual(refused.outcome, .refused); XCTAssertNil(refused.work)
        XCTAssertThrowsError(try f.admission.shutdownBinding(matching: b))
        XCTAssertEqual(try f.admission.connectionReservations(), 0)
        let stage = try f.admission.reserveStage(); stage.close()
        f.armFailureMode.withLock { $0 = 0 }
        let fresh = try f.endpoint(), next = try await open(fresh)
        XCTAssertNotEqual(b.connectionID, next.connectionID)
        let observed = try await call(fresh, request(.observe, binding: next)); XCTAssertEqual(observed.outcome, .applied)
        let armed = try await call(fresh, request(.arm, binding: next)); XCTAssertEqual(armed.outcome, .applied)
        await fresh.closeAndWait(); try f.admission.shutdownBinding(matching: next).cancel(matching: next)
    }
    func testFailedRollbackReturnsAmbiguousNilAndCannotReleaseANewerArmedTarget() async throws {
        let f = try Fixture(), e = try f.endpoint(), b = try await open(e)
        f.armFailureMode.withLock { $0 = 2 }
        let reply = try await rawCall(e, request(.arm, binding: b)); XCTAssertNil(reply)
        let replacement = try XCTUnwrap(f.replacement.withLock { $0 })
        XCTAssertNotEqual(replacement.connectionID, b.connectionID)
        XCTAssertThrowsError(try f.admission.shutdownBinding(matching: b)); XCTAssertThrowsError(try f.admission.reserveStage())
        let held = try f.admission.shutdownBinding(matching: replacement)
        XCTAssertEqual(held.binding, replacement); try held.cancel(matching: replacement)
    }
    func testValidationFailureBeforeCancelLeavesTheExistingArmedBlockUntouched() async throws {
        let f = try Fixture(), e = try f.endpoint(), b = try await open(e)
        let armed = try await call(e, request(.arm, binding: b)); XCTAssertEqual(armed.outcome, .applied)
        f.valid.withLock { $0 = false }
        let refused = try await call(e, request(.cancel, binding: b)); XCTAssertEqual(refused.outcome, .refused)
        XCTAssertEqual(try f.admission.shutdownBinding(matching: b).binding, b); XCTAssertThrowsError(try f.admission.reserveStage())
        f.valid.withLock { $0 = true }; let fresh = try f.endpoint(); _ = try await open(fresh)
        let cancelled = try await call(fresh, request(.cancel, binding: b)); XCTAssertEqual(cancelled.outcome, .applied)
        let stage = try f.admission.reserveStage(); stage.close()
    }
    func testCancelAndReopenHaveNoFallibleValidationAfterTheirRelease() async throws {
        for action in [Request.Action.cancel, .reopen] {
            let f = try Fixture(), e = try f.endpoint(), b = try await open(e)
            let armed = try await call(e, request(.arm, binding: b)); XCTAssertEqual(armed.outcome, .applied)
            f.requiredArmedDuringRelease.withLock { $0 = b }
            let released = try await call(e, request(action, binding: b)); XCTAssertEqual(released.outcome, .applied)
            XCTAssertEqual(f.postReleaseChecks.withLock { $0 }, 0)
            XCTAssertThrowsError(try f.admission.shutdownBinding(matching: b))
            let stage = try f.admission.reserveStage(); stage.close()
        }
    }
    func testConcurrentExchangeClosesTheConnectionAndReleasesOnlyItsUnarmedRestriction() async throws {
        let f = try Fixture(), stage = try f.admission.reserveStage(), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let e = try f.endpoint(budget: budget), b = try await open(e)
        defer { f.pause.resume(); stage.close(); e.close() }
        let pending = try await call(e, request(.arm, binding: b)); XCTAssertEqual(pending.outcome, .stagesPending)
        XCTAssertThrowsError(try f.admission.reserveStage())
        f.pauseObserve.withLock { $0 = true }
        let firstReplies = Mutex(0), concurrentReplies = Mutex(0)
        invoke(e, try request(.observe, binding: b).encoded) { _ in firstReplies.withLock { $0 += 1 } }
        try await waitUntil { f.pause.entered }
        invoke(e, try request(.observe, binding: b, challenge: 99).encoded) { data in
            XCTAssertNil(data); concurrentReplies.withLock { $0 += 1 }
        }
        XCTAssertEqual(concurrentReplies.withLock { $0 }, 1); XCTAssertFalse(budget.acquire())
        XCTAssertEqual(try f.admission.connectionReservations(), 0)
        let extra = try f.admission.reserveStage(); XCTAssertEqual(try f.admission.stagedReservations(), 2); extra.close()
        f.pause.resume(); await e.closeAndWait()
        XCTAssertEqual(firstReplies.withLock { $0 }, 0); XCTAssertEqual(try f.admission.stagedReservations(), 1)
        XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testAppliedReleaseLeavesTheServerConnectionUntilTheClientCloses() async throws {
        for action in [Request.Action.cancel, .reopen] {
            let f = try Fixture(), endpoint = try f.endpoint(), opened = try await call(endpoint, request(.open))
            _ = try await call(endpoint, request(.arm, binding: opened.binding))
            let released = try await call(endpoint, request(action, binding: opened.binding))
            XCTAssertEqual(released.outcome, .applied); XCTAssertEqual(f.invalidations.withLock { $0 }, 0)
            let stage = try f.admission.reserveStage(); stage.close()
            await endpoint.closeAndWait(); XCTAssertEqual(f.invalidations.withLock { $0 }, 1)
        }
    }

}
