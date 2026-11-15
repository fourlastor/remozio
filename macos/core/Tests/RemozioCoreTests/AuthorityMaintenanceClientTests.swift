import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceClientTests: XCTestCase, @unchecked Sendable {
    private typealias Request = AuthorityMaintenanceChannelRequest
    private typealias Response = AuthorityMaintenanceChannelResponse
    private enum Fault: Error { case denied, deadline }
    private static func work(stages: Int = 0) throws -> AuthorityMaintenanceChannelWork {
        try .init(journal: .init(requests: .init(liveRequests: 0, commandCaptures: 0, activityOwners: 0),
            exchanges: .init(active: 0, stopped: false), nativeExecutions: 0, executionActivityOwners: 0),
            execution: .init(started: true, stopping: false, failed: false, queuedTurns: 0, rejectedTurns: 0),
            pairing: .init(ready: true, stagedAttempts: stages, activityOwners: 0, operationActive: false))
    }
    private func context() throws -> Request {
        try .init(action: .open, accountID: Data(repeating: 1, count: 16), attemptID: Data(repeating: 2, count: 16),
            revision: Data(repeating: 3, count: 16), installationID: Data(repeating: 7, count: 16),
            gate: .init(device: 8, inode: 9), binding: nil, challenge: Data(repeating: 6, count: 32))
    }
    private final class Driver: AuthorityMaintenanceClientDriver, Sendable {
        enum Mode: Sendable { case normal, nilReply(Request.Action), malformed(Request.Action), wrongChallenge(Request.Action), foreignBinding(Request.Action), hold(Request.Action), refused(Request.Action) }
        private struct State {
            var invalidated: (@Sendable () -> Void)?, held: (@Sendable (AuthorityMaintenanceClientReply) -> Void)?
            var heldRequest: Request?, mode = Mode.normal, pendingArms = 0, calls: [Request] = []
            var helloVersion: UInt64 = 1, peerAllowed = true, starts = 0, hellos = 0, closes = 0, duplicate = false
            var invalidateAfterReply: Request.Action?
        }
        private let state = Mutex(State())
        func configure(mode: Mode = .normal, pendingArms: Int = 0, helloVersion: UInt64 = 1, peerAllowed: Bool = true, duplicate: Bool = false, invalidateAfterReply: Request.Action? = nil) {
            state.withLock { $0.mode = mode; $0.pendingArms = pendingArms; $0.helloVersion = helloVersion; $0.peerAllowed = peerAllowed; $0.duplicate = duplicate; $0.invalidateAfterReply = invalidateAfterReply }
        }
        var calls: [Request] { state.withLock { $0.calls } }
        var hellos: Int { state.withLock { $0.hellos } }
        var closes: Int { state.withLock { $0.closes } }
        func start(_ invalidated: @escaping @Sendable () -> Void) { state.withLock { $0.invalidated = invalidated; $0.starts += 1 } }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            let value = state.withLock { $0.hellos += 1; return $0.peerAllowed ? AuthorityMaintenanceClientReply.hello($0.helloVersion) : .bytes(nil) }
            reply(value)
        }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let q = try Request.decode(bytes)
                let result: (Mode, Bool, Bool, Bool) = state.withLock {
                    $0.calls.append(q)
                    if case .hold(let action) = $0.mode, action == q.action { $0.held = reply; $0.heldRequest = q; return ($0.mode, false, true, false) }
                    let pending = q.action == .arm && $0.pendingArms > 0
                    if pending { $0.pendingArms -= 1 }; return ($0.mode, pending, false, $0.duplicate)
                }
                if result.2 { return }
                var expected = q
                if case .nilReply(let action) = result.0, action == q.action { reply(.bytes(nil)); return }
                if case .malformed(let action) = result.0, action == q.action { reply(.bytes(Data([0xff]))); return }
                if case .wrongChallenge(let action) = result.0, action == q.action {
                    expected = try .init(action: q.action, accountID: q.accountID, attemptID: q.attemptID, revision: q.revision,
                        installationID: q.installationID, gate: q.gate, binding: q.binding, challenge: Data(repeating: 99, count: 32))
                }
                var binding = try q.binding ?? AuthorityMaintenanceBinding(accountID: q.accountID, attemptID: q.attemptID, revision: q.revision,
                    incarnation: Data(repeating: 4, count: 16), connectionID: Data(repeating: 5, count: 16))
                if case .foreignBinding(let action) = result.0, action == q.action {
                    binding = try .init(accountID: q.accountID, attemptID: q.attemptID, revision: q.revision,
                        incarnation: Data(repeating: 98, count: 16), connectionID: Data(repeating: 97, count: 16))
                }
                let refused: Bool = if case .refused(let action) = result.0 { action == q.action } else { false }
                let outcome: Response.Outcome = refused ? .refused : result.1 ? .stagesPending : .applied
                let observes = q.action == .open || q.action == .observe || q.action == .arm
                let response = try Response(request: expected, binding: binding,
                    work: observes && !refused ? AuthorityMaintenanceClientTests.work(stages: result.1 ? 1 : 0) : nil, outcome: outcome)
                let value = AuthorityMaintenanceClientReply.bytes(try response.encoded); reply(value)
                if state.withLock({ $0.invalidateAfterReply == q.action }) { invalidate() }
                if result.3 { reply(value) }
            } catch { reply(.bytes(nil)) }
        }
        func invalidate() { let callback = state.withLock { $0.invalidated }; callback?() }
        func close() { state.withLock { $0.closes += 1 }; invalidate() }
        func completeHeld() {
            let pair = state.withLock { let p = ($0.held, $0.heldRequest); $0.held = nil; return p }
            guard let callback = pair.0, let q = pair.1, let binding = q.binding else { return }
            callback(.bytes(try? Response(request: q, binding: binding, work: AuthorityMaintenanceClientTests.work(), outcome: .applied).encoded))
        }
    }
    private func client(_ driver: Driver, timeout: UInt64 = 100, interval: UInt64 = 2,
                        verify: @escaping @Sendable () throws -> Void = {}) throws -> AuthorityMaintenanceXPCClient {
        try .openOwned(context: context(), driver: driver, timeoutMilliseconds: timeout, intervalMilliseconds: interval, verify: verify)
    }
    private var deadline: ContinuousClock.Instant { .now.advanced(by: .seconds(2)) }
    private func waitUntil(_ condition: () -> Bool) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(1))
        while !condition() { guard ContinuousClock.now < end else { throw Fault.deadline }; try await Task.sleep(for: .milliseconds(1)) }
    }
    private func expect(_ expected: AuthorityMaintenanceClientError, _ operation: () async throws -> Void) async {
        do { try await operation(); XCTFail("Expected a terminal client error") }
        catch { XCTAssertEqual(error as? AuthorityMaintenanceClientError, expected) }
    }
    func testHandshakePrecedesOpenAndEachRequestHasFreshExactCorrelation() async throws {
        let d = Driver(), c = try client(d); let opened = try await c.start(until: deadline)
        let observed = try await c.observe(until: deadline)
        XCTAssertEqual(d.hellos, 1); XCTAssertEqual(d.calls.map(\.action), [.open, .observe]); XCTAssertEqual(opened.binding, observed.binding)
        XCTAssertNotEqual(d.calls[0].challenge, d.calls[1].challenge); XCTAssertEqual(d.calls[0].installationID, try context().installationID)
        XCTAssertEqual(d.calls[1].gate, try context().gate); try await c.release(until: deadline)
        XCTAssertEqual(d.calls.map(\.action), [.open, .observe, .cancel])
    }
    func testRejectedPeerHelloCannotSendAnyIdentifiersOrOpen() async throws {
        let d = Driver(); d.configure(peerAllowed: false); let c = try client(d)
        await expect(.needsOwnerRecovery) { _ = try await c.start(until: self.deadline) }
        XCTAssertEqual(d.hellos, 1); XCTAssertTrue(d.calls.isEmpty); XCTAssertGreaterThan(d.closes, 0)
    }
    func testUnsupportedHelloVersionCannotSendOpen() async throws {
        let d = Driver(); d.configure(helloVersion: 2); let c = try client(d)
        await expect(.needsOwnerRecovery) { _ = try await c.start(until: self.deadline) }; XCTAssertTrue(d.calls.isEmpty)
    }
    func testChangedLocalIdentityBeforeHelloCannotStartTheDriver() async throws {
        let d = Driver(), c = try client(d, verify: { throw Fault.denied })
        await expect(.needsOwnerRecovery) { _ = try await c.start(until: self.deadline) }; XCTAssertEqual(d.hellos, 0); XCTAssertTrue(d.calls.isEmpty)
    }
    func testChangedLocalIdentityAfterOpenReplyRetiresTheConnection() async throws {
        let checks = Mutex(0), d = Driver(), c = try client(d, verify: {
            let n = checks.withLock { $0 += 1; return $0 }; if n == 4 { throw Fault.denied }
        })
        await expect(.needsOwnerRecovery) { _ = try await c.start(until: self.deadline) }; XCTAssertEqual(d.calls.map(\.action), [.open])
    }
    func testOnlyStagesPendingAllowsAnotherArmWithTheSameBinding() async throws {
        let d = Driver(); d.configure(pendingArms: 2); let c = try client(d), opened = try await c.start(until: deadline)
        let result = try await c.arm(until: deadline); XCTAssertEqual(result.outcome, .applied)
        XCTAssertEqual(d.calls.map(\.action), [.open, .arm, .arm, .arm]); XCTAssertTrue(d.calls.dropFirst().allSatisfy { $0.binding == opened.binding })
        XCTAssertEqual(Set(d.calls.map(\.challenge)).count, 4)
        await expect(.invalidState) { _ = try await c.arm(until: self.deadline) }; XCTAssertEqual(d.calls.count, 4); await c.close()
    }
    func testPendingStagesRespectOriginalBoundThenCancelTheExactBinding() async throws {
        let d = Driver(); d.configure(pendingArms: 1000); let c = try client(d, timeout: 200, interval: 100), opened = try await c.start(until: deadline)
        let began = ContinuousClock.now
        await expect(.cancelled) { _ = try await c.arm(until: began.advanced(by: .milliseconds(60))) }
        XCTAssertLessThan(began.duration(to: .now), .milliseconds(500)); XCTAssertEqual(d.calls.last?.action, .cancel)
        XCTAssertEqual(d.calls.last?.binding, opened.binding); XCTAssertTrue(d.calls.dropFirst().dropLast().allSatisfy { $0.action == .arm })
    }
    func testExpiredOriginalBoundCancelsWithoutSendingAnArm() async throws {
        let d = Driver(), c = try client(d); _ = try await c.start(until: deadline)
        await expect(.cancelled) { _ = try await c.arm(until: .now.advanced(by: .milliseconds(-1))) }; XCTAssertEqual(d.calls.map(\.action), [.open, .cancel])
    }
    func testRefusedArmTerminatesWithoutRetryOrAnotherMutation() async throws {
        let d = Driver(); d.configure(mode: .refused(.arm)); let c = try client(d); _ = try await c.start(until: deadline)
        await expect(.cancelled) { _ = try await c.arm(until: self.deadline) }; XCTAssertEqual(d.calls.map(\.action), [.open, .arm])
        await expect(.invalidState) { _ = try await c.arm(until: self.deadline) }
    }
    func testNilArmReplyRequiresRecoveryAndNeverReplaysArm() async throws {
        let d = Driver(); d.configure(mode: .nilReply(.arm)); let c = try client(d); _ = try await c.start(until: deadline)
        await expect(.needsOwnerRecovery) { _ = try await c.arm(until: self.deadline) }; XCTAssertEqual(d.calls.map(\.action), [.open, .arm])
        await expect(.invalidState) { _ = try await c.arm(until: self.deadline) }
    }
    func testMalformedAndUncorrelatedRepliesRequireRecoveryWithoutRetry() async throws {
        for mode in [Driver.Mode.malformed(.arm), .wrongChallenge(.arm), .foreignBinding(.arm)] {
            let d = Driver(); d.configure(mode: mode); let c = try client(d); _ = try await c.start(until: deadline)
            await expect(.needsOwnerRecovery) { _ = try await c.arm(until: self.deadline) }; XCTAssertEqual(d.calls.map(\.action), [.open, .arm])
        }
    }
    func testTimedOutArmAndLateReplyCannotReopenOrReplay() async throws {
        let d = Driver(); d.configure(mode: .hold(.arm)); let c = try client(d, timeout: 15); _ = try await c.start(until: deadline)
        await expect(.needsOwnerRecovery) { _ = try await c.arm(until: self.deadline) }; d.completeHeld()
        await expect(.invalidState) { _ = try await c.arm(until: self.deadline) }; XCTAssertEqual(d.calls.map(\.action), [.open, .arm])
    }
    func testConcurrentOperationClosesBothWithoutSendingASecondRequest() async throws {
        let d = Driver(); d.configure(mode: .hold(.observe)); let c = try client(d); _ = try await c.start(until: deadline)
        let first = Task { try await c.observe(until: deadline) }; try await waitUntil { d.calls.count == 2 }
        await expect(.needsOwnerRecovery) { _ = try await c.observe(until: self.deadline) }
        await expect(.needsOwnerRecovery) { _ = try await first.value }; d.completeHeld(); XCTAssertEqual(d.calls.map(\.action), [.open, .observe])
    }
    func testTaskCancellationClosesAnUncertainCallAndIgnoresItsLateReply() async throws {
        let d = Driver(); d.configure(mode: .hold(.arm)); let c = try client(d); _ = try await c.start(until: deadline)
        let arm = Task { try await c.arm(until: deadline) }; try await waitUntil { d.calls.count == 2 }; arm.cancel()
        await expect(.needsOwnerRecovery) { _ = try await arm.value }; d.completeHeld(); XCTAssertEqual(d.calls.map(\.action), [.open, .arm])
    }
    func testSynchronousInvalidationDoesNotDeadlockOrPermitAnotherSend() async throws {
        let d = Driver(), c = try client(d); _ = try await c.start(until: deadline); d.invalidate()
        do { _ = try await c.observe(until: deadline); XCTFail() }
        catch { XCTAssertTrue([AuthorityMaintenanceClientError.invalidState, .needsOwnerRecovery].contains(error as? AuthorityMaintenanceClientError ?? .cancelled)) }
        XCTAssertEqual(d.calls.map(\.action), [.open])
    }
    func testDuplicateCallbacksCannotCompleteTheNextRequest() async throws {
        let d = Driver(); d.configure(duplicate: true); let c = try client(d); _ = try await c.start(until: deadline)
        _ = try await c.observe(until: deadline); _ = try await c.arm(until: deadline); XCTAssertEqual(d.calls.map(\.action), [.open, .observe, .arm]); await c.close()
    }
    func testRefusedCleanupRequiresRecoveryAndIsNotRetried() async throws {
        let d = Driver(); d.configure(mode: .refused(.cancel)); let c = try client(d); _ = try await c.start(until: deadline)
        await expect(.needsOwnerRecovery) { try await c.release(until: self.deadline) }; XCTAssertEqual(d.calls.map(\.action), [.open, .cancel])
    }
    func testReopenRequiresTheSameIncarnationBeforeSendingTheTarget() async throws {
        let d = Driver(), c = try client(d), opened = try await c.start(until: deadline)
        let foreign = try AuthorityMaintenanceBinding(accountID: opened.binding.accountID, attemptID: opened.binding.attemptID,
            revision: opened.binding.revision, incarnation: Data(repeating: 99, count: 16), connectionID: opened.binding.connectionID)
        await expect(.needsOwnerRecovery) { try await c.release(foreign, reopen: true, until: self.deadline) }; XCTAssertEqual(d.calls.map(\.action), [.open])
    }
    func testOwnedConfigurationRejectsInvalidTimeoutIntervalAndContext() throws {
        let d = Driver(), q = try context()
        for timeout: UInt64 in [0, 60_001] { XCTAssertThrowsError(try AuthorityMaintenanceXPCClient.openOwned(context: q, driver: d, timeoutMilliseconds: timeout)) }
        for interval: UInt64 in [0, 1001] { XCTAssertThrowsError(try AuthorityMaintenanceXPCClient.openOwned(context: q, driver: d, intervalMilliseconds: interval)) }
    }
    func testEndpointHelloIsAuthenticatedAndCreatesNoAdmissionOrWork() throws {
        let q = try context(), admission = try AuthorityMaintenancePairingAdmission(accountID: q.accountID, incarnation: Data(repeating: 4, count: 16))
        let checks = Mutex(0), handshakes = Mutex(0), version = Mutex(UInt64.max)
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: admission, check: { _ in XCTFail("No protected read") }, observe: { _ in throw Fault.denied })
        let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1), verify: { checks.withLock { $0 += 1 } }, onHandshake: { handshakes.withLock { $0 += 1 } })
        endpoint.hello { n in version.withLock { $0 = n } }; XCTAssertEqual(version.withLock { $0 }, 1)
        XCTAssertEqual(checks.withLock { $0 }, 1); XCTAssertEqual(handshakes.withLock { $0 }, 0)
        XCTAssertEqual(endpoint.pendingOperations(), 0); XCTAssertEqual(try admission.connectionReservations(), 0)
        let stage = try admission.reserveStage(); stage.close(); endpoint.close(); endpoint.hello { n in version.withLock { $0 = n } }; XCTAssertEqual(version.withLock { $0 }, 0)
    }
    func testEndpointHelloRejectsOffStackIdentityBeforeAnyProtectedAccess() throws {
        let q = try context(), admission = try AuthorityMaintenancePairingAdmission(accountID: q.accountID, incarnation: Data(repeating: 4, count: 16))
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: admission, check: { _ in XCTFail() }, observe: { _ in throw Fault.denied })
        let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1), verify: { throw Fault.denied })
        let version = Mutex(UInt64.max); endpoint.hello { n in version.withLock { $0 = n } }
        XCTAssertEqual(version.withLock { $0 }, 0); XCTAssertEqual(try admission.connectionReservations(), 0)
    }
    private final class AnonymousDriver: AuthorityMaintenanceClientDriver, @unchecked Sendable {
        let connection: NSXPCConnection
        let events = Mutex<[String]>([])
        init(_ listener: NSXPCListener) { connection = .init(listenerEndpoint: listener.endpoint); connection.remoteObjectInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self) }
        func start(_ invalidated: @escaping @Sendable () -> Void) {
            connection.invalidationHandler = { [weak self] in self?.events.withLock { $0.append("invalidated") }; invalidated() }
            connection.interruptionHandler = { [weak self] in self?.events.withLock { $0.append("interrupted") }; invalidated() }; connection.activate()
        }
        private func proxy(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) -> (any AuthorityMaintenanceXPCProtocol)? {
            connection.remoteObjectProxyWithErrorHandler { [self] error in
                let e = error as NSError; events.withLock { $0.append("proxy " + e.domain + ":" + String(e.code)) }; reply(.bytes(nil))
            } as? any AuthorityMaintenanceXPCProtocol
        }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            events.withLock { $0.append("hello sent") }; proxy(reply)?.hello { [self] version in
                events.withLock { $0.append("hello reply " + String(version)) }; reply(.hello(version))
            }
        }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            let action = (try? Request.decode(bytes).action.rawValue) ?? 0; events.withLock { $0.append("send " + String(action)) }
            proxy(reply)?.exchange(bytes) { [self] bytes in
                events.withLock { $0.append(bytes == nil ? "nil reply" : "data reply") }; reply(.bytes(bytes))
            }
        }
        func close() { connection.invalidate() }
        deinit { close() }
    }
    private struct Builder: AuthorityMaintenanceEndpointBuilding {
        let access: AuthorityMaintenanceChannelAccess
        func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget, onHandshake: @escaping @Sendable () -> Void,
                  onClose: @escaping @Sendable () -> Void) throws -> AuthorityMaintenanceXPCEndpoint {
            let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: budget,
                invalidate: { [weak connection] in connection?.invalidate(); onClose() }, onHandshake: onHandshake)
            connection.exportedInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self); connection.exportedObject = endpoint
            connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }; connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }; return endpoint
        }
    }
    func testAnonymousTransportPreservesArmedTargetAfterCloseAndExactReopenReleasesIt() async throws {
        let q = try context(), admission = try AuthorityMaintenancePairingAdmission(accountID: q.accountID, incarnation: Data(repeating: 4, count: 16))
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: admission, check: { _ in }, observe: { _ in try Self.work(stages: admission.stagedReservations()) })
        let native = NSXPCListener.anonymous(), owner = try OwnedMaintenanceListener.openOwned(listener: native, builder: Builder(access: access))
        try owner.start(); defer { owner.close() }
        let first = AnonymousDriver(native), second = AnonymousDriver(native)
        let c = try AuthorityMaintenanceXPCClient.openOwned(context: q, driver: first)
        var phase = "initial open"
        do {
            let opened = try await c.start(until: deadline); phase = "arm"
            let armed = try await c.arm(until: deadline); XCTAssertEqual(armed.binding, opened.binding)
            await c.close(); XCTAssertThrowsError(try admission.reserveStage()); phase = "recovery open"
            let recovery = try AuthorityMaintenanceXPCClient.openOwned(context: q, driver: second)
            _ = try await recovery.start(until: deadline); phase = "exact reopen"
            try await recovery.release(opened.binding, reopen: true, until: deadline)
            let stage = try admission.reserveStage(); stage.close(); await owner.closeAndWait(); XCTAssertEqual(owner.retainedEndpoints(), 0)
        } catch {
            XCTFail("Anonymous transport failed during \(phase); first=\(first.events.withLock { $0 }); second=\(second.events.withLock { $0 })")
            throw error
        }
    }
    func testNativeClientRefusesOrdinaryIdentityBeforeConstructingAConnection() throws {
        XCTAssertNotEqual(getuid(), 0)
        func entry(_ role: AuthorityCodeRole) throws -> AuthorityCodeEntry {
            try .init(role: role, teamID: "ABCDEFGHIJ", identifier: role == .authority ? "dev.sebastiano.remozio.macos.authority" : "dev.sebastiano.remozio.macos.setup-controller",
                installedGeneration: 4, minimumGeneration: 4, codeDirectoryHash: Data(repeating: 1, count: 20), active: true)
        }
        let app = try ReleaseComponent(role: .app, identifier: "dev.sebastiano.remozio.macos", generation: 4,
            relativePath: "Contents/MacOS/Remozio", codeDirectoryHash: nil, build: "4", teamID: "ABCDEFGHIJ", formats: [])
        let release = SignedReleaseEvidence(manifest: try .init(release: "0.1.0", build: "4", components: [app]), codeDirectoryHashes: [:])
        XCTAssertThrowsError(try AuthorityMaintenanceXPCClient(context: context(), authority: entry(.authority), setup: entry(.setupController), release: release)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testDeliveredAppliedRepliesSurviveImmediateTransportInvalidation() async throws {
        for action in [Request.Action.open, .observe, .arm, .cancel, .reopen] {
            let d = Driver(), c = try client(d)
            if action == .open {
                d.configure(invalidateAfterReply: .open); let reply = try await c.start(until: deadline); XCTAssertEqual(reply.outcome, .applied)
            } else {
                _ = try await c.start(until: deadline); d.configure(invalidateAfterReply: action)
                switch action {
                case .observe: let reply = try await c.observe(until: deadline); XCTAssertEqual(reply.outcome, .applied)
                case .arm: let reply = try await c.arm(until: deadline); XCTAssertEqual(reply.outcome, .applied)
                case .cancel, .reopen: try await c.release(reopen: action == .reopen, until: deadline)
                case .open: XCTFail()
                }
            }
            await expect(.invalidState) { _ = try await c.arm(until: self.deadline) }
            XCTAssertEqual(d.calls.last?.action, action)
        }
    }
    func testDeliveredRefusedRepliesRemainCancelledAfterImmediateInvalidation() async throws {
        for action in [Request.Action.open, .observe, .arm] {
            let d = Driver(), c = try client(d)
            if action != .open { _ = try await c.start(until: deadline) }
            d.configure(mode: .refused(action), invalidateAfterReply: action)
            await expect(.cancelled) {
                switch action {
                case .open: _ = try await c.start(until: self.deadline)
                case .observe: _ = try await c.observe(until: self.deadline)
                case .arm: _ = try await c.arm(until: self.deadline)
                default: XCTFail()
                }
            }
            XCTAssertEqual(d.calls.last?.action, action)
        }
    }
    func testInvalidationBeforeDeliveryCannotAdoptTheLateAppliedReply() async throws {
        let d = Driver(), c = try client(d); _ = try await c.start(until: deadline); d.configure(mode: .hold(.arm))
        let arm = Task { try await c.arm(until: deadline) }; try await waitUntil { d.calls.count == 2 }
        d.invalidate(); await expect(.needsOwnerRecovery) { _ = try await arm.value }; d.completeHeld()
        await expect(.invalidState) { _ = try await c.arm(until: self.deadline) }; XCTAssertEqual(d.calls.map(\.action), [.open, .arm])
    }

}
