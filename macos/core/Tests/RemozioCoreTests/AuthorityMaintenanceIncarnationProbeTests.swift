import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned endpoints, fake drivers and an anonymous XPC listener. These controls prove no installed Root or native peer identity.
final class AuthorityMaintenanceIncarnationProbeTests: XCTestCase, @unchecked Sendable {
    private typealias Request = AuthorityMaintenanceChannelRequest
    private typealias Response = AuthorityMaintenanceChannelResponse
    private typealias Probe = AuthorityMaintenanceIncarnationRequest
    private enum Fault: Error { case denied, timeout }
    private static let account = Data(repeating: 1, count: 16), epoch = Data(repeating: 4, count: 16)
    private var deadline: ContinuousClock.Instant { .now.advanced(by: .seconds(2)) }
    private func data(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }

    // MARK: Endpoint

    private final class Endpoint: @unchecked Sendable {
        let admission: AuthorityMaintenancePairingAdmission, incarnation: Data, budget: AuthorityXPCWorkBudget
        let checks = Mutex(0), captures = Mutex(0), acquisitions = Mutex(0), gates = Mutex(0)
        let handshakes = Mutex(0), invalidations = Mutex(0), verifications = Mutex(0)
        let entered = DispatchSemaphore(value: 0), unblock = DispatchSemaphore(value: 0), blockGate: Bool
        private(set) var endpoint: AuthorityMaintenanceXPCEndpoint!
        init(blockGate: Bool = false) throws {
            let clock = try AuthorityClock(); var epoch = clock.epoch.uuid
            incarnation = withUnsafeBytes(of: &epoch) { Data($0) }
            admission = try .init(accountID: AuthorityMaintenanceIncarnationProbeTests.account, incarnation: incarnation)
            budget = try .init(maximum: 1); self.blockGate = blockGate
            let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: admission, acquireActivity: { [self] in
                acquisitions.withLock { $0 += 1 }; return nil
            }, check: { [self] _ in checks.withLock { $0 += 1 } }, observe: { [self] _ in
                captures.withLock { $0 += 1 }; return try MaintenanceStopTestDriver.work()
            }, readGate: { [self] _ in
                gates.withLock { $0 += 1 }
                if self.blockGate { entered.signal(); _ = unblock.wait(timeout: .now() + 3) }
                throw RuntimePreparationError.changedScope
            })
            endpoint = try .openOwned(access: access, budget: budget, verify: { [self] in verifications.withLock { $0 += 1 } },
                invalidate: { [self] in invalidations.withLock { $0 += 1 } }, onHandshake: { [self] in handshakes.withLock { $0 += 1 } })
        }
        func hello() -> UInt64 { let v = Mutex(UInt64.max); endpoint.hello { n in v.withLock { $0 = n } }; return v.withLock { $0 } }
        func raw(_ payload: Data) throws -> Data? {
            let done = DispatchSemaphore(value: 0), result = Mutex<Data?>(nil)
            endpoint.observeIncarnation(payload) { b in result.withLock { $0 = b }; done.signal() }
            guard done.wait(timeout: .now() + 3) == .success else { throw Fault.timeout }
            return result.withLock { $0 }
        }
        func probe(account: Data = AuthorityMaintenanceIncarnationProbeTests.account, challenge: UInt8 = 6) throws -> AuthorityMaintenanceIncarnationResponse? {
            let q = try Probe(accountID: account, challenge: Data(repeating: challenge, count: 16))
            return try raw(q.encoded).map { try .decode($0, expected: q) }
        }
        func requireUntouched(file: StaticString = #filePath, line: UInt = #line) throws {
            XCTAssertEqual(checks.withLock { $0 }, 0, file: file, line: line); XCTAssertEqual(captures.withLock { $0 }, 0, file: file, line: line)
            XCTAssertEqual(acquisitions.withLock { $0 }, 0, file: file, line: line); XCTAssertEqual(handshakes.withLock { $0 }, 0, file: file, line: line)
            XCTAssertEqual(try admission.connectionReservations(), 0, file: file, line: line)
            XCTAssertEqual(try admission.stagedReservations(), 0, file: file, line: line); XCTAssertFalse(admission.hasArmedShutdown, file: file, line: line)
            let stage = try admission.reserveStage(); stage.close()
        }
    }
    func testProbeRepliesWithTheEpochThatAdmissionPutsInEveryBinding() throws {
        let f = try Endpoint(); defer { f.endpoint.close() }
        XCTAssertEqual(f.hello(), AuthorityMaintenanceChannelScope.protocolVersion)
        let first = try XCTUnwrap(f.probe()), second = try XCTUnwrap(f.probe(challenge: 7))
        XCTAssertEqual(first.incarnation, f.incarnation); XCTAssertEqual(second.incarnation, f.incarnation)
        XCTAssertEqual(first.accountID, Self.account); XCTAssertEqual(first.challenge, data(6)); XCTAssertEqual(second.challenge, data(7))
        XCTAssertEqual(f.verifications.withLock { $0 }, 3)
        try f.requireUntouched()
        let connection = try f.admission.openConnection(attemptID: data(2), revision: data(3))
        XCTAssertEqual(connection.binding.incarnation, first.incarnation); connection.close()
        XCTAssertEqual(try f.admission.refusalBinding(accountID: Self.account, attemptID: data(2), revision: data(3)).incarnation, first.incarnation)
        XCTAssertEqual(f.endpoint.pendingOperations(), 0); XCTAssertTrue(f.budget.acquire()); f.budget.release()
        XCTAssertEqual(f.invalidations.withLock { $0 }, 0)
    }
    func testProbeBeforeHelloClosesWithoutReadingAnything() throws {
        let f = try Endpoint()
        XCTAssertNil(try f.raw(Probe(accountID: Self.account, challenge: data(6)).encoded))
        XCTAssertEqual(f.invalidations.withLock { $0 }, 1); try f.requireUntouched()
        XCTAssertEqual(f.hello(), 0); XCTAssertTrue(f.budget.acquire()); f.budget.release()
    }
    func testForeignAccountClosesTheConnection() throws {
        let f = try Endpoint(); XCTAssertEqual(f.hello(), AuthorityMaintenanceChannelScope.protocolVersion)
        XCTAssertNil(try f.probe(account: data(2)))
        XCTAssertEqual(f.invalidations.withLock { $0 }, 1); try f.requireUntouched()
        XCTAssertNil(try f.raw(Probe(accountID: Self.account, challenge: data(6)).encoded))
        XCTAssertEqual(f.endpoint.pendingOperations(), 0); XCTAssertTrue(f.budget.acquire()); f.budget.release()
    }
    func testOffStackInvocationIsRejectedBeforeDecoding() throws {
        let admission = try AuthorityMaintenancePairingAdmission(accountID: Self.account, incarnation: Self.epoch)
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: admission, check: { _ in XCTFail() }, observe: { _ in throw Fault.denied })
        let invalidated = Mutex(0), replies = Mutex(0), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: budget,
            verify: { throw Fault.denied }, invalidate: { invalidated.withLock { $0 += 1 } })
        endpoint.observeIncarnation(try Probe(accountID: Self.account, challenge: data(6)).encoded) { XCTAssertNil($0); replies.withLock { $0 += 1 } }
        XCTAssertEqual(replies.withLock { $0 }, 1); XCTAssertEqual(invalidated.withLock { $0 }, 1)
        XCTAssertEqual(endpoint.pendingOperations(), 0); XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testMalformedOrOversizedFramesClose() throws {
        let valid = try Probe(accountID: Self.account, challenge: data(6)).encoded
        func map(_ fields: [UInt64: CBORValue]) throws -> Data {
            try DeterministicCBOR.encode(.map(fields), limits: CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 64))
        }
        let tag = CBORValue.text("authority.maintenance-incarnation-request")
        let frames: [Data] = [Data(), Data(repeating: 0, count: 129), valid + Data([0]), Data(valid.dropLast()),
            try map([0: .unsigned(2), 1: tag, 2: .bytes(Self.account), 3: .bytes(data(6))]),
            try map([0: .unsigned(1), 1: .text("authority.maintenance-gate-request"), 2: .bytes(Self.account), 3: .bytes(data(6))]),
            try map([0: .unsigned(1), 1: tag, 2: .bytes(Self.account), 3: .bytes(data(6, 15))]),
            try map([0: .unsigned(1), 1: tag, 2: .bytes(data(1, 17)), 3: .bytes(data(6))]),
            try map([0: .unsigned(1), 1: tag, 2: .bytes(Self.account)]),
            try map([0: .unsigned(1), 1: tag, 2: .bytes(Self.account), 3: .bytes(data(6)), 4: .bytes(data(7))]),
            try AuthorityMaintenanceIncarnationResponse(request: Probe(accountID: Self.account, challenge: data(6)), incarnation: Self.epoch).encoded]
        for frame in frames {
            let f = try Endpoint(); XCTAssertEqual(f.hello(), AuthorityMaintenanceChannelScope.protocolVersion)
            XCTAssertNil(try f.raw(frame)); XCTAssertEqual(f.invalidations.withLock { $0 }, 1)
            try f.requireUntouched(); XCTAssertEqual(f.endpoint.pendingOperations(), 0)
        }
    }
    func testConcurrentOperationClosesTheConnectionAndLeavesTheBudgetToItsOwner() async throws {
        let f = try Endpoint(blockGate: true); XCTAssertEqual(f.hello(), AuthorityMaintenanceChannelScope.protocolVersion)
        let target = try AuthorityMaintenanceBinding(accountID: Self.account, attemptID: data(2), revision: data(3),
            incarnation: f.incarnation, connectionID: data(5))
        let gate = try AuthorityMaintenanceGateRequest(accountID: Self.account, attemptID: data(2), revision: data(8),
            installationID: data(7), gate: .init(device: 8, inode: 9), target: target, challenge: data(11))
        f.endpoint.readGate(try gate.encoded) { _ in }
        XCTAssertEqual(f.entered.wait(timeout: .now() + 3), .success); XCTAssertFalse(f.budget.acquire())
        XCTAssertNil(try f.probe()); XCTAssertEqual(f.invalidations.withLock { $0 }, 1); XCTAssertFalse(f.budget.acquire())
        f.unblock.signal(); await f.endpoint.closeAndWait()
        XCTAssertEqual(f.endpoint.pendingOperations(), 0); XCTAssertTrue(f.budget.acquire()); f.budget.release()
        XCTAssertEqual(try f.admission.connectionReservations(), 0)
    }
    func testClosedAdmissionRefusesTheProbe() throws {
        let f = try Endpoint(); XCTAssertEqual(f.hello(), AuthorityMaintenanceChannelScope.protocolVersion)
        f.admission.close(); XCTAssertNil(try f.probe()); XCTAssertEqual(f.invalidations.withLock { $0 }, 1)
    }

    // MARK: Client

    private final class Driver: AuthorityMaintenanceClientDriver, Sendable {
        enum Mode: Sendable { case normal, wrongChallenge, foreignAccount, nilReply, malformed }
        private struct State {
            var mode = Mode.normal, epoch = AuthorityMaintenanceIncarnationProbeTests.epoch
            var helloVersion = AuthorityMaintenanceChannelScope.protocolVersion
            var hellos = 0, starts = 0, probes = 0, gates = 0, calls: [Request] = [], invalidated: (@Sendable () -> Void)?
        }
        private let state = Mutex(State())
        func configure(mode: Mode = .normal, helloVersion: UInt64 = AuthorityMaintenanceChannelScope.protocolVersion) {
            state.withLock { $0.mode = mode; $0.helloVersion = helloVersion }
        }
        var hellos: Int { state.withLock { $0.hellos } }
        var starts: Int { state.withLock { $0.starts } }
        var probes: Int { state.withLock { $0.probes } }
        var gates: Int { state.withLock { $0.gates } }
        var actions: [Request.Action] { state.withLock { $0.calls.map(\.action) } }
        func start(_ invalidated: @escaping @Sendable () -> Void) { state.withLock { $0.starts += 1; $0.invalidated = invalidated } }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            reply(.hello(state.withLock { $0.hellos += 1; return $0.helloVersion }))
        }
        func observeIncarnation(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let q = try Probe.decode(bytes), (mode, epoch) = state.withLock { $0.probes += 1; return ($0.mode, $0.epoch) }
                switch mode {
                case .normal: reply(.bytes(try AuthorityMaintenanceIncarnationResponse(request: q, incarnation: epoch).encoded))
                case .wrongChallenge:
                    reply(.bytes(try AuthorityMaintenanceIncarnationResponse(request: Probe(accountID: q.accountID, challenge: Data(repeating: 99, count: 16)), incarnation: epoch).encoded))
                case .foreignAccount:
                    reply(.bytes(try AuthorityMaintenanceIncarnationResponse(request: Probe(accountID: Data(repeating: 98, count: 16), challenge: q.challenge), incarnation: epoch).encoded))
                case .nilReply: reply(.bytes(nil))
                case .malformed: reply(.bytes(Data([0xff])))
                }
            } catch { reply(.bytes(nil)) }
        }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let q = try Request.decode(bytes), epoch = state.withLock { $0.calls.append(q); return $0.epoch }
                let binding = try q.binding ?? AuthorityMaintenanceBinding(accountID: q.accountID, attemptID: q.attemptID,
                    revision: q.revision, incarnation: epoch, connectionID: Data(repeating: 5, count: 16))
                let work = [.open, .observe, .arm].contains(q.action) ? try MaintenanceStopTestDriver.work() : nil
                reply(.bytes(try Response(request: q, binding: binding, work: work, outcome: .applied).encoded))
            } catch { reply(.bytes(nil)) }
        }
        func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let q = try AuthorityMaintenanceGateRequest.decode(bytes), epoch = state.withLock { $0.gates += 1; return $0.epoch }
                reply(.bytes(try AuthorityMaintenanceGateResponse(request: q, authorityIncarnation: epoch, hold: .released, admission: .available).encoded))
            } catch { reply(.bytes(nil)) }
        }
        func invalidate() { let callback = state.withLock { $0.invalidated }; callback?() }
        func close() { invalidate() }
    }
    private func context() throws -> Request {
        try .init(action: .open, accountID: Self.account, attemptID: data(2), revision: data(3), installationID: data(7),
            gate: .init(device: 8, inode: 9), binding: nil, challenge: data(6, 32))
    }
    private func client(_ driver: any AuthorityMaintenanceClientDriver) throws -> AuthorityMaintenanceXPCClient {
        try .openOwned(context: context(), driver: driver, timeoutMilliseconds: 500, intervalMilliseconds: 2)
    }
    private func stopped(_ incarnation: Data) throws -> AuthorityMaintenanceBinding {
        try .init(accountID: Self.account, attemptID: data(2), revision: data(80), incarnation: incarnation, connectionID: data(9))
    }
    private func expect(_ expected: AuthorityMaintenanceClientError, _ operation: () async throws -> Void) async {
        do { try await operation(); XCTFail("Expected a terminal client error") }
        catch { XCTAssertEqual(error as? AuthorityMaintenanceClientError, expected) }
    }
    func testProofGatesAHealthyOpenOnTheProbingConnectionWithoutASecondHello() async throws {
        let d = Driver(), c = try client(d)
        let proof = try await c.observeIncarnationOwned(until: deadline)
        XCTAssertEqual(proof.accountID, Self.account); XCTAssertEqual(proof.incarnation, Self.epoch)
        XCTAssertEqual(d.hellos, 1); XCTAssertEqual(d.starts, 1); XCTAssertEqual(d.probes, 1); XCTAssertTrue(d.actions.isEmpty)
        XCTAssertNoThrow(try proof.requireObserved(by: c))
        let opened = try await c.startObserved(proof, stopped: stopped(data(70)), until: deadline)
        XCTAssertEqual(opened.outcome, .applied); XCTAssertEqual(opened.binding.incarnation, proof.incarnation)
        XCTAssertEqual(d.hellos, 1); XCTAssertEqual(d.starts, 1); XCTAssertEqual(d.actions, [.open])
        XCTAssertNoThrow(try proof.requireObserved(by: c))
        _ = try await c.observe(until: deadline); try await c.release(until: deadline)
        XCTAssertEqual(d.actions, [.open, .observe, .cancel]); XCTAssertThrowsError(try proof.requireObserved(by: c))
    }
    func testSameEpochProofReopensTheSavedTargetOnTheProbingConnection() async throws {
        let d = Driver(), c = try client(d), proof = try await c.observeIncarnationOwned(until: deadline)
        let readback = try await c.reopenSavedObserved(proof, target: stopped(Self.epoch), until: deadline)
        XCTAssertEqual(readback.hold, .released); XCTAssertEqual(readback.admission, .available)
        XCTAssertEqual(readback.authorityIncarnation, Self.epoch)
        XCTAssertEqual(d.hellos, 1); XCTAssertEqual(d.starts, 1); XCTAssertEqual(d.actions, [.reopen]); XCTAssertEqual(d.gates, 1)
        XCTAssertThrowsError(try proof.requireObserved(by: c))
    }
    func testSameEpochCannotOpenHealthyAndNewEpochCannotReopen() async throws {
        let d = Driver(), c = try client(d), proof = try await c.observeIncarnationOwned(until: deadline)
        await expect(.needsOwnerRecovery) { _ = try await c.startObserved(proof, stopped: self.stopped(Self.epoch), until: self.deadline) }
        XCTAssertTrue(d.actions.isEmpty); XCTAssertThrowsError(try proof.requireObserved(by: c))
        let other = Driver(), reopening = try client(other), fresh = try await reopening.observeIncarnationOwned(until: deadline)
        await expect(.needsOwnerRecovery) { _ = try await reopening.reopenSavedObserved(fresh, target: self.stopped(self.data(70)), until: self.deadline) }
        XCTAssertTrue(other.actions.isEmpty); XCTAssertEqual(other.gates, 0); XCTAssertEqual(other.hellos, 1)
    }
    func testProofFromAnotherClientIsRefused() async throws {
        let first = Driver(), second = Driver(), a = try client(first), b = try client(second)
        let proof = try await a.observeIncarnationOwned(until: deadline), own = try await b.observeIncarnationOwned(until: deadline)
        XCTAssertEqual(proof.incarnation, own.incarnation); XCTAssertNotEqual(proof, own)
        XCTAssertThrowsError(try proof.requireObserved(by: b)); XCTAssertThrowsError(try own.requireObserved(by: a))
        await expect(.needsOwnerRecovery) { _ = try await b.startObserved(proof, stopped: self.stopped(self.data(70)), until: self.deadline) }
        XCTAssertTrue(second.actions.isEmpty); XCTAssertEqual(second.hellos, 1)
        let third = Driver(), c = try client(third), other = try await a.observeIncarnationOwned(until: deadline)
        await expect(.invalidState) { _ = try await c.startObserved(other, stopped: self.stopped(self.data(70)), until: self.deadline) }
        XCTAssertEqual(third.hellos, 0); XCTAssertTrue(third.actions.isEmpty)
        await expect(.needsOwnerRecovery) { _ = try await a.reopenSavedObserved(own, target: self.stopped(Self.epoch), until: self.deadline) }
        XCTAssertTrue(first.actions.isEmpty)
    }
    func testProofIsRefusedAfterItsClientClosesOrItsTransportIsInvalidated() async throws {
        let d = Driver(), c = try client(d), proof = try await c.observeIncarnationOwned(until: deadline)
        XCTAssertNoThrow(try proof.requireObserved(by: c)); await c.close(); XCTAssertThrowsError(try proof.requireObserved(by: c))
        await expect(.invalidState) { _ = try await c.startObserved(proof, stopped: self.stopped(self.data(70)), until: self.deadline) }
        let lost = Driver(), l = try client(lost), observed = try await l.observeIncarnationOwned(until: deadline)
        lost.invalidate(); XCTAssertThrowsError(try observed.requireObserved(by: l))
    }
    func testEchoMismatchesAndLostRepliesRetireTheConnection() async throws {
        for mode in [Driver.Mode.wrongChallenge, .foreignAccount, .nilReply, .malformed] {
            let d = Driver(); d.configure(mode: mode); let c = try client(d)
            await expect(.needsOwnerRecovery) { _ = try await c.observeIncarnationOwned(until: self.deadline) }
            XCTAssertEqual(d.probes, 1); await expect(.invalidState) { _ = try await c.start(until: self.deadline) }
            XCTAssertTrue(d.actions.isEmpty)
        }
    }
    func testVersionOneHelloRefusesTheProbeBeforeItIsSent() async throws {
        for version: UInt64 in [0, 1, 3] {
            let d = Driver(); d.configure(helloVersion: version); let c = try client(d)
            await expect(.needsOwnerRecovery) { _ = try await c.observeIncarnationOwned(until: self.deadline) }
            XCTAssertEqual(d.hellos, 1); XCTAssertEqual(d.probes, 0)
        }
    }
    func testExistingStartStillSendsItsOwnHelloAndCannotFollowAProbe() async throws {
        let d = Driver(), c = try client(d); _ = try await c.start(until: deadline); XCTAssertEqual(d.hellos, 1)
        let probed = Driver(), p = try client(probed); _ = try await p.observeIncarnationOwned(until: deadline)
        await expect(.invalidState) { _ = try await p.start(until: self.deadline) }; XCTAssertTrue(probed.actions.isEmpty)
    }
    func testNativeEntryRefusesAnOrdinaryOwnerAndAnOwnedDriver() async throws {
        XCTAssertNotEqual(getuid(), 0)
        let d = Driver(), c = try client(d)
        do { _ = try await c.observeIncarnationNative(until: deadline); XCTFail() } catch { XCTAssertEqual(error as? JournalLeaseError, .rootRequired) }
        XCTAssertEqual(d.hellos, 0)
    }

    // MARK: Anonymous XPC

    private final class AnonymousDriver: AuthorityMaintenanceClientDriver, @unchecked Sendable {
        let connection: NSXPCConnection, hellos = Mutex(0)
        init(_ listener: NSXPCListener) {
            connection = .init(listenerEndpoint: listener.endpoint)
            connection.remoteObjectInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self)
        }
        func start(_ invalidated: @escaping @Sendable () -> Void) {
            connection.invalidationHandler = invalidated; connection.interruptionHandler = invalidated; connection.activate()
        }
        private func proxy(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) -> (any AuthorityMaintenanceXPCProtocol)? {
            connection.remoteObjectProxyWithErrorHandler { _ in reply(.bytes(nil)) } as? any AuthorityMaintenanceXPCProtocol
        }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            hellos.withLock { $0 += 1 }; proxy(reply)?.hello { reply(.hello($0)) }
        }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            proxy(reply)?.exchange(bytes) { reply(.bytes($0)) }
        }
        func observeIncarnation(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            proxy(reply)?.observeIncarnation(bytes) { reply(.bytes($0)) }
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
            connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }; connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
            return endpoint
        }
    }
    func testAnonymousTransportProbeReportsTheEpochThatTheFollowingOpenBindingCarries() async throws {
        let clock = try AuthorityClock(); var raw = clock.epoch.uuid
        let incarnation = withUnsafeBytes(of: &raw) { Data($0) }
        let admission = try AuthorityMaintenancePairingAdmission(accountID: Self.account, incarnation: incarnation)
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: admission, check: { _ in },
            observe: { _ in try MaintenanceStopTestDriver.work() })
        let native = NSXPCListener.anonymous(), owner = try OwnedMaintenanceListener.openOwned(listener: native, builder: Builder(access: access))
        try owner.start(); defer { owner.close() }
        let driver = AnonymousDriver(native), c = try AuthorityMaintenanceXPCClient.openOwned(context: context(), driver: driver)
        let proof = try await c.observeIncarnationOwned(until: deadline)
        XCTAssertEqual(proof.incarnation, incarnation); XCTAssertEqual(try admission.connectionReservations(), 0)
        let opened = try await c.startObserved(proof, stopped: stopped(data(70)), until: deadline)
        XCTAssertEqual(opened.binding.incarnation, incarnation); XCTAssertEqual(driver.hellos.withLock { $0 }, 1)
        XCTAssertEqual(try admission.connectionReservations(), 1); XCTAssertNoThrow(try proof.requireObserved(by: c))
        try await c.release(until: deadline); XCTAssertThrowsError(try proof.requireObserved(by: c))
        await owner.closeAndWait(); XCTAssertEqual(owner.retainedEndpoints(), 0)
    }
}
