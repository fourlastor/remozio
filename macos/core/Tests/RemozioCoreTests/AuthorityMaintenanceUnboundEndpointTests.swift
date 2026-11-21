import Darwin
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceUnboundEndpointTests: XCTestCase, @unchecked Sendable {
    private enum Fault: Error { case timeout, wrongOrder, wrongRoute, activity, peer }
    private enum Selector { case exchange, gate }
    private final class Counts: Sendable {
        struct Value { var opens = 0, activities = 0, closes = 0, boundReads = 0 }
        let value = Mutex(Value())
    }
    private func fixture(_ body: (UnboundAuthorityMachine) throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { writer in
            let source = try writer.machine().stableRuntimeSource(candidate: writer.candidate)
            let account = try XCTUnwrap(source.preparations.first { $0.accountID == writer.target.accountID })
            let files = RuntimeMaintenanceReaderFixture(machine: writer.machine, candidate: writer.candidate,
                account: account, authority: writer.authority, databasePath: writer.databasePath,
                reopen: { try writer.reopen(nil) }, edit: writer.edit)
            let owner = try UnboundAuthorityMachine(files, startupHeld: true)
            defer { owner.close() }; try body(owner)
        }
    }
    private func work() throws -> AuthorityMaintenanceChannelWork {
        try .init(journal: .init(requests: .init(liveRequests: 0, commandCaptures: 0, activityOwners: 0),
            exchanges: .init(active: 0, stopped: false), nativeExecutions: 0, executionActivityOwners: 0),
            execution: .init(started: true, stopping: false, failed: false, queuedTurns: 0, rejectedTurns: 0),
            pairing: .init(ready: true, stagedAttempts: 0, activityOwners: 0, operationActive: false))
    }
    private func endpoint(_ owner: UnboundAuthorityMachine, counts: Counts,
        budget: AuthorityXPCWorkBudget? = nil, verify: @escaping () throws -> Void = {},
        beforeOpen: @escaping @Sendable () throws -> Void = {}, activityFails: Bool = false,
        operation: AuthorityMaintenanceUnboundOperation? = nil)
        throws -> AuthorityMaintenanceXPCEndpoint {
        let selected = try operation ?? owner.operation()
        let context = try selected.contextOwned(installationID: owner.records.pending.scope.installationID,
            beforeOpen: {
                counts.value.withLock { $0.opens += 1 }
                try beforeOpen()
            })
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: owner.admission,
            commandExclusion: owner.commands, acquireActivity: {
                do {
                    let unexpected = try owner.commands.acquire(); unexpected.close(); throw Fault.wrongOrder
                } catch AuthorityMaintenanceCommandExclusion.AcquisitionError.busy {}
                counts.value.withLock { $0.activities += 1 }
                if activityFails { throw Fault.activity }; return nil
            }, check: { _ in }, observe: { _ in try self.work() }, readGate: { _ in
                counts.value.withLock { $0.boundReads += 1 }; throw Fault.wrongRoute
            }, unbound: context)
        return try .openOwned(access: access, budget: budget ?? .init(maximum: 1), verify: verify,
            invalidate: { counts.value.withLock { $0.closes += 1 } })
    }
    private func wait(_ test: () -> Bool) throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !test() {
            guard ContinuousClock.now < deadline else { throw Fault.timeout }; usleep(1000)
        }
    }
    private func hello(_ peer: any AuthorityMaintenanceXPCProtocol) throws -> UInt64 {
        let result = Mutex<UInt64?>(nil)
        peer.hello { version in result.withLock { $0 = version } }
        try wait { result.withLock { $0 != nil } }; return try XCTUnwrap(result.withLock { $0 })
    }
    private func call(_ peer: any AuthorityMaintenanceXPCProtocol, _ bytes: Data, _ selector: Selector,
        endpoint: AuthorityMaintenanceXPCEndpoint? = nil) throws -> Data? {
        let result = Mutex<(Bool, Data?)>((false, nil))
        let reply: @Sendable (Data?) -> Void = { bytes in result.withLock { $0 = (true, bytes) } }
        switch selector {
        case .exchange: peer.exchange(bytes, reply: reply)
        case .gate: peer.readGate(bytes, reply: reply)
        }
        try wait { result.withLock { $0.0 } && (endpoint?.pendingOperations() ?? 0) == 0 }
        return result.withLock { $0.1 }
    }
    private func gate(_ endpoint: AuthorityMaintenanceXPCEndpoint, _ request: AuthorityMaintenanceUnboundRequest)
        throws -> AuthorityMaintenanceUnboundGateResponse {
        try .decode(XCTUnwrap(call(endpoint, request.encoded, .gate, endpoint: endpoint)))
    }
    private func release(_ endpoint: AuthorityMaintenanceXPCEndpoint, _ request: AuthorityMaintenanceUnboundRequest)
        throws -> AuthorityMaintenanceUnboundReleaseResponse {
        try .decode(XCTUnwrap(call(endpoint, request.encoded, .exchange, endpoint: endpoint)))
    }
    private func joinedClose(_ endpoint: AuthorityMaintenanceXPCEndpoint) throws {
        let done = Mutex(false)
        Task { await endpoint.closeAndWait(); done.withLock { $0 = true } }
        try wait { done.withLock { $0 } }
    }
    private func bound(_ owner: UnboundAuthorityMachine) throws -> AuthorityMaintenanceChannelRequest {
        let q = try owner.records.request(.gate)
        return try .init(action: .open, accountID: q.accountID, attemptID: q.attemptID,
            revision: q.revision, installationID: q.installationID, gate: q.gate,
            binding: nil, challenge: unboundAuthorityBytes(50, 32))
    }

    func testSharedDispatchReleasesTheHeldBusyWindowAndReadsItsActualGate() throws {
        try fixture { owner in
            let counts = Counts(), e = try endpoint(owner, counts: counts), before = try runtimeMaintenanceFixtureRows(owner.fixture.databasePath)
            defer { e.close() }; XCTAssertEqual(try hello(e), 3)
            let probe = try gate(e, owner.records.request(.gate))
            XCTAssertEqual(probe.hold, .held); XCTAssertEqual(probe.admission, .busy)
            XCTAssertEqual(try release(e, owner.records.request(.release)).outcome, .released)
            let final = try gate(e, owner.records.request(.gate))
            XCTAssertEqual(final.hold, .released); XCTAssertEqual(final.admission, .available)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(owner.fixture.databasePath), before)
            XCTAssertEqual(counts.value.withLock { $0.activities }, 3)
            XCTAssertEqual(counts.value.withLock { $0.opens }, 3)
            XCTAssertEqual(counts.value.withLock { $0.closes }, 0)
        }
    }
    func testCompetingCommandReturnsTheRealHeldBusyReplyWithoutOpeningTheFactory() throws {
        try fixture { owner in
            let counts = Counts(), budget = try AuthorityXPCWorkBudget(maximum: 1), e = try endpoint(owner, counts: counts, budget: budget)
            defer { e.close() }; XCTAssertEqual(try hello(e), 3)
            let command = try owner.commands.acquire()
            let request = try owner.records.request(.gate), observed = try gate(e, request)
            XCTAssertEqual(observed.request, request); XCTAssertEqual(observed.hold, .held); XCTAssertEqual(observed.admission, .busy)
            XCTAssertEqual(counts.value.withLock { $0.opens }, 0); XCTAssertEqual(counts.value.withLock { $0.activities }, 0)
            XCTAssertEqual(owner.reads.withLock { $0 }, 0); XCTAssertEqual(counts.value.withLock { $0.closes }, 0)
            XCTAssertTrue(budget.acquire()); budget.release(); try command.validate(); command.close()
            XCTAssertEqual(try release(e, owner.records.request(.release)).outcome, .released)
        }
    }
    func testCompetingCommandReportsTheActualReleasedHoldWithoutAStoreRead() throws {
        try fixture { owner in
            let operation = try owner.operation()
            XCTAssertEqual(try operation.release(owner.records.request(.release)).outcome, .released)
            let reads = owner.reads.withLock { $0 }, counts = Counts(), e = try endpoint(owner, counts: counts)
            defer { e.close() }; XCTAssertEqual(try hello(e), 3)
            let command = try owner.commands.acquire(); defer { command.close() }
            let observed = try gate(e, owner.records.request(.gate))
            XCTAssertEqual(observed.hold, .released); XCTAssertEqual(observed.admission, .busy)
            XCTAssertEqual(owner.reads.withLock { $0 }, reads); XCTAssertEqual(counts.value.withLock { $0.closes }, 0)
        }
    }
    func testLazyFactoryBusyUsesTheSameActualHoldReplyAndReleasesItsCommand() throws {
        try fixture { owner in
            let counts = Counts(), e = try endpoint(owner, counts: counts, beforeOpen: {
                throw AuthorityMaintenanceCommandExclusion.AcquisitionError.busy
            })
            defer { e.close() }; XCTAssertEqual(try hello(e), 3)
            let observed = try gate(e, owner.records.request(.gate))
            XCTAssertEqual(observed.hold, .held); XCTAssertEqual(observed.admission, .busy)
            XCTAssertEqual(counts.value.withLock { $0.activities }, 1); XCTAssertEqual(counts.value.withLock { $0.opens }, 1)
            XCTAssertEqual(owner.reads.withLock { $0 }, 0); XCTAssertEqual(counts.value.withLock { $0.closes }, 0)
            let command = try owner.commands.acquire(); command.close()
            XCTAssertEqual(try release(e, owner.records.request(.release)).outcome, .busy)
        }
    }
    func testBusyGateRejectsAnotherAttemptInsteadOfInventingAHold() throws {
        try fixture { owner in
            let counts = Counts(), e = try endpoint(owner, counts: counts); defer { e.close() }
            XCTAssertEqual(try hello(e), 3)
            let q = try owner.records.request(.gate)
            let other = try AuthorityMaintenanceUnboundRequest(kind: .gate, installationID: q.installationID,
                accountID: q.accountID, attemptID: unboundAuthorityBytes(91), revision: q.revision, rowDigest: q.rowDigest,
                pendingRevision: q.pendingRevision, intentID: q.intentID, gate: q.gate,
                authorityIncarnation: q.authorityIncarnation, challenge: q.challenge)
            let command = try owner.commands.acquire(); defer { command.close() }
            XCTAssertNil(try call(e, other.encoded, .gate, endpoint: e))
            XCTAssertEqual(owner.reads.withLock { $0 }, 0); XCTAssertGreaterThan(counts.value.withLock { $0.closes }, 0)
            try command.validate()
        }
    }
    func testBusyAfterTheActualReleaseEffectClosesInsteadOfReturningBusy() throws {
        try fixture { owner in
            let operation = try owner.operation { count, _ in
                if count == 2 { throw AuthorityMaintenanceCommandExclusion.AcquisitionError.busy }
            }
            let counts = Counts(), e = try endpoint(owner, counts: counts, operation: operation)
            defer { e.close() }; XCTAssertEqual(try hello(e), 3)
            let before = try runtimeMaintenanceFixtureRows(owner.fixture.databasePath)
            XCTAssertNil(try call(e, owner.records.request(.release).encoded, .exchange, endpoint: e))
            XCTAssertGreaterThan(counts.value.withLock { $0.closes }, 0)
            XCTAssertEqual(owner.reads.withLock { $0 }, 2); XCTAssertNoThrow(try owner.hold.requireOpen())
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(owner.fixture.databasePath), before)
            let command = try owner.commands.acquire(); command.close()
        }
    }
    func testUnboundCallsBeforeHelloRefuseWithoutFactoryActivityOrReads() throws {
        try fixture { owner in
            for kind in [AuthorityMaintenanceUnboundRequest.Kind.release, .gate] {
                let counts = Counts(), e = try endpoint(owner, counts: counts); defer { e.close() }
                XCTAssertNil(try call(e, owner.records.request(kind).encoded, kind == .release ? .exchange : .gate, endpoint: e))
                XCTAssertEqual(counts.value.withLock { $0.opens }, 0); XCTAssertEqual(counts.value.withLock { $0.activities }, 0)
            }
            XCTAssertEqual(owner.reads.withLock { $0 }, 0)
        }
    }
    func testBoundExchangeStillWorksBeforeHelloAndCannotSwitchToUnbound() throws {
        try fixture { owner in
            let counts = Counts(), e = try endpoint(owner, counts: counts); defer { e.close() }
            let request = try bound(owner)
            let opened = try AuthorityMaintenanceChannelResponse.decode(XCTUnwrap(call(e, request.encoded, .exchange, endpoint: e)), expected: request)
            XCTAssertEqual(opened.outcome, .applied); XCTAssertEqual(try hello(e), 3)
            XCTAssertNil(try call(e, owner.records.request(.gate).encoded, .gate, endpoint: e))
            XCTAssertEqual(counts.value.withLock { $0.opens }, 0); XCTAssertEqual(owner.reads.withLock { $0 }, 0)
        }
    }
    func testUnboundModeRejectsBothBoundSelectorsBeforeTheirEffects() throws {
        try fixture { owner in
            for selector in [Selector.exchange, .gate] {
                let counts = Counts(), e = try endpoint(owner, counts: counts); defer { e.close() }
                XCTAssertEqual(try hello(e), 3)
                let held = try gate(e, owner.records.request(.gate)); XCTAssertEqual(held.hold, .held)
                let reads = owner.reads.withLock { $0 }, request = try bound(owner)
                let bytes: Data
                switch selector {
                case .exchange: bytes = try request.encoded
                case .gate:
                    let binding = try owner.admission.refusalBinding(accountID: request.accountID,
                        attemptID: request.attemptID, revision: request.revision)
                    bytes = try AuthorityMaintenanceGateRequest(accountID: request.accountID, attemptID: request.attemptID,
                        revision: request.revision, installationID: request.installationID, gate: request.gate,
                        target: binding, challenge: unboundAuthorityBytes(51)).encoded
                }
                XCTAssertNil(try call(e, bytes, selector, endpoint: e))
                XCTAssertEqual(owner.reads.withLock { $0 }, reads); XCTAssertEqual(counts.value.withLock { $0.boundReads }, 0)
            }
        }
    }
    func testWrongSelectorAndNoncanonicalUnboundBytesNeverOpenTheFactory() throws {
        try fixture { owner in
            for fault in 0..<3 {
                let counts = Counts(), e = try endpoint(owner, counts: counts); defer { e.close() }
                XCTAssertEqual(try hello(e), 3)
                let kind: AuthorityMaintenanceUnboundRequest.Kind = fault == 0 ? .release : .gate
                var bytes = try owner.records.request(kind).encoded
                if fault == 2 { bytes = Data([0xb8, 0x0c]) + bytes.dropFirst() }
                XCTAssertNil(try call(e, bytes, fault == 1 ? .exchange : .gate, endpoint: e))
                XCTAssertEqual(counts.value.withLock { $0.opens }, 0); XCTAssertEqual(counts.value.withLock { $0.activities }, 0)
            }
            XCTAssertEqual(owner.reads.withLock { $0 }, 0)
        }
    }
    func testActivityFailureClosesWithoutAFactoryReadOrLeakedCommand() throws {
        try fixture { owner in
            let counts = Counts(), budget = try AuthorityXPCWorkBudget(maximum: 1)
            let e = try endpoint(owner, counts: counts, budget: budget, activityFails: true); defer { e.close() }
            XCTAssertEqual(try hello(e), 3)
            XCTAssertNil(try call(e, owner.records.request(.release).encoded, .exchange, endpoint: e))
            XCTAssertEqual(counts.value.withLock { $0.opens }, 0); XCTAssertEqual(owner.reads.withLock { $0 }, 0)
            let command = try owner.commands.acquire(); command.close(); XCTAssertTrue(budget.acquire()); budget.release()
        }
    }
    func testCloseDuringFactoryWorkJoinsTheTaskAndPreventsLateRelease() throws {
        try fixture { owner in
            let entered = Mutex(false), resumes = DispatchSemaphore(value: 0), counts = Counts()
            let budget = try AuthorityXPCWorkBudget(maximum: 1)
            let e = try endpoint(owner, counts: counts, budget: budget, beforeOpen: {
                entered.withLock { $0 = true }
                guard resumes.wait(timeout: .now() + 4) == .success else { throw Fault.timeout }
            })
            defer { resumes.signal(); e.close() }; XCTAssertEqual(try hello(e), 3)
            let replies = Mutex(0)
            e.exchange(try owner.records.request(.release).encoded) { _ in replies.withLock { $0 += 1 } }
            try wait { entered.withLock { $0 } }; e.close(); resumes.signal(); try joinedClose(e)
            XCTAssertEqual(e.pendingOperations(), 0); XCTAssertEqual(replies.withLock { $0 }, 0)
            XCTAssertEqual(owner.reads.withLock { $0 }, 0); XCTAssertThrowsError(try owner.hold.requireOpen())
            let command = try owner.commands.acquire(); command.close(); XCTAssertTrue(budget.acquire()); budget.release()
        }
    }
    func testForeignAndClosedCommandTokensRefuseBeforeProtectedReads() throws {
        try fixture { owner in
            let operation = try owner.operation(), other = AuthorityMaintenanceCommandExclusion()
            let foreign = try other.acquire(); defer { foreign.close() }
            XCTAssertThrowsError(try operation.release(owner.records.request(.release), command: foreign))
            XCTAssertThrowsError(try operation.observeGate(owner.records.request(.gate), command: foreign))
            let closed = try owner.commands.acquire(); closed.close()
            XCTAssertThrowsError(try operation.release(owner.records.request(.release), command: closed))
            XCTAssertEqual(owner.reads.withLock { $0 }, 0); XCTAssertThrowsError(try owner.hold.requireOpen())
        }
    }
    func testOwnedAccessRefusesForeignAdmissionAndCommandOwners() throws {
        try fixture { owner in
            let context = try owner.operation().contextOwned(installationID: owner.records.pending.scope.installationID)
            let other = try AuthorityMaintenancePairingAdmission(accountID: owner.records.pending.scope.authority.accountID,
                incarnation: unboundAuthorityBytes(41))
            XCTAssertThrowsError(try AuthorityMaintenanceChannelAccess.openOwned(admission: other,
                check: { _ in }, observe: { _ in try self.work() }, unbound: context))
            XCTAssertThrowsError(try AuthorityMaintenanceChannelAccess.openOwned(admission: owner.admission,
                commandExclusion: .init(), check: { _ in }, observe: { _ in try self.work() }, unbound: context))
            XCTAssertEqual(owner.reads.withLock { $0 }, 0)
        }
    }

    private final class InvocationStack: @unchecked Sendable {
        private let lock = NSLock()
        private var connection: NSXPCConnection?
        let checks = Mutex(0)
        func install(_ connection: NSXPCConnection) { lock.withLock { self.connection = connection } }
        func verify() throws {
            let expected = lock.withLock { connection }
            guard let actual = NSXPCConnection.current(), actual === expected,
                  actual.processIdentifier == getpid(), actual.effectiveUserIdentifier == getuid() else { throw Fault.peer }
            checks.withLock { $0 += 1 }
        }
        func close() {
            let old = lock.withLock { let old = connection; connection = nil; return old }; old?.invalidate()
        }
    }
    private final class Bridge: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        let endpoint: AuthorityMaintenanceXPCEndpoint, invocation: InvocationStack
        init(endpoint: AuthorityMaintenanceXPCEndpoint, invocation: InvocationStack) {
            self.endpoint = endpoint; self.invocation = invocation
        }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            invocation.install(connection)
            connection.exportedInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self)
            connection.exportedObject = endpoint
            connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
            connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }
            connection.activate(); return true
        }
        func close() { invocation.close(); endpoint.close() }
    }
    /// Owned anonymous XPC uses the shared endpoint. Installed Root signature checks remain unqualified.
    func testAnonymousXPCDispatchAuthenticatesOnTheExportedStackAndUsesTheSameOperation() throws {
        try fixture { owner in
            let counts = Counts(), stack = InvocationStack(), e = try endpoint(owner, counts: counts, verify: { try stack.verify() })
            let bridge = Bridge(endpoint: e, invocation: stack), listener = NSXPCListener.anonymous()
            listener.delegate = bridge; listener.activate()
            let client = NSXPCConnection(listenerEndpoint: listener.endpoint)
            client.remoteObjectInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self); client.activate()
            defer { client.invalidate(); bridge.close(); listener.invalidate() }
            let failures = Mutex(0)
            let proxy = try XCTUnwrap(client.remoteObjectProxyWithErrorHandler { _ in failures.withLock { $0 += 1 } }
                as? any AuthorityMaintenanceXPCProtocol)
            XCTAssertEqual(try hello(proxy), 3)
            let before = try runtimeMaintenanceFixtureRows(owner.fixture.databasePath)
            let release = try owner.records.request(.release), gate = try owner.records.request(.gate)
            let reply = try AuthorityMaintenanceUnboundReleaseResponse.decode(XCTUnwrap(call(proxy, release.encoded, .exchange, endpoint: e)))
            XCTAssertEqual(reply.request, release); XCTAssertEqual(reply.outcome, .released)
            let observed = try AuthorityMaintenanceUnboundGateResponse.decode(XCTUnwrap(call(proxy, gate.encoded, .gate, endpoint: e)))
            XCTAssertEqual(observed.request, gate); XCTAssertEqual(observed.hold, .released); XCTAssertEqual(observed.admission, .available)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(owner.fixture.databasePath), before)
            XCTAssertGreaterThanOrEqual(stack.checks.withLock { $0 }, 3); XCTAssertEqual(failures.withLock { $0 }, 0)
            try joinedClose(e)
        }
    }
}
