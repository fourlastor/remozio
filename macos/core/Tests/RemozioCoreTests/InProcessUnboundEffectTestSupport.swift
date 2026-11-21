import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// A real ordinary-owner store and Authority operation. Driver faults remain synthetic and library-only.
final class InProcessUnboundEffectFixture: @unchecked Sendable {
    typealias Row = RuntimeMaintenanceWindowRecord
    typealias Phases = SetupRetainedInvocationReservation.RestorationPhases
    enum Fault: Equatable, Sendable { case none, nativeClosing, lostReleaseReply, foreignDrain, rpcBusy, pendingGate }
    struct AuthorityState: Sendable {
        let pairing: AuthorityMaintenancePairingAdmission, hold: AuthorityMaintenanceAdmissionHold
        let boundary: UpdateAdmissionBoundary, operation: AuthorityMaintenanceUnboundOperation
    }
    let f: ExplicitStartupFixture
    let authority: Mutex<AuthorityState>
    let fault = Mutex(Fault.none), releases = Mutex(0), writes = Mutex<[Row.Phase]>([])
    let foreignDrain = Mutex<UpdateDrainToken?>(nil)
    let gateCalls = Mutex(0), gatePending = Mutex(false), driverClosed = Mutex(false)
    let beforeCompletion = Mutex<(@Sendable () throws -> Void)?>(nil)
    let afterCompletion = Mutex<(@Sendable () throws -> Void)?>(nil)
    let afterIntent = Mutex<(@Sendable () throws -> Void)?>(nil)
    let beforeIntent = Mutex<(@Sendable () throws -> Void)?>(nil)
    let resourceCount = Mutex(0)
    init(_ f: ExplicitStartupFixture, held: Bool = false) throws {
        self.f = f; authority = Mutex(try Self.authority(f, held: held, epoch: 41))
    }
    private static func authority(_ f: ExplicitStartupFixture, held: Bool, epoch: UInt8) throws -> AuthorityState {
        let frame = try f.h.frame(), registration = frame.source.actual.admission, scope = f.h.initial.scope
        let projection = try RuntimeMaintenanceAdmissionProjection(record: held ? frame.window : nil,
            macID: scope.macID, installationID: scope.installationID, account: scope.authority, registration: registration)
        let hold = AuthorityMaintenanceAdmissionHold(projection: projection)
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: scope.authority.accountID,
            incarnation: Data(repeating: epoch, count: 16))
        let anchor = URL(fileURLWithPath: f.h.f.databasePath).deletingLastPathComponent().deletingLastPathComponent().path
        let machine = try UpdateAdmissionBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
            owner: getuid(), expected: registration.machine)
        let boundary = try UpdateAdmissionBoundary(machine: machine, account: f.h.barrier,
            verifyAdmission: { try hold.requireOpen() })
        let gate = try XCTUnwrap(registration.accounts.first { $0.accountID == scope.authority.accountID }).identity
        let operation = try AuthorityMaintenanceUnboundOperation.openOwned(admission: pairing, commands: .init(), hold: hold,
            boundary: boundary, accountID: scope.authority.accountID, gateIdentity: gate, read: { request, epoch in
                try f.h.f.machine().runtimeMaintenanceUnboundCommandRecord(request, account: scope.authority,
                    incarnation: epoch, candidate: f.h.f.candidate)
            })
        return .init(pairing: pairing, hold: hold, boundary: boundary, operation: operation)
    }
    func restartAuthorityHeld(epoch: UInt8) throws {
        let next = try Self.authority(f, held: true, epoch: epoch)
        authority.withLock { $0 = next }
    }
    private struct Resources: @unchecked Sendable {
        let directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease
    }
    func effect() throws -> SetupOrphanInProcessRestoreEffect {
        try .owned(processLease: f.processLease, read: { try self.f.h.frame() }, makeResources: { try self.resources() })
    }
    func resources() throws -> SetupOrphanInProcessRestoreEffect.OwnedResources {
        let (directory, admission) = try f.resources(), held = Resources(directory: directory, admission: admission)
        resourceCount.withLock { $0 += 1 }
        let h = f.h
        return try .init(release: h.f.candidate, admission: admission, directory: directory, accountBarrier: h.barrier,
            read: { try h.frame() }, persist: { next, previous in
                self.writes.withLock { $0.append(next.phase) }; return try h.persistForRecovery(next, previous: previous)
            }, writeIntent: { previous, joined, frame in
                let beforeIntent = self.beforeIntent.withLock { $0 }
                try beforeIntent?()
                let receipt = try h.f.machine().writeRuntimeMaintenanceUnboundIntent(replacing: previous,
                    joined: joined, expected: frame.source.actual, candidate: h.f.candidate,
                    directory: held.directory, admission: held.admission)
                self.writes.withLock { $0.append(receipt.record.phase) }
                let afterIntent = self.afterIntent.withLock { $0 }
                try afterIntent?(); return receipt
            }, writeCompletion: { previous, joined, observation, frame in
                let beforeCompletion = self.beforeCompletion.withLock { $0 }
                try beforeCompletion?()
                let receipt = try h.f.machine().writeRuntimeMaintenanceUnboundCompletion(replacing: previous,
                    joined: joined, observation: observation, expected: frame.source.actual, candidate: h.f.candidate,
                    directory: held.directory, admission: held.admission)
                self.writes.withLock { $0.append(receipt.record.phase) }
                let afterCompletion = self.afterCompletion.withLock { $0 }
                try afterCompletion?(); return receipt
            }, verify: { try h.verifyCurrent() }, inspect: { _ in try h.inspectOverride?() ?? h.inspected },
            observe: { _, _, _ in h.witness }, register: { h.registrations += 1 }, makeDriver: { phases in
                if try h.frame().window?.shutdownBinding != nil { return self.f.driver }
                return Driver(owner: self, phases: phases)
            }, capturePeer: { h.witness }, requirePeerLive: { witness in
                guard try !witness.hasExited() else { throw RuntimePreparationError.changedScope }
            })
    }
    func joined(shutdownSession: AdministrativeSetupShutdown.RecoverySessionWork? = nil)
        async throws -> (SetupRetainedOrphanClaim.Joined, SetupRetainedOrphanClaim.Target) {
        if f.invocation != nil { try f.retained.lose(&f.invocation) }
        let rights = f.rightsLive
        let authorization = try f.retained.authorize(verify: {
            guard rights.value.withLock({ $0 }) else { throw SetupAdministratorAuthorizationError.closed }
        })
        let target = try SetupRetainedOrphanClaim.Target.capture(owner: f.retained.owner, authorization: authorization)
        let claim = try f.retained.claim(authorization, target: target, shutdownSession: shutdownSession); f.claim = claim
        return (try await claim.join(), target)
    }
    func closeForeignDrain() { let drain = foreignDrain.withLock { value in let old = value; value = nil; return old }; drain?.close() }
    deinit { closeForeignDrain() }
    private final class Driver: AuthorityMaintenanceClientDriver, Sendable {
        private struct State { var closed = false; var invalidated: (@Sendable () -> Void)? }
        private let state = Mutex(State())
        let owner: InProcessUnboundEffectFixture, phases: Phases
        init(owner: InProcessUnboundEffectFixture, phases: Phases) { self.owner = owner; self.phases = phases }
        func start(_ invalidated: @escaping @Sendable () -> Void) { state.withLock { $0.invalidated = invalidated } }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            reply(.hello(AuthorityMaintenanceChannelScope.protocolVersion))
        }
        func observeIncarnation(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let q = try AuthorityMaintenanceIncarnationRequest.decode(bytes)
                let actual = try owner.authority.withLock { try $0.pairing.liveIncarnation(accountID: q.accountID) }
                reply(.bytes(try AuthorityMaintenanceIncarnationResponse(request: q, incarnation: actual).encoded))
            } catch { reply(.bytes(nil)) }
        }
        func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            owner.gateCalls.withLock { $0 += 1 }
            if owner.fault.withLock({ $0 }) == .pendingGate { owner.gatePending.withLock { $0 = true }; return }
            if owner.fault.withLock({ $0 }) == .nativeClosing { reply(.bytes(nil)); close(); return }
            Task {
                do {
                    let response = try await phases.run {
                        guard !self.state.withLock({ $0.closed }) else { throw AuthorityMaintenanceClientError.cancelled }
                        if self.owner.fault.withLock({ $0 }) == .foreignDrain,
                           self.owner.foreignDrain.withLock({ $0 == nil }) {
                            let drain = try self.owner.f.h.barrier.beginDrain()
                            self.owner.foreignDrain.withLock { $0 = drain }
                        }
                        let q = try AuthorityMaintenanceUnboundRequest.decode(bytes)
                        let operation = self.owner.authority.withLock { $0.operation }
                        let observed = try operation.observeGate(q)
                        if self.owner.fault.withLock({ $0 }) == .rpcBusy {
                            return try AuthorityMaintenanceUnboundGateResponse(request: observed.request,
                                hold: observed.hold, admission: .busy).encoded
                        }
                        return try observed.encoded
                    }
                    reply(.bytes(response))
                } catch { reply(.bytes(nil)) }
            }
        }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            Task {
                do {
                    let response = try await phases.run {
                        guard !self.state.withLock({ $0.closed }) else { throw AuthorityMaintenanceClientError.cancelled }
                        let q = try AuthorityMaintenanceUnboundRequest.decode(bytes)
                        self.owner.releases.withLock { $0 += 1 }
                        let operation = self.owner.authority.withLock { $0.operation }
                        return try operation.release(q).encoded
                    }
                    if owner.fault.withLock({ $0 }) == .lostReleaseReply { reply(.bytes(nil)); close() }
                    else { reply(.bytes(response)) }
                } catch { reply(.bytes(nil)) }
            }
        }
        func close() {
            let callback = state.withLock { value -> (@Sendable () -> Void)? in
                guard !value.closed else { return nil }; value.closed = true; return value.invalidated
            }
            owner.driverClosed.withLock { $0 = true }; callback?()
        }
    }
}
