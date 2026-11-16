import Darwin
import Foundation
import Security

/// Owns one retained invocation through work, reply and explicit cleanup. It cannot create native loans.
final class SetupRetainedInvocation: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
    struct RightsState: Equatable, Sendable { let cancelled: Bool, expired: Bool }
    let peer: XPCPeerCredentials
    private let capture: (XPCInvocationGuard, SignedReleaseEvidence) throws -> SetupRetainedCallerBinding
    private let captureMaintenance: (XPCInvocationGuard, SignedReleaseEvidence) throws -> SetupAccountOwner.RetainedMaintenanceCapture
    private let recaptureMaintenance: (SetupAccountOwner.RetainedMaintenanceCapture, [PreparationIntentStore.RuntimeMaintenanceTransition],
        RuntimeMaintenanceStopCapture, AuthorityJournalCutoverInspection, SignedReleaseEvidence, () throws -> Void) throws -> SetupAccountOwner.RetainedMaintenanceCapture
    let acceptedPolicy: XPCPeerPolicy
    let incarnation: UUID
    private let processID = getpid(), processOwner = getuid()
    private let lock = NSRecursiveLock()
    private let cancellation = SetupAuditUpgradeCancellation()
    private let verifyRights: () throws -> Void
    private let closeRights: () -> Void
    private let verifyReservation: () throws -> Void
    private let reservation: SetupRetainedInvocationReservation
    private var active = false, invoked = false, closing = false, closed = false
    private var context: SetupRetainedInvocationContext?
    private let contextWorker = NSLock()
    private var contextThread: pthread_t?
    private var contextMintFailed = false
    var description: String { "SetupRetainedInvocation(redacted)" }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    /// Import on the actual exported invocation. No external form crosses dispatch or enters storage.
    static func open(owner: SetupAccountOwner, invocation: XPCInvocationGuard, externalForm: Data) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw SetupAdministratorAuthorizationError.wrongProcess }
        let peer = try invocation.verifyInvocation()
        guard peer.userID > 0, peer.userID < UInt32.max else { throw SetupAdministratorAuthorizationError.wrongProcess }
        let reference = try SetupAdministratorNative.importCurrentRights(externalForm: externalForm)
        let result = try begin(owner: owner, peer: peer, incarnation: invocation.incarnation, policy: invocation.acceptedPeerPolicy, verifyRights: {
            try SetupAdministratorNative.validatePolicy()
            try SetupAdministratorNative.copyRights(reference, flags: [])
            try SetupAdministratorNative.validatePolicy()
        }, closeRights: { _ = AuthorizationFree(reference, []) })
        do { try result.installContext { try .open(owner: result, invocation: invocation) }; return result }
        catch { try? result.close(); throw error }
    }
    /// Ordinary-owner controls cannot import Root rights or construct an invocation in a Root process.
    static func openOwned(owner: SetupAccountOwner, binding: SetupRetainedCallerBinding, policy: XPCPeerPolicy,
                          verifyRights: @escaping () throws -> Void, closeRights: @escaping () -> Void = {}) throws -> Self {
        guard getuid() > 0, getuid() == geteuid() else { throw SetupAdministratorAuthorizationError.wrongProcess }
        return try begin(owner: owner, peer: binding.peer, incarnation: binding.incarnation, policy: policy,
            verifyRights: verifyRights, closeRights: closeRights)
    }
    private static func begin(owner: SetupAccountOwner, peer: XPCPeerCredentials, incarnation: UUID, policy: XPCPeerPolicy,
        verifyRights: @escaping () throws -> Void, closeRights: @escaping () -> Void) throws -> Self {
        do {
            try verifyRights()
            let reservation = try owner.reserveRetainedInvocation(incarnation: incarnation)
            do {
                try verifyRights(); try reservation.verify()
                let value = Self(peer: peer, incarnation: incarnation, policy: policy, verifyRights: verifyRights, closeRights: closeRights,
                    verifyReservation: reservation.verify, reservation: reservation.record, capture: { invocation, candidate in
                        try owner.retainedCallerBinding(invocation: invocation, candidate: candidate, admission: reservation.record.admission)
                    }, captureMaintenance: { invocation, candidate in
                        try owner.retainedMaintenanceCapture(invocation: invocation, candidate: candidate, admission: reservation.record.admission)
                    }, recaptureMaintenance: { expected, transitions, capture, pair, candidate, current in
                        try owner.recaptureRetainedMaintenance(expected: expected, transitions: transitions, capture: capture,
                            pair: pair, candidate: candidate, admission: reservation.record.admission, current: current)
                    })
                try reservation.record.attach(value)
                return value
            } catch { reservation.record.abortConstruction(); throw error }
        } catch { closeRights(); throw error }
    }
    private init(peer: XPCPeerCredentials, incarnation: UUID, policy: XPCPeerPolicy,
                 verifyRights: @escaping () throws -> Void, closeRights: @escaping () -> Void,
                 verifyReservation: @escaping () throws -> Void, reservation: SetupRetainedInvocationReservation,
                 capture: @escaping (XPCInvocationGuard, SignedReleaseEvidence) throws -> SetupRetainedCallerBinding,
                 captureMaintenance: @escaping (XPCInvocationGuard, SignedReleaseEvidence) throws -> SetupAccountOwner.RetainedMaintenanceCapture,
                 recaptureMaintenance: @escaping (SetupAccountOwner.RetainedMaintenanceCapture, [PreparationIntentStore.RuntimeMaintenanceTransition],
                    RuntimeMaintenanceStopCapture, AuthorityJournalCutoverInspection, SignedReleaseEvidence, () throws -> Void) throws -> SetupAccountOwner.RetainedMaintenanceCapture) {
        self.peer = peer; self.incarnation = incarnation; acceptedPolicy = policy; self.capture = capture
        self.captureMaintenance = captureMaintenance; self.recaptureMaintenance = recaptureMaintenance
        self.verifyRights = verifyRights; self.closeRights = closeRights
        self.verifyReservation = verifyReservation; self.reservation = reservation
    }
    func belongs(to reservation: SetupRetainedInvocationReservation) -> Bool {
        getpid() == processID && self.reservation === reservation
    }
    /// Capture on the exported invocation after this owner exists. Failure keeps its reservation for cleanup.
    func callerBinding(invocation: XPCInvocationGuard, candidate: SignedReleaseEvidence) throws -> SetupRetainedCallerBinding {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        return try lock.withLock {
            guard !active, !invoked, invocation.incarnation == incarnation else { throw XPCPeerPolicyError.wrongConnection }
            active = true; defer { active = false }
            try validateLifetime()
            guard try invocation.verifyInvocation() == peer else { throw XPCPeerPolicyError.wrongPeer }
            let value = try capture(invocation, candidate)
            guard value.incarnation == incarnation, value.peer == peer else { throw XPCPeerPolicyError.wrongPeer }
            try validateLifetime(); return value
        }
    }
    func maintenanceCapture(invocation: XPCInvocationGuard, candidate: SignedReleaseEvidence,
        purpose: RuntimeMaintenanceWindowRecord.Purpose) throws -> SetupAccountOwner.RetainedMaintenanceCapture {
        try RuntimeMaintenanceCommitments.requireProfile(purpose)
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        return try lock.withLock {
            guard !active, !invoked, invocation.incarnation == incarnation else { throw XPCPeerPolicyError.wrongConnection }
            active = true; defer { active = false }; try validateLifetime()
            guard try invocation.verifyInvocation() == peer else { throw XPCPeerPolicyError.wrongPeer }
            let value = try captureMaintenance(invocation, candidate); try validateLifetime(); return value
        }
    }
    /// Fresh rights authorize metadata for this invocation. The real writer still proves storage and native ownership.
    func authorizedMaintenanceWindow(invocation: XPCInvocationGuard, expected: SetupAccountOwner.RetainedMaintenanceCapture,
        purpose: RuntimeMaintenanceWindowRecord.Purpose, candidate: SignedReleaseEvidence,
        id: Data, revision: Data) throws -> RuntimeMaintenanceWindowRecord {
        try RuntimeMaintenanceCommitments.requireProfile(purpose)
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        return try lock.withLock {
            try validateLifetime()
            guard !active, !invoked, invocation.incarnation == incarnation, try invocation.verifyInvocation() == peer,
                  expected.binding.peer == peer, expected.binding.incarnation == incarnation else {
                throw XPCPeerPolicyError.wrongPeer
            }
            let commitments = try RuntimeMaintenanceCommitments.capture(binding: expected.binding,
                inputs: expected.inputs, candidate: candidate, purpose: purpose)
            try validateLifetime()
            return try .init(id: id, revision: revision, purpose: purpose, scope: commitments.scope)
        }
    }
    func recaptureMaintenance(expected: SetupAccountOwner.RetainedMaintenanceCapture,
        transitions: [PreparationIntentStore.RuntimeMaintenanceTransition], capture: RuntimeMaintenanceStopCapture,
        pair: AuthorityJournalCutoverInspection, candidate: SignedReleaseEvidence) throws -> SetupAccountOwner.RetainedMaintenanceCapture {
        try withWorkerContext { scope in
            try scope.verify()
            guard expected.binding.peer == peer, expected.binding.incarnation == incarnation else { throw XPCPeerPolicyError.wrongPeer }
            let result = try recaptureMaintenance(expected, transitions, capture, pair, candidate, scope.verify)
            try scope.verify(); return result
        }
    }
    private func installContext(_ make: () throws -> SetupRetainedInvocationContext) throws {
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard !active, !invoked, !closed, context == nil, !contextMintFailed else {
                contextMintFailed = true; context?.retire(); throw JournalLeaseError.invalidated
            }
            active = true; defer { active = false }
            do {
                try validateLifetime(); let value = try make()
                guard !contextMintFailed else { value.retire(); throw JournalLeaseError.invalidated }
                context = value; try validateLifetime()
            } catch { contextMintFailed = true; context?.retire(); throw error }
        }
    }
    func withWorkerContext<Value>(_ body: (SetupRetainedInvocationContext.Scope) throws -> Value) throws -> Value {
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        try requireContextThread()
        return try lock.withLock {
            guard let context else { throw JournalLeaseError.invalidated }; return try context.withWorker(body)
        }
    }
    @discardableResult
    func installOwnedContext(connection: NSXPCConnection,
        readPeer: @escaping (NSXPCConnection) throws -> XPCPeerCredentials) throws -> SetupRetainedInvocationContext {
        try RuntimeMaintenanceOwnedControl.require()
        try installContext { try .openOwned(owner: self, connection: connection, readPeer: readPeer) }
        return try lock.withLock { guard let context else { throw JournalLeaseError.invalidated }; return context }
    }
    private func requireContextThread() throws {
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        try contextWorker.withLock {
            guard let contextThread, pthread_equal(contextThread, pthread_self()) != 0 else { throw JournalLeaseError.invalidated }
        }
    }
    func validateContextLifetime(_ value: SetupRetainedInvocationContext) throws {
        try requireContextThread()
        try lock.withLock {
            guard active, invoked, context === value else { throw JournalLeaseError.invalidated }
            try validateLifetime()
        }
    }
    /// A foreign connection cannot cancel this invocation. Cancellation does not release resources.
    func cancel(incarnation: UUID) {
        guard incarnation == self.incarnation else { return }; cancellation.cancel()
    }
    func validateLifetime() throws {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try validateOwner()
            try cancellation.check(); try verifyRights(); try verifyReservation(); try cancellation.check()
        }
    }
    private func validateOwner() throws {
        guard getpid() == processID, !closed, !closing, getuid() == processOwner, geteuid() == processOwner else {
            throw SetupAdministratorAuthorizationError.closed
        }
    }
    private func rightsState() -> RightsState {
        var cancelled = false, expired = false
        do { try cancellation.check() } catch { cancelled = true }
        do { try verifyRights() } catch { expired = true }
        return .init(cancelled: cancelled, expired: expired)
    }
    /// A single synchronous worker owns all work and its reply. A failure never permits body replay.
    func run<Value>(work: () throws -> Value, reply: (Value, RightsState) throws -> Void) throws {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard !active, !invoked, !closing, !closed else { throw AdministrativeSetupError.unavailable }
            try reservation.beginWorker(self)
            active = true; invoked = true; contextWorker.withLock { contextThread = pthread_self() }
            defer { active = false; contextWorker.withLock { contextThread = nil }; reservation.endWorker(self) }
            try validateLifetime(); let value = try work(); try validateOwner()
            let state = rightsState(); try validateOwner()
            try reply(value, state)
        }
    }
    /// Register the real cleanup owner before borrowing its resources. This does not grant native authority.
    func retainCleanup(_ close: @escaping () throws -> Void) throws {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard !closing, !closed else { throw AdministrativeSetupError.unavailable }
            try reservation.retainCleanup(self, close)
        }
    }
    /// Expired rights cannot prevent cleanup. A failed join leaves both admissions and shared activity held.
    func close() throws {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard !active else { throw AdministrativeSetupError.unavailable }
            guard !closed else { return }
            closing = true
            try reservation.settle(self) {
                closed = true; context?.retire(); context = nil; closeRights()
            }
        }
    }
    deinit { if getpid() == processID { closeRightsIfNeeded() } }
    private func closeRightsIfNeeded() { if !closed { closed = true; context?.retire(); context = nil; closeRights() } }
}
