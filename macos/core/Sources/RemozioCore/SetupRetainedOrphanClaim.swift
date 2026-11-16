import Darwin
import Foundation
import Security

/// Fresh connection-bound rights. These rights cannot borrow a second operation or select a foreign reservation.
final class SetupRetainedRecoveryAuthorization: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    var description: String { "SetupRetainedRecoveryAuthorization(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    let peer: XPCPeerCredentials, currentOwner: LocalAccountIdentity, incarnation: UUID
    private let process = getpid(), user = getuid(), lock = NSLock()
    private let verify: () throws -> Void, release: () -> Void
    private var closed = false, used = false, checking = false, released = false
    private init(peer: XPCPeerCredentials, currentOwner: LocalAccountIdentity, incarnation: UUID,
        verify: @escaping () throws -> Void, release: @escaping () -> Void) {
        self.peer = peer; self.currentOwner = currentOwner; self.incarnation = incarnation
        self.verify = verify; self.release = release
    }
    /// Capture on the actual exported invocation. No endpoint calls this factory in M12a.
    static func openNative(invocation: XPCInvocationGuard, externalForm: Data) throws -> SetupRetainedRecoveryAuthorization {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try invocation.withRetainedConnection { connection, policy, peer in
            guard peer.userID > 0, peer.userID < UInt32.max else { throw XPCPeerPolicyError.wrongPeer }
            let owner = try LocalAccountDirectory.lookup(uid: peer.userID)
            let reference = try SetupAdministratorNative.importCurrentRights(externalForm: externalForm)
            let value = SetupRetainedRecoveryAuthorization(peer: peer, currentOwner: owner, incarnation: invocation.incarnation,
                verify: {
                    try invocation.requireRetainedConnection(connection, peer: peer, policy: policy)
                    guard try LocalAccountDirectory.lookup(uid: peer.userID) == owner else { throw XPCPeerPolicyError.wrongPeer }
                    try SetupAdministratorNative.validatePolicy()
                    try SetupAdministratorNative.copyRights(reference, flags: [])
                    try SetupAdministratorNative.validatePolicy()
                }, release: { _ = AuthorizationFree(reference, []) })
            do { try value.requireCurrent(); return value } catch { value.close(); throw error }
        }
    }
    /// Ordinary-owner rights/lifetime controls only. Root cannot inject verification or cleanup callbacks.
    static func openOwned(peer: XPCPeerCredentials, currentOwner: LocalAccountIdentity, incarnation: UUID,
        verifyRights: @escaping () throws -> Void, closeRights: @escaping () -> Void = {}) throws -> SetupRetainedRecoveryAuthorization {
        try RuntimeMaintenanceOwnedControl.require()
        guard peer.processID > 0, peer.userID > 0, peer.userID < UInt32.max,
              peer.userID == currentOwner.uid else { throw XPCPeerPolicyError.wrongPeer }
        let value = Self(peer: peer, currentOwner: currentOwner, incarnation: incarnation,
            verify: verifyRights, release: closeRights)
        do { try value.requireCurrent(); return value } catch { value.close(); throw error }
    }
    func requireCurrent() throws {
        guard getpid() == process, getuid() == user, geteuid() == user else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard !closed, !checking else { throw SetupAdministratorAuthorizationError.closed }; checking = true
        }
        defer {
            lock.withLock { checking = false }
            releaseIfClosed()
        }
        try verify()
        guard getpid() == process, getuid() == user, geteuid() == user else { throw JournalLeaseError.invalidated }
        try lock.withLock { guard !closed else { throw SetupAdministratorAuthorizationError.closed } }
    }
    /// Each explicit claim imports its own rights. A failed claim cannot reuse this authorization for another record.
    func takeForClaim() throws {
        guard getpid() == process, getuid() == user, geteuid() == user else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard !closed, !used, !checking else { throw SetupAdministratorAuthorizationError.closed }; used = true
        }
        try requireCurrent()
    }
    private func releaseIfClosed() {
        let shouldRelease = lock.withLock {
            guard closed, !checking, !released else { return false }; released = true; return true
        }
        if shouldRelease { release() }
    }
    func close() {
        guard getpid() == process else { return }
        lock.withLock { closed = true }
        releaseIfClosed()
    }
    deinit { close() }
}

/// An exact orphan claim. Only a joined, positively window-free record can release admission here.
final class SetupRetainedOrphanClaim: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    var description: String { "SetupRetainedOrphanClaim(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    struct Target: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        let record: SetupRetainedInvocationReservation
        let identity: SetupRetainedInvocationStatus.Identity
        let binding: SetupRetainedInvocationStatus.Binding?
        let window: SetupRetainedInvocationStatus.Window?
        /// The owner supplies the actual record after fresh authentication. Status identifiers remain hidden before capture.
        static func capture(owner: SetupAccountOwner, authorization: SetupRetainedRecoveryAuthorization) throws -> Self {
            try owner.retainedOrphanTarget(authorization: authorization)
        }
        var description: String { "SetupRetainedRecoveryTarget(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    }
    final class Joined: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        var description: String { "SetupRetainedRecoveryJoined(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        let evidence: SetupRetainedRecoveryLedger.Evidence
        private let claim: SetupRetainedOrphanClaim
        fileprivate init(claim: SetupRetainedOrphanClaim, evidence: SetupRetainedRecoveryLedger.Evidence) {
            self.claim = claim; self.evidence = evidence
        }
        /// Later restoration must still authenticate its current action and obtain actual durable/readback proof.
        func requireCurrentAuthorization() throws {
            try claim.authorization.requireCurrent(); try claim.token.requireCurrent()
        }
        /// No window was ever made writable by this generation. A window-bearing record needs M12b or M12c instead.
        @discardableResult
        func releaseIfWindowFree() throws -> Bool {
            try requireCurrentAuthorization()
            return try claim.token.releaseWindowFree()
        }
    }
    private let authorization: SetupRetainedRecoveryAuthorization
    private let token: SetupRetainedInvocationReservation.RecoveryToken
    private init(authorization: SetupRetainedRecoveryAuthorization, token: SetupRetainedInvocationReservation.RecoveryToken) {
        self.authorization = authorization; self.token = token
    }
    /// Library only. The owner method seals its existing record without acquiring another admission.
    static func open(owner: SetupAccountOwner, target: Target,
        authorization: SetupRetainedRecoveryAuthorization) throws -> SetupRetainedOrphanClaim {
        do {
            let token = try owner.claimRetainedOrphan(target: target, authorization: authorization)
            let value = Self(authorization: authorization, token: token)
            try authorization.requireCurrent(); return value
        } catch { authorization.close(); throw error }
    }
    /// All callers share the retained actual join task. A cancelled waiter still waits for real cleanup.
    func join() async throws -> Joined {
        let task = try token.joinTask()
        try await task.value
        return try .init(claim: self, evidence: token.joinedEvidence())
    }
    /// Retire a lost caller while an async join still retains this object. The ledger's actual join keeps running.
    func abandon() { token.ownerDropped(); authorization.close() }
    deinit { abandon() }
}
