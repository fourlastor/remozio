import Darwin
import Foundation

/// Keeps admission and cleanup independently of the invocation. Object loss never proves settlement.
final class SetupRetainedInvocationReservation: @unchecked Sendable {
    // Keep a strong invocation parameter through each locked weak load. Release removed cleanup closures outside this lock.
    // Invocation deinit takes this lock, so dropping its last strong reference while holding it would deadlock.
    enum State: Equatable { case reserved, attached, orphan, settled }
    let admission: SetupOwnerAsyncWork.Token
    private let reply: SetupOwnerAsyncWork.Token
    private let activity: ReleaseActivityToken?
    private let statusID = UUID()
    private let authenticatedPeerUID: uid_t
    private let ownerUID = getuid()
    private var capturedBinding: SetupRetainedInvocationStatus.Binding?
    private var capturedWindow: SetupRetainedInvocationStatus.Window?
    private let incarnation: UUID
    private let process = getpid()
    private let lock: NSLock
    private weak var invocation: SetupRetainedInvocation?
    private var invocationID: ObjectIdentifier?
    private var phase: State = .reserved
    private var worker = false, settling = false
    private var cleanup: [() throws -> Void] = []

    /// An injected status lock is an ordinary-owner test seam. Root cannot inject this lock.
    init(authenticatedPeer: XPCPeerCredentials, incarnation: UUID, admission: SetupOwnerAsyncWork.Token, reply: SetupOwnerAsyncWork.Token,
         activity: ReleaseActivityToken?, ownedStatusLock: NSLock? = nil) throws {
        guard authenticatedPeer.processID > 0, authenticatedPeer.userID > 0, authenticatedPeer.userID < UInt32.max else {
            throw XPCPeerPolicyError.wrongPeer
        }
        if ownedStatusLock != nil { try RuntimeMaintenanceOwnedControl.require() }
        lock = ownedStatusLock ?? NSLock()
        authenticatedPeerUID = authenticatedPeer.userID
        self.incarnation = incarnation; self.admission = admission; self.reply = reply; self.activity = activity
    }
    /// The caller has already checked the actual exported peer and current directory identity. No native caller exists yet.
    func status(authenticatedPeer peer: XPCPeerCredentials, currentOwner: LocalAccountIdentity) -> SetupRetainedInvocationStatus {
        guard getpid() == process, getuid() == ownerUID, geteuid() == ownerUID,
              peer.processID > 0, peer.userID == authenticatedPeerUID, currentOwner.uid == authenticatedPeerUID,
              lock.try() else { return .unavailable }
        defer { lock.unlock() }
        if let capturedBinding, !capturedBinding.matches(currentOwner) { return .unavailable }
        let observed: SetupRetainedInvocationStatus.Reservation
        switch phase {
        case .reserved: observed = .reserved
        case .attached: observed = .attached
        case .orphan: observed = .orphan
        case .settled: observed = .settled
        }
        let cleanupState: SetupRetainedInvocationStatus.Fact<SetupRetainedInvocationStatus.Cleanup>
        if phase == .settled { cleanupState = .observed(.settled) }
        else if settling { cleanupState = .observed(.joining) }
        else if !cleanup.isEmpty { cleanupState = .observed(.pending) }
        else { cleanupState = .observed(.noneRegistered) }
        return .reservation(observed, identity: .init(reservationID: statusID, incarnation: incarnation), binding: capturedBinding,
            expectedWindow: capturedWindow, worker: worker ? .running : .idle, cleanup: cleanupState)
    }
    /// Store only a completed protected capture, never an unvalidated target hint or request UID.
    func bind(_ value: SetupRetainedCallerBinding, invocation owner: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(owner) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try requireAttached(owner)
            guard value.peer == owner.peer, value.peer.userID == authenticatedPeerUID,
                  value.authorityOwner.uid == authenticatedPeerUID, value.incarnation == incarnation else {
                throw XPCPeerPolicyError.wrongPeer
            }
            let binding = try SetupRetainedInvocationStatus.capturedBinding(value)
            guard capturedBinding == nil || capturedBinding == binding else { throw RuntimePreparationError.changedScope }
            capturedBinding = binding
        }
    }
    /// Pins authorized metadata only. A matching row still needs a protected read before it supplies outcomes.
    func bindWindow(_ window: RuntimeMaintenanceWindowRecord, invocation owner: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(owner) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try requireAttached(owner)
            guard let capturedBinding, capturedBinding.matches(window.scope) else { throw RuntimePreparationError.changedScope }
            let identity = SetupRetainedInvocationStatus.Window(window)
            guard capturedWindow == nil || capturedWindow == identity else { throw RuntimePreparationError.changedScope }
            capturedWindow = identity
        }
    }
    func state() throws -> State {
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        return lock.withLock { currentState() }
    }
    private func currentState() -> State { phase }
    /// A deinit notification avoids taking the last strong invocation reference on the bounded status read path.
    func invocationDidDeinit(_ id: ObjectIdentifier, incarnation: UUID) {
        guard getpid() == process else { return }
        lock.withLock {
            if invocationID == id, self.incarnation == incarnation, phase == .attached { phase = .orphan }
        }
    }
    func attach(_ value: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard phase == .reserved, value.belongs(to: self), value.incarnation == incarnation else { throw XPCPeerPolicyError.wrongConnection }
            invocation = value; invocationID = ObjectIdentifier(value); phase = .attached
        }
    }
    func verify() throws {
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard currentState() == .reserved || phase == .attached, !settling else { throw AdministrativeSetupError.unavailable }
            try activity?.validate()
        }
    }
    func beginWorker(_ value: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try requireAttached(value)
            guard !worker else { throw AdministrativeSetupError.unavailable }
            worker = true
        }
    }
    func endWorker(_ value: SetupRetainedInvocation) {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { return }
        lock.withLock { if invocation === value { worker = false } }
    }
    /// Retain the actual cleanup owner before borrowing its resources. Failed cleanup remains in this reservation.
    func retainCleanup(_ value: SetupRetainedInvocation, _ close: @escaping () throws -> Void) throws {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock { try requireAttached(value); cleanup.append(close) }
    }
    private func requireAttached(_ value: SetupRetainedInvocation) throws {
        guard currentState() == .attached, invocation === value, value.incarnation == incarnation, !settling else {
            throw AdministrativeSetupError.unavailable
        }
    }
    /// Construction has no worker or native loan. Only its exact reserved record can take this exit.
    func abortConstruction() {
        guard getpid() == process else { return }
        lock.withLock {
            guard phase == .reserved else { return }
            phase = .settled; activity?.close(); admission.close(); reply.close()
        }
    }
    /// The synchronous worker has returned through all scoped loans. Each retained cleanup must also return successfully.
    func settle(_ value: SetupRetainedInvocation, finalCleanup: () -> Void = {}) throws {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try requireAttached(value)
            guard !worker else { throw AdministrativeSetupError.unavailable }
            settling = true
        }
        defer { lock.withLock { settling = false } }
        while let close = lock.withLock({ cleanup.last }) {
            try close()
            let removed = lock.withLock { cleanup.popLast() }
            withExtendedLifetime((close, removed)) {}
        }
        finalCleanup()
        lock.withLock {
            phase = .settled; activity?.close(); admission.close(); reply.close()
        }
    }
}
