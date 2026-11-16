import Darwin
import Foundation

/// Keeps admission and cleanup independently of the invocation. Object loss never proves settlement.
final class SetupRetainedInvocationReservation: @unchecked Sendable {
    enum State: Equatable { case reserved, attached, orphan, settled }
    let admission: SetupOwnerAsyncWork.Token
    private let reply: SetupOwnerAsyncWork.Token
    private let activity: ReleaseActivityToken?
    private let incarnation: UUID
    private let process = getpid()
    private let lock = NSLock()
    private weak var invocation: SetupRetainedInvocation?
    private var phase: State = .reserved
    private var worker = false, settling = false
    private var cleanup: [() throws -> Void] = []

    init(incarnation: UUID, admission: SetupOwnerAsyncWork.Token, reply: SetupOwnerAsyncWork.Token,
         activity: ReleaseActivityToken?) {
        self.incarnation = incarnation; self.admission = admission; self.reply = reply; self.activity = activity
    }
    func state() throws -> State {
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        return lock.withLock { currentState() }
    }
    private func currentState() -> State {
        if phase == .attached, invocation == nil { phase = .orphan }
        return phase
    }
    func attach(_ value: SetupRetainedInvocation) throws {
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard phase == .reserved, value.belongs(to: self), value.incarnation == incarnation else { throw XPCPeerPolicyError.wrongConnection }
            invocation = value; phase = .attached
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
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try requireAttached(value)
            guard !worker else { throw AdministrativeSetupError.unavailable }
            worker = true
        }
    }
    func endWorker(_ value: SetupRetainedInvocation) {
        guard getpid() == process else { return }
        lock.withLock { if invocation === value { worker = false } }
    }
    /// Retain the actual cleanup owner before borrowing its resources. Failed cleanup remains in this reservation.
    func retainCleanup(_ value: SetupRetainedInvocation, _ close: @escaping () throws -> Void) throws {
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
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try requireAttached(value)
            guard !worker else { throw AdministrativeSetupError.unavailable }
            settling = true
        }
        defer { lock.withLock { settling = false } }
        while let close = lock.withLock({ cleanup.last }) {
            try close()
            lock.withLock { _ = cleanup.popLast() }
        }
        finalCleanup()
        lock.withLock {
            phase = .settled; activity?.close(); admission.close(); reply.close()
        }
    }
}
