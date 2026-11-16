import Darwin
import Foundation

/// Captured facts only. No field authorizes work, releases admission, or proves a durable outcome by inference.
struct SetupRetainedInvocationStatus: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    enum Fact<Value: Equatable & Sendable>: Equatable, Sendable { case unavailable, observed(Value) }
    enum Reservation: Equatable, Sendable { case absent, reserved, attached, orphan, recovering, settled }
    enum Worker: Equatable, Sendable { case idle, running, registered }
    enum Cleanup: Equatable, Sendable { case noneRegistered, pending, joining, joined, settled }
    enum Supervisor: Equatable, Sendable {
        case recovering, joining, busy, cancelled, retired, noWindow
        case phase(RuntimeMaintenanceWindowRecord.Phase), failed(RuntimeMaintenanceWindowRecord.Failure)
    }
    struct Identity: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        let reservationID: UUID, incarnation: UUID
        var description: String { "SetupRetainedStatusIdentity(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    }
    struct Window: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        let id: Data, revision: Data
        let purpose: RuntimeMaintenanceWindowRecord.Purpose
        let scope: RuntimeMaintenanceWindowRecord.Scope
        init(_ record: RuntimeMaintenanceWindowRecord) {
            id = record.id; revision = record.revision; purpose = record.purpose; scope = record.scope
        }
        /// Revision belongs to the observed row. A transition keeps the window ID, purpose and immutable scope.
        func identifies(_ record: RuntimeMaintenanceWindowRecord) -> Bool {
            id == record.id && purpose == record.purpose && scope == record.scope
        }
        var description: String { "SetupRetainedStatusWindow(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    }
    struct Restoration: Equatable, Sendable {
        let phase: RuntimeMaintenanceWindowRecord.Phase
        let service: RuntimeMaintenanceWindowRecord.ServiceOutcome
        let failure: RuntimeMaintenanceWindowRecord.Failure?
    }
    struct Binding: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        let macID: Data, installationID: Data, releaseDigest: Data
        let authority: RuntimeMaintenanceWindowRecord.Account, target: RuntimeMaintenanceWindowRecord.Account
        fileprivate init(_ value: SetupRetainedCallerBinding) throws {
            let source = value.entry.runtime.setup.source.actual.inventory
            func account(_ id: Data, _ owner: LocalAccountIdentity) throws -> RuntimeMaintenanceWindowRecord.Account {
                var directory = owner.directoryID.uuid
                return try .init(accountID: id, ownerUID: owner.uid, directoryID: withUnsafeBytes(of: &directory) { Data($0) })
            }
            macID = source.macID; installationID = source.installationID; releaseDigest = source.releaseDigest
            authority = try account(value.authorityAccountID, value.authorityOwner)
            target = try account(value.entry.runtime.preparation.accountID, value.targetOwner)
        }
        func matches(_ scope: RuntimeMaintenanceWindowRecord.Scope) -> Bool {
            scope.macID == macID && scope.installationID == installationID && scope.releaseDigest == releaseDigest
                && scope.authority == authority && scope.target == target
        }
        func matches(_ owner: LocalAccountIdentity) -> Bool {
            var directory = owner.directoryID.uuid
            return owner.uid == authority.ownerUID && authority.directoryID == withUnsafeBytes(of: &directory) { Data($0) }
        }
        var description: String { "SetupRetainedStatusBinding(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    }
    let reservation: Fact<Reservation>
    let identity: Fact<Identity>
    let binding: Fact<Binding>
    let window: Fact<Window>
    let operation: Fact<RuntimeMaintenanceWindowRecord.OperationOutcome>
    let restoration: Fact<Restoration>
    let worker: Fact<Worker>
    let cleanup: Fact<Cleanup>
    private let expectedWindow: Window?
    let supervisor: Fact<Supervisor>
    static let unavailable = Self(reservation: .unavailable, identity: .unavailable, binding: .unavailable, window: .unavailable, operation: .unavailable,
        restoration: .unavailable, worker: .unavailable, cleanup: .unavailable, supervisor: .unavailable)
    fileprivate init(reservation: Fact<Reservation>, identity: Fact<Identity> = .unavailable, binding: Fact<Binding> = .unavailable, window: Fact<Window> = .unavailable,
        operation: Fact<RuntimeMaintenanceWindowRecord.OperationOutcome> = .unavailable,
        restoration: Fact<Restoration> = .unavailable, worker: Fact<Worker> = .unavailable, cleanup: Fact<Cleanup> = .unavailable,
        supervisor: Fact<Supervisor> = .unavailable, expectedWindow: Window? = nil) {
        self.reservation = reservation; self.identity = identity; self.binding = binding; self.window = window; self.operation = operation
        self.restoration = restoration; self.worker = worker; self.cleanup = cleanup; self.supervisor = supervisor
        self.expectedWindow = expectedWindow
    }
    /// The future bounded reader supplies an actual protected row. This comparison cannot create a writer or a release permit.
    func observing(_ record: RuntimeMaintenanceWindowRecord) -> Self {
        guard case .observed(let bound) = binding, bound.matches(record.scope), expectedWindow?.identifies(record) == true else {
            return .init(reservation: reservation, identity: identity, binding: binding, worker: worker, cleanup: cleanup, supervisor: supervisor, expectedWindow: expectedWindow)
        }
        let binding = bound
        return .init(reservation: reservation, identity: identity, binding: .observed(binding), window: .observed(.init(record)), operation: .observed(record.operation),
            restoration: .observed(.init(phase: record.phase, service: record.service, failure: record.failure)),
            worker: worker, cleanup: cleanup, supervisor: supervisor, expectedWindow: expectedWindow)
    }
    func observing(supervisor observation: Supervisor) -> Self {
        .init(reservation: reservation, identity: identity, binding: binding, window: window, operation: operation,
            restoration: restoration, worker: worker, cleanup: cleanup, supervisor: .observed(observation), expectedWindow: expectedWindow)
    }
    var description: String { "SetupRetainedInvocationStatus(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    /// A separate slot avoids the owner's mutation lock. Reads neither wait for publication nor borrow either admission.
    final class Reader: @unchecked Sendable {
        private let process = getpid(), user = getuid()
        private let lock: NSLock
        private var record: SetupRetainedInvocationReservation?
        private var closed = false
        init() { lock = NSLock() }
        private init(ownedStatusLock: NSLock) { lock = ownedStatusLock }
        /// Ordinary-owner contention tests only. Root cannot inject the status lock.
        static func openOwned(statusLock: NSLock) throws -> Reader {
            try RuntimeMaintenanceOwnedControl.require()
            return .init(ownedStatusLock: statusLock)
        }
        func publish(_ value: SetupRetainedInvocationReservation) {
            guard getpid() == process else { return }
            lock.withLock { if !closed { record = value } }
        }
        func close() { guard getpid() == process else { return }; lock.withLock { closed = true } }
        func read(authenticatedPeer peer: XPCPeerCredentials, currentOwner: LocalAccountIdentity) -> SetupRetainedInvocationStatus {
            read(authenticatedPeer: peer, currentOwner: currentOwner, afterSnapshot: nil)
        }
        /// Ordinary-owner race fixtures only. Root cannot inject a callback into a status read.
        func readOwned(authenticatedPeer peer: XPCPeerCredentials, currentOwner: LocalAccountIdentity,
            afterSnapshot: @escaping () -> Void) throws -> SetupRetainedInvocationStatus {
            try RuntimeMaintenanceOwnedControl.require()
            return read(authenticatedPeer: peer, currentOwner: currentOwner, afterSnapshot: afterSnapshot)
        }
        private func read(authenticatedPeer peer: XPCPeerCredentials, currentOwner: LocalAccountIdentity,
            afterSnapshot: (() -> Void)?) -> SetupRetainedInvocationStatus {
            guard getpid() == process, getuid() == user, geteuid() == user,
                  peer.processID > 0, peer.userID > 0, peer.userID < UInt32.max, currentOwner.uid == peer.userID,
                  lock.try() else { return .unavailable }
            let current = record, stopped = closed; lock.unlock()
            guard !stopped else { return .unavailable }
            guard let current else { return .init(reservation: .observed(.absent)) }
            let result = current.status(authenticatedPeer: peer, currentOwner: currentOwner)
            afterSnapshot?()
            guard lock.try() else { return .unavailable }
            defer { lock.unlock() }
            guard !closed, record === current else { return .unavailable }
            return result
        }
    }
    static func capturedBinding(_ value: SetupRetainedCallerBinding) throws -> Binding { try .init(value) }
    static func reservation(_ value: Reservation, identity: Identity, binding: Binding?, expectedWindow: Window?,
        worker: Fact<Worker>, cleanup: Fact<Cleanup>) -> Self {
        .init(reservation: .observed(value), identity: binding == nil ? .unavailable : .observed(identity),
            binding: binding.map { .observed($0) } ?? .unavailable, worker: worker, cleanup: cleanup, expectedWindow: expectedWindow)
    }
}
