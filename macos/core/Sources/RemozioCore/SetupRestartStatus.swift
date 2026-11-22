import Darwin
import Foundation

/// Library status values only. No value authorizes recovery or releases an admission.
enum SetupRestartStatus {
    enum Slot: UInt64, Sendable { case held = 1, released = 2 }
    enum Claim: UInt64, Sendable { case present = 1, abandoned = 2 }
    enum Task: UInt64, Sendable {
        case notStarted = 1, running = 2, failedReturn = 3, completionPending = 4, completionAdopted = 5, idleReleased = 6
    }
    enum Custody: UInt64, Sendable { case notOpened = 1, open = 2, closed = 3 }
    enum Writer: UInt64, Sendable { case noUncertaintyObserved = 1, uncertain = 2 }
    struct Row: Equatable, Sendable {
        let window: SetupRetainedInvocationStatus.Window
        let operation: RuntimeMaintenanceWindowRecord.OperationOutcome
        let restoration: SetupRetainedInvocationStatus.Restoration
        init(_ value: RuntimeMaintenanceWindowRecord) {
            window = .init(value); operation = value.operation
            restoration = .init(phase: value.phase, service: value.service, failure: value.failure)
        }
    }
    struct Snapshot: Equatable, Sendable {
        let revision: UInt64
        let slot: Slot, claim: Claim, task: Task
        let custody: Custody?, writer: Writer?
        let row: Row?
    }
    /// Contains copied metadata only. Status cannot retain a task, completion, custody or release closure through this handle.
    final class Handle: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        let accountID: Data, owner: LocalAccountIdentity
        private let process = getpid(), user = getuid(), lock = NSLock()
        private var value = Snapshot(revision: 0, slot: .held, claim: .abandoned, task: .notStarted,
            custody: .notOpened, writer: .noUncertaintyObserved, row: nil)
        init(accountID: Data, owner: LocalAccountIdentity) { self.accountID = accountID; self.owner = owner }
        var description: String { "SetupRestartStatusHandle(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        func matches(_ peer: XPCPeerCredentials, _ currentOwner: LocalAccountIdentity) -> Bool {
            peer.userID == owner.uid && currentOwner.uid == owner.uid && currentOwner.directoryID == owner.directoryID
        }
        func publish(slot: Slot, claim: Claim, task: Task, custody: Custody?, writer: Writer?, row: Row?) {
            guard getpid() == process, getuid() == user, geteuid() == user else { return }
            lock.withLock {
                value = .init(revision: value.revision &+ 1, slot: slot, claim: claim, task: task,
                    custody: custody, writer: writer, row: row)
            }
        }
        func read() -> Snapshot? {
            guard getpid() == process, getuid() == user, geteuid() == user, lock.try() else { return nil }
            defer { lock.unlock() }; return value
        }
        func isCurrent(_ snapshot: Snapshot) -> Bool {
            guard getpid() == process, getuid() == user, geteuid() == user, lock.try() else { return false }
            defer { lock.unlock() }; return value.revision == snapshot.revision
        }
    }
}

/// Status v2 remains library-only. Its legacy view hides restart facts from v1 clients.
struct SetupRetainedStatusProjection: Equatable, Sendable {
    let retained: SetupRetainedInvocationStatus
    let restart: SetupRestartStatus.Snapshot?
    let applicability: SetupRetainedStatusV3Wire.Applicability?
    init(retained: SetupRetainedInvocationStatus, restart: SetupRestartStatus.Snapshot?,
         applicability: SetupRetainedStatusV3Wire.Applicability? = nil) {
        self.retained = retained
        self.restart = restart
        self.applicability = restart == nil ? applicability : nil
    }

    static let unavailable = Self(retained: .unavailable, restart: nil)
    var v1: SetupRetainedInvocationStatus { restart == nil ? retained : .unavailable }
}
