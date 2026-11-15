import Foundation
import RemozioProtocol
import Synchronization

/// Correlation metadata only. Decoding cannot create a connection owner or authorize a stop.
struct AuthorityMaintenanceBinding: Equatable, Sendable {
    let accountID: Data, attemptID: Data, revision: Data, incarnation: Data, connectionID: Data
    init(accountID: Data, attemptID: Data, revision: Data, incarnation: Data, connectionID: Data) throws {
        guard [accountID, attemptID, revision, incarnation, connectionID].allSatisfy({ $0.count == 16 }) else {
            throw RuntimePreparationError.invalidRecord
        }
        self.accountID = accountID; self.attemptID = attemptID; self.revision = revision
        self.incarnation = incarnation; self.connectionID = connectionID
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(accountID), 2: .bytes(attemptID),
            3: .bytes(revision), 4: .bytes(incarnation), 5: .bytes(connectionID)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...5), fields[0] == .unsigned(1) else {
            throw RuntimePreparationError.invalidRecord
        }
        func data(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = fields[key] else { throw RuntimePreparationError.invalidRecord }; return value
        }
        let result = try Self(accountID: data(1), attemptID: data(2), revision: data(3), incarnation: data(4), connectionID: data(5))
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    private static let limits = try! CBORLimits(maxBytes: 256, maxDepth: 1, maxItems: 13)
}

/// Internal shared owner. Native connection authentication and protected record checks belong to its caller.
/// Stage reservations and the maintenance block share one lock. Neither grants idle or shutdown authority.
final class AuthorityMaintenancePairingAdmission: Sendable {
    enum TransferError: Error, Equatable { case stagesPending(Int) }
    private struct State {
        var closed = false
        var connections = Set<UUID>(), stages: [UUID: Int] = [:]
        var blocker: UUID?
        var armed: AuthorityMaintenanceBinding?
    }
    private let state = Mutex(State())
    private let accountID: Data, incarnation: Data
    init(accountID: Data, incarnation: Data) throws {
        guard accountID.count == 16, incarnation.count == 16 else { throw RuntimePreparationError.invalidRecord }
        self.accountID = accountID; self.incarnation = incarnation
    }
    /// The future accepted-connection owner calls this after native and protected scope validation.
    /// The connection identity is minted here, never accepted from a decoded request.
    func openConnection(attemptID: Data, revision: Data) throws -> Connection {
        var id = UUID().uuid
        let binding = try AuthorityMaintenanceBinding(accountID: accountID, attemptID: attemptID, revision: revision,
            incarnation: incarnation, connectionID: withUnsafeBytes(of: &id) { Data($0) })
        return try state.withLock {
            guard !$0.closed else { throw AuthorityPairingSetupError.unavailable }
            let owner = UUID(); $0.connections.insert(owner)
            return Connection(admission: self, id: owner, binding: binding)
        }
    }
    /// Refusal correlation only. This method never reserves a Connection or changes admission.
    func refusalBinding(accountID: Data, attemptID: Data, revision: Data) throws -> AuthorityMaintenanceBinding {
        var id = UUID().uuid
        return try .init(accountID: accountID, attemptID: attemptID, revision: revision, incarnation: incarnation,
            connectionID: withUnsafeBytes(of: &id) { Data($0) })
    }
    func requireAccount(_ accountID: Data) throws {
        try state.withLock {
            guard !$0.closed else { throw AuthorityPairingSetupError.unavailable }
            guard accountID == self.accountID else { throw RuntimePreparationError.changedScope }
        }
    }
    func openConnection(accountID: Data, attemptID: Data, revision: Data) throws -> Connection {
        try requireAccount(accountID)
        return try openConnection(attemptID: attemptID, revision: revision)
    }
    func connectionReservations() throws -> Int {
        try state.withLock { guard !$0.closed else { throw AuthorityPairingSetupError.unavailable }; return $0.connections.count }
    }
    /// Retain through stage creation and the staged attempt's ordinary commit, cancel or expiry cleanup.
    func reserveStage() throws -> Stage {
        try state.withLock {
            guard !$0.closed, $0.blocker == nil, $0.armed == nil else { throw AuthorityPairingSetupError.unavailable }
            let id = UUID(); $0.stages[id] = 1; return Stage(admission: self, id: id)
        }
    }
    func stagedReservations() throws -> Int {
        try state.withLock {
            guard !$0.closed else { throw AuthorityPairingSetupError.unavailable }; return $0.stages.count
        }
    }
    func close() {
        state.withLock { $0.closed = true; $0.connections.removeAll(); $0.blocker = nil }
    }
    private func block(_ id: UUID) throws -> Int {
        try state.withLock {
            guard !$0.closed, $0.armed == nil, $0.connections.contains(id), $0.blocker == nil || $0.blocker == id else {
                throw AuthorityPairingSetupError.unavailable
            }
            $0.blocker = id; return $0.stages.count
        }
    }
    /// Reattach only to the existing armed target after native authentication and protected scope checks.
    /// The lookup never creates a new block or grants shutdown authority from metadata.
    func shutdownBinding(matching binding: AuthorityMaintenanceBinding) throws -> Shutdown {
        try state.withLock {
            guard !$0.closed, $0.armed == binding else { throw RuntimePreparationError.changedScope }
            return Shutdown(admission: self, binding: binding)
        }
    }
    private func transfer(_ id: UUID, binding: AuthorityMaintenanceBinding) throws -> Shutdown {
        try state.withLock {
            guard !$0.closed, $0.armed == nil, $0.connections.contains(id), $0.blocker == id else {
                throw AuthorityPairingSetupError.unavailable
            }
            guard $0.stages.isEmpty else { throw TransferError.stagesPending($0.stages.count) }
            $0.armed = binding; $0.blocker = nil; $0.connections.remove(id)
            return Shutdown(admission: self, binding: binding)
        }
    }
    private func releaseShutdown(_ binding: AuthorityMaintenanceBinding) throws {
        try state.withLock {
            guard !$0.closed, $0.armed == binding else { throw RuntimePreparationError.changedScope }
            $0.armed = nil
        }
    }
    private func releaseUnarmed(_ id: UUID) throws {
        try state.withLock {
            guard !$0.closed, $0.armed == nil, $0.connections.contains(id), $0.blocker == nil || $0.blocker == id else {
                throw RuntimePreparationError.changedScope
            }
            $0.connections.remove(id); if $0.blocker == id { $0.blocker = nil }
        }
    }
    private func releaseConnection(_ id: UUID) {
        state.withLock {
            $0.connections.remove(id)
            if $0.blocker == id { $0.blocker = nil }
        }
    }
    private func retainStage(_ id: UUID) throws -> Stage {
        try state.withLock {
            guard !$0.closed, let count = $0.stages[id] else { throw AuthorityPairingSetupError.unavailable }
            $0.stages[id] = count + 1; return Stage(admission: self, id: id)
        }
    }
    private func releaseStage(_ id: UUID) {
        state.withLock { if let count = $0.stages[id] { $0.stages[id] = count > 1 ? count - 1 : nil } }
    }
    final class Connection: Sendable {
        let binding: AuthorityMaintenanceBinding
        private let admission: AuthorityMaintenancePairingAdmission
        private let id: UUID
        fileprivate init(admission: AuthorityMaintenancePairingAdmission, id: UUID, binding: AuthorityMaintenanceBinding) {
            self.admission = admission; self.id = id; self.binding = binding
        }
        /// Blocks new stages but preserves every existing reservation. The count is an observation only.
        func blockNewStages(matching expected: AuthorityMaintenanceBinding) throws -> Int {
            guard expected == binding else { throw RuntimePreparationError.changedScope }
            return try admission.block(id)
        }
        /// The block must exist and all stage reservations must have settled. Other work needs separate checks.
        func transferToShutdown(matching expected: AuthorityMaintenanceBinding) throws -> Shutdown {
            guard expected == binding else { throw RuntimePreparationError.changedScope }
            return try admission.transfer(id, binding: binding)
        }
        /// Before arming, cancel or reopen only this connection. It never releases an armed block or account drain.
        func release(matching expected: AuthorityMaintenanceBinding) throws {
            guard expected == binding else { throw RuntimePreparationError.changedScope }; close()
        }
        func releaseUnarmed(matching expected: AuthorityMaintenanceBinding) throws {
            guard expected == binding else { throw RuntimePreparationError.changedScope }; try admission.releaseUnarmed(id)
        }
        func close() { admission.releaseConnection(id) }
        deinit { close() }
    }
    /// A process-owned target, independent of the XPC connection. Dropping a handle never releases its block.
    final class Shutdown: Sendable {
        let binding: AuthorityMaintenanceBinding
        private let admission: AuthorityMaintenancePairingAdmission
        fileprivate init(admission: AuthorityMaintenancePairingAdmission, binding: AuthorityMaintenanceBinding) {
            self.admission = admission; self.binding = binding
        }
        func cancel(matching expected: AuthorityMaintenanceBinding) throws { try release(expected) }
        func reopen(matching expected: AuthorityMaintenanceBinding) throws { try release(expected) }
        private func release(_ expected: AuthorityMaintenanceBinding) throws {
            guard expected == binding else { throw RuntimePreparationError.changedScope }
            try admission.releaseShutdown(binding)
        }
    }
    final class Stage: Sendable {
        private let closed = Mutex(false)
        private let admission: AuthorityMaintenancePairingAdmission
        private let id: UUID
        fileprivate init(admission: AuthorityMaintenancePairingAdmission, id: UUID) { self.admission = admission; self.id = id }
        func retained() throws -> Stage {
            try closed.withLock { guard !$0 else { throw JournalLeaseError.invalidated }; return try admission.retainStage(id) }
        }
        func close() { if closed.withLock({ if $0 { return false }; $0 = true; return true }) { admission.releaseStage(id) } }
        deinit { close() }
    }
}
