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
    private struct State {
        var closed = false
        var connections = Set<UUID>(), stages = Set<UUID>()
        var blocker: UUID?
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
    /// Retain through stage creation and the staged attempt's ordinary commit, cancel or expiry cleanup.
    func reserveStage() throws -> Stage {
        try state.withLock {
            guard !$0.closed, $0.blocker == nil else { throw AuthorityPairingSetupError.unavailable }
            let id = UUID(); $0.stages.insert(id); return Stage(admission: self, id: id)
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
            guard !$0.closed, $0.connections.contains(id), $0.blocker == nil || $0.blocker == id else {
                throw AuthorityPairingSetupError.unavailable
            }
            $0.blocker = id; return $0.stages.count
        }
    }
    private func releaseConnection(_ id: UUID) {
        state.withLock {
            $0.connections.remove(id)
            if $0.blocker == id { $0.blocker = nil }
        }
    }
    private func releaseStage(_ id: UUID) { _ = state.withLock { $0.stages.remove(id) } }
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
        /// Cancel or reopen only this binding. It never releases an account drain or another connection's block.
        func release(matching expected: AuthorityMaintenanceBinding) throws {
            guard expected == binding else { throw RuntimePreparationError.changedScope }; close()
        }
        func close() { admission.releaseConnection(id) }
        deinit { close() }
    }
    final class Stage: Sendable {
        private let admission: AuthorityMaintenancePairingAdmission
        private let id: UUID
        fileprivate init(admission: AuthorityMaintenancePairingAdmission, id: UUID) { self.admission = admission; self.id = id }
        func close() { admission.releaseStage(id) }
        deinit { close() }
    }
}
