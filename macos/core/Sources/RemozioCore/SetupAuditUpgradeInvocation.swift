import Darwin
import Foundation

/// One bounded maintenance invocation. The endpoint must close this owner after its reply callback settles.
final class SetupAuditUpgradeInvocation: @unchecked Sendable {
    private let operation: RuntimeAuditUpgradeOperation
    private let baseline: SetupAuditUpgradeProgress
    private let lock = NSRecursiveLock()
    private let processID = getpid()
    private var active = false, invoked = false, retired = false, closed = false

    /// Authorization must be imported on the authenticated exported invocation before task dispatch.
    static func open(owner: SetupAccountOwner, expected: SetupAuditUpgradeProgress,
                     authorization: SetupAuditUpgradeAuthorization) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try begin(owner: owner, expected: expected, authorization: authorization, openOperation: RuntimeAuditUpgradeOperation.open)
    }
    static func openOwned(owner: SetupAccountOwner, expected: SetupAuditUpgradeProgress,
                          authorization: SetupAuditUpgradeAuthorization,
                          openOperation: (SetupAuditUpgradeScope) throws -> RuntimeAuditUpgradeOperation) throws -> Self {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return try begin(owner: owner, expected: expected, authorization: authorization, openOperation: openOperation)
    }
    private static func begin(owner: SetupAccountOwner, expected: SetupAuditUpgradeProgress,
                              authorization: SetupAuditUpgradeAuthorization,
                              openOperation: (SetupAuditUpgradeScope) throws -> RuntimeAuditUpgradeOperation) throws -> Self {
        let scope = try owner.acquireAuditUpgradeScope(authorization: authorization)
        do {
            let current = try scope.withMachine { machine in
                try SetupAuditUpgradeProgress.capture(machine: machine, account: scope.account,
                    inventory: scope.inventory, initialization: scope.initialization)
            }
            try current.validateScope(of: expected)
            return Self(operation: try openOperation(scope), baseline: current)
        } catch { try scope.close(); throw error }
    }
    private init(operation: RuntimeAuditUpgradeOperation, baseline: SetupAuditUpgradeProgress) {
        self.operation = operation; self.baseline = baseline
    }
    /// Advances through the finite cutover stages. Busy resources return an observation without a retry loop.
    func run(reply: (Data) throws -> Void) throws {
        guard getpid() == processID else { throw RuntimeActivationError.unavailable }
        try lock.withLock {
            guard !active, !invoked, !retired, !closed else { throw RuntimeActivationError.unavailable }
            active = true; invoked = true; defer { active = false }
            do {
                for _ in 0..<8 {
                    try Task.checkCancellation()
                    let next = try operation.advance()
                    switch next {
                    case .waitingForActivity, .waitingForMachine, .waitingForQuiescence, .registrationObserved, .alreadyCurrent:
                        try operation.validateReply()
                        let bytes = try baseline.observing(next).bytes
                        try operation.validateReply()
                        try reply(bytes)
                        return
                    case .graphPrepared, .filesChanging, .filesVerified, .metadataCommitted, .readyToRestart: continue
                    }
                }
                throw RuntimeActivationError.unavailable
            } catch { retired = true; throw error }
        }
    }
    /// Cleanup can be retried after rights expire. Failed cleanup retains the operation and its setup reservation.
    func close() throws {
        guard getpid() == processID else { throw RuntimeActivationError.unavailable }
        try lock.withLock {
            guard !active else { throw RuntimeActivationError.unavailable }
            guard !closed else { return }
            retired = true
            try operation.close(); closed = true
        }
    }
}
