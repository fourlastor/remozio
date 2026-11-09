import Foundation

/// Coordinates one Authority account during restart checking. The machine restart owner retains the original drain.
final class MachineUpdateRestartAuthorityCoordinator: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let owner: MachineUpdateAuthorityHealthOwner
    private let requirement: MachineUpdateRestartHealthPlan.Requirement
    private var attempted = false, checked = false, closing = false

    static func openNative(snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence, accountID: Data,
        activity: MachineUpdateRestartSharedActivity, sourceAccess: MachineUpdateHealthSourceAccess,
        readCurrent: @escaping @Sendable (MachineUpdateRestartReadinessLoan) throws -> MachineUpdateRestartSnapshot) throws -> Self {
        let owner = try MachineUpdateAuthorityHealthOwner.openForRestart(snapshot: snapshot, candidate: candidate,
            accountID: accountID, activity: activity, sourceAccess: sourceAccess, readCurrent: readCurrent)
        return .init(owner: owner)
    }

    init(owner: MachineUpdateAuthorityHealthOwner) {
        self.owner = owner; requirement = owner.requirement
    }

    func check() throws -> MachineUpdateAuthenticatedRoleReply {
        try lock.withLock {
            guard !attempted, !closing else { throw MachineUpdateRoleChallengeError.unavailable }
            attempted = true
            do {
                try Task.checkCancellation()
                try owner.validateHealthScope()
                let challenge = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
                defer { challenge.close() }
                let reply = try owner.answer(challenge.request)
                let proof = try challenge.accept(reply, authenticatePeer: { _ in try owner.validateHealthScope() })
                try Task.checkCancellation()
                guard !closing else { throw MachineUpdateRoleChallengeError.unavailable }
                checked = true
                return proof
            } catch MachineUpdateHealthSourceError.busy {
                attempted = false
                throw MachineUpdateHealthSourceError.busy
            }
        }
    }

    func validate() throws {
        try lock.withLock {
            guard checked, !closing else { throw MachineUpdateRoleChallengeError.unavailable }
            do { try owner.validateHealthScope() }
            catch MachineUpdateHealthSourceError.busy { throw MachineUpdateHealthSourceError.busy }
            catch { checked = false; throw error }
            guard !closing else { throw MachineUpdateRoleChallengeError.unavailable }
        }
    }

    func close() throws {
        try lock.withLock {
            closing = true; checked = false
            try owner.close()
        }
    }
}
