import Foundation

enum MachineUpdateHealthCoordinatorError: Error, Equatable {
    case invalidInventory, incompleteHealth, busy, changedScope, duplicateOwner, closed
    case recoveryCompletedNeedsFreshCheck
    case installedGatewayRecoveryRequired, installedReadinessDisabled
}

/// Exact selected checks and preserved accounts. These values grant no startup, journal writer or completion authority.
struct MachineUpdateHealthInventory: Sendable {
    typealias Requirement = MachineUpdateRestartHealthPlan.Requirement
    private struct Key: Hashable { let account: Data; let role: UInt64 }
    let requirements: [Requirement]
    let preservedAccounts: [Data]
    var accountIDs: [Data] { Set(requirements.map { $0.binding.accountID }).sorted { $0.lexicographicallyPrecedes($1) } }
    init(plan: MachineUpdateRestartHealthPlan) throws {
        try self.init(requirements: plan.requirements, preservedAccounts: plan.preservedAccounts)
    }
    /// Owned inventories exercise exact coverage only. The native factory must select the protected restart plan.
    init(requirements: [Requirement], preservedAccounts: [Data]) throws {
        var keys = Set<Key>()
        for value in requirements {
            guard [.authority, .transport, .notificationGateway].contains(value.role), value.code.role == value.role,
                  value.code.active, value.publicKey.count == 65, value.binding.formatVersion == 2,
                  value.role == .authority ? value.executionUID == 0 : (value.executionUID > 0 && value.executionUID < UInt32.max),
                  keys.insert(.init(account: value.binding.accountID, role: value.role.rawValue)).inserted else {
                throw MachineUpdateHealthCoordinatorError.invalidInventory
            }
            if let first = requirements.first {
                let a = first.binding, b = value.binding
                guard a.activationAttempt == b.activationAttempt, a.macID == b.macID, a.installationID == b.installationID,
                      a.candidateDigest == b.candidateDigest, a.sourceInventoryDigest == b.sourceInventoryDigest,
                      a.admissionDigest == b.admissionDigest, a.previousInstalledReleaseDigest == b.previousInstalledReleaseDigest,
                      a.installedReleaseDigest == b.installedReleaseDigest, a.updateID == b.updateID,
                      first.configurationEpoch == value.configurationEpoch, first.configurationRevision == value.configurationRevision,
                      first.backendEpoch == value.backendEpoch, first.backendRevision == value.backendRevision else {
                    throw MachineUpdateHealthCoordinatorError.invalidInventory
                }
            }
        }
        let accounts = Set(requirements.map { $0.binding.accountID })
        guard Set(preservedAccounts).count == preservedAccounts.count, preservedAccounts.allSatisfy({ $0.count == 16 }),
              accounts.isDisjoint(with: preservedAccounts) else { throw MachineUpdateHealthCoordinatorError.invalidInventory }
        for account in accounts {
            let selected = requirements.filter { $0.binding.accountID == account }
            guard let first = selected.first, selected.allSatisfy({ $0.binding == first.binding }) else {
                throw MachineUpdateHealthCoordinatorError.invalidInventory
            }
            let roles = Set(selected.map { $0.role.rawValue })
            guard roles.contains(AuthorityCodeRole.authority.rawValue) == roles.contains(AuthorityCodeRole.transport.rawValue) else {
                throw MachineUpdateHealthCoordinatorError.invalidInventory
            }
        }
        self.requirements = requirements.sorted {
            if $0.binding.accountID != $1.binding.accountID { return $0.binding.accountID.lexicographicallyPrecedes($1.binding.accountID) }
            return $0.role.rawValue < $1.role.rawValue
        }
        self.preservedAccounts = preservedAccounts.sorted { $0.lexicographicallyPrecedes($1) }
    }
    func requirements(accountID: Data) -> [Requirement] { requirements.filter { $0.binding.accountID == accountID } }
    func requireReplies(_ replies: [MachineUpdateAuthenticatedRoleReply], accountID: Data) throws {
        let expected = requirements(accountID: accountID)
        guard !expected.isEmpty, replies.count == expected.count,
              Set(replies.map { $0.requirement.role.rawValue }).count == replies.count,
              Set(replies.map(\.challengeDigest)).count == replies.count,
              replies.allSatisfy({ $0.challengeDigest.count == 32 && expected.contains($0.requirement) }) else {
            throw MachineUpdateHealthCoordinatorError.incompleteHealth
        }
    }
}
