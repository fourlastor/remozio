import Foundation

/// Records conclusive policy results from a verified pair. An unresolved write remains pending.
enum MachineUpdateCompletionRecoverySequence {
    typealias Scope = PreparationIntentStore.CompletionSnapshotScope
    typealias Stage = PreparationIntentStore.CompletionIntentStorageStage

    static func reconcileConclusive(_ expected: MachineUpdateCompletionIntentArchive,
        snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        machine: PreparationIntentStore, directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        verify: (Stage?, Scope) throws -> Void,
        boundary: (Data, Scope) throws -> AuthorityJournal.MachineUpdatePolicyBoundary) throws
        -> MachineUpdateCompletionIntentArchive {
        let accounts = try observe(expected, snapshot: snapshot, candidate: candidate, machine: machine,
            directory: directory, restart: restart, verify: verify, boundary: boundary)
        let recoverable = accounts.first { $0.state == .unrecordedCommit }
        guard let recoverable else { return expected }
        return try machine.recordRecoveredMachineUpdatePolicyBoundary(recoverable.boundary, expected: expected,
            snapshot: snapshot, candidate: candidate, directory: directory, restart: restart) { stage, scope in
                try verify(stage, scope)
                guard try boundary(recoverable.accountID, scope) == recoverable.boundary else {
                    throw PreparationStoreError.staleRevision
                }
                try verify(stage, scope)
            }
    }

    /// Advances the prepared rows only after the paired reads settle any previous marker.
    /// A writer must close its owned pair before returning its receipt.
    static func resumePrepared(_ expected: MachineUpdateCompletionIntentArchive,
        snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        machine: PreparationIntentStore, directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        verify: (Stage?, Scope) throws -> Void,
        boundary: (Data, Scope) throws -> AuthorityJournal.MachineUpdatePolicyBoundary,
        commit: (PreparationIntentStore.PolicyWritePermit, Scope) throws -> AuthorityJournal.MachineUpdatePolicyCommitReceipt)
        throws -> MachineUpdateCompletionIntentArchive {
        var current = try reconcileConclusive(expected, snapshot: snapshot, candidate: candidate, machine: machine,
            directory: directory, restart: restart, verify: verify, boundary: boundary)
        for policy in expected.policies {
            let accounts = try observe(current, snapshot: snapshot, candidate: candidate, machine: machine,
                directory: directory, restart: restart, verify: verify, boundary: boundary)
            guard accounts.allSatisfy({ $0.state == .prepared || $0.state == .recorded }),
                  let account = accounts.first(where: { $0.accountID == policy.binding.accountID }) else {
                throw PreparationStoreError.invalidTransition
            }
            if account.state == .recorded { continue }
            let authorized = try machine.authorizeMachineUpdatePolicyWrite(expected: current, accountID: account.accountID,
                boundary: account.boundary, snapshot: snapshot, candidate: candidate, directory: directory,
                restart: restart, readBoundary: { try boundary(account.accountID, $0) },
                verifyScoped: { try verify($0, $1) })
            let receipt = try machine.withCurrentMachineUpdateCompletionSnapshot(expected: authorized.archive,
                restartSnapshot: snapshot, candidate: candidate, directory: directory, restart: restart) { scope in
                    try verify(nil, scope)
                    let result = try commit(authorized.permit, scope)
                    try verify(nil, scope)
                    return result
                }
            guard receipt.source == account.boundary else { throw PreparationStoreError.staleRevision }
            let target = AuthorityJournal.MachineUpdatePolicyBoundary(macID: receipt.source.macID,
                accountID: receipt.source.accountID, policy: receipt.policy, checkpoint: receipt.checkpoint)
            current = try machine.recordMachineUpdatePolicyReceipt(receipt, expected: authorized.archive, snapshot: snapshot,
                candidate: candidate, directory: directory, restart: restart) { stage, scope in
                    try verify(stage, scope)
                    guard try boundary(account.accountID, scope) == target else { throw PreparationStoreError.staleRevision }
                    try verify(stage, scope)
                }
        }
        let final = try observe(current, snapshot: snapshot, candidate: candidate, machine: machine,
            directory: directory, restart: restart, verify: verify, boundary: boundary)
        guard final.allSatisfy({ $0.state == .recorded }) else { throw PreparationStoreError.invalidTransition }
        return current
    }

    private static func observe(_ expected: MachineUpdateCompletionIntentArchive,
        snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        machine: PreparationIntentStore, directory: ReleaseDestinationLease, restart: UpdateRestartAdmissionLease,
        verify: (Stage?, Scope) throws -> Void,
        boundary: (Data, Scope) throws -> AuthorityJournal.MachineUpdatePolicyBoundary)
        throws -> [MachineUpdateCompletionPolicyProfile.Account] {
        return try machine.withCurrentMachineUpdateCompletionSnapshot(expected: expected,
            restartSnapshot: snapshot, candidate: candidate, directory: directory, restart: restart) { scope in
            try verify(nil, scope)
            let profile = try MachineUpdateCompletionPolicyProfile(archive: scope.read().intent)
            let boundaries = try expected.policies.map { policy in
                try verify(nil, scope)
                let current = try boundary(policy.binding.accountID, scope)
                try verify(nil, scope)
                return current
            }
            return try profile.requireBoundaries(boundaries)
        }
    }
}
