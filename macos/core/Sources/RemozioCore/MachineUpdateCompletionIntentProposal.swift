import Foundation

/// Proposed operands only. Native health, paired reads and a protected transaction remain separate requirements.
enum MachineUpdateCompletionIntentProposal {
    static func make(snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        inventory: MachineUpdateHealthInventory, policies: [AuthorityJournal.MachineUpdatePolicyBoundary],
        targetRevision: Data) throws -> MachineUpdateCompletionIntentArchive {
        let selected = try MachineUpdateHealthInventory(plan: MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: candidate))
        let configured = snapshot.configuration.record.accounts.filter(\.configurationPublished).map(\.accountID)
        guard inventory.requirements == selected.requirements, inventory.preservedAccounts == selected.preservedAccounts,
              Set(policies.map(\.accountID)) == Set(configured), policies.count == configured.count,
              policies.allSatisfy({ $0.macID == snapshot.source.replacement.inventory.macID }) else {
            throw PreparationStoreError.staleRevision
        }
        var records: [MachineUpdatePolicyIntentRecord] = []
        for accountID in configured.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            guard let policy = policies.first(where: { $0.accountID == accountID }),
                  let configuration = try snapshot.configuration.configuration(accountID: accountID),
                  try snapshot.configuration.policy(accountID: accountID) == policy.policy else {
                throw PreparationStoreError.staleRevision
            }
            let plan = try MachineUpdatePolicyPlan(source: policy.policy, candidate: candidate)
            records.append(try .init(binding: configuration.completion.binding,
                epochs: .init(configuration: snapshot.configuration.record, backend: snapshot.backend.record),
                source: policy, plan: plan))
        }
        let record = try MachineUpdateCompletionIntentRecord(snapshot: snapshot, candidate: candidate,
            policyRecords: records, targetRevision: targetRevision)
        return try .init(record: record, policies: records)
    }
}
