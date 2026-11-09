import Foundation

/// Classifies paired policy facts against retained progress. This value grants no writer, health or retry authority.
struct MachineUpdateCompletionPolicyProfile {
    enum State: Equatable, Sendable {
        case prepared
        case unresolvedSource
        case unrecordedCommit
        case recorded
    }
    struct Account: Equatable, Sendable {
        let accountID: Data
        let binding: RuntimeReleaseBinding
        let boundary: AuthorityJournal.MachineUpdatePolicyBoundary
        let state: State
    }
    private let archive: MachineUpdateCompletionIntentArchive

    init(snapshot: MachineUpdateCompletionSnapshot, candidate: SignedReleaseEvidence,
         currentSourceDigest: Data) throws {
        try snapshot.intent.requireSnapshot(snapshot.restart, candidate: candidate,
            currentSourceDigest: currentSourceDigest)
        try self.init(archive: snapshot.intent)
    }

    /// Classifies a retained archive only. Publication must also verify the fresh machine source.
    init(archive: MachineUpdateCompletionIntentArchive) throws {
        try archive.validate()
        self.archive = archive
    }

    func requireRecorded(_ boundaries: [AuthorityJournal.MachineUpdatePolicyBoundary]) throws {
        let accounts = try requireBoundaries(boundaries)
        guard accounts.allSatisfy({ $0.state == .recorded }) else { throw PreparationStoreError.invalidTransition }
    }

    /// Requires every configured account once. Unconfigured accounts cannot gain a policy participant.
    func requireBoundaries(_ boundaries: [AuthorityJournal.MachineUpdatePolicyBoundary]) throws -> [Account] {
        guard boundaries.count == archive.policies.count,
              Set(boundaries.map(\.accountID)).count == boundaries.count,
              Set(boundaries.map(\.accountID)) == Set(archive.policies.map { $0.binding.accountID }) else {
            throw PreparationStoreError.staleRevision
        }
        return try archive.policies.map { record in
            guard let current = boundaries.first(where: { $0.accountID == record.binding.accountID }),
                  current.macID == record.binding.macID else { throw PreparationStoreError.staleRevision }
            let state: State
            switch record.phase {
            case .prepared:
                try record.requireSource(current)
                state = .prepared
            case .writing:
                do {
                    switch try record.reconciling(current) {
                    case .sourceUnchanged: state = .unresolvedSource
                    case .recorded: state = .unrecordedCommit
                    }
                } catch PreparationStoreError.corruptRecord {
                    // The archive already passed validation. These incompatible facts came from the live pair.
                    throw PreparationStoreError.staleRevision
                }
            case .recorded:
                guard let policy = record.committedPolicy, let checkpoint = record.committedCheckpoint,
                      try policy.snapshot() == current.policy, try current.checkpoint.bytes == checkpoint else {
                    throw PreparationStoreError.staleRevision
                }
                state = .recorded
            }
            return Account(accountID: record.binding.accountID, binding: record.binding, boundary: current, state: state)
        }
    }
}
