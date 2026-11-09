import Foundation

/// Current publication facts and the historical completion source. This value grants no native file writer or admission authority.
struct MachineUpdateCompletionPublicationSnapshot {
    let completion: MachineUpdateCompletionSnapshot
    let publication: MachineUpdateCompletionPublicationRecord?
    init(completion: MachineUpdateCompletionSnapshot, publication: MachineUpdateCompletionPublicationRecord?,
         candidate: SignedReleaseEvidence) throws {
        try completion.intent.validate()
        if let publication {
            let plan = try MachineUpdateCompletionPublicationPlan(retainedConfiguration: completion.restart.configuration,
                retainedBackend: completion.restart.backend, intent: completion.intent, candidate: candidate)
            try publication.requirePlan(plan)
        }
        self.completion = completion
        self.publication = publication
    }

    func requireSame(as other: Self) throws {
        try completion.requireSame(as: other.completion)
        guard publication == other.publication else { throw PreparationStoreError.staleRevision }
    }
}
