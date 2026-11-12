import Foundation

/// Captures promotion metadata with its recorded completion. This value grants no file access or ordinary startup authority.
struct MachineUpdateRetainedSetupPromotionSnapshot {
    let completion: MachineUpdateRetainedSetupCompletionSnapshot
    let intent: MachineUpdateRetainedSetupPromotionIntentRecord?

    init(completion: MachineUpdateRetainedSetupCompletionSnapshot,
        intent: MachineUpdateRetainedSetupPromotionIntentRecord?, candidate: SignedReleaseEvidence) throws {
        let schema = completion.activation.runtime.setup.source.actual.schemaVersion
        guard [Int64(26), 27, 28].contains(schema), completion.intent?.phase == .recorded else {
            throw RuntimeActivationError.incomplete
        }
        try MachineUpdateRetainedSetupPromotionStorage.requireReaderFormats(candidate)
        try completion.requireSame(as: .init(activation: completion.activation, intent: completion.intent, candidate: candidate))
        if let intent {
            guard [Int64(27), 28].contains(schema) else { throw PreparationStoreError.corruptRecord }
            try intent.requireSnapshot(completion, candidate: candidate)
        }
        self.completion = completion; self.intent = intent
    }
    func requireSame(as other: Self) throws {
        try completion.requireSame(as: other.completion)
        guard intent == other.intent else { throw PreparationStoreError.staleRevision }
    }
    func requireRetention(_ record: MachineUpdateRetainedSetupPromotionIntentRecord, from before: Self) throws {
        guard before.intent == nil, intent == record, record.phase == .prepared,
              [Int64(27), 28].contains(completion.activation.runtime.setup.source.actual.schemaVersion) else {
            throw PreparationStoreError.staleRevision
        }
        try completion.requirePromotionMetadataChange(from: before.completion)
    }
    func requireTransition(_ record: MachineUpdateRetainedSetupPromotionIntentRecord, from before: Self) throws {
        guard let previous = before.intent, intent == record,
              [Int64(27), 28].contains(completion.activation.runtime.setup.source.actual.schemaVersion) else {
            throw PreparationStoreError.staleRevision
        }
        guard [Int64(27), 28].contains(before.completion.activation.runtime.setup.source.actual.schemaVersion) else {
            throw PreparationStoreError.staleRevision
        }
        try completion.requirePromotionMetadataChange(from: before.completion)
        try record.requireTransition(from: previous)
    }
}
