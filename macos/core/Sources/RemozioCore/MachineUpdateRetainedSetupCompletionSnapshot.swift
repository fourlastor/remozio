import Foundation

/// Joins actual machine records with the immutable startup receipt. It grants no writer, health, or ordinary startup authority.
struct MachineUpdateRetainedSetupCompletionSnapshot {
    enum PairStatus: Equatable {
        case startup
        case completionReceiptPending(MachineUpdateRetainedSetupCompletionIntentRecord)
        case completionRecorded(MachineUpdateRetainedSetupCompletionIntentRecord)
    }
    let activation: MachineUpdateRetainedSetupActivationSnapshot
    let intent: MachineUpdateRetainedSetupCompletionIntentRecord?

    init(activation: MachineUpdateRetainedSetupActivationSnapshot,
        intent: MachineUpdateRetainedSetupCompletionIntentRecord?, candidate: SignedReleaseEvidence) throws {
        let schema = activation.runtime.setup.source.actual.schemaVersion
        try activation.requireCompletionReaderFormats(candidate: candidate)
        guard activation.state.jobsRegistered, activation.runtime.setup.account?.inInventory == true,
              activation.state.plan != nil else { throw RuntimeActivationError.incomplete }
        if let intent {
            guard [MachineUpdateRetainedSetupCompletionStorage.schemaVersion, MachineUpdateRetainedSetupPromotionStorage.schemaVersion, MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion, RuntimeMaintenanceWindowStorage.schemaVersion].contains(schema) else { throw PreparationStoreError.staleRevision }
            try intent.requireSnapshot(activation, candidate: candidate)
        }
        self.activation = activation; self.intent = intent
    }

    func requireSame(as other: Self) throws {
        try activation.requireSame(as: other.activation)
        guard intent == other.intent else { throw PreparationStoreError.staleRevision }
    }

    /// Checks the permitted completion row and schema change. The private writer protects every other row.
    func requireRetention(_ record: MachineUpdateRetainedSetupCompletionIntentRecord, from before: Self) throws {
        guard intent == record, before.intent == nil, record.phase == .prepared,
              [Int64(26), 27, 28].contains(activation.runtime.setup.source.actual.schemaVersion) else { throw PreparationStoreError.staleRevision }
        try requireUnchangedActivation(from: before, allowMigration: true)
    }
    func requireTransition(_ record: MachineUpdateRetainedSetupCompletionIntentRecord, from before: Self) throws {
        guard intent == record, let previous = before.intent,
              [Int64(26), 27, 28].contains(activation.runtime.setup.source.actual.schemaVersion) else { throw PreparationStoreError.staleRevision }
        try record.requireTransition(from: previous)
        try requireUnchangedActivation(from: before, allowMigration: false)
    }
    /// Checks the isolated promotion migration. The caller must protect every completion row and all other machine records.
    func requirePromotionMetadataChange(from before: Self) throws {
        guard intent == before.intent, intent?.phase == .recorded,
              [Int64(26), 27, 28].contains(before.activation.runtime.setup.source.actual.schemaVersion),
              [Int64(27), 28].contains(activation.runtime.setup.source.actual.schemaVersion) else {
            throw PreparationStoreError.staleRevision
        }
        try requireUnchangedActivation(from: before, allowMigration: false, allowPromotionMigration: true)
    }
    /// Checks the isolated readiness row and migration. The private writer must protect every other row.
    func requireReadinessMetadataChange(from before: Self) throws {
        guard intent == before.intent, intent?.phase == .recorded,
              [Int64(27), 28].contains(before.activation.runtime.setup.source.actual.schemaVersion),
              activation.runtime.setup.source.actual.schemaVersion == 28 else {
            throw PreparationStoreError.staleRevision
        }
        try requireUnchangedActivation(from: before, allowMigration: false, allowReadinessMigration: true)
    }
    private func requireUnchangedActivation(from before: Self, allowMigration: Bool,
        allowPromotionMigration: Bool = false, allowReadinessMigration: Bool = false) throws {
        let actual = activation.runtime.setup.source, previous = before.activation.runtime.setup.source
        let frame = actual.actual, prior = previous.actual
        try activation.runtime.setup.requireOwner(before.activation.runtime.setup.owner)
        guard frame.schemaVersion == prior.schemaVersion || allowMigration && prior.schemaVersion == 25 && frame.schemaVersion == 26
                || allowPromotionMigration && prior.schemaVersion == 26 && frame.schemaVersion == 27
                || allowReadinessMigration && prior.schemaVersion == 27 && frame.schemaVersion == 28,
              frame.inventory == prior.inventory, frame.activation == prior.activation, frame.admission == prior.admission,
              frame.candidate == prior.candidate, frame.installed.record == prior.installed.record,
              frame.installed.artifacts == prior.installed.artifacts, try frame.seal.encoded == prior.seal.encoded,
              actual.historicalInventory == previous.historicalInventory, actual.provisioningHistory == previous.provisioningHistory,
              actual.preparations == previous.preparations, actual.initializations == previous.initializations,
              actual.accounts == previous.accounts, activation.intent == before.activation.intent,
              activation.runtime.preparation == before.activation.runtime.preparation,
              activation.runtime.state == before.activation.runtime.state,
              activation.runtime.plan == before.activation.runtime.plan,
              activation.runtime.reservedNumbers == before.activation.runtime.reservedNumbers,
              try activation.runtime.plan.encoded == before.activation.runtime.plan.encoded,
              activation.runtime.setup.account?.origin == before.activation.runtime.setup.account?.origin,
              try frame.installed.configuration().configuration(accountID: activation.runtime.preparation.accountID)?.completion.encoded
                == prior.installed.configuration().configuration(accountID: before.activation.runtime.preparation.accountID)?.completion.encoded else {
            throw PreparationStoreError.staleRevision
        }
        try activation.state.requireSame(as: before.activation.state)
    }

    /// Allows only forward completion metadata. The health owner must still read and validate the actual paired stores.
    func requireHealthContinuation(from before: Self, candidate: SignedReleaseEvidence) throws {
        try requireSame(as: .init(activation: activation, intent: intent, candidate: candidate))
        try before.requireSame(as: .init(activation: before.activation, intent: before.intent, candidate: candidate))
        if intent == before.intent {
            try requireUnchangedActivation(from: before, allowMigration: false); return
        }
        guard let intent else { throw PreparationStoreError.staleRevision }
        try requireUnchangedActivation(from: before, allowMigration: before.intent == nil)
        if let previous = before.intent {
            guard intent.id == previous.id, intent.revision != previous.revision,
                  intent.formatVersion == previous.formatVersion, intent.startupIntent == previous.startupIntent,
                  intent.binding == previous.binding, intent.activationPlanDigest == previous.activationPlanDigest,
                  intent.inventoryDigest == previous.inventoryDigest,
                  intent.phase.rawValue > previous.phase.rawValue else { throw PreparationStoreError.staleRevision }
        }
    }

    /// Classifies a fresh paired read. A pending receipt is only a proposal; the private owner must persist it separately.
    func classifyPair(_ current: AuthorityJournal.MachineUpdatePolicyBoundary) throws -> PairStatus {
        guard let intent else { try activation.requirePair(current); return .startup }
        switch intent.phase {
        case .prepared:
            try intent.requireSource(current); return .startup
        case .writing:
            switch try intent.reconciling(current) {
            case .sourceUnchanged: return .startup
            case .recorded(let proposal): return .completionReceiptPending(proposal)
            }
        case .recorded:
            try intent.requireRecorded(current); return .completionRecorded(intent)
        }
    }
}
