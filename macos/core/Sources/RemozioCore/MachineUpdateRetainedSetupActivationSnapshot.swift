import Foundation

/// Current retained activation values. The snapshot grants no writer, registration, health, or native authority.
struct MachineUpdateRetainedSetupActivationSnapshot: CustomStringConvertible, CustomDebugStringConvertible {
    let runtime: MachineUpdateStableRuntimePreparationSnapshot
    let state: RuntimeRetainedSetupActivationState
    let intent: MachineUpdateRetainedSetupPolicyIntentRecord
    var description: String { "MachineUpdateRetainedSetupActivationSnapshot(redacted)" }
    var debugDescription: String { description }

    init(runtime: MachineUpdateStableRuntimePreparationSnapshot, state: RuntimeRetainedSetupActivationState,
        intent: MachineUpdateRetainedSetupPolicyIntentRecord, candidate: SignedReleaseEvidence) throws {
        let preparation = runtime.preparation, setup = runtime.setup, actual = setup.source.actual
        guard setup.account?.origin == .retained,
              try actual.installed.configuration().configuration(accountID: preparation.accountID)?.completion == nil,
              runtime.state.configurationPublished, runtime.state.reference != nil,
              setup.account?.initialization?.complete == true, (25...28).contains(actual.schemaVersion),
              intent.phase == .recorded, intent.macID == preparation.macID, intent.installationID == preparation.installationID,
              intent.accountID == preparation.accountID, intent.ownerUID == preparation.ownerUID else {
            throw RuntimeActivationError.changedScope
        }
        try Self.requireDeclaredSchema(actual.schemaVersion, candidate: candidate)
        try RuntimeRetainedSetupActivationPlan.requireFormats(candidate)
        try intent.requireCandidate(candidate)
        if let plan = state.plan {
            try Self.requireBoundPlan(plan, runtime: runtime, state: state, intent: intent, candidate: candidate)
        } else {
            guard setup.account?.inInventory == false, !state.jobsRegistered else { throw RuntimeActivationError.changedScope }
            let unactivated = try MachineUpdateStableRuntimeActivationSnapshot(runtime: runtime,
                state: .init(plan: nil, jobsRegistered: false), candidate: candidate)
            try intent.requireSnapshot(unactivated, candidate: candidate)
        }
        self.runtime = runtime; self.state = state; self.intent = intent
    }
    private static func requireDeclaredSchema(_ schema: Int64, candidate: SignedReleaseEvidence) throws {
        try MachineUpdateStableReleaseRecord.requireFormats(candidate)
        try MachineUpdateRetainedSetupPolicyStorage.requireReaderFormats(candidate)
        if schema >= 26 { try MachineUpdateRetainedSetupCompletionStorage.requireReaderFormats(candidate) }
        if schema >= 27 { try MachineUpdateRetainedSetupPromotionStorage.requireReaderFormats(candidate) }
        if schema == 28 { try MachineUpdateRetainedSetupPromotionReadyStorage.requireReaderFormats(candidate) }
    }
    func requireSame(as other: Self) throws {
        try runtime.requireSame(as: other.runtime); try state.requireSame(as: other.state)
        guard intent == other.intent else { throw PreparationStoreError.staleRevision }
    }
    func requireCurrent(machine: PreparationIntentStore, candidate: SignedReleaseEvidence) throws {
        try machine.retainedSetupActivationSnapshot(owner: runtime.setup.owner, candidate: candidate).requireSame(as: self)
    }
    /// The owner must observe the actual paired stores. A metadata receipt does not prove their current state.
    func requirePair(_ current: AuthorityJournal.MachineUpdatePolicyBoundary) throws {
        try intent.requireRecorded(current)
        try state.plan?.retainedSetupBinding.requireRecordedBoundary(current)
    }
    /// Checks proposed values only. The owner must also authenticate current files, identity, and admission.
    func requirePlan(_ plan: RuntimeRetainedSetupActivationPlan, candidate: SignedReleaseEvidence) throws {
        try Self.requireBoundPlan(plan, runtime: runtime, state: state, intent: intent, candidate: candidate)
        if let retained = state.plan {
            guard try retained.encoded == plan.encoded else { throw RuntimeActivationError.conflictingPlan }
        } else {
            guard plan.retainedSetupInventory == runtime.setup.source.actual.inventory,
                  runtime.setup.account?.inInventory == false, !state.jobsRegistered else {
                throw PreparationStoreError.staleRevision
            }
        }
    }
    private static func requireBoundPlan(_ plan: RuntimeRetainedSetupActivationPlan,
        runtime: MachineUpdateStableRuntimePreparationSnapshot, state: RuntimeRetainedSetupActivationState, intent: MachineUpdateRetainedSetupPolicyIntentRecord,
        candidate: SignedReleaseEvidence) throws {
        let source = runtime.setup.source, actual = source.actual
        let binding = plan.retainedSetupBinding, observed = plan.retainedSetupInventory
        guard plan.formatVersion == 6, let initial = runtime.setup.account?.initialization,
              let committedPolicy = intent.committedPolicy, let committedCheckpoint = intent.committedCheckpoint,
              runtime.state.reference == plan.reference else { throw RuntimeActivationError.changedScope }
        try plan.validate(account: runtime.preparation, reference: plan.reference)
        try plan.host.validateRelease(candidate, bundlePath: actual.inventory.bundlePath)
        let original = try source.unconfiguredRetainedAccount(accountID: runtime.preparation.accountID,
            ownerUID: runtime.preparation.ownerUID)
        let provisioning = try source.provisioningInventory(accountID: runtime.preparation.accountID,
            ownerUID: runtime.preparation.ownerUID, releaseDigest: runtime.preparation.releaseDigest)
        let recorded = try committedPolicy.snapshot()
        let digest = try MachineUpdateRetainedSetupActivationSource.recordedScopeDigest(runtime: runtime,
            observedInventory: observed, sourcePolicy: intent.sourcePolicy.snapshot(),
            sourceCheckpoint: .decode(intent.sourceCheckpoint), candidate: candidate)
        func hash(_ bytes: Data) -> Data { MachineUpdateActivationRecord.digest(bytes) }
        guard digest == intent.sourceDigest, binding.retainedSourceDigest == digest,
              binding.activationAttempt == actual.seal.finishing.attemptID,
              binding.candidateDigest == actual.seal.finishing.candidateDigest,
              binding.admissionDigest == actual.seal.finishing.admissionDigest, binding.updateID == actual.seal.finishing.updateID,
              try binding.stableSealDigest == hash(actual.seal.encoded),
              try binding.installedEpochDigest == hash(actual.installed.record.encoded),
              binding.sealedInventoryDigest == actual.seal.initialInventoryDigest,
              binding.sourceAccountDigest == original.sourceDigest,
              try binding.initializationDigest == hash(initial.bytes), binding.initializationDigest == intent.initializationDigest,
              binding.provisioningInventoryDigest == hash(provisioning.canonicalBytes),
              binding.previousInstalledReleaseDigest == source.historicalInventory.releaseDigest,
              binding.installedReleaseDigest == actual.inventory.releaseDigest,
              try binding.policyIntentDigest == hash(intent.encoded),
              try binding.sourcePolicyDigest == hash(intent.sourcePolicy.snapshot().storedBytes),
              binding.sourceCheckpointDigest == hash(intent.sourceCheckpoint),
              binding.startupPolicyDigest == hash(intent.startupPolicy),
              try binding.startupPolicySnapshotDigest == hash(recorded.storedBytes),
              binding.startupCheckpointDigest == hash(committedCheckpoint),
              binding.completionPolicyDigest == hash(intent.completionPolicy) else { throw PreparationStoreError.staleRevision }
        try binding.requireStartupPolicy(recorded.policy)
        if runtime.setup.account?.inInventory == true {
            guard try plan.enrolledInventory(actual.inventory) == actual.inventory else { throw RuntimeActivationError.changedScope }
        } else { guard !state.jobsRegistered else { throw RuntimeActivationError.changedScope } }
    }
    /// Checks one plan insertion. A future private writer must separately pin every other protected row.
    func requireRetention(_ plan: RuntimeRetainedSetupActivationPlan, from before: Self) throws {
        guard intent == before.intent, before.state.plan == nil, !before.state.jobsRegistered, !state.jobsRegistered,
              runtime.setup.account?.inInventory == false, before.runtime.setup.account?.inInventory == false,
              try state.plan?.encoded == plan.encoded else { throw RuntimeActivationError.changedScope }
        try requireUnchangedRuntime(from: before)
    }
    private func requireUnchangedRuntime(from before: Self) throws {
        let setup = runtime.setup, previous = before.runtime.setup, actual = setup.source.actual, prior = previous.source.actual
        try setup.requireOwner(previous.owner)
        guard runtime.state == before.runtime.state, runtime.plan == before.runtime.plan,
              runtime.reservedNumbers == before.runtime.reservedNumbers, setup.account == previous.account,
              setup.source.historicalInventory == previous.source.historicalInventory,
              setup.source.provisioningHistory == previous.source.provisioningHistory,
              setup.source.preparations == previous.source.preparations, setup.source.initializations == previous.source.initializations,
              setup.source.accounts == previous.source.accounts,
              actual.schemaVersion == prior.schemaVersion, actual.inventory == prior.inventory,
              actual.activation == prior.activation, actual.admission == prior.admission, actual.candidate == prior.candidate,
              actual.installed.record == prior.installed.record, actual.installed.artifacts == prior.installed.artifacts,
              try actual.seal.encoded == prior.seal.encoded else { throw RuntimeActivationError.changedScope }
    }
    /// Checks one inventory addition. The private writer separately pins every other protected row.
    func requireInventoryEnrollment(_ plan: RuntimeRetainedSetupActivationPlan, from before: Self) throws {
        let setup = runtime.setup, previous = before.runtime.setup
        let actual = setup.source.actual, prior = previous.source.actual
        try setup.requireOwner(previous.owner)
        let proposed = try plan.enrolledInventory(prior.inventory)
        let inventory = try InstallationInventory(macID: proposed.macID, installationID: proposed.installationID,
            revision: actual.inventory.revision, bundlePath: proposed.bundlePath, releaseDigest: proposed.releaseDigest,
            accounts: proposed.accounts, services: proposed.services, formatVersion: proposed.formatVersion)
        guard intent == before.intent, previous.account?.inInventory == false, setup.account?.inInventory == true,
              proposed != prior.inventory, actual.inventory == inventory, actual.inventory.revision != prior.inventory.revision,
              actual.schemaVersion == prior.schemaVersion, actual.activation == prior.activation, actual.admission == prior.admission,
              actual.candidate == prior.candidate, actual.installed.record == prior.installed.record,
              actual.installed.artifacts == prior.installed.artifacts, try actual.seal.encoded == prior.seal.encoded,
              runtime.state == before.runtime.state, runtime.plan == before.runtime.plan,
              runtime.reservedNumbers == before.runtime.reservedNumbers, try runtime.plan.encoded == before.runtime.plan.encoded,
              setup.preparation == previous.preparation, setup.account?.initialization == previous.account?.initialization,
              setup.account?.origin == previous.account?.origin, setup.account?.accountID == previous.account?.accountID,
              setup.account?.ownerUID == previous.account?.ownerUID,
              setup.source.historicalInventory == previous.source.historicalInventory,
              setup.source.provisioningHistory == previous.source.provisioningHistory,
              setup.source.preparations == previous.source.preparations, setup.source.initializations == previous.source.initializations,
              setup.source.accounts.filter({ $0.accountID != plan.accountID }) == previous.source.accounts.filter({ $0.accountID != plan.accountID }),
              try state.plan?.encoded == plan.encoded, try before.state.plan?.encoded == plan.encoded,
              !state.jobsRegistered, !before.state.jobsRegistered else { throw RuntimeActivationError.changedScope }
    }
    /// Checks one historical registration marker. It grants no floor or ordinary startup authority.
    func requireRegistrationMarker(_ plan: RuntimeRetainedSetupActivationPlan, from before: Self) throws {
        try requireUnchangedRuntime(from: before)
        let inventory = runtime.setup.source.actual.inventory
        guard intent == before.intent, runtime.setup.account?.inInventory == true, before.runtime.setup.account?.inInventory == true,
              try state.plan?.encoded == plan.encoded, try before.state.plan?.encoded == plan.encoded,
              state.jobsRegistered, !before.state.jobsRegistered,
              try plan.enrolledInventory(inventory) == inventory else { throw RuntimeActivationError.changedScope }
    }
    /// Validates the actual runtime files against this plan. This does not publish activation files or register jobs.
    func validateRuntime(plan: RuntimeRetainedSetupActivationPlan, material: RuntimePreparationMaterial,
        readPolicyBoundary: () throws -> AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence,
        verifyCurrent: () throws -> Void,
        read: (RuntimePublishedArtifactValidation.Artifact) throws -> Data) throws {
        try validateRuntimeFiles(plan: plan, material: material, candidate: candidate, verifyCurrent: {
            try verifyCurrent(); try requirePair(readPolicyBoundary()); try verifyCurrent()
        }, read: read)
    }
    private func validateRuntimeFiles(plan: RuntimeRetainedSetupActivationPlan, material: RuntimePreparationMaterial,
        candidate: SignedReleaseEvidence, verifyCurrent: () throws -> Void,
        read: (RuntimePublishedArtifactValidation.Artifact) throws -> Data) throws {
        func verify() throws { try verifyCurrent() }
        try verify(); try requirePlan(plan, candidate: candidate)
        guard try material.reference == plan.reference, let initial = runtime.setup.account?.initialization else {
            throw RuntimePreparationError.conflictingMaterial
        }
        func captured(_ file: AdministrativeSetupPublication.File) throws -> Data {
            try verify()
            let bytes = try read(.init(path: RuntimePreparationPaths.sharedDirectory + "/" + file.name,
                bytes: Data(), access: .publicRoot))
            try verify(); return bytes
        }
        let owner = runtime.preparation.ownerUID
        let clients = try RuntimeActivationClients(presence: .decode(captured(.presenceClient(ownerUID: owner))),
            pairing: .decode(captured(.pairingClient(ownerUID: owner))), frontend: .decode(captured(.frontendClient(ownerUID: owner))))
        let bundle = try plan.configurationBundle(account: runtime.preparation, initialization: initial,
            inventory: runtime.setup.source.actual.inventory, clients: clients)
        try RuntimePublishedArtifactValidation.validate(bundle: bundle, material: material, verifyCurrent: verify, read: read)
        try verify(); try requirePlan(plan, candidate: candidate); try verify()
    }
}

/// Historical retained markers only. This state cannot hold an ordinary executable plan.
struct RuntimeRetainedSetupActivationState {
    let plan: RuntimeRetainedSetupActivationPlan?
    let jobsRegistered: Bool
    init(plan: RuntimeRetainedSetupActivationPlan?, jobsRegistered: Bool) throws {
        guard plan != nil || !jobsRegistered else { throw RuntimeActivationError.incomplete }
        self.plan = plan; self.jobsRegistered = jobsRegistered
    }
    func requireSame(as other: Self) throws {
        guard jobsRegistered == other.jobsRegistered, try plan?.encoded == other.plan?.encoded else {
            throw PreparationStoreError.staleRevision
        }
    }
}
