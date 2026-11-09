import Foundation
import RemozioProtocol

/// Machine-side operands for an unpublished retained Setup policy.
struct MachineUpdateRetainedSetupPolicyMaterial {
    let runtime: MachineUpdateStableRuntimePreparationSnapshot
    let original: MachineUpdateCompletionIntentRecord.Account
    let initialization: AuthorityInitializationIntent
    let reference: RuntimeMaterialReference

    init(runtime: MachineUpdateStableRuntimePreparationSnapshot, activation: RuntimeActivationState) throws {
        guard activation.plan == nil, !activation.jobsRegistered, !runtime.state.configurationPublished,
              runtime.setup.account?.inInventory == false else {
            throw RuntimeActivationError.changedScope
        }
        let preparation = runtime.preparation
        original = try runtime.setup.source.unconfiguredRetainedAccount(accountID: preparation.accountID,
            ownerUID: preparation.ownerUID)
        guard let initialization = runtime.setup.account?.initialization, initialization.complete,
              let reference = runtime.state.reference else { throw RuntimeActivationError.incomplete }
        guard initialization.initializationBytes == preparation.initializationBytes else {
            throw RuntimeActivationError.changedScope
        }
        self.runtime = runtime
        self.initialization = initialization
        self.reference = reference
    }

    /// Reconstructs the archived policy scope from the original policy and checkpoint.
    func scopeDigest(policy: MachineUpdatePolicyPlan, checkpoint: ContinuityCheckpoint) throws -> Data {
        let preparation = runtime.preparation
        let actual = runtime.setup.source.actual
        guard policy.source.policy == (try preparation.initialAuthority.codePolicy),
              checkpoint == initialization.checkpoint,
              policy.releaseDigest == actual.inventory.releaseDigest,
              preparation.releaseDigest != policy.releaseDigest else { throw RuntimeActivationError.changedScope }
        let limits = try CBORLimits(maxBytes: 1_048_576, maxDepth: 3, maxItems: 40)
        let bytes = try DeterministicCBOR.encode(.map([
            0: .text("remozio/retained-setup-activation-source/v2"),
            1: .bytes(actual.inventory.canonicalBytes), 2: .bytes(actual.seal.encoded),
            3: .bytes(original.sourceDigest), 4: .bytes(preparation.bytes),
            5: .bytes(initialization.bytes), 6: .bytes(runtime.plan.encoded), 7: .bytes(reference.encoded),
            8: .bytes(policy.source.storedBytes), 9: .bytes(checkpoint.bytes),
            10: .bytes(policy.startupPolicy.bytes), 11: .bytes(policy.completionPolicy.bytes),
            12: .text(policy.source.revision.uuidString.lowercased())
        ]), limits: limits)
        return MachineUpdateActivationRecord.digest(bytes)
    }

    func requireSame(as other: Self) throws {
        try runtime.requireSame(as: other.runtime)
        guard original == other.original, initialization == other.initialization, reference == other.reference else {
            throw PreparationStoreError.staleRevision
        }
    }
}

/// Joins unactivated machine facts with the original paired journal. It grants no policy write or native startup.
struct MachineUpdateRetainedSetupActivationSource: CustomStringConvertible, CustomDebugStringConvertible {
    let runtime: MachineUpdateStableRuntimePreparationSnapshot
    let original: MachineUpdateCompletionIntentRecord.Account
    let accountPolicy: AuthorityJournal.MachineUpdatePolicyBoundary
    let policy: MachineUpdatePolicyPlan
    let digest: Data
    var description: String { "MachineUpdateRetainedSetupActivationSource(redacted)" }
    var debugDescription: String { description }

    fileprivate init(runtime: MachineUpdateStableRuntimePreparationSnapshot,
        original: MachineUpdateCompletionIntentRecord.Account, accountPolicy: AuthorityJournal.MachineUpdatePolicyBoundary,
        policy: MachineUpdatePolicyPlan, digest: Data) {
        self.runtime = runtime
        self.original = original
        self.accountPolicy = accountPolicy
        self.policy = policy
        self.digest = digest
    }

    static func capture(owner: LocalAccountIdentity, machine: PreparationIntentStore,
        journal: AuthorityJournal, candidate: SignedReleaseEvidence) throws -> Self {
        let material = try machine.retainedSetupPolicyMaterial(owner: owner, candidate: candidate)
        let runtime = material.runtime, original = material.original
        let initialization = material.initialization
        let accountPolicy = try journal.captureUnactivatedSetupPolicySource(expected: initialization)
        let policy = try MachineUpdatePolicyPlan(source: accountPolicy.policy, candidate: candidate)
        let digest = try material.scopeDigest(policy: policy, checkpoint: accountPolicy.checkpoint)
        try machine.retainedSetupPolicyMaterial(owner: owner, candidate: candidate).requireSame(as: material)
        guard try journal.captureUnactivatedSetupPolicySource(expected: initialization) == accountPolicy else {
            throw PreparationStoreError.staleRevision
        }
        return .init(runtime: runtime, original: original, accountPolicy: accountPolicy, policy: policy, digest: digest)
    }
}
