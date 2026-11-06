import Foundation
import RemozioProtocol

/// Proposed installed-release scope only. Decoding grants no publication, restart, health or floor authority.
struct RuntimeReleaseBinding: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.installed-release"
    static let maximumBytes = 8192
    let formatVersion: UInt64
    let activationAttempt: UUID
    let macID: Data
    let installationID: Data
    let accountID: Data
    let candidateDigest: Data
    let sourceInventoryDigest: Data
    let admissionDigest: Data
    let sourceAccountDigest: Data
    let runtimeReferenceDigest: Data?
    let sourcePolicyRevision: UUID
    let sourcePolicyDigest: Data
    let previousInstalledReleaseDigest: Data
    let installedReleaseDigest: Data
    let updateID: Data
    let startupPolicyDigest: Data
    let completionPolicyDigest: Data
    var description: String { "RuntimeReleaseBinding(redacted)" }
    var debugDescription: String { description }

    init(accountID: Data, source: MachineUpdateRestartSource, candidate: SignedReleaseEvidence,
         policy: MachineUpdatePolicyPlan) throws {
        let context = source.replacement, inventory = context.inventory, activation = context.activation
        guard activation.phase.irreversible, let replacement = context.replacement, replacement.phase == .observed,
              let account = source.accounts.first(where: { $0.accountID == accountID }),
              let runtime = context.runtime.runtimes.first(where: { $0.reference.services.accountID == accountID }),
              let preparation = account.preparation, preparation.storagePrepared,
              let initial = account.initialization, initial.complete,
              preparation.accountID == accountID, preparation.ownerUID == account.ownerUID,
              runtime.reference.services.ownerUID == account.ownerUID,
              runtime.reference.services.macID == inventory.macID,
              runtime.reference.services.installationID == inventory.installationID else {
            throw RuntimePreparationError.changedScope
        }
        try runtime.reference.validate(account: preparation, services: runtime.reference.services)
        // The observed swap must belong to this activation and its operands, not only be in the observed phase.
        do { try replacement.requireScope(activation: activation, inventory: inventory, candidate: context.candidate) }
        catch { throw RuntimePreparationError.changedScope }
        try activation.requireScope(candidate: context.candidate, inventory: inventory, admission: context.admission)
        try policy.requireCandidate(candidate)
        guard try DurableReleasePreparation.digest(candidate) == activation.updateID else { throw RuntimePreparationError.changedScope }
        formatVersion = 2; activationAttempt = activation.attemptID; macID = inventory.macID
        installationID = inventory.installationID; self.accountID = accountID
        candidateDigest = activation.candidateDigest; sourceInventoryDigest = activation.inventoryDigest
        admissionDigest = activation.admissionDigest; sourceAccountDigest = try source.accountDigest(accountID: accountID)
        runtimeReferenceDigest = try MachineUpdateActivationRecord.digest(runtime.reference.encoded)
        sourcePolicyRevision = policy.source.revision; sourcePolicyDigest = try MachineUpdateActivationRecord.digest(policy.source.storedBytes)
        previousInstalledReleaseDigest = inventory.releaseDigest; installedReleaseDigest = policy.releaseDigest
        updateID = activation.updateID; startupPolicyDigest = try MachineUpdateActivationRecord.digest(policy.startupPolicy.bytes)
        completionPolicyDigest = try MachineUpdateActivationRecord.digest(policy.completionPolicy.bytes)
        try validate()
    }

    /// Use inside fresh scoped machine and account reads. Other accounts and publication phases need the enclosing machine owner.
    func requireSourceForPublication(_ source: MachineUpdateRestartSource, currentPolicy: AuthorityCodePolicySnapshot,
                                     candidate: SignedReleaseEvidence) throws {
        let policy = try MachineUpdatePolicyPlan(source: currentPolicy, candidate: candidate)
        guard try Self(accountID: accountID, source: source, candidate: candidate, policy: policy) == self else {
            throw RuntimePreparationError.changedScope
        }
    }
    func requireHistoricalRuntime(_ reference: RuntimeMaterialReference) throws {
        guard formatVersion == 2, macID == reference.services.macID,
              installationID == reference.services.installationID, accountID == reference.services.accountID,
              try runtimeReferenceDigest == MachineUpdateActivationRecord.digest(reference.encoded) else {
            throw RuntimePreparationError.changedScope
        }
    }
    func requirePolicy(_ policy: AuthorityCodePolicy, stage: RuntimeReleasePolicyStage) throws {
        switch stage {
        case .startup: try requireStartupPolicy(policy)
        case .completion: try requireCompletionPolicy(policy)
        }
    }
    func requireStartupPolicy(_ policy: AuthorityCodePolicy) throws {
        guard try MachineUpdateActivationRecord.digest(policy.bytes) == startupPolicyDigest else {
            throw RuntimePreparationError.changedScope
        }
    }
    func requireCompletionPolicy(_ policy: AuthorityCodePolicy) throws {
        guard try MachineUpdateActivationRecord.digest(policy.bytes) == completionPolicyDigest else {
            throw RuntimePreparationError.changedScope
        }
    }

    private func validate() throws {
        guard (formatVersion == 1 && runtimeReferenceDigest == nil || formatVersion == 2 && runtimeReferenceDigest?.count == 32),
              [macID, installationID, accountID].allSatisfy({ $0.count == 16 }),
              [candidateDigest, sourceInventoryDigest, admissionDigest, sourceAccountDigest, sourcePolicyDigest,
               previousInstalledReleaseDigest, installedReleaseDigest, updateID, startupPolicyDigest,
               completionPolicyDigest].allSatisfy({ $0.count == 32 }) else { throw RuntimePreparationError.invalidRecord }
    }
    var encoded: Data { get throws {
        try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else { throw RuntimePreparationError.invalidRecord }
        return bytes
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw RuntimePreparationError.invalidRecord }
            let value = try JSONDecoder().decode(Self.self, from: bytes); try value.validate()
            guard try value.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return value
        } catch { throw RuntimePreparationError.invalidRecord }
    }
}

enum RuntimeReleasePolicyStage: UInt64, Equatable, Sendable {
    case startup = 1
    case completion = 2
}
