import Foundation

/// Actual initial Setup values. Comparisons grant no writer, file custody or import acknowledgement authority.
struct MachineUpdateRetainedSetupInitialRuntimeEntry: CustomStringConvertible, CustomDebugStringConvertible {
    private enum Stage {
        case material(MachineUpdateRetainedSetupMaterialSnapshot)
        case policy(MachineUpdateRetainedSetupPolicySnapshot)
    }
    private let stage: Stage
    var description: String { "MachineUpdateRetainedSetupInitialRuntimeEntry(redacted)" }
    var debugDescription: String { description }
    var runtime: MachineUpdateStableRuntimePreparationSnapshot {
        switch stage { case .material(let value): return value.runtime; case .policy(let value): return value.activation.runtime }
    }
    var activation: RuntimeActivationState {
        switch stage { case .material(let value): return value.activation; case .policy(let value): return value.activation.state }
    }
    var policy: MachineUpdateRetainedSetupPolicySnapshot? {
        guard case .policy(let value) = stage else { return nil }; return value
    }
    var intent: MachineUpdateRetainedSetupPolicyIntentRecord? { policy?.intent }

    init(runtime: MachineUpdateStableRuntimePreparationSnapshot, activation: RuntimeActivationState,
        intent: MachineUpdateRetainedSetupPolicyIntentRecord?, candidate: SignedReleaseEvidence) throws {
        if runtime.state.reference == nil {
            guard intent == nil else { throw RuntimePreparationError.changedScope }
            stage = .material(try .init(runtime: runtime, activation: activation))
        } else {
            let value = try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(
                runtime: runtime, state: activation, candidate: candidate)
            let snapshot = try MachineUpdateRetainedSetupPolicySnapshot(activation: value, intent: intent, candidate: candidate)
            guard !runtime.state.configurationPublished || intent?.phase == .recorded else {
                throw RuntimePreparationError.incomplete
            }
            stage = .policy(snapshot)
        }
    }
    func requireActivation(_ actual: RuntimeActivationState) throws {
        guard actual.jobsRegistered == activation.jobsRegistered, try actual.plan?.encoded == activation.plan?.encoded else {
            throw PreparationStoreError.staleRevision
        }
    }
    func requireSame(as other: Self) throws {
        try runtime.requireSame(as: other.runtime); try requireActivation(other.activation)
        guard intent == other.intent else { throw PreparationStoreError.staleRevision }
    }
    func requireMaterial(_ reference: RuntimeMaterialReference, from before: Self) throws {
        guard intent == nil, before.intent == nil else { throw PreparationStoreError.staleRevision }
        let actual = try MachineUpdateRetainedSetupMaterialSnapshot(runtime: runtime, activation: activation)
        let previous = try MachineUpdateRetainedSetupMaterialSnapshot(runtime: before.runtime, activation: before.activation)
        try actual.requireRetained(reference, from: previous)
    }
    func requirePolicyRetention(_ record: MachineUpdateRetainedSetupPolicyIntentRecord, from before: Self) throws {
        guard let actual = policy, let previous = before.policy else { throw RuntimePreparationError.incomplete }
        try actual.requireRetention(record, from: previous)
    }
    func requirePolicyTransition(_ record: MachineUpdateRetainedSetupPolicyIntentRecord, from before: Self) throws {
        guard let actual = policy, let previous = before.policy else { throw RuntimePreparationError.incomplete }
        try actual.requireTransition(record, from: previous)
    }
    func requirePublication(from before: Self, reference: RuntimeMaterialReference) throws {
        guard let actual = policy, let previous = before.policy else { throw RuntimePreparationError.incomplete }
        try actual.requirePublication(from: previous, reference: reference)
    }
    /// Allows only compared import values. The acknowledgement writer must separately pin all machine rows and the catalog.
    func requireAcknowledgement(inputs: MachineUpdateRetainedSetupRuntimeInputs, from before: Self,
        previousInputs: MachineUpdateRetainedSetupRuntimeInputs) throws {
        guard let recorded = before.intent, recorded.phase == .recorded, intent == recorded,
              before.runtime.state.configurationPublished, runtime.state == before.runtime.state,
              runtime.preparation == before.runtime.preparation, runtime.plan == before.runtime.plan,
              runtime.reservedNumbers == before.runtime.reservedNumbers else { throw PreparationStoreError.staleRevision }
        try runtime.setup.requireAccountStorageState(preparation: before.runtime.preparation,
            initialization: before.runtime.setup.account?.initialization, from: before.runtime.setup)
        try requireActivation(before.activation)
        try previousInputs.requireSource(before.runtime); try inputs.requireSource(runtime)
        try inputs.requirePublicationAcknowledgement(from: previousInputs)
    }
}
