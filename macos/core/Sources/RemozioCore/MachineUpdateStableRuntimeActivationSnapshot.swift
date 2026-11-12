import Foundation

/// Actual activation facts and current host selection. This snapshot grants no write, registration, health, or admission authority.
struct MachineUpdateStableRuntimeActivationSnapshot: CustomStringConvertible, CustomDebugStringConvertible {
    let runtime: MachineUpdateStableRuntimePreparationSnapshot
    let state: RuntimeActivationState
    let installed: RuntimeReleaseConfigurationPlan?
    let origin: MachineUpdateStableRuntimeSource.ProvisioningOrigin
    var description: String { "MachineUpdateStableRuntimeActivationSnapshot(redacted)" }
    var debugDescription: String { description }
    var selectedHost: InstalledAuthorityCommandConfiguration? {
        installed?.host ?? (origin == .currentRelease ? state.plan?.host : nil)
    }
    var progress: SetupActivationProgress { get throws {
        try .init(account: runtime.preparation, runtime: runtime.state, state: state)
    } }

    var requiresRetainedMaterialCustody: Bool { !runtime.state.configurationPublished }

    init(runtime: MachineUpdateStableRuntimePreparationSnapshot, state: RuntimeActivationState,
        candidate: SignedReleaseEvidence) throws {
        try self.init(runtime: runtime, state: state, candidate: candidate, allowRetainedPolicyMaterial: false)
    }
    /// Captures policy operands before consumer publication. The native owner must separately verify retained material custody.
    static func retainedSetupPolicyMaterial(runtime: MachineUpdateStableRuntimePreparationSnapshot,
        state: RuntimeActivationState, candidate: SignedReleaseEvidence) throws -> Self {
        try .init(runtime: runtime, state: state, candidate: candidate, allowRetainedPolicyMaterial: true)
    }
    private init(runtime: MachineUpdateStableRuntimePreparationSnapshot, state: RuntimeActivationState,
        candidate: SignedReleaseEvidence, allowRetainedPolicyMaterial: Bool) throws {
        guard runtime.state.configurationPublished || allowRetainedPolicyMaterial, let reference = runtime.state.reference,
              let scope = runtime.setup.account, scope.initialization?.complete == true,
              state.plan != nil || !state.jobsRegistered else { throw RuntimeActivationError.incomplete }
        try reference.validate(account: runtime.preparation, services: runtime.plan)
        if let plan = state.plan {
            try plan.validate(account: runtime.preparation, reference: reference)
            guard plan.bundlePath == runtime.setup.source.actual.inventory.bundlePath else { throw RuntimeActivationError.changedScope }
        }
        let source = runtime.setup.source, actual = source.actual
        let installed = try actual.installed.configuration().configuration(accountID: scope.accountID)?.completion
        if let installed {
            let intent = try actual.installed.completionIntent()
            guard scope.origin == .retained, installed.policyStage == .completion,
                  installed.gateway.runtime == reference,
                  installed.binding.installedReleaseDigest == actual.inventory.releaseDigest,
                  installed.binding.activationAttempt == actual.seal.finishing.attemptID,
                  installed.binding.candidateDigest == actual.seal.finishing.candidateDigest,
                  installed.binding.admissionDigest == actual.seal.finishing.admissionDigest,
                  let original = intent.record.accounts.first(where: { $0.accountID == scope.accountID }),
                  installed.binding.sourceAccountDigest == original.sourceDigest,
                  installed.binding.sourceInventoryDigest == MachineUpdateActivationRecord.digest(source.historicalInventory.canonicalBytes),
                  installed.binding.previousInstalledReleaseDigest == source.historicalInventory.releaseDigest else {
                throw RuntimeActivationError.changedScope
            }
            try installed.binding.requireHistoricalRuntime(reference)
            try installed.host.validateRelease(candidate, bundlePath: actual.inventory.bundlePath)
            if scope.inInventory {
                _ = try installed.host.validate(inventory: actual.inventory, release: candidate, bundlePath: actual.inventory.bundlePath)
            }
            let gateway = installed.gateway, services = gateway.runtime.services
            guard gateway.retainedSetupBinding == nil, gateway.retainedSetupCompletionBinding == nil else {
                throw GatewayPreparationError.changedScope
            }
            try gateway.runtime.validate(account: runtime.preparation, services: services)
            guard actual.inventory.macID == services.macID, actual.inventory.installationID == services.installationID,
                  actual.inventory.releaseDigest == gateway.installedReleaseDigest,
                  actual.inventory.bundlePath == gateway.bundlePath else { throw GatewayPreparationError.changedScope }
            try installed.binding.requireHistoricalRuntime(gateway.runtime)
            try installed.binding.requirePolicy(gateway.codePolicy, stage: .completion)
            try gateway.validateRelease(candidate)
        } else if scope.origin == .currentRelease, let plan = state.plan {
            try plan.host.validateRelease(candidate, bundlePath: actual.inventory.bundlePath)
            if scope.inInventory {
                _ = try plan.host.validate(inventory: actual.inventory, release: candidate, bundlePath: actual.inventory.bundlePath)
            }
        }
        if !runtime.state.configurationPublished {
            guard allowRetainedPolicyMaterial, scope.origin == .retained, !scope.inInventory,
                  installed == nil, state.plan == nil, !state.jobsRegistered,
                  runtime.preparation.storagePrepared else { throw RuntimeActivationError.incomplete }
            _ = try source.unconfiguredRetainedAccount(accountID: runtime.preparation.accountID,
                ownerUID: runtime.preparation.ownerUID)
        }
        self.runtime = runtime; self.state = state; self.installed = installed; origin = scope.origin
    }
    func requireState(_ actual: RuntimeActivationState) throws {
        guard actual.jobsRegistered == state.jobsRegistered, try actual.plan?.encoded == state.plan?.encoded else {
            throw PreparationStoreError.staleRevision
        }
    }
    func requireSame(as other: Self) throws {
        try runtime.requireSame(as: other.runtime); try requireState(other.state)
        guard origin == other.origin, try installed?.encoded == other.installed?.encoded else { throw PreparationStoreError.staleRevision }
    }
    func requireCurrent(machine: PreparationIntentStore, candidate: SignedReleaseEvidence) throws {
        try machine.stableRuntimeActivationSnapshot(owner: runtime.setup.owner, candidate: candidate).requireSame(as: self)
    }
}
