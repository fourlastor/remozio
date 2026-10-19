import Foundation

struct GatewayRuntimeActivationContext {
    let plan: GatewayRuntimeActivationPlan
    let account: AccountPreparationIntent
    let initialization: AuthorityInitializationIntent
    let journal: GatewayJournalPreparationState
    let foreground: RuntimeActivationPlan
    let inventory: InstallationInventory
}
struct GatewayRuntimeActivationOperations {
    let verifyInitializerAbsent: (GatewayRuntimeActivationContext, () throws -> Void) throws -> Void
    let prepare: (GatewayRuntimeActivationContext, GatewayRuntimeActivationFiles.Mode, () throws -> Void) throws -> Void
    let validate: (GatewayRuntimeActivationContext, () throws -> Void) throws -> Void
    let register: (InstalledAccountJobManifest, () throws -> Void) throws -> Void
    static var native: Self {
        func files(_ context: GatewayRuntimeActivationContext, _ mode: GatewayRuntimeActivationFiles.Mode,
                   _ verify: () throws -> Void) throws {
            _ = try GatewayRuntimeActivationFiles.prepare(plan: context.plan, account: context.account,
                initialization: context.initialization, journal: context.journal, foreground: context.foreground,
                inventory: context.inventory, mode: mode, verifyCurrent: verify)
        }
        return .init(verifyInitializerAbsent: { try GatewayRuntimeActivationPrerequisites.requireNativeInitializerAbsent($0, verifyCurrent: $1) },
            prepare: files, validate: { try files($0, .validateRetained, $1) },
            register: { try RuntimeJobRegistration.ensure($0, verifyCurrent: $1) })
    }
}

/// The setup owner authenticates the administrator and holds the release scope across this operation.
/// Native initializer inspections run outside machine scopes. Registration alone does not prove runtime health.
enum GatewayRuntimeActivationOperation {
    typealias MachineAccess = (_ body: (PreparationIntentStore) throws -> Void) throws -> Void
    enum Stage: CaseIterable { case intentRetained, artifactsPublished, publicationRetained, inventoryEnrolled, jobRegistered, completed }

    static func resume(plan: GatewayRuntimeActivationPlan, withMachine: MachineAccess,
                       verifyScope: (PreparationIntentStore) throws -> Void,
                       operations: GatewayRuntimeActivationOperations,
                       didStage: (Stage) throws -> Void = { _ in }) throws -> GatewayRuntimeActivationState {
        try withoutActuallyEscaping(verifyScope) { verifyScope in
        try withoutActuallyEscaping(didStage) { didStage in
        func verifyRetained(_ machine: PreparationIntentStore) throws {
            try verifyScope(machine)
            let state = try machine.gatewayRuntimeActivation(accountID: plan.accountID)
            guard try state.plan?.encoded == plan.encoded else { throw GatewayPreparationError.changedScope }
            try verifyScope(machine)
        }
        func context(_ machine: PreparationIntentStore) throws -> GatewayRuntimeActivationContext {
            try verifyRetained(machine)
            guard let account = try machine.accountPreparation(ownerUID: plan.extensions.authority.material.runtime.services.ownerUID),
                  account.accountID == plan.accountID,
                  let initialization = try machine.initialization(accountID: plan.accountID), initialization.complete,
                  let foreground = try machine.runtimeActivation(accountID: plan.accountID).plan,
                  let inventory = try machine.inventory() else { throw GatewayPreparationError.incomplete }
            try machine.validateAccountPreparation(account)
            let journal = try machine.gatewayJournalPreparation(accountID: plan.accountID)
            _ = try plan.proposal(journal: journal, foreground: foreground, inventory: inventory)
            try verifyScope(machine)
            return .init(plan: plan, account: account, initialization: initialization, journal: journal,
                foreground: foreground, inventory: inventory)
        }
        var initialContext: GatewayRuntimeActivationContext?
        try withMachine { machine in
            try verifyScope(machine); try machine.retainGatewayRuntimeActivation(plan); try didStage(.intentRetained)
            initialContext = try context(machine)
        }
        func verifyPreparedScope() throws { try withMachine { try verifyRetained($0) } }
        guard let initialContext else { throw GatewayPreparationError.incomplete }
        try operations.verifyInitializerAbsent(initialContext, verifyPreparedScope)
        try withMachine { machine in
            let current = try context(machine), retained = try machine.gatewayRuntimeActivation(accountID: plan.accountID)
            func verify() throws { try verifyRetained(machine) }
            try operations.prepare(current, retained.filesPublished ? .validateRetained : .publishPending, verify)
            try verify(); try didStage(.artifactsPublished); try verify()
            try operations.validate(try context(machine), verify); try machine.markGatewayRuntimePublished(plan)
            try didStage(.publicationRetained); try verify()
            _ = try machine.enrollGatewayRuntimeActivation(plan); try didStage(.inventoryEnrolled); try verify()
        }
        func verifyReady() throws {
            try withMachine { machine in
                let current = try context(machine), state = try machine.gatewayRuntimeActivation(accountID: plan.accountID)
                let proposal = try plan.proposal(journal: current.journal, foreground: current.foreground, inventory: current.inventory)
                guard state.filesPublished, try proposal.enrolledInventory(current.inventory) == current.inventory else {
                    throw GatewayPreparationError.incomplete
                }
                try operations.validate(current) { try verifyRetained(machine) }
            }
        }
        // Each verification closes its machine lease before launchctl runs. A lost registration reply is reconciled by exact job identity.
        try verifyReady(); try operations.verifyInitializerAbsent(initialContext, verifyReady)
        try operations.register(plan.gatewayJob, verifyReady)
        try didStage(.jobRegistered); try verifyReady()
        try operations.verifyInitializerAbsent(initialContext, verifyReady)
        var result: GatewayRuntimeActivationState?
        try withMachine { machine in
            let current = try context(machine)
            try operations.validate(current) { try verifyRetained(machine) }
            try machine.markGatewayRuntimeRegistered(plan); try didStage(.completed)
            _ = try context(machine); result = try machine.gatewayRuntimeActivation(accountID: plan.accountID)
        }
        guard let result else { throw GatewayPreparationError.incomplete }; return result
        }
        }
    }
}
