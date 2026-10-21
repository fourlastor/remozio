import Foundation

/// Each Root operation checks the import after it acquires its own machine lease.
/// The record authorizes no credential custody and proves no service health.
enum SharedSetupImportGatewayRuntimeScope {
    static func validate(machine: PreparationIntentStore, account: AccountPreparationIntent,
                         expected: SharedSetupImportIntent?, activationSettings: GatewayRuntimeActivationSettings? = nil) throws {
        guard let expected else {
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            return
        }
        try machine.validateAccountPreparation(account)
        guard let inventory = try machine.inventory(),
              expected.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)) else {
            throw SharedSetupImportError.wrongScope
        }
        guard expected.phase == .gatewayPrepared || expected.phase == .relayPrepared else {
            throw SharedSetupImportError.invalidTransition
        }
        try machine.withSharedImportJournal { journal in
            guard let journal, try journal.current(scope: expected.scope) == expected else {
                throw SharedSetupImportError.staleRevision
            }
            let recipe = expected.recipe, settings = try recipe.settings
            guard let project = recipe.firebaseProject, let push = recipe.pushClient,
                  let selection = settings.defaults.gateway else { throw GatewayPreparationError.incomplete }
            if let activationSettings, activationSettings != selection.activation {
                throw GatewayPreparationError.conflictingMaterial
            }
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let foregroundState = try machine.runtimeActivation(accountID: account.accountID)
            let material = try machine.gatewayPreparation(accountID: account.accountID)
            let journalState = try machine.gatewayJournalPreparation(accountID: account.accountID)
            guard runtime.configurationPublished, let runtimeReference = runtime.reference,
                  foregroundState.jobsRegistered, let foreground = foregroundState.plan,
                  foreground.reference == runtimeReference, let reference = material.reference,
                  reference.runtime == runtimeReference, let intent = journalState.intent, intent.material == reference,
                  reference.phonePush.projectID == project, reference.phonePush.senderID == push.senderID,
                  reference.phonePush.packageName == push.packageName else { throw GatewayPreparationError.changedScope }
            try intent.validate(foreground: foreground, inventory: inventory)
            let selected = try GatewayConfigurationBundle(foreground: foreground, material: reference, inventory: inventory,
                settings: selection.service, wakeMaximumConnections: selection.maximumWakeConnections,
                wakeMaximumOperations: selection.maximumWakeOperations,
                wakeChallengeLifetimeMilliseconds: selection.wakeChallengeLifetimeMilliseconds)
            guard selected.gateway.canonicalBytes == intent.configuration.canonicalBytes else {
                throw GatewayPreparationError.changedScope
            }
            guard try journal.current(scope: expected.scope) == expected else { throw SharedSetupImportError.staleRevision }
        }
    }
}
