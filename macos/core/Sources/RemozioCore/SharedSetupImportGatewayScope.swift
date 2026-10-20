import Foundation

/// The setup owner holds the release barrier and machine lease. Journal acquisition follows the machine lease.
enum SharedSetupImportGatewayScope {
    static func requireLegacyMutationAllowed(machine: PreparationIntentStore, account: AccountPreparationIntent) throws {
        try machine.validateAccountPreparation(account)
        guard let inventory = try machine.inventory() else { throw SharedSetupImportError.wrongScope }
        let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
        try machine.withSharedImportJournal { journal in
            if let retained = try journal?.current(scope: scope), retained.phase != .rootComplete {
                throw SharedSetupImportError.conflict
            }
        }
    }

    static func completedDefaults(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> GatewayRuntimeSettingsSelection? {
        try machine.validateAccountPreparation(account)
        guard let inventory = try machine.inventory() else { throw SharedSetupImportError.wrongScope }
        let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
        return try machine.withSharedImportJournal { journal in
            guard let retained = try journal?.current(scope: scope) else { return nil }
            guard retained.phase == .rootComplete else { throw SharedSetupImportError.conflict }
            guard retained.recipe.firebaseProject == nil, retained.recipe.pushClient == nil else { return nil }
            return try retained.recipe.settings.defaults.gateway
        }
    }

    /// Credentials exist only in memory here. The operation must perform final custody and verify its native outputs separately.
    /// This boundary advances no marker and makes no provider, registration or completion claim.
    static func withReviewedPreparation<Value>(machine: PreparationIntentStore, account: AccountPreparationIntent,
                                               journal: SharedSetupImportJournal, expected: SharedSetupImportIntent,
                                               proposal: PortableSetup, fileWakeCustodyAccepted: Bool,
                                               verifyCurrent: () throws -> Void,
                                               operation: (GatewaySetupPreparationChoices?, () throws -> Void) throws -> Value) throws -> Value {
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        guard let inventory = try machine.inventory(),
              expected.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)),
              try journal.current(scope: expected.scope) == expected else { throw SharedSetupImportError.staleRevision }
        guard expected.phase == .runtimePublished else { throw SharedSetupImportError.invalidTransition }
        guard try expected.matches(proposal) else { throw SharedSetupImportError.conflict }
        let runtime = try machine.runtimePreparation(accountID: account.accountID)
        let activation = try machine.runtimeActivation(accountID: account.accountID)
        guard runtime.configurationPublished, let material = runtime.reference, activation.jobsRegistered,
              let foreground = activation.plan, foreground.reference == material,
              try foreground.enrolledInventory(inventory) == inventory else { throw GatewayPreparationError.incomplete }
        let choices: GatewaySetupPreparationChoices?
        if proposal.fcm == nil && proposal.pushClient == nil { choices = nil }
        else {
            guard fileWakeCustodyAccepted else { throw GatewayPreparationError.custodyNotAccepted }
            choices = try proposal.gatewayPreparationChoices(fileWakeCustodyAccepted: true)
        }
        return try withoutActuallyEscaping(verifyCurrent) { current in
            let foregroundBytes = try foreground.encoded
            func verify() throws {
                try current(); try machine.validateAccountPreparation(account)
                let current = try machine.runtimeActivation(accountID: account.accountID)
                guard try machine.inventory() == inventory,
                      try machine.runtimePreparation(accountID: account.accountID) == runtime,
                      current.jobsRegistered, try current.plan?.encoded == foregroundBytes,
                      try journal.current(scope: expected.scope) == expected else { throw SharedSetupImportError.staleRevision }
            }
            try verify(); let result = try operation(choices, verify); try verify(); return result
        }
    }
}
