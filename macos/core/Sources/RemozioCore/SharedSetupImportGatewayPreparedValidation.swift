import Darwin
import Foundation

/// Validates retained outputs only. The caller separately binds the reviewed import and fresh administrator authorization.
enum SharedSetupImportGatewayPreparedValidation {
    static func validateNative(machine: PreparationIntentStore, account: AccountPreparationIntent,
                               choices: GatewaySetupPreparationChoices, selection: GatewayRuntimeSettingsSelection,
                               verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.privateDirectory.dropFirst()),
            owner: 0, createIfMissing: false)
        defer { directory.close() }
        try validate(machine: machine, account: account, choices: choices, selection: selection, verifyCurrent: verifyCurrent,
            readMaterial: {
                try directory.validate()
                return try GatewayPreparationMaterial.decode(ProtectedServiceConfiguration.read(anchor: directory.path,
                    relativePath: AdministrativeSetupPublication.File.gatewayMaterial.name, owner: 0))
            }, validatePrivate: { reference, verify in
                _ = try GatewayPrivateArtifactPublication.publish(account: account, expected: reference,
                    mode: .validateRetained, verifyCurrent: verify)
            }, validateJournal: { intent, verify in
                _ = try GatewayJournalFileProvisioning.prepare(account: account, services: intent.material.runtime.services,
                    mode: .requireExisting, expected: intent.files, verifyCurrent: verify)
            })
    }

    // Ordinary-owner fixtures use the same public-reference, credential and selection checks. Native ownership remains separate.
    static func validate(machine: PreparationIntentStore, account: AccountPreparationIntent,
                         choices: GatewaySetupPreparationChoices, selection: GatewayRuntimeSettingsSelection,
                         verifyCurrent: () throws -> Void, readMaterial: () throws -> GatewayPreparationMaterial,
                         validatePrivate: (GatewayMaterialReference, () throws -> Void) throws -> Void,
                         validateJournal: (GatewayJournalSetupIntent, () throws -> Void) throws -> Void) throws {
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        let runtime = try machine.runtimePreparation(accountID: account.accountID)
        let activation = try machine.runtimeActivation(accountID: account.accountID)
        let material = try machine.gatewayPreparation(accountID: account.accountID)
        let journal = try machine.gatewayJournalPreparation(accountID: account.accountID)
        guard let inventory = try machine.inventory(), runtime.configurationPublished, let runtimeReference = runtime.reference,
              activation.jobsRegistered, let foreground = activation.plan, foreground.reference == runtimeReference,
              let reference = material.reference, reference.runtime == runtimeReference,
              let intent = journal.intent, intent.material == reference,
              try choices.settings.setupBytes == selection.service.setupBytes else { throw GatewayPreparationError.incomplete }
        try intent.validate(foreground: foreground, inventory: inventory)
        let proposal = try GatewayConfigurationBundle(foreground: foreground, material: reference, inventory: inventory,
            settings: selection.service, wakeMaximumConnections: selection.maximumWakeConnections,
            wakeMaximumOperations: selection.maximumWakeOperations,
            wakeChallengeLifetimeMilliseconds: selection.wakeChallengeLifetimeMilliseconds)
        guard intent.configuration.canonicalBytes == proposal.gateway.canonicalBytes else { throw GatewayPreparationError.changedScope }
        try withoutActuallyEscaping(verifyCurrent) { current in
            let foregroundBytes = try foreground.encoded, provider = try choices.provider.gatewayCredentialJSON()
            func verify() throws {
                try current(); try machine.validateAccountPreparation(account)
                let current = try machine.runtimeActivation(accountID: account.accountID)
                guard try machine.inventory() == inventory,
                      try machine.runtimePreparation(accountID: account.accountID) == runtime,
                      try machine.gatewayPreparation(accountID: account.accountID) == material,
                      try machine.gatewayJournalPreparation(accountID: account.accountID) == journal,
                      current.jobsRegistered, try current.plan?.encoded == foregroundBytes else { throw GatewayPreparationError.changedScope }
            }
            func verifyMaterial() throws {
                try verify(); let retained = try readMaterial()
                guard try retained.reference == reference, retained.providerJSON == provider,
                      retained.phonePush.projectID == choices.provider.project,
                      retained.phonePush.senderID == choices.senderID, retained.phonePush.packageName == choices.packageName else {
                    throw GatewayPreparationError.conflictingMaterial
                }
                try verify()
            }
            try verifyMaterial(); try validatePrivate(reference, verify)
            try verifyMaterial(); try validateJournal(intent, verify)
            try verifyMaterial()
        }
    }

    static func validateAbsent(machine: PreparationIntentStore, account: AccountPreparationIntent,
                               verifyCurrent: () throws -> Void) throws {
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        let material = try machine.gatewayPreparation(accountID: account.accountID)
        let journal = try machine.gatewayJournalPreparation(accountID: account.accountID)
        let activation = try machine.gatewayRuntimeActivation(accountID: account.accountID)
        let settings = try machine.gatewaySettingsTransition(accountID: account.accountID)
        guard material.reference == nil, journal.intent == nil, !journal.initialized,
              activation.plan == nil, !activation.filesPublished, !activation.jobRegistered,
              settings.active == nil, settings.pending == nil, settings.phase == nil else { throw GatewayPreparationError.conflictingMaterial }
        try verifyCurrent(); try machine.validateAccountPreparation(account)
    }
}
