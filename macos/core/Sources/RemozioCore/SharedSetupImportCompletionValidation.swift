import Darwin
import Foundation

/// Verifies retained outputs. It never repairs files, registers jobs, or advances an import marker.
enum SharedSetupImportCompletionValidation {
    enum Failure: Error, Equatable { case incomplete, changedOutputs, relayNotImplemented }
    struct Foreground {
        let account: AccountPreparationIntent
        let initialization: AuthorityInitializationIntent
        let plan: RuntimeActivationPlan
        let inventory: InstallationInventory
    }
    struct Gateway {
        let foreground: Foreground
        let choices: GatewaySetupPreparationChoices
        let selection: GatewayRuntimeSettingsSelection
        let journal: GatewayJournalPreparationState
        let plan: GatewayRuntimeActivationPlan
    }
    struct Operations {
        let foreground: (Foreground, () throws -> Void) throws -> Void
        let gateway: (PreparationIntentStore, Gateway, () throws -> Void) throws -> Void
        static var native: Self {
            .init(foreground: { value, verify in
                try RuntimeActivationFiles.validate(plan: value.plan, account: value.account,
                    initialization: value.initialization, inventory: value.inventory, verifyCurrent: verify)
            }, gateway: { machine, value, verify in
                let foreground = value.foreground
                try SharedSetupImportGatewayPreparedValidation.validateNative(machine: machine, account: foreground.account,
                    choices: value.choices, selection: value.selection, verifyCurrent: verify)
                _ = try GatewayRuntimeActivationFiles.prepare(plan: value.plan, account: foreground.account,
                    initialization: foreground.initialization, journal: value.journal, foreground: foreground.plan,
                    inventory: foreground.inventory, mode: .validateRetained, verifyCurrent: verify)
                guard let intent = value.journal.intent else { throw Failure.incomplete }
                let configuration = try GatewayJournalSetupServiceConfiguration(intent: intent,
                    bundlePath: foreground.inventory.bundlePath, codePolicy: foreground.plan.host.codePolicy)
                try verify()
                guard try GatewayJournalSetupJobRegistration.isAbsent(.init(configuration: configuration)) else { throw Failure.incomplete }
                try verify()
            })
        }
    }
    static func validate(machine: PreparationIntentStore, account: AccountPreparationIntent,
                         retained: SharedSetupImportIntent, proposal: PortableSetup,
                         operations: Operations = .native, verifyCurrent: () throws -> Void) throws {
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        guard retained.phase == .gatewayPrepared || retained.phase == .relayPrepared || retained.phase == .rootComplete else {
            throw Failure.incomplete
        }
        guard try retained.matches(proposal) else { throw SharedSetupImportError.conflict }
        // Relay verification must exist before a proposal that selects Cloudflare can complete.
        guard proposal.cloudflare == nil else { throw Failure.relayNotImplemented }
        guard let inventory = try machine.inventory(),
              retained.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)),
              let initialization = try machine.initialization(accountID: account.accountID), initialization.complete else {
            throw SharedSetupImportError.wrongScope
        }
        let services = try machine.serviceAccountPlan(accountID: account.accountID)
        let runtime = try machine.runtimePreparation(accountID: account.accountID)
        let activation = try machine.runtimeActivation(accountID: account.accountID)
        guard services.complete, runtime.configurationPublished, let reference = runtime.reference,
              reference.services == services.plan, activation.jobsRegistered, let plan = activation.plan,
              plan.reference == reference, try plan.enrolledInventory(inventory) == inventory else { throw Failure.incomplete }
        try plan.validate(account: account, reference: reference)
        let bundle = try RuntimeConfigurationBundle.initial(account: account, initialization: initialization,
            reference: reference, inventory: inventory, importIntent: retained)
        guard bundle.command.canonicalBytes == plan.host.command.canonicalBytes,
              bundle.transport.canonicalBytes == plan.transport.canonicalBytes else { throw Failure.changedOutputs }
        let material = try machine.gatewayPreparation(accountID: account.accountID)
        let journal = try machine.gatewayJournalPreparation(accountID: account.accountID)
        let gateway = try machine.gatewayRuntimeActivation(accountID: account.accountID)
        let settings = try machine.gatewaySettingsTransition(accountID: account.accountID)
        guard settings.active == nil, settings.pending == nil, settings.phase == nil else { throw Failure.changedOutputs }
        let planBytes = try plan.encoded, gatewayBytes = try gateway.plan?.encoded
        func verify() throws {
            try verifyCurrent(); try machine.validateAccountPreparation(account)
            let current = try machine.runtimeActivation(accountID: account.accountID)
            let currentGateway = try machine.gatewayRuntimeActivation(accountID: account.accountID)
            let settings = try machine.gatewaySettingsTransition(accountID: account.accountID)
            guard try machine.inventory() == inventory, try machine.initialization(accountID: account.accountID) == initialization,
                  try machine.serviceAccountPlan(accountID: account.accountID) == services,
                  try machine.runtimePreparation(accountID: account.accountID) == runtime,
                  current.jobsRegistered, try current.plan?.encoded == planBytes,
                  try machine.gatewayPreparation(accountID: account.accountID) == material,
                  try machine.gatewayJournalPreparation(accountID: account.accountID) == journal,
                  currentGateway.filesPublished == gateway.filesPublished, currentGateway.jobRegistered == gateway.jobRegistered,
                  try currentGateway.plan?.encoded == gatewayBytes,
                  settings.active == nil, settings.pending == nil, settings.phase == nil else { throw Failure.changedOutputs }
        }
        let foreground = Foreground(account: account, initialization: initialization, plan: plan, inventory: inventory)
        try verify(); try operations.foreground(foreground, verify); try verify()
        if proposal.fcm == nil && proposal.pushClient == nil {
            try SharedSetupImportGatewayPreparedValidation.validateAbsent(machine: machine, account: account, verifyCurrent: verify)
        } else {
            let choices = try proposal.gatewayPreparationChoices(fileWakeCustodyAccepted: false)
            guard let selection = proposal.defaults.gateway, journal.initialized,
                  let intent = journal.intent, intent.material == material.reference,
                  gateway.filesPublished, gateway.jobRegistered, let gatewayPlan = gateway.plan else { throw Failure.incomplete }
            let actual = try GatewayRuntimeSettingsSelection(activation: gatewayPlan, journal: journal, foreground: plan, inventory: inventory)
            guard try actual.bytes == selection.bytes,
                  try inventory.services.contains(gatewayPlan.gatewayJob.declaration) else { throw Failure.changedOutputs }
            try operations.gateway(machine, .init(foreground: foreground, choices: choices, selection: selection,
                journal: journal, plan: gatewayPlan), verify)
        }
        try verify()
    }
}
