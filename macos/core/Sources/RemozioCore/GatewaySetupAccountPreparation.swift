import Darwin
import Foundation

struct GatewaySetupPreparationChoices: Sendable {
    let provider: SetupFCMConfiguration
    let senderID: String
    let packageName: String
    let settings: GatewayServiceSettings
    let fileWakeCustodyAccepted: Bool
}

/// Native preparation for the current foreground account. The setup endpoint must validate administrator rights before use.
/// No service, provider request or normal runtime configuration is activated here.
enum GatewaySetupAccountPreparation {
    static func prepare(machine: PreparationIntentStore, account: AccountPreparationIntent, choices: GatewaySetupPreparationChoices,
                        verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        let state = try machine.gatewayPreparation(accountID: account.accountID)
        let prepared = try GatewayMaterialPreparationController.prepare(machine: machine, account: account, expected: state,
            provider: choices.provider, senderID: choices.senderID, packageName: choices.packageName,
            fileWakeCustodyAccepted: choices.fileWakeCustodyAccepted, verifyCurrent: verifyCurrent)
        guard let material = prepared.reference, let foreground = try machine.runtimeActivation(accountID: account.accountID).plan,
              let inventory = try machine.inventory() else { throw GatewayPreparationError.incomplete }
        let proposal = try GatewayConfigurationBundle(foreground: foreground, material: material, inventory: inventory, settings: choices.settings)
        try verifyCurrent()
        _ = try GatewayJournalSetupPreparation.prepare(machine: machine, account: account, material: material,
            configuration: proposal.gateway, expected: machine.gatewayJournalPreparation(accountID: account.accountID), verifyCurrent: verifyCurrent)
        try verifyCurrent()
    }
}
