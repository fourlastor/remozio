import Darwin
import Foundation

/// Retained local outputs only. Validation neither repairs files nor proves provider connectivity.
enum SharedSetupImportRelayPreparedValidation {
    struct Selection: Equatable, Sendable {
        let context: RelayRunCredentialSetupContext
        let application: SharedSetupAccessApplicationRecord
        let dns: SharedSetupDNSRecord
        let planSnapshot: SharedSetupImportRelayStorage.Snapshot
        let tunnelSnapshot: SharedSetupRelayProvisioningStorage.Snapshot
        let accessSnapshot: SharedSetupAccessApplicationStorage.Snapshot
        let dnsSnapshot: SharedSetupDNSStorage.Snapshot
        let runSnapshot: SharedSetupRelayRunReferenceStorage.Snapshot
    }
    static func capture(machine: PreparationIntentStore, account: AccountPreparationIntent,
                        retained: SharedSetupImportIntent, verifyCurrent: () throws -> Void) throws -> Selection {
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        guard retained.recipe.cloudflare != nil, retained.phase != .retained,
              let inventory = try machine.inventory(),
              retained.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)) else {
            throw SharedSetupImportError.wrongScope
        }
        let runtime = try machine.runtimePreparation(accountID: account.accountID)
        guard runtime.configurationPublished, let reference = runtime.reference else { throw RuntimePreparationError.incomplete }
        return try machine.withSharedImportRelayDirectory { directory, owner in
            guard let plan = try SharedSetupImportRelayStorage.read(expected: retained, directory: directory, owner: owner),
                  let planSnapshot = try SharedSetupImportRelayStorage.snapshot(expected: retained, directory: directory, owner: owner),
                  let tunnel = try SharedSetupRelayProvisioningStorage.read(expected: retained, plan: plan, directory: directory, owner: owner),
                  let tunnelSnapshot = try SharedSetupRelayProvisioningStorage.snapshot(expected: retained, plan: plan, directory: directory, owner: owner),
                  let application = try SharedSetupAccessApplicationStorage.read(expected: retained, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner),
                  let accessSnapshot = try SharedSetupAccessApplicationStorage.snapshot(expected: retained, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner),
                  let dns = try SharedSetupDNSStorage.read(expected: retained, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner),
                  let dnsSnapshot = try SharedSetupDNSStorage.snapshot(expected: retained, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner),
                  let run = try SharedSetupRelayRunReferenceStorage.snapshot(expected: retained, plan: plan, created: tunnel,
                    directory: directory, owner: owner) else { throw RuntimePreparationError.incomplete }
            _ = try dns.createdRecord(expected: retained, plan: plan, createdTunnel: tunnel, application: application)
            _ = try RelayRunCredentialReference.decode(run.reference.encoded, expected: retained, plan: plan, created: tunnel,
                runtime: reference, account: account, inventory: inventory)
            try verifyCurrent()
            guard try machine.runtimePreparation(accountID: account.accountID) == runtime,
                  try machine.inventory() == inventory else { throw RuntimePreparationError.changedScope }
            return .init(context: .init(account: account, inventory: inventory, expected: retained, plan: plan,
                created: tunnel, runtime: reference, reference: run.reference), application: application, dns: dns,
                planSnapshot: planSnapshot, tunnelSnapshot: tunnelSnapshot, accessSnapshot: accessSnapshot,
                dnsSnapshot: dnsSnapshot, runSnapshot: run)
        }
    }
    static func validateNative(machine: PreparationIntentStore, account: AccountPreparationIntent,
                               retained: SharedSetupImportIntent, verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try validate(machine: machine, account: account, retained: retained, verifyCurrent: verifyCurrent) { context, verify in
            guard let reference = context.reference else { throw RuntimePreparationError.missingMaterial }
            _ = try RelayConnectorStartupPublication.publishNative(context: context, reference: reference,
                mode: .validateRetained, verifyCurrent: verify)
        }
    }
    // Owned fixture readers prove local selection and immutable validation, not native Root custody or service admission.
    static func validate(machine: PreparationIntentStore, account: AccountPreparationIntent, retained: SharedSetupImportIntent,
                         verifyCurrent: () throws -> Void,
                         validateFiles: (RelayRunCredentialSetupContext, () throws -> Void) throws -> Void) throws {
        try withoutActuallyEscaping(verifyCurrent) { current in
            let selected = try capture(machine: machine, account: account, retained: retained, verifyCurrent: current)
            func verify() throws {
                guard try capture(machine: machine, account: account, retained: retained, verifyCurrent: current) == selected else {
                    throw RuntimePreparationError.changedScope
                }
            }
            try verify(); try validateFiles(selected.context, verify); try verify()
        }
    }
}
