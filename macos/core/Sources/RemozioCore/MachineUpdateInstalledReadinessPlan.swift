import Foundation
import RemozioProtocol

/// Selects readiness operands from a finishing loan. The values can outlive the loan.
/// Recheck them under a fresh loan before using them.
struct MachineUpdateInstalledReadinessPlan: Sendable {
    struct Account: Sendable {
        let preparation: AccountPreparationIntent
        let initialization: AuthorityInitializationIntent
        let configuration: RuntimeReleaseConfigurationPlan
        let backend: RuntimeReleaseBackendPlan?
        var accountID: Data { preparation.accountID }
    }

    let view: MachineUpdateInstalledRuntimeView
    let accounts: [Account]
    let inventory: MachineUpdateHealthInventory
    let focusedAccountID: Data?
    let unselectedRegisteredAccounts: [Data]

    init(scope: PreparationIntentStore.CompletionFinalizationScope, candidate: SignedReleaseEvidence,
        focusedAccountID: Data? = nil) throws {
        let view = try MachineUpdateInstalledRuntimeView(compatibility: scope.readCompatibility(), candidate: candidate)
        let archive = view.compatibility.source.actual.installed
        let configurationEpoch = try archive.configuration().record
        let backendEpoch = try archive.backend().record
        var accounts: [Account] = []
        var requirements: [MachineUpdateHealthInventory.Requirement] = []
        var preserved: [Data] = []
        var unselected: [Data] = []
        for account in view.accounts {
            let gatewayRegistered = account.gateway?.jobRegistered == true
            guard account.provisioning?.jobsRegistered == true || gatewayRegistered else {
                preserved.append(account.accountID)
                continue
            }
            guard account.scope.inInventory else { throw RuntimePreparationError.changedScope }
            if let focusedAccountID, account.accountID != focusedAccountID {
                unselected.append(account.accountID)
                continue
            }
            guard let runtime = account.provisioning, runtime.jobsRegistered, runtime.configurationPublished,
                  let preparation = account.preparation, preparation.storagePrepared,
                  let initialization = account.initialization, initialization.complete,
                  let configuration = account.configuration,
                  let transportHost = configuration.transport.settingsHost else {
                throw RuntimePreparationError.changedScope
            }
            // Every registered account must prove readiness before settlement can reopen machine admission.
            // Mixed readiness prevents the settlement owner from opening. The update stays in finishing with admission closed.
            guard configuration.host.installedReadinessEnabled else {
                throw MachineUpdateHealthCoordinatorError.installedReadinessDisabled
            }
            _ = try configuration.host.validate(inventory: view.installedInventory, release: candidate,
                bundlePath: view.installedInventory.bundlePath)
            try MachineUpdateConsumerHealthReleaseValidation.validate(candidate, host: transportHost, purpose: .installedReadiness)

            let services = runtime.reference.services
            func add(_ role: AuthorityCodeRole, uid: UInt32, publicKey: Data) throws {
                guard let code = configuration.host.codePolicy.entries.first(where: { $0.role == role && $0.active }) else {
                    throw RuntimePreparationError.changedScope
                }
                requirements.append(.init(binding: configuration.binding,
                    configurationEpoch: configurationEpoch.id, configurationRevision: configurationEpoch.revision,
                    backendEpoch: backendEpoch.id, backendRevision: backendEpoch.revision,
                    role: role, executionUID: uid, code: code, publicKey: publicKey))
            }

            try add(.authority, uid: 0, publicKey: services.authorityPublicKey)
            try add(.transport, uid: transportHost.serviceUID, publicKey: runtime.reference.transportPublicKeyX963)
            if gatewayRegistered {
                let gatewayHost = configuration.gateway
                guard account.gateway?.configurationPublished == true, let backend = account.backend,
                      backend.gateway.serviceUID == gatewayHost.serviceUID,
                      view.installedInventory.services.contains(where: {
                          $0.role == .notificationGateway && $0.kind == .daemon && $0.domainUID == nil &&
                          $0.accountID == account.accountID && $0.executionUID == gatewayHost.serviceUID
                      }) else { throw RuntimePreparationError.changedScope }
                try MachineUpdateConsumerHealthReleaseValidation.validate(candidate, host: gatewayHost, purpose: .installedReadiness)
                try add(.notificationGateway, uid: gatewayHost.serviceUID, publicKey: backend.gateway.receiptPublicKey)
            }
            accounts.append(.init(preparation: preparation, initialization: initialization,
                configuration: configuration, backend: account.backend))
        }
        let inventory = try MachineUpdateHealthInventory(requirements: requirements, preservedAccounts: preserved)
        try view.requireCurrent(scope: scope, candidate: candidate)
        self.view = view
        self.accounts = accounts
        self.inventory = inventory
        self.focusedAccountID = focusedAccountID
        unselectedRegisteredAccounts = unselected
    }

    func select(accountID: Data, role: AuthorityCodeRole) throws -> (Account, MachineUpdateHealthInventory.Requirement) {
        guard let account = accounts.first(where: { $0.accountID == accountID }),
              let requirement = inventory.requirements(accountID: accountID).first(where: { $0.role == role }) else {
            throw RuntimePreparationError.changedScope
        }
        return (account, requirement)
    }

    func selectAuthority(host: InstalledAuthorityCommandConfiguration) throws -> MachineUpdateHealthInventory.Requirement {
        let (account, requirement) = try select(accountID: host.command.accountID, role: .authority)
        guard account.configuration.host.canonicalBytes == host.canonicalBytes else {
            throw InstalledAuthorityCommandError.changedConfiguration
        }
        return requirement
    }

    func requireSame(as expected: Self) throws {
        try view.requireSame(as: expected.view)
        guard focusedAccountID == expected.focusedAccountID,
              unselectedRegisteredAccounts == expected.unselectedRegisteredAccounts,
              inventory.requirements == expected.inventory.requirements,
              inventory.preservedAccounts == expected.inventory.preservedAccounts else { throw PreparationStoreError.staleRevision }
    }

    func requireCurrent(scope: PreparationIntentStore.CompletionFinalizationScope, candidate: SignedReleaseEvidence) throws {
        try view.requireCurrent(scope: scope, candidate: candidate)
    }
}
