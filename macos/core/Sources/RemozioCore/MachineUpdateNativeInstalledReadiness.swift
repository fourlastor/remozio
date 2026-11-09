import Darwin
import Foundation

/// Selects the registered native peers from the verified installed plan.
enum MachineUpdateNativeInstalledReadiness {
    struct Account: Sendable {
        let host: InstalledAuthorityCommandConfiguration
        let authority: MachineUpdateHealthInventory.Requirement
        let transport: GatewaySettingsConsumerHostConfiguration
        let gateway: GatewaySettingsConsumerHostConfiguration?
        let registration: GatewayRegistrationIdentity?
    }

    static func select(accountID: Data, plan: MachineUpdateInstalledReadinessPlan) throws -> Account {
        let (account, authority) = try plan.select(accountID: accountID, role: .authority)
        guard let transport = account.configuration.transport.settingsHost else { throw RuntimePreparationError.changedScope }
        let registered = plan.inventory.requirements(accountID: accountID).contains { $0.role == .notificationGateway }
        if registered {
            guard let backend = account.backend, backend.gateway.registration == transport.runtime.gateway else {
                throw RuntimePreparationError.changedScope
            }
            return .init(host: account.configuration.host, authority: authority, transport: transport,
                gateway: account.configuration.gateway, registration: backend.gateway.registration)
        }
        return .init(host: account.configuration.host, authority: authority, transport: transport, gateway: nil, registration: nil)
    }

    /// During settlement, live peers read the actual transaction frame before switching to the acknowledged stable record.
    static func coordinator(plan: MachineUpdateInstalledReadinessPlan, candidate: SignedReleaseEvidence,
        terminal: MachineUpdateInstalledTerminalReadBridge,
        acquireActivity: @escaping @Sendable () throws -> any OwnedReleaseActivity) throws -> MachineUpdateInstalledReadinessCoordinator {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try terminal.requirePlan(plan, candidate: candidate)
        let acquireActivity = coordinatedActivity(terminal: terminal, acquireActivity: acquireActivity)
        let activity = try acquireActivity()
        let verify: @Sendable () throws -> Void = {
            try activity.validate()
            try terminal.requireCurrent()
            try activity.validate()
        }
        do {
            try verify()
            let accounts = try Dictionary(uniqueKeysWithValues: plan.inventory.accountIDs.map {
                ($0, try select(accountID: $0, plan: plan))
            })
            try verify()
            return try MachineUpdateInstalledReadinessCoordinator(plan: plan, candidate: candidate, terminal: terminal, activity: activity,
                makeAccount: { accountID, requirements in
                    try verify()
                    guard let account = accounts[accountID] else { throw RuntimePreparationError.changedScope }
                    let scope = try MachineUpdateAuthorityReadinessScope(host: account.host, requirement: account.authority,
                        release: candidate, verifySelection: verify, acquireActivity: acquireActivity)
                    return try MachineUpdateNativeInstalledReadinessAccount.native(scope: scope, requirements: requirements,
                        transport: account.transport, gateway: account.gateway, registration: account.registration, release: candidate)
                })
        } catch {
            activity.close()
            throw error
        }
    }

    static func coordinatedActivity(terminal: MachineUpdateInstalledTerminalReadBridge,
        acquireActivity: @escaping @Sendable () throws -> any OwnedReleaseActivity) -> @Sendable () throws -> any OwnedReleaseActivity {
        { try terminal.acquirePeerActivity(acquireActivity) }
    }
}
