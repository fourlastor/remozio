import Foundation

/// Checks the installed cohort and joins owner cleanup. The caller retains closed admission.
struct MachineUpdateInstalledReadinessCoordinator: Sendable {
    private let health: MachineUpdateRestartHealthCoordinator

    init(plan: MachineUpdateInstalledReadinessPlan, activity: any OwnedReleaseActivity,
        verifyCurrent: @escaping @Sendable () throws -> Void,
        makeAccount: @escaping @Sendable (Data, [MachineUpdateHealthInventory.Requirement]) async throws -> any OwnedMachineUpdateInstalledReadinessAccount) throws {
        guard plan.focusedAccountID == nil else { throw PreparationStoreError.invalidTransition }
        health = MachineUpdateRestartHealthCoordinator(inventory: plan.inventory, verifyCurrent: verifyCurrent,
            installedActivity: activity, makeAccount: { accountID, requirements in
                try await makeAccount(accountID, requirements)
            }, recoverOrdinary: { _ in throw MachineUpdateHealthCoordinatorError.installedGatewayRecoveryRequired })
    }

    func withVerifiedReadiness<Value: Sendable>(
        _ body: @Sendable (MachineUpdateVerifiedInstalledReadinessScope) throws -> Value
    ) async throws -> Value {
        // The settlement owner joins cleanup after resolving a possible durable commit.
        try await health.withVerifiedInstalledReadiness(joinCleanup: false, body)
    }

    func close() async throws {
        try await health.close()
    }
}
