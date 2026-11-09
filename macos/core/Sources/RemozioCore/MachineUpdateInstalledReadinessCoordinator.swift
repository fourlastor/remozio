import Foundation

/// Lends the verified installed cohort for settlement. The caller closes the owners after resolving the commit.
struct MachineUpdateInstalledReadinessCoordinator: Sendable {
    private let health: MachineUpdateRestartHealthCoordinator

    init(plan: MachineUpdateInstalledReadinessPlan, candidate: SignedReleaseEvidence,
        terminal: MachineUpdateInstalledTerminalReadBridge, activity: any OwnedReleaseActivity,
        makeAccount: @escaping @Sendable (Data, [MachineUpdateHealthInventory.Requirement]) async throws -> any OwnedMachineUpdateInstalledReadinessAccount) throws {
        health = try MachineUpdateRestartHealthCoordinator(plan: plan, candidate: candidate, terminal: terminal,
            activity: activity, makeAccount: makeAccount)
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
