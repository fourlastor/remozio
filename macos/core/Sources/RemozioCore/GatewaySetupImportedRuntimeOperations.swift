import Foundation

/// Component progress only. The import remains pending until every selected Root section is verified.
struct SetupImportedGatewayRuntimeResult: Sendable {
    let progress: SetupPortableImportProgress
    let cleanupComplete: Bool
    let activation: SetupGatewayActivationProgress?
}

/// Only protected local host inputs select the machine directory and Mac identity.
struct GatewaySetupImportedRuntimeOperations: Sendable {
    let initialize: @Sendable (UInt32, Data, SharedSetupImportIntent,
                               @escaping @Sendable (InstallationInventory) throws -> Void) async throws -> GatewaySetupJournalReport
    let activate: @Sendable (UInt32, SetupGatewayActivationProgress, GatewayRuntimeActivationSettings, SharedSetupImportIntent,
                             @escaping @Sendable (InstallationInventory) throws -> Void) async throws -> GatewaySetupActivationReport
    static func native(machineDirectory: String, macID: Data) -> Self {
        .init(initialize: { uid, digest, expected, verify in
            let result = try await GatewayJournalSetupRootOperation.resumeNative(machineDirectory: machineDirectory, macID: macID,
                ownerUID: uid, expectedIntentDigest: digest, expectedImport: expected, verifyHost: verify)
            guard result.state.initialized, let intent = result.state.intent, try intent.digest == digest else {
                throw GatewayPreparationError.changedScope
            }
            return .init(intentDigest: digest, cleanupComplete: result.cleanupComplete)
        }, activate: { uid, progress, settings, expected, verify in
            let result = try GatewayRuntimeActivationRootOperation.resumeNative(machineDirectory: machineDirectory, macID: macID,
                ownerUID: uid, expected: progress, settings: settings, expectedImport: expected, verifyHost: verify)
            guard result.jobRegistered, let digest = result.planDigest else { throw GatewayPreparationError.incomplete }
            return .init(planDigest: digest)
        })
    }
}
