import Foundation

struct GatewaySetupJournalReport: Sendable {
    let intentDigest: Data
    let cleanupComplete: Bool
}

/// The native factory fixes both storage location and Mac identity from protected host configuration.
/// This internal result is accepted only after a fresh read of the machine state.
struct GatewaySetupJournalOperations: Sendable {
    let resume: @Sendable (UInt32, Data, @escaping @Sendable (InstallationInventory) throws -> Void) async throws -> GatewaySetupJournalReport
    static func native(machineDirectory: String, macID: Data) -> Self {
        .init(resume: { uid, digest, verify in
            let result = try await GatewayJournalSetupRootOperation.resumeNative(machineDirectory: machineDirectory, macID: macID,
                ownerUID: uid, expectedIntentDigest: digest, verifyHost: verify)
            guard result.state.initialized, let intent = result.state.intent, try intent.digest == digest else {
                throw GatewayPreparationError.changedScope
            }
            return .init(intentDigest: digest, cleanupComplete: result.cleanupComplete)
        })
    }
}
