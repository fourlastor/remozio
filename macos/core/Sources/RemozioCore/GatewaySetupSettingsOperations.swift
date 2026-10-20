import Foundation

struct GatewaySetupSettingsReport: Sendable { let revisionDigest: Data }

/// Only an authenticated setup owner can admit this operation. Completion requires a fresh protected read.
struct GatewaySetupSettingsOperations: Sendable {
    let resume: @Sendable (UInt32, SetupGatewayActivationProgress, GatewayRuntimeSettingsRevision,
                          @escaping @Sendable (InstallationInventory) throws -> Void) async throws -> GatewaySetupSettingsReport
    static func native(machineDirectory: String, macID: Data) -> Self {
        .init(resume: { uid, expected, revision, verify in
            _ = try await GatewaySettingsTransitionRootOperation.resumeNative(machineDirectory: machineDirectory,
                macID: macID, ownerUID: uid, expected: expected, revision: revision, verifyHost: verify)
            return try .init(revisionDigest: revision.digest)
        })
    }
}
