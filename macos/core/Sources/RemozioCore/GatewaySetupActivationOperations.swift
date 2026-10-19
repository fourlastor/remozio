import Foundation

struct GatewaySetupActivationReport: Sendable { let planDigest: Data }

/// Fixed protected host inputs. A report never substitutes for a fresh read of the machine store.
struct GatewaySetupActivationOperations: Sendable {
    let resume: @Sendable (UInt32, SetupGatewayActivationProgress, GatewayRuntimeActivationSettings,
                          @escaping @Sendable (InstallationInventory) throws -> Void) async throws -> GatewaySetupActivationReport
    static func native(machineDirectory: String, macID: Data) -> Self {
        .init(resume: { uid, expected, settings, verify in
            let result = try GatewayRuntimeActivationRootOperation.resumeNative(machineDirectory: machineDirectory, macID: macID,
                ownerUID: uid, expected: expected, settings: settings, verifyHost: verify)
            guard result.jobRegistered, let digest = result.planDigest else { throw GatewayPreparationError.incomplete }
            return .init(planDigest: digest)
        })
    }
}
