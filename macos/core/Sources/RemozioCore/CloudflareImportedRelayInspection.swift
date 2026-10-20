import Foundation

/// Ephemeral public ingress inventory. Resource ownership, private routes and Access need separate validation.
struct CloudflareImportedRelayInspection: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let scope: CloudflareProvisioningScope
    let tunnel: CloudflareTunnelObservation?
    let configuration: CloudflareTunnelConfigurationObservation?
    init(scope: CloudflareProvisioningScope, tunnel: CloudflareTunnelObservation?, configuration: CloudflareTunnelConfigurationObservation? = nil) {
        self.scope = scope; self.tunnel = tunnel; self.configuration = configuration
    }
    var description: String { "CloudflareImportedRelayInspection(redacted)" }
    var debugDescription: String { description }
    func validate(configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan) throws {
        try Self.validateSelection(configuration, expected: expected, plan: plan); try scope.validate(configuration)
        guard (tunnel == nil) == (self.configuration == nil) else { throw CloudflareProvisioningError.wrongScope }
        if let tunnel {
            guard tunnel.accountID == configuration.accountID, tunnel.name == plan.tunnelName,
                  tunnel.tunnelID.utf8.count == 36, let uuid = UUID(uuidString: tunnel.tunnelID),
                  uuid.uuidString.lowercased() == tunnel.tunnelID else { throw CloudflareProvisioningError.wrongScope }
            try self.configuration?.validate(tunnel: tunnel, plan: plan)
        }
    }
    private static func validateSelection(_ configuration: SetupCloudflareConfiguration,
                                          expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan) throws {
        try plan.validate(expected: expected)
        guard let selected = expected.recipe.cloudflare, selected.accountID == configuration.accountID,
              selected.zoneID == configuration.zoneID, selected.dnsSuffix == configuration.dnsSuffix else {
            throw CloudflareProvisioningError.wrongScope
        }
    }
    static func native(configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                       plan: SharedSetupImportRelayPlan) async throws -> Self {
        let transport = try FCMHTTPTransport(timeoutSeconds: 30)
        return try await inspect(configuration: configuration, expected: expected, plan: plan, send: { try await transport.send($0) })
    }
    /// One scoped read sequence. Absence needs a complete inventory; presence also needs exact ingress readback.
    static func inspect(configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                        plan: SharedSetupImportRelayPlan, send: @escaping CloudflareProvisioningScopeClient.Send) async throws -> Self {
        try Task.checkCancellation(); try validateSelection(configuration, expected: expected, plan: plan)
        let scope = try await CloudflareProvisioningScopeClient(send: send).inspect(configuration)
        try Task.checkCancellation()
        let tunnel = try await CloudflareTunnelInspectionClient(send: send).inspect(configuration, expected: expected, plan: plan)
        try Task.checkCancellation()
        let configurationResult: CloudflareTunnelConfigurationObservation?
        if let tunnel {
            configurationResult = try await CloudflareTunnelConfigurationClient(send: send).inspect(configuration,
                expected: expected, plan: plan, tunnel: tunnel)
        } else { configurationResult = nil }
        let result = Self(scope: scope, tunnel: tunnel, configuration: configurationResult)
        try result.validate(configuration: configuration, expected: expected, plan: plan)
        try Task.checkCancellation(); return result
    }
}
