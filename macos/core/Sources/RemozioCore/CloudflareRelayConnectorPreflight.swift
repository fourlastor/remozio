import Foundation

/// Fresh provider observations for a retained DNS record. They prove no edge propagation or approval delivery.
struct CloudflareRelayConnectorPreflight: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let prerequisites: CloudflareRelayPublicationPreflight
    let dns: CloudflareDNSRecordObservation
    func validate(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                  createdTunnel: SharedSetupRelayProvisioningRecord, application: SharedSetupAccessApplicationRecord,
                  record: SharedSetupDNSRecord) throws {
        try prerequisites.validate(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application)
        try dns.validate(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application, record: record)
        switch prerequisites.hostnameAssessment {
        case .noOtherMatchObserved, .exactHostnamePrecedesBroaderWildcardRoots: break
        case .requiresPrecedenceVerification: throw RelayProvisioningError.requiresReconciliation
        }
    }
    var description: String { "CloudflareRelayConnectorPreflight(redacted)" }
    var debugDescription: String { description }
}

/// Read-only checks precede local startup publication. Existing DNS is inspected, never created or adopted here.
struct CloudflareRelayConnectorPreflightClient: Sendable {
    private let send: CloudflareProvisioningScopeClient.Send
    init(send: @escaping CloudflareProvisioningScopeClient.Send) { self.send = send }
    func inspect(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                 plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                 application: SharedSetupAccessApplicationRecord, record: SharedSetupDNSRecord) async throws -> CloudflareRelayConnectorPreflight {
        try Task.checkCancellation()
        let tunnel = try createdTunnel.createdTunnel(expected: expected, plan: plan)
        _ = try record.createdRecord(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application)
        let routes = CloudflarePrivateRouteClient(send: send)
        let before = try await routes.inspect(configuration, expected: expected, plan: plan, created: createdTunnel)
        let ingress = try await CloudflareTunnelConfigurationClient(send: send).inspect(configuration, expected: expected, plan: plan, tunnel: tunnel)
        let access = try await CloudflareAccessApplicationClient(send: send).inspectInitial(configuration, expected: expected,
            plan: plan, createdTunnel: createdTunnel, application: application)
        let inventory = try await CloudflareAccessHostnameClient(send: send).inspect(configuration, expected: expected,
            plan: plan, createdTunnel: createdTunnel, application: application)
        let dns = try await CloudflareDNSRecordClient(send: send).inspect(configuration, expected: expected,
            plan: plan, createdTunnel: createdTunnel, application: application, record: record)
        let after = try await routes.inspect(configuration, expected: expected, plan: plan, created: createdTunnel)
        let result = CloudflareRelayConnectorPreflight(prerequisites: .init(ingress: ingress, privateRoutesBefore: before,
            privateRoutesAfter: after, access: access, hostnameInventory: inventory, accessRecordDigest: record.accessRecordDigest), dns: dns)
        try result.validate(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application, record: record)
        try Task.checkCancellation(); return result
    }
}
