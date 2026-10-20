import CryptoKit
import Foundation

/// Scoped observations only. Provider state is not locked and this value grants no durable publication permission.
struct CloudflareRelayPublicationPreflight: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    enum HostnameAssessment: Equatable, Sendable { case noOtherMatchObserved, exactHostnamePrecedesBroaderWildcardRoots, requiresPrecedenceVerification }
    let ingress: CloudflareTunnelConfigurationObservation
    let privateRoutesBefore: CloudflarePrivateRouteObservation
    let privateRoutesAfter: CloudflarePrivateRouteObservation
    let access: CloudflareInitialAccessObservation
    let hostnameInventory: CloudflareAccessHostnameInventory
    let accessRecordDigest: Data
    var hostnameAssessment: HostnameAssessment {
        let matches = hostnameInventory.matches
        let own = matches.filter { $0.applicationID == access.identity.applicationID }
        guard hostnameInventory.unresolvedApplicationIDs.isEmpty, own.count == 1,
              let selected = own.first, selected.uri == access.identity.hostname,
              !selected.wildcardHostname, !selected.hasPublicOverrides else { return .requiresPrecedenceVerification }
        let others = matches.filter { $0.applicationID != access.identity.applicationID }
        if others.isEmpty { return .noOtherMatchObserved }
        guard others.allSatisfy({ match in
            let parts = match.uri.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
            return match.wildcardHostname && !match.hasPublicOverrides &&
                (parts.count == 1 || parts[1].isEmpty || parts[1] == "*")
        }) else { return .requiresPrecedenceVerification }
        return .exactHostnamePrecedesBroaderWildcardRoots
    }
    func validate(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                  application: SharedSetupAccessApplicationRecord) throws {
        try ingress.validate(tunnel: createdTunnel.createdTunnel(expected: expected, plan: plan), plan: plan)
        try privateRoutesBefore.validate(expected: expected, plan: plan, created: createdTunnel)
        try privateRoutesAfter.validate(expected: expected, plan: plan, created: createdTunnel)
        try access.validate(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application)
        try hostnameInventory.validate(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application)
        guard accessRecordDigest == Data(SHA256.hash(data: application.bytes)) else { throw CloudflareProvisioningError.wrongScope }
    }
    var description: String { "CloudflareRelayPublicationPreflight(redacted)" }
    var debugDescription: String { description }
}

/// Read-only composition. Root wildcard precedence follows the vendor contract; propagation remains unproven.
struct CloudflareRelayPublicationPreflightClient: Sendable {
    typealias Send = CloudflareProvisioningScopeClient.Send
    private let send: Send
    init(send: @escaping Send) { self.send = send }
    func inspect(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                 plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                 application: SharedSetupAccessApplicationRecord) async throws -> CloudflareRelayPublicationPreflight {
        try Task.checkCancellation()
        let tunnel = try createdTunnel.createdTunnel(expected: expected, plan: plan)
        _ = try application.createdApplication(expected: expected, plan: plan, createdTunnel: createdTunnel)
        let routes = CloudflarePrivateRouteClient(send: send)
        let before = try await routes.inspect(configuration, expected: expected, plan: plan, created: createdTunnel)
        let ingress = try await CloudflareTunnelConfigurationClient(send: send).inspect(configuration, expected: expected, plan: plan, tunnel: tunnel)
        let access = try await CloudflareAccessApplicationClient(send: send).inspectInitial(configuration, expected: expected,
            plan: plan, createdTunnel: createdTunnel, application: application)
        let inventory = try await CloudflareAccessHostnameClient(send: send).inspect(configuration, expected: expected,
            plan: plan, createdTunnel: createdTunnel, application: application)
        try await CloudflareDNSRecordClient(send: send).inspectAbsent(configuration, expected: expected, plan: plan,
            createdTunnel: createdTunnel, application: application)
        let after = try await routes.inspect(configuration, expected: expected, plan: plan, created: createdTunnel)
        let result = CloudflareRelayPublicationPreflight(ingress: ingress, privateRoutesBefore: before, privateRoutesAfter: after,
            access: access, hostnameInventory: inventory, accessRecordDigest: Data(SHA256.hash(data: application.bytes)))
        try result.validate(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application)
        try Task.checkCancellation(); return result
    }
}
