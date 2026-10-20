import Foundation

/// Rechecks the exact resource recorded by creation. A matching name alone cannot select a resource.
struct CloudflareCreatedTunnelClient: Sendable {
    typealias Send = CloudflareProvisioningScopeClient.Send
    private let send: Send
    init(send: @escaping Send) { self.send = send }
    func inspect(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                 plan: SharedSetupImportRelayPlan, created: SharedSetupRelayProvisioningRecord) async throws -> CloudflareTunnelObservation {
        try Task.checkCancellation()
        let selected = try created.createdTunnel(expected: expected, plan: plan)
        let request = try configuration.createdTunnelRequest(expected: expected, plan: plan, created: created)
        let reply: FCMHTTPReply
        do { reply = try await send(request) }
        catch {
            if Task.isCancelled || error is CancellationError { throw CancellationError() }
            if case FCMError.responseTooLarge = error { throw CloudflareProvisioningError.responseTooLarge }
            throw CloudflareProvisioningError.unavailable
        }
        try Task.checkCancellation()
        guard reply.body.count <= FCMHTTPTransport.maximumResponseBytes else { throw CloudflareProvisioningError.responseTooLarge }
        switch reply.status {
        case 200: break
        case 401, 403: throw CloudflareProvisioningError.unauthorized
        case 429: throw CloudflareProvisioningError.rateLimited
        case 400..<500: throw CloudflareProvisioningError.providerRejected
        default: throw CloudflareProvisioningError.unavailable
        }
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: reply.body) else { throw CloudflareProvisioningError.invalidResponse }
        guard envelope.success, envelope.errors.isEmpty else { throw CloudflareProvisioningError.providerRejected }
        let tunnel = envelope.result
        guard tunnel.id.utf8.count == 36, let uuid = UUID(uuidString: tunnel.id), uuid.uuidString.lowercased() == selected.tunnelID,
              tunnel.account_tag == configuration.accountID, tunnel.name == selected.name,
              tunnel.config_src == "cloudflare", tunnel.remote_config != false,
              tunnel.tun_type == nil || tunnel.tun_type == "cfd_tunnel", tunnel.deleted_at == nil else {
            throw CloudflareProvisioningError.wrongScope
        }
        try Task.checkCancellation(); return selected
    }
    private struct Envelope: Decodable { let success: Bool; let errors: [IgnoredError]; let result: Tunnel }
    private struct IgnoredError: Decodable {}
    private struct Tunnel: Decodable {
        let id: String
        let account_tag: String
        let name: String
        let config_src: String
        let remote_config: Bool?
        let tun_type: String?
        let deleted_at: String?
    }
}
