import Foundation

/// Outcomes after dispatch. Unknown includes transport failure, ambiguous status and malformed or crossed success replies.
enum CloudflareTunnelCreationOutcome: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case created(CloudflareTunnelObservation), rejected(SharedSetupRelayProvisioningRecord.Refusal), unknown
    var description: String { "CloudflareTunnelCreationOutcome(redacted)" }
    var debugDescription: String { description }
}

/// One typed POST, no retry and no token retrieval. The setup owner must retain the dispatched record before calling this client.
struct CloudflareTunnelCreationClient: Sendable {
    typealias Send = CloudflareProvisioningScopeClient.Send
    private let send: Send
    init(send: @escaping Send) { self.send = send }
    static func native() throws -> Self {
        let transport = try FCMHTTPTransport(timeoutSeconds: 30)
        return .init(send: { try await transport.send($0) })
    }
    func create(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                dispatched: SharedSetupRelayProvisioningRecord) async throws -> CloudflareTunnelCreationOutcome {
        try Task.checkCancellation()
        let request = try configuration.tunnelCreationRequest(expected: expected, plan: plan, dispatched: dispatched)
        let reply: FCMHTTPReply
        do { reply = try await send(request) } catch { return .unknown }
        // Preserve a validated acknowledgement even if cancellation raced its receipt. The owner records it before reporting cancellation.
        guard reply.body.count <= FCMHTTPTransport.maximumResponseBytes else { return .unknown }
        switch reply.status {
        case 401, 403: return .rejected(.unauthorized)
        case 429: return .rejected(.rateLimited)
        case 408, 409, 425: return .unknown
        case 400..<500: return .rejected(.providerRejected)
        case 200: break
        default: return .unknown
        }
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: reply.body), envelope.success,
              envelope.errors.isEmpty, let tunnel = envelope.result,
              tunnel.account_tag == configuration.accountID, tunnel.name == plan.tunnelName,
              tunnel.config_src == "cloudflare", tunnel.remote_config != false,
              tunnel.tun_type == nil || tunnel.tun_type == "cfd_tunnel", tunnel.deleted_at == nil,
              tunnel.id.utf8.count == 36, let uuid = UUID(uuidString: tunnel.id) else { return .unknown }
        return .created(.init(accountID: configuration.accountID, tunnelID: uuid.uuidString.lowercased(), name: tunnel.name))
    }
    private struct Envelope: Decodable {
        let success: Bool
        let errors: [IgnoredError]
        let result: Tunnel?
    }
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
