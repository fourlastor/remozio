import Foundation

/// Reads bounded filtered pages through the terminal empty page. Account-wide totals do not prove filtered completeness.
/// This client cannot create, adopt, configure, delete or fetch a tunnel token.
struct CloudflareTunnelInspectionClient: Sendable {
    static let pageSize = 100
    static let maximumPages = 10
    static let maximumRequests = maximumPages + 1
    static let maximumTotalBytes = 524_288
    typealias Send = CloudflareProvisioningScopeClient.Send
    private let send: Send
    init(send: @escaping Send) { self.send = send }
    static func native(timeoutSeconds: TimeInterval = 30) throws -> Self {
        let transport = try FCMHTTPTransport(timeoutSeconds: timeoutSeconds)
        return .init(send: { try await transport.send($0) })
    }
    func inspect(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                 plan: SharedSetupImportRelayPlan) async throws -> CloudflareTunnelObservation? {
        var page = 1, totalBytes = 0, selectedSize: Int?, seen = Set<String>()
        var match: CloudflareTunnelObservation?
        while page <= Self.maximumRequests {
            try Task.checkCancellation()
            let request = try configuration.tunnelInspectionRequest(expected: expected, plan: plan, page: page)
            let reply: FCMHTTPReply
            do { reply = try await send(request) }
            catch {
                if Task.isCancelled || error is CancellationError { throw CancellationError() }
                if case FCMError.responseTooLarge = error { throw CloudflareProvisioningError.responseTooLarge }
                throw CloudflareProvisioningError.unavailable
            }
            try Task.checkCancellation()
            guard reply.body.count <= FCMHTTPTransport.maximumResponseBytes,
                  reply.body.count <= Self.maximumTotalBytes - totalBytes else { throw CloudflareProvisioningError.responseTooLarge }
            totalBytes += reply.body.count
            switch reply.status {
            case 200: break
            case 401, 403: throw CloudflareProvisioningError.unauthorized
            case 429: throw CloudflareProvisioningError.rateLimited
            case 400..<500: throw CloudflareProvisioningError.providerRejected
            default: throw CloudflareProvisioningError.unavailable
            }
            let envelope: Envelope
            do { envelope = try JSONDecoder().decode(Envelope.self, from: reply.body) }
            catch { throw CloudflareProvisioningError.invalidResponse }
            guard envelope.success, envelope.errors.isEmpty else { throw CloudflareProvisioningError.providerRejected }
            let info = envelope.result_info
            guard info.page == page, (1...Self.pageSize).contains(info.per_page),
                  (info.total_count.map { $0 >= 0 } ?? true),
                  info.count == envelope.result.count, info.count <= info.per_page,
                  selectedSize == nil || selectedSize == info.per_page else { throw CloudflareProvisioningError.invalidResponse }
            selectedSize = info.per_page
            if envelope.result.isEmpty { try Task.checkCancellation(); return match }
            guard page <= Self.maximumPages else { throw CloudflareProvisioningError.invalidResponse }
            for tunnel in envelope.result {
                guard tunnel.account_tag == configuration.accountID else { throw CloudflareProvisioningError.wrongScope }
                guard tunnel.id.utf8.count == 36, let uuid = UUID(uuidString: tunnel.id),
                      seen.insert(uuid.uuidString.lowercased()).inserted else { throw CloudflareProvisioningError.invalidResponse }
                guard tunnel.name == plan.tunnelName else { continue }
                guard match == nil, tunnel.config_src == "cloudflare", tunnel.remote_config != false,
                      tunnel.tun_type == "cfd_tunnel", tunnel.deleted_at == nil else { throw CloudflareProvisioningError.wrongScope }
                match = .init(accountID: configuration.accountID, tunnelID: uuid.uuidString.lowercased(), name: tunnel.name)
            }
            page += 1
        }
        throw CloudflareProvisioningError.invalidResponse
    }
    private struct Envelope: Decodable {
        let success: Bool
        let errors: [IgnoredProviderError]
        let result: [Tunnel]
        let result_info: Page
    }
    private struct IgnoredProviderError: Decodable {}
    private struct Page: Decodable {
        let page: Int
        let per_page: Int
        let count: Int
        let total_count: Int?
    }
    private struct Tunnel: Decodable {
        let id: String
        let account_tag: String
        let name: String
        let config_src: String
        let remote_config: Bool?
        let tun_type: String
        let deleted_at: String?
    }
}
