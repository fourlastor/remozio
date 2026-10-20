import Foundation

/// Reads every bounded result page. This client cannot create, adopt, configure, delete or fetch a tunnel token.
struct CloudflareTunnelInspectionClient: Sendable {
    static let pageSize = 100
    static let maximumPages = 10
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
        var page = 1, totalBytes = 0, expectedTotal: Int?, selectedSize: Int?, seen = Set<String>()
        var match: CloudflareTunnelObservation?
        while page <= Self.maximumPages {
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
                  (0...Self.pageSize * Self.maximumPages).contains(info.total_count),
                  info.count == envelope.result.count, info.count <= info.per_page,
                  expectedTotal == nil || expectedTotal == info.total_count,
                  selectedSize == nil || selectedSize == info.per_page else { throw CloudflareProvisioningError.invalidResponse }
            let pages = max(1, (info.total_count + info.per_page - 1) / info.per_page)
            guard pages <= Self.maximumPages, page <= pages,
                  info.total_pages == nil || info.total_pages == pages || (info.total_count == 0 && info.total_pages == 0),
                  info.count == min(info.per_page, info.total_count - (page - 1) * info.per_page) else {
                throw CloudflareProvisioningError.invalidResponse
            }
            expectedTotal = info.total_count; selectedSize = info.per_page
            for tunnel in envelope.result {
                guard tunnel.account_tag == configuration.accountID else { throw CloudflareProvisioningError.wrongScope }
                guard tunnel.id.utf8.count == 36, let uuid = UUID(uuidString: tunnel.id),
                      seen.insert(uuid.uuidString.lowercased()).inserted else { throw CloudflareProvisioningError.invalidResponse }
                guard tunnel.name == plan.tunnelName else { continue }
                guard match == nil, tunnel.config_src == "cloudflare", tunnel.remote_config != false,
                      tunnel.tun_type == "cfd_tunnel", tunnel.deleted_at == nil else { throw CloudflareProvisioningError.wrongScope }
                match = .init(accountID: configuration.accountID, tunnelID: uuid.uuidString.lowercased(), name: tunnel.name)
            }
            if page == pages {
                guard seen.count == info.total_count else { throw CloudflareProvisioningError.invalidResponse }
                try Task.checkCancellation(); return match
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
        let total_count: Int
        let total_pages: Int?
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
