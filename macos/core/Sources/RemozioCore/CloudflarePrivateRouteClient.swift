import CryptoKit
import Foundation

/// Point-in-time absence of private IP and hostname routes for the retained tunnel. Access needs separate validation.
struct CloudflarePrivateRouteObservation: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let accountID: String
    let tunnelID: String
    let planDigest: Data
    func validate(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, created: SharedSetupRelayProvisioningRecord) throws {
        let tunnel = try created.createdTunnel(expected: expected, plan: plan)
        guard accountID == tunnel.accountID, tunnelID == tunnel.tunnelID, planDigest == Data(SHA256.hash(data: plan.bytes)) else {
            throw CloudflareProvisioningError.wrongScope
        }
    }
    var description: String { "CloudflarePrivateRouteObservation(redacted)" }
    var debugDescription: String { description }
}

/// Each fixed, tunnel-filtered list must be empty. A nonempty list never authorizes automatic route deletion.
struct CloudflarePrivateRouteClient: Sendable {
    enum Kind: CaseIterable, Sendable { case ip, hostname }
    typealias Send = CloudflareProvisioningScopeClient.Send
    private let send: Send
    init(send: @escaping Send) { self.send = send }
    func inspect(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                 plan: SharedSetupImportRelayPlan, created: SharedSetupRelayProvisioningRecord) async throws -> CloudflarePrivateRouteObservation {
        let tunnel = try created.createdTunnel(expected: expected, plan: plan)
        for kind in Kind.allCases {
            try Task.checkCancellation()
            let request = try configuration.privateRouteInspectionRequest(expected: expected, plan: plan, created: created, kind: kind)
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
            guard envelope.result.isEmpty else { throw CloudflareProvisioningError.wrongScope }
            let page = envelope.result_info
            // The documented total counts are unfiltered. They cannot require other Macs to have no routes.
            guard page.page == 1, page.count == 0, (1...100).contains(page.per_page),
                  (page.total_count ?? 0) >= 0,
                  (page.total_pages ?? 0) >= 0 else { throw CloudflareProvisioningError.invalidResponse }
        }
        try Task.checkCancellation()
        return .init(accountID: tunnel.accountID, tunnelID: tunnel.tunnelID, planDigest: Data(SHA256.hash(data: plan.bytes)))
    }
    private struct Envelope: Decodable { let success: Bool; let errors: [Ignored]; let result: [Ignored]; let result_info: Page }
    private struct Ignored: Decodable {}
    private struct Page: Decodable {
        let page: Int
        let count: Int
        let per_page: Int
        let total_count: Int?
        let total_pages: Int?
    }
}
