import CryptoKit
import Foundation

/// Public ingress evidence only. Access, private-network routes, service readiness and resource ownership require separate checks.
struct CloudflareTunnelConfigurationObservation: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let accountID: String
    let tunnelID: String
    let providerVersion: UInt64
    let planDigest: Data
    func validate(tunnel: CloudflareTunnelObservation, plan: SharedSetupImportRelayPlan) throws {
        guard accountID == tunnel.accountID, tunnelID == tunnel.tunnelID,
              planDigest == Data(SHA256.hash(data: plan.bytes)) else { throw CloudflareProvisioningError.wrongScope }
    }
    var description: String { "CloudflareTunnelConfigurationObservation(redacted)" }
    var debugDescription: String { description }
}

/// Only the planned loopback approval endpoint and a rejecting catch-all are accepted.
struct CloudflareTunnelConfigurationClient: Sendable {
    typealias Send = CloudflareProvisioningScopeClient.Send
    private let send: Send
    init(send: @escaping Send) { self.send = send }
    static func native(timeoutSeconds: TimeInterval = 30) throws -> Self {
        let transport = try FCMHTTPTransport(timeoutSeconds: timeoutSeconds)
        return .init(send: { try await transport.send($0) })
    }
    func inspect(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                 plan: SharedSetupImportRelayPlan, tunnel: CloudflareTunnelObservation) async throws -> CloudflareTunnelConfigurationObservation {
        try Task.checkCancellation()
        let request = try configuration.tunnelConfigurationRequest(expected: expected, plan: plan, tunnel: tunnel)
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
        let envelope: Envelope
        do { envelope = try JSONDecoder().decode(Envelope.self, from: reply.body) }
        catch let known as CloudflareProvisioningError { throw known }
        catch { throw CloudflareProvisioningError.invalidResponse }
        guard envelope.success, envelope.errors.isEmpty else { throw CloudflareProvisioningError.providerRejected }
        let result = envelope.result
        guard result.account_id == configuration.accountID, result.tunnel_id == tunnel.tunnelID,
              result.source == "cloudflare" else { throw CloudflareProvisioningError.wrongScope }
        try result.config.validate(plan: plan)
        try Task.checkCancellation()
        return .init(accountID: result.account_id, tunnelID: result.tunnel_id, providerVersion: result.version,
            planDigest: Data(SHA256.hash(data: plan.bytes)))
    }
    /// This payload exposes only the planned approval endpoint. It contains no provider credential.
    static func plannedConfiguration(_ plan: SharedSetupImportRelayPlan) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["config": ["ingress": [
            ["hostname": plan.hostname, "path": "^/$", "service": "http://127.0.0.1:" + String(plan.port)],
            ["service": "http_status:404"]]]], options: [.sortedKeys])
    }
    private struct Envelope: Decodable {
        let success: Bool
        let errors: [IgnoredProviderError]
        let result: Configuration
    }
    private struct IgnoredProviderError: Decodable {}
    private struct Configuration: Decodable {
        let account_id: String
        let tunnel_id: String
        let source: String
        let version: UInt64
        let config: Ingress
    }
    private struct Key: CodingKey {
        let stringValue: String
        let intValue: Int? = nil
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
        init(_ string: String) { stringValue = string }
    }
    private struct Empty: Decodable {
        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: Key.self)
            guard fields.allKeys.isEmpty else { throw CloudflareProvisioningError.wrongScope }
        }
    }
    private struct Warp: Decodable {
        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: Key.self)
            guard Set(fields.allKeys.map(\.stringValue)) == ["enabled"],
                  try !fields.decode(Bool.self, forKey: Key("enabled")) else { throw CloudflareProvisioningError.wrongScope }
        }
    }
    private struct Ingress: Decodable {
        let rules: [Rule]
        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: Key.self)
            guard Set(fields.allKeys.map(\.stringValue)).isSubset(of: ["ingress", "originRequest", "warp-routing"]) else {
                throw CloudflareProvisioningError.wrongScope
            }
            rules = try fields.decode([Rule].self, forKey: Key("ingress"))
            if fields.contains(Key("originRequest")) { _ = try fields.decode(Empty.self, forKey: Key("originRequest")) }
            if fields.contains(Key("warp-routing")) { _ = try fields.decode(Warp.self, forKey: Key("warp-routing")) }
        }
        func validate(plan: SharedSetupImportRelayPlan) throws {
            guard rules.count == 2,
                  rules[0].hostname == plan.hostname, rules[0].path == "^/$",
                  rules[0].service == "http://127.0.0.1:" + String(plan.port),
                  rules[1].hostname == nil, rules[1].path == nil, rules[1].service == "http_status:404" else {
                throw CloudflareProvisioningError.wrongScope
            }
        }
    }
    private struct Rule: Decodable {
        let hostname: String?
        let path: String?
        let service: String
        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: Key.self)
            guard Set(fields.allKeys.map(\.stringValue)).isSubset(of: ["hostname", "path", "service", "originRequest"]) else {
                throw CloudflareProvisioningError.wrongScope
            }
            hostname = try fields.decodeIfPresent(String.self, forKey: Key("hostname"))
            path = try fields.decodeIfPresent(String.self, forKey: Key("path"))
            service = try fields.decode(String.self, forKey: Key("service"))
            if fields.contains(Key("originRequest")) { _ = try fields.decode(Empty.self, forKey: Key("originRequest")) }
        }
    }
}
