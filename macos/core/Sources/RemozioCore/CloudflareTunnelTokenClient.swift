import Foundation

/// One local tunnel credential. It is never part of a portable setup recipe.
struct CloudflareTunnelRunCredential: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    static let maximumTokenBytes = 8192
    let tunnel: CloudflareTunnelObservation
    private let fileBytes: Data
    var description: String { "CloudflareTunnelRunCredential(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    fileprivate init(token: String, tunnel: CloudflareTunnelObservation) throws {
        guard !token.isEmpty, token.utf8.count <= Self.maximumTokenBytes,
              let json = Data(base64Encoded: token), json.base64EncodedString() == token,
              let value = try? JSONDecoder().decode(Fields.self, from: json) else {
            throw CloudflareProvisioningError.invalidResponse
        }
        guard value.a == tunnel.accountID, value.t == tunnel.tunnelID,
              value.e == nil || value.e == "" else { throw CloudflareProvisioningError.wrongScope }
        guard let secret = Data(base64Encoded: value.s), !secret.isEmpty,
              secret.count <= 4096, secret.base64EncodedString() == value.s else {
            throw CloudflareProvisioningError.invalidResponse
        }
        // Re-encode only the validated fields. The consumer never reparses unvalidated provider fields.
        let normalized = try JSONSerialization.data(withJSONObject: ["a": tunnel.accountID, "t": tunnel.tunnelID,
            "s": secret.base64EncodedString()], options: [.sortedKeys, .withoutEscapingSlashes])
        let bytes = Data(normalized.base64EncodedString().utf8)
        guard bytes.count <= Self.maximumTokenBytes else { throw CloudflareProvisioningError.invalidResponse }
        self.tunnel = tunnel; self.fileBytes = bytes
    }

    func withFileBytes<Value>(_ body: (Data) throws -> Value) rethrows -> Value { try body(fileBytes) }
    static func restore(_ bytes: Data, tunnel: CloudflareTunnelObservation) throws -> Self {
        guard bytes.count <= maximumTokenBytes, let token = String(data: bytes, encoding: .utf8) else {
            throw CloudflareProvisioningError.invalidResponse
        }
        let value = try Self(token: token, tunnel: tunnel)
        guard value.fileBytes == bytes else { throw CloudflareProvisioningError.invalidResponse }
        return value
    }
    private struct Fields: Decodable { let a: String; let t: String; let s: String; let e: String? }
}

/// Reads the retained tunnel's run token. It cannot create, rotate or delete provider resources.
struct CloudflareTunnelTokenClient: Sendable {
    typealias Send = CloudflareProvisioningScopeClient.Send
    private let send: Send
    init(send: @escaping Send) { self.send = send }

    func read(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
              plan: SharedSetupImportRelayPlan, created: SharedSetupRelayProvisioningRecord) async throws -> CloudflareTunnelRunCredential {
        try Task.checkCancellation()
        let selected = try created.createdTunnel(expected: expected, plan: plan)
        let inspector = CloudflareCreatedTunnelClient(send: send)
        _ = try await inspector.inspect(configuration, expected: expected, plan: plan, created: created)
        let reply = try await CloudflareAccessApplicationClient(send: send).read(
            configuration.tunnelTokenRequest(expected: expected, plan: plan, created: created))
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: reply.body) else {
            throw CloudflareProvisioningError.invalidResponse
        }
        guard envelope.success, envelope.errors.isEmpty else { throw CloudflareProvisioningError.providerRejected }
        let credential = try CloudflareTunnelRunCredential(token: envelope.result, tunnel: selected)
        _ = try await inspector.inspect(configuration, expected: expected, plan: plan, created: created)
        try Task.checkCancellation()
        return credential
    }
    private struct Ignored: Decodable {}
    private struct Envelope: Decodable { let success: Bool; let errors: [Ignored]; let result: String }
}

extension SetupCloudflareConfiguration {
    func tunnelTokenRequest(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                            created: SharedSetupRelayProvisioningRecord) throws -> URLRequest {
        var request = try createdTunnelRequest(expected: expected, plan: plan, created: created)
        request.url = request.url!.appendingPathComponent("token")
        return request
    }
}
