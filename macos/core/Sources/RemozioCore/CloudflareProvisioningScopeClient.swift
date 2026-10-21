import Foundation

/// Provider scope readback only. It grants no provisioning permission and retains no credential.
struct CloudflareProvisioningScope: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let accountID: String
    let zoneID: String
    let zoneName: String
    let dnsSuffix: String
    func validate(_ configuration: SetupCloudflareConfiguration) throws {
        do { try SetupCloudflareConfiguration.validateScope(accountID: accountID, zoneID: zoneID, dnsSuffix: zoneName) }
        catch { throw CloudflareProvisioningError.invalidResponse }
        guard accountID == configuration.accountID, zoneID == configuration.zoneID, dnsSuffix == configuration.dnsSuffix,
              dnsSuffix == zoneName || dnsSuffix.hasSuffix("." + zoneName) else { throw CloudflareProvisioningError.wrongScope }
    }
    var description: String { "CloudflareProvisioningScope(redacted)" }
    var debugDescription: String { description }
}

enum CloudflareProvisioningError: Error, Equatable {
    case invalidResponse, responseTooLarge, unauthorized, rateLimited, providerRejected, unavailable, wrongScope
}

/// Fixed provider origin, bounded response, no redirects or retries. Each attempt owns its network session.
struct CloudflareProvisioningScopeClient: Sendable {
    typealias Send = @Sendable (URLRequest) async throws -> FCMHTTPReply
    private let send: Send
    init(send: @escaping Send) { self.send = send }
    static func native(timeoutSeconds: TimeInterval = 30) throws -> Self {
        let transport = try FCMHTTPTransport(timeoutSeconds: timeoutSeconds)
        return .init(send: { try await transport.send($0) })
    }
    func inspect(_ configuration: SetupCloudflareConfiguration) async throws -> CloudflareProvisioningScope {
        try Task.checkCancellation()
        let reply: FCMHTTPReply
        do { reply = try await send(configuration.zoneInspectionRequest()) }
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
        catch { throw CloudflareProvisioningError.invalidResponse }
        guard envelope.success, envelope.errors.isEmpty else { throw CloudflareProvisioningError.providerRejected }
        guard let zone = envelope.result else { throw CloudflareProvisioningError.invalidResponse }
        let name = zone.name.lowercased()
        do { try SetupCloudflareConfiguration.validateScope(accountID: zone.account.id, zoneID: zone.id, dnsSuffix: name) }
        catch { throw CloudflareProvisioningError.invalidResponse }
        guard zone.id == configuration.zoneID, zone.account.id == configuration.accountID,
              configuration.dnsSuffix == name || configuration.dnsSuffix.hasSuffix("." + name) else {
            throw CloudflareProvisioningError.wrongScope
        }
        guard zone.status == "active", !zone.paused else { throw CloudflareProvisioningError.unavailable }
        try Task.checkCancellation()
        return .init(accountID: zone.account.id, zoneID: zone.id, zoneName: name, dnsSuffix: configuration.dnsSuffix)
    }
    private struct Envelope: Decodable {
        let success: Bool
        let errors: [IgnoredProviderError]
        let result: Zone?
    }
    private struct IgnoredProviderError: Decodable {}
    private struct Zone: Decodable {
        struct Account: Decodable { let id: String }
        let id: String
        let account: Account
        let name: String
        let status: String
        let paused: Bool
    }
}
