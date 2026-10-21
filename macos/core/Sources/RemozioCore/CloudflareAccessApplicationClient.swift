import CryptoKit
import Foundation

/// Exact application configuration and an empty policy list. Hostname overlap and phone policy lifecycle need separate checks.
struct CloudflareInitialAccessObservation: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let identity: CloudflareAccessApplicationIdentity
    let planDigest: Data
    func validate(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                  application: SharedSetupAccessApplicationRecord) throws {
        guard identity == (try application.createdApplication(expected: expected, plan: plan, createdTunnel: createdTunnel)),
              planDigest == Data(SHA256.hash(data: plan.bytes)) else { throw CloudflareProvisioningError.wrongScope }
    }
    var description: String { "CloudflareInitialAccessObservation(redacted)" }
    var debugDescription: String { description }
}

enum CloudflareAccessApplicationCreationOutcome: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case created(CloudflareAccessApplicationIdentity), rejected(SharedSetupAccessApplicationRecord.Refusal), unknown
    var description: String { "CloudflareAccessApplicationCreationOutcome(redacted)" }
    var debugDescription: String { description }
}

/// Fixed account/application operations only. It cannot create service tokens,publish DNS or change a policy.
struct CloudflareAccessApplicationClient: Sendable {
    typealias Send = CloudflareProvisioningScopeClient.Send
    private let send: Send
    init(send: @escaping Send) { self.send = send }
    func inspectAbsent(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                       plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord) async throws {
        let reply = try await read(configuration.accessApplicationInventoryRequest(expected: expected, plan: plan, createdTunnel: createdTunnel))
        try emptyList(reply)
    }
    func create(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                dispatched: SharedSetupAccessApplicationRecord) async throws -> CloudflareAccessApplicationCreationOutcome {
        try Task.checkCancellation()
        let request = try configuration.accessApplicationCreationRequest(expected: expected, plan: plan, createdTunnel: createdTunnel, dispatched: dispatched)
        let reply: FCMHTTPReply
        do { reply = try await send(request) } catch { return .unknown }
        guard reply.body.count <= FCMHTTPTransport.maximumResponseBytes else { return .unknown }
        switch reply.status {
        case 200: break
        case 401, 403: return .rejected(.unauthorized)
        case 429: return .rejected(.rateLimited)
        case 408, 409, 425: return .unknown
        case 400..<500: return .rejected(.providerRejected)
        default: return .unknown
        }
        guard let envelope = try? JSONDecoder().decode(CreationEnvelope.self, from: reply.body), envelope.success, envelope.errors.isEmpty,
              let app = envelope.result, app.name == plan.accessApplicationName, app.domain == plan.hostname, app.type == "self_hosted",
              app.id.utf8.count == 36, let uuid = UUID(uuidString: app.id),
              (try? dispatched.transition(to: .created, applicationID: uuid.uuidString.lowercased(), audience: app.aud)) != nil else { return .unknown }
        return .created(.init(accountID: configuration.accountID, applicationID: uuid.uuidString.lowercased(),
            name: app.name, hostname: app.domain, audience: app.aud))
    }
    func inspectInitial(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                        plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                        application: SharedSetupAccessApplicationRecord) async throws -> CloudflareInitialAccessObservation {
        let selected = try application.createdApplication(expected: expected, plan: plan, createdTunnel: createdTunnel)
        let reply = try await read(configuration.accessApplicationRequest(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application))
        let envelope: ApplicationEnvelope
        do { envelope = try JSONDecoder().decode(ApplicationEnvelope.self, from: reply.body) }
        catch let known as CloudflareProvisioningError { throw known }
        catch { throw CloudflareProvisioningError.invalidResponse }
        guard envelope.success, envelope.errors.isEmpty else { throw CloudflareProvisioningError.providerRejected }
        try envelope.result.validate(selected)
        let policies = try await read(configuration.accessApplicationRequest(expected: expected, plan: plan,
            createdTunnel: createdTunnel, application: application, policies: true))
        try emptyList(policies); try Task.checkCancellation()
        return .init(identity: selected, planDigest: Data(SHA256.hash(data: plan.bytes)))
    }
    func read(_ request: URLRequest) async throws -> FCMHTTPReply {
        try Task.checkCancellation()
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
        case 200: return reply
        case 401, 403: throw CloudflareProvisioningError.unauthorized
        case 429: throw CloudflareProvisioningError.rateLimited
        case 400..<500: throw CloudflareProvisioningError.providerRejected
        default: throw CloudflareProvisioningError.unavailable
        }
    }
    private func emptyList(_ reply: FCMHTTPReply) throws {
        guard let envelope = try? JSONDecoder().decode(ListEnvelope.self, from: reply.body) else { throw CloudflareProvisioningError.invalidResponse }
        guard envelope.success, envelope.errors.isEmpty else { throw CloudflareProvisioningError.providerRejected }
        guard envelope.result.isEmpty else { throw CloudflareProvisioningError.wrongScope }
        let page = envelope.result_info
        guard page.page == 1, page.count == 0, (1...100).contains(page.per_page), (page.total_count ?? 0) >= 0 else {
            throw CloudflareProvisioningError.invalidResponse
        }
    }
    private struct Ignored: Decodable, Equatable {}
    private struct ListEnvelope: Decodable {
        let success: Bool; let errors: [Ignored]; let result: [Ignored]; let result_info: Page
        struct Page: Decodable { let page: Int; let count: Int; let per_page: Int; let total_count: Int? }
    }
    private struct CreationEnvelope: Decodable {
        let success: Bool; let errors: [Ignored]; let result: Identity?
        struct Identity: Decodable { let id: String; let name: String; let domain: String; let type: String; let aud: String }
    }
    private struct ApplicationEnvelope: Decodable { let success: Bool; let errors: [Ignored]; let result: Application }
    private struct Application: Decodable {
        let id: String; let name: String; let domain: String; let type: String; let aud: String
        let service_auth_401_redirect: Bool
        let auto_redirect_to_identity: Bool?
        let app_launcher_visible: Bool?
        let allow_authenticate_via_warp: Bool?
        let skip_interstitial: Bool?
        let read_service_tokens_from_header: String?
        let custom_deny_url: String?
        let custom_non_identity_deny_url: String?
        let destinations: [Destination]?
        let self_hosted_domains: [String]?
        let cors_headers: CORS?
        let scim_config: Ignored?
        func validate(_ selected: CloudflareAccessApplicationIdentity) throws {
            guard id == selected.applicationID, name == selected.name, domain == selected.hostname, type == "self_hosted", aud == selected.audience,
                  service_auth_401_redirect, auto_redirect_to_identity != true, app_launcher_visible != true,
                  allow_authenticate_via_warp == false, skip_interstitial != true,
                  (read_service_tokens_from_header ?? "").isEmpty, (custom_deny_url ?? "").isEmpty,
                  (custom_non_identity_deny_url ?? "").isEmpty, cors_headers?.bypass_options != true, scim_config == nil else {
                throw CloudflareProvisioningError.wrongScope
            }
            if let destinations {
                guard destinations.count == 1, destinations[0].type == "public", destinations[0].uri == selected.hostname else {
                    throw CloudflareProvisioningError.wrongScope
                }
            } else if let self_hosted_domains, !self_hosted_domains.isEmpty {
                guard self_hosted_domains == [selected.hostname] else { throw CloudflareProvisioningError.wrongScope }
            }
        }
    }
    private struct CORS: Decodable { let bypass_options: Bool? }
    private struct Key: CodingKey {
        let stringValue: String; let intValue: Int? = nil
        init(stringValue: String) { self.stringValue = stringValue }; init?(intValue: Int) { return nil }
        init(_ value: String) { stringValue = value }
    }
    private struct Destination: Decodable {
        let type: String; let uri: String
        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: Key.self)
            guard Set(fields.allKeys.map(\.stringValue)).isSubset(of: ["type", "uri", "overrides"]) else { throw CloudflareProvisioningError.wrongScope }
            type = try fields.decode(String.self, forKey: Key("type")); uri = try fields.decode(String.self, forKey: Key("uri"))
            if fields.contains(Key("overrides")) {
                guard try fields.decode([Ignored].self, forKey: Key("overrides")).isEmpty else { throw CloudflareProvisioningError.wrongScope }
            }
        }
    }
}
