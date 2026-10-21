import CryptoKit
import Foundation

/// Exact record configuration only. It proves neither propagation nor current Access coverage.
struct CloudflareDNSRecordObservation: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let identity: CloudflareDNSRecordIdentity
    let recordDigest: Data
    func validate(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                  application: SharedSetupAccessApplicationRecord, record: SharedSetupDNSRecord) throws {
        guard identity == (try record.createdRecord(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application)),
              recordDigest == Data(SHA256.hash(data: record.bytes)) else { throw CloudflareProvisioningError.wrongScope }
    }
    var description: String { "CloudflareDNSRecordObservation(redacted)" }
    var debugDescription: String { description }
}

enum CloudflareDNSCreationOutcome: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case created(CloudflareDNSRecordIdentity), rejected(SharedSetupDNSRecord.Refusal), unknown
    var description: String { "CloudflareDNSCreationOutcome(redacted)" }
    var debugDescription: String { description }
}

/// Fixed zone operations only. The setup owner must retain dispatch and verify provider prerequisites before creation.
struct CloudflareDNSRecordClient: Sendable {
    typealias Send = CloudflareProvisioningScopeClient.Send
    private let send: Send
    init(send: @escaping Send) { self.send = send }
    func inspectAbsent(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                       plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                       application: SharedSetupAccessApplicationRecord) async throws {
        let reader = CloudflareAccessApplicationClient(send: send)
        for shadowing in [false, true] {
            let request = try configuration.dnsInventoryRequest(expected: expected, plan: plan, createdTunnel: createdTunnel,
                application: application, shadowing: shadowing)
            try emptyList(await reader.read(request))
        }
    }
    func create(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                application: SharedSetupAccessApplicationRecord, dispatched: SharedSetupDNSRecord) async throws -> CloudflareDNSCreationOutcome {
        try Task.checkCancellation()
        let request = try configuration.dnsCreationRequest(expected: expected, plan: plan, createdTunnel: createdTunnel,
            application: application, dispatched: dispatched)
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
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: reply.body), envelope.success, envelope.errors.isEmpty,
              let record = envelope.result, SharedSetupDNSRecord.validProviderID(record.id),
              (try? record.validate(zoneID: configuration.zoneID, recordID: record.id, hostname: plan.hostname,
                  target: dispatched.tunnelID + ".cfargotunnel.com")) != nil,
              (try? dispatched.transition(to: .created, dnsRecordID: record.id)) != nil else { return .unknown }
        return .created(.init(zoneID: configuration.zoneID, recordID: record.id, hostname: plan.hostname, target: record.content))
    }
    func inspect(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                 plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                 application: SharedSetupAccessApplicationRecord, record: SharedSetupDNSRecord) async throws -> CloudflareDNSRecordObservation {
        let selected = try record.createdRecord(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application)
        let request = try configuration.dnsRecordRequest(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application, record: record)
        let reply = try await CloudflareAccessApplicationClient(send: send).read(request)
        let envelope: Envelope
        do { envelope = try JSONDecoder().decode(Envelope.self, from: reply.body) }
        catch { throw CloudflareProvisioningError.invalidResponse }
        guard envelope.success, envelope.errors.isEmpty else { throw CloudflareProvisioningError.providerRejected }
        guard let result = envelope.result else { throw CloudflareProvisioningError.invalidResponse }
        try result.validate(zoneID: selected.zoneID, recordID: selected.recordID, hostname: selected.hostname, target: selected.target)
        try Task.checkCancellation()
        return .init(identity: selected, recordDigest: Data(SHA256.hash(data: record.bytes)))
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
    private struct Ignored: Decodable {}
    private struct ListEnvelope: Decodable {
        let success: Bool; let errors: [Ignored]; let result: [Ignored]; let result_info: Page
        struct Page: Decodable { let page: Int; let count: Int; let per_page: Int; let total_count: Int? }
    }
    private struct Envelope: Decodable { let success: Bool; let errors: [Ignored]; let result: Record? }
    private struct Record: Decodable {
        let id: String; let name: String; let type: String; let content: String; let proxied: Bool; let proxiable: Bool; let ttl: Int
        let zone_id: String?; let meta: Metadata
        func validate(zoneID: String, recordID: String, hostname: String, target: String) throws {
            guard id == recordID, name == hostname, type == "CNAME", content == target, proxied, proxiable, ttl == 1,
                  zone_id == nil || zone_id == zoneID, meta.shadowed_by?.isEmpty != false, meta.dead_glue != true,
                  meta.is_glue != true else { throw CloudflareProvisioningError.wrongScope }
        }
    }
    private struct Metadata: Decodable { let shadowed_by: [String]?; let dead_glue: Bool?; let is_glue: Bool? }
}
