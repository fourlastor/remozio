import CryptoKit
import Foundation

/// A point-in-time inventory. It does not establish routing precedence or authorize DNS publication.
struct CloudflareAccessHostnameInventory: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    struct Match: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
        let applicationID: String
        let uri: String
        let wildcardHostname: Bool
        let hasPublicOverrides: Bool
        var description: String { "CloudflareAccessHostnameMatch(redacted)" }
        var debugDescription: String { description }
    }
    let identity: CloudflareAccessApplicationIdentity
    let planDigest: Data
    let applicationCount: Int
    let matches: [Match]
    let unresolvedApplicationIDs: [String]
    func validate(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                  application: SharedSetupAccessApplicationRecord) throws {
        guard identity == (try application.createdApplication(expected: expected, plan: plan, createdTunnel: createdTunnel)),
              planDigest == Data(SHA256.hash(data: plan.bytes)) else { throw CloudflareProvisioningError.wrongScope }
    }
    var description: String { "CloudflareAccessHostnameInventory(redacted)" }
    var debugDescription: String { description }
}

/// Account-scoped reads only. Destination aliases are included; provider URLs are never followed.
struct CloudflareAccessHostnameClient: Sendable {
    static let maximumPages = 100
    typealias Send = CloudflareProvisioningScopeClient.Send
    private let send: Send
    init(send: @escaping Send) { self.send = send }
    func inspect(_ configuration: SetupCloudflareConfiguration, expected: SharedSetupImportIntent,
                 plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                 application: SharedSetupAccessApplicationRecord) async throws -> CloudflareAccessHostnameInventory {
        let selected = try application.createdApplication(expected: expected, plan: plan, createdTunnel: createdTunnel)
        let reader = CloudflareAccessApplicationClient(send: send)
        var ids = Set<String>(), matches: [CloudflareAccessHostnameInventory.Match] = [], unresolved: [String] = []
        var pageSize: Int?, totalCount: Int?, totalPages: Int?
        for number in 1...Self.maximumPages {
            let request = try configuration.accessAccountInventoryRequest(expected: expected, plan: plan, createdTunnel: createdTunnel, page: number)
            let reply = try await reader.read(request)
            let envelope: Envelope
            do { envelope = try JSONDecoder().decode(Envelope.self, from: reply.body) }
            catch { throw CloudflareProvisioningError.invalidResponse }
            guard envelope.success, envelope.errors.isEmpty else { throw CloudflareProvisioningError.providerRejected }
            let info = envelope.result_info
            guard info.page == number, (1...100).contains(info.per_page), info.count == envelope.result.count,
                  (0...info.per_page).contains(info.count), pageSize == nil || pageSize == info.per_page,
                  info.total_count == nil || info.total_count! >= 0,
                  info.total_pages == nil || (0...Self.maximumPages).contains(info.total_pages!) else { throw CloudflareProvisioningError.invalidResponse }
            if number == 1 { pageSize = info.per_page; totalCount = info.total_count; totalPages = info.total_pages }
            guard totalCount == info.total_count, totalPages == info.total_pages,
                  totalPages != 0 || (number == 1 && envelope.result.isEmpty) else { throw CloudflareProvisioningError.invalidResponse }
            if let totalCount, let totalPages {
                let expectedPages = totalCount / info.per_page + (totalCount % info.per_page == 0 ? 0 : 1)
                guard totalPages == expectedPages || (totalCount == 0 && totalPages == 1) else { throw CloudflareProvisioningError.invalidResponse }
            }
            for row in envelope.result {
                guard row.id.utf8.count == 36, let id = UUID(uuidString: row.id),
                      ids.insert(id.uuidString.lowercased()).inserted else { throw CloudflareProvisioningError.invalidResponse }
                let appID = id.uuidString.lowercased()
                let routes = try row.routes()
                if routes.unresolved { unresolved.append(appID) }
                for destination in routes.values {
                    let parsed = try Self.hostname(destination.uri)
                    if Self.matches(parsed, hostname: plan.hostname) {
                        matches.append(.init(applicationID: appID, uri: destination.uri, wildcardHostname: parsed.contains("*"),
                            hasPublicOverrides: destination.hasPublicOverrides))
                    }
                }
            }
            let terminal: Bool
            if let totalCount {
                guard ids.count <= totalCount else { throw CloudflareProvisioningError.invalidResponse }
                terminal = ids.count == totalCount
                if !terminal && info.count != info.per_page { throw CloudflareProvisioningError.invalidResponse }
            } else if let totalPages {
                terminal = number >= totalPages
                if !terminal && info.count != info.per_page { throw CloudflareProvisioningError.invalidResponse }
            } else { terminal = info.count < info.per_page }
            if terminal {
                guard ids.contains(selected.applicationID),
                      matches.contains(where: { $0.applicationID == selected.applicationID && $0.uri == selected.hostname }) else {
                    throw CloudflareProvisioningError.wrongScope
                }
                try Task.checkCancellation()
                return .init(identity: selected, planDigest: Data(SHA256.hash(data: plan.bytes)), applicationCount: ids.count,
                    matches: matches, unresolvedApplicationIDs: unresolved)
            }
        }
        throw CloudflareProvisioningError.invalidResponse
    }
    private static func hostname(_ uri: String) throws -> String {
        guard !uri.isEmpty, uri.utf8.count <= 2048, uri.utf8.allSatisfy({ (33...126).contains($0) }),
              !uri.contains("://"), !uri.contains("?"), !uri.contains("#"), !uri.contains("\\") else { throw CloudflareProvisioningError.invalidResponse }
        let host = String(uri.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)[0]).lowercased()
        guard host.utf8.count <= 253, host.contains("."), !host.hasSuffix("."),
              host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ label in
                  !label.isEmpty && !label.hasPrefix("-") && !label.hasSuffix("-") && label.utf8.count <= 63 && label.filter({ $0 == "*" }).count <= 1 &&
                  label.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 42 })
              }) else { throw CloudflareProvisioningError.invalidResponse }
        return host
    }
    private static func matches(_ pattern: String, hostname: String) -> Bool {
        let patternLabels = pattern.split(separator: "."), labels = hostname.split(separator: ".")
        guard patternLabels.count == labels.count else { return false }
        return zip(patternLabels, labels).allSatisfy { pattern, label in
            guard let star = pattern.firstIndex(of: "*") else { return pattern == label }
            let prefix = pattern[..<star], suffix = pattern[pattern.index(after: star)...]
            return label.count >= prefix.count + suffix.count && label.hasPrefix(prefix) && label.hasSuffix(suffix)
        }
    }
    private struct Ignored: Decodable {}
    private struct Envelope: Decodable {
        let success: Bool; let errors: [Ignored]; let result: [Application]; let result_info: Page
    }
    private struct Page: Decodable {
        let page: Int; let count: Int; let per_page: Int; let total_count: Int?; let total_pages: Int?
    }
    private struct Route {
        let uri: String; let hasPublicOverrides: Bool
    }
    private struct Application: Decodable {
        let id: String; let type: String; let domain: String?; let destinations: [Destination]?; let self_hosted_domains: [String]?
        func routes() throws -> (values: [Route], unresolved: Bool) {
            // SaaS federation and bookmark tiles do not protect a public hostname.
            if ["saas", "bookmark"].contains(type) {
                guard destinations?.isEmpty != false, self_hosted_domains?.isEmpty != false else { return ([], true) }
                return ([], false)
            }
            guard ["self_hosted", "ssh", "vnc"].contains(type) else { return ([], true) }
            if let destinations {
                var result: [Route] = [], unknown = false
                for destination in destinations {
                    if destination.type == "public" {
                        guard let uri = destination.uri else { throw CloudflareProvisioningError.invalidResponse }
                        result.append(.init(uri: uri, hasPublicOverrides: destination.overrides?.isEmpty == false))
                        unknown = unknown || destination.unknownPublicFields
                    } else if destination.type != "private" { unknown = true }
                }
                return (result, unknown)
            }
            var seen = Set<String>()
            let domains = (domain.map { [$0] } ?? []) + (self_hosted_domains ?? [])
            let routes = domains.filter { seen.insert($0).inserted }.map { Route(uri: $0, hasPublicOverrides: false) }
            guard !routes.isEmpty else { throw CloudflareProvisioningError.invalidResponse }
            return (routes, false)
        }
    }
    private struct Key: CodingKey {
        let stringValue: String; let intValue: Int? = nil
        init(stringValue: String) { self.stringValue = stringValue }; init?(intValue: Int) { return nil }
        init(_ value: String) { stringValue = value }
    }
    private struct Destination: Decodable {
        let type: String; let uri: String?; let overrides: [Ignored]?; let unknownPublicFields: Bool
        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: Key.self)
            type = try fields.decode(String.self, forKey: Key("type"))
            uri = try fields.decodeIfPresent(String.self, forKey: Key("uri"))
            overrides = try fields.decodeIfPresent([Ignored].self, forKey: Key("overrides"))
            unknownPublicFields = type == "public" && !Set(fields.allKeys.map(\.stringValue)).isSubset(of: ["type", "uri", "overrides"])
        }
    }
}
