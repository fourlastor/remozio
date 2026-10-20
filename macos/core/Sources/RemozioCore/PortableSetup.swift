import Foundation
import RemozioProtocol

public enum PortableSetupError: Error { case rejected }
/// Shared Firebase routing only. It contains no phone registration or device identity.
public struct SetupPushClientConfiguration: Sendable, Equatable {
    public let projectID: String
    public let senderID: String
    public let packageName: String
    public init(projectID: String, senderID: String, packageName: String) throws {
        do { _ = try PhonePushTokenOffer(token: "validation", projectID: projectID, senderID: senderID, packageName: packageName) }
        catch { throw PortableSetupError.rejected }
        self.projectID = projectID; self.senderID = senderID; self.packageName = packageName
    }
}

public enum SetupCategory: String, Sendable { case sharedDefaults, gatewayOperationalDefaults, appPreferences, fcmCredentials, cloudflareProvisioning }

/// Describes the import scope without exposing credential values. It does not assert provider authorization.
public struct SetupPreview: Sendable {
    public let categories: [SetupCategory]
    public let appPreferences: PortableAppPreferences?
    public let firebaseProject: String?
    public let pushClient: SetupPushClientConfiguration?
    public let cloudflareAccount: String?
    public let cloudflareZone: String?
    public let dnsSuffix: String?
}

/// Shared defaults only. Current routing mode and per-device overrides are not exported.
public struct SharedSetupDefaults: Sendable {
    public let presence: PresenceConfiguration
    public let wake: GatewayWakePolicy
    public let delivery: GatewayDeliveryPolicy
    public let gateway: GatewayRuntimeSettingsSelection?
    public init(presence: PresenceConfiguration, wake: GatewayWakePolicy, delivery: GatewayDeliveryPolicy) {
        self.presence = presence; self.wake = wake; self.delivery = delivery; gateway = nil
    }
    public init(presence: PresenceConfiguration, gateway: GatewayRuntimeSettingsSelection) {
        self.presence = presence; self.gateway = gateway
        wake = gateway.service.wake; delivery = gateway.service.delivery
    }
}

/// Shared push credentials, not a phone registration token or a Mac authority identity.
public struct SetupFCMConfiguration: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let project: String
    fileprivate let email: String
    fileprivate let keyID: String
    fileprivate let privateKeyPEM: String

    public init(project: String, clientEmail: String, privateKeyID: String, privateKeyPEM: String) throws {
        try Self.validateProject(project)
        guard clientEmail.utf8.count <= 254, privateKeyID.utf8.count <= 256,
              privateKeyPEM.utf8.count <= 16_384 else { throw PortableSetupError.rejected }
        self.project = project; self.email = clientEmail; self.keyID = privateKeyID; self.privateKeyPEM = privateKeyPEM
        do { _ = try serviceAccount() } catch { throw PortableSetupError.rejected }
    }

    static func validateProject(_ project: String) throws {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.:".utf8)
        guard !project.isEmpty, project != ".", project != "..", project.utf8.count <= 128,
              project.utf8.allSatisfy(allowed.contains) else { throw PortableSetupError.rejected }
    }

    public func serviceAccount() throws -> FCMServiceAccount {
        try FCMServiceAccount(json: JSONSerialization.data(withJSONObject: [
            "type": "service_account", "token_uri": FCMServiceAccount.tokenEndpoint,
            "client_email": email, "private_key_id": keyID, "private_key": privateKeyPEM,
        ]))
    }
    /// Protected gateway preparation uses this stable credential record. Shared exports keep their existing format.
    func gatewayCredentialJSON() throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "type": "service_account", "token_uri": FCMServiceAccount.tokenEndpoint, "project_id": project,
            "client_email": email, "private_key_id": keyID, "private_key": privateKeyPEM,
        ], options: [.sortedKeys])
    }
    public var description: String { "SetupFCMConfiguration(redacted)" }
    public var debugDescription: String { description }
}

/// Provisioning scope for independent resources. Provider checks are required before use.
/// There is deliberately no field for an existing tunnel ID, run credential, or Access application ID.
public struct SetupCloudflareConfiguration: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let accountID: String
    public let zoneID: String
    public let dnsSuffix: String
    fileprivate let apiToken: String

    public init(accountID: String, zoneID: String, dnsSuffix: String, apiToken: String) throws {
        try Self.validateScope(accountID: accountID, zoneID: zoneID, dnsSuffix: dnsSuffix)
        guard (1...4096).contains(apiToken.utf8.count), apiToken.utf8.allSatisfy({ (33...126).contains($0) }) else {
            throw PortableSetupError.rejected
        }
        self.accountID = accountID; self.zoneID = zoneID; self.dnsSuffix = dnsSuffix; self.apiToken = apiToken
    }
    static func validateScope(accountID: String, zoneID: String, dnsSuffix: String) throws {
        func identifier(_ value: String) -> Bool {
            value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        }
        let labels = dnsSuffix.split(separator: ".", omittingEmptySubsequences: false)
        guard identifier(accountID), identifier(zoneID), dnsSuffix.utf8.count <= 253,
              labels.allSatisfy({ label in
                  !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
                  label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
              }) else { throw PortableSetupError.rejected }
    }

    /// Reads the selected zone through a fixed provider endpoint. It exposes no general credential or HTTP interface.
    func zoneInspectionRequest() -> URLRequest {
        let endpoint = URL(string: "https://api.cloudflare.com/client/v4/zones/" + zoneID)!
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.setValue("Bearer " + apiToken, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }
    func tunnelInspectionRequest(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, page: Int) throws -> URLRequest {
        try plan.validate(expected: expected)
        guard let selected = expected.recipe.cloudflare, selected.accountID == accountID,
              selected.zoneID == zoneID, selected.dnsSuffix == dnsSuffix,
              (1...CloudflareTunnelInspectionClient.maximumPages).contains(page) else {
            throw CloudflareProvisioningError.wrongScope
        }
        var endpoint = URLComponents(string: "https://api.cloudflare.com/client/v4/accounts/" + accountID + "/cfd_tunnel")!
        endpoint.queryItems = [URLQueryItem(name: "name", value: plan.tunnelName), URLQueryItem(name: "is_deleted", value: "false"),
            URLQueryItem(name: "page", value: String(page)), URLQueryItem(name: "per_page", value: String(CloudflareTunnelInspectionClient.pageSize))]
        var request = URLRequest(url: endpoint.url!)
        request.httpMethod = "GET"
        request.setValue("Bearer " + apiToken, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }
    func tunnelConfigurationRequest(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                                    tunnel: CloudflareTunnelObservation) throws -> URLRequest {
        try plan.validate(expected: expected)
        guard let selected = expected.recipe.cloudflare, selected.accountID == accountID, selected.zoneID == zoneID,
              selected.dnsSuffix == dnsSuffix, tunnel.accountID == accountID, tunnel.name == plan.tunnelName,
              tunnel.tunnelID.utf8.count == 36, let uuid = UUID(uuidString: tunnel.tunnelID),
              uuid.uuidString.lowercased() == tunnel.tunnelID else { throw CloudflareProvisioningError.wrongScope }
        let endpoint = URL(string: "https://api.cloudflare.com/client/v4/accounts/" + accountID + "/cfd_tunnel/" + tunnel.tunnelID + "/configurations")!
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.setValue("Bearer " + apiToken, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }
    func tunnelCreationRequest(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                               dispatched: SharedSetupRelayProvisioningRecord) throws -> URLRequest {
        try dispatched.validate(expected: expected, plan: plan)
        guard [.retained, .runtimePublished, .gatewayPrepared].contains(expected.phase), dispatched.phase == .dispatched, let selected = expected.recipe.cloudflare,
              selected.accountID == accountID, selected.zoneID == zoneID, selected.dnsSuffix == dnsSuffix else {
            throw RelayProvisioningError.wrongScope
        }
        var request = URLRequest(url: URL(string: "https://api.cloudflare.com/client/v4/accounts/" + accountID + "/cfd_tunnel")!)
        request.httpMethod = "POST"; request.httpBody = try SharedSetupRelayProvisioningRecord.requestBody(plan: plan)
        request.setValue("Bearer " + apiToken, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return request
    }

    func createdTunnelRequest(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                              created: SharedSetupRelayProvisioningRecord) throws -> URLRequest {
        let tunnel = try created.createdTunnel(expected: expected, plan: plan)
        var request = try tunnelConfigurationRequest(expected: expected, plan: plan, tunnel: tunnel)
        request.url = URL(string: "https://api.cloudflare.com/client/v4/accounts/" + accountID + "/cfd_tunnel/" + tunnel.tunnelID)!
        return request
    }

    public var description: String { "SetupCloudflareConfiguration(redacted)" }
    public var debugDescription: String { description }
}

/// A data-only setup proposal. Opening it neither installs configuration nor creates an identity.
/// Only the protected Mac setup host may apply its settings after preview and explicit confirmation.
public struct PortableSetup: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public static let formatName = "setup.portable"
    public static let supportedVersions: Set<UInt64> = [1, 2, 3, 4]
    public let defaults: SharedSetupDefaults
    public let appPreferences: PortableAppPreferences?
    public let fcm: SetupFCMConfiguration?
    public let cloudflare: SetupCloudflareConfiguration?
    public let pushClient: SetupPushClientConfiguration?
    public static let maximumCanonicalByteCount = 65_536
    private static let limits = try! CBORLimits(maxBytes: maximumCanonicalByteCount, maxDepth: 4, maxItems: 128)

    public init(defaults: SharedSetupDefaults, fcm: SetupFCMConfiguration? = nil, cloudflare: SetupCloudflareConfiguration? = nil,
                pushClient: SetupPushClientConfiguration? = nil, appPreferences: PortableAppPreferences? = nil) {
        self.defaults = defaults; self.fcm = fcm; self.cloudflare = cloudflare; self.pushClient = pushClient; self.appPreferences = appPreferences
    }
    /// Import preparation requires complete shared configuration and a new local custody choice.
    public func gatewayPreparationChoices(fileWakeCustodyAccepted: Bool) throws -> GatewaySetupPreparationChoices {
        guard let gateway = defaults.gateway, let fcm, let pushClient, pushClient.projectID == fcm.project else {
            throw PortableSetupError.rejected
        }
        return try .init(provider: fcm, senderID: pushClient.senderID, packageName: pushClient.packageName,
            settings: gateway.service, fileWakeCustodyAccepted: fileWakeCustodyAccepted)
    }
    /// Adds explicit app preferences while retaining the provider and shared service scope.
    public func addingAppPreferences(_ preferences: PortableAppPreferences) -> Self {
        .init(defaults: defaults, fcm: fcm, cloudflare: cloudflare, pushClient: pushClient, appPreferences: preferences)
    }
    public var preview: SetupPreview {
        SetupPreview(categories: [.sharedDefaults] + (defaults.gateway == nil ? [] : [.gatewayOperationalDefaults]) + (appPreferences == nil ? [] : [.appPreferences]) + (fcm == nil ? [] : [.fcmCredentials]) +
                     (cloudflare == nil ? [] : [.cloudflareProvisioning]), appPreferences: appPreferences, firebaseProject: fcm?.project, pushClient: pushClient,
                     cloudflareAccount: cloudflare?.accountID, cloudflareZone: cloudflare?.zoneID, dnsSuffix: cloudflare?.dnsSuffix)
    }
    public var description: String { "PortableSetup(redacted)" }
    public var debugDescription: String { description }

    public func encryptedFile(password: String) throws -> Data {
        try SetupFileEncryption.seal(canonicalBytes(), password: password)
    }
    public init(encryptedFile: Data, password: String) throws {
        do { try self.init(canonicalBytes: SetupFileEncryption.open(encryptedFile, password: password)) }
        catch { throw PortableSetupError.rejected }
    }

    func canonicalBytes() throws -> Data {
        let p = defaults.presence, w = defaults.wake, d = defaults.delivery
        var settings: [UInt64: CBORValue] = [
            0: .array([p.idleMilliseconds, p.observationLifetimeMilliseconds, p.unavailableGraceMilliseconds].map(CBORValue.unsigned)),
            1: Self.wakeValue(w), 2: Self.deliveryValue(d),
        ]
        if let gateway = defaults.gateway { settings[3] = .bytes(try gateway.bytes) }
        let push: CBORValue = fcm.map { .map([0: .text($0.project), 1: .text($0.email), 2: .text($0.keyID), 3: .text($0.privateKeyPEM)]) } ?? .null
        let provision: CBORValue = cloudflare.map { .map([0: .text($0.accountID), 1: .text($0.zoneID), 2: .text($0.dnsSuffix), 3: .text($0.apiToken)]) } ?? .null
        var root: [UInt64: CBORValue] = [0: .unsigned(defaults.gateway == nil ? 1 : 2), 1: .map(settings), 2: push, 3: provision]
        if let pushClient {
            guard defaults.gateway != nil, fcm?.project == pushClient.projectID else { throw PortableSetupError.rejected }
            root[0] = .unsigned(3)
            root[4] = .array([pushClient.projectID, pushClient.senderID, pushClient.packageName].map(CBORValue.text))
        }
        if let appPreferences {
            root[0] = .unsigned(4)
            if root[4] == nil { root[4] = .null }
            root[5] = .bytes(try appPreferences.bytes)
        }
        return try DeterministicCBOR.encode(.map(root), limits: Self.limits)
    }

    private static func wakeValue(_ value: GatewayWakePolicy) -> CBORValue {
        .array([UInt64(value.maximumEntries), UInt64(value.maximumAttempts), value.minimumEnrollmentIntervalMillis,
                value.maximumLifetimeMillis, UInt64(value.maximumTTLSeconds)].map(CBORValue.unsigned))
    }
    private static func deliveryValue(_ value: GatewayDeliveryPolicy) -> CBORValue {
        .array([UInt64(value.maximumFlights), value.minimumSendIntervalMillis, value.retryBaseDelayMillis,
                value.maximumRetryBackoffMillis].map(CBORValue.unsigned))
    }
    init(canonicalBytes: Data) throws {
        do {
            let value = try DeterministicCBOR.decode(canonicalBytes, limits: Self.limits)
            guard case .map(let fields) = value, case .unsigned(let version) = fields[0],
                  Self.supportedVersions.contains(version) else { throw PortableSetupError.rejected }
            let root = try Fields(value, count: version == 4 ? 6 : version == 3 ? 5 : 4)
            let hasGateway: Bool
            if version == 4 {
                guard case .map(let settings) = root[1] else { throw PortableSetupError.rejected }
                hasGateway = settings[3] != nil
            } else { hasGateway = version >= 2 }
            let settings = try Fields(root[1], count: hasGateway ? 4 : 3)
            let p = try settings.numbers(0, count: 3), w = try settings.numbers(1, count: 5), d = try settings.numbers(2, count: 4)
            guard let entries = Int(exactly: w[0]), let attempts = Int(exactly: w[1]),
                  let ttl = UInt32(exactly: w[4]), let flights = Int(exactly: d[0]) else { throw PortableSetupError.rejected }
            let legacy = try SharedSetupDefaults(
                presence: PresenceConfiguration(idleMilliseconds: p[0], observationLifetimeMilliseconds: p[1], unavailableGraceMilliseconds: p[2]),
                wake: GatewayWakePolicy(maximumEntries: entries, maximumAttempts: attempts, minimumEnrollmentIntervalMillis: w[2], maximumLifetimeMillis: w[3], maximumTTLSeconds: ttl),
                delivery: GatewayDeliveryPolicy(maximumFlights: flights, minimumSendIntervalMillis: d[1], retryBaseDelayMillis: d[2], maximumRetryBackoffMillis: d[3]))
            if hasGateway {
                guard case .bytes(let bytes) = settings[3] else { throw PortableSetupError.rejected }
                let gateway = try GatewayRuntimeSettingsSelection.decode(bytes)
                let expanded = SharedSetupDefaults(presence: legacy.presence, gateway: gateway)
                guard Self.wakeValue(expanded.wake) == Self.wakeValue(legacy.wake),
                      Self.deliveryValue(expanded.delivery) == Self.deliveryValue(legacy.delivery) else {
                    throw PortableSetupError.rejected
                }
                defaults = expanded
            } else { defaults = legacy }
            if root[2] == .null { fcm = nil } else {
                let fields = try Fields(root[2], count: 4)
                fcm = try SetupFCMConfiguration(project: fields.text(0), clientEmail: fields.text(1), privateKeyID: fields.text(2), privateKeyPEM: fields.text(3))
            }
            if version == 3 || (version == 4 && root[4] != .null) {
                guard hasGateway else { throw PortableSetupError.rejected }
                guard case .array(let values) = root[4], values.count == 3,
                      case .text(let project) = values[0], case .text(let sender) = values[1], case .text(let package) = values[2],
                      fcm?.project == project else { throw PortableSetupError.rejected }
                pushClient = try .init(projectID: project, senderID: sender, packageName: package)
            } else { pushClient = nil }
            if version == 4 {
                guard case .bytes(let preferences) = root[5] else { throw PortableSetupError.rejected }
                appPreferences = try PortableAppPreferences.decode(preferences)
            } else { appPreferences = nil }
            if root[3] == .null { cloudflare = nil } else {
                let fields = try Fields(root[3], count: 4)
                cloudflare = try SetupCloudflareConfiguration(accountID: fields.text(0), zoneID: fields.text(1), dnsSuffix: fields.text(2), apiToken: fields.text(3))
            }
        } catch { throw PortableSetupError.rejected }
    }
}

private struct Fields {
    private let values: [UInt64: CBORValue]
    init(_ value: CBORValue, count: Int) throws {
        guard case let .map(values) = value, Set(values.keys) == Set((0..<count).map(UInt64.init)) else { throw PortableSetupError.rejected }
        self.values = values
    }
    subscript(_ key: UInt64) -> CBORValue { values[key]! }
    func text(_ key: UInt64) throws -> String {
        guard case let .text(value) = self[key] else { throw PortableSetupError.rejected }; return value
    }
    func numbers(_ key: UInt64, count: Int) throws -> [UInt64] {
        guard case let .array(values) = self[key], values.count == count else { throw PortableSetupError.rejected }
        return try values.map { guard case let .unsigned(value) = $0 else { throw PortableSetupError.rejected }; return value }
    }
}
