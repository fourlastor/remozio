import Foundation
import RemozioProtocol

public enum PortableSetupError: Error { case rejected }
public enum SetupCategory: String, Sendable { case sharedDefaults, fcmCredentials, cloudflareProvisioning }

/// Describes the import scope without exposing credential values. It does not assert provider authorization.
public struct SetupPreview: Sendable {
    public let categories: [SetupCategory]
    public let firebaseProject: String?
    public let cloudflareAccount: String?
    public let cloudflareZone: String?
    public let dnsSuffix: String?
}

/// Shared defaults only. Current routing mode and per-device overrides are not exported.
public struct SharedSetupDefaults: Sendable {
    public let presence: PresenceConfiguration
    public let wake: GatewayWakePolicy
    public let delivery: GatewayDeliveryPolicy
    public init(presence: PresenceConfiguration, wake: GatewayWakePolicy, delivery: GatewayDeliveryPolicy) {
        self.presence = presence; self.wake = wake; self.delivery = delivery
    }
}

/// Shared push credentials, not a phone registration token or a Mac authority identity.
public struct SetupFCMConfiguration: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let project: String
    fileprivate let email: String
    fileprivate let keyID: String
    fileprivate let privateKeyPEM: String

    public init(project: String, clientEmail: String, privateKeyID: String, privateKeyPEM: String) throws {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.:".utf8)
        guard !project.isEmpty, project != ".", project != "..", project.utf8.count <= 128,
              project.utf8.allSatisfy(allowed.contains), clientEmail.utf8.count <= 254,
              privateKeyID.utf8.count <= 256, privateKeyPEM.utf8.count <= 16_384 else { throw PortableSetupError.rejected }
        self.project = project; self.email = clientEmail; self.keyID = privateKeyID; self.privateKeyPEM = privateKeyPEM
        do { _ = try serviceAccount() } catch { throw PortableSetupError.rejected }
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
        func identifier(_ value: String) -> Bool {
            value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        }
        let labels = dnsSuffix.split(separator: ".", omittingEmptySubsequences: false)
        guard identifier(accountID), identifier(zoneID), dnsSuffix.utf8.count <= 253,
              labels.allSatisfy({ label in
                  !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
                  label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
              }), (1...4096).contains(apiToken.utf8.count), apiToken.utf8.allSatisfy({ (33...126).contains($0) }) else {
            throw PortableSetupError.rejected
        }
        self.accountID = accountID; self.zoneID = zoneID; self.dnsSuffix = dnsSuffix; self.apiToken = apiToken
    }
    public var description: String { "SetupCloudflareConfiguration(redacted)" }
    public var debugDescription: String { description }
}

/// A data-only setup proposal. Opening it neither installs configuration nor creates an identity.
/// Only the protected Mac setup host may apply its settings after preview and explicit confirmation.
public struct PortableSetup: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let defaults: SharedSetupDefaults
    public let fcm: SetupFCMConfiguration?
    public let cloudflare: SetupCloudflareConfiguration?
    private static let limits = try! CBORLimits(maxBytes: 65_536, maxDepth: 4, maxItems: 128)

    public init(defaults: SharedSetupDefaults, fcm: SetupFCMConfiguration? = nil, cloudflare: SetupCloudflareConfiguration? = nil) {
        self.defaults = defaults; self.fcm = fcm; self.cloudflare = cloudflare
    }
    public var preview: SetupPreview {
        SetupPreview(categories: [.sharedDefaults] + (fcm == nil ? [] : [.fcmCredentials]) +
                     (cloudflare == nil ? [] : [.cloudflareProvisioning]), firebaseProject: fcm?.project,
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
        let settings: CBORValue = .map([
            0: .array([p.idleMilliseconds, p.observationLifetimeMilliseconds, p.unavailableGraceMilliseconds].map(CBORValue.unsigned)),
            1: .array([UInt64(w.maximumEntries), UInt64(w.maximumAttempts), w.minimumEnrollmentIntervalMillis,
                       w.maximumLifetimeMillis, UInt64(w.maximumTTLSeconds)].map(CBORValue.unsigned)),
            2: .array([UInt64(d.maximumFlights), d.minimumSendIntervalMillis, d.retryBaseDelayMillis,
                       d.maximumRetryBackoffMillis].map(CBORValue.unsigned)),
        ])
        let push: CBORValue = fcm.map { .map([0: .text($0.project), 1: .text($0.email), 2: .text($0.keyID), 3: .text($0.privateKeyPEM)]) } ?? .null
        let provision: CBORValue = cloudflare.map { .map([0: .text($0.accountID), 1: .text($0.zoneID), 2: .text($0.dnsSuffix), 3: .text($0.apiToken)]) } ?? .null
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: settings, 2: push, 3: provision]), limits: Self.limits)
    }

    init(canonicalBytes: Data) throws {
        do {
            let root = try Fields(DeterministicCBOR.decode(canonicalBytes, limits: Self.limits), count: 4)
            guard root[0] == .unsigned(1) else { throw PortableSetupError.rejected }
            let settings = try Fields(root[1], count: 3)
            let p = try settings.numbers(0, count: 3), w = try settings.numbers(1, count: 5), d = try settings.numbers(2, count: 4)
            guard let entries = Int(exactly: w[0]), let attempts = Int(exactly: w[1]),
                  let ttl = UInt32(exactly: w[4]), let flights = Int(exactly: d[0]) else { throw PortableSetupError.rejected }
            defaults = try SharedSetupDefaults(
                presence: PresenceConfiguration(idleMilliseconds: p[0], observationLifetimeMilliseconds: p[1], unavailableGraceMilliseconds: p[2]),
                wake: GatewayWakePolicy(maximumEntries: entries, maximumAttempts: attempts, minimumEnrollmentIntervalMillis: w[2], maximumLifetimeMillis: w[3], maximumTTLSeconds: ttl),
                delivery: GatewayDeliveryPolicy(maximumFlights: flights, minimumSendIntervalMillis: d[1], retryBaseDelayMillis: d[2], maximumRetryBackoffMillis: d[3]))
            if root[2] == .null { fcm = nil } else {
                let fields = try Fields(root[2], count: 4)
                fcm = try SetupFCMConfiguration(project: fields.text(0), clientEmail: fields.text(1), privateKeyID: fields.text(2), privateKeyPEM: fields.text(3))
            }
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
