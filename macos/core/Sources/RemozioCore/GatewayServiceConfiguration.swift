import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum GatewayServiceError: Error, Equatable {
    case invalidConfiguration, wrongAccount, invalidCredentials, invalidMessage, unavailable, capacityExceeded
}

/// Protected local settings. No setting renews a candidate or request deadline.
public struct GatewayServiceSettings: Sendable {
    public let maximumOperations: Int
    public let handshakeTimeoutMillis: UInt64
    public let authorityLeaseMillis: UInt64
    public let providerTimeoutSeconds: UInt64
    public let schedulerRetryMillis: UInt64
    public let maximumStoredControls: Int
    public let maximumPendingPerEnrollment: Int
    public let maximumCandidateLifetimeMillis: UInt64
    public let databaseBusyMillis: UInt32
    public let delivery: GatewayDeliveryPolicy
    public let probe: GatewayProbePolicy
    public let wake: GatewayWakePolicy

    public init(delivery: GatewayDeliveryPolicy, probe: GatewayProbePolicy, wake: GatewayWakePolicy,
                maximumOperations: Int = 8, handshakeTimeoutMillis: UInt64 = 5000,
                authorityLeaseMillis: UInt64 = 15000, providerTimeoutSeconds: UInt64 = 30,
                schedulerRetryMillis: UInt64 = 1000, maximumStoredControls: Int = 4096,
                maximumPendingPerEnrollment: Int = 4, maximumCandidateLifetimeMillis: UInt64 = 300000,
                databaseBusyMillis: UInt32 = 1000) throws {
        guard (1...64).contains(maximumOperations), (1...60000).contains(handshakeTimeoutMillis),
              (1...60000).contains(authorityLeaseMillis), (1...120).contains(providerTimeoutSeconds),
              (1...60000).contains(schedulerRetryMillis), (1...1000000).contains(maximumStoredControls),
              (1...maximumStoredControls).contains(maximumPendingPerEnrollment),
              (1...86400000).contains(maximumCandidateLifetimeMillis), databaseBusyMillis <= 60000 else {
            throw GatewayServiceError.invalidConfiguration
        }
        self.delivery = delivery; self.probe = probe; self.wake = wake
        self.maximumOperations = maximumOperations; self.handshakeTimeoutMillis = handshakeTimeoutMillis
        self.authorityLeaseMillis = authorityLeaseMillis; self.providerTimeoutSeconds = providerTimeoutSeconds
        self.schedulerRetryMillis = schedulerRetryMillis; self.maximumStoredControls = maximumStoredControls
        self.maximumPendingPerEnrollment = maximumPendingPerEnrollment
        self.maximumCandidateLifetimeMillis = maximumCandidateLifetimeMillis; self.databaseBusyMillis = databaseBusyMillis
    }

    /// Versioned local setup input. This value does not renew a request or candidate deadline.
    public var setupBytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-service-settings"), 2: value]), limits: Self.setupLimits)
    } }
    public static func decodeSetupBytes(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: setupLimits), Set(f.keys) == Set(UInt64(0)...2),
              f[0] == .unsigned(1), f[1] == .text("remozio-gateway-service-settings"), let fields = f[2] else {
            throw GatewayServiceError.invalidConfiguration
        }
        let result = try decode(fields)
        guard try result.setupBytes == bytes else { throw GatewayServiceError.invalidConfiguration }; return result
    }
    private static let setupLimits = try! CBORLimits(maxBytes: 4096, maxDepth: 3, maxItems: 128)

    fileprivate var value: CBORValue {
        .map([0: .unsigned(UInt64(maximumOperations)), 1: .unsigned(handshakeTimeoutMillis),
            2: .unsigned(authorityLeaseMillis), 3: .unsigned(providerTimeoutSeconds), 4: .unsigned(schedulerRetryMillis),
            5: .unsigned(UInt64(maximumStoredControls)), 6: .unsigned(UInt64(maximumPendingPerEnrollment)),
            7: .unsigned(maximumCandidateLifetimeMillis), 8: .unsigned(UInt64(databaseBusyMillis)),
            9: .array([UInt64(delivery.maximumFlights), delivery.minimumSendIntervalMillis,
                delivery.retryBaseDelayMillis, delivery.maximumRetryBackoffMillis].map(CBORValue.unsigned)),
            10: .array([UInt64(probe.maximumAttempts), probe.minimumRetryDelayMillis,
                UInt64(probe.maximumTTLSeconds)].map(CBORValue.unsigned)),
            11: .array([UInt64(wake.maximumEntries), UInt64(wake.maximumAttempts), wake.minimumEnrollmentIntervalMillis,
                wake.maximumLifetimeMillis, UInt64(wake.maximumTTLSeconds)].map(CBORValue.unsigned))])
    }

    fileprivate static func decode(_ value: CBORValue) throws -> Self {
        guard case .map(let fields) = value, Set(fields.keys) == Set(UInt64(0)...11) else { throw GatewayServiceError.invalidConfiguration }
        func number(_ key: UInt64) throws -> UInt64 {
            guard case .unsigned(let result) = fields[key] else { throw GatewayServiceError.invalidConfiguration }; return result
        }
        func integer(_ key: UInt64) throws -> Int { try exact(try number(key)) }
        func array(_ key: UInt64, _ count: Int) throws -> [UInt64] {
            guard case .array(let values) = fields[key], values.count == count else { throw GatewayServiceError.invalidConfiguration }
            return try values.map {
                guard case .unsigned(let number) = $0 else { throw GatewayServiceError.invalidConfiguration }; return number
            }
        }
        let delivery = try array(9, 4), probe = try array(10, 3), wake = try array(11, 5)
        guard let busy = UInt32(exactly: try number(8)), let probeTTL = UInt32(exactly: probe[2]),
              let wakeTTL = UInt32(exactly: wake[4]) else { throw GatewayServiceError.invalidConfiguration }
        return try Self(delivery: GatewayDeliveryPolicy(maximumFlights: exact(delivery[0]), minimumSendIntervalMillis: delivery[1],
                retryBaseDelayMillis: delivery[2], maximumRetryBackoffMillis: delivery[3]),
            probe: GatewayProbePolicy(maximumAttempts: exact(probe[0]), minimumRetryDelayMillis: probe[1], maximumTTLSeconds: probeTTL),
            wake: GatewayWakePolicy(maximumEntries: exact(wake[0]), maximumAttempts: exact(wake[1]),
                minimumEnrollmentIntervalMillis: wake[2], maximumLifetimeMillis: wake[3], maximumTTLSeconds: wakeTTL),
            maximumOperations: integer(0), handshakeTimeoutMillis: number(1), authorityLeaseMillis: number(2),
            providerTimeoutSeconds: number(3), schedulerRetryMillis: number(4), maximumStoredControls: integer(5),
            maximumPendingPerEnrollment: integer(6), maximumCandidateLifetimeMillis: number(7), databaseBusyMillis: busy)
    }

    private static func exact(_ number: UInt64) throws -> Int {
        guard let value = Int(exactly: number) else { throw GatewayServiceError.invalidConfiguration }; return value
    }
}

/// Root-owned public metadata. Protected setup must establish registration, pins, accounts, and private files first.
public struct GatewayServiceConfiguration: Sendable {
    public static let formatName = "gateway.service-config"
    public static let supportedVersions: Set<UInt64> = [1, 2]
    public let registration: GatewayRegistrationIdentity
    public let receiptPublicKey: Data
    public let directoryPath: String
    public let providerPath: String
    public let receiptKeyPath: String
    public let serviceUID: uid_t
    public let ownerUID: uid_t
    public let serviceName: String
    public let authorityPolicy: XPCPeerPolicy
    public let wakeEndpoint: GatewayWakeEndpointConfiguration?
    public let project: String
    public let packageName: String
    public let settings: GatewayServiceSettings
    public let canonicalBytes: Data

    public init(registration: GatewayRegistrationIdentity, receiptPublicKey: Data, directoryPath: String,
                providerPath: String, receiptKeyPath: String, serviceUID: uid_t, ownerUID: uid_t,
                serviceName: String, teamID: String, authorityIdentifier: String, authorityHashes: Set<Data>,
                project: String, packageName: String, settings: GatewayServiceSettings,
                wakeEndpoint: GatewayWakeEndpointConfiguration? = nil) throws {
        guard serviceUID > 0, serviceUID < UInt32.max, ownerUID > 0, ownerUID < UInt32.max, serviceUID != ownerUID,
              receiptPublicKey.count == 65, receiptPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: receiptPublicKey)) != nil,
              receiptPublicKey != registration.rootPublicKey,
              Self.validPath(directoryPath), Self.validPath(providerPath), Self.validPath(receiptKeyPath), providerPath != receiptKeyPath,
              !providerPath.hasPrefix(directoryPath + "/"), !receiptKeyPath.hasPrefix(directoryPath + "/"),
              providerPath != directoryPath, receiptKeyPath != directoryPath,
              serviceName.hasPrefix("dev.remozio."), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }) else {
            throw GatewayServiceError.invalidConfiguration
        }
        if let wakeEndpoint {
            guard wakeEndpoint.serviceName != serviceName, wakeEndpoint.transportUID != serviceUID,
                  wakeEndpoint.transportUID != ownerUID, wakeEndpoint.teamID == teamID,
                  wakeEndpoint.componentIdentifier != authorityIdentifier else { throw GatewayServiceError.invalidConfiguration }
        }
        self.wakeEndpoint = wakeEndpoint
        authorityPolicy = try XPCPeerPolicy(teamID: teamID, componentIdentifier: authorityIdentifier,
            approvedCodeDirectoryHashes: authorityHashes, expectedUserID: 0)
        _ = try FCMWakeSender(project: project, packageName: packageName, timeoutSeconds: Double(settings.providerTimeoutSeconds))
        self.registration = registration; self.receiptPublicKey = receiptPublicKey; self.directoryPath = directoryPath
        self.providerPath = providerPath; self.receiptKeyPath = receiptKeyPath; self.serviceUID = serviceUID; self.ownerUID = ownerUID
        self.serviceName = serviceName; self.project = project; self.packageName = packageName; self.settings = settings
        var fields: [UInt64: CBORValue] = [0: .unsigned(wakeEndpoint == nil ? 1 : 2), 1: .bytes(try registration.encode()),
            2: .bytes(receiptPublicKey), 3: .text(directoryPath), 4: .text(providerPath), 5: .text(receiptKeyPath),
            6: .unsigned(UInt64(serviceUID)), 7: .unsigned(UInt64(ownerUID)), 8: .text(serviceName),
            9: .array([.text(teamID), .text(authorityIdentifier), .array(authorityHashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes))]),
            10: settings.value, 11: .text(project), 12: .text(packageName)]
        if let wakeEndpoint { fields[13] = wakeEndpoint.value }
        canonicalBytes = try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    }

    public static func load(path: String) throws -> Self {
        let result = try decode(ProtectedServiceConfiguration.readPublic(path: path))
        try result.requireNativeProcess()
        return result
    }

    /// Decoding alone does not authenticate provisioning. Native startup must call load(path:).
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              ((fields[0] == .unsigned(1) && Set(fields.keys) == Set(UInt64(0)...12)) ||
               (fields[0] == .unsigned(2) && Set(fields.keys) == Set(UInt64(0)...13))), case .bytes(let identityBytes) = fields[1],
              case .bytes(let receiptKey) = fields[2], case .array(let peer) = fields[9], peer.count == 3,
              case .text(let team) = peer[0], case .text(let component) = peer[1], case .array(let hashes) = peer[2],
              let settingsValue = fields[10], case .map(let identity) = try DeterministicCBOR.decode(identityBytes, limits: limits),
              Set(identity.keys) == Set(UInt64(0)...5) else { throw GatewayServiceError.invalidConfiguration }
        func blob(_ key: UInt64) throws -> Data {
            guard case .bytes(let bytes) = identity[key] else { throw GatewayServiceError.invalidConfiguration }; return bytes
        }
        func text(_ key: UInt64) throws -> String {
            guard case .text(let value) = fields[key] else { throw GatewayServiceError.invalidConfiguration }; return value
        }
        func uid(_ key: UInt64) throws -> uid_t {
            guard case .unsigned(let number) = fields[key], let result = uid_t(exactly: number) else { throw GatewayServiceError.invalidConfiguration }; return result
        }
        let hashValues = try hashes.map { value -> Data in
            guard case .bytes(let bytes) = value else { throw GatewayServiceError.invalidConfiguration }; return bytes
        }
        let result = try Self(registration: GatewayRegistrationIdentity(ownerID: blob(0), macID: blob(1), accountID: blob(2),
                gatewayID: blob(3), lifecycleEpoch: blob(4), rootPublicKey: blob(5)), receiptPublicKey: receiptKey,
            directoryPath: text(3), providerPath: text(4), receiptKeyPath: text(5), serviceUID: uid(6), ownerUID: uid(7),
            serviceName: text(8), teamID: team, authorityIdentifier: component, authorityHashes: Set(hashValues),
            project: text(11), packageName: text(12), settings: GatewayServiceSettings.decode(settingsValue),
            wakeEndpoint: fields[13].map { try GatewayWakeEndpointConfiguration.decode($0) })
        guard result.canonicalBytes == bytes else { throw GatewayServiceError.invalidConfiguration }
        return result
    }

    /// Native startup rechecks directory membership and the process groups before private access.
    func requireNativeProcess(validate: (uid_t, uid_t) throws -> Void = DedicatedServiceAccount.requireCurrent) throws {
        try requireProcess(realUID: getuid(), effectiveUID: geteuid())
        do { try validate(serviceUID, ownerUID) }
        catch { throw GatewayServiceError.wrongAccount }
    }
    func requireProcess(realUID: uid_t, effectiveUID: uid_t) throws {
        guard realUID == serviceUID, effectiveUID == serviceUID else { throw GatewayServiceError.wrongAccount }
    }
    private static var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 65536, maxDepth: 4, maxItems: 128) } }
    private static func validPath(_ path: String) -> Bool {
        let parts = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        return path.hasPrefix("/") && path.utf8.count < Int(PATH_MAX) && !parts.isEmpty &&
            parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }
    }
}
