import Foundation
import RemozioProtocol

/// Protected startup inputs for the shared request, wake and account presence owner.
public struct AuthorityPresenceStartupConfiguration: Sendable, CustomStringConvertible {
    public let wake: AuthorityWakeStartupConfiguration
    public let presence: AuthorityAccountPresenceConfiguration
    public let endpoint: AuthorityPresenceEndpointConfiguration
    public let pairing: AuthorityPairingSetupConfiguration?
    public let canonicalBytes: Data
    public var description: String { "AuthorityPresenceStartupConfiguration(redacted)" }
    public init(wake: AuthorityWakeStartupConfiguration, ownerUID: UInt32, appServiceName: String,
                teamID: String, appIdentifier: String, appHashes: Set<Data>, policy: PresenceConfiguration,
                pairing: AuthorityPairingSetupConfiguration? = nil) throws {
        guard ownerUID != wake.request.service.transportPolicy.expectedUserID, ownerUID != wake.gatewayPolicy.expectedUserID,
              appServiceName != wake.request.service.serviceName, appServiceName != wake.gatewayServiceName else { throw AuthorityPresenceError.invalidConfiguration }
        presence = try .init(macID: wake.request.service.macID, accountID: wake.request.service.accountID, ownerUID: ownerUID, policy: policy)
        endpoint = try .init(serviceName: appServiceName, appPolicy: .init(teamID: teamID, componentIdentifier: appIdentifier,
            approvedCodeDirectoryHashes: appHashes, expectedUserID: ownerUID))
        self.wake = wake; self.pairing = pairing
        var fields: [UInt64: CBORValue] = [0: .unsigned(pairing == nil ? 1 : 2), 1: .bytes(wake.canonicalBytes),
            2: .unsigned(UInt64(ownerUID)), 3: .text(appServiceName), 4: .text(teamID), 5: .text(appIdentifier),
            6: .array(appHashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)),
            7: .unsigned(policy.idleMilliseconds), 8: .unsigned(policy.observationLifetimeMilliseconds),
            9: .unsigned(policy.unavailableGraceMilliseconds)]
        if let pairing { fields[10] = .bytes(pairing.canonicalBytes) }
        canonicalBytes = try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    }
    public static func load(path: String) throws -> Self { try decode(ProtectedServiceConfiguration.read(path: path)) }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              (fields[0] == .unsigned(1) && Set(fields.keys) == Set(UInt64(0)...9)) ||
              (fields[0] == .unsigned(2) && Set(fields.keys) == Set(UInt64(0)...10)), case .bytes(let wake) = fields[1], case .unsigned(let uid) = fields[2], let ownerUID = UInt32(exactly: uid),
              case .text(let service) = fields[3], case .text(let team) = fields[4], case .text(let app) = fields[5],
              case .array(let hashes) = fields[6], case .unsigned(let idle) = fields[7], case .unsigned(let lifetime) = fields[8],
              case .unsigned(let grace) = fields[9] else { throw AuthorityPresenceError.invalidConfiguration }
        let values = try hashes.map { value -> Data in
            guard case .bytes(let bytes) = value else { throw AuthorityPresenceError.invalidConfiguration }; return bytes
        }
        let pairing: AuthorityPairingSetupConfiguration?
        if fields[0] == .unsigned(2) {
            guard case .bytes(let setup) = fields[10] else { throw AuthorityPresenceError.invalidConfiguration }
            pairing = try .decode(setup)
        } else { pairing = nil }
        let result = try Self(wake: .decode(wake), ownerUID: ownerUID, appServiceName: service, teamID: team, appIdentifier: app,
            appHashes: Set(values), policy: .init(idleMilliseconds: idle, observationLifetimeMilliseconds: lifetime,
                unavailableGraceMilliseconds: grace), pairing: pairing)
        guard result.canonicalBytes == bytes else { throw AuthorityPresenceError.invalidConfiguration }
        return result
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 2, maxItems: 48) } }
}

/// Public Root-owned metadata. It contains no private keys and grants no caller authority by itself.
public struct AuthorityPresenceClientConfiguration: Sendable, CustomStringConvertible {
    public let macID: Data
    public let accountID: Data
    public let ownerUID: UInt32
    public let serviceName: String
    public let rootPolicy: XPCPeerPolicy
    public let timeoutMilliseconds: UInt64
    public let canonicalBytes: Data
    public var description: String { "AuthorityPresenceClientConfiguration(redacted)" }
    public init(macID: Data, accountID: Data, ownerUID: UInt32, serviceName: String,
                teamID: String, rootIdentifier: String, rootHashes: Set<Data>, timeoutMilliseconds: UInt64 = 5000) throws {
        guard macID.count == 16, accountID.count == 16, ownerUID > 0, ownerUID < UInt32.max,
              GatewayWakeEndpointConfiguration.validServiceName(serviceName), (1...60_000).contains(timeoutMilliseconds) else {
            throw AuthorityPresenceError.invalidConfiguration
        }
        rootPolicy = try .init(teamID: teamID, componentIdentifier: rootIdentifier, approvedCodeDirectoryHashes: rootHashes, expectedUserID: 0)
        self.macID = macID; self.accountID = accountID; self.ownerUID = ownerUID; self.serviceName = serviceName
        self.timeoutMilliseconds = timeoutMilliseconds
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID),
            3: .unsigned(UInt64(ownerUID)), 4: .text(serviceName), 5: .text(teamID), 6: .text(rootIdentifier),
            7: .array(rootHashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)), 8: .unsigned(timeoutMilliseconds)]), limits: Self.limits)
    }
    public static func load(path: String) throws -> Self { try decode(ProtectedServiceConfiguration.readPublic(path: path)) }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...8),
              fields[0] == .unsigned(1), case .bytes(let mac) = fields[1], case .bytes(let account) = fields[2],
              case .unsigned(let uid) = fields[3], let ownerUID = UInt32(exactly: uid), case .text(let service) = fields[4],
              case .text(let team) = fields[5], case .text(let root) = fields[6], case .array(let hashes) = fields[7],
              case .unsigned(let timeout) = fields[8] else { throw AuthorityPresenceError.invalidConfiguration }
        let values = try hashes.map { value -> Data in
            guard case .bytes(let bytes) = value else { throw AuthorityPresenceError.invalidConfiguration }; return bytes
        }
        let result = try Self(macID: mac, accountID: account, ownerUID: ownerUID, serviceName: service,
            teamID: team, rootIdentifier: root, rootHashes: Set(values), timeoutMilliseconds: timeout)
        guard result.canonicalBytes == bytes else { throw AuthorityPresenceError.invalidConfiguration }
        return result
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 4096, maxDepth: 2, maxItems: 48) } }
}
