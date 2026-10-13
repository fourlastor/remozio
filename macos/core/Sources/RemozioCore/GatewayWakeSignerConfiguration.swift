import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum GatewayWakeSignerError: Error, Equatable {
    case invalidConfiguration, invalidRecord, wrongAccount, wrongIdentity, unavailable
}

/// Custody is chosen during protected provisioning. Lookup failure never selects another source.
public enum GatewayWakeKeyCustody: UInt64, Sendable { case secureEnclave = 1, protectedFile = 2 }

/// Root-owned local metadata for a distinct wake key. Shared setup exports must exclude this configuration.
public struct GatewayWakeSignerConfiguration: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let binding: GatewaySubmissionBinding
    public let credentialID: Data
    public let transportUID: UInt32
    public let ownerUID: UInt32
    public let gatewayPolicy: XPCPeerPolicy
    public let serviceName: String
    public let custody: GatewayWakeKeyCustody
    public let keyRecordPath: String
    public let publicKey: Data
    public let timeoutMilliseconds: UInt64
    public let canonicalBytes: Data
    public var description: String { "GatewayWakeSignerConfiguration(redacted)" }
    public var debugDescription: String { description }

    public init(binding: GatewaySubmissionBinding, credentialID: Data, transportUID: UInt32, ownerUID: UInt32,
                gatewayUID: UInt32, serviceName: String, teamID: String, gatewayIdentifier: String,
                gatewayHashes: Set<Data>, custody: GatewayWakeKeyCustody, keyRecordPath: String,
                publicKey: Data, timeoutMilliseconds: UInt64 = 5000) throws {
        guard credentialID.count == 16, [transportUID, ownerUID, gatewayUID].allSatisfy({ $0 > 0 && $0 < UInt32.max }),
              Set([transportUID, ownerUID, gatewayUID]).count == 3,
              GatewayWakeEndpointConfiguration.validServiceName(serviceName),
              Self.validPath(keyRecordPath), (1...60_000).contains(timeoutMilliseconds),
              publicKey.count == 65, publicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil else {
            throw GatewayWakeSignerError.invalidConfiguration
        }
        gatewayPolicy = try XPCPeerPolicy(teamID: teamID, componentIdentifier: gatewayIdentifier,
            approvedCodeDirectoryHashes: gatewayHashes, expectedUserID: gatewayUID)
        self.binding = binding; self.credentialID = credentialID; self.transportUID = transportUID; self.ownerUID = ownerUID
        self.serviceName = serviceName; self.custody = custody; self.keyRecordPath = keyRecordPath; self.publicKey = publicKey
        self.timeoutMilliseconds = timeoutMilliseconds
        canonicalBytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: GatewayWakeKeyScope.encode(binding), 2: .bytes(credentialID),
            3: .unsigned(UInt64(transportUID)), 4: .unsigned(UInt64(ownerUID)), 5: .unsigned(UInt64(gatewayUID)),
            6: .text(serviceName), 7: .text(teamID), 8: .text(gatewayIdentifier),
            9: .array(gatewayHashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)),
            10: .unsigned(custody.rawValue), 11: .text(keyRecordPath), 12: .bytes(publicKey), 13: .unsigned(timeoutMilliseconds),
        ]), limits: Self.limits())
    }

    public static func load(path: String) throws -> Self {
        let value = try decode(ProtectedServiceConfiguration.readPublic(path: path))
        try value.requireNativeProcess()
        return value
    }
    /// Native startup rechecks directory membership and the process groups before private access.
    func requireNativeProcess(validate: (uid_t, uid_t) throws -> Void = DedicatedServiceAccount.requireCurrent) throws {
        try requireProcess(realUID: getuid(), effectiveUID: geteuid())
        do { try validate(transportUID, ownerUID) }
        catch { throw GatewayWakeSignerError.wrongAccount }
    }
    func requireProcess(realUID: UInt32, effectiveUID: UInt32) throws {
        guard realUID == transportUID, effectiveUID == transportUID else { throw GatewayWakeSignerError.wrongAccount }
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set(UInt64(0)...13), fields[0] == .unsigned(1), let scope = fields[1],
              case .bytes(let credential) = fields[2],
              case .unsigned(let transport) = fields[3], let transportUID = UInt32(exactly: transport),
              case .unsigned(let owner) = fields[4], let ownerUID = UInt32(exactly: owner),
              case .unsigned(let gateway) = fields[5], let gatewayUID = UInt32(exactly: gateway),
              case .text(let name) = fields[6], case .text(let team) = fields[7], case .text(let identifier) = fields[8],
              case .array(let hashes) = fields[9], (1...16).contains(hashes.count),
              case .unsigned(let mode) = fields[10], let custody = GatewayWakeKeyCustody(rawValue: mode),
              case .text(let path) = fields[11], case .bytes(let key) = fields[12], case .unsigned(let timeout) = fields[13] else {
            throw GatewayWakeSignerError.invalidConfiguration
        }
        let values = try hashes.map { value -> Data in
            guard case .bytes(let hash) = value else { throw GatewayWakeSignerError.invalidConfiguration }; return hash
        }
        let result = try Self(binding: GatewayWakeKeyScope.decode(scope), credentialID: credential,
            transportUID: transportUID, ownerUID: ownerUID, gatewayUID: gatewayUID, serviceName: name, teamID: team,
            gatewayIdentifier: identifier, gatewayHashes: Set(values), custody: custody, keyRecordPath: path,
            publicKey: key, timeoutMilliseconds: timeout)
        guard result.canonicalBytes == bytes else { throw GatewayWakeSignerError.invalidConfiguration }
        return result
    }
    private static func validPath(_ path: String) -> Bool {
        let parts = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        return path.hasPrefix("/") && !parts.isEmpty && path.utf8.count < Int(PATH_MAX) &&
            parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }
    }
    private static func limits() throws -> CBORLimits {
        try CBORLimits(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 2, maxItems: 128)
    }
}

enum GatewayWakeKeyScope {
    static func encode(_ binding: GatewaySubmissionBinding) -> CBORValue {
        .array([binding.ownerID, binding.macID, binding.accountID, binding.gatewayID, binding.lifecycleEpoch].map(CBORValue.bytes))
    }
    static func decode(_ value: CBORValue) throws -> GatewaySubmissionBinding {
        guard case .array(let fields) = value, fields.count == 5 else { throw GatewayWakeSignerError.invalidRecord }
        let ids = try fields.map { value -> Data in
            guard case .bytes(let id) = value, id.count == 16 else { throw GatewayWakeSignerError.invalidRecord }; return id
        }
        return try GatewaySubmissionBinding(ownerID: ids[0], macID: ids[1], accountID: ids[2], gatewayID: ids[3], lifecycleEpoch: ids[4])
    }
}
