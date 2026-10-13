import Darwin
import Foundation
import RemozioProtocol

public enum ApprovalTransportStartupError: Error, Equatable { case invalidConfiguration, wrongAccount, identityUnavailable, invalidIdentity }

public enum ApprovalTransportIdentitySource: Sendable, Equatable {
    case secureEnclaveKeychain(reference: Data)
    case protectedFile(path: String)
}

/// Root-owned installation metadata. Identity locations contain no private key bytes.
public struct ApprovalTransportConfiguration: Sendable, CustomStringConvertible {
    public let macID: Data
    public let accountID: Data
    public let ownerUID: UInt32
    public let serviceUID: UInt32
    public let authorityServiceName: String
    public let authorityPolicy: XPCPeerPolicy
    public let identitySource: ApprovalTransportIdentitySource
    public var identityReference: Data? {
        if case .secureEnclaveKeychain(let reference) = identitySource { return reference }
        return nil
    }
    public let identityPublicKeyInfo: Data
    public let maximumConnections: Int
    public let timeoutMilliseconds: UInt64
    public let refreshMilliseconds: UInt64
    public let canonicalBytes: Data
    public var description: String { "ApprovalTransportConfiguration(redacted)" }

    public init(macID: Data, accountID: Data, ownerUID: UInt32, serviceUID: UInt32, authorityServiceName: String,
                teamID: String, authorityIdentifier: String, authorityHashes: Set<Data>, identityReference: Data,
                identityPublicKeyInfo: Data, maximumConnections: Int = 8, timeoutMilliseconds: UInt64 = 15_000,
                refreshMilliseconds: UInt64 = 5000) throws {
        try self.init(macID: macID, accountID: accountID, ownerUID: ownerUID, serviceUID: serviceUID,
            authorityServiceName: authorityServiceName, teamID: teamID, authorityIdentifier: authorityIdentifier,
            authorityHashes: authorityHashes, identitySource: .secureEnclaveKeychain(reference: identityReference),
            identityPublicKeyInfo: identityPublicKeyInfo, maximumConnections: maximumConnections,
            timeoutMilliseconds: timeoutMilliseconds, refreshMilliseconds: refreshMilliseconds)
    }

    public init(macID: Data, accountID: Data, ownerUID: UInt32, serviceUID: UInt32, authorityServiceName: String,
                teamID: String, authorityIdentifier: String, authorityHashes: Set<Data>,
                identitySource: ApprovalTransportIdentitySource, identityPublicKeyInfo: Data,
                maximumConnections: Int = 8, timeoutMilliseconds: UInt64 = 15_000,
                refreshMilliseconds: UInt64 = 5000) throws {
        guard macID.count == 16, accountID.count == 16, ownerUID > 0, ownerUID < UInt32.max,
              serviceUID > 0, serviceUID < UInt32.max, serviceUID != ownerUID,
              authorityServiceName.hasPrefix("dev.remozio."), (1...255).contains(authorityServiceName.utf8.count),
              authorityServiceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) ||
                  (97...122).contains($0) || $0 == 46 || $0 == 45 }),
              (1...64).contains(maximumConnections),
              (1...60_000).contains(timeoutMilliseconds), (500...60_000).contains(refreshMilliseconds) else {
            throw ApprovalTransportStartupError.invalidConfiguration
        }
        let version: UInt64, location: CBORValue
        switch identitySource {
        case .secureEnclaveKeychain(let reference):
            guard (1...4096).contains(reference.count) else { throw ApprovalTransportStartupError.invalidConfiguration }
            version = 1; location = .bytes(reference)
        case .protectedFile(let path):
            let parts = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
            guard path.hasPrefix("/"), !parts.isEmpty, path.utf8.count < Int(PATH_MAX),
                  parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }) else {
                throw ApprovalTransportStartupError.invalidConfiguration
            }
            version = 2; location = .text(path)
        }
        _ = try PinnedTLSPeer(subjectPublicKeyInfo: identityPublicKeyInfo)
        authorityPolicy = try XPCPeerPolicy(teamID: teamID, componentIdentifier: authorityIdentifier,
            approvedCodeDirectoryHashes: authorityHashes, expectedUserID: 0)
        self.macID = macID; self.accountID = accountID; self.ownerUID = ownerUID; self.serviceUID = serviceUID
        self.authorityServiceName = authorityServiceName; self.identitySource = identitySource
        self.identityPublicKeyInfo = identityPublicKeyInfo; self.maximumConnections = maximumConnections
        self.timeoutMilliseconds = timeoutMilliseconds; self.refreshMilliseconds = refreshMilliseconds
        canonicalBytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(version), 1: .bytes(macID), 2: .bytes(accountID), 3: .unsigned(UInt64(ownerUID)),
            4: .unsigned(UInt64(serviceUID)), 5: .text(authorityServiceName), 6: .text(teamID),
            7: .text(authorityIdentifier),
            8: .array(authorityHashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)),
            9: location, 10: .bytes(identityPublicKeyInfo), 11: .unsigned(UInt64(maximumConnections)),
            12: .unsigned(timeoutMilliseconds), 13: .unsigned(refreshMilliseconds),
        ]), limits: Self.limits())
    }

    /// Public metadata still requires Root ownership and protected local ancestors. No keychain lookup occurs here.
    public static func load(path: String) throws -> Self {
        let value = try decode(ProtectedServiceConfiguration.readPublic(path: path))
        try value.requireNativeProcess()
        return value
    }
    /// Native startup rechecks directory membership and the process groups before private access.
    func requireNativeProcess(validate: (uid_t, uid_t) throws -> Void = DedicatedServiceAccount.requireCurrent) throws {
        try requireProcess(realUID: getuid(), effectiveUID: geteuid())
        do { try validate(serviceUID, ownerUID) }
        catch { throw ApprovalTransportStartupError.wrongAccount }
    }
    func requireProcess(realUID: UInt32, effectiveUID: UInt32) throws {
        guard realUID == serviceUID, effectiveUID == serviceUID else { throw ApprovalTransportStartupError.wrongAccount }
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set(UInt64(0)...13),
              case .bytes(let mac) = fields[1], case .bytes(let account) = fields[2],
              case .unsigned(let owner) = fields[3], let ownerUID = UInt32(exactly: owner),
              case .unsigned(let service) = fields[4], let serviceUID = UInt32(exactly: service),
              case .text(let name) = fields[5], case .text(let team) = fields[6], case .text(let identifier) = fields[7],
              case .array(let hashes) = fields[8], (1...16).contains(hashes.count),
              case .bytes(let key) = fields[10],
              case .unsigned(let connections) = fields[11], let maximum = Int(exactly: connections),
              case .unsigned(let timeout) = fields[12], case .unsigned(let refresh) = fields[13] else {
            throw ApprovalTransportStartupError.invalidConfiguration
        }
        let source: ApprovalTransportIdentitySource
        switch (fields[0], fields[9]) {
        case (.unsigned(1), .bytes(let reference)): source = .secureEnclaveKeychain(reference: reference)
        case (.unsigned(2), .text(let path)): source = .protectedFile(path: path)
        default: throw ApprovalTransportStartupError.invalidConfiguration
        }
        let values = try hashes.map { value -> Data in
            guard case .bytes(let hash) = value else { throw ApprovalTransportStartupError.invalidConfiguration }; return hash
        }
        let result = try Self(macID: mac, accountID: account, ownerUID: ownerUID, serviceUID: serviceUID,
            authorityServiceName: name, teamID: team, authorityIdentifier: identifier, authorityHashes: Set(values),
            identitySource: source, identityPublicKeyInfo: key, maximumConnections: maximum,
            timeoutMilliseconds: timeout, refreshMilliseconds: refresh)
        guard result.canonicalBytes == bytes else { throw ApprovalTransportStartupError.invalidConfiguration }
        return result
    }
    private static func limits() throws -> CBORLimits {
        try CBORLimits(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 2, maxItems: 128)
    }
}
