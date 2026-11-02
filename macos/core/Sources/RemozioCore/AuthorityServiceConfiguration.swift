import Darwin
import Foundation
import RemozioProtocol

public enum AuthorityServiceConfigurationError: Error { case invalidConfiguration }

/// Protected launch inputs. They contain no key material and grant no request approval authority.
public struct AuthorityServiceConfiguration: Sendable {
    public static let defaultMaximumPayloadBytes = 262_144
    public let macID: Data
    public let accountID: Data
    public let continuityDirectory: String?
    public let journalDirectory: String
    public let serviceName: String
    public let transportPolicy: XPCPeerPolicy
    public let maximumPayloadBytes: Int
    /// Reserves the signed carrier inside the configured channel payload budget.
    public var maximumRequestBodyBytes: Int { Self.requestBodyLimit(maximumPayloadBytes) }
    static func requestBodyLimit(_ maximumPayloadBytes: Int) -> Int {
        max(1, maximumPayloadBytes - ApprovalMessage.overheadBytes)
    }
    public let minimumEnvelopeVersion: UInt64
    public let auditVersions: Set<UInt64>
    public let maximumConnections: Int
    public let handshakeTimeoutMilliseconds: UInt64
    public let maximumOperations: Int
    public let canonicalBytes: Data

    public init(macID: Data, accountID: Data, journalDirectory: String, serviceName: String,
                teamID: String, transportIdentifier: String, transportHashes: Set<Data>, transportUID: UInt32,
                maximumPayloadBytes: Int = AuthorityServiceConfiguration.defaultMaximumPayloadBytes, minimumEnvelopeVersion: UInt64 = 1, auditVersions: Set<UInt64> = [],
                maximumConnections: Int = 8, handshakeTimeoutMilliseconds: UInt64 = 5000, maximumOperations: Int = 8,
                continuityDirectory: String? = nil) throws {
        let components = journalDirectory.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard macID.count == 16, accountID.count == 16, transportUID > 0, transportUID < UInt32.max,
              journalDirectory.hasPrefix("/"), journalDirectory.utf8.count < Int(PATH_MAX), !components.isEmpty,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              MacServiceNamespace.accepts(serviceName), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }),
              (1...16_777_216).contains(maximumPayloadBytes), minimumEnvelopeVersion > 0,
              auditVersions.count <= 16, !auditVersions.contains(0), (1...64).contains(maximumConnections),
              (1...60_000).contains(handshakeTimeoutMilliseconds), (1...64).contains(maximumOperations) else { throw Self.invalid }
        if let continuityDirectory {
            let parts = continuityDirectory.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
            guard continuityDirectory.hasPrefix("/"), continuityDirectory.utf8.count < Int(PATH_MAX), !parts.isEmpty,
                  parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
                  continuityDirectory != journalDirectory,
                  !continuityDirectory.hasPrefix(journalDirectory + "/"),
                  !journalDirectory.hasPrefix(continuityDirectory + "/") else { throw Self.invalid }
        }
        self.continuityDirectory = continuityDirectory
        transportPolicy = try XPCPeerPolicy(teamID: teamID, componentIdentifier: transportIdentifier,
            approvedCodeDirectoryHashes: transportHashes, expectedUserID: transportUID)
        self.macID = macID; self.accountID = accountID; self.journalDirectory = journalDirectory; self.serviceName = serviceName
        self.maximumPayloadBytes = maximumPayloadBytes; self.minimumEnvelopeVersion = minimumEnvelopeVersion
        self.auditVersions = auditVersions; self.maximumConnections = maximumConnections
        self.handshakeTimeoutMilliseconds = handshakeTimeoutMilliseconds; self.maximumOperations = maximumOperations
        var fields: [UInt64: CBORValue] = [
            0: .unsigned(continuityDirectory == nil ? 1 : 2), 1: .bytes(macID), 2: .bytes(accountID), 3: .text(journalDirectory), 4: .text(serviceName),
            5: .text(teamID), 6: .text(transportIdentifier), 7: .array(transportHashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)),
            8: .unsigned(UInt64(transportUID)), 9: .unsigned(UInt64(maximumPayloadBytes)), 10: .unsigned(minimumEnvelopeVersion),
            11: .array(auditVersions.sorted().map(CBORValue.unsigned)), 12: .unsigned(UInt64(maximumConnections)),
            13: .unsigned(handshakeTimeoutMilliseconds), 14: .unsigned(UInt64(maximumOperations)),
        ]
        if let continuityDirectory { fields[15] = .text(continuityDirectory) }
        canonicalBytes = try DeterministicCBOR.encode(.map(fields), limits: Self.limits())
    }
    public static func load(path: String) throws -> AuthorityServiceConfiguration {
        try decode(ProtectedServiceConfiguration.read(path: path))
    }
    /// Parsing alone does not establish provenance. Runtime startup must use load(path:).
    public static func decode(_ bytes: Data) throws -> AuthorityServiceConfiguration {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              case .unsigned(let version) = fields[0], (1...2).contains(version),
              Set(fields.keys) == Set((0...(version == 1 ? 14 : 15)).map(UInt64.init)),
              case .bytes(let mac) = fields[1], case .bytes(let account) = fields[2],
              case .array(let hashes) = fields[7], (1...16).contains(hashes.count),
              case .array(let audits) = fields[11], audits.count <= 16 else { throw invalid }
        func string(_ key: UInt64) throws -> String {
            guard case .text(let value) = fields[key] else { throw invalid }; return value
        }
        func number(_ key: UInt64) throws -> UInt64 {
            guard case .unsigned(let value) = fields[key] else { throw invalid }; return value
        }
        func integer(_ key: UInt64) throws -> Int {
            guard let result = Int(exactly: try number(key)) else { throw invalid }; return result
        }
        guard let uid = UInt32(exactly: try number(8)) else { throw invalid }
        let hashValues = try hashes.map { value -> Data in
            guard case .bytes(let data) = value else { throw invalid }; return data
        }
        let auditValues = try audits.map { value -> UInt64 in
            guard case .unsigned(let version) = value else { throw invalid }; return version
        }
        let result = try AuthorityServiceConfiguration(macID: mac, accountID: account, journalDirectory: string(3), serviceName: string(4),
            teamID: string(5), transportIdentifier: string(6), transportHashes: Set(hashValues), transportUID: uid,
            maximumPayloadBytes: integer(9), minimumEnvelopeVersion: number(10), auditVersions: Set(auditValues),
            maximumConnections: integer(12), handshakeTimeoutMilliseconds: number(13), maximumOperations: integer(14),
            continuityDirectory: version == 2 ? string(15) : nil)
        guard result.canonicalBytes == bytes else { throw invalid }; return result
    }
    private static var invalid: AuthorityServiceConfigurationError { .invalidConfiguration }
    private static func limits() throws -> CBORLimits {
        try CBORLimits(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 3, maxItems: 128)
    }
}
