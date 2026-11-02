import Darwin
import Foundation
import RemozioMach
import RemozioProtocol

public enum CommandFrontendConfigurationError: Error, Equatable { case invalidConfiguration }

/// Public installation metadata. Loading verifies provenance; decoding alone grants no authority.
public struct CommandFrontendConfiguration: Sendable {
    public let macID: Data
    public let accountID: Data
    public let serviceName: String
    public let teamID: String
    public let authorityIdentifier: String
    public let authorityPolicy: XPCPeerPolicy
    public let submissionLimits: CBORLimits
    public let defaultIOMode: CommandIOMode
    public let defaultDisconnectBehavior: StartedCommandDisconnect
    public let readiness: CommandCallerReadinessConfiguration
    public let canonicalBytes: Data

    public init(macID: Data, accountID: Data, serviceName: String, teamID: String,
                authorityIdentifier: String, authorityHashes: Set<Data>, submissionLimits: CBORLimits,
                defaultIOMode: CommandIOMode, defaultDisconnectBehavior: StartedCommandDisconnect,
                readiness: CommandCallerReadinessConfiguration) throws {
        guard macID.count == 16, accountID.count == 16, MacServiceNamespace.accepts(serviceName),
              !serviceName.isEmpty, serviceName.utf8.count < remozio_frontend_service_name_capacity(), serviceName.utf8.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45
              }), submissionLimits.maxBytes <= Int(UInt32.max) - 1024 else { throw Self.invalid }
        authorityPolicy = try XPCPeerPolicy(teamID: teamID, componentIdentifier: authorityIdentifier,
            approvedCodeDirectoryHashes: authorityHashes, expectedUserID: 0)
        self.macID = macID; self.accountID = accountID; self.serviceName = serviceName
        self.teamID = teamID; self.authorityIdentifier = authorityIdentifier
        self.submissionLimits = submissionLimits; self.defaultIOMode = defaultIOMode
        self.defaultDisconnectBehavior = defaultDisconnectBehavior; self.readiness = readiness
        canonicalBytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .text(serviceName),
            4: .text(teamID), 5: .text(authorityIdentifier),
            6: .array(authorityHashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)),
            7: .map([0: .unsigned(UInt64(submissionLimits.maxBytes)), 1: .unsigned(UInt64(submissionLimits.maxDepth)),
                     2: .unsigned(UInt64(submissionLimits.maxItems))]),
            8: .unsigned(defaultIOMode.rawValue), 9: .unsigned(defaultDisconnectBehavior.rawValue),
            10: .map([0: .unsigned(readiness.timeoutMilliseconds), 1: .unsigned(UInt64(readiness.initialBackoffMilliseconds)),
                      2: .unsigned(UInt64(readiness.maximumBackoffMilliseconds)),
                      3: .unsigned(UInt64(readiness.controlTimeoutMilliseconds))]),
        ]), limits: Self.metadataLimits())
    }

    /// A normal user can read this file. Root ownership and protected local ancestors remain mandatory.
    public static func load(path: String) throws -> Self {
        do { return try decode(ProtectedServiceConfiguration.readPublic(path: path)) }
        catch { throw invalid }
    }

    /// Reloads protected pins before a fresh handshake. Installation identity remains fixed for this invocation.
    public func reloadAuthorityPolicy(path: String) throws -> XPCPeerPolicy {
        try refreshedAuthorityPolicy(Self.load(path: path))
    }

    func refreshedAuthorityPolicy(_ current: Self) throws -> XPCPeerPolicy {
        guard current.macID == macID, current.accountID == accountID, current.serviceName == serviceName,
              current.teamID == teamID, current.authorityIdentifier == authorityIdentifier else { throw Self.invalid }
        return current.authorityPolicy
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: metadataLimits()),
              Set(fields.keys) == Set(UInt64(0)...10), fields[0] == .unsigned(1),
              case .bytes(let mac) = fields[1], case .bytes(let account) = fields[2],
              case .text(let service) = fields[3], case .text(let team) = fields[4], case .text(let identifier) = fields[5],
              case .array(let hashes) = fields[6], (1...16).contains(hashes.count),
              case .map(let limits) = fields[7], Set(limits.keys) == Set(UInt64(0)...2),
              case .unsigned(let mode) = fields[8], let io = CommandIOMode(rawValue: mode),
              case .unsigned(let disconnect) = fields[9], let lifetime = StartedCommandDisconnect(rawValue: disconnect),
              case .map(let wait) = fields[10], Set(wait.keys) == Set(UInt64(0)...3) else { throw invalid }
        func number(_ map: [UInt64: CBORValue], _ key: UInt64) throws -> UInt64 {
            guard case .unsigned(let value) = map[key] else { throw invalid }; return value
        }
        func integer(_ map: [UInt64: CBORValue], _ key: UInt64) throws -> Int {
            guard let value = Int(exactly: try number(map, key)) else { throw invalid }; return value
        }
        func duration(_ key: UInt64) throws -> UInt32 {
            guard let value = UInt32(exactly: try number(wait, key)) else { throw invalid }; return value
        }
        let values = try hashes.map { value -> Data in
            guard case .bytes(let data) = value else { throw invalid }; return data
        }
        let result = try Self(macID: mac, accountID: account, serviceName: service, teamID: team,
            authorityIdentifier: identifier, authorityHashes: Set(values),
            submissionLimits: CBORLimits(maxBytes: integer(limits, 0), maxDepth: integer(limits, 1), maxItems: integer(limits, 2)),
            defaultIOMode: io, defaultDisconnectBehavior: lifetime,
            readiness: CommandCallerReadinessConfiguration(timeoutMilliseconds: number(wait, 0),
                initialBackoffMilliseconds: duration(1), maximumBackoffMilliseconds: duration(2), controlTimeoutMilliseconds: duration(3)))
        guard result.canonicalBytes == bytes else { throw invalid }; return result
    }
    private static var invalid: CommandFrontendConfigurationError { .invalidConfiguration }
    private static func metadataLimits() throws -> CBORLimits {
        try CBORLimits(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 3, maxItems: 128)
    }
}
