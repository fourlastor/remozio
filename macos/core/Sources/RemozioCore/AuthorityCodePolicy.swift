import Foundation
import RemozioProtocol

public enum AuthorityCodePolicyError: Error, Equatable {
    case invalidPolicy, staleRevision, removedRole, identityChanged, rollback, corruptData
}

/// Stable storage identifiers. Extending this catalog requires a new policy format.
public enum AuthorityCodeRole: UInt64, CaseIterable, Sendable {
    case app = 1, authority, guiAgent, transport, commandFrontend, notificationGateway
    case tunnelClient, setupController, bridgeEndpoint, bridgeCommand, commandChild, commandMonitor
}

/// Retained installation metadata. Construction does not verify a binary or authorize its activation.
public struct AuthorityCodeEntry: Hashable, Sendable {
    public let role: AuthorityCodeRole
    public let teamID: String
    public let identifier: String
    public let installedGeneration: UInt64
    public let minimumGeneration: UInt64
    public let codeDirectoryHash: Data
    public let active: Bool

    public init(role: AuthorityCodeRole, teamID: String, identifier: String, installedGeneration: UInt64,
                minimumGeneration: UInt64, codeDirectoryHash: Data, active: Bool) throws {
        guard teamID.utf8.count == 10, teamID.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) }),
              (1...255).contains(identifier.utf8.count), identifier.utf8.allSatisfy({
                  (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 46 || $0 == 45
              }), minimumGeneration > 0, installedGeneration >= minimumGeneration, codeDirectoryHash.count == 20 else {
            throw AuthorityCodePolicyError.invalidPolicy
        }
        self.role = role; self.teamID = teamID; self.identifier = identifier
        self.installedGeneration = installedGeneration; self.minimumGeneration = minimumGeneration
        self.codeDirectoryHash = codeDirectoryHash; self.active = active
    }
}

/// Includes inactive roles so disabling a component cannot erase its security floor.
public struct AuthorityCodePolicy: Hashable, Sendable {
    public let formatVersion: UInt64
    public let entries: [AuthorityCodeEntry]
    public init(entries: [AuthorityCodeEntry]) throws {
        try self.init(entries: entries, formatVersion: 3)
    }

    private init(entries: [AuthorityCodeEntry], formatVersion: UInt64) throws {
        guard (1...3).contains(formatVersion) else { throw AuthorityCodePolicyError.invalidPolicy }
        let maximumRole: UInt64 = formatVersion == 1 ? 10 : formatVersion == 2 ? 11 : 12
        guard !entries.isEmpty, entries.count <= Int(maximumRole),
              entries.allSatisfy({ $0.role.rawValue <= maximumRole }),
              Set(entries.map(\.role)).count == entries.count else { throw AuthorityCodePolicyError.invalidPolicy }
        self.formatVersion = formatVersion
        self.entries = entries.sorted { $0.role.rawValue < $1.role.rawValue }
    }

    /// Keeps the retained format while preparing changed values. The owner must separately validate a policy successor.
    func retainingFormat(with entries: [AuthorityCodeEntry]) throws -> Self {
        try .init(entries: entries, formatVersion: formatVersion)
    }

    func requireSuccessor(of previous: Self) throws {
        guard formatVersion >= previous.formatVersion else { throw AuthorityCodePolicyError.rollback }
        for old in previous.entries {
            guard let next = entries.first(where: { $0.role == old.role }) else { throw AuthorityCodePolicyError.removedRole }
            guard next.teamID == old.teamID, next.identifier == old.identifier else { throw AuthorityCodePolicyError.identityChanged }
            guard next.installedGeneration >= old.installedGeneration, next.minimumGeneration >= old.minimumGeneration else {
                throw AuthorityCodePolicyError.rollback
            }
        }
    }

    // Encoding and decoding are pure functions of the value and of the exact bytes, and verification repeats both.
    private static let encodings = PureResultMemo<AuthorityCodePolicy, Data>()
    private static let decodings = PureResultMemo<Data, AuthorityCodePolicy>()

    var bytes: Data {
        get throws { try Self.encodings.value(for: self) { try encodedBytes() } }
    }

    private func encodedBytes() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(formatVersion), 1: .array(entries.map { entry in
            .map([0: .unsigned(entry.role.rawValue), 1: .text(entry.teamID), 2: .text(entry.identifier),
                  3: .unsigned(entry.installedGeneration), 4: .unsigned(entry.minimumGeneration),
                  5: .bytes(entry.codeDirectoryHash), 6: .unsigned(entry.active ? 1 : 0)])
        })]), limits: Self.limits())
    }

    static let maximumBytes = 8192
    private static func limits() throws -> CBORLimits { try CBORLimits(maxBytes: maximumBytes, maxDepth: 4, maxItems: 256) }
    static func decode(_ bytes: Data) throws -> Self {
        try decodings.value(for: bytes) { try decodeUncached(bytes) }
    }

    private static func decodeUncached(_ bytes: Data) throws -> Self {
        do {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
                  fields.count == 2, case .unsigned(let version) = fields[0], case .array(let entries) = fields[1] else {
                throw AuthorityCodePolicyError.corruptData
            }
            let value = try Self(entries: entries.map { item in
                guard case .map(let fields) = item, Set(fields.keys) == Set((0...6).map(UInt64.init)),
                      case .unsigned(let roleValue) = fields[0], let role = AuthorityCodeRole(rawValue: roleValue),
                      case .text(let team) = fields[1], case .text(let identifier) = fields[2],
                      case .unsigned(let installed) = fields[3], case .unsigned(let minimum) = fields[4],
                      case .bytes(let hash) = fields[5], case .unsigned(let active) = fields[6], active <= 1 else {
                    throw AuthorityCodePolicyError.corruptData
                }
                return try AuthorityCodeEntry(role: role, teamID: team, identifier: identifier, installedGeneration: installed,
                    minimumGeneration: minimum, codeDirectoryHash: hash, active: active == 1)
            }, formatVersion: version)
            guard try value.bytes == bytes else { throw AuthorityCodePolicyError.corruptData }
            return value
        } catch { throw AuthorityCodePolicyError.corruptData }
    }
}

public struct AuthorityCodePolicySnapshot: Equatable, Sendable {
    public let revision: UUID
    public let policy: AuthorityCodePolicy
    /// Retained change tokens. Only the journal generates them; callers cannot choose a successor token.
    public let roleRevisions: [AuthorityCodeRole: UUID]

    var storedBytes: Data {
        get throws {
            guard Set(roleRevisions.keys) == Set(policy.entries.map(\.role)) else { throw AuthorityCodePolicyError.corruptData }
            let roles = Dictionary(uniqueKeysWithValues: roleRevisions.map { role, revision in
                var value = revision.uuid
                return (role.rawValue, CBORValue.bytes(withUnsafeBytes(of: &value) { Data($0) }))
            })
            return try DeterministicCBOR.encode(.map([0: .unsigned(2), 1: .bytes(policy.bytes), 2: .map(roles)]), limits: Self.limits())
        }
    }

    static func decodeStored(_ bytes: Data, revision: UUID) throws -> Self {
        do {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
                  case .unsigned(let version) = fields[0] else { throw AuthorityCodePolicyError.corruptData }
            if version == 1 {
                let policy = try AuthorityCodePolicy.decode(bytes)
                // Legacy rows use their protected global revision until the first changed write retains role tokens.
                return Self(revision: revision, policy: policy,
                    roleRevisions: Dictionary(uniqueKeysWithValues: policy.entries.map { ($0.role, revision) }))
            }
            guard version == 2, Set(fields.keys) == [0, 1, 2], case .bytes(let policyBytes) = fields[1],
                  case .map(let roles) = fields[2] else { throw AuthorityCodePolicyError.corruptData }
            let policy = try AuthorityCodePolicy.decode(policyBytes)
            var revisions = [AuthorityCodeRole: UUID]()
            for (key, value) in roles {
                guard let role = AuthorityCodeRole(rawValue: key), case .bytes(let bytes) = value, bytes.count == 16 else {
                    throw AuthorityCodePolicyError.corruptData
                }
                revisions[role] = bytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
            }
            let result = Self(revision: revision, policy: policy, roleRevisions: revisions)
            guard try result.storedBytes == bytes else { throw AuthorityCodePolicyError.corruptData }
            return result
        } catch { throw AuthorityCodePolicyError.corruptData }
    }
    private static func limits() throws -> CBORLimits {
        try CBORLimits(maxBytes: AuthorityCodePolicy.maximumBytes, maxDepth: 4, maxItems: 256)
    }
}
