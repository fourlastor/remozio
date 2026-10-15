import CryptoKit
import Foundation
import RemozioProtocol

enum ServiceAccountProvisioningError: Error, Equatable {
    case invalidPlan, conflictingRecord, missingRecord, changedScope, unavailable, exhausted, incomplete
}
enum ServiceAccountRole: UInt64, Sendable { case transport = 4, gateway = 6 }

/// A retained record claim. Matching a name alone never proves ownership.
struct ServiceAccountClaim: Equatable, Sendable, CustomStringConvertible {
    let accountID: Data
    let role: ServiceAccountRole
    let number: UInt32
    let userID: UUID
    let groupID: UUID
    var description: String { "ServiceAccountClaim(redacted)" }
    var name: String { Self.recordName(accountID: accountID, role: role) }
    static func recordName(accountID: Data, role: ServiceAccountRole) -> String {
        let prefix: String
        switch role { case .transport: prefix = "t"; case .gateway: prefix = "g" }
        let suffix = SHA256.hash(data: accountID).prefix(12).map { String(format: "%02x", $0) }.joined()
        return "_rmz_" + prefix + "_" + suffix
    }
    init(accountID: Data, role: ServiceAccountRole, number: UInt32, userID: UUID, groupID: UUID) throws {
        guard accountID.count == 16, number > 0, number < UInt32.max, number != 80, userID != groupID else {
            throw ServiceAccountProvisioningError.invalidPlan
        }
        self.accountID = accountID; self.role = role; self.number = number; self.userID = userID; self.groupID = groupID
    }
    fileprivate var value: CBORValue {
        .array([.unsigned(role.rawValue), .unsigned(UInt64(number)), .bytes(ServiceAccountPlan.bytes(userID)), .bytes(ServiceAccountPlan.bytes(groupID))])
    }
}

/// Frozen setup inputs, retained before any directory write. This value grants no provisioning or runtime authority.
struct ServiceAccountPlan: Equatable, Sendable, CustomStringConvertible {
    // Version 1 provisions these roles. Future optional roles must not change old record semantics.
    static let roles: [ServiceAccountRole] = [.transport, .gateway]
    let planID: Data
    let macID: Data
    let accountID: Data
    let accountSetupID: Data
    let installationID: Data
    let releaseDigest: Data
    let ownerUID: UInt32
    let ownerDirectoryID: UUID
    let authorityPublicKey: Data
    let claims: [ServiceAccountClaim]
    var description: String { "ServiceAccountPlan(redacted)" }

    init(account: AccountPreparationIntent, planID: Data, claims: [ServiceAccountClaim]) throws {
        guard account.storagePrepared, let pin = account.authorityPublicKey else { throw ServiceAccountProvisioningError.incomplete }
        try self.init(planID: planID, macID: account.macID, accountID: account.accountID, accountSetupID: account.setupID,
            installationID: account.installationID, releaseDigest: account.releaseDigest, ownerUID: account.ownerUID,
            ownerDirectoryID: account.directoryID, authorityPublicKey: pin, claims: claims)
    }
    private init(planID: Data, macID: Data, accountID: Data, accountSetupID: Data, installationID: Data,
                 releaseDigest: Data, ownerUID: UInt32, ownerDirectoryID: UUID, authorityPublicKey: Data,
                 claims: [ServiceAccountClaim]) throws {
        guard [planID, macID, accountID, accountSetupID, installationID].allSatisfy({ $0.count == 16 }),
              releaseDigest.count == 32, ownerUID > 0, ownerUID < UInt32.max,
              authorityPublicKey.count == 65, authorityPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: authorityPublicKey)) != nil,
              claims.count == Self.roles.count,
              Set(claims.map(\.role)) == Set(Self.roles),
              Set(claims.map(\.number)).count == claims.count,
              claims.allSatisfy({ $0.accountID == accountID && $0.number != ownerUID }),
              Set(claims.flatMap { [$0.userID, $0.groupID] }).count == claims.count * 2,
              !claims.contains(where: { $0.userID == ownerDirectoryID || $0.groupID == ownerDirectoryID }) else {
            throw ServiceAccountProvisioningError.invalidPlan
        }
        self.planID = planID; self.macID = macID; self.accountID = accountID; self.accountSetupID = accountSetupID
        self.installationID = installationID; self.releaseDigest = releaseDigest; self.ownerUID = ownerUID
        self.ownerDirectoryID = ownerDirectoryID; self.authorityPublicKey = authorityPublicKey
        self.claims = claims.sorted { $0.role.rawValue < $1.role.rawValue }
    }
    func validate(account: AccountPreparationIntent) throws {
        guard account.storagePrepared, macID == account.macID, accountID == account.accountID, accountSetupID == account.setupID,
              installationID == account.installationID, releaseDigest == account.releaseDigest, ownerUID == account.ownerUID,
              ownerDirectoryID == account.directoryID, authorityPublicKey == account.authorityPublicKey else {
            throw ServiceAccountProvisioningError.changedScope
        }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(accountSetupID),
            4: .bytes(installationID), 5: .bytes(releaseDigest), 6: .unsigned(UInt64(ownerUID)),
            7: .bytes(Self.bytes(ownerDirectoryID)), 8: .bytes(authorityPublicKey), 9: .bytes(planID),
            10: .array(claims.map(\.value))]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...10),
              f[0] == .unsigned(1), case .bytes(let mac) = f[1], case .bytes(let account) = f[2],
              case .bytes(let setup) = f[3], case .bytes(let installation) = f[4], case .bytes(let release) = f[5],
              case .unsigned(let rawUID) = f[6], let uid = UInt32(exactly: rawUID),
              case .bytes(let owner) = f[7], case .bytes(let pin) = f[8], case .bytes(let plan) = f[9],
              case .array(let rows) = f[10], rows.count == Self.roles.count else {
            throw ServiceAccountProvisioningError.invalidPlan
        }
        let claims = try rows.map { row -> ServiceAccountClaim in
            guard case .array(let fields) = row, fields.count == 4, case .unsigned(let role) = fields[0],
                  let kind = ServiceAccountRole(rawValue: role), case .unsigned(let raw) = fields[1], let number = UInt32(exactly: raw),
                  case .bytes(let user) = fields[2], case .bytes(let group) = fields[3] else { throw ServiceAccountProvisioningError.invalidPlan }
            return try .init(accountID: account, role: kind, number: number, userID: uuid(user), groupID: uuid(group))
        }
        let value = try Self(planID: plan, macID: mac, accountID: account, accountSetupID: setup, installationID: installation,
            releaseDigest: release, ownerUID: uid, ownerDirectoryID: uuid(owner), authorityPublicKey: pin, claims: claims)
        guard try value.encoded == bytes else { throw ServiceAccountProvisioningError.invalidPlan }
        return value
    }
    static func bytes(_ id: UUID) -> Data { var value = id.uuid; return withUnsafeBytes(of: &value) { Data($0) } }
    private static func uuid(_ bytes: Data) throws -> UUID {
        guard bytes.count == 16 else { throw ServiceAccountProvisioningError.invalidPlan }
        return bytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 4096, maxDepth: 3, maxItems: 96) } }
}
