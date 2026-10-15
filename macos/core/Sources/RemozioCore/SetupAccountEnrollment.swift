import Foundation
import RemozioProtocol

/// Explicit command setup choices. The Root endpoint derives the caller and account identity independently.
public struct AccountEnrollmentRequest: Equatable, Sendable {
    public let allowedTargetUIDs: Set<UInt32>
    public let independentPolicyDisclosureAccepted: Bool
    public init(allowedTargetUIDs: Set<UInt32>, independentPolicyDisclosureAccepted: Bool) throws {
        guard allowedTargetUIDs.count <= 64, !allowedTargetUIDs.contains(UInt32.max) else { throw AccountPreparationError.invalidRecord }
        guard independentPolicyDisclosureAccepted else { throw CommandElevationPolicyError.disclosureRequired }
        self.allowedTargetUIDs = allowedTargetUIDs
        self.independentPolicyDisclosureAccepted = independentPolicyDisclosureAccepted
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .array(allowedTargetUIDs.sorted().map { .unsigned(UInt64($0)) }),
            2: .boolean(independentPolicyDisclosureAccepted)]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == [0, 1, 2],
              f[0] == .unsigned(1), case .array(let raw) = f[1], raw.count <= 64, case .boolean(let accepted) = f[2] else {
            throw AccountPreparationError.invalidRecord
        }
        let targets = try raw.map { value -> UInt32 in
            guard case .unsigned(let uid) = value, let result = UInt32(exactly: uid) else { throw AccountPreparationError.invalidRecord }
            return result
        }
        let value = try Self(allowedTargetUIDs: Set(targets), independentPolicyDisclosureAccepted: accepted)
        guard try value.bytes == bytes else { throw AccountPreparationError.invalidRecord }
        return value
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 1024, maxDepth: 2, maxItems: 96) } }
}

/// Setup progress for this Mac account. It does not assert service registration, phone pairing or command readiness.
public struct SetupAccountEnrollmentProgress: Equatable, Sendable {
    public let macID: Data
    public let accountID: Data
    public let setupID: Data
    public let revision: Data
    public let ownerUID: UInt32
    public let allowedTargetUIDs: Set<UInt32>
    public let keyPrepared: Bool
    public let storagePrepared: Bool
    init(_ value: AccountPreparationIntent) throws {
        macID = value.macID; accountID = value.accountID; setupID = value.setupID; revision = value.revision
        ownerUID = value.ownerUID; allowedTargetUIDs = try value.commandPolicy.allowedTargetUIDs
        keyPrepared = value.authorityPublicKey != nil; storagePrepared = value.storagePrepared
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(setupID), 4: .bytes(revision),
            5: .unsigned(UInt64(ownerUID)), 6: .array(allowedTargetUIDs.sorted().map { .unsigned(UInt64($0)) }),
            7: .boolean(keyPrepared), 8: .boolean(storagePrepared)]), limits: AccountEnrollmentRequest.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: AccountEnrollmentRequest.limits), Set(f.keys) == Set(UInt64(0)...8),
              f[0] == .unsigned(1), case .bytes(let mac) = f[1], case .bytes(let account) = f[2],
              case .bytes(let setup) = f[3], case .bytes(let revision) = f[4], [mac, account, setup, revision].allSatisfy({ $0.count == 16 }),
              case .unsigned(let rawUID) = f[5], let uid = UInt32(exactly: rawUID), uid > 0, uid < UInt32.max,
              case .array(let targets) = f[6], targets.count <= 64,
              case .boolean(let key) = f[7], case .boolean(let prepared) = f[8], !prepared || key else { throw AccountPreparationError.invalidRecord }
        var uids = Set<UInt32>()
        for value in targets {
            guard case .unsigned(let raw) = value, let target = UInt32(exactly: raw), target < UInt32.max,
                  uids.insert(target).inserted else { throw AccountPreparationError.invalidRecord }
        }
        let value = Self(macID: mac, accountID: account, setupID: setup, revision: revision, ownerUID: uid,
            allowedTargetUIDs: uids, keyPrepared: key, storagePrepared: prepared)
        guard try value.bytes == bytes else { throw AccountPreparationError.invalidRecord }
        return value
    }
    private init(macID: Data, accountID: Data, setupID: Data, revision: Data, ownerUID: UInt32, allowedTargetUIDs: Set<UInt32>,
                 keyPrepared: Bool, storagePrepared: Bool) {
        self.macID = macID; self.accountID = accountID; self.setupID = setupID; self.revision = revision; self.ownerUID = ownerUID
        self.allowedTargetUIDs = allowedTargetUIDs; self.keyPrepared = keyPrepared; self.storagePrepared = storagePrepared
    }
}
