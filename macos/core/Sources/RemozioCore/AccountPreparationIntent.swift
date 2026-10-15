import CryptoKit
import Foundation
import RemozioProtocol

public enum AccountPreparationError: Error, Equatable {
    case invalidRecord, conflict, staleRevision, missing, ownershipChanged, incomplete
}

/// Retained setup inputs. This record grants no service registration, pairing or execution authority.
public struct AccountPreparationIntent: Equatable, Sendable, CustomStringConvertible {
    public let setupID: Data
    public let revision: Data
    public let macID: Data
    public let installationID: Data
    public let releaseDigest: Data
    public let accountID: Data
    public let ownerUID: UInt32
    public let directoryID: UUID
    let policyBytes: Data
    let initializationBytes: Data
    public let authorityPublicKey: Data?
    public let storagePrepared: Bool
    public var description: String { "AccountPreparationIntent(redacted)" }
    public var commandPolicy: CommandElevationPolicy { get throws { try .decode(policyBytes) } }
    public var initialAuthority: AuthorityJournalInitialization { get throws { try .decodeInitialization(initializationBytes) } }

    init(setupID: Data, revision: Data, macID: Data, installationID: Data, releaseDigest: Data,
         accountID: Data, ownerUID: UInt32, directoryID: UUID, policyBytes: Data, initializationBytes: Data,
         authorityPublicKey: Data? = nil, storagePrepared: Bool = false) throws {
        guard [setupID, revision, macID, installationID, accountID].allSatisfy({ $0.count == 16 }),
              releaseDigest.count == 32, ownerUID > 0, ownerUID < UInt32.max,
              !storagePrepared || authorityPublicKey != nil else { throw AccountPreparationError.invalidRecord }
        let policy = try CommandElevationPolicy.decode(policyBytes)
        let initial = try AuthorityJournalInitialization.decodeInitialization(initializationBytes)
        guard policy.macID == macID, policy.accountID == accountID, policy.callerUID == ownerUID,
              initial.descriptor.macID == macID, initial.descriptor.accountID == accountID,
              initial.descriptor.generation == 1, initial.descriptor.cause == .initial,
              initial.installCommandReplay else { throw AccountPreparationError.invalidRecord }
        if let key = authorityPublicKey {
            guard key.count == 65, key.first == 4, (try? P256.Signing.PublicKey(x963Representation: key)) != nil else {
                throw AccountPreparationError.invalidRecord
            }
        }
        self.setupID = setupID; self.revision = revision; self.macID = macID; self.installationID = installationID
        self.releaseDigest = releaseDigest; self.accountID = accountID; self.ownerUID = ownerUID; self.directoryID = directoryID
        self.policyBytes = policyBytes; self.initializationBytes = initializationBytes
        self.authorityPublicKey = authorityPublicKey; self.storagePrepared = storagePrepared
        guard try bytes.count <= Self.maximumBytes else { throw AccountPreparationError.invalidRecord }
    }
    func pinning(_ publicKey: Data) throws -> Self {
        if let authorityPublicKey {
            guard authorityPublicKey == publicKey else { throw AccountPreparationError.conflict }
            return self
        }
        return try replacing(publicKey: publicKey, prepared: false)
    }
    func prepared(initialization: AuthorityInitializationIntent) throws -> Self {
        guard authorityPublicKey != nil, initialization.complete,
              initialization.macID == macID, initialization.accountID == accountID,
              initialization.installationID == installationID, initialization.releaseDigest == releaseDigest,
              initialization.initializationBytes == initializationBytes else { throw AccountPreparationError.incomplete }
        if storagePrepared { return self }
        return try replacing(publicKey: authorityPublicKey, prepared: true)
    }
    private func replacing(publicKey: Data?, prepared: Bool) throws -> Self {
        var revision = Self.randomID()
        while revision == self.revision { revision = Self.randomID() }
        return try .init(setupID: setupID, revision: revision, macID: macID, installationID: installationID,
            releaseDigest: releaseDigest, accountID: accountID, ownerUID: ownerUID, directoryID: directoryID,
            policyBytes: policyBytes, initializationBytes: initializationBytes, authorityPublicKey: publicKey, storagePrepared: prepared)
    }
    var bytes: Data {
        get throws {
            var uuid = directoryID.uuid
            return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(setupID), 2: .bytes(revision),
                3: .bytes(macID), 4: .bytes(installationID), 5: .bytes(releaseDigest), 6: .bytes(accountID),
                7: .unsigned(UInt64(ownerUID)), 8: .bytes(withUnsafeBytes(of: &uuid) { Data($0) }),
                9: .bytes(policyBytes), 10: .bytes(initializationBytes),
                11: authorityPublicKey.map(CBORValue.bytes) ?? .null, 12: .boolean(storagePrepared)]), limits: Self.limits())
        }
    }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(f.keys) == Set(UInt64(0)...12), f[0] == .unsigned(1),
              case .bytes(let setup) = f[1], case .bytes(let revision) = f[2], case .bytes(let mac) = f[3],
              case .bytes(let installation) = f[4], case .bytes(let release) = f[5], case .bytes(let account) = f[6],
              case .unsigned(let rawUID) = f[7], let uid = UInt32(exactly: rawUID),
              case .bytes(let directory) = f[8], directory.count == 16,
              case .bytes(let policy) = f[9], case .bytes(let initial) = f[10],
              case .boolean(let prepared) = f[12] else { throw AccountPreparationError.invalidRecord }
        let key: Data?
        switch f[11] { case .null?: key = nil; case .bytes(let bytes)?: key = bytes; default: throw AccountPreparationError.invalidRecord }
        let id = directory.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
        let value = try Self(setupID: setup, revision: revision, macID: mac, installationID: installation,
            releaseDigest: release, accountID: account, ownerUID: uid, directoryID: id, policyBytes: policy,
            initializationBytes: initial, authorityPublicKey: key, storagePrepared: prepared)
        guard try value.bytes == bytes else { throw AccountPreparationError.invalidRecord }
        return value
    }
    static func randomID() -> Data { var id = UUID().uuid; return withUnsafeBytes(of: &id) { Data($0) } }
    static let maximumBytes = 147456
    private static func limits() throws -> CBORLimits { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 32) }
}
