import Darwin
import Foundation
import RemozioProtocol

/// Exact close metadata only. Native exit, job absence and journal custody remain separate requirements.
struct AuthorityMaintenanceCloseMarker: Equatable, Sendable {
    static let formatName = "authority.maintenance-close-marker"
    static let fileName = "authority-maintenance-close.cbor"
    let binding: AuthorityMaintenanceBinding
    let macID: Data, installationID: Data, releaseDigest: Data, codeHash: Data, directoryID: Data
    let ownerUID: uid_t, gate: PreparationFileIdentity
    init(binding: AuthorityMaintenanceBinding, macID: Data, installationID: Data, releaseDigest: Data,
        codeHash: Data, directoryID: Data, ownerUID: uid_t, gate: PreparationFileIdentity) throws {
        guard [macID, installationID, directoryID].allSatisfy({ $0.count == 16 }), releaseDigest.count == 32,
              [20, 32].contains(codeHash.count), ownerUID > 0, ownerUID < UInt32.max, gate.inode > 0 else {
            throw RuntimePreparationError.invalidRecord
        }
        self.binding = binding; self.macID = macID; self.installationID = installationID; self.releaseDigest = releaseDigest
        self.codeHash = codeHash; self.directoryID = directoryID; self.ownerUID = ownerUID; self.gate = gate
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.formatName), 2: .bytes(binding.encoded),
            3: .bytes(macID), 4: .bytes(installationID), 5: .bytes(releaseDigest), 6: .bytes(codeHash),
            7: .bytes(directoryID), 8: .unsigned(UInt64(ownerUID)), 9: .unsigned(UInt64(gate.device)), 10: .unsigned(gate.inode)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...10),
              f[0] == .unsigned(1), f[1] == .text(formatName), case .unsigned(let uid) = f[8], uid < UInt64(UInt32.max),
              case .unsigned(let device) = f[9], device <= UInt64(UInt32.max), case .unsigned(let inode) = f[10] else { throw RuntimePreparationError.invalidRecord }
        func data(_ k: UInt64) throws -> Data { guard case .bytes(let b) = f[k] else { throw RuntimePreparationError.invalidRecord }; return b }
        let value = try Self(binding: .decode(data(2)), macID: data(3), installationID: data(4), releaseDigest: data(5),
            codeHash: data(6), directoryID: data(7), ownerUID: uid_t(uid), gate: .init(device: UInt32(device), inode: inode))
        guard try value.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return value
    }
    /// Readback never creates a missing marker. It confirms exact bytes and retained file and directory durability.
    static func readback(_ expected: Self) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let path = try RuntimePreparationPaths(accountID: expected.binding.accountID).serviceDirectory
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(path.dropFirst()), owner: 0,
            visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }; try readback(expected, directory: directory, owner: 0)
    }
    static func readback(_ expected: Self, directory: ProtectedSetupDirectory, owner: uid_t) throws {
        try directory.validate()
        let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: fileName, owner: owner)
        guard try decode(bytes) == expected else { throw RuntimePreparationError.changedScope }
        try AdministrativeSetupPublication.retainMaintenanceCloseMarker(bytes, directory: directory, owner: owner)
        guard try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: fileName, owner: owner) == bytes else { throw JournalLeaseError.identityChanged }
        try directory.validate()
    }
    private static let limits = try! CBORLimits(maxBytes: 512, maxDepth: 1, maxItems: 23)
}
