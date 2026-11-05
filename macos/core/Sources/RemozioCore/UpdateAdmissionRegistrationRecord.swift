import Darwin
import Foundation

/// Retained file identities only. This record grants no drain, deferral, replacement or restart authority.
struct UpdateAdmissionRegistrationRecord: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    struct Account: Codable, Equatable, Sendable {
        let accountID: Data
        let identity: PreparationFileIdentity
    }
    static let formatName = "authority.update-admission-registration"
    static let maximumBytes = 32_768
    let formatVersion: UInt64
    let macID: Data
    let installationID: Data
    let machine: PreparationFileIdentity
    let accounts: [Account]
    let designatedOwner: Data?
    let revision: UUID
    var description: String { "UpdateAdmissionRegistrationRecord(redacted)" }
    var debugDescription: String { description }

    init(macID: Data, installationID: Data, machine: PreparationFileIdentity, accounts: [Account],
         designatedOwner: Data?, revision: UUID = UUID()) throws {
        formatVersion = 1; self.macID = macID; self.installationID = installationID; self.machine = machine
        self.accounts = accounts.sorted { $0.accountID.lexicographicallyPrecedes($1.accountID) }
        self.designatedOwner = designatedOwner; self.revision = revision
        try validate()
    }
    private func validate() throws {
        guard formatVersion == 1, macID.count == 16, installationID.count == 16, machine.inode > 0,
              (1...64).contains(accounts.count), accounts.allSatisfy({ $0.accountID.count == 16 && $0.identity.inode > 0 }),
              Set(accounts.map(\.accountID)).count == accounts.count,
              accounts.map(\.accountID) == accounts.map(\.accountID).sorted(by: { $0.lexicographicallyPrecedes($1) }),
              designatedOwner == nil || accounts.contains(where: { $0.accountID == designatedOwner }) else {
            throw PreparationStoreError.corruptRecord
        }
        let identities = [machine] + accounts.map(\.identity)
        for index in identities.indices {
            guard !identities.dropFirst(index + 1).contains(identities[index]) else { throw PreparationStoreError.corruptRecord }
        }
    }
    var encoded: Data { get throws {
        try validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else { throw PreparationStoreError.corruptRecord }
        return bytes
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw PreparationStoreError.corruptRecord }
            let value = try JSONDecoder().decode(Self.self, from: bytes); try value.validate()
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }
            return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [16], writeVersions: [16]),
                 RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: [1])]
        }
    } }
}

/// Enables storage only after checking the installed readers. It does not provision files or select an update owner.
enum UpdateAdmissionRegistrationStorage {
    static func enable(installedRelease: SignedReleaseEvidence, policy: AuthorityCodePolicy, store: PreparationIntentStore) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try enableInLease(installedRelease: installedRelease, policy: policy, store: store)
    }
    static func enableInLease(installedRelease: SignedReleaseEvidence, policy: AuthorityCodePolicy, store: PreparationIntentStore) throws {
        try UpdateSchedulingCandidateRecord.validateReaders(installedRelease, policy: policy)
        try ReleaseCompatibilityPreflight.validate(installedRelease, policy: policy,
            requirements: .init(formats: UpdateAdmissionRegistrationRecord.requirements, requests: []))
        try RuntimeReleaseCompatibilitySnapshot.capture(machine: store).validate(installedRelease, policy: policy, machine: store)
        try store.upgradeUpdateAdmissionStorage(expectedInstalledReleaseDigest: InstallationInventory.digest(installedRelease))
    }
}
