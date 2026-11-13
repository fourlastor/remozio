import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

/// Digests and public scope only. The update snapshot retains no imported provider credential bytes.
struct SharedSetupImportCompatibilitySnapshot: Equatable, Sendable {
    struct Record: Equatable, Sendable {
        let accountID: Data
        let operationID: Data
        let revision: Data
        let phase: UInt64
        let digest: Data
        let portableVersion: UInt64
        let settingsVersion: UInt64
        let relay: SharedSetupImportRelayStorage.Snapshot?
        let relayProvisioning: SharedSetupRelayProvisioningStorage.Snapshot?
        let accessApplication: SharedSetupAccessApplicationStorage.Snapshot?
        let dnsRecord: SharedSetupDNSStorage.Snapshot?
        let runCredential: SharedSetupRelayRunReferenceStorage.Snapshot?
        init(accountID: Data, operationID: Data, revision: Data, phase: UInt64, digest: Data, portableVersion: UInt64,
             settingsVersion: UInt64, relay: SharedSetupImportRelayStorage.Snapshot?,
             relayProvisioning: SharedSetupRelayProvisioningStorage.Snapshot?, accessApplication: SharedSetupAccessApplicationStorage.Snapshot?,
             dnsRecord: SharedSetupDNSStorage.Snapshot?, runCredential: SharedSetupRelayRunReferenceStorage.Snapshot? = nil) {
            self.accountID = accountID; self.operationID = operationID; self.revision = revision; self.phase = phase
            self.digest = digest; self.portableVersion = portableVersion; self.settingsVersion = settingsVersion
            self.relay = relay; self.relayProvisioning = relayProvisioning; self.accessApplication = accessApplication
            self.dnsRecord = dnsRecord; self.runCredential = runCredential
        }
    }
    let directories: [ProtectedStorageLease.DirectoryIdentity]
    let database: ProtectedStorageLease.DirectoryIdentity
    let writer: ProtectedStorageLease.DirectoryIdentity
    let records: [Record]

    /// The setup owner holds its release barrier and machine lease first. Absence never creates files.
    static func capture(anchor: String, relativeMachineDirectory: String, owner: uid_t, macID: Data,
                        installationID: Data?) throws -> Self? {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        let machine = try ProtectedSetupDirectory(anchor: anchor, relativePath: relativeMachineDirectory,
            owner: owner, createIfMissing: false)
        defer { machine.close() }
        return try machine.withPrivateDirectory { parent in
            var info = stat()
            if fstatat(parent, "SharedSetupImport", &info, AT_SYMLINK_NOFOLLOW) != 0 {
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
                return nil
            }
            guard let installationID else { throw SharedSetupImportError.wrongScope }
            let lease = try ProtectedStorageLease(anchor: anchor, relativeDirectory: relativeMachineDirectory + "/SharedSetupImport",
                owner: owner, ancestorOwner: owner, databaseName: "setup-import.sqlite")
            let journal = try SharedSetupImportJournal(lease: lease, owner: owner, macID: macID,
                installationID: installationID, initialize: false)
            defer { try? journal.close() }
            let relayDirectory = try ProtectedSetupDirectory(anchor: anchor, relativePath: relativeMachineDirectory + "/SharedSetupImport",
                owner: owner, createIfMissing: false)
            defer { relayDirectory.close() }
            return try journal.compatibilitySnapshot(directory: relayDirectory)
        }
    }
}
