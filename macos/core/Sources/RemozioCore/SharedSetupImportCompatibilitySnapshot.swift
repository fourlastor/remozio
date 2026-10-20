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
            let intents = try journal.records()
            try SharedSetupImportRelayStorage.validateTrackedFiles(records: intents, directory: relayDirectory)
            let records = try intents.map { intent -> Record in
                let plan = try SharedSetupImportRelayStorage.read(expected: intent, directory: relayDirectory, owner: owner)
                let tunnel = try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: relayDirectory, owner: owner)
                let access = try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel, directory: relayDirectory, owner: owner)
                return try .init(accountID: intent.scope.accountID, operationID: intent.operationID, revision: intent.revision,
                    phase: intent.phase.rawValue, digest: Data(SHA256.hash(data: intent.bytes)),
                    portableVersion: intent.originalPortableVersion, settingsVersion: intent.recipe.settingsVersion,
                    relay: SharedSetupImportRelayStorage.snapshot(expected: intent, directory: relayDirectory, owner: owner),
                    relayProvisioning: SharedSetupRelayProvisioningStorage.snapshot(expected: intent,
                        plan: SharedSetupImportRelayStorage.read(expected: intent, directory: relayDirectory, owner: owner),
                        directory: relayDirectory, owner: owner),
                    accessApplication: SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                        createdTunnel: tunnel, directory: relayDirectory, owner: owner),
                    dnsRecord: SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: access, directory: relayDirectory, owner: owner))
            }
            return try .init(directories: lease.directoryIdentities(), database: lease.fileIdentity(name: "setup-import.sqlite"),
                writer: lease.fileIdentity(name: "writer.lock"), records: records)
        }
    }
}
