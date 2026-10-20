import CryptoKit
import Darwin
import Foundation

/// Retains file identities and public record digests. It contains no imported provider credential.
struct SharedSetupImportCompatibilitySnapshot: Equatable, Sendable {
    struct Record: Equatable, Sendable {
        let accountID: Data
        let operationID: Data
        let revision: Data
        let phase: UInt64
        let digest: Data
        let portableVersion: UInt64
        let settingsVersion: UInt64
    }
    let directories: [ProtectedStorageLease.DirectoryIdentity]
    let database: ProtectedStorageLease.DirectoryIdentity
    let writer: ProtectedStorageLease.DirectoryIdentity
    let records: [Record]

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
            let relative = relativeMachineDirectory + "/SharedSetupImport"
            let lease = try ProtectedStorageLease(anchor: anchor, relativeDirectory: relative,
                owner: owner, ancestorOwner: owner, databaseName: "setup-import.sqlite")
            let journal = try SharedSetupImportJournal(lease: lease, owner: owner, macID: macID,
                installationID: installationID, initialize: false)
            defer { try? journal.close() }
            let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: relative,
                owner: owner, createIfMissing: false)
            defer { directory.close() }
            let intents = try journal.records()
            try directory.validate()
            let names = Set(try FileManager.default.contentsOfDirectory(atPath: directory.path))
            guard names == ["setup-import.sqlite", "writer.lock"] else { throw SharedSetupImportError.incompatibleStore }
            try directory.validate()
            let records = try intents.map { intent in
                try Record(accountID: intent.scope.accountID, operationID: intent.operationID, revision: intent.revision,
                    phase: intent.phase.rawValue, digest: Data(SHA256.hash(data: intent.bytes)),
                    portableVersion: intent.originalPortableVersion, settingsVersion: intent.recipe.settingsVersion)
            }
            return try .init(directories: lease.directoryIdentities(), database: lease.fileIdentity(name: "setup-import.sqlite"),
                writer: lease.fileIdentity(name: "writer.lock"), records: records)
        }
    }
}
