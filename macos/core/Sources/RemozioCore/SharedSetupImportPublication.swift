import Darwin
import Foundation

/// The setup owner holds its release barrier and machine lease before calling this internal storage operation.
/// Only the final directory name accepts an import. Unpublished staging directories contain no provider credentials.
enum SharedSetupImportPublication {
    enum Stage: CaseIterable { case directoryPrepared, filesPrepared, intentRetained, beforePublication, published, durable }
    static func create(anchor: String, relativeMachineDirectory: String, owner: uid_t,
                       expectedScope: SharedSetupImportIntent.Scope, intent: SharedSetupImportIntent,
                       verifyCurrent: () throws -> Void, didStage: (Stage) throws -> Void = { _ in }) throws -> SharedSetupImportIntent {
        guard intent.scope == expectedScope else { throw SharedSetupImportError.wrongScope }
        guard intent.phase == .retained else { throw SharedSetupImportError.invalidTransition }
        try verifyCurrent()
        let parent = try ProtectedSetupDirectory(anchor: anchor, relativePath: relativeMachineDirectory,
            owner: owner, createIfMissing: false)
        defer { parent.close() }
        return try parent.withPrivateDirectory { parentFD in
            var existing = stat()
            if fstatat(parentFD, "SharedSetupImport", &existing, AT_SYMLINK_NOFOLLOW) == 0 {
                throw SharedSetupImportError.conflict
            }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
            try verifyCurrent()
            let stagingName = ".remozio-import-" + UUID().uuidString
            let relativeStaging = relativeMachineDirectory + "/" + stagingName
            let staging = try ProtectedSetupDirectory(anchor: anchor, relativePath: relativeStaging, owner: owner)
            defer { staging.close() }
            guard staging.created else { throw SharedSetupImportError.conflict }
            try didStage(.directoryPrepared); try verifyCurrent()
            let files = try SetupDatabaseFileProvisioning.prepare(directory: staging, kind: .sharedSetupImport, owner: owner)
            guard files.createdFileNames == ["writer.lock", "setup-import.sqlite"] else { throw SharedSetupImportError.conflict }
            try didStage(.filesPrepared); try verifyCurrent()
            let lease = try ProtectedStorageLease(anchor: anchor, relativeDirectory: relativeStaging,
                owner: owner, ancestorOwner: owner, databaseName: "setup-import.sqlite")
            let journal = try SharedSetupImportJournal(lease: lease, owner: owner, macID: expectedScope.macID,
                installationID: expectedScope.installationID, initialize: true)
            do {
                try journal.begin(intent)
                guard try journal.current(scope: expectedScope) == intent, try journal.records().count == 1 else {
                    throw SharedSetupImportError.corruptRecord
                }
                try journal.close()
            } catch { try? journal.close(); throw error }
            try didStage(.intentRetained); try verifyCurrent()
            try staging.withPrivateDirectory { fd in
                guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
            }
            guard let identity = try staging.directoryIdentities().last else { throw JournalLeaseError.identityChanged }
            try didStage(.beforePublication); try verifyCurrent(); try staging.validate(); try parent.validate()
            var named = stat()
            guard fstatat(parentFD, stagingName, &named, AT_SYMLINK_NOFOLLOW) == 0,
                  named.st_dev == identity.device, named.st_ino == identity.inode else { throw JournalLeaseError.identityChanged }
            guard renameatx_np(parentFD, stagingName, parentFD, "SharedSetupImport", UInt32(RENAME_EXCL)) == 0 else {
                throw JournalLeaseError.system(errno)
            }
            // The held staging object closes its descriptors without validating its former name after this rename.
            try didStage(.published)
            guard fsync(parentFD) == 0 else { throw JournalLeaseError.system(errno) }
            try didStage(.durable); try verifyCurrent(); try parent.validate()
            let published = try ProtectedSetupDirectory(anchor: anchor, relativePath: relativeMachineDirectory + "/SharedSetupImport",
                owner: owner, createIfMissing: false)
            defer { published.close() }
            guard try published.directoryIdentities().last == identity else { throw JournalLeaseError.identityChanged }
            return try SharedSetupImportJournal.withExisting(anchor: anchor, relativeMachineDirectory: relativeMachineDirectory,
                owner: owner, macID: expectedScope.macID, installationID: expectedScope.installationID) { journal in
                guard let journal, try journal.current(scope: expectedScope) == intent,
                      try journal.records().count == 1 else { throw SharedSetupImportError.corruptRecord }
                try verifyCurrent(); return intent
            }
        }
    }
}
