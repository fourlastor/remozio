import Darwin
import Foundation

// Setup only. The authenticated endpoint must validate administrator rights before calling its owner.
// Prepared storage is not an installed account or a running service.
enum AccountPreparationController {
    static func resume(machine: PreparationIntentStore, expected: AccountPreparationIntent,
                       verifyCurrent: () throws -> Void) throws -> AccountPreparationIntent {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let accounts = "/Library/Application Support/Remozio/Accounts"
        let account = accounts + "/" + expected.accountID.map { String(format: "%02x", $0) }.joined()
        let authority = account + "/Authority"
        let key = authority + "/Key"
        let journal = authority + "/Journal/journal.sqlite"
        let continuity = authority + "/Continuity/continuity.sqlite"
        return try resume(machine: machine, expected: expected, verifyCurrent: verifyCurrent,
            provisionKey: { progress in
                var directories: [ProtectedSetupDirectory] = []
                defer { for directory in directories.reversed() { directory.close() } }
                for path in [accounts, account, authority, key] {
                    try verifyCurrent(); try machine.validateAccountPreparation(progress)
                    directories.append(try ProtectedSetupDirectory.createOrOpen(path: path))
                    for directory in directories { try directory.validate() }
                }
                let value = try AuthorityKeyProvisioning.restoreOrCreate(directoryPath: key, macID: progress.macID,
                    accountID: progress.accountID, expectedPublicKey: progress.authorityPublicKey)
                for directory in directories { try directory.validate() }
                return value.publicKey
            },
            beginInitialization: { progress in
                guard let inventory = try machine.inventory() else { throw AccountPreparationError.conflict }
                return try machine.beginInitialization(initial: progress.initialAuthority, journalPath: journal,
                    continuityPath: continuity, expectedInventoryRevision: inventory.revision)
            },
            resumeInitialization: { try AuthorityAccountInitialization.resume(machine: machine, expected: $0) })
    }

    enum Stage: CaseIterable { case keyProvisioned, keyPinned, initializationRetained, storesInitialized, completed }
    // Same-owner fixtures use actual machine, journal and continuity stores. They cannot prove native hardware or Root behavior.
    static func resume(machine: PreparationIntentStore, expected: AccountPreparationIntent,
                       verifyCurrent: () throws -> Void,
                       provisionKey: (AccountPreparationIntent) throws -> Data,
                       beginInitialization: (AccountPreparationIntent) throws -> AuthorityInitializationIntent,
                       resumeInitialization: (AuthorityInitializationIntent) throws -> AuthorityInitializationIntent,
                       didStage: (Stage) throws -> Void = { _ in }) throws -> AccountPreparationIntent {
        var progress = expected
        func verify() throws { try verifyCurrent(); try machine.validateAccountPreparation(progress) }
        try verify()
        // Completion is retained progress. It never authorizes recreating a missing key or store.
        if progress.storagePrepared { return progress }
        let key = try provisionKey(progress)
        try didStage(.keyProvisioned); try verify()
        progress = try machine.pinAccountPreparation(expected: progress, publicKey: key)
        try didStage(.keyPinned); try verify()
        let initial: AuthorityInitializationIntent
        if let retained = try machine.initialization(accountID: progress.accountID) {
            guard retained.initializationBytes == progress.initializationBytes,
                  retained.installationID == progress.installationID, retained.releaseDigest == progress.releaseDigest else {
                throw AccountPreparationError.conflict
            }
            initial = retained
        } else { initial = try beginInitialization(progress) }
        try didStage(.initializationRetained); try verify()
        _ = try resumeInitialization(initial)
        try didStage(.storesInitialized); try verify()
        progress = try machine.completeAccountPreparation(expected: progress)
        try didStage(.completed); try verify()
        return progress
    }
}
