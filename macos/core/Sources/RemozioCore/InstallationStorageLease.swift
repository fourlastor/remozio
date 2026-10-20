import Darwin
import Foundation

/// Owns the machine-scoped installation record files. It grants no activation authority.
final class InstallationStorageLease {
    private let storage: ProtectedStorageLease
    private let owner: uid_t
    private let anchor: String
    private let relativeDirectory: String
    var databasePath: String { storage.databasePath }

    static func acquire(directoryPath: String) throws -> InstallationStorageLease {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard directoryPath.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try .init(anchor: "/", relativeDirectory: String(directoryPath.dropFirst()), owner: 0)
    }

    // Internal ordinary-owner seam. Production requires both Root identities and fixed file names.
    init(anchor: String, relativeDirectory: String, owner: uid_t) throws {
        self.owner = owner; self.anchor = anchor; self.relativeDirectory = relativeDirectory
        storage = try ProtectedStorageLease(anchor: anchor, relativeDirectory: relativeDirectory,
            owner: owner, ancestorOwner: owner, databaseName: "installation.sqlite")
    }

    func validate() throws {
        guard getuid() == owner, geteuid() == owner else {
            storage.close(); throw JournalLeaseError.unsafeMetadata
        }
        try storage.validate()
    }
    func directoryIdentities() throws -> [ProtectedStorageLease.DirectoryIdentity] {
        try storage.directoryIdentities()
    }
    func withSharedImportJournal<Value>(macID: Data, installationID: Data,
                                       body: (SharedSetupImportJournal?) throws -> Value) throws -> Value {
        try validate()
        let result = try SharedSetupImportJournal.withExisting(anchor: anchor, relativeMachineDirectory: relativeDirectory,
            owner: owner, macID: macID, installationID: installationID, body: body)
        try validate(); return result
    }

    func publishSharedImport(_ intent: SharedSetupImportIntent, verifyCurrent: () throws -> Void,
                             didStage: (SharedSetupImportPublication.Stage) throws -> Void) throws -> SharedSetupImportIntent {
        try validate()
        let result = try SharedSetupImportPublication.create(anchor: anchor, relativeMachineDirectory: relativeDirectory,
            owner: owner, expectedScope: intent.scope, intent: intent, verifyCurrent: {
                try self.validate(); try verifyCurrent()
            }, didStage: didStage)
        try validate(); return result
    }

    func sharedImportCompatibilitySnapshot(macID: Data, installationID: Data?) throws -> SharedSetupImportCompatibilitySnapshot? {
        try validate()
        let snapshot = try SharedSetupImportCompatibilitySnapshot.capture(
            anchor: anchor, relativeMachineDirectory: relativeDirectory,
            owner: owner, macID: macID, installationID: installationID)
        try validate(); return snapshot
    }

    func close() { storage.close() }
}
