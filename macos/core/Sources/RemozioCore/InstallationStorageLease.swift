import Darwin
import Foundation

/// Owns the machine-scoped installation record files. It grants no activation authority.
final class InstallationStorageLease {
    private let storage: ProtectedStorageLease
    private let owner: uid_t
    var databasePath: String { storage.databasePath }

    static func acquire(directoryPath: String) throws -> InstallationStorageLease {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard directoryPath.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try .init(anchor: "/", relativeDirectory: String(directoryPath.dropFirst()), owner: 0)
    }

    // Internal ordinary-owner seam. Production requires both Root identities and fixed file names.
    init(anchor: String, relativeDirectory: String, owner: uid_t) throws {
        self.owner = owner
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
    func close() { storage.close() }
}
