import Darwin
import Foundation

/// Owns the push service's existing storage and writer lock. Serialize access and close SQLite before releasing it.
public final class ProtectedGatewayLease {
    private let storage: ProtectedStorageLease
    public var databasePath: String { storage.databasePath }

    /// Read the dedicated service UID and canonical path from protected administrator setup, never from an incoming message.
    public static func acquire(directoryPath: String, serviceUID: uid_t) throws -> ProtectedGatewayLease {
        guard serviceUID != 0, geteuid() == serviceUID else { throw JournalLeaseError.serviceIdentityRequired }
        guard directoryPath.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try ProtectedGatewayLease(anchor: "/", relativeDirectory: String(directoryPath.dropFirst()),
            serviceUID: serviceUID, ancestorUID: 0)
    }

    /// Internal fixture entry point. Production fixes the anchor to / and every ancestor owner to root.
    init(anchor: String, relativeDirectory: String, serviceUID: uid_t, ancestorUID: uid_t) throws {
        guard serviceUID != 0, geteuid() == serviceUID else { throw JournalLeaseError.serviceIdentityRequired }
        storage = try ProtectedStorageLease(anchor: anchor, relativeDirectory: relativeDirectory,
            owner: serviceUID, ancestorOwner: ancestorUID, databaseName: "gateway.sqlite")
    }

    /// Recheck process identity, path identities, ownership, modes and ACLs before opening SQLite or committing.
    public func validate() throws { try storage.validate() }

    // Protected setup retains these identities before any gateway journal initialization.
    func fileIdentity() throws -> GatewayJournalFileIdentity {
        guard let directory = try storage.directoryIdentities().last else { throw JournalLeaseError.identityChanged }
        return try .init(directory: directory, writer: storage.fileIdentity(name: "writer.lock"), database: storage.fileIdentity(name: "gateway.sqlite"))
    }

    /// Release descriptors and the lock. This does not delete storage or reset gateway trust.
    public func close() { storage.close() }
}
