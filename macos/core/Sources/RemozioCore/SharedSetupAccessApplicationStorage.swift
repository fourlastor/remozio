import CryptoKit
import Darwin
import Foundation

/// The owner holds machine and import leases. Atomic replacement retains metadata only, with no credential staging.
enum SharedSetupAccessApplicationStorage {
    typealias Snapshot = SharedSetupImportRelayStorage.Snapshot
    static func read(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan?, createdTunnel: SharedSetupRelayProvisioningRecord?, directory: ProtectedSetupDirectory,
                     owner: uid_t) throws -> SharedSetupAccessApplicationRecord? {
        let file = AdministrativeSetupPublication.File.importAccessApplication(accountID: expected.scope.accountID)
        let present = try directory.withPrivateDirectory { parent -> Bool in
            var info = stat()
            if fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }; return false
        }
        guard present else { return nil }
        guard let plan, let createdTunnel else { throw RelayProvisioningError.wrongScope }
        let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: owner)
        let record = try SharedSetupAccessApplicationRecord.decode(bytes, expected: expected, plan: plan, createdTunnel: createdTunnel)
        try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner)
        return record
    }
    static func snapshot(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan?, createdTunnel: SharedSetupRelayProvisioningRecord?, directory: ProtectedSetupDirectory,
                         owner: uid_t) throws -> Snapshot? {
        guard let record = try read(expected: expected, plan: plan, createdTunnel: createdTunnel, directory: directory, owner: owner) else { return nil }
        let file = AdministrativeSetupPublication.File.importAccessApplication(accountID: expected.scope.accountID)
        let identity = try directory.withPrivateDirectory { parent -> ProtectedStorageLease.DirectoryIdentity in
            var info = stat()
            guard fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
            return .init(device: info.st_dev, inode: info.st_ino)
        }
        guard try read(expected: expected, plan: plan, createdTunnel: createdTunnel, directory: directory, owner: owner) == record else { throw RelayProvisioningError.staleRecord }
        try directory.withPrivateDirectory { parent in
            var info = stat()
            guard fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0,
                  info.st_dev == identity.device, info.st_ino == identity.inode else { throw JournalLeaseError.identityChanged }
        }
        return .init(identity: identity, digest: Data(SHA256.hash(data: record.bytes)))
    }
    static func begin(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord, directory: ProtectedSetupDirectory,
                      owner: uid_t, verifyCurrent: () throws -> Void) throws -> SharedSetupAccessApplicationRecord {
        try verifyCurrent()
        guard try SharedSetupImportRelayStorage.read(expected: expected, directory: directory, owner: owner) == plan,
              try SharedSetupRelayProvisioningStorage.read(expected: expected, plan: plan, directory: directory, owner: owner) == createdTunnel else {
            throw RelayProvisioningError.wrongScope
        }
        if let current = try read(expected: expected, plan: plan, createdTunnel: createdTunnel, directory: directory, owner: owner) { try verifyCurrent(); return current }
        let record = try SharedSetupAccessApplicationRecord(expected: expected, plan: plan, createdTunnel: createdTunnel)
        _ = try AdministrativeSetupPublication.replaceAccessApplication(record.bytes, previous: nil, expected: expected,
            plan: plan, createdTunnel: createdTunnel, directory: directory, owner: owner, verify: verifyCurrent)
        guard try read(expected: expected, plan: plan, createdTunnel: createdTunnel, directory: directory, owner: owner) == record else { throw RelayProvisioningError.staleRecord }
        return record
    }
    static func replace(_ next: SharedSetupAccessApplicationRecord, previous: SharedSetupAccessApplicationRecord,
                        expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                        directory: ProtectedSetupDirectory, owner: uid_t, verifyCurrent: () throws -> Void,
                        didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws {
        try verifyCurrent()
        guard try SharedSetupImportRelayStorage.read(expected: expected, directory: directory, owner: owner) == plan,
              try SharedSetupRelayProvisioningStorage.read(expected: expected, plan: plan, directory: directory, owner: owner) == createdTunnel,
              try read(expected: expected, plan: plan, createdTunnel: createdTunnel, directory: directory, owner: owner) == previous else {
            throw RelayProvisioningError.staleRecord
        }
        _ = try AdministrativeSetupPublication.replaceAccessApplication(next.bytes, previous: previous.bytes, expected: expected,
            plan: plan, createdTunnel: createdTunnel, directory: directory, owner: owner, verify: verifyCurrent, didStage: didStage)
        guard try read(expected: expected, plan: plan, createdTunnel: createdTunnel, directory: directory, owner: owner) == next else { throw RelayProvisioningError.staleRecord }
        try verifyCurrent()
    }
}
