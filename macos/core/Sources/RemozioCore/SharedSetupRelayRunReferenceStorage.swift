import CryptoKit
import Darwin
import Foundation

/// Retains public credential bindings under the existing machine and import leases. It grants no startup authority.
enum SharedSetupRelayRunReferenceStorage {
    struct Snapshot: Equatable, Sendable {
        let identity: ProtectedStorageLease.DirectoryIdentity
        let digest: Data
        let reference: RelayRunCredentialReference
    }
    static func read(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan?,
                     created: SharedSetupRelayProvisioningRecord?, directory: ProtectedSetupDirectory,
                     owner: uid_t) throws -> RelayRunCredentialReference? {
        let file = AdministrativeSetupPublication.File.importRelayRunReference(accountID: expected.scope.accountID)
        let present = try directory.withPrivateDirectory { parent -> Bool in
            var info = stat()
            if fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }; return false
        }
        guard present else { return nil }
        guard let plan, let created else { throw RelayProvisioningError.wrongScope }
        let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: owner)
        let reference = try RelayRunCredentialReference.decodeRetainedMetadata(bytes, expected: expected, plan: plan, created: created)
        try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner)
        return reference
    }
    static func snapshot(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan?,
                         created: SharedSetupRelayProvisioningRecord?, directory: ProtectedSetupDirectory,
                         owner: uid_t) throws -> Snapshot? {
        guard let reference = try read(expected: expected, plan: plan, created: created, directory: directory, owner: owner) else { return nil }
        let file = AdministrativeSetupPublication.File.importRelayRunReference(accountID: expected.scope.accountID)
        let identity = try directory.withPrivateDirectory { parent -> ProtectedStorageLease.DirectoryIdentity in
            var info = stat()
            guard fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
            return .init(device: info.st_dev, inode: info.st_ino)
        }
        guard try read(expected: expected, plan: plan, created: created, directory: directory, owner: owner) == reference else {
            throw RelayProvisioningError.staleRecord
        }
        try directory.withPrivateDirectory { parent in
            var info = stat()
            guard fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0,
                  info.st_dev == identity.device, info.st_ino == identity.inode else { throw JournalLeaseError.identityChanged }
        }
        return try .init(identity: identity, digest: Data(SHA256.hash(data: reference.encoded)), reference: reference)
    }
    static func retain(_ reference: RelayRunCredentialReference, expected: SharedSetupImportIntent,
                       plan: SharedSetupImportRelayPlan, created: SharedSetupRelayProvisioningRecord,
                       runtime: RuntimeMaterialReference, directory: ProtectedSetupDirectory, owner: uid_t,
                       verifyCurrent: () throws -> Void,
                       didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RelayRunCredentialReference {
        try verifyCurrent()
        let bytes = try reference.encoded
        guard try RelayRunCredentialReference.decodeRetainedMetadata(bytes, expected: expected, plan: plan, created: created) == reference,
              reference.runtime == runtime,
              try SharedSetupImportRelayStorage.read(expected: expected, directory: directory, owner: owner) == plan,
              try SharedSetupRelayProvisioningStorage.read(expected: expected, plan: plan, directory: directory, owner: owner) == created else {
            throw RelayProvisioningError.wrongScope
        }
        let file = AdministrativeSetupPublication.File.importRelayRunReference(accountID: expected.scope.accountID)
        if let current = try read(expected: expected, plan: plan, created: created, directory: directory, owner: owner) {
            guard current == reference else { throw RuntimePreparationError.conflictingMaterial }
        } else {
            guard expected.phase == .runtimePublished || expected.phase == .gatewayPrepared else { throw RuntimePreparationError.incomplete }
        }
        _ = try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: owner,
            verify: verifyCurrent, didStage: didStage)
        guard try read(expected: expected, plan: plan, created: created, directory: directory, owner: owner) == reference else {
            throw RelayProvisioningError.staleRecord
        }
        try verifyCurrent(); return reference
    }
}
