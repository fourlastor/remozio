import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

public enum AuthorityKeyProvisioningError: Error, Equatable {
    case invalidScope, missingExistingKey, conflictingState
}

/// Public setup metadata. This value grants no enrollment or action authority.
public struct AuthorityKeyProvisioningResult: Sendable, CustomStringConvertible {
    public let macID: Data
    public let accountID: Data
    public let publicKey: Data
    public var description: String { "AuthorityKeyProvisioningResult(redacted)" }
    fileprivate init(_ record: AuthoritySigningKeyRecord) {
        macID = record.macID; accountID = record.accountID; publicKey = record.publicKey
    }
}

/// Privileged setup only. The host must establish administrator authorization and trusted code placement first.
public enum AuthorityKeyProvisioning {
    public static let recordFileName = "authority-key.cbor"
    /// The directory must already be Root-private. Existing or prepared keys are never replaced.
    /// Supply the retained public pin for an established identity.
    public static func restoreOrCreate(directoryPath: String, macID: Data, accountID: Data,
                                       expectedPublicKey: Data? = nil) throws -> AuthorityKeyProvisioningResult {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard directoryPath.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        guard macID.count == 16, accountID.count == 16,
              expectedPublicKey == nil || (try? P256.Signing.PublicKey(x963Representation: expectedPublicKey!)) != nil else {
            throw AuthorityKeyProvisioningError.invalidScope
        }
        let storage = try AuthorityKeyProvisioningStorage(anchor: "/", relativeDirectory: String(directoryPath.dropFirst()), owner: 0)
        defer { storage.close() }
        let record = try storage.restoreOrCreate(macID: macID, accountID: accountID, expectedPublicKey: expectedPublicKey,
            create: { try createHardwareRecord(macID: macID, accountID: accountID) },
            verify: { try $0.verifyProvisioningHardware() })
        return AuthorityKeyProvisioningResult(record)
    }

    private static func createHardwareRecord(macID: Data, accountID: Data) throws -> AuthoritySigningKeyRecord {
        guard SecureEnclave.isAvailable else { throw AuthorityRequestSignerError.unavailable }
        let context = LAContext(); context.interactionNotAllowed = true
        defer { context.invalidate() }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage, &error) else { throw AuthorityRequestSignerError.unavailable }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
            return try AuthoritySigningKeyRecord(macID: macID, accountID: accountID, key: key)
        } catch { throw AuthorityRequestSignerError.unavailable }
    }
}

/// Same-owner fixture seam. Product callers cannot inject key creation, verification or fault hooks.
final class AuthorityKeyProvisioningStorage {
    enum Stage: Equatable { case prepared, published }
    static let recordName = AuthorityKeyProvisioning.recordFileName
    static let pendingName = "authority-key.pending.cbor"
    private struct Node {
        let fd: Int32, parent: Int32?, name: String, directory: Bool, privateObject: Bool
        let device: dev_t, inode: ino_t
    }
    private var nodes: [Node] = []
    private let owner: uid_t
    private let processID = getpid()
    private var retired = false
    private var closed = false

    init(anchor: String, relativeDirectory: String, owner: uid_t) throws {
        let parts = relativeDirectory.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        let fullDirectory = (anchor == "/" ? "" : anchor) + "/" + relativeDirectory
        guard !parts.isEmpty, !anchor.utf8.contains(0),
              fullDirectory.utf8.count + AuthorityKeyProvisioning.recordFileName.utf8.count + 2 < Int(PATH_MAX),
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              getuid() == owner, geteuid() == owner else { throw JournalLeaseError.invalidPath }
        self.owner = owner
        do {
            var parent = try retain(open(anchor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                parent: nil, name: anchor, directory: true, privateObject: false)
            for (index, part) in parts.enumerated() {
                parent = try retain(openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                    parent: parent, name: part, directory: true, privateObject: index == parts.count - 1)
            }
            var lockFD = openat(parent, "provisioning.lock", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
            if lockFD >= 0 {
                if fchmod(lockFD, 0o600) != 0 { let failure = errno; _ = Darwin.close(lockFD); throw JournalLeaseError.system(failure) }
            } else if errno == EEXIST {
                lockFD = openat(parent, "provisioning.lock", O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            }
            let lock = try retain(lockFD, parent: parent, name: "provisioning.lock", directory: false, privateObject: true)
            guard flock(lock, LOCK_EX | LOCK_NB) == 0 else {
                throw errno == EWOULDBLOCK ? JournalLeaseError.busy : JournalLeaseError.system(errno)
            }
            try validate()
        } catch { close(); throw error }
    }
    deinit { close() }
    private var directoryFD: Int32 { nodes[nodes.count - 2].fd }

    func close() {
        guard !closed else { return }; closed = true
        for node in nodes.reversed() { _ = Darwin.close(node.fd) }; nodes.removeAll()
    }
    private func retain(_ fd: Int32, parent: Int32?, name: String, directory: Bool, privateObject: Bool) throws -> Int32 {
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        do {
            var info = stat(); guard fstat(fd, &info) == 0 else { throw JournalLeaseError.system(errno) }
            try ProtectedStorageMetadata.validate(fd, info, directory: directory, privateObject: privateObject, owner: owner, ancestorOwner: owner)
            nodes.append(Node(fd: fd, parent: parent, name: name, directory: directory, privateObject: privateObject,
                device: info.st_dev, inode: info.st_ino)); return fd
        } catch { _ = Darwin.close(fd); throw error }
    }
    private func validate() throws {
        guard !closed else { throw JournalLeaseError.closed }
        guard !retired else { throw JournalLeaseError.invalidated }
        do {
            guard getpid() == processID, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            for node in nodes {
                var held = stat(), named = stat()
                guard fstat(node.fd, &held) == 0 else { throw JournalLeaseError.system(errno) }
                let result = node.parent.map { fstatat($0, node.name, &named, AT_SYMLINK_NOFOLLOW) } ?? lstat(node.name, &named)
                guard result == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == node.device, held.st_ino == node.inode, named.st_dev == node.device, named.st_ino == node.inode else {
                    throw JournalLeaseError.identityChanged
                }
                try ProtectedStorageMetadata.validate(node.fd, held, directory: node.directory,
                    privateObject: node.privateObject, owner: owner, ancestorOwner: owner)
            }
        } catch { retired = true; throw error }
    }
    private func inspect(_ fd: Int32, name: String) throws -> stat {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(directoryFD, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw JournalLeaseError.identityChanged }
        try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
        return held
    }
    private func read(_ name: String, synchronize: Bool = false) throws -> AuthoritySigningKeyRecord? {
        try validate()
        let fd = openat(directoryFD, name, (synchronize ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 { if errno == ENOENT { return nil }; throw JournalLeaseError.system(errno) }
        defer { _ = Darwin.close(fd) }
        let before = try inspect(fd, name: name)
        guard before.st_size > 0, before.st_size <= AuthoritySigningKeyRecord.maximumBytes else { throw AuthorityRequestSignerError.invalidRecord }
        var bytes = Data(count: Int(before.st_size)), offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw JournalLeaseError.identityChanged }; offset += count
        }
        if synchronize { try sync(fd) }
        let after = try inspect(fd, name: name)
        guard before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec, before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw JournalLeaseError.identityChanged }
        try validate(); return try AuthoritySigningKeyRecord.decode(bytes)
    }
    private func sync(_ fd: Int32) throws {
        guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
    }
    private func prepare(_ record: AuthoritySigningKeyRecord) throws {
        try validate()
        let bytes = try record.encode()
        let fd = openat(directoryFD, Self.pendingName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        defer { _ = Darwin.close(fd) }
        guard fchmod(fd, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
        _ = try inspect(fd, name: Self.pendingName)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw JournalLeaseError.system(errno) }; offset += count
        }
        try sync(fd); try sync(directoryFD); try validate()
        guard try read(Self.pendingName)?.encode() == bytes else { throw JournalLeaseError.identityChanged }
    }
    func restoreOrCreate(macID: Data, accountID: Data, expectedPublicKey: Data? = nil,
                         create: () throws -> AuthoritySigningKeyRecord,
                         verify: (AuthoritySigningKeyRecord) throws -> Void,
                         didStage: (Stage) throws -> Void = { _ in }) throws -> AuthoritySigningKeyRecord {
        guard macID.count == 16, accountID.count == 16,
              expectedPublicKey == nil || (try? P256.Signing.PublicKey(x963Representation: expectedPublicKey!)) != nil else {
            throw AuthorityKeyProvisioningError.invalidScope
        }
        func verifyScoped(_ record: AuthoritySigningKeyRecord) throws {
            guard record.macID == macID, record.accountID == accountID,
                  expectedPublicKey == nil || record.publicKey == expectedPublicKey else { throw AuthorityRequestSignerError.wrongIdentity }
            try verify(record); try validate()
        }
        if let retained = try read(Self.recordName) {
            guard try read(Self.pendingName) == nil else { throw AuthorityKeyProvisioningError.conflictingState }
            try verifyScoped(retained); try sync(directoryFD); return retained
        }
        let record: AuthoritySigningKeyRecord
        if let pending = try read(Self.pendingName, synchronize: true) { record = pending }
        else {
            guard expectedPublicKey == nil else { throw AuthorityKeyProvisioningError.missingExistingKey }
            record = try create(); try verifyScoped(record); try prepare(record)
        }
        try verifyScoped(record); try didStage(.prepared); try validate()
        guard try read(Self.pendingName)?.encode() == record.encode() else { throw JournalLeaseError.identityChanged }
        guard renameatx_np(directoryFD, Self.pendingName, directoryFD, Self.recordName, UInt32(RENAME_EXCL)) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        try didStage(.published); try validate(); try sync(directoryFD); try validate()
        guard let retained = try read(Self.recordName), try retained.encode() == record.encode() else { throw JournalLeaseError.identityChanged }
        return retained
    }
}
