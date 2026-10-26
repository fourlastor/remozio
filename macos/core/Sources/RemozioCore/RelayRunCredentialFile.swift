import CryptoKit
import Darwin
import Foundation

/// Retains the selected private token file. It grants no provider or approval authority.
final class RelayRunCredentialFile: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let lock = NSLock()
    private let directory: ReleaseDestinationLease
    private let owner: uid_t
    private let group: gid_t
    private let name: String
    private let tunnel: CloudflareTunnelObservation
    private let digest: Data
    private let verifyCurrent: @Sendable () throws -> Void
    private let processID = getpid()
    private var descriptor: Int32 = -1
    private var snapshot: stat?
    private var closed = false
    private var retired = false
    var description: String { "RelayRunCredentialFile(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    static func openNative(scope: GatewaySettingsConsumerNativeScope,
                           reference: RelayRunCredentialReference) throws -> RelayRunCredentialFile {
        let host = scope.configuration
        guard host.role == .transport, reference.runtime == host.runtime else { throw RuntimePreparationError.changedScope }
        try scope.validate()
        let path = try RuntimePreparationPaths(accountID: host.runtime.services.accountID).serviceDirectory
        let directory = try ReleaseDestinationLease.readForServiceRegistration(path: path)
        return try .init(directory: directory, owner: host.serviceUID, group: host.serviceUID,
            tunnel: reference.tunnel, digest: reference.credentialDigest, verifyCurrent: { try scope.validate() })
    }

    // Owned fixtures exercise file behavior. They do not prove Root ancestry or service-account isolation.
    init(directory: ReleaseDestinationLease, owner: uid_t, group: gid_t, tunnel: CloudflareTunnelObservation,
         digest: Data, verifyCurrent: @escaping @Sendable () throws -> Void = {}) throws {
        self.directory = directory; self.owner = owner; self.group = group; self.tunnel = tunnel
        self.digest = digest; self.verifyCurrent = verifyCurrent
        let file = AdministrativeSetupPublication.File.transportTunnelToken(ownerUID: owner, groupID: group)
        name = file.name
        var opened: Int32 = -1
        do {
            try file.validate()
            guard owner > 0, digest.count == 32, getuid() == owner, geteuid() == owner else {
                throw JournalLeaseError.unsafeMetadata
            }
            try verifyCurrent()
            let info = try directory.withDirectory { parent in
                opened = try Self.openFile(parent: parent, name: name)
                return try inspect(opened, parent: parent, expected: nil)
            }
            descriptor = opened; opened = -1; snapshot = info
            try validate()
        } catch {
            if opened >= 0 { _ = Darwin.close(opened) }
            close(); throw error
        }
    }
    deinit { close() }

    func validate() throws { try lock.withLock { try validateLocked() } }

    /// The callback borrows one fresh description for synchronous spawn actions. It must own any child it creates.
    /// Each description has an independent offset. Restarting a connector cannot reuse its predecessor's token cursor.
    func withDescriptorForSpawn<Value>(_ body: (Int32) throws -> Value) throws -> Value {
        try lock.withLock {
            var opened: Int32 = -1
            defer { if opened >= 0 { _ = Darwin.close(opened) } }
            do {
                try validateLocked()
                try directory.withDirectory { parent in
                    opened = try Self.openFile(parent: parent, name: name)
                    _ = try inspect(opened, parent: parent, expected: snapshot)
                }
                try verifyCurrent()
            } catch { retired = true; throw error }
            // Do not throw after the callback returns an owned child. Its supervisor validates later state.
            return try body(opened)
        }
    }
    func close() {
        lock.withLock {
            guard !closed else { return }; closed = true
            if descriptor >= 0 { _ = Darwin.close(descriptor); descriptor = -1 }
            directory.close()
        }
    }
    private func validateLocked() throws {
        guard !closed, !retired, descriptor >= 0, let snapshot else { throw JournalLeaseError.invalidated }
        do {
            guard getpid() == processID, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            try verifyCurrent()
            try directory.withDirectory { parent in _ = try inspect(descriptor, parent: parent, expected: snapshot) }
            try verifyCurrent()
        } catch { retired = true; throw error }
    }
    private static func openFile(parent: Int32, name: String) throws -> Int32 {
        let original = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard original >= 0 else { throw JournalLeaseError.system(errno) }
        defer { _ = Darwin.close(original) }
        // Keep source descriptors clear of the child's standard streams and fixed inherited descriptors.
        let copied = fcntl(original, F_DUPFD_CLOEXEC, 32)
        guard copied >= 0 else { throw JournalLeaseError.system(errno) }
        return copied
    }
    private func inspect(_ fd: Int32, parent: Int32, expected: stat?) throws -> stat {
        let before = try metadata(fd, parent: parent, expected: expected)
        var bytes = Data(count: Int(before.st_size)), offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes {
                pread(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset, off_t(offset))
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw count == 0 ? JournalLeaseError.identityChanged : JournalLeaseError.system(errno) }
            offset += count
        }
        _ = try metadata(fd, parent: parent, expected: before)
        guard Data(SHA256.hash(data: bytes)) == digest else { throw RuntimePreparationError.conflictingMaterial }
        _ = try CloudflareTunnelRunCredential.restore(bytes, tunnel: tunnel)
        return before
    }
    private func metadata(_ fd: Int32, parent: Int32, expected: stat?) throws -> stat {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino, named.st_mode & S_IFMT == S_IFREG else {
            throw JournalLeaseError.identityChanged
        }
        if let expected {
            guard held.st_dev == expected.st_dev, held.st_ino == expected.st_ino, held.st_size == expected.st_size,
                  held.st_mtimespec.tv_sec == expected.st_mtimespec.tv_sec,
                  held.st_mtimespec.tv_nsec == expected.st_mtimespec.tv_nsec,
                  held.st_ctimespec.tv_sec == expected.st_ctimespec.tv_sec,
                  held.st_ctimespec.tv_nsec == expected.st_ctimespec.tv_nsec else { throw JournalLeaseError.identityChanged }
        }
        guard held.st_uid == owner, held.st_gid == group, held.st_mode & 0o7777 == 0o600,
              held.st_size > 0, held.st_size <= CloudflareTunnelRunCredential.maximumTokenBytes else {
            throw JournalLeaseError.unsafeMetadata
        }
        try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
        let flags = fcntl(fd, F_GETFD), status = fcntl(fd, F_GETFL)
        guard flags >= 0, flags & FD_CLOEXEC != 0, status >= 0, status & O_ACCMODE == O_RDONLY else {
            throw JournalLeaseError.unsafeMetadata
        }
        return held
    }
}
