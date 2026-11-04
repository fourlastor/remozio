import Darwin
import Foundation

/// Retains existing gateway file identities and its writer lock. Never opens SQLite or changes stored data.
final class GatewayJournalCutoverLease {
    private let parent: ProtectedSetupDirectory
    private let owner: uid_t
    private let serviceUID: uid_t
    private let serviceGID: gid_t
    private let expected: GatewayJournalFileIdentity?
    private let verifyCurrent: () throws -> Void
    private let processID = getpid()
    private var directory: Int32 = -1
    private var writer: Int32 = -1
    private var database: Int32 = -1
    private var closed = false
    private var retired = false

    static func open(graph: RuntimeAuditUpgradeGraph, rootActivity: ReleaseActivityToken,
                     verifyOwner: @escaping () throws -> Void) throws -> GatewayJournalCutoverLease {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try graph.requireOwner(0)
        let services = graph.snapshot.plan.preparation.intent.source.services
        guard let claim = services.claims.first(where: { $0.role == .gateway }),
              let retained = graph.snapshot.retainedParents[.services] else { throw RuntimePreparationError.incomplete }
        let path = try RuntimePreparationPaths(accountID: services.accountID).serviceDirectory
        guard path == retained.path, !retained.missingChild else { throw RuntimePreparationError.changedScope }
        let parent = try ProtectedSetupDirectory(anchor: "/", relativePath: String(path.dropFirst()), owner: 0,
            visibility: .sharedMetadata, createIfMissing: false)
        func verify() throws {
            try rootActivity.validateExclusive(); try verifyOwner()
            try parent.withSharedDirectory { fd in
                var value = stat(); guard fstat(fd, &value) == 0 else { throw JournalLeaseError.system(errno) }
                guard value.st_dev == retained.device, value.st_ino == retained.inode else { throw JournalLeaseError.identityChanged }
            }
        }
        return try .init(parent: parent, owner: 0, serviceUID: claim.number, serviceGID: claim.number,
            expected: graph.gatewayJournalIdentity, verifyCurrent: verify)
    }
    static func openOwned(parent: ProtectedSetupDirectory, expected: GatewayJournalFileIdentity?,
                          verifyCurrent: @escaping () throws -> Void = {}) throws -> GatewayJournalCutoverLease {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return try .init(parent: parent, owner: getuid(), serviceUID: getuid(), serviceGID: getgid(),
            expected: expected, verifyCurrent: verifyCurrent)
    }
    private init(parent: ProtectedSetupDirectory, owner: uid_t, serviceUID: uid_t, serviceGID: gid_t,
                 expected: GatewayJournalFileIdentity?, verifyCurrent: @escaping () throws -> Void) throws {
        self.parent = parent; self.owner = owner; self.serviceUID = serviceUID; self.serviceGID = serviceGID
        self.expected = expected; self.verifyCurrent = verifyCurrent
        do {
            try verifyCurrent()
            try parent.withSharedDirectory { fd in
                if expected == nil { try requireAbsent(fd); return }
                directory = openat(fd, "Gateway", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard directory >= 0 else { throw JournalLeaseError.system(errno) }
                writer = openat(directory, "writer.lock", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard writer >= 0 else { throw JournalLeaseError.system(errno) }
                database = openat(directory, "gateway.sqlite", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard database >= 0 else { throw JournalLeaseError.system(errno) }
                try inspect(fd)
                guard flock(writer, LOCK_EX | LOCK_NB) == 0 else {
                    throw errno == EWOULDBLOCK ? JournalLeaseError.busy : JournalLeaseError.system(errno)
                }
                try inspect(fd)
            }
            try validate()
        } catch { close(); throw error }
    }
    private func requireAbsent(_ fd: Int32) throws {
        var value = stat()
        guard fstatat(fd, "Gateway", &value, AT_SYMLINK_NOFOLLOW) < 0, errno == ENOENT else { throw JournalLeaseError.identityChanged }
    }
    private func inspect(_ fd: Int32) throws {
        guard try GatewayJournalFileProvisioning.inspect(parent: fd, name: "Gateway", directory: directory,
            writer: writer, database: database, serviceUID: serviceUID, serviceGID: serviceGID,
            processOwner: owner, requireEmpty: false) == expected else { throw JournalLeaseError.identityChanged }
        for descriptor in [directory, writer, database] {
            let flags = fcntl(descriptor, F_GETFD), status = fcntl(descriptor, F_GETFL)
            guard flags >= 0, flags & FD_CLOEXEC != 0, status >= 0, status & O_ACCMODE == O_RDONLY else {
                throw JournalLeaseError.unsafeMetadata
            }
        }
    }
    func validate() throws {
        guard !closed, !retired else { throw JournalLeaseError.invalidated }
        do {
            guard getpid() == processID, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            try verifyCurrent()
            try parent.withSharedDirectory { fd in if expected == nil { try requireAbsent(fd) } else { try inspect(fd) } }
            try verifyCurrent()
        } catch { retired = true; throw error }
    }
    func close() {
        guard !closed else { return }; closed = true
        for fd in [database, writer, directory] where fd >= 0 { _ = Darwin.close(fd) }
        database = -1; writer = -1; directory = -1
    }
    deinit { close() }
}
