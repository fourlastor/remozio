import Darwin
import Foundation

final class EnclaveProbeNamespace {
    static let path = "/Library/Application Support/RemozioEnclaveLifecycleExperiment"
    private static let file = "key-state.bin"
    private let directory: Int32
    private let placement: ServiceProbePlacement
    private let device: dev_t
    private let inode: ino_t

    init() throws {
        guard getuid() == 0, geteuid() == 0 else { throw EnclaveProbeError.wrongAccount }
        let placement = try ServiceProbePlacement(app: URL(fileURLWithPath: Self.path))
        let fd = open(Self.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw EnclaveProbeError.unsafePlacement }
        do {
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw EnclaveProbeError.unsafePlacement }
            try ProtectedStorageMetadata.validate(fd, info, directory: true, privateObject: true, owner: 0, ancestorOwner: 0)
            try placement.validate()
            self.placement = placement; directory = fd; device = info.st_dev; inode = info.st_ino
        } catch { _ = Darwin.close(fd); placement.close(); throw error }
    }
    deinit { _ = Darwin.close(directory); placement.close() }
    private func validate() throws {
        guard getuid() == 0, geteuid() == 0 else { throw EnclaveProbeError.wrongAccount }
        var held = stat(), named = stat()
        guard fstat(directory, &held) == 0, lstat(Self.path, &named) == 0,
              held.st_dev == device, held.st_ino == inode, named.st_dev == device, named.st_ino == inode else {
            throw EnclaveProbeError.unsafePlacement
        }
        try ProtectedStorageMetadata.validate(directory, held, directory: true, privateObject: true, owner: 0, ancestorOwner: 0)
        try placement.validate()
    }
    func requireAbsent() throws {
        try validate()
        var info = stat()
        guard fstatat(directory, Self.file, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else {
            throw EnclaveProbeError.unsafePlacement
        }
    }
    private func inspect(_ fd: Int32) throws -> stat {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(directory, Self.file, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw EnclaveProbeError.unsafePlacement }
        try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: true, owner: 0, ancestorOwner: 0)
        return held
    }
    func read() throws -> EnclaveProbeRecord {
        try validate()
        let fd = openat(directory, Self.file, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw EnclaveProbeError.unsafePlacement }
        defer { _ = Darwin.close(fd) }
        let before = try inspect(fd)
        guard before.st_size > 0, before.st_size <= EnclaveProbeRecord.fixedBytes + EnclaveProbeRecord.maximumWrappedBytes else {
            throw EnclaveProbeError.invalidState
        }
        var data = Data(count: Int(before.st_size)), offset = 0
        while offset < data.count {
            let count = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw EnclaveProbeError.invalidState }
            offset += count
        }
        let after = try inspect(fd)
        guard after.st_dev == before.st_dev, after.st_ino == before.st_ino, after.st_size == before.st_size,
              after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec, after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec,
              after.st_ctimespec.tv_sec == before.st_ctimespec.tv_sec, after.st_ctimespec.tv_nsec == before.st_ctimespec.tv_nsec else {
            throw EnclaveProbeError.unsafePlacement
        }
        try validate()
        return try EnclaveProbeRecord.decode(data)
    }
    func create(_ record: EnclaveProbeRecord) throws {
        try requireAbsent()
        let bytes = record.encode()
        let fd = openat(directory, Self.file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw EnclaveProbeError.unsafePlacement }
        defer { _ = Darwin.close(fd) }
        guard fchmod(fd, 0o600) == 0 else { throw EnclaveProbeError.unsafePlacement }
        _ = try inspect(fd)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw EnclaveProbeError.invalidState }
            offset += count
        }
        guard fsync(fd) == 0, fsync(directory) == 0, try inspect(fd).st_size == bytes.count else {
            throw EnclaveProbeError.unsafePlacement
        }
        try validate()
        guard try read().encode() == bytes else { throw EnclaveProbeError.invalidState }
    }
}
