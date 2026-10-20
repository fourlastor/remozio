import Darwin
import Foundation

/// Remove only the exact protected fence inode. The owner supplies current scope and live acceptance checks.
enum GatewaySettingsFenceRemoval {
    enum Result: Equatable { case removed, absent }
    static func remove(_ bytes: Data, directory: ProtectedSetupDirectory, owner: uid_t,
                       verifyCurrent: () throws -> Void, didValidate: () throws -> Void = {},
                       didRemove: () throws -> Void = {}) throws -> Result {
        guard getuid() == owner, geteuid() == owner, !bytes.isEmpty,
              bytes.count <= ProtectedServiceConfiguration.maximumBytes else { throw JournalLeaseError.unsafeMetadata }
        let file = AdministrativeSetupPublication.File.gatewaySettingsFence
        func verify() throws { try verifyCurrent(); try directory.validate() }
        func requireAbsent(_ parent: Int32) throws {
            var named = stat()
            guard fstatat(parent, file.name, &named, AT_SYMLINK_NOFOLLOW) < 0 else { throw JournalLeaseError.identityChanged }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
        }
        try verify()
        return try directory.withSharedDirectory { parent in
            let fd = openat(parent, file.name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            if fd < 0 {
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
                try verify()
                guard fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
                try requireAbsent(parent); return .absent
            }
            defer { _ = Darwin.close(fd) }
            func inspect() throws -> stat {
                var held = stat(), named = stat()
                guard fstat(fd, &held) == 0, fstatat(parent, file.name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw JournalLeaseError.identityChanged }
                try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: false, owner: owner, ancestorOwner: owner)
                guard held.st_mode & 0o7777 == file.mode, held.st_size == bytes.count else { throw JournalLeaseError.unsafeMetadata }
                return held
            }
            let original = try inspect()
            var data = Data(count: bytes.count), offset = 0
            while offset < data.count {
                let count = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw JournalLeaseError.identityChanged }; offset += count
            }
            guard data == bytes else { throw GatewayPreparationError.changedScope }
            try didValidate(); try verify()
            let current = try inspect()
            guard current.st_dev == original.st_dev, current.st_ino == original.st_ino,
                  current.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec, current.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec,
                  current.st_ctimespec.tv_sec == original.st_ctimespec.tv_sec, current.st_ctimespec.tv_nsec == original.st_ctimespec.tv_nsec else {
                throw JournalLeaseError.identityChanged
            }
            guard unlinkat(parent, file.name, 0) == 0, fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
            try didRemove(); try verify()
            try requireAbsent(parent); return .removed
        }
    }
}
