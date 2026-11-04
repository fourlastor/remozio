import Darwin
import Foundation

/// Reject recovery files before SQLite opens. The caller must retain its protected writer lease throughout inspection.
enum CutoverSQLitePreflight {
    static func validate(path: String, validateLease: () throws -> Void) throws {
        try validateLease()
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { throw JournalLeaseError.system(errno) }
        defer { _ = Darwin.close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0 else { throw JournalLeaseError.system(errno) }
        guard (info.st_mode & S_IFMT) == S_IFREG, info.st_size >= 100 else { throw JournalDatabaseError.incompatibleStore }
        var header = [UInt8](repeating: 0, count: 100), used = 0
        while used < header.count {
            let count = header.withUnsafeMutableBytes { pread(descriptor, $0.baseAddress!.advanced(by: used), $0.count - used, off_t(used)) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw JournalDatabaseError.incompatibleStore }; used += count
        }
        guard header.prefix(16).elementsEqual("SQLite format 3\0".utf8), header[18] == 1, header[19] == 1 else {
            throw JournalDatabaseError.incompatibleStore
        }
        for suffix in ["-journal", "-wal", "-shm"] {
            var sidecar = stat()
            if lstat(path + suffix, &sidecar) == 0 { throw JournalDatabaseError.incompatibleStore }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
        }
        try validateLease()
    }
}
