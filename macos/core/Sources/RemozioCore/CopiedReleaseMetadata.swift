import Darwin
import Foundation

/// Checks copied objects and the typed installed app root. Attribute values confer no authority.
enum CopiedReleaseMetadata {
    enum Context { case copiedObject, installedApplicationRoot }
    static func validate(_ fd: Int32, _ info: stat, context: Context = .copiedObject) throws {
        guard info.st_flags == 0 else { throw JournalLeaseError.unsafeMetadata }
        var allowed: Set<String> = ["com.apple.provenance"]
        if context == .installedApplicationRoot {
            guard info.st_mode & S_IFMT == S_IFDIR else { throw JournalLeaseError.unsafeMetadata }
            allowed.insert("com.apple.macl")
        }
        guard try attributeNames(fd).isSubset(of: allowed) else {
            throw JournalLeaseError.unsafeMetadata
        }
    }

    private static func attributeNames(_ fd: Int32) throws -> Set<String> {
        for _ in 0..<3 {
            let size = flistxattr(fd, nil, 0, XATTR_SHOWCOMPRESSION)
            guard size >= 0 else { throw JournalLeaseError.system(errno) }
            guard size <= 8192 else { throw JournalLeaseError.unsafeMetadata }
            if size == 0 { return [] }
            var buffer = [CChar](repeating: 0, count: size)
            let count = buffer.withUnsafeMutableBufferPointer {
                flistxattr(fd, $0.baseAddress!, $0.count, XATTR_SHOWCOMPRESSION)
            }
            if count < 0 && errno == ERANGE { continue }
            guard count >= 0 else { throw JournalLeaseError.system(errno) }
            guard count > 0, count <= buffer.count, buffer[count - 1] == 0 else {
                throw JournalLeaseError.unsafeMetadata
            }
            let bytes = buffer.prefix(count).map { UInt8(bitPattern: $0) }
            let parts = bytes.dropLast().split(separator: 0, omittingEmptySubsequences: false)
            guard parts.count <= 64 else { throw JournalLeaseError.unsafeMetadata }
            var names = Set<String>()
            for part in parts {
                guard !part.isEmpty, part.count <= Int(XATTR_MAXNAMELEN),
                      let name = String(bytes: part, encoding: .utf8), names.insert(name).inserted else {
                    throw JournalLeaseError.unsafeMetadata
                }
            }
            return names
        }
        throw JournalLeaseError.system(ERANGE)
    }
}
