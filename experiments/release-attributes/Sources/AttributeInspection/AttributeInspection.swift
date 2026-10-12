import Darwin
import Foundation

enum AttributeError: Error, Equatable { case limit, malformed, system(Int32) }
struct AttributeInspection {
    static func names(fd: Int32, maximumBytes: Int = 8192, maximumNames: Int = 64) throws -> Set<String> {
        guard (1...8192).contains(maximumBytes), (1...64).contains(maximumNames) else { throw AttributeError.limit }
        for _ in 0..<3 {
            let size = flistxattr(fd, nil, 0, XATTR_SHOWCOMPRESSION)
            guard size >= 0 else { throw AttributeError.system(errno) }
            guard size <= maximumBytes else { throw AttributeError.limit }
            if size == 0 { return [] }
            var buffer = [CChar](repeating: 0, count: size)
            let count = buffer.withUnsafeMutableBufferPointer { flistxattr(fd, $0.baseAddress!, $0.count, XATTR_SHOWCOMPRESSION) }
            if count < 0 && errno == ERANGE { continue }
            guard count > 0, count <= buffer.count, buffer[count - 1] == 0 else {
                if count < 0 { throw AttributeError.system(errno) }
                throw AttributeError.malformed
            }
            let bytes = buffer.prefix(count).map { UInt8(bitPattern: $0) }
            let parts = bytes.dropLast().split(separator: 0, omittingEmptySubsequences: false)
            guard parts.count <= maximumNames else { throw AttributeError.limit }
            var names = Set<String>()
            for part in parts {
                guard !part.isEmpty, part.count <= Int(XATTR_MAXNAMELEN),
                      let name = String(bytes: part, encoding: .utf8), names.insert(name).inserted else {
                    throw AttributeError.malformed
                }
            }
            return names
        }
        throw AttributeError.system(ERANGE)
    }
}
