import Darwin
import Foundation

public enum SetupPreviewReadError: Error { case unreadable, rejected }

/// Serializes password derivation. Opening a setup file does not apply its configuration.
public actor SetupFilePreviewReader {
    public static let shared = SetupFilePreviewReader()
    public init() {}

    public func preview(file: URL, password: String) throws -> SetupPreview {
        let reviewed = try review(file: file, password: password)
        defer { reviewed.close() }
        return reviewed.preview
    }

    public func review(file: URL, password: String) throws -> ReviewedSetupFile {
        try Task.checkCancellation()
        let scoped = file.startAccessingSecurityScopedResource()
        defer { if scoped { file.stopAccessingSecurityScopedResource() } }
        let encrypted = try Self.read(file)
        try Task.checkCancellation()
        let proposal: PortableSetup
        do { proposal = try PortableSetup(encryptedFile: encrypted, password: password) }
        catch { throw SetupPreviewReadError.rejected }
        try Task.checkCancellation()
        return ReviewedSetupFile(proposal: proposal)
    }

    static func read(_ file: URL) throws -> Data {
        guard file.isFileURL else { throw SetupPreviewReadError.unreadable }
        let fd = file.withUnsafeFileSystemRepresentation { path in
            path.map { Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NONBLOCK) } ?? -1
        }
        guard fd >= 0 else { throw SetupPreviewReadError.unreadable }
        defer { Darwin.close(fd) }
        var info = stat()
        let limit = SetupFileEncryption.maximumFileBytes
        guard fstat(fd, &info) == 0, info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              info.st_size > 0, info.st_size <= limit else { throw SetupPreviewReadError.unreadable }
        var output = Data()
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while output.count <= limit {
            try Task.checkCancellation()
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, min($0.count, limit + 1 - output.count)) }
            if count < 0 {
                if errno == EINTR { continue }
                throw SetupPreviewReadError.unreadable
            }
            if count == 0 { return output }
            output.append(contentsOf: buffer.prefix(count))
        }
        throw SetupPreviewReadError.unreadable
    }
}
