import Darwin
import Foundation

public enum AXStructureProbeError: String, Error, Equatable {
    case invalidArguments, ordinaryUserRequired, unsafeDirectory, outputExists, encodingFailed, writeFailed, publicationUncertain
}

public struct AXStructureProbeRequest: Equatable, Sendable {
    public let processID: Int32
    public let outputPath: String

    public init(arguments: [String]) throws {
        guard arguments.count == 4 else { throw AXStructureProbeError.invalidArguments }
        var fields: [String: String] = [:]
        for index in stride(from: 0, to: arguments.count, by: 2) {
            let key = arguments[index]
            guard ["--pid", "--output"].contains(key), fields[key] == nil else { throw AXStructureProbeError.invalidArguments }
            fields[key] = arguments[index + 1]
        }
        guard let text = fields["--pid"], !text.isEmpty, text.utf8.allSatisfy({ (48...57).contains($0) }),
              let processID = Int32(text), processID > 0, let path = fields["--output"] else {
            throw AXStructureProbeError.invalidArguments
        }
        _ = try Self.pathComponents(path)
        self.processID = processID; outputPath = path
    }
    static func pathComponents(_ path: String) throws -> [String] {
        guard path.hasPrefix("/"), path.utf8.count <= 4096, !path.utf8.contains(0) else { throw AXStructureProbeError.invalidArguments }
        let parts = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255 }) else {
            throw AXStructureProbeError.invalidArguments
        }
        return parts
    }
}

/// Publishes one local diagnostic without replacement. The JSON is data, never an authorization or selector contract.
public enum AXStructureFixtureFile {
    static let maximumEncodedBytes = 8 * 1024 * 1024

    public static func save(_ snapshot: AXStructureSnapshot, request: AXStructureProbeRequest) throws {
        guard getuid() > 0, getuid() == geteuid() else {
            throw AXStructureProbeError.ordinaryUserRequired
        }
        guard snapshot.processID == request.processID else { throw AXStructureProbeError.invalidArguments }
        let components = try AXStructureProbeRequest.pathComponents(request.outputPath)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        let bytes: Data
        do { bytes = try encoder.encode(snapshot) + Data([10]) }
        catch { throw AXStructureProbeError.encodingFailed }
        guard bytes.count <= maximumEncodedBytes else { throw AXStructureProbeError.encodingFailed }
        let parent = try openParent(components: Array(components.dropLast()))
        defer { close(parent) }
        let file = components.last!, temporary = ".remozio-ax-" + UUID().uuidString + ".tmp"
        let fd = openat(parent, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw AXStructureProbeError.writeFailed }
        defer { close(fd) }
        var owned = stat()
        guard fstat(fd, &owned) == 0 else { throw AXStructureProbeError.writeFailed }
        defer {
            var current = stat()
            if fstatat(parent, temporary, &current, AT_SYMLINK_NOFOLLOW) == 0,
               current.st_dev == owned.st_dev, current.st_ino == owned.st_ino {
                _ = unlinkat(parent, temporary, 0)
            }
        }
        guard owned.st_mode & S_IFMT == S_IFREG, owned.st_uid == getuid(), owned.st_nlink == 1,
              fchmod(fd, mode_t(0o600)) == 0 else { throw AXStructureProbeError.writeFailed }
        try bytes.withUnsafeBytes { buffer in
            var offset = 0, interruptions = 0
            while offset < buffer.count {
                let count = write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0, errno == EINTR, interruptions < 128 { interruptions += 1; continue }
                guard count > 0 else { throw AXStructureProbeError.writeFailed }
                offset += count
            }
        }
        guard fsync(fd) == 0 else { throw AXStructureProbeError.writeFailed }
        guard linkat(parent, temporary, parent, file, 0) == 0 else {
            if errno == EEXIST { throw AXStructureProbeError.outputExists }
            throw AXStructureProbeError.writeFailed
        }
        // A failure here is ambiguous publication. Keep the destination and never overwrite or retry it.
        guard fsync(parent) == 0 else { throw AXStructureProbeError.publicationUncertain }
    }
    private static func openParent(components: [String]) throws -> Int32 {
        let path = "/" + components.joined(separator: "/")
        guard let resolved = realpath(path, nil) else { throw AXStructureProbeError.unsafeDirectory }
        defer { free(resolved) }
        guard let canonical = String(validatingCString: resolved) else { throw AXStructureProbeError.unsafeDirectory }
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw AXStructureProbeError.unsafeDirectory }
        do {
            for component in canonical.dropFirst().split(separator: "/").map(String.init) {
                let next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw AXStructureProbeError.unsafeDirectory }
                close(fd); fd = next
            }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  info.st_uid == getuid(), info.st_mode & 0o022 == 0 else { throw AXStructureProbeError.unsafeDirectory }
            return fd
        } catch { close(fd); throw error }
    }
}
