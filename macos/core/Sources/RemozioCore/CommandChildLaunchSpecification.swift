import Darwin
import Foundation
import RemozioProtocol

/// Prepared by Root from the active filesystem proof.
struct CommandExecutableLaunch: Sendable {
    enum Mode: UInt32, Sendable {
        case protectedPath = 1
        case pathBound = 2
    }

    enum PathBoundReason: String, Sendable {
        case pathEncoding = "path-encoding"
        case rootIdentity = "root-identity"
        case unsafePlacement = "unsafe-placement"
        case identityChanged = "identity-changed"
        case inspectionFailed = "inspection-failed"
    }

    let mode: Mode
    let info: stat
    let pathBoundReason: PathBoundReason?

    init(mode: Mode, info: stat, pathBoundReason: PathBoundReason? = nil) {
        self.mode = mode
        self.info = info
        self.pathBoundReason = pathBoundReason
    }

    func accepts(_ current: Self) -> Bool {
        CommandFilesystemCapture.stable(info, current.info) &&
            (mode == .pathBound || current.mode == .protectedPath)
    }
}

/// Private Root-to-child data. These bytes are not an authorization or a public command endpoint.
struct CommandChildLaunchSpecification {
    static let maximumBytes = 8 * 1024 * 1024
    static let maximumEntries = 262_144
    let canonicalBytes: Data

    init(capture: CommandCapture, resolvedExecutablePath: Data? = nil, launch: CommandExecutableLaunch,
         preparationMilliseconds: UInt32, fileCreationMask: UInt32) throws {
        try self.init(capture: capture, executablePath: resolvedExecutablePath ?? capture.executable.path,
            preparationMilliseconds: preparationMilliseconds,
            fileCreationMask: fileCreationMask, directoryAccount: true, launch: launch)
    }

    /// Encodes format 3 for native compatibility fixtures.
    init(historicalAccountCapture capture: CommandCapture, resolvedExecutablePath: Data? = nil,
         preparationMilliseconds: UInt32, fileCreationMask: UInt32) throws {
        try self.init(capture: capture, executablePath: resolvedExecutablePath ?? capture.executable.path,
            preparationMilliseconds: preparationMilliseconds, fileCreationMask: fileCreationMask, directoryAccount: true)
    }

    /// Encodes the historical static-group format for compatibility controls. The production child refuses it.
    init(legacyCapture capture: CommandCapture, preparationMilliseconds: UInt32, fileCreationMask: UInt32) throws {
        try self.init(capture: capture, executablePath: capture.executable.path, preparationMilliseconds: preparationMilliseconds,
            fileCreationMask: fileCreationMask, directoryAccount: false)
    }

    private init(capture: CommandCapture, executablePath: Data, preparationMilliseconds: UInt32, fileCreationMask: UInt32,
                 directoryAccount: Bool, launch: CommandExecutableLaunch? = nil) throws {
        guard (100...60_000).contains(preparationMilliseconds), fileCreationMask <= 0o777,
              capture.target.uid != UInt32.max, capture.target.gid != UInt32.max,
              capture.target.supplementaryGroups.count <= (directoryAccount ? 1024 : 16),
              Set(capture.target.supplementaryGroups + [capture.target.gid]).count <= (directoryAccount ? 1024 : 16),
              capture.target.supplementaryGroups.allSatisfy({ $0 != UInt32.max }),
              !capture.arguments.isEmpty, capture.arguments.count <= Self.maximumEntries,
              capture.environment.count <= Self.maximumEntries else { throw CommandChildSpecificationError.invalid }
        let accountName: Data?
        if directoryAccount {
            guard let name = capture.target.observedName, !name.isEmpty else { throw CommandChildSpecificationError.invalid }
            let bytes = Data(name.utf8), groups = capture.target.supplementaryGroups
            guard bytes.count <= 65_535, !bytes.contains(0), !groups.isEmpty,
                  groups.contains(capture.target.gid), groups == Set(groups).sorted() else {
                throw CommandChildSpecificationError.invalid
            }
            accountName = bytes
        } else { accountName = nil }
        var body = Data()
        func appendWord(_ value: UInt32) { var word = value.bigEndian; withUnsafeBytes(of: &word) { body.append(contentsOf: $0) } }
        func appendWideWord(_ value: UInt64) {
            appendWord(UInt32(value >> 32))
            appendWord(UInt32(truncatingIfNeeded: value))
        }
        func appendString(_ value: Data) throws {
            guard !value.contains(0), let count = UInt32(exactly: value.count),
                  value.count <= Self.maximumBytes - min(body.count, Self.maximumBytes) - 4 else {
                throw CommandChildSpecificationError.invalid
            }
            appendWord(count); body.append(value)
        }
        let mappedTerminal = capture.ioMode == .pty && capture.stdioLayout != nil
        if directoryAccount || mappedTerminal {
            appendWord(mappedTerminal ? capture.stdioLayout!.ptyMask : capture.ioMode == .pty ? 7 : 0)
        }
        if let launch {
            let file = launch.info
            guard file.st_size >= 0, (0..<1_000_000_000).contains(file.st_mtimespec.tv_nsec),
                  (0..<1_000_000_000).contains(file.st_ctimespec.tv_nsec) else {
                throw CommandChildSpecificationError.invalid
            }
            appendWord(launch.mode.rawValue)
            appendWord(UInt32(bitPattern: file.st_dev))
            appendWideWord(file.st_ino)
            appendWideWord(UInt64(file.st_size))
            appendWord(UInt32(file.st_mode))
            appendWord(file.st_uid)
            appendWord(file.st_gid)
            appendWideWord(UInt64(bitPattern: Int64(file.st_mtimespec.tv_sec)))
            appendWord(UInt32(file.st_mtimespec.tv_nsec))
            appendWideWord(UInt64(bitPattern: Int64(file.st_ctimespec.tv_sec)))
            appendWord(UInt32(file.st_ctimespec.tv_nsec))
        }
        for group in capture.target.supplementaryGroups { appendWord(group) }
        if let accountName { try appendString(accountName) }
        guard executablePath.first == 0x2f else { throw CommandChildSpecificationError.invalid }
        try appendString(executablePath)
        for argument in capture.arguments { try appendString(argument) }
        var previous: Data?
        for entry in capture.environment {
            guard !entry.name.isEmpty, !entry.name.contains(0), !entry.name.contains(0x3d),
                  previous == nil || previous!.lexicographicallyPrecedes(entry.name) else {
                throw CommandChildSpecificationError.invalid
            }
            var value = entry.name; value.append(0x3d); value.append(entry.value)
            try appendString(value); previous = entry.name
        }
        guard body.count <= Self.maximumBytes - 40, let count = UInt32(exactly: body.count) else {
            throw CommandChildSpecificationError.invalid
        }
        var frame = Data()
        let format: UInt32
        if launch != nil { format = 0x524d4334 }
        else if directoryAccount { format = 0x524d4333 }
        else { format = mappedTerminal ? 0x524d4332 : 0x524d4331 }
        for value: UInt32 in [format, count, capture.target.uid, capture.target.gid,
            UInt32(capture.target.supplementaryGroups.count), UInt32(capture.arguments.count), UInt32(capture.environment.count),
            preparationMilliseconds, fileCreationMask, mappedTerminal ? 2 : UInt32(capture.ioMode.rawValue)] {
            var word = value.bigEndian; withUnsafeBytes(of: &word) { frame.append(contentsOf: $0) }
        }
        frame.append(body); canonicalBytes = frame
    }
}

enum CommandChildSpecificationError: Error { case invalid }
