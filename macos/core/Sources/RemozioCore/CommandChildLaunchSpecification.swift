import Foundation
import RemozioProtocol

/// Private Root-to-child data. These bytes are not an authorization or a public command endpoint.
struct CommandChildLaunchSpecification {
    static let maximumBytes = 8 * 1024 * 1024
    static let maximumEntries = 262_144
    let canonicalBytes: Data

    init(capture: CommandCapture, preparationMilliseconds: UInt32, fileCreationMask: UInt32) throws {
        try self.init(capture: capture, preparationMilliseconds: preparationMilliseconds,
            fileCreationMask: fileCreationMask, directoryAccount: true)
    }

    /// Encodes the historical static-group format for compatibility controls. The production child refuses it.
    init(legacyCapture capture: CommandCapture, preparationMilliseconds: UInt32, fileCreationMask: UInt32) throws {
        try self.init(capture: capture, preparationMilliseconds: preparationMilliseconds,
            fileCreationMask: fileCreationMask, directoryAccount: false)
    }

    private init(capture: CommandCapture, preparationMilliseconds: UInt32, fileCreationMask: UInt32,
                 directoryAccount: Bool) throws {
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
        for group in capture.target.supplementaryGroups { appendWord(group) }
        if let accountName { try appendString(accountName) }
        guard capture.executable.path.first == 0x2f else { throw CommandChildSpecificationError.invalid }
        try appendString(capture.executable.path)
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
        for value: UInt32 in [directoryAccount ? 0x524d4333 : mappedTerminal ? 0x524d4332 : 0x524d4331, count, capture.target.uid, capture.target.gid,
            UInt32(capture.target.supplementaryGroups.count), UInt32(capture.arguments.count), UInt32(capture.environment.count),
            preparationMilliseconds, fileCreationMask, mappedTerminal ? 2 : UInt32(capture.ioMode.rawValue)] {
            var word = value.bigEndian; withUnsafeBytes(of: &word) { frame.append(contentsOf: $0) }
        }
        frame.append(body); canonicalBytes = frame
    }
}

enum CommandChildSpecificationError: Error { case invalid }
