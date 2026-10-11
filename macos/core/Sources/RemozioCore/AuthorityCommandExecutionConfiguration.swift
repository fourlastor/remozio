import Darwin
import Foundation
import RemozioProtocol

/// Protected host inputs for execution. Decoding grants no dispatch or installation authority.
public struct AuthorityCommandExecutionConfiguration: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public static let supportedVersions: Set<UInt64> = [1]
    public let monitorPath: String
    public let childPath: String
    public let preparationMilliseconds: UInt32
    public let fileCreationMask: UInt32
    public let maximumActiveCommands: Int
    public let pollIntervalMilliseconds: Int
    public let maximumPending: Int
    public let canonicalBytes: Data
    public var description: String { "AuthorityCommandExecutionConfiguration(redacted)" }
    public var debugDescription: String { description }

    public init(monitorPath: String, childPath: String, preparationMilliseconds: UInt32 = 5000,
                fileCreationMask: UInt32 = 0o077, maximumActiveCommands: Int = 32,
                pollIntervalMilliseconds: Int = 20, maximumPending: Int = 1024) throws {
        guard Self.validPath(monitorPath), Self.validPath(childPath), monitorPath != childPath,
              (100...60_000).contains(preparationMilliseconds), fileCreationMask <= 0o777,
              (1...1024).contains(maximumActiveCommands), (10...1000).contains(pollIntervalMilliseconds),
              (1...4096).contains(maximumPending) else { throw AuthorityCommandStartupError.invalidConfiguration }
        self.monitorPath = monitorPath; self.childPath = childPath
        self.preparationMilliseconds = preparationMilliseconds; self.fileCreationMask = fileCreationMask
        self.maximumActiveCommands = maximumActiveCommands; self.pollIntervalMilliseconds = pollIntervalMilliseconds
        self.maximumPending = maximumPending
        canonicalBytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .text(monitorPath), 2: .text(childPath),
            3: .unsigned(UInt64(preparationMilliseconds)), 4: .unsigned(UInt64(fileCreationMask)),
            5: .unsigned(UInt64(maximumActiveCommands)), 6: .unsigned(UInt64(pollIntervalMilliseconds)),
            7: .unsigned(UInt64(maximumPending))
        ]), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...7), case .unsigned(let version) = fields[0], supportedVersions.contains(version),
              case .text(let monitor) = fields[1], case .text(let child) = fields[2] else {
            throw AuthorityCommandStartupError.invalidConfiguration
        }
        func number(_ key: UInt64) throws -> UInt64 {
            guard case .unsigned(let value) = fields[key] else { throw AuthorityCommandStartupError.invalidConfiguration }
            return value
        }
        func duration(_ key: UInt64) throws -> UInt32 {
            guard let value = UInt32(exactly: try number(key)) else { throw AuthorityCommandStartupError.invalidConfiguration }
            return value
        }
        func integer(_ key: UInt64) throws -> Int {
            guard let value = Int(exactly: try number(key)) else { throw AuthorityCommandStartupError.invalidConfiguration }
            return value
        }
        let value = try Self(monitorPath: monitor, childPath: child, preparationMilliseconds: duration(3),
            fileCreationMask: duration(4), maximumActiveCommands: integer(5), pollIntervalMilliseconds: integer(6), maximumPending: integer(7))
        guard value.canonicalBytes == bytes else { throw AuthorityCommandStartupError.invalidConfiguration }
        return value
    }

    private static func validPath(_ value: String) -> Bool {
        let parts = value.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        return value.hasPrefix("/") && value.utf8.count < Int(PATH_MAX) && !parts.isEmpty &&
            parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 2, maxItems: 32) } }
}
