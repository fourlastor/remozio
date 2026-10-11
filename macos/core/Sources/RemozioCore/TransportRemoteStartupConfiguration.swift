import Darwin
import Foundation
import RemozioProtocol

/// Protected public metadata for one approval relay and the existing transport and optional wake worker.
public struct TransportRemoteStartupConfiguration: Sendable, CustomStringConvertible {
    public let transport: ApprovalTransportConfiguration
    public let wake: TransportWakeStartupConfiguration?
    public let relayPort: UInt16
    public let canonicalBytes: Data
    public var description: String { "TransportRemoteStartupConfiguration(redacted)" }

    public init(transport: ApprovalTransportConfiguration, wake: TransportWakeStartupConfiguration? = nil,
                relayPort: UInt16) throws {
        guard relayPort > 0, wake == nil || wake?.transport.canonicalBytes == transport.canonicalBytes else {
            throw ApprovalTransportStartupError.invalidConfiguration
        }
        self.transport = transport; self.wake = wake; self.relayPort = relayPort
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(transport.canonicalBytes),
            2: wake.map { .bytes($0.canonicalBytes) } ?? .null, 3: .unsigned(UInt64(relayPort))]), limits: Self.limits)
    }
    public static func load(path: String) throws -> Self {
        let value = try decode(ProtectedServiceConfiguration.readPublic(path: path))
        try value.transport.requireProcess(realUID: getuid(), effectiveUID: geteuid())
        return value
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(1),
              case .bytes(let transport) = fields[1], case .unsigned(let port) = fields[3],
              let relayPort = UInt16(exactly: port) else { throw ApprovalTransportStartupError.invalidConfiguration }
        let wake: TransportWakeStartupConfiguration?
        switch fields[2] {
        case .null?: wake = nil
        case .bytes(let bytes)?: wake = try TransportWakeStartupConfiguration.decode(bytes)
        default: throw ApprovalTransportStartupError.invalidConfiguration
        }
        let result = try Self(transport: ApprovalTransportConfiguration.decode(transport), wake: wake, relayPort: relayPort)
        guard result.canonicalBytes == bytes else { throw ApprovalTransportStartupError.invalidConfiguration }
        return result
    }
    private static var limits: CBORLimits {
        get throws { try .init(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 1, maxItems: 9) }
    }
}
