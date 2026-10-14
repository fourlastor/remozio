import Foundation
import RemozioProtocol

/// Explicit optional setup control alongside the existing direct, wake and relay transport roles.
public struct TransportPairingStartupConfiguration: Sendable, CustomStringConvertible {
    public let transport: ApprovalTransportConfiguration
    public let wake: TransportWakeStartupConfiguration?
    public let relayPort: UInt16?
    public let control: TransportPairingControlConfiguration
    public let canonicalBytes: Data
    public var description: String { "TransportPairingStartupConfiguration(redacted)" }
    public init(transport: ApprovalTransportConfiguration, control: TransportPairingControlConfiguration,
                wake: TransportWakeStartupConfiguration? = nil, relayPort: UInt16? = nil) throws {
        guard transport.macID == control.macID, transport.accountID == control.accountID,
              transport.ownerUID == control.ownerUID, transport.serviceUID == control.transportUID,
              control.serviceName != transport.authorityServiceName,
              wake == nil || wake?.transport.canonicalBytes == transport.canonicalBytes,
              wake == nil || wake?.wake.serviceName != control.serviceName,
              relayPort.map({ $0 > 0 }) ?? true else { throw TransportPairingControlError.invalidConfiguration }
        self.transport = transport; self.control = control; self.wake = wake; self.relayPort = relayPort
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(transport.canonicalBytes),
            2: wake.map { .bytes($0.canonicalBytes) } ?? .null, 3: relayPort.map { .unsigned(UInt64($0)) } ?? .null,
            4: .bytes(control.canonicalBytes)]), limits: Self.limits)
    }
    public static func load(path: String) throws -> Self {
        let value = try decode(ProtectedServiceConfiguration.readPublic(path: path))
        try value.transport.requireNativeProcess(); try value.wake?.wake.requireNativeProcess(); return value
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...4),
              f[0] == .unsigned(1), case .bytes(let transport) = f[1], case .bytes(let control) = f[4] else {
            throw TransportPairingControlError.invalidConfiguration
        }
        let wake: TransportWakeStartupConfiguration?
        switch f[2] { case .null?: wake = nil; case .bytes(let bytes)?: wake = try .decode(bytes); default: throw TransportPairingControlError.invalidConfiguration }
        let port: UInt16?
        switch f[3] {
        case .null?: port = nil
        case .unsigned(let value)?: guard let number = UInt16(exactly: value) else { throw TransportPairingControlError.invalidConfiguration }; port = number
        default: throw TransportPairingControlError.invalidConfiguration
        }
        let result = try Self(transport: .decode(transport), control: .decode(control), wake: wake, relayPort: port)
        guard result.canonicalBytes == bytes else { throw TransportPairingControlError.invalidConfiguration }; return result
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 1, maxItems: 11) } }
}
