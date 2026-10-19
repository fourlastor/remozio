import Foundation
import RemozioProtocol

/// Explicit optional setup control alongside the existing direct, wake and relay transport roles.
public struct TransportPairingStartupConfiguration: Sendable, CustomStringConvertible {
    public static let formatName = "transport.pairing-config"
    public static let supportedVersions: Set<UInt64> = [1, 2]
    public let transport: ApprovalTransportConfiguration
    public let wake: TransportWakeStartupConfiguration?
    public let relayPort: UInt16?
    public let control: TransportPairingControlConfiguration
    public let canonicalBytes: Data
    let settingsHost: GatewaySettingsConsumerHostConfiguration?
    public var description: String { "TransportPairingStartupConfiguration(redacted)" }
    public init(transport: ApprovalTransportConfiguration, control: TransportPairingControlConfiguration,
                wake: TransportWakeStartupConfiguration? = nil, relayPort: UInt16? = nil) throws {
        try self.init(transport: transport, control: control, wake: wake, relayPort: relayPort, settingsHost: nil)
    }
    init(transport: ApprovalTransportConfiguration, control: TransportPairingControlConfiguration,
         wake: TransportWakeStartupConfiguration? = nil, relayPort: UInt16? = nil,
         settingsHost: GatewaySettingsConsumerHostConfiguration?) throws {
        try settingsHost?.validate(transport: transport, pairing: control)
        guard transport.macID == control.macID, transport.accountID == control.accountID,
              transport.ownerUID == control.ownerUID, transport.serviceUID == control.transportUID,
              control.serviceName != transport.authorityServiceName,
              wake == nil || wake?.transport.canonicalBytes == transport.canonicalBytes,
              wake == nil || wake?.wake.serviceName != control.serviceName,
              relayPort.map({ $0 > 0 }) ?? true else { throw TransportPairingControlError.invalidConfiguration }
        self.transport = transport; self.control = control; self.wake = wake; self.relayPort = relayPort; self.settingsHost = settingsHost
        var fields: [UInt64: CBORValue] = [0: .unsigned(settingsHost == nil ? 1 : 2), 1: .bytes(transport.canonicalBytes),
            2: wake.map { .bytes($0.canonicalBytes) } ?? .null, 3: relayPort.map { .unsigned(UInt64($0)) } ?? .null,
            4: .bytes(control.canonicalBytes)]
        if let settingsHost { fields[5] = .bytes(try settingsHost.encoded) }
        canonicalBytes = try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    }
    public static func load(path: String) throws -> Self {
        let value = try decode(ProtectedServiceConfiguration.readPublic(path: path))
        try value.requireLegacyStartup()
        try value.transport.requireNativeProcess(); try value.wake?.wake.requireNativeProcess(); return value
    }
    func replacingWake(_ wake: TransportWakeStartupConfiguration) throws -> Self {
        try .init(transport: transport, control: control, wake: wake, relayPort: relayPort, settingsHost: settingsHost)
    }
    // The legacy entry point cannot discard a settings host and start without its control and lifetime owner.
    func requireLegacyStartup() throws {
        guard settingsHost == nil else { throw TransportPairingControlError.unsupportedVersion }
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), case .unsigned(let version) = f[0],
              supportedVersions.contains(version), Set(f.keys) == Set(UInt64(0)...(version == 1 ? 4 : 5)),
              case .bytes(let transport) = f[1], case .bytes(let control) = f[4] else {
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
        let settingsHost: GatewaySettingsConsumerHostConfiguration?
        if version == 1 { settingsHost = nil }
        else {
            guard case .bytes(let bytes) = f[5] else { throw TransportPairingControlError.invalidConfiguration }
            settingsHost = try .decode(bytes)
        }
        let result = try Self(transport: .decode(transport), control: .decode(control), wake: wake, relayPort: port, settingsHost: settingsHost)
        guard result.canonicalBytes == bytes else { throw TransportPairingControlError.invalidConfiguration }; return result
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 1, maxItems: 13) } }
}
