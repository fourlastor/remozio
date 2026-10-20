import Darwin
import Foundation
import RemozioProtocol

/// Root-owned metadata for the direct transport and its optional wake companion. No private key is embedded here.
public struct TransportWakeStartupConfiguration: Sendable, CustomStringConvertible {
    public let transport: ApprovalTransportConfiguration
    public let wake: GatewayWakeSignerConfiguration
    public let pollMilliseconds: UInt64
    public let canonicalBytes: Data
    public var description: String { "TransportWakeStartupConfiguration(redacted)" }
    public init(transport: ApprovalTransportConfiguration, wake: GatewayWakeSignerConfiguration, pollMilliseconds: UInt64 = 1000) throws {
        guard transport.macID == wake.binding.macID, transport.accountID == wake.binding.accountID,
              transport.ownerUID == wake.ownerUID, transport.serviceUID == wake.transportUID,
              (100...60_000).contains(pollMilliseconds) else { throw ApprovalTransportStartupError.invalidConfiguration }
        self.transport = transport; self.wake = wake; self.pollMilliseconds = pollMilliseconds
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(transport.canonicalBytes),
            2: .bytes(wake.canonicalBytes), 3: .unsigned(pollMilliseconds)]), limits: Self.limits)
    }
    public static func load(path: String) throws -> Self {
        let value = try decode(ProtectedServiceConfiguration.readPublic(path: path))
        try value.transport.requireNativeProcess()
        try value.wake.requireNativeProcess()
        return value
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...3),
              fields[0] == .unsigned(1), case .bytes(let transport) = fields[1], case .bytes(let wake) = fields[2],
              case .unsigned(let poll) = fields[3] else { throw ApprovalTransportStartupError.invalidConfiguration }
        let result = try Self(transport: ApprovalTransportConfiguration.decode(transport),
            wake: GatewayWakeSignerConfiguration.decode(wake), pollMilliseconds: poll)
        guard result.canonicalBytes == bytes else { throw ApprovalTransportStartupError.invalidConfiguration }
        return result
    }
    /// Loads only the configured protected key. Failure never generates a replacement or changes custody.
    public func makeRuntime() throws -> TransportWakeRuntime {
        try makeRuntime(verifyCurrent: {})
    }
    /// The consumer keeps this guard through key restoration, channel operations and challenged signing.
    func makeRuntime(verifyCurrent: @escaping @Sendable () throws -> Void) throws -> TransportWakeRuntime {
        try transport.requireNativeProcess()
        try verifyCurrent()
        let signer = try GatewayWakeSigner.load(configuration: wake)
        try verifyCurrent()
        let hints = try AuthorityWakeHintChannel(serviceName: transport.authorityServiceName, transportUID: transport.serviceUID,
            authorityPolicy: transport.authorityPolicy, binding: wake.binding, timeoutMilliseconds: wake.timeoutMilliseconds,
            verifyCurrent: verifyCurrent)
        let gateway = try GatewayWakeChannel(serviceName: wake.serviceName, transportUID: wake.transportUID,
            gatewayPolicy: wake.gatewayPolicy, timeoutMilliseconds: wake.timeoutMilliseconds, verifyCurrent: verifyCurrent)
        try verifyCurrent()
        return try TransportWakeRuntime(hints: hints, gateway: gateway, signer: signer, verifyCurrent: verifyCurrent)
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 1, maxItems: 9) } }
}
