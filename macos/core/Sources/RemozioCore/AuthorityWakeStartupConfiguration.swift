import Darwin
import Foundation
import RemozioProtocol

/// Protected Root startup inputs. Gateway identity and code pins come from installation, never incoming hints.
public struct AuthorityWakeStartupConfiguration: Sendable, CustomStringConvertible {
    public let request: AuthorityRequestStartupConfiguration
    public let registration: GatewayRegistrationIdentity
    public let gatewayServiceName: String
    public let gatewayPolicy: XPCPeerPolicy
    public let leaseMilliseconds: UInt64
    public let pollMilliseconds: UInt64
    public let timeoutMilliseconds: UInt64
    public let phonePush: AuthorityPhonePushStartupConfiguration?
    public let canonicalBytes: Data
    public var description: String { "AuthorityWakeStartupConfiguration(redacted)" }
    public init(request: AuthorityRequestStartupConfiguration, registration: GatewayRegistrationIdentity,
                gatewayServiceName: String, gatewayUID: UInt32, teamID: String, gatewayIdentifier: String,
                gatewayHashes: Set<Data>, leaseMilliseconds: UInt64 = 10_000, pollMilliseconds: UInt64 = 1000,
                timeoutMilliseconds: UInt64 = 5000, phonePush: AuthorityPhonePushStartupConfiguration? = nil) throws {
        guard request.service.macID == registration.macID, request.service.accountID == registration.accountID,
              request.authorityPublicKey == registration.rootPublicKey, gatewayUID > 0, gatewayUID < UInt32.max,
              gatewayUID != request.service.transportPolicy.expectedUserID,
              GatewayWakeEndpointConfiguration.validServiceName(gatewayServiceName),
              (200...60_000).contains(leaseMilliseconds), (100...leaseMilliseconds / 2).contains(pollMilliseconds),
              (1...leaseMilliseconds / 2).contains(timeoutMilliseconds) else { throw AuthorityServiceConfigurationError.invalidConfiguration }
        gatewayPolicy = try XPCPeerPolicy(teamID: teamID, componentIdentifier: gatewayIdentifier,
            approvedCodeDirectoryHashes: gatewayHashes, expectedUserID: gatewayUID)
        _ = try phonePush?.registrationPolicy(registration)
        self.phonePush = phonePush
        self.request = request; self.registration = registration; self.gatewayServiceName = gatewayServiceName
        self.leaseMilliseconds = leaseMilliseconds; self.pollMilliseconds = pollMilliseconds; self.timeoutMilliseconds = timeoutMilliseconds
        var fields: [UInt64: CBORValue] = [0: .unsigned(phonePush == nil ? 1 : 2), 1: .bytes(request.canonicalBytes),
            2: .bytes(try registration.encode()), 3: .text(gatewayServiceName), 4: .unsigned(UInt64(gatewayUID)),
            5: .text(teamID), 6: .text(gatewayIdentifier),
            7: .array(gatewayHashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)),
            8: .unsigned(leaseMilliseconds), 9: .unsigned(pollMilliseconds), 10: .unsigned(timeoutMilliseconds)]
        if let phonePush { fields[11] = .bytes(phonePush.canonicalBytes) }
        canonicalBytes = try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    }
    public static func load(path: String) throws -> Self { try decode(ProtectedServiceConfiguration.read(path: path)) }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), ((fields[0] == .unsigned(1) && Set(fields.keys) == Set(UInt64(0)...10)) ||
               (fields[0] == .unsigned(2) && Set(fields.keys) == Set(UInt64(0)...11))), case .bytes(let request) = fields[1], case .bytes(let registration) = fields[2],
              case .text(let name) = fields[3], case .unsigned(let uid) = fields[4], let gatewayUID = UInt32(exactly: uid),
              case .text(let team) = fields[5], case .text(let component) = fields[6], case .array(let hashes) = fields[7],
              case .unsigned(let lease) = fields[8], case .unsigned(let poll) = fields[9], case .unsigned(let timeout) = fields[10] else {
            throw AuthorityServiceConfigurationError.invalidConfiguration
        }
        let values = try hashes.map { value -> Data in
            guard case .bytes(let hash) = value else { throw AuthorityServiceConfigurationError.invalidConfiguration }; return hash
        }
        let phonePush: AuthorityPhonePushStartupConfiguration?
        if fields[0] == .unsigned(2) {
            guard case .bytes(let config) = fields[11] else { throw AuthorityServiceConfigurationError.invalidConfiguration }
            phonePush = try .decode(config)
        } else { phonePush = nil }
        let result = try Self(request: AuthorityRequestStartupConfiguration.decode(request), registration: GatewayRegistrationIdentity.decode(registration),
            gatewayServiceName: name, gatewayUID: gatewayUID, teamID: team, gatewayIdentifier: component, gatewayHashes: Set(values),
            leaseMilliseconds: lease, pollMilliseconds: poll, timeoutMilliseconds: timeout, phonePush: phonePush)
        guard result.canonicalBytes == bytes else { throw AuthorityServiceConfigurationError.invalidConfiguration }
        return result
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 2, maxItems: 48) } }
}
