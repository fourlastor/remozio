import Foundation
import RemozioProtocol

/// Protected setup selects a dedicated transport account and a distinct Mach service.
public struct GatewayWakeEndpointConfiguration: Sendable {
    public let serviceName: String
    public let transportUID: uid_t
    public let policy: XPCPeerPolicy
    public let maximumConnections: Int
    public let maximumOperations: Int
    public let challengeLifetimeMillis: UInt64
    let teamID: String
    let componentIdentifier: String
    private let hashes: Set<Data>

    public init(serviceName: String, transportUID: uid_t, teamID: String, componentIdentifier: String,
                approvedCodeDirectoryHashes: Set<Data>, maximumConnections: Int = 4, maximumOperations: Int = 8,
                challengeLifetimeMillis: UInt64 = 5000) throws {
        guard Self.validServiceName(serviceName), transportUID > 0, transportUID < UInt32.max,
              (1...64).contains(maximumConnections), (1...64).contains(maximumOperations),
              (1...60_000).contains(challengeLifetimeMillis) else { throw GatewayServiceError.invalidConfiguration }
        policy = try XPCPeerPolicy(teamID: teamID, componentIdentifier: componentIdentifier,
            approvedCodeDirectoryHashes: approvedCodeDirectoryHashes, expectedUserID: transportUID)
        self.serviceName = serviceName; self.transportUID = transportUID; self.teamID = teamID
        self.componentIdentifier = componentIdentifier; hashes = approvedCodeDirectoryHashes
        self.maximumConnections = maximumConnections; self.maximumOperations = maximumOperations
        self.challengeLifetimeMillis = challengeLifetimeMillis
    }
    var value: CBORValue {
        .array([.text(serviceName), .unsigned(UInt64(transportUID)), .text(teamID), .text(componentIdentifier),
            .array(hashes.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)),
            .unsigned(UInt64(maximumConnections)), .unsigned(UInt64(maximumOperations)), .unsigned(challengeLifetimeMillis)])
    }
    static func decode(_ value: CBORValue) throws -> Self {
        guard case .array(let fields) = value, fields.count == 8, case .text(let name) = fields[0],
              case .unsigned(let uid) = fields[1], let uid = uid_t(exactly: uid), case .text(let team) = fields[2],
              case .text(let component) = fields[3], case .array(let hashes) = fields[4],
              case .unsigned(let connections) = fields[5], let connections = Int(exactly: connections),
              case .unsigned(let operations) = fields[6], let operations = Int(exactly: operations),
              case .unsigned(let lifetime) = fields[7] else { throw GatewayServiceError.invalidConfiguration }
        let values = try hashes.map { value -> Data in
            guard case .bytes(let hash) = value else { throw GatewayServiceError.invalidConfiguration }; return hash
        }
        return try Self(serviceName: name, transportUID: uid, teamID: team, componentIdentifier: component,
            approvedCodeDirectoryHashes: Set(values), maximumConnections: connections, maximumOperations: operations,
            challengeLifetimeMillis: lifetime)
    }
    static func validServiceName(_ name: String) -> Bool {
        MacServiceNamespace.accepts(name) && (1...255).contains(name.utf8.count) &&
            name.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }
    }
}
