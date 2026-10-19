import Foundation
import RemozioProtocol

/// Immutable setup metadata. A decoded identity does not prove file ownership or grant an activity scope.
struct ServiceReleaseActivityReference: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.service-release-activity-reference"
    static let supportedVersions: Set<UInt64> = [1]
    let services: ServiceAccountPlan
    let transport: PreparationFileIdentity
    let gateway: PreparationFileIdentity
    var description: String { "ServiceReleaseActivityReference(redacted)" }
    var debugDescription: String { description }
    var identities: [ServiceAccountRole: PreparationFileIdentity] { [.transport: transport, .gateway: gateway] }

    init(services: ServiceAccountPlan, identities: [ServiceAccountRole: PreparationFileIdentity]) throws {
        guard Set(identities.keys) == Set(ServiceAccountPlan.roles),
              let transport = identities[.transport], let gateway = identities[.gateway],
              transport.inode > 0, gateway.inode > 0, transport != gateway else {
            throw RuntimePreparationError.invalidRecord
        }
        self.services = services; self.transport = transport; self.gateway = gateway
    }
    func identity(for role: ServiceAccountRole) -> PreparationFileIdentity { role == .transport ? transport : gateway }
    func validate(services current: ServiceAccountPlan) throws {
        guard services == current else { throw RuntimePreparationError.changedScope }
    }
    var encoded: Data { get throws {
        func value(_ identity: PreparationFileIdentity) -> CBORValue {
            .array([.unsigned(UInt64(identity.device)), .unsigned(identity.inode)])
        }
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-service-release-activity"),
            2: .bytes(services.encoded), 3: value(transport), 4: value(gateway)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .unsigned(1),
              fields[1] == .text("remozio-service-release-activity"), case .bytes(let services) = fields[2] else {
            throw RuntimePreparationError.invalidRecord
        }
        func identity(_ key: UInt64) throws -> PreparationFileIdentity {
            guard case .array(let values) = fields[key], values.count == 2,
                  case .unsigned(let device) = values[0], let number = UInt32(exactly: device),
                  case .unsigned(let inode) = values[1], inode > 0 else { throw RuntimePreparationError.invalidRecord }
            return .init(device: number, inode: inode)
        }
        let result = try Self(services: .decode(services), identities: [.transport: identity(3), .gateway: identity(4)])
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    static let limits = try! CBORLimits(maxBytes: 6144, maxDepth: 2, maxItems: 19)
}
