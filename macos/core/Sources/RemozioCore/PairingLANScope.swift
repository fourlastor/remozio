import Foundation
import RemozioProtocol

/// LAN scope from the protected Authority pairing configuration.
public struct PairingLANScope: Equatable, Sendable {
    public enum AddressFamily: UInt64, Sendable { case ipv4 = 4, ipv6 = 6 }

    public let interfaceName: String
    public let family: AddressFamily

    public init(interfaceName: String, family: AddressFamily) throws {
        let bytes = interfaceName.utf8
        guard (1...15).contains(bytes.count), let first = bytes.first, (97...122).contains(first),
              bytes.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) }) else {
            throw AuthorityPairingSetupError.invalidConfiguration
        }
        self.interfaceName = interfaceName
        self.family = family
    }

    var cborValue: CBORValue { .array([.text(interfaceName), .unsigned(family.rawValue)]) }

    static func decode(_ value: CBORValue) throws -> Self {
        guard case .array(let fields) = value, fields.count == 2, case .text(let name) = fields[0],
              case .unsigned(let wireFamily) = fields[1], let family = AddressFamily(rawValue: wireFamily) else {
            throw AuthorityPairingSetupError.invalidConfiguration
        }
        return try .init(interfaceName: name, family: family)
    }
}

/// Public scope grant for the exact window on its authenticated proof link.
struct PairingLANBinding: Equatable, Sendable {
    let windowID: Data
    let revision: AuthorityPairingSetupAccess.V2ActivationRevision
    let scope: PairingLANScope
    let expiresAtMilliseconds: UInt64

    func remainingMilliseconds(at now: UInt64, windowLifetime: UInt64) -> UInt64? {
        guard now < expiresAtMilliseconds, expiresAtMilliseconds - now <= windowLifetime else { return nil }
        return expiresAtMilliseconds - now
    }

    func encode() throws -> Data {
        guard windowID.count == 16, revision.configurationDigest.count == 32, expiresAtMilliseconds > 0 else { throw AuthorityXPCError.invalidMessage }
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(windowID),
            2: .bytes(AuthorityPairingProofWire.bytes(revision.authorityEpoch)), 3: .bytes(revision.configurationDigest),
            4: scope.cborValue, 5: .unsigned(expiresAtMilliseconds)]), limits: Self.limits)
    }

    static func decode(_ bytes: Data, windowID: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...5), fields[0] == .unsigned(1), fields[1] == .bytes(windowID),
              case .bytes(let epoch) = fields[2], case .bytes(let digest) = fields[3], let scope = fields[4],
              case .unsigned(let expires) = fields[5] else {
            throw AuthorityXPCError.invalidMessage
        }
        let binding = try Self(windowID: windowID,
            revision: .init(authorityEpoch: AuthorityPairingProofWire.identifier(epoch), configurationDigest: digest),
            scope: .decode(scope), expiresAtMilliseconds: expires)
        guard try binding.encode() == bytes else { throw AuthorityXPCError.invalidMessage }
        return binding
    }

    private static var limits: CBORLimits { get throws { try .init(maxBytes: 128, maxDepth: 2, maxItems: 15) } }
}
