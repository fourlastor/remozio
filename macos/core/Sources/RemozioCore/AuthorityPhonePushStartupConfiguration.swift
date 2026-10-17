import CryptoKit
import Foundation
import RemozioProtocol

/// Protected administrator inputs. Decoding does not authenticate their source or enable provider delivery.
public struct AuthorityPhonePushStartupConfiguration: Sendable, CustomStringConvertible {
    public let projectID: String
    public let senderID: String
    public let packageName: String
    public let gatewayReceiptPublicKey: Data
    public let maximumControls: Int
    public let candidateLifetimeMilliseconds: UInt64
    public let canonicalBytes: Data
    public var description: String { "AuthorityPhonePushStartupConfiguration(redacted)" }

    public init(projectID: String, senderID: String, packageName: String, gatewayReceiptPublicKey: Data,
                maximumControls: Int = 4096, candidateLifetimeMilliseconds: UInt64 = 300_000) throws {
        _ = try PhonePushTokenOffer(token: "validation", projectID: projectID, senderID: senderID, packageName: packageName)
        guard gatewayReceiptPublicKey.count == 65,
              (try? P256.Signing.PublicKey(x963Representation: gatewayReceiptPublicKey)) != nil,
              (2...100_000).contains(maximumControls), (1...86_400_000).contains(candidateLifetimeMilliseconds) else {
            throw AuthorityServiceConfigurationError.invalidConfiguration
        }
        self.projectID = projectID; self.senderID = senderID; self.packageName = packageName
        self.gatewayReceiptPublicKey = gatewayReceiptPublicKey; self.maximumControls = maximumControls
        self.candidateLifetimeMilliseconds = candidateLifetimeMilliseconds
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(projectID),
            2: .text(senderID), 3: .text(packageName), 4: .bytes(gatewayReceiptPublicKey),
            5: .unsigned(UInt64(maximumControls)), 6: .unsigned(candidateLifetimeMilliseconds)]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...6),
              f[0] == .unsigned(1), case .text(let project) = f[1], case .text(let sender) = f[2], case .text(let package) = f[3],
              case .bytes(let key) = f[4], case .unsigned(let count) = f[5], let maximum = Int(exactly: count),
              case .unsigned(let lifetime) = f[6] else { throw AuthorityServiceConfigurationError.invalidConfiguration }
        let value = try Self(projectID: project, senderID: sender, packageName: package, gatewayReceiptPublicKey: key,
            maximumControls: maximum, candidateLifetimeMilliseconds: lifetime)
        guard value.canonicalBytes == bytes else { throw AuthorityServiceConfigurationError.invalidConfiguration }; return value
    }
    func journalPolicy(clockEpoch: UUID) throws -> GatewayAuthorityPolicy {
        try .init(payloadLimits: CBORLimits(maxBytes: 4096, maxDepth: 8, maxItems: 128),
            signingLimits: CBORLimits(maxBytes: 8192, maxDepth: 8, maxItems: 128), maximumControls: maximumControls,
            candidateLifetimeMillis: candidateLifetimeMilliseconds, clockEpoch: clockEpoch)
    }
    func registrationPolicy(_ registration: GatewayRegistrationIdentity) throws -> AuthorityPhonePushPolicy {
        guard gatewayReceiptPublicKey != registration.rootPublicKey else { throw AuthorityServiceConfigurationError.invalidConfiguration }
        return try .init(registration: registration, projectID: projectID, senderID: senderID, packageName: packageName)
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 2048, maxDepth: 1, maxItems: 16) } }
}
