import CryptoKit
import Foundation
import RemozioHostCore

/// A local diagnostic for the last publication turn. It does not confirm a mapping or phone delivery.
public enum AuthorityPhonePushPublicationDiagnostic: Sendable, Equatable {
    case disabled, notStarted, turnCompleted, retryPending, closed
}

/// Protected runtime inputs. Callbacks are synchronous and must not reenter the journal or publisher.
public struct AuthorityPhonePushPublication: Sendable, CustomStringConvertible {
    let provider: AuthorityPhonePushRegistration
    let gatewayPublicKey: Data
    let maximumPhonesPerTurn: Int
    let wallTime: @Sendable () throws -> UInt64
    public var description: String { "AuthorityPhonePushPublication(redacted)" }
    public init(provider: AuthorityPhonePushRegistration, gatewayPublicKey: Data, maximumPhonesPerTurn: Int = 16,
                wallTime: @escaping @Sendable () throws -> UInt64 = {
                    let value = Date().timeIntervalSince1970 * 1000
                    guard value.isFinite, value >= 0, value < Double(UInt64.max) else { throw AuthorityClockError.overflow }
                    return UInt64(value)
                }) throws {
        guard gatewayPublicKey.count == 65, gatewayPublicKey != provider.policy.registration.rootPublicKey,
              (try? P256.Signing.PublicKey(x963Representation: gatewayPublicKey)) != nil,
              (1...64).contains(maximumPhonesPerTurn) else { throw AuthorityWakePublisherError.invalidConfiguration }
        self.provider = provider; self.gatewayPublicKey = gatewayPublicKey
        self.maximumPhonesPerTurn = maximumPhonesPerTurn; self.wallTime = wallTime
    }
}
