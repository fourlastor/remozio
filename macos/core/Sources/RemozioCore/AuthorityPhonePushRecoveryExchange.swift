import CryptoKit
import Foundation
import RemozioProtocol

public typealias AuthorityPhonePushRecoveryProvider = @Sendable (
    ApprovalRequestCoordinator, AuthorityPeerBinding, PhonePushRecoveryFrame,
    @Sendable (JournalTransaction) throws -> Void
) throws -> PhonePushRecoveryFrame

extension AuthorityPhonePushRegistration {
    public func recoveryProvider(clock: @escaping @Sendable () throws -> AuthorityMoment,
                                 wall: @escaping @Sendable () throws -> UInt64) -> AuthorityPhonePushRecoveryProvider {
        { owner, binding, frame, validate in
            try owner.phonePushRecovery(frame, binding: binding, provider: self,
                now: clock(), wall: wall(), validateTransport: validate)
        }
    }
}

/// Shape checks supplement the authenticated transport admission. They grant no provider or approval authority.
enum AuthorityPhonePushRecoveryExchange {
    static func request(_ request: PhonePushRecoveryFrame, binding: AuthorityPeerBinding) throws {
        guard case .resume = request else { throw AuthorityXPCError.invalidMessage }
        _ = try request.encode()
    }
    static func response(_ response: PhonePushRecoveryFrame, to request: PhonePushRecoveryFrame,
                         binding: AuthorityPeerBinding) throws {
        guard response.correlationID == request.correlationID else { throw AuthorityXPCError.invalidMessage }
        switch (request, response) {
        case (.resume(_, let offer), .state(_, let state)):
            let m = state.metadata, s = binding.scope
            guard m.macID == s.macID, m.accountID == s.accountID, m.phoneID == s.phoneID, m.enrollmentEpoch == s.enrollmentEpoch,
                  m.tokenDigest == Data(SHA256.hash(data: Data(offer.token.utf8))) else { throw AuthorityXPCError.invalidMessage }
        case (.resume, .outcome): break
        default: throw AuthorityXPCError.invalidMessage
        }
        _ = try response.encode()
    }
}
