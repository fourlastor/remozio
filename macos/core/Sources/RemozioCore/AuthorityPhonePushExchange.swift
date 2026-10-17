import CryptoKit
import Foundation
import RemozioProtocol

/// The owner supplies the checkpoint and validates current transport policy in the mutation transaction.
public typealias AuthorityPhonePushRegistrationProvider = @Sendable (
    ApprovalRequestCoordinator, AuthorityPeerBinding, PhonePushRegistrationFrame,
    @Sendable (JournalTransaction) throws -> Void
) throws -> PhonePushRegistrationFrame

extension AuthorityPhonePushRegistration {
    public func provider(clock: @escaping @Sendable () throws -> AuthorityMoment,
                         wall: @escaping @Sendable () throws -> UInt64) -> AuthorityPhonePushRegistrationProvider {
        { owner, binding, frame, validate in
            try owner.phonePushRegistration(frame, binding: binding, provider: self,
                now: clock(), wall: wall(), validateTransport: validate)
        }
    }
}

/// Shape and scope checks supplement authenticated IPC. They do not establish provider possession or current trust.
enum AuthorityPhonePushExchange {
    static func request(_ request: PhonePushRegistrationFrame, binding: AuthorityPeerBinding) throws {
        _ = try request.encode()
        switch request {
        case .offer: break
        case .proof(_, let proof):
            let b = proof.binding, s = binding.scope
            guard b.macID == s.macID, b.accountID == s.accountID, b.phoneID == s.phoneID,
                  b.enrollmentEpoch == s.enrollmentEpoch else { throw AuthorityXPCError.invalidMessage }
        default: throw AuthorityXPCError.invalidMessage
        }
    }
    static func response(_ response: PhonePushRegistrationFrame, to request: PhonePushRegistrationFrame,
                         binding: AuthorityPeerBinding) throws {
        guard response.correlationID == request.correlationID else { throw AuthorityXPCError.invalidMessage }
        switch (request, response) {
        case (.offer(_, let offer), .prepared(_, let m)):
            let s = binding.scope
            guard m.macID == s.macID, m.accountID == s.accountID, m.phoneID == s.phoneID, m.enrollmentEpoch == s.enrollmentEpoch,
                  m.tokenDigest == Data(SHA256.hash(data: Data(offer.token.utf8))) else { throw AuthorityXPCError.invalidMessage }
        case (.offer, .outcome), (.proof, .outcome): break
        default: throw AuthorityXPCError.invalidMessage
        }
        _ = try response.encode()
    }
}
