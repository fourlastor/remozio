import CryptoKit
import Foundation
import RemozioProtocol

/// Acquire the machine lease before the account operation. Check the supplied validator inside each account transaction.
public typealias AuthorityPhoneUpdateSchedulingProvider = @Sendable (
    AuthorityJournal, AuthorityPeerBinding, PhoneUpdateSchedulingFrame, @Sendable (JournalTransaction) throws -> Void
) throws -> PhoneUpdateSchedulingFrame

/// IPC correlation supplements Root signatures. The enrolled phone must verify its signature and original query lifetime.
enum AuthorityPhoneUpdateSchedulingExchange {
    static let limits = try! CBORLimits(maxBytes: 2048, maxDepth: 3, maxItems: 32)

    static func request(_ request: PhoneUpdateSchedulingFrame, binding: AuthorityPeerBinding) throws {
        _ = try request.encode()
        switch request {
        case .status, .challenge: break
        case .apply(_, let bytes, _):
            try requireScope(UpdateSchedulingControl.decode(bytes, limits: limits), binding: binding)
        default: throw AuthorityXPCError.invalidMessage
        }
    }

    static func response(_ response: PhoneUpdateSchedulingFrame, to request: PhoneUpdateSchedulingFrame,
                         binding: AuthorityPeerBinding) throws {
        try self.request(request, binding: binding)
        _ = try response.encode()
        guard response.queryNonce == request.queryNonce else { throw AuthorityXPCError.invalidMessage }
        if case .failure = response { return }
        switch (request, response) {
        case let (.challenge(nonce, update, generation, revision, action), .challengeResponse(_, bytes, _)):
            let challenge = try RootUpdateSchedulingChallenge.decode(bytes, limits: limits)
            let control = try UpdateSchedulingControl.decode(challenge.canonicalControl, limits: limits)
            try requireScope(control, binding: binding)
            guard challenge.queryNonce == nonce, control.updateID == update,
                  control.expectedGeneration == generation, control.expectedRevision == revision, control.action == action else {
                throw AuthorityXPCError.invalidMessage
            }
        case let (.status, .stateResponse(_, bytes, _)):
            let status = try UpdateSchedulingStatusResponse.decode(bytes)
            guard status.scope == binding.scope, status.controlDigest == nil else { throw AuthorityXPCError.invalidMessage }
        case let (.apply(_, bytes, _), .stateResponse(_, payload, _)):
            let control = try UpdateSchedulingControl.decode(bytes, limits: limits)
            let status = try UpdateSchedulingStatusResponse.decode(payload)
            let next = control.expectedRevision.addingReportingOverflow(1)
            guard !next.overflow, status.scope == binding.scope, status.controlDigest == Data(SHA256.hash(data: bytes)),
                  status.updateID == control.updateID, status.generation == control.expectedGeneration,
                  status.revision == next.partialValue, status.requestedAction == control.action else {
                throw AuthorityXPCError.invalidMessage
            }
        default: throw AuthorityXPCError.invalidMessage
        }
    }

    private static func requireScope(_ control: UpdateSchedulingControl, binding: AuthorityPeerBinding) throws {
        let scope = binding.scope
        guard control.macID == scope.macID, control.accountID == scope.accountID,
              control.phoneID == scope.phoneID, control.enrollmentEpoch == scope.enrollmentEpoch else {
            throw AuthorityXPCError.invalidMessage
        }
    }
}
