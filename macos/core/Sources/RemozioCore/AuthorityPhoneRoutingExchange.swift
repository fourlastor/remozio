import CryptoKit
import Foundation
import RemozioProtocol

/// IPC shape and correlation checks supplement Root signing. The phone must verify trust and freshness independently.
enum AuthorityPhoneRoutingExchange {
    static func request(_ request: PhoneRoutingFrame, binding: AuthorityPeerBinding) throws {
        _ = try request.encode()
        switch request {
        case .status, .challenge: break
        case .apply(_, let bytes, _):
            let control = try RoutingAwayControl.decode(bytes, limits: .init(maxBytes: 1024, maxDepth: 2, maxItems: 32))
            let scope = binding.scope
            guard control.macID == scope.macID, control.accountID == scope.accountID,
                  control.phoneID == scope.phoneID, control.enrollmentEpoch == scope.enrollmentEpoch else {
                throw AuthorityXPCError.invalidMessage
            }
        default: throw AuthorityXPCError.invalidMessage
        }
    }
    static func response(_ response: PhoneRoutingFrame, to request: PhoneRoutingFrame, binding: AuthorityPeerBinding) throws {
        try self.request(request, binding: binding)
        _ = try response.encode()
        guard response.queryNonce == request.queryNonce else { throw AuthorityXPCError.invalidMessage }
        if case .failure = response { return }
        guard case .response(_, let bytes, _) = response else { throw AuthorityXPCError.invalidMessage }
        let result = try RoutingStatusResponse.decode(bytes)
        guard result.scope == binding.scope else { throw AuthorityXPCError.invalidMessage }
        switch request {
        case .status:
            guard result.outcome == .status else { throw AuthorityXPCError.invalidMessage }
        case .challenge(_, let expected):
            guard (result.outcome == .challenge && result.state.revision == expected) || result.outcome == .conflict,
                  result.controlDigest == nil else { throw AuthorityXPCError.invalidMessage }
        case .apply(_, let control, _):
            guard result.outcome == .applied || result.outcome == .conflict,
                  result.controlDigest == Data(SHA256.hash(data: control)) else { throw AuthorityXPCError.invalidMessage }
            if result.outcome == .applied {
                let original = try RoutingAwayControl.decode(control, limits: .init(maxBytes: 1024, maxDepth: 2, maxItems: 32))
                let applied = original.expectedRevision.addingReportingOverflow(1)
                guard !applied.overflow, result.appliedRevision == applied.partialValue else { throw AuthorityXPCError.invalidMessage }
            }
        default: throw AuthorityXPCError.invalidMessage
        }
    }
}
