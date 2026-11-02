import Foundation
import RemozioProtocol

/// IPC shape checks do not authenticate audit evidence. The phone verifies the Root signature and freshness independently.
enum AuthorityPhoneAuditExchange {
    static func request(_ request: PhoneAuditFrame) throws {
        guard request.isQuery, try request.encode().count <= PhoneAuditFrame.maximumQueryBytes else {
            throw AuthorityXPCError.invalidMessage
        }
    }
    static func response(_ response: PhoneAuditFrame, to request: PhoneAuditFrame, binding: AuthorityPeerBinding) throws {
        try self.request(request)
        _ = try response.encode()
        guard response.queryNonce == request.queryNonce else { throw AuthorityXPCError.invalidMessage }
        if case .failure = response { return }
        let limits = try AuditReplyLimits.phoneFrame(maximumBytes: PhoneAuditFrame.maximumBytes)
        switch (request, response) {
        case let (.historyQuery(nonce, epoch, after), .historyResponse(_, bytes, _)):
            let value = try AuditHistoryStatus.decode(bytes, limits: limits.history, descriptorLimits: limits.descriptor)
            guard value.macID == binding.scope.macID, value.accountID == binding.scope.accountID,
                  value.queryNonce == nonce, value.requestedEpoch == epoch, value.requestedAfter == after else {
                throw AuthorityXPCError.invalidMessage
            }
        case let (.pageQuery(nonce, epoch, generation, after), .pageResponse(_, bytes, _)):
            let value = try AuditBatch.decode(bytes, batchLimits: limits.batch, recordLimits: limits.record, maximumRecords: limits.maximumRecords)
            guard value.macID == binding.scope.macID, value.accountID == binding.scope.accountID,
                  value.queryNonce == nonce, value.journalEpoch == epoch, value.epochCreationGeneration == generation,
                  value.requestedAfter == after else { throw AuthorityXPCError.invalidMessage }
        default: throw AuthorityXPCError.invalidMessage
        }
    }
}
