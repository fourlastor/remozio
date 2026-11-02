import Foundation
import RemozioProtocol

extension DirectApprovalTransportService {
    /// Serve one query on a dedicated enrolled audit channel. A new query needs a fresh connection and nonce.
    public func runPhoneAudit(for session: DirectApprovalSession, over channel: NegotiatedNetworkChannel,
                              timeoutMilliseconds: UInt64 = 30_000) async throws {
        try await withTaskCancellationHandler {
            do {
                guard (1...60_000).contains(timeoutMilliseconds), channel.purpose == .audit else { throw ApprovalChannelError.invalidInput }
                try await validate(session)
                let metadata = try await channel.negotiated()
                guard metadata.peer.role == .phone, metadata.peer.scope == session.peer.scope, metadata.envelopeVersion == 1,
                      metadata.peer.requests.isEmpty, metadata.peer.auditVersions.contains(1),
                      session.peer.auditVersions.contains(1) else { throw ApprovalChannelError.invalidInput }
                let deadline = ContinuousClock.now.advanced(by: .milliseconds(Int64(timeoutMilliseconds)))
                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask {
                        guard let bytes = try await channel.receive(maximumBytes: PhoneAuditFrame.maximumQueryBytes) else {
                            throw ApprovalChannelError.invalidInput
                        }
                        let request = try PhoneAuditFrame.decode(bytes)
                        try AuthorityPhoneAuditExchange.request(request)
                        let response = try await self.phoneAudit(for: session, frame: request)
                        let binding = AuthorityPeerBinding(peer: session.peer, revision: session.revision)
                        try AuthorityPhoneAuditExchange.response(response, to: request, binding: binding)
                        try await self.validate(session)
                        try await Self.send(response.encode(), over: channel, deadline: deadline)
                    }
                    group.addTask {
                        try await ContinuousClock().sleep(until: deadline)
                        channel.close(); throw ApprovalChannelError.timedOut
                    }
                    defer { group.cancelAll() }
                    _ = try await group.next()
                }
                await channel.closeAndWait()
            } catch { await channel.closeAndWait(); throw error }
        } onCancel: { channel.close() }
    }
}
