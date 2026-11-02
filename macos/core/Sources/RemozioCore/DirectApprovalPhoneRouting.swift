import Foundation
import RemozioProtocol

extension DirectApprovalTransportService {
    /// One exchange on a distinct enrolled channel. Routing does not require a command capability.
    public func runPhoneRouting(for session: DirectApprovalSession, over channel: NegotiatedNetworkChannel,
                                timeoutMilliseconds: UInt64 = 30_000) async throws {
        try await withTaskCancellationHandler {
            do {
                guard (1...60_000).contains(timeoutMilliseconds), channel.purpose == .routing else { throw ApprovalChannelError.invalidInput }
                try await validate(session)
                let metadata = try await channel.negotiated()
                guard metadata.peer.role == .phone, metadata.peer.scope == session.peer.scope, metadata.envelopeVersion == 1,
                      metadata.peer.requests.isEmpty, metadata.peer.auditVersions.isEmpty else { throw ApprovalChannelError.invalidInput }
                let deadline = ContinuousClock.now.advanced(by: .milliseconds(Int64(timeoutMilliseconds)))
                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask {
                        guard let bytes = try await channel.receive(maximumBytes: PhoneRoutingFrame.maximumBytes) else {
                            throw ApprovalChannelError.invalidInput
                        }
                        let request = try PhoneRoutingFrame.decode(bytes)
                        let binding = AuthorityPeerBinding(peer: session.peer, revision: session.revision)
                        try AuthorityPhoneRoutingExchange.request(request, binding: binding)
                        let response = try await self.phoneRouting(for: session, frame: request)
                        try AuthorityPhoneRoutingExchange.response(response, to: request, binding: binding)
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
