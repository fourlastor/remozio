import Foundation
import RemozioProtocol

extension DirectApprovalTransportService {
    /// Probe precedes private Resume fields. No failed application exchange is replayed.
    public func runPhonePushRecovery(for session: DirectApprovalSession, over channel: NegotiatedNetworkChannel,
                                     timeoutMilliseconds: UInt64 = 30_000) async throws {
        try await withTaskCancellationHandler {
            do {
                guard (1...60_000).contains(timeoutMilliseconds), channel.purpose == .pushRecovery else {
                    throw ApprovalChannelError.invalidInput
                }
                try await validate(session)
                let metadata = try await channel.negotiated()
                guard metadata.peer.role == .phone, metadata.peer.scope == session.peer.scope, metadata.envelopeVersion == 1,
                      metadata.peer.requests.isEmpty, metadata.peer.auditVersions.isEmpty else { throw ApprovalChannelError.invalidInput }
                let deadline = ContinuousClock.now.advanced(by: .milliseconds(Int64(timeoutMilliseconds)))
                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask {
                        guard let probeBytes = try await channel.receive(maximumBytes: PhonePushRecoveryFrame.maximumBytes),
                              case .probe(let probeID) = try PhonePushRecoveryFrame.decode(probeBytes) else {
                            throw ApprovalChannelError.invalidInput
                        }
                        if let failure = try await self.phonePushRecoveryReadiness(for: session) {
                            try await self.validate(session)
                            try await Self.send(PhonePushRecoveryFrame.outcome(correlationID: probeID, failure: failure).encode(),
                                over: channel, deadline: deadline)
                            return
                        }
                        try await self.validate(session)
                        try await Self.send(PhonePushRecoveryFrame.ready(correlationID: probeID).encode(), over: channel, deadline: deadline)
                        guard let resumeBytes = try await channel.receive(maximumBytes: PhonePushRecoveryFrame.maximumBytes) else {
                            throw ApprovalChannelError.invalidInput
                        }
                        let request = try PhonePushRecoveryFrame.decode(resumeBytes)
                        guard case .resume(let resumeID, _) = request, resumeID != probeID else { throw ApprovalChannelError.invalidInput }
                        let binding = AuthorityPeerBinding(peer: session.peer, revision: session.revision)
                        try AuthorityPhonePushRecoveryExchange.request(request, binding: binding)
                        let response = try await self.phonePushRecovery(for: session, frame: request)
                        try AuthorityPhonePushRecoveryExchange.response(response, to: request, binding: binding)
                        try await self.validate(session)
                        try await Self.send(response.encode(), over: channel, deadline: deadline)
                    }
                    group.addTask {
                        try await ContinuousClock().sleep(until: deadline)
                        channel.close()
                        throw ApprovalChannelError.timedOut
                    }
                    defer { group.cancelAll() }
                    _ = try await group.next()
                }
                await channel.closeAndWait()
            } catch { await channel.closeAndWait(); throw error }
        } onCancel: { channel.close() }
    }
}
