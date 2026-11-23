import CryptoKit
import Foundation
import RemozioProtocol

extension GatewayRootChannel {
    /// Older gateways reject the optional inner query without closing this authenticated connection.
    /// The protected query owner must verify its independent signature, nonce and current scope.
    func mappingState(query: Data) async throws -> GatewayMappingStateReply {
        let reply = try await head(query: query)
        return GatewayMappingStateReply(canonicalPayload: reply.canonicalPayload, signature: reply.signature)
    }

    /// A receipt records historical admission. It cannot authorize a probe or confirm a current mapping.
    public func applyTokenCandidate(_ envelope: GatewayAuthorityEnvelope,
                                   registration: GatewayRegistrationIdentity) async throws -> GatewayCandidateAdmission {
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 8, maxItems: 128)
        let signing = try CBORLimits(maxBytes: 131_072, maxDepth: 8, maxItems: 128)
        let candidate = try GatewayTokenCandidate.decode(envelope.canonicalPayload, limits: limits)
        guard envelope.kind == 1, let token = envelope.registrationToken, !token.isEmpty, token.utf8.count <= 4096,
              token.utf8.allSatisfy({ (33...126).contains($0) }), registration.matches(candidate.binding),
              candidate.operationID == envelope.operationID, candidate.revision == envelope.revision,
              Data(SHA256.hash(data: Data(token.utf8))) == candidate.binding.tokenDigest,
              try GatewayTokenCandidateSignature.verify(signature: envelope.signature, publicKey: registration.rootPublicKey,
                wireVersion: 1, canonicalPayload: envelope.canonicalPayload, payloadLimits: limits, inputLimits: signing) else {
            throw GatewayRootChannelError.invalidMessage
        }
        let fields = try await command(.candidate(payload: envelope.canonicalPayload, signature: envelope.signature,
            wireVersion: 1, phoneID: candidate.binding.phoneID, token: token))
        do {
            guard fields.count == 4, case .bytes(let payload) = fields[1], case .bytes(let signature) = fields[2],
                  case .boolean(let inserted) = fields[3], payload == envelope.canonicalPayload,
                  try GatewayTokenCandidateSignature.verify(signature: signature, publicKey: registration.rootPublicKey,
                    wireVersion: 1, canonicalPayload: payload, payloadLimits: limits, inputLimits: signing) else {
                throw GatewayRootChannelError.invalidMessage
            }
            return GatewayCandidateAdmission(receipt: GatewayCandidateReceipt(candidate: candidate,
                canonicalPayload: payload, signature: signature), inserted: inserted)
        } catch { close(); throw error }
    }

    /// Echoed Root signatures establish the acknowledged operation, not freshness or current delivery authority.
    public func applyTokenActivation(_ envelope: GatewayAuthorityEnvelope,
                                    registration: GatewayRegistrationIdentity) async throws -> GatewayRecipientApplication {
        try await applyRecipient(envelope, kind: .activation, registration: registration, recoveryHead: nil)
    }

    func recoverPhoneRevocation(_ envelope: GatewayAuthorityEnvelope, registration: GatewayRegistrationIdentity,
                                expectedHead: UInt64) async throws -> GatewayRecipientApplication {
        try requirePhoneRevocationRecovery(registration: registration)
        return try await applyRecipient(envelope, kind: .phoneRevocation, registration: registration, recoveryHead: expectedHead)
    }

    private func applyRecipient(_ envelope: GatewayAuthorityEnvelope, kind: GatewayRecipientKind,
                                registration: GatewayRegistrationIdentity, recoveryHead: UInt64?) async throws -> GatewayRecipientApplication {
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 8, maxItems: 128)
        let signing = try CBORLimits(maxBytes: 131_072, maxDepth: 8, maxItems: 128)
        let control = try GatewayStoredRecipient.decode(envelope.canonicalPayload, kind: kind, limits: limits)
        guard envelope.kind == kind.rawValue, envelope.registrationToken == nil, control.matches(registration),
              control.operationID == envelope.operationID, control.revision == envelope.revision,
              try GatewayRecipientSignature.verify(signature: envelope.signature, publicKey: registration.rootPublicKey,
                wireVersion: 1, kind: kind, canonicalPayload: envelope.canonicalPayload,
                payloadLimits: limits, inputLimits: signing) else { throw GatewayRootChannelError.invalidMessage }
        let recipient: GatewayRootCommand
        if let recoveryHead {
            recipient = .recoverPhoneRevocation(payload: envelope.canonicalPayload, signature: envelope.signature,
                phoneID: control.phoneID, expectedHead: recoveryHead)
        } else {
            recipient = .recipient(payload: envelope.canonicalPayload, signature: envelope.signature,
                wireVersion: 1, phoneID: control.phoneID, kind: kind)
        }
        let fields = try await command(recipient)
        do {
            guard fields.count == 4, case .bytes(let payload) = fields[1], case .bytes(let signature) = fields[2],
                  case .boolean(let inserted) = fields[3], payload == envelope.canonicalPayload,
                  recoveryHead == nil || signature == envelope.signature,
                  try GatewayRecipientSignature.verify(signature: signature, publicKey: registration.rootPublicKey,
                    wireVersion: 1, kind: kind, canonicalPayload: payload, payloadLimits: limits, inputLimits: signing) else {
                throw GatewayRootChannelError.invalidMessage
            }
            return GatewayRecipientApplication(receipt: GatewayRecipientReceipt(control: control,
                canonicalPayload: payload, signature: signature), inserted: inserted)
        } catch { close(); throw error }
    }
}
