import Foundation
import RemozioProtocol

public enum PairingEnrollmentError: Error, Equatable {
    case wrongContext, invalidProof, expired, invalidAudit
}

/// Root-local setup state. Construct only after administrator authorization and human transcript verification.
/// Network input cannot create this authorization context. A restart requires a new authorized attempt.
public final class PairingEnrollmentAttempt: Sendable {
    public let transcript: PairingTranscript
    private let authorizedReplacement: PairingReplacement?
    private let revision: UUID
    private let started: AuthorityMoment
    private let deadline: UInt64
    private let enrollment: StoredApprovalEnrollment

    public init(transcript: PairingTranscript, trusted: ApprovalTrustSnapshot,
                authorizedReplacement: PairingReplacement?,
                authorityPublicKey: Data, transportPublicKey: Data, minimumEnvelopeVersion: UInt64,
                started: AuthorityMoment, startedAtUnixMillis: UInt64, deadlineMilliseconds: UInt64) throws {
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 5, maxItems: 5000)
        guard case let .map(offer) = try DeterministicCBOR.decode(transcript.phone.encode(), limits: limits),
              case let .array(scope) = offer[2], scope.count == 4,
              case let .bytes(mac) = scope[0], case let .bytes(account) = scope[1],
              case let .bytes(phone) = scope[2], case let .bytes(epoch) = scope[3] else { throw PairingEnrollmentError.wrongContext }
        var uuid = trusted.revision.uuid
        let revisionBytes = withUnsafeBytes(of: &uuid) { Data($0) }
        guard transcript.replacement?.phoneID == authorizedReplacement?.phoneID,
              transcript.replacement?.epoch == authorizedReplacement?.epoch,
              mac == trusted.macID, account == trusted.accountID,
              transcript.expectedTrustRevision == revisionBytes,
              transcript.macAuthorityKey == authorityPublicKey, transcript.macTransportKey == transportPublicKey,
              transcript.minimumEnvelopeVersion == minimumEnvelopeVersion,
              started.milliseconds < deadlineMilliseconds else {
            throw PairingEnrollmentError.wrongContext
        }
        guard startedAtUnixMillis >= transcript.issuedAtUnixMillis,
              startedAtUnixMillis < transcript.expiresAtUnixMillis else { throw PairingEnrollmentError.expired }
        let remaining = transcript.expiresAtUnixMillis - startedAtUnixMillis
        let lifetime = min(deadlineMilliseconds - started.milliseconds, remaining)
        self.enrollment = try StoredApprovalEnrollment(epoch: epoch, notificationTag: transcript.enrollmentTag,
            identityPublicKey: transcript.transportKey.publicKey,
            approval: ApprovalEnrollment(phoneID: phone, active: true, capabilities: Self.capabilities(transcript), keys: [
                EnrolledApprovalKey(id: transcript.decisionKey.keyID, keyClass: .decision, publicKey: transcript.decisionKey.publicKey),
                EnrolledApprovalKey(id: transcript.biometricKey.keyID, keyClass: .biometric, publicKey: transcript.biometricKey.publicKey),
            ]))
        self.authorizedReplacement = authorizedReplacement
        self.transcript = transcript; self.revision = trusted.revision
        self.started = started; self.deadline = started.milliseconds + lifetime
    }

    static func capabilities(_ transcript: PairingTranscript) throws -> ContractCapabilities {
        var contracts: [RequestContract: Set<UInt64>] = [:]
        for capability in transcript.phone.requests {
            let kind: RequestKind
            switch capability.kind {
            case 0: kind = .command
            case 1: kind = .onePasswordAccess
            case 2: kind = .onePasswordUnlock
            case 3: kind = .littleSnitch
            default: continue
            }
            let contract = try RequestContract(requestKind: kind, wireVersion: capability.wireVersion, schemaVersion: capability.schemaVersion)
            contracts[contract] = capability.features
        }
        return ContractCapabilities(contracts: contracts)
    }

    /// Commits keys, optional old-phone revocation, and audit records in one transaction.
    /// The host rechecks administrator authorization before this call and signs a receipt only after it returns.
    public func commit(database: JournalDatabase, biometricProof: Data, writer: AuditEpochWriter,
                       expectedAuditHead: UInt64, addEventID: Data, removalEventID: Data? = nil,
                       receiptTimeMs: UInt64?, gateway: EnrollmentGatewayRemoval? = nil,
                       now: () throws -> AuthorityMoment) throws -> (revision: UUID, gatewayControl: GatewayAuthorityEnvelope?) {
        try database.write { transaction in
            try commit(transaction: transaction, biometricProof: biometricProof, writer: writer,
                expectedAuditHead: expectedAuditHead, addEventID: addEventID, removalEventID: removalEventID,
                receiptTimeMs: receiptTimeMs, gateway: gateway, now: now)
        }
    }

    /// The shared request owner supplies its checkpointed transaction and current audit head.
    func commit(transaction: JournalTransaction, biometricProof: Data, writer: AuditEpochWriter,
                expectedAuditHead: UInt64, addEventID: Data, removalEventID: Data?,
                receiptTimeMs: UInt64?, gateway: EnrollmentGatewayRemoval?,
                now: () throws -> AuthorityMoment) throws -> (revision: UUID, gatewayControl: GatewayAuthorityEnvelope?) {
        guard try transcript.verify(signature: biometricProof, publicKey: transcript.biometricKey.publicKey, purpose: .phoneBiometric) else {
            throw PairingEnrollmentError.invalidProof
        }
        guard addEventID.count == 16, expectedAuditHead < UInt64.max else { throw PairingEnrollmentError.invalidAudit }
        if authorizedReplacement != nil {
            guard let removalEventID, removalEventID.count == 16, removalEventID != addEventID,
                  expectedAuditHead < UInt64.max - 1 else { throw PairingEnrollmentError.invalidAudit }
        } else if removalEventID != nil || gateway != nil { throw PairingEnrollmentError.wrongContext }
        let current = try now()
        guard current.epoch == started.epoch, current.milliseconds >= started.milliseconds,
              current.milliseconds < deadline else { throw PairingEnrollmentError.expired }
        let trust = try transaction.approvalTrustSnapshot()
        guard trust.revision == revision else { throw EnrollmentJournalError.staleRevision }
        guard try transcript.phone.scope == ChannelScope(macID: trust.macID, accountID: trust.accountID,
            phoneID: enrollment.approval.phoneID, enrollmentEpoch: enrollment.epoch) else { throw PairingEnrollmentError.wrongContext }
        var expected = revision
        var head = expectedAuditHead
        var control: GatewayAuthorityEnvelope?
        if let replacement = authorizedReplacement {
            let removed = try transaction.revokeApprovalEnrollment(phoneID: replacement.phoneID, epoch: replacement.epoch,
                expectedTrustRevision: expected, eventID: removalEventID!, receiptTimeMs: receiptTimeMs,
                writer: writer, expectedAuditHead: head, gateway: gateway)
            expected = removed.revision; control = removed.gatewayControl; head += 1
        }
        let next = try transaction.addApprovalEnrollment(enrollment, expectedTrustRevision: expected,
            eventID: addEventID, receiptTimeMs: receiptTimeMs, writer: writer, expectedAuditHead: head)
        try transaction.retainPairing(transcript, biometricProof: biometricProof, enrollment: enrollment)
        let finished = try now()
        guard finished.epoch == started.epoch, finished.milliseconds >= current.milliseconds,
              finished.milliseconds < deadline else { throw PairingEnrollmentError.expired }
        return (next, control)
    }
}
