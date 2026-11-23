import Foundation
import RemozioProtocol

public enum PairingEnrollmentError: Error, Equatable {
    case wrongContext, invalidProof, expired, invalidAudit
}

/// Root-local setup state. Construct only after administrator authorization and human transcript verification.
/// Network input cannot create this authorization context. A restart requires a new authorized attempt.
public final class PairingEnrollmentAttempt: Sendable {
    public let transcript: PairingTranscript
    private let replacement: Replacement
    private let revision: UUID
    private let started: AuthorityMoment
    private let deadline: UInt64
    private let enrollment: StoredApprovalEnrollment

    enum Replacement: Sendable {
        case none
        case revokeActive(PairingReplacement)
        case requireRevoked(PairingReplacement)

        var predecessor: PairingReplacement? {
            switch self {
            case .none: nil
            case .revokeActive(let value), .requireRevoked(let value): value
            }
        }
    }

    public convenience init(transcript: PairingTranscript, trusted: ApprovalTrustSnapshot,
                            authorizedReplacement: PairingReplacement?,
                            authorityPublicKey: Data, transportPublicKey: Data, minimumEnvelopeVersion: UInt64,
                            started: AuthorityMoment, startedAtUnixMillis: UInt64, deadlineMilliseconds: UInt64) throws {
        try self.init(transcript: transcript, trusted: trusted,
            replacement: authorizedReplacement.map(Replacement.revokeActive) ?? .none,
            authorityPublicKey: authorityPublicKey, transportPublicKey: transportPublicKey,
            minimumEnvelopeVersion: minimumEnvelopeVersion, started: started,
            startedAtUnixMillis: startedAtUnixMillis, deadlineMilliseconds: deadlineMilliseconds)
    }

    init(transcript: PairingTranscript, trusted: ApprovalTrustSnapshot, replacement: Replacement,
         authorityPublicKey: Data, transportPublicKey: Data, minimumEnvelopeVersion: UInt64,
         started: AuthorityMoment, startedAtUnixMillis: UInt64, deadlineMilliseconds: UInt64) throws {
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 5, maxItems: 5000)
        guard case let .map(offer) = try DeterministicCBOR.decode(transcript.phone.encode(), limits: limits),
              case let .array(scope) = offer[2], scope.count == 4,
              case let .bytes(mac) = scope[0], case let .bytes(account) = scope[1],
              case let .bytes(phone) = scope[2], case let .bytes(epoch) = scope[3] else { throw PairingEnrollmentError.wrongContext }
        var uuid = trusted.revision.uuid
        let revisionBytes = withUnsafeBytes(of: &uuid) { Data($0) }
        guard transcript.replacement == replacement.predecessor,
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
        self.replacement = replacement
        self.transcript = transcript; self.revision = trusted.revision
        self.started = started; self.deadline = started.milliseconds + lifetime
    }

    /// Retained setup cleanup uses the same bounded monotonic lifetime as enrollment commit.
    func remainingMilliseconds(at current: AuthorityMoment) throws -> UInt64 {
        guard current.epoch == started.epoch, current.milliseconds >= started.milliseconds else {
            throw PairingEnrollmentError.expired
        }
        return current.milliseconds < deadline ? deadline - current.milliseconds : 0
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

    static func revokedPredecessors(_ rows: [StoredApprovalEnrollment], restrictions: Set<Data>) -> [DeliveryRecipient] {
        let active = Set(rows.lazy.filter { $0.approval.active }.map { $0.approval.phoneID })
        return rows.compactMap { row in
            guard !active.contains(row.approval.phoneID), !restrictions.contains(row.approval.phoneID) else { return nil }
            return DeliveryRecipient(row)
        }
    }

    func validateEnrollmentHistory(_ transaction: JournalTransaction) throws {
        let scope = transcript.phone.scope
        let retained = try transaction.approvalEnrollments()
        let samePhone = retained.filter { $0.approval.phoneID == scope.phoneID }
        switch replacement {
        case .none:
            guard samePhone.isEmpty else { throw EnrollmentJournalError.reusedIdentity }
        case .requireRevoked(let predecessor):
            guard predecessor.phoneID == scope.phoneID, predecessor.epoch != scope.enrollmentEpoch else {
                throw PairingEnrollmentError.wrongContext
            }
            guard try !transaction.approvalTrustRestrictions().contains(scope.phoneID) else {
                throw EnrollmentJournalError.recoveryRequired
            }
            guard Self.revokedPredecessors(samePhone, restrictions: []).contains(
                DeliveryRecipient(phoneID: predecessor.phoneID, enrollmentEpoch: predecessor.epoch)) else {
                throw EnrollmentJournalError.unavailableEnrollment
            }
        case .revokeActive:
            return
        }
        let proposedKeys = Set([transcript.transportKey.publicKey, transcript.decisionKey.publicKey, transcript.biometricKey.publicKey])
        for row in retained {
            guard proposedKeys.isDisjoint(with: [row.identityPublicKey] + row.approval.keys.map(\.publicKey)) else {
                throw EnrollmentJournalError.reusedIdentity
            }
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
        if case .revokeActive = replacement {
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
        try validateEnrollmentHistory(transaction)
        var expected = revision
        var head = expectedAuditHead
        var control: GatewayAuthorityEnvelope?
        if case .revokeActive(let replacement) = replacement {
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
