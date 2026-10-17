import CryptoKit
import Foundation
import RemozioProtocol

/// Routing compatibility from protected setup. Constructing this value does not authenticate installation.
public struct AuthorityPhonePushPolicy: Sendable {
    public let registration: GatewayRegistrationIdentity
    public let projectID: String
    public let senderID: String
    public let packageName: String
    public init(registration: GatewayRegistrationIdentity, projectID: String, senderID: String, packageName: String) throws {
        _ = try PhonePushTokenOffer(token: "validation", projectID: projectID, senderID: senderID, packageName: packageName)
        self.registration = registration; self.projectID = projectID; self.senderID = senderID; self.packageName = packageName
    }
}

/// Fixed gateway operations. The request owner commits them with its independent continuity checkpoint.
public struct AuthorityPhonePushRegistration: Sendable {
    let policy: AuthorityPhonePushPolicy
    private let signing: @Sendable (Data) throws -> Data
    private let verifySelf: @Sendable (JournalTransaction) throws -> Void
    private var limits: CBORLimits { get throws { try .init(maxBytes: 4096, maxDepth: 8, maxItems: 128) } }

    public init(policy: AuthorityPhonePushPolicy, signer: EnclaveAuthorityRequestSigner) throws {
        guard signer.macID == policy.registration.macID, signer.accountID == policy.registration.accountID,
              signer.publicKey == policy.registration.rootPublicKey else { throw AuthorityRequestSignerError.wrongIdentity }
        self.init(policy: policy, signing: { try signer.sign($0) }, verifySelf: AuthoritySelfValidation.validate)
    }
    // Software signing and self-validation seams remain internal to component fixtures.
    init(policy: AuthorityPhonePushPolicy, signing: @escaping @Sendable (Data) throws -> Data,
         verifySelf: @escaping @Sendable (JournalTransaction) throws -> Void = { _ in }) {
        self.policy = policy; self.signing = signing; self.verifySelf = verifySelf
    }
    func configure(transaction: JournalTransaction) throws {
        try verifySelf(transaction)
        try transaction.configureGatewayAuthority(policy.registration)
    }
    func publicationBarrier(after revision: UInt64, transaction tx: JournalTransaction) throws -> UInt64? {
        try verifySelf(tx)
        return try tx.firstGatewayNonRegistrationControl(after: revision, registration: policy.registration)
    }
    func current(phoneID: Data, enrollmentEpoch: Data, transaction tx: JournalTransaction,
                 now: AuthorityMoment, wall: UInt64) throws -> GatewayCurrentTokenState? {
        try verifySelf(tx)
        let revision = try tx.approvalTrustSnapshot().revision
        return try tx.currentGatewayTokenState(phoneID: phoneID, enrollmentEpoch: enrollmentEpoch,
            registration: policy.registration, registrationActive: true, expectedTrustRevision: revision,
            nowUnixMillis: wall, now: now)
    }
    func renewExpired(phoneID: Data, enrollmentEpoch: Data, transaction tx: JournalTransaction,
                      now: AuthorityMoment, wall: UInt64) throws -> GatewayCurrentTokenState? {
        guard let previous = try current(phoneID: phoneID, enrollmentEpoch: enrollmentEpoch, transaction: tx, now: now, wall: wall),
              previous.needsRenewal else {
            return try current(phoneID: phoneID, enrollmentEpoch: enrollmentEpoch, transaction: tx, now: now, wall: wall)
        }
        let r = policy.registration, revision = try tx.approvalTrustSnapshot().revision
        _ = try tx.renewDesiredGatewayCandidate(phoneID: phoneID, enrollmentEpoch: enrollmentEpoch,
            registration: r, registrationActive: true, expectedTrustRevision: revision,
            expectedHead: tx.gatewayAuthorityHead(r), nowUnixMillis: wall, now: now,
            sign: { candidate in
                try signing(GatewayTokenCandidateSigningInput.make(wireVersion: 1,
                    canonicalPayload: candidate.encode(limits: limits), payloadLimits: limits, inputLimits: limits))
            })
        return try current(phoneID: phoneID, enrollmentEpoch: enrollmentEpoch, transaction: tx, now: now, wall: wall)
    }
    func acknowledge(_ head: VerifiedGatewayHead, expectedTrustRevision: UUID, transaction tx: JournalTransaction,
                     commit: Bool) throws -> GatewayAcknowledgmentResult {
        try verifySelf(tx)
        guard head.evidence.registration == policy.registration else { throw GatewayAuthorityError.wrongScope }
        guard try tx.approvalTrustSnapshot().revision == expectedTrustRevision else { throw EnrollmentJournalError.staleRevision }
        if commit { return try tx.acknowledgeGatewayHead(head) }
        return try tx.inspectGatewayHead(head)
    }

    /// Only a fresh absent observation for the exact committed desired mapping may trigger repair.
    func renewMissing(_ observation: VerifiedGatewayMappingState, expectedTrustRevision: UUID,
                      transaction tx: JournalTransaction, now: AuthorityMoment, wall: UInt64) throws -> GatewayCurrentTokenState? {
        try verifySelf(tx)
        guard try tx.approvalTrustSnapshot().revision == expectedTrustRevision else { throw EnrollmentJournalError.staleRevision }
        guard observation.scope.registration == policy.registration, observation.activation == nil,
              let retained = try current(phoneID: observation.scope.phoneID, enrollmentEpoch: observation.scope.enrollmentEpoch,
                transaction: tx, now: now, wall: wall), retained.activation != nil else { throw GatewayAuthorityError.superseded }
        let candidate = try GatewayTokenCandidate.decode(retained.candidate.canonicalPayload, limits: limits)
        guard observation.scope.matches(candidate.binding) else { throw GatewayAuthorityError.superseded }
        let r = policy.registration
        _ = try tx.renewDesiredGatewayCandidate(phoneID: candidate.binding.phoneID, enrollmentEpoch: candidate.binding.enrollmentEpoch,
            registration: r, registrationActive: true, expectedTrustRevision: expectedTrustRevision,
            expectedHead: tx.gatewayAuthorityHead(r), nowUnixMillis: wall, now: now,
            sign: { candidate in
                try signing(GatewayTokenCandidateSigningInput.make(wireVersion: 1,
                    canonicalPayload: candidate.encode(limits: limits), payloadLimits: limits, inputLimits: limits))
            })
        return try current(phoneID: candidate.binding.phoneID, enrollmentEpoch: candidate.binding.enrollmentEpoch,
            transaction: tx, now: now, wall: wall)
    }

    func process(_ request: PhonePushRegistrationFrame, binding: AuthorityPeerBinding, transaction tx: JournalTransaction,
                 now: AuthorityMoment, wall: UInt64) throws -> PhonePushRegistrationFrame {
        try verifySelf(tx)
        try tx.requireDirectApprovalBinding(binding)
        let r = policy.registration, scope = binding.scope
        guard r.macID == scope.macID, r.accountID == scope.accountID else { throw GatewayAuthorityError.wrongScope }
        let revision = try tx.gatewayAuthorityHead(r)
        switch request {
        case .offer(let correlation, let offer):
            guard offer.projectID == policy.projectID, offer.senderID == policy.senderID, offer.packageName == policy.packageName else {
                return .outcome(correlationID: correlation, outcome: .incompatible)
            }
            let envelope = try tx.prepareGatewayCandidate(registrationToken: offer.token, authenticatedPhoneID: scope.phoneID,
                authenticatedEnrollmentEpoch: scope.enrollmentEpoch, registration: r, registrationActive: true,
                expectedTrustRevision: binding.revision, expectedHead: revision, nowUnixMillis: wall, now: now,
                sign: { candidate in
                    try signing(GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: candidate.encode(limits: limits),
                        payloadLimits: limits, inputLimits: limits))
                })
            let candidate = try GatewayTokenCandidate.decode(envelope.canonicalPayload, limits: limits)
            return .prepared(correlationID: correlation, metadata: try PhonePushRegistrationMetadata(candidate))
        case .proof(let correlation, let proof):
            let b = proof.binding
            guard b.macID == scope.macID, b.accountID == scope.accountID, b.phoneID == scope.phoneID,
                  b.enrollmentEpoch == scope.enrollmentEpoch, b.ownerID == r.ownerID,
                  b.gatewayID == r.gatewayID, b.lifecycleEpoch == r.lifecycleEpoch else { throw GatewayAuthorityError.wrongScope }
            _ = try tx.consumeGatewayProof(canonicalProof: proof.encode(limits: limits), authenticatedPhoneID: scope.phoneID,
                authenticatedEnrollmentEpoch: scope.enrollmentEpoch, registration: r, registrationActive: true,
                expectedTrustRevision: binding.revision, expectedHead: revision, nowUnixMillis: wall, now: now,
                sign: { activation in
                    try signing(GatewayRecipientSigningInput.make(wireVersion: 1, kind: .activation,
                        canonicalPayload: activation.encode(limits: limits), payloadLimits: limits, inputLimits: limits))
                })
            return .outcome(correlationID: correlation, outcome: .proofCommitted)
        default: throw AuthorityXPCError.invalidMessage
        }
    }
}
