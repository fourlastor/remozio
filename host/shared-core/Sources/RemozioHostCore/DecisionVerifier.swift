import Foundation
import RemozioProtocol

/// Authority-owned time from a sleep-inclusive monotonic clock. Replace the epoch after an authority restart.
public struct AuthorityMoment: Equatable, Sendable {
    public let epoch: UUID
    public let milliseconds: UInt64
    public init(epoch: UUID, milliseconds: UInt64) {
        self.epoch = epoch
        self.milliseconds = milliseconds
    }
}

public enum DecisionVerificationError: Error, Equatable {
    case invalidTrustedState, wrongRequest, wrongAccount, unavailableRequest, invalidClock, expired
    case unsupportedContract, unsupportedFeatures, unavailableEnrollment, wrongKey, wrongKeyClass, invalidSignature
}

/// Retained in authority memory. The wall times in the wire payload never establish this deadline.
public struct RetainedApprovalRequest: Sendable {
    public let payload: IssuedRequestPayload
    public let phase: RequestPhase
    public let admittedAt: AuthorityMoment
    public let deadlineMilliseconds: UInt64

    public init(payload: IssuedRequestPayload, phase: RequestPhase, admittedAt: AuthorityMoment,
                deadlineMilliseconds: UInt64) throws {
        guard admittedAt.milliseconds < deadlineMilliseconds else { throw DecisionVerificationError.invalidTrustedState }
        self.payload = payload
        self.phase = phase
        self.admittedAt = admittedAt
        self.deadlineMilliseconds = deadlineMilliseconds
    }
}

public struct EnrolledApprovalKey: Sendable {
    public let id: Data
    public let keyClass: ApprovalKeyClass
    public let publicKey: Data
    public init(id: Data, keyClass: ApprovalKeyClass, publicKey: Data) throws {
        guard id.count == 16, publicKey.count == 65, publicKey.first == 4 else {
            throw DecisionVerificationError.invalidTrustedState
        }
        self.id = id
        self.keyClass = keyClass
        self.publicKey = publicKey
    }
}

/// Read from current trusted enrollment, never constructed from decision fields or transport advertisements.
public struct ApprovalEnrollment: Sendable {
    public let phoneID: Data
    public let active: Bool
    public let capabilities: ContractCapabilities
    public let keys: [EnrolledApprovalKey]
    public init(phoneID: Data, active: Bool, capabilities: ContractCapabilities, keys: [EnrolledApprovalKey]) throws {
        guard phoneID.count == 16, Set(keys.map(\.id)).count == keys.count else {
            throw DecisionVerificationError.invalidTrustedState
        }
        self.phoneID = phoneID
        self.active = active
        self.capabilities = capabilities
        self.keys = keys
    }
}

/// One account's consistent trust snapshot. Any trust or floor change must change revision before further consumption.
public struct ApprovalTrustSnapshot: Sendable {
    public let macID: Data
    public let accountID: Data
    public let revision: UUID
    public let authorityCapabilities: ContractCapabilities
    public let allowedContracts: Set<RequestContract>
    public let enrollments: [ApprovalEnrollment]
    public init(macID: Data, accountID: Data, revision: UUID, authorityCapabilities: ContractCapabilities,
                allowedContracts: Set<RequestContract>, enrollments: [ApprovalEnrollment]) throws {
        guard macID.count == 16, accountID.count == 16,
              Set(enrollments.map(\.phoneID)).count == enrollments.count else {
            throw DecisionVerificationError.invalidTrustedState
        }
        self.macID = macID
        self.accountID = accountID
        self.revision = revision
        self.authorityCapabilities = authorityCapabilities
        self.allowedContracts = allowedContracts
        self.enrollments = enrollments
    }
}

/// Local verification evidence, not a dispatch permit. Revalidate and consume durably under the authority's writer lock.
public struct VerifiedDecision: Sendable {
    public let decision: DecisionPayload
    public let requirement: ActionRequirement
    public let trustRevision: UUID
    public let clockEpoch: UUID
    public let deadlineMilliseconds: UInt64
    fileprivate init(decision: DecisionPayload, requirement: ActionRequirement, trustRevision: UUID,
                     clockEpoch: UUID, deadlineMilliseconds: UInt64) {
        self.decision = decision
        self.requirement = requirement
        self.trustRevision = trustRevision
        self.clockEpoch = clockEpoch
        self.deadlineMilliseconds = deadlineMilliseconds
    }
}

public enum DecisionVerifier {
    public static func verify(canonicalDecision: Data, signature: Data, retained: RetainedApprovalRequest,
                              trust: ApprovalTrustSnapshot, now: AuthorityMoment,
                              decisionLimits: CBORLimits, requestLimits: CBORLimits,
                              signingLimits: CBORLimits) throws -> VerifiedDecision {
        let decision = try DecisionPayload.decode(canonicalDecision, limits: decisionLimits)
        let request = retained.payload
        guard request.macID == trust.macID, request.accountID == trust.accountID else {
            throw DecisionVerificationError.wrongAccount
        }
        guard decision.macID == request.macID, decision.accountID == request.accountID,
              decision.requestID == request.requestID, decision.challenge == request.challenge,
              decision.requestDigest == (try request.requestDigest(bodyLimits: requestLimits, signingLimits: signingLimits)) else {
            throw DecisionVerificationError.wrongRequest
        }
        guard retained.phase == .queued || retained.phase == .presented else {
            throw DecisionVerificationError.unavailableRequest
        }
        guard now.epoch == retained.admittedAt.epoch, now.milliseconds >= retained.admittedAt.milliseconds else {
            throw DecisionVerificationError.invalidClock
        }
        guard now.milliseconds < retained.deadlineMilliseconds else { throw DecisionVerificationError.expired }
        guard trust.allowedContracts.contains(request.contract),
              let localFeatures = trust.authorityCapabilities.contracts[request.contract] else {
            throw DecisionVerificationError.unsupportedContract
        }
        guard let enrollment = trust.enrollments.first(where: { $0.phoneID == decision.phoneID }), enrollment.active else {
            throw DecisionVerificationError.unavailableEnrollment
        }
        guard let peerFeatures = enrollment.capabilities.contracts[request.contract] else {
            throw DecisionVerificationError.unsupportedContract
        }
        guard request.requiredFeatures.isSubset(of: localFeatures), request.requiredFeatures.isSubset(of: peerFeatures) else {
            throw DecisionVerificationError.unsupportedFeatures
        }
        let requirement = try ActionPolicy.requirement(for: decision.action, requestKind: request.contract.requestKind,
            retainedPermittedActions: Set(request.permittedActions))
        guard let key = enrollment.keys.first(where: { $0.id == decision.keyID }) else { throw DecisionVerificationError.wrongKey }
        guard key.keyClass == requirement.keyClass else { throw DecisionVerificationError.wrongKeyClass }
        let purpose: SigningPurpose
        switch requirement.purpose {
        case .cancellation: purpose = .cancellation
        case .oneTimeUI: purpose = .oneTimeUI
        case .biometricAuthorization: purpose = .biometricAuthorization
        }
        guard try ApprovalSignature.verify(signature: signature, publicKey: key.publicKey,
            wireVersion: request.contract.wireVersion, messageType: .decision, purpose: purpose,
            canonicalPayload: canonicalDecision, payloadLimits: decisionLimits, inputLimits: signingLimits) else {
            throw DecisionVerificationError.invalidSignature
        }
        return VerifiedDecision(decision: decision, requirement: requirement, trustRevision: trust.revision,
            clockEpoch: now.epoch, deadlineMilliseconds: retained.deadlineMilliseconds)
    }
}
