import CryptoKit
import Foundation
import RemozioProtocol

/// Protected scheduling state for one already verified release. It grants no activation authority.
struct UpdateSchedulingSnapshot: Equatable, Sendable {
    let updateID: Data
    let generation: UInt64
    let revision: UInt64

    init(updateID: Data, generation: UInt64, revision: UInt64) throws {
        guard updateID.count == 32, generation > 0 else { throw UpdateSchedulingVerificationError.invalidTrustedState }
        self.updateID = updateID; self.generation = generation; self.revision = revision
    }
}

enum UpdateSchedulingVerificationError: Error, Equatable {
    case invalidTrustedState, wrongBinding, staleTrust, staleSchedulingState, wrongChallenge
    case invalidClock, expired, unavailableEnrollment, wrongKey, invalidSignature
}

/// Retain under the authority's owner. A restart invalidates this challenge's clock epoch.
struct RetainedUpdateSchedulingChallenge: Sendable {
    let control: UpdateSchedulingControl
    let trustRevision: UUID
    let issuedAt: AuthorityMoment
    let deadlineMilliseconds: UInt64

    init(control: UpdateSchedulingControl, trustRevision: UUID, issuedAt: AuthorityMoment, deadlineMilliseconds: UInt64) throws {
        guard issuedAt.milliseconds < deadlineMilliseconds,
              deadlineMilliseconds - issuedAt.milliseconds == control.expiresAtUnixMillis - control.issuedAtUnixMillis else {
            throw UpdateSchedulingVerificationError.invalidTrustedState
        }
        self.control = control; self.trustRevision = trustRevision
        self.issuedAt = issuedAt; self.deadlineMilliseconds = deadlineMilliseconds
    }
}

/// Verification evidence only. Consume the challenge with the scheduling change in the protected transaction.
struct VerifiedUpdateSchedulingControl: Sendable {
    let control: UpdateSchedulingControl
    let trustRevision: UUID
    let clockEpoch: UUID
    let deadlineMilliseconds: UInt64
    fileprivate init(control: UpdateSchedulingControl, trustRevision: UUID, clockEpoch: UUID, deadlineMilliseconds: UInt64) {
        self.control = control; self.trustRevision = trustRevision
        self.clockEpoch = clockEpoch; self.deadlineMilliseconds = deadlineMilliseconds
    }
}

/// The host supplies the authenticated channel binding and current protected trust from the same journal transaction.
/// This component neither consumes a challenge nor changes admission, dispatch, scheduling, or installation state.
enum UpdateSchedulingVerifier {
    static func verify(canonicalControl: Data, signature: Data, retained: RetainedUpdateSchedulingChallenge,
                       current: UpdateSchedulingSnapshot, binding: AuthorityPeerBinding, trust: RequestDeliveryTrust,
                       now: AuthorityMoment, nowUnixMillis: UInt64, payloadLimits: CBORLimits, signingLimits: CBORLimits)
        throws -> VerifiedUpdateSchedulingControl {
        let control = try UpdateSchedulingControl.decode(canonicalControl, limits: payloadLimits)
        guard control.macID == trust.approval.macID, control.accountID == trust.approval.accountID,
              control.macID == binding.scope.macID, control.accountID == binding.scope.accountID,
              control.phoneID == binding.scope.phoneID, control.enrollmentEpoch == binding.scope.enrollmentEpoch else {
            throw UpdateSchedulingVerificationError.wrongBinding
        }
        guard retained.trustRevision == trust.approval.revision, binding.revision == trust.approval.revision else {
            throw UpdateSchedulingVerificationError.staleTrust
        }
        guard control == retained.control else { throw UpdateSchedulingVerificationError.wrongChallenge }
        guard current.updateID == control.updateID, current.generation == control.expectedGeneration,
              current.revision == control.expectedRevision else { throw UpdateSchedulingVerificationError.staleSchedulingState }
        guard now.epoch == retained.issuedAt.epoch, now.milliseconds >= retained.issuedAt.milliseconds else {
            throw UpdateSchedulingVerificationError.invalidClock
        }
        guard now.milliseconds < retained.deadlineMilliseconds,
              nowUnixMillis >= control.issuedAtUnixMillis, nowUnixMillis < control.expiresAtUnixMillis else {
            throw UpdateSchedulingVerificationError.expired
        }
        guard trust.approval.enrollments.contains(where: { $0.phoneID == control.phoneID && $0.active }),
              let enrollment = trust.enrollments.first(where: {
            $0.approval.phoneID == control.phoneID && $0.epoch == control.enrollmentEpoch && $0.approval.active
        }) else { throw UpdateSchedulingVerificationError.unavailableEnrollment }
        guard let transport = try? P256.Signing.PublicKey(derRepresentation: binding.transportPublicKey),
              transport.x963Representation == enrollment.identityPublicKey else {
            throw UpdateSchedulingVerificationError.wrongBinding
        }
        guard let key = enrollment.approval.keys.first(where: { $0.id == control.keyID && $0.keyClass == .decision }) else {
            throw UpdateSchedulingVerificationError.wrongKey
        }
        guard try UpdateSchedulingSignature.verify(signature: signature, publicKey: key.publicKey, wireVersion: 1,
            canonicalPayload: canonicalControl, payloadLimits: payloadLimits, inputLimits: signingLimits) else {
            throw UpdateSchedulingVerificationError.invalidSignature
        }
        return VerifiedUpdateSchedulingControl(control: control, trustRevision: trust.approval.revision,
            clockEpoch: now.epoch, deadlineMilliseconds: retained.deadlineMilliseconds)
    }
}

extension JournalTransaction {
    /// Checks current protected enrollment in this transaction. Scheduling and one-use consumption remain separate work.
    func verifyUpdateScheduling(canonicalControl: Data, signature: Data, retained: RetainedUpdateSchedulingChallenge,
                                current: UpdateSchedulingSnapshot, binding: AuthorityPeerBinding,
                                now: AuthorityMoment, nowUnixMillis: UInt64, payloadLimits: CBORLimits, signingLimits: CBORLimits)
        throws -> VerifiedUpdateSchedulingControl {
        try UpdateSchedulingVerifier.verify(canonicalControl: canonicalControl, signature: signature, retained: retained,
            current: current, binding: binding, trust: requestDeliveryTrust(), now: now, nowUnixMillis: nowUnixMillis,
            payloadLimits: payloadLimits, signingLimits: signingLimits)
    }
}

extension RetainedUpdateSchedulingChallenge {
    func requireLive(now: AuthorityMoment, wall: UInt64) throws {
        guard now.epoch == issuedAt.epoch, now.milliseconds >= issuedAt.milliseconds else {
            throw UpdateSchedulingVerificationError.invalidClock
        }
        guard now.milliseconds < deadlineMilliseconds, wall >= control.issuedAtUnixMillis,
              wall < control.expiresAtUnixMillis else { throw UpdateSchedulingVerificationError.expired }
    }
}
