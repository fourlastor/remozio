import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore
import RemozioProtocol

final class AuthorityPhonePushRecoveryTests: XCTestCase {
    private enum Failure: Error { case injected, invalidResponse }
    private typealias Harness = AuthorityPhonePushRegistrationTests.Harness
    private func resume(_ h: Harness, token: String = "synthetic-token", project: String = "project", time: UInt64 = 100,
                        binding: AuthorityPeerBinding? = nil, validate: (JournalTransaction) throws -> Void = { _ in }) throws -> PhonePushRecoveryFrame {
        let frame = PhonePushRecoveryFrame.resume(correlationID: Data(repeating: 80, count: 16),
            offer: try PhonePushTokenOffer(token: token, projectID: project, senderID: "123", packageName: "dev.remozio.android"))
        return try h.owner.phonePushRecovery(frame, binding: binding ?? h.binding, provider: h.provider,
            now: .init(epoch: h.clock, milliseconds: time), wall: 900 + time, validateTransport: validate)
    }
    private func state(_ frame: PhonePushRecoveryFrame) throws -> PhonePushRecoveryState {
        guard case .state(_, let state) = frame else { throw Failure.invalidResponse }; return state
    }
    private func commitProof(_ h: Harness, metadata: PhonePushRegistrationMetadata) throws {
        let candidate = try h.candidate(metadata)
        _ = try h.exchange(.proof(correlationID: Data(repeating: 81, count: 16), proof: GatewayTokenProof(binding: candidate.binding)))
    }
    private func observation(_ h: Harness, time: UInt64 = 120, present: Bool = true, receivedAt: UInt64? = nil) throws -> VerifiedGatewayMappingState {
        let now = AuthorityMoment(epoch: h.clock, milliseconds: time)
        let state = try XCTUnwrap(h.owner.currentPhonePushRegistration(h.provider, phoneID: h.binding.scope.phoneID,
            enrollmentEpoch: h.binding.scope.enrollmentEpoch, now: now, wall: 900 + time))
        let candidate = try GatewayTokenCandidate.decode(state.candidate.canonicalPayload, limits: h.limits)
        let scope = try GatewayMappingScope(registration: h.registration, binding: candidate.binding)
        let key = P256.Signing.PrivateKey(), owner = try GatewayMappingQueryOwner(scope: scope,
            gatewayPublicKey: key.publicKey.x963Representation, clockEpoch: h.clock)
        let (_, nonce) = try GatewayMappingStateWire.query(owner.query(now: now))
        var fields = try scope.fields
        fields[0] = .unsigned(2); fields[1] = .unsigned(5); fields[3] = .bytes(nonce); fields[8] = .unsigned(present ? 1 : 0)
        fields[9] = .bytes(present ? try XCTUnwrap(state.activation).canonicalPayload : Data())
        fields[10] = .bytes(present ? try XCTUnwrap(state.activation).signature : Data())
        let payload = try DeterministicCBOR.encode(.map(fields), limits: GatewayMappingStateWire.replyLimits)
        return try owner.accept(GatewayMappingStateReply(canonicalPayload: payload,
            signature: key.signature(for: GatewayMappingStateWire.signingInput(payload)).rawRepresentation),
            now: .init(epoch: h.clock, milliseconds: receivedAt ?? time))
    }
    private func record(_ h: Harness, _ observation: VerifiedGatewayMappingState, session: UUID, time: UInt64 = 121,
                        validUntil: UInt64 = 10000, revision: UUID? = nil) throws {
        try h.owner.recordPhonePushMapping(h.provider, observation: observation, session: session,
            expectedTrustRevision: revision ?? h.binding.revision, validUntilMilliseconds: validUntil,
            now: .init(epoch: h.clock, milliseconds: time), wall: 900 + time)
    }
    func testOnlyFreshObservationCanElevateCommittedProofToObservedMapping() throws {
        let h = try Harness(), metadata = try state(resume(h)).metadata
        try commitProof(h, metadata: metadata)
        let session = UUID(); try h.owner.beginWakePublicationSession(session)
        let observed = try observation(h), checkpoint = try h.store.read(), signs = h.signs.value
        try record(h, observed, session: session)
        let current = try state(resume(h, time: 122))
        XCTAssertEqual(current.phase, .mappingObserved); XCTAssertEqual(current.observationAgeMilliseconds, 2)
        XCTAssertEqual(try state(resume(h, time: 5120)).phase, .proofCommitted)
        XCTAssertEqual(try h.store.read(), checkpoint); XCTAssertEqual(h.signs.value, signs)
    }
    func testDelayedGatewayReplyCannotRestartTheObservationWindow() throws {
        let h = try Harness(), metadata = try state(resume(h)).metadata
        try commitProof(h, metadata: metadata)
        let session = UUID(); try h.owner.beginWakePublicationSession(session)
        let delayed = try observation(h, time: 120, receivedAt: 5119), checkpoint = try h.store.read()
        XCTAssertEqual(delayed.queriedAt.milliseconds, 120)
        XCTAssertEqual(delayed.receivedAt.milliseconds, 5119)
        XCTAssertEqual(delayed.validUntilMilliseconds, 5120)
        try record(h, delayed, session: session, time: 5119)
        let current = try state(resume(h, time: 5119))
        XCTAssertEqual(current.phase, .mappingObserved); XCTAssertEqual(current.observationAgeMilliseconds, 4999)
        XCTAssertEqual(try state(resume(h, time: 5120)).phase, .proofCommitted)
        XCTAssertThrowsError(try record(h, delayed, session: session, time: 5120))
        XCTAssertEqual(try state(resume(h, time: 5121)).phase, .proofCommitted)
        XCTAssertEqual(try h.store.read(), checkpoint)
    }
    func testPublisherLeaseExpiryRemovesObservedMappingStatus() throws {
        let h = try Harness(), metadata = try state(resume(h)).metadata
        try commitProof(h, metadata: metadata)
        let session = UUID(); try h.owner.beginWakePublicationSession(session)
        try record(h, observation(h), session: session, validUntil: 150)
        XCTAssertEqual(try state(resume(h, time: 149)).phase, .mappingObserved)
        XCTAssertEqual(try state(resume(h, time: 150)).phase, .proofCommitted)
    }
    func testRetiredPublisherCannotRestoreOrClearANewerObservation() throws {
        let h = try Harness(), metadata = try state(resume(h)).metadata
        try commitProof(h, metadata: metadata)
        let first = UUID(), second = UUID(); try h.owner.beginWakePublicationSession(first)
        let observed = try observation(h); try record(h, observed, session: first)
        h.owner.endWakePublicationSession(first); try h.owner.beginWakePublicationSession(second)
        XCTAssertEqual(try state(resume(h, time: 122)).phase, .proofCommitted)
        XCTAssertThrowsError(try record(h, observed, session: first, time: 123))
        try record(h, observed, session: second, time: 124)
        h.owner.endWakePublicationSession(first)
        XCTAssertEqual(try state(resume(h, time: 125)).phase, .mappingObserved)
    }
    func testFreshAbsenceClearsEarlierPositiveObservationWithoutWritingContinuity() throws {
        let h = try Harness(), metadata = try state(resume(h)).metadata
        try commitProof(h, metadata: metadata)
        let session = UUID(); try h.owner.beginWakePublicationSession(session)
        try record(h, observation(h), session: session)
        XCTAssertEqual(try state(resume(h, time: 122)).phase, .mappingObserved)
        let checkpoint = try h.store.read(), missing = try observation(h, time: 130, present: false)
        try record(h, missing, session: session, time: 131)
        XCTAssertEqual(try state(resume(h, time: 132)).phase, .proofCommitted)
        XCTAssertEqual(try h.store.read(), checkpoint)
    }
    func testWrongTrustAndSupersededObservationsCannotConfirmAnotherToken() throws {
        let h = try Harness(), metadata = try state(resume(h)).metadata
        try commitProof(h, metadata: metadata)
        let session = UUID(); try h.owner.beginWakePublicationSession(session)
        let observed = try observation(h); try record(h, observed, session: session)
        XCTAssertThrowsError(try record(h, observed, session: session, time: 122, revision: UUID()))
        let next = try state(resume(h, token: "replacement-token", time: 123))
        XCTAssertNotEqual(next.metadata.candidateID, metadata.candidateID)
        XCTAssertEqual(next.phase, .awaitingProviderProof)
        XCTAssertThrowsError(try record(h, observed, session: session, time: 124))
        XCTAssertEqual(try state(resume(h, token: "replacement-token", time: 125)).phase, .awaitingProviderProof)
    }
    func testHandshakeAndHostRolesCannotEnterRootResume() throws {
        let h = try Harness(), before = try h.store.read(), id = Data(repeating: 80, count: 16)
        let roles: [PhonePushRecoveryFrame] = [.probe(correlationID: id), .ready(correlationID: id), .outcome(correlationID: id, failure: .unavailable)]
        for frame in roles {
            XCTAssertThrowsError(try h.owner.phonePushRecovery(frame, binding: h.binding, provider: h.provider,
                now: .init(epoch: h.clock, milliseconds: 100), wall: 1000,
                validateTransport: { _ in XCTFail("Invalid role reached transport policy callback") }))
        }
        XCTAssertEqual(h.signs.value, 0); XCTAssertEqual(try h.head, 0)
        XCTAssertEqual(try h.store.read(), before)
    }
    func testRepeatedResumeRecoversLostMetadataWithoutAnotherCheckpointOrSignature() throws {
        let h = try Harness(), first = try state(resume(h))
        XCTAssertEqual(first.phase, .awaitingProviderProof); XCTAssertNil(first.observationAgeMilliseconds)
        let checkpoint = try h.store.read(), signs = h.signs.value
        let recovered = try state(resume(h, time: 101))
        XCTAssertEqual(recovered.metadata, first.metadata)
        XCTAssertEqual(recovered.phase, .awaitingProviderProof)
        XCTAssertEqual(try h.head, 1); XCTAssertEqual(h.signs.value, signs)
        XCTAssertEqual(try h.store.read(), checkpoint); try h.assertCheckpoint()
    }
    func testLostProofReplyRecoversCommitBeyondTheOriginalProofDeadline() throws {
        let h = try Harness(), prepared = try state(resume(h))
        try commitProof(h, metadata: prepared.metadata)
        let checkpoint = try h.store.read(), signs = h.signs.value
        let recovered = try state(resume(h, time: 1101))
        XCTAssertEqual(recovered.metadata, prepared.metadata)
        XCTAssertEqual(recovered.phase, .proofCommitted)
        XCTAssertNil(recovered.observationAgeMilliseconds)
        XCTAssertEqual(try h.head, 2); XCTAssertEqual(h.signs.value, signs)
        XCTAssertEqual(try h.store.read(), checkpoint)
    }
    func testExpiredPendingResumeRenewsOnceAndPreservesEnrollmentAndTokenBinding() throws {
        let h = try Harness(), previous = try state(resume(h))
        let renewed = try state(resume(h, time: 1101))
        XCTAssertNotEqual(renewed.metadata.candidateID, previous.metadata.candidateID)
        XCTAssertEqual(renewed.metadata.enrollmentEpoch, previous.metadata.enrollmentEpoch)
        XCTAssertEqual(renewed.metadata.enrollmentTag, previous.metadata.enrollmentTag)
        XCTAssertEqual(renewed.metadata.tokenDigest, previous.metadata.tokenDigest)
        XCTAssertEqual(renewed.phase, .awaitingProviderProof)
        let checkpoint = try h.store.read(), signs = h.signs.value
        XCTAssertEqual(try state(resume(h, time: 1102)).metadata, renewed.metadata)
        XCTAssertEqual(try h.store.read(), checkpoint); XCTAssertEqual(h.signs.value, signs)
        XCTAssertEqual(try h.head, 2)
    }
    func testChangedTokenCreatesANewPendingCandidateAndInvalidatesOldProof() throws {
        let h = try Harness(), first = try state(resume(h)), candidate = try h.candidate(first.metadata)
        let next = try state(resume(h, token: "replacement-token"))
        XCTAssertNotEqual(next.metadata.tokenDigest, first.metadata.tokenDigest)
        XCTAssertNotEqual(next.metadata.candidateID, first.metadata.candidateID)
        XCTAssertEqual(next.phase, .awaitingProviderProof)
        XCTAssertThrowsError(try h.exchange(.proof(correlationID: Data(repeating: 81, count: 16), proof: GatewayTokenProof(binding: candidate.binding))))
        XCTAssertEqual(try state(resume(h, token: "replacement-token")).metadata, next.metadata)
        XCTAssertEqual(try h.head, 2)
    }
    func testIncompatibleProviderReturnsNoCandidateOrContinuityWrite() throws {
        let h = try Harness(), before = try h.store.read()
        guard case .outcome(_, .incompatible) = try resume(h, project: "different-project") else { return XCTFail("Wrong recovery failure") }
        XCTAssertEqual(try h.head, 0); XCTAssertEqual(h.signs.value, 0)
        XCTAssertEqual(try h.store.read(), before)
    }
    func testTransportAndStaleBindingCannotReachTheSigner() throws {
        let h = try Harness(), before = try h.store.read()
        XCTAssertThrowsError(try resume(h, validate: { _ in throw Failure.injected }))
        let stale = try AuthorityPeerBinding(scope: h.binding.scope, transportPublicKey: h.binding.transportPublicKey, revision: UUID())
        XCTAssertThrowsError(try resume(h, binding: stale))
        XCTAssertEqual(try h.head, 0); XCTAssertEqual(h.signs.value, 0)
        XCTAssertEqual(try h.store.read(), before)
    }
    func testTransportPolicyIsRecheckedInsideTheMutationTransaction() throws {
        let h = try Harness(); var calls = 0
        XCTAssertThrowsError(try resume(h, validate: { _ in calls += 1; if calls == 2 { throw Failure.injected } }))
        XCTAssertEqual(calls, 2); XCTAssertEqual(try h.head, 0); XCTAssertEqual(h.signs.value, 0)
        XCTAssertEqual(try state(resume(h)).phase, .awaitingProviderProof)
    }
    func testCheckpointFailureWithholdsPreparedRecoveryState() throws {
        for finalize in [false, true] {
            let h = try Harness(); try h.failCheckpoint(finalize: finalize)
            XCTAssertThrowsError(try resume(h))
            XCTAssertThrowsError(try resume(h))
        }
    }
    func testOneProviderTokenHasIndependentStateForEveryEnrolledPhone() throws {
        let h = try Harness(enrollmentCount: 2)
        let first = try state(resume(h)), second = try state(resume(h, binding: h.bindings[1]))
        XCTAssertNotEqual(first.metadata.phoneID, second.metadata.phoneID)
        XCTAssertNotEqual(first.metadata.candidateID, second.metadata.candidateID)
        XCTAssertNotEqual(first.metadata.enrollmentTag, second.metadata.enrollmentTag)
        XCTAssertEqual(first.metadata.tokenDigest, second.metadata.tokenDigest)
        let checkpoint = try h.store.read()
        XCTAssertEqual(try state(resume(h)).metadata, first.metadata)
        XCTAssertEqual(try state(resume(h, binding: h.bindings[1])).metadata, second.metadata)
        XCTAssertEqual(try h.store.read(), checkpoint); XCTAssertEqual(try h.head, 2)
    }
}
