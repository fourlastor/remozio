import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RootUpdateSchedulingFixture {
    private enum Fault: Error { case injected }
    let data: UpdateSchedulingAccountFixture
    let owner: ApprovalRequestCoordinator
    let nonce = Data(repeating: 42, count: 32)
    init(checkpointed: Bool = true, enabled: Bool = true, startupOffer: Bool = true, gatewayEnabled: Bool = true,
        updateOwner: UpdateSchedulingAccountFixture.UpdateOwner = .currentAccount, retireExpiredGrant: Bool = false) throws {
        let prepared = try UpdateSchedulingAccountFixture(enabled: enabled, gatewayEnabled: gatewayEnabled, updateOwner: updateOwner)
        if enabled && startupOffer { try prepared.install(); _ = try prepared.offer() }
        else { _ = try prepared.machine.select(prepared.machine.copy()) }
        if retireExpiredGrant {
            let peer = try prepared.binding(), registration = try prepared.gateway
            try prepared.commits.write(epoch: prepared.epoch) { tx in
                let envelope = try tx.prepareGatewayCandidate(registrationToken: "synthetic-token",
                    authenticatedPhoneID: prepared.id(6), authenticatedEnrollmentEpoch: prepared.id(4),
                    registration: registration, registrationActive: true, expectedTrustRevision: peer.revision,
                    expectedHead: 0, nowUnixMillis: 1000, now: prepared.nextNow(), sign: { candidate in
                        try prepared.rootKey.signature(for: GatewayTokenCandidateSigningInput.make(wireVersion: 1,
                            canonicalPayload: candidate.encode(limits: prepared.limits), payloadLimits: prepared.limits,
                            inputLimits: prepared.limits)).rawRepresentation
                    })
                guard case .eligible(let control) = try tx.gatewayGrantRetirement(at: envelope.revision,
                    registration: registration, wall: 2000) else { throw Fault.injected }
                try tx.stageGatewayGrantAbandonment(control, wall: 2000)
            }
        }
        let coordinator: ApprovalRequestCoordinator
        if checkpointed {
            coordinator = try ApprovalRequestCoordinator(database: prepared.db, continuity: prepared.store, writer: prepared.writer,
                clockEpoch: prepared.clock, maximumRequests: 10, maximumRetainedBytes: 65536,
                requestLimits: prepared.limits, captureLimits: prepared.limits, decisionLimits: prepared.limits,
                signingLimits: prepared.limits, auditLimits: prepared.limits)
        } else {
            coordinator = try ApprovalRequestCoordinator(database: prepared.db, writer: prepared.writer,
                clockEpoch: prepared.clock, maximumRequests: 10, maximumRetainedBytes: 65536,
                requestLimits: prepared.limits, captureLimits: prepared.limits, decisionLimits: prepared.limits,
                signingLimits: prepared.limits, auditLimits: prepared.limits)
        }
        prepared.commits = nil; data = prepared; owner = coordinator
    }
    deinit { owner.close() }
    func checkHost(_ tx: JournalTransaction) throws {
        let trust = try tx.approvalTrustSnapshot()
        guard trust.macID == data.macID, trust.accountID == data.accountID, try tx.codePolicy() != nil else { throw Fault.injected }
    }
    func status() throws -> UpdateSchedulingIntent {
        let peer = try data.binding()
        return try data.withCandidate { try owner.observeUpdateScheduling(candidate: $0, binding: peer, verifyHost: checkHost) }
    }
    func issue(_ action: UpdateSchedulingAction, nonce: Data? = nil, binding: AuthorityPeerBinding? = nil,
        now: (() throws -> AuthorityMoment)? = nil, verifyHost: ((JournalTransaction) throws -> Void)? = nil,
        sign: ((Data) throws -> Data)? = nil) throws -> RootUpdateSchedulingReply {
        let snapshot = try XCTUnwrap(data.db.read { try $0.updateSchedulingIntent() }).snapshot
        let peer = try binding ?? data.binding()
        return try data.withCandidate {
            try owner.issueUpdateSchedulingChallenge(candidate: $0, queryNonce: nonce ?? self.nonce, action: action,
                expected: snapshot, binding: peer, authorityPublicKey: data.rootKey.publicKey.x963Representation,
                verifyHost: verifyHost ?? checkHost, now: now ?? data.nextNow, wall: { 1000 },
                sign: sign ?? { try self.data.rootKey.signature(for: $0).rawRepresentation })
        }
    }
    func control() throws -> UpdateSchedulingControl {
        let reply = try issue(.deferUpdate)
        return try UpdateSchedulingControl.decode(RootUpdateSchedulingChallenge.decode(reply.canonicalChallenge,
            limits: data.limits).canonicalControl, limits: data.limits)
    }
    func consume(_ control: UpdateSchedulingControl, now: (() throws -> AuthorityMoment)? = nil,
        verifyHost: ((JournalTransaction) throws -> Void)? = nil) throws -> UpdateSchedulingIntent {
        let peer = try data.binding(), bytes = try control.encode(limits: data.limits), signature = try data.sign(control)
        return try data.withCandidate {
            try owner.consumeUpdateScheduling(candidate: $0, canonicalControl: bytes, signature: signature,
                binding: peer, verifyHost: verifyHost ?? checkHost, now: now ?? data.nextNow, wall: { 1500 })
        }
    }
}
