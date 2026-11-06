import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Correlation checks only. Root and phone signature checks have separate tests.
final class AuthorityPhoneUpdateSchedulingExchangeTests: XCTestCase {
    private func binding(account: UInt8 = 2) throws -> AuthorityPeerBinding {
        try .init(scope: ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: account, count: 16),
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
    }
    private func query(_ n: UInt8 = 5) -> PhoneUpdateSchedulingFrame { .status(queryNonce: Data(repeating: n, count: 32)) }
    private func control(_ peer: AuthorityPeerBinding, revision: UInt64 = 0,
                         action: UpdateSchedulingAction = .deferUpdate) throws -> Data {
        try UpdateSchedulingControl(macID: peer.scope.macID, accountID: peer.scope.accountID,
            phoneID: peer.scope.phoneID, enrollmentEpoch: peer.scope.enrollmentEpoch, operationID: Data(repeating: 7, count: 16),
            challenge: Data(repeating: 8, count: 32), keyID: Data(repeating: 9, count: 16), updateID: Data(repeating: 6, count: 32),
            expectedGeneration: 1, expectedRevision: revision, issuedAtUnixMillis: 100, expiresAtUnixMillis: 200,
            action: action).encode(limits: AuthorityPhoneUpdateSchedulingExchange.limits)
    }
    func testChallengeReplyMustMatchTheRequestedActionAndCurrentSnapshot() throws {
        let peer = try binding(), bytes = try control(peer), nonce = query().queryNonce
        let payload = try RootUpdateSchedulingChallenge(queryNonce: nonce, canonicalControl: bytes,
            limits: AuthorityPhoneUpdateSchedulingExchange.limits).encode(limits: AuthorityPhoneUpdateSchedulingExchange.limits)
        let response = PhoneUpdateSchedulingFrame.challengeResponse(queryNonce: nonce, canonicalPayload: payload, signature: Data(count: 64))
        let requests: [PhoneUpdateSchedulingFrame] = [.challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32), generation: 1, revision: 0, action: .deferUpdate),
            .challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32), generation: 1, revision: 0, action: .cancelDrain),
            .challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32), generation: 2, revision: 0, action: .deferUpdate),
            .challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32), generation: 1, revision: 1, action: .deferUpdate),
            .challenge(queryNonce: nonce, updateID: Data(repeating: 10, count: 32), generation: 1, revision: 0, action: .deferUpdate)]
        for (index, request) in requests.enumerated() {
            if index == 0 { XCTAssertNoThrow(try AuthorityPhoneUpdateSchedulingExchange.response(response, to: request, binding: peer)) }
            else { XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(response, to: request, binding: peer)) }
        }
    }
    func testAcceptedReceiptBindsDigestGenerationActionAndNextRevisionWithoutOverflow() throws {
        let peer = try binding(), nonce = query().queryNonce, bytes = try control(peer), digest = Data(SHA256.hash(data: bytes))
        let request = PhoneUpdateSchedulingFrame.apply(queryNonce: nonce, canonicalControl: bytes, signature: Data(count: 64))
        let values: [(Data, UInt64, UInt64, UpdateSchedulingAction, Data)] = [
            (Data(repeating: 6, count: 32), 1, 1, .deferUpdate, digest),
            (Data(repeating: 6, count: 32), 2, 1, .deferUpdate, digest),
            (Data(repeating: 6, count: 32), 1, 2, .deferUpdate, digest),
            (Data(repeating: 6, count: 32), 1, 1, .cancelDrain, digest),
            (Data(repeating: 10, count: 32), 1, 1, .deferUpdate, digest),
            (Data(repeating: 6, count: 32), 1, 1, .deferUpdate, Data(count: 32))]
        for (index, value) in values.enumerated() {
            let payload = try UpdateSchedulingStatusResponse(scope: peer.scope, queryNonce: nonce, updateID: value.0,
                generation: value.1, revision: value.2, requestedAction: value.3, controlDigest: value.4).encode()
            let response = PhoneUpdateSchedulingFrame.stateResponse(queryNonce: nonce, canonicalPayload: payload, signature: Data(count: 64))
            if index == 0 { XCTAssertNoThrow(try AuthorityPhoneUpdateSchedulingExchange.response(response, to: request, binding: peer)) }
            else { XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(response, to: request, binding: peer)) }
        }
        // A wrapped receipt for an exhausted revision cannot be encoded: revision 0 carries no action and no digest.
        // The overflow guard in the exchange is a second barrier, and an unwrapped revision-0 status fails the digest check.
        let exhaustedBytes = try control(peer, revision: .max), exhaustedDigest = Data(SHA256.hash(data: exhaustedBytes))
        XCTAssertThrowsError(try UpdateSchedulingStatusResponse(scope: peer.scope, queryNonce: nonce, updateID: Data(repeating: 6, count: 32),
            generation: 1, revision: 0, requestedAction: .deferUpdate, controlDigest: exhaustedDigest))
        let exhausted = PhoneUpdateSchedulingFrame.apply(queryNonce: nonce, canonicalControl: exhaustedBytes, signature: Data(count: 64))
        let wrapped = try UpdateSchedulingStatusResponse(scope: peer.scope, queryNonce: nonce, updateID: Data(repeating: 6, count: 32),
            generation: 1, revision: 0, requestedAction: nil, controlDigest: nil).encode()
        XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(.stateResponse(queryNonce: nonce, canonicalPayload: wrapped,
            signature: Data(count: 64)), to: exhausted, binding: peer))
    }
    func testStatusReplyMustUseTheRequestNonceScopeAndNoControlDigest() throws {
        let peer = try binding(), other = try binding(account: 9), request = query(), nonce = request.queryNonce
        func reply(_ scope: ChannelScope, nonce replyNonce: Data, revision: UInt64 = 0, digest: Data? = nil) throws -> PhoneUpdateSchedulingFrame {
            let payload = try UpdateSchedulingStatusResponse(scope: scope, queryNonce: replyNonce, updateID: Data(repeating: 6, count: 32),
                generation: 1, revision: revision, requestedAction: revision == 0 ? nil : .deferUpdate, controlDigest: digest).encode()
            return .stateResponse(queryNonce: replyNonce, canonicalPayload: payload, signature: Data(count: 64))
        }
        XCTAssertNoThrow(try AuthorityPhoneUpdateSchedulingExchange.response(reply(peer.scope, nonce: nonce), to: request, binding: peer))
        XCTAssertNoThrow(try AuthorityPhoneUpdateSchedulingExchange.response(reply(peer.scope, nonce: nonce, revision: 1),
            to: request, binding: peer))
        XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(reply(other.scope, nonce: nonce), to: request, binding: peer))
        XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(reply(peer.scope, nonce: nonce, revision: 1,
            digest: Data(repeating: 11, count: 32)), to: request, binding: peer))
        XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(reply(peer.scope, nonce: query(12).queryNonce),
            to: request, binding: peer))
    }
    func testChallengeOrApplyNamingAnotherAccountIsRefused() throws {
        let peer = try binding(), foreign = try binding(account: 9), nonce = query().queryNonce, bytes = try control(foreign)
        let payload = try RootUpdateSchedulingChallenge(queryNonce: nonce, canonicalControl: bytes,
            limits: AuthorityPhoneUpdateSchedulingExchange.limits).encode(limits: AuthorityPhoneUpdateSchedulingExchange.limits)
        let response = PhoneUpdateSchedulingFrame.challengeResponse(queryNonce: nonce, canonicalPayload: payload, signature: Data(count: 64))
        let request = PhoneUpdateSchedulingFrame.challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32),
            generation: 1, revision: 0, action: .deferUpdate)
        XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(response, to: request, binding: peer))
        XCTAssertNoThrow(try AuthorityPhoneUpdateSchedulingExchange.response(response, to: request, binding: foreign))
        XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.request(.apply(queryNonce: nonce, canonicalControl: bytes,
            signature: Data(count: 64)), binding: peer))
    }
    func testAFailureReplyPassesOnlyWithTheRequestNonce() throws {
        let peer = try binding(), nonce = query().queryNonce, bytes = try control(peer)
        let requests: [PhoneUpdateSchedulingFrame] = [.status(queryNonce: nonce),
            .challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32), generation: 1, revision: 0, action: .deferUpdate),
            .apply(queryNonce: nonce, canonicalControl: bytes, signature: Data(count: 64))]
        for request in requests {
            XCTAssertNoThrow(try AuthorityPhoneUpdateSchedulingExchange.response(.failure(queryNonce: nonce, reason: .unavailable),
                to: request, binding: peer))
            XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(.failure(queryNonce: query(12).queryNonce,
                reason: .unavailable), to: request, binding: peer))
        }
    }
}
