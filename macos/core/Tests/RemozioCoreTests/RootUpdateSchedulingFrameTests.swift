import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RootUpdateSchedulingFrameTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 4096, maxDepth: 2, maxItems: 32)
    private func status(_ f: RootUpdateSchedulingFixture, nonce: Data, sign: ((Data) throws -> Data)? = nil) throws -> PhoneUpdateSchedulingFrame {
        let binding = try f.data.binding()
        return try f.data.withCandidate { candidate in
            try f.owner.updateSchedulingStateFrame(candidate: candidate, queryNonce: nonce, binding: binding,
                authorityPublicKey: f.data.rootKey.publicKey.x963Representation, verifyHost: f.checkHost,
                now: f.data.nextNow, wall: { 1000 }, sign: sign ?? { try f.data.rootKey.signature(for: $0).rawRepresentation })
        }
    }
    private func apply(_ f: RootUpdateSchedulingFixture, control: UpdateSchedulingControl, nonce: Data,
                       sign: ((Data) throws -> Data)? = nil) throws -> PhoneUpdateSchedulingFrame {
        let binding = try f.data.binding(), bytes = try control.encode(limits: f.data.limits), signature = try f.data.sign(control)
        return try f.data.withCandidate { candidate in
            try f.owner.consumeUpdateSchedulingFrame(candidate: candidate, queryNonce: nonce, canonicalControl: bytes,
                signature: signature, binding: binding, authorityPublicKey: f.data.rootKey.publicKey.x963Representation,
                verifyHost: f.checkHost, now: f.data.nextNow, wall: { 1500 },
                sign: sign ?? { try f.data.rootKey.signature(for: $0).rawRepresentation })
        }
    }
    func testStatusBindsTheQueryAndCurrentScopeWithoutChangingStorage() throws {
        let f = try RootUpdateSchedulingFixture(), nonce = Data(repeating: 51, count: 32), before = try f.data.store.read()
        guard case let .stateResponse(returnedNonce, bytes, signature) = try status(f, nonce: nonce) else { return XCTFail() }
        let state = try UpdateSchedulingStatusResponse.decode(bytes)
        XCTAssertEqual(returnedNonce, nonce); XCTAssertEqual(state.queryNonce, nonce)
        XCTAssertEqual(state.scope, try f.data.binding().scope); XCTAssertNil(state.controlDigest)
        XCTAssertTrue(try UpdateSchedulingStatusSignature.verify(signature: signature,
            authorityPublicKey: f.data.rootKey.publicKey.x963Representation, wireVersion: 1, canonicalPayload: bytes, inputLimits: limits))
        XCTAssertEqual(try f.data.store.read(), before)
    }
    func testAcceptedReplyBindsTheExactConsumedControlAndCommittedRevision() throws {
        let f = try RootUpdateSchedulingFixture(), control = try f.control(), nonce = Data(repeating: 52, count: 32)
        guard case let .stateResponse(returnedNonce, bytes, signature) = try apply(f, control: control, nonce: nonce) else { return XCTFail() }
        let state = try UpdateSchedulingStatusResponse.decode(bytes)
        XCTAssertEqual(returnedNonce, nonce); XCTAssertEqual(state.queryNonce, nonce)
        XCTAssertEqual(state.updateID, control.updateID); XCTAssertEqual(state.generation, control.expectedGeneration)
        XCTAssertEqual(state.revision, control.expectedRevision + 1); XCTAssertEqual(state.requestedAction, control.action)
        XCTAssertEqual(state.controlDigest, Data(SHA256.hash(data: try control.encode(limits: f.data.limits))))
        XCTAssertTrue(try UpdateSchedulingStatusSignature.verify(signature: signature,
            authorityPublicKey: f.data.rootKey.publicKey.x963Representation, wireVersion: 1, canonicalPayload: bytes, inputLimits: limits))
        XCTAssertNil(try f.data.store.read().pending)
        XCTAssertThrowsError(try apply(f, control: control, nonce: nonce))
    }
    func testFailedReceiptSigningReturnsNoReplyButPreservesTheCommittedConsumption() throws {
        let f = try RootUpdateSchedulingFixture(), control = try f.control(), nonce = Data(repeating: 53, count: 32)
        XCTAssertThrowsError(try apply(f, control: control, nonce: nonce, sign: { _ in Data(repeating: 0, count: 64) })) {
            XCTAssertEqual($0 as? UpdateSchedulingVerificationError, .invalidSignature)
        }
        XCTAssertEqual(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: control.operationID) }, 1)
        guard case let .stateResponse(_, bytes, _) = try status(f, nonce: nonce) else { return XCTFail() }
        let observed = try UpdateSchedulingStatusResponse.decode(bytes)
        XCTAssertEqual(observed.revision, 1); XCTAssertNil(observed.controlDigest)
        XCTAssertThrowsError(try apply(f, control: control, nonce: nonce))
    }
    func testMalformedReceiptNonceFailsBeforeConsumptionOrSigning() throws {
        let f = try RootUpdateSchedulingFixture(), control = try f.control(), before = try f.data.store.read()
        var signed = false
        XCTAssertThrowsError(try apply(f, control: control, nonce: Data(repeating: 1, count: 31), sign: { _ in signed = true; return Data() }))
        XCTAssertFalse(signed); XCTAssertEqual(try f.data.store.read(), before)
        XCTAssertNil(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: control.operationID) })
    }
    func testWrongRootSignatureCannotPublishAStatusObservation() throws {
        let f = try RootUpdateSchedulingFixture(), before = try f.data.store.read()
        XCTAssertThrowsError(try status(f, nonce: Data(repeating: 55, count: 32), sign: { _ in Data(repeating: 0, count: 64) }))
        XCTAssertEqual(try f.data.store.read(), before)
    }
}
