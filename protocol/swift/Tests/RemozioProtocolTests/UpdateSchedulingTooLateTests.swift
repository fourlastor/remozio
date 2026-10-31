import Foundation
import XCTest
@testable import RemozioProtocol

private struct TooLateMutation: Decodable { let name: String; let hex: String }
private struct TooLateRow: Decodable {
    let name: String; let hex: String; let request: String?; let requestDigest: String?
    let signature: String; let signingInput: String
    let wrongProgressDomainSignature: String?; let wrongStatusDomainSignature: String?; let wrongControlDomainSignature: String?
    let mutations: [TooLateMutation]?
}
private struct TooLateVectors: Decodable {
    let publicKey: String; let otherPublicKey: String; let valid: [TooLateRow]; let invalid: [TooLateRow]
}
private func tooLateHex(_ text: String) -> Data {
    Data(stride(from: 0, to: text.count, by: 2).map {
        let start = text.index(text.startIndex, offsetBy: $0)
        return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
    })
}
final class UpdateSchedulingTooLateTests: XCTestCase {
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 2, maxItems: 32) } }
    private func vectors() throws -> TooLateVectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(TooLateVectors.self, from: Data(contentsOf:
            root.appendingPathComponent("vectors/update-scheduling-too-late-v1.json")))
    }
    private func verify(_ signature: Data, key: Data, payload: Data) throws -> Bool {
        try UpdateSchedulingTooLateSignature.verify(signature: signature, authorityPublicKey: key,
            wireVersion: 1, canonicalPayload: payload, inputLimits: limits)
    }
    func testSharedVectorsBindTheExactRequestProgressAndRootSignature() throws {
        let data = try vectors(); XCTAssertEqual(data.valid.count, 8)
        for row in data.valid {
            let payload = tooLateHex(row.hex), request = try PhoneUpdateSchedulingFrame.decode(tooLateHex(row.request!))
            let value = try UpdateSchedulingTooLateResponse.decode(payload)
            XCTAssertEqual(try value.encode(), payload)
            XCTAssertEqual(try UpdateSchedulingTooLateResponse(request: request, progress: value.progress), value)
            XCTAssertEqual(try UpdateSchedulingTooLateResponse.digest(request), tooLateHex(row.requestDigest!))
            XCTAssertTrue(try value.matches(request: request, expectedScope: value.progress.status.scope))
            XCTAssertEqual(try UpdateSchedulingTooLateSigningInput.make(wireVersion: 1, canonicalPayload: payload,
                inputLimits: limits), tooLateHex(row.signingInput))
            XCTAssertTrue(try verify(tooLateHex(row.signature), key: tooLateHex(data.publicKey), payload: payload))
            XCTAssertTrue(value.progress.phase.irreversible); XCTAssertTrue(value.progress.availableActions.isEmpty)
            XCTAssertNil(value.progress.status.controlDigest)
        }
    }
    func testValidSignaturesCannotMakeMalformedReversibleOrAcknowledgmentPayloadsValid() throws {
        let data = try vectors(); XCTAssertEqual(data.invalid.count, 19)
        for row in data.invalid {
            let bytes = tooLateHex(row.hex)
            XCTAssertTrue(P256Verification.verify(signature: tooLateHex(row.signature), publicKey: tooLateHex(data.publicKey),
                input: tooLateHex(row.signingInput)), row.name)
            XCTAssertThrowsError(try UpdateSchedulingTooLateResponse.decode(bytes), row.name)
            XCTAssertThrowsError(try verify(tooLateHex(row.signature), key: tooLateHex(data.publicKey), payload: bytes), row.name)
        }
    }
    func testSignaturesBindEveryFieldAndCannotCrossAnyExistingSchedulingDomain() throws {
        let data = try vectors(), key = tooLateHex(data.publicKey)
        for row in data.valid {
            let bytes = tooLateHex(row.hex), signature = tooLateHex(row.signature)
            XCTAssertFalse(try verify(signature, key: tooLateHex(data.otherPublicKey), payload: bytes))
            for wrong in [row.wrongProgressDomainSignature, row.wrongStatusDomainSignature, row.wrongControlDomainSignature] {
                XCTAssertFalse(try verify(tooLateHex(wrong!), key: key, payload: bytes))
            }
            for mutation in row.mutations! {
                let changed = tooLateHex(mutation.hex); _ = try UpdateSchedulingTooLateResponse.decode(changed)
                XCTAssertFalse(try verify(signature, key: key, payload: changed), mutation.name)
            }
        }
    }
    func testAnotherScopeNonceActionRevisionOrCandidateCannotReuseTheReply() throws {
        let row = try vectors().valid.first { $0.name.hasSuffix("challenge") }!
        let value = try UpdateSchedulingTooLateResponse.decode(tooLateHex(row.hex))
        guard case let .challenge(nonce, update, generation, revision, action) = try PhoneUpdateSchedulingFrame.decode(tooLateHex(row.request!)) else {
            return XCTFail("Missing challenge")
        }
        let scope = value.progress.status.scope
        let other = try ChannelScope(macID: Data(repeating: 99, count: 16), accountID: scope.accountID,
            phoneID: scope.phoneID, enrollmentEpoch: scope.enrollmentEpoch)
        XCTAssertFalse(try value.matches(request: .challenge(queryNonce: nonce, updateID: update, generation: generation,
            revision: revision, action: action), expectedScope: other))
        for changed in [PhoneUpdateSchedulingFrame.challenge(queryNonce: Data(repeating: 99, count: 32), updateID: update,
                generation: generation, revision: revision, action: action),
            .challenge(queryNonce: nonce, updateID: update, generation: generation, revision: revision + 1, action: action),
            .challenge(queryNonce: nonce, updateID: update, generation: generation, revision: revision, action: .deferUpdate),
            .challenge(queryNonce: nonce, updateID: Data(repeating: 99, count: 32), generation: generation, revision: revision, action: action),
            .challenge(queryNonce: nonce, updateID: update, generation: generation + 1, revision: revision, action: action)] {
            XCTAssertFalse(try value.matches(request: changed, expectedScope: scope))
        }
        XCTAssertThrowsError(try UpdateSchedulingTooLateResponse(request: .challenge(queryNonce: nonce,
            updateID: update, generation: generation + 1, revision: revision, action: action), progress: value.progress))
    }
    func testApplySignatureAndCapturedPhoneRemainPartOfTheRejectedRequest() throws {
        let row = try vectors().valid.first { $0.name.hasSuffix("apply") }!
        let value = try UpdateSchedulingTooLateResponse.decode(tooLateHex(row.hex))
        guard case let .apply(nonce, control, signature) = try PhoneUpdateSchedulingFrame.decode(tooLateHex(row.request!)) else {
            return XCTFail("Missing apply")
        }
        var changedSignature = signature; changedSignature[0] ^= 1
        XCTAssertFalse(try value.matches(request: .apply(queryNonce: nonce, canonicalControl: control, signature: changedSignature),
            expectedScope: value.progress.status.scope))
        let bounds = try CBORLimits(maxBytes: 1024, maxDepth: 2, maxItems: 32)
        guard case var .map(fields) = try DeterministicCBOR.decode(control, limits: bounds) else { return XCTFail("Missing control") }
        fields[3] = .bytes(Data(repeating: 99, count: 16))
        let wrong = PhoneUpdateSchedulingFrame.apply(queryNonce: nonce,
            canonicalControl: try DeterministicCBOR.encode(.map(fields), limits: bounds), signature: signature)
        XCTAssertThrowsError(try UpdateSchedulingTooLateResponse(request: wrong, progress: value.progress))
    }
    func testStatusAndResponseFramesCannotMasqueradeAsRejectedActions() throws {
        let row = try vectors().valid[0], value = try UpdateSchedulingTooLateResponse.decode(tooLateHex(row.hex))
        for frame in [PhoneUpdateSchedulingFrame.status(queryNonce: value.progress.status.queryNonce),
                      .failure(queryNonce: value.progress.status.queryNonce, reason: .unavailable)] {
            XCTAssertThrowsError(try UpdateSchedulingTooLateResponse.digest(frame))
            XCTAssertThrowsError(try UpdateSchedulingTooLateResponse(request: frame, progress: value.progress))
        }
        XCTAssertThrowsError(try UpdateSchedulingStatusResponse.decode(tooLateHex(row.hex)))
        XCTAssertThrowsError(try UpdateSchedulingProgressResponse.decode(tooLateHex(row.hex)))
    }
    func testVersionResourceAndSignatureBoundsRemainStrict() throws {
        let data = try vectors(), row = data.valid[0], bytes = tooLateHex(row.hex), key = tooLateHex(data.publicKey)
        for version: UInt64 in [0, 2, .max] {
            XCTAssertThrowsError(try UpdateSchedulingTooLateSigningInput.make(wireVersion: version,
                canonicalPayload: bytes, inputLimits: limits))
        }
        XCTAssertThrowsError(try UpdateSchedulingTooLateResponse.decode(Data(count: 8193)))
        let size = try UpdateSchedulingTooLateSigningInput.make(wireVersion: 1, canonicalPayload: bytes, inputLimits: limits).count
        XCTAssertThrowsError(try UpdateSchedulingTooLateSigningInput.make(wireVersion: 1, canonicalPayload: bytes,
            inputLimits: CBORLimits(maxBytes: size - 1, maxDepth: 2, maxItems: 32)))
        for count in [0, 63, 65] { XCTAssertFalse(try verify(Data(count: count), key: key, payload: bytes)) }
    }
    func testValueCopiesAndDescriptionsDoNotExposeOrReplaceCapturedEvidence() throws {
        let row = try vectors().valid[0], bytes = tooLateHex(row.hex)
        let value = try UpdateSchedulingTooLateResponse.decode(bytes)
        var copy = value.requestDigest; copy[0] ^= 1
        XCTAssertNotEqual(copy, value.requestDigest); XCTAssertEqual(try value.encode(), bytes)
        XCTAssertEqual(value.description, "UpdateSchedulingTooLateResponse(redacted)")
        XCTAssertEqual(value.debugDescription, value.description)
    }
}
