import Foundation
import XCTest
@testable import RemozioProtocol

final class PairingInvitationV2Tests: XCTestCase {
    private struct Vector: Decodable {
        let name: String
        let lifetimeMilliseconds: UInt64
        let invitation: String
        let text: String
        let proposal: String
        let proofInput: String
        let tag: String
        let transcript: String
        let proposalPrelude: String
    }

    private struct Recovery: Decodable {
        let exporter: String
        let challenge: String
        let lookup: String
        let signingInput: String
        let proof: String
        let committed: String
        let expired: String
        let expiryInput: String
    }

    private struct Invalid: Decodable { let name: String; let hex: String }
    private struct BonjourWindow: Decodable { let windowID: String; let name: String }

    private struct Vectors: Decodable {
        let challenge: String
        let exporter: String
        let valid: [Vector]
        let bonjourWindowNames: [BonjourWindow]
        let invalid: [Invalid]
        let challengePrelude: String
        let invalidPreludes: [String]
        let recovery: Recovery
    }

    private func vectors() throws -> Vectors {
        let protocolRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let vector = protocolRoot.appendingPathComponent("vectors/pairing-invitation-v2.json")
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: vector))
    }

    private func hex(_ value: String) -> Data {
        let text = Array(value.utf8)
        return Data(stride(from: 0, to: text.count, by: 2).map {
            UInt8(String(decoding: text[$0...($0 + 1)], as: UTF8.self), radix: 16)!
        })
    }

    func testInvitationAndProofInteroperateForBothSetupModes() throws {
        let values = try vectors()
        for row in values.valid {
            let invitation = try PairingInvitationV2.importText(row.text)
            let proposal = try PairingPhoneProposal.decode(hex(row.proposal))
            let challenge = hex(values.challenge), exporter = hex(values.exporter)
            let expected = hex(row.tag)
            XCTAssertEqual(try invitation.encode(), hex(row.invitation), row.name)
            XCTAssertEqual(try invitation.exportText(), row.text)
            XCTAssertEqual(invitation.lifetimeMilliseconds, row.lifetimeMilliseconds)
            XCTAssertEqual(invitation.replacement, proposal.replacement)
            XCTAssertEqual(try invitation.proofInput(proposal: proposal, challenge: challenge, exporter: exporter), hex(row.proofInput))
            XCTAssertEqual(try invitation.proof(proposal: proposal, challenge: challenge, exporter: exporter), expected)
            XCTAssertTrue(try invitation.verifiesProof(expected, proposal: proposal, challenge: challenge, exporter: exporter))
            let transcript = try PairingTranscript.decode(hex(row.transcript))
            try invitation.invitation.validateMacClaims(in: transcript)
            try proposal.validate(transcript)
            XCTAssertEqual(String(reflecting: invitation), "PairingInvitationV2(redacted)")
            XCTAssertTrue(invitation.customMirror.children.isEmpty)
        }
    }

    func testBonjourNameMatchesTheSharedVectorBeforeAndAfterExport() throws {
        let values = try vectors()
        let template = try PairingInvitationV2.importText(try XCTUnwrap(values.valid.first).text)
        var names = Set<String>()
        for row in values.bonjourWindowNames {
            let invitation = try PairingInvitationV2(invitation: template.invitation, windowID: hex(row.windowID),
                secret: Data(repeating: 2, count: 32), lifetimeMilliseconds: template.lifetimeMilliseconds)
            let imported = try PairingInvitationV2.importText(invitation.exportText())
            let expected = try PairingInvitationV2.bonjourInstanceName(windowID: invitation.windowID)
            XCTAssertEqual(expected, row.name)
            XCTAssertEqual(try PairingInvitationV2.bonjourInstanceName(windowID: imported.windowID), expected)
            XCTAssertTrue(names.insert(expected).inserted)
        }
        XCTAssertEqual(names.count, 2)
        XCTAssertThrowsError(try PairingInvitationV2.bonjourInstanceName(windowID: Data(count: 15)))
    }

    func testProofRejectsAnotherConnectionAndInvalidInputs() throws {
        let values = try vectors()
        let row = try XCTUnwrap(values.valid.first)
        let invitation = try PairingInvitationV2.importText(row.text)
        let proposal = try PairingPhoneProposal.decode(hex(row.proposal))
        let challenge = hex(values.challenge), exporter = hex(values.exporter), tag = hex(row.tag)
        var wrongTag = tag
        wrongTag[0] ^= 1
        XCTAssertFalse(try invitation.verifiesProof(wrongTag, proposal: proposal, challenge: challenge, exporter: exporter))
        XCTAssertFalse(try invitation.verifiesProof(Data(tag.dropLast()), proposal: proposal, challenge: challenge, exporter: exporter))
        XCTAssertFalse(try invitation.verifiesProof(tag, proposal: proposal, challenge: exporter, exporter: challenge))
        XCTAssertThrowsError(try invitation.proof(proposal: proposal, challenge: challenge, exporter: Data()))
        let wrongWindow = try PairingInvitationV2(invitation: invitation.invitation, windowID: Data(repeating: 1, count: 16),
            secret: Data(repeating: 2, count: 32), lifetimeMilliseconds: invitation.lifetimeMilliseconds)
        XCTAssertFalse(try wrongWindow.verifiesProof(tag, proposal: proposal, challenge: challenge, exporter: exporter))
        let replacementRow = try XCTUnwrap(values.valid.last)
        let replacement = try PairingPhoneProposal.decode(hex(replacementRow.proposal))
        XCTAssertThrowsError(try invitation.proof(proposal: replacement, challenge: challenge, exporter: exporter))
    }

    func testInvitationAndPreludeRejectMalformedAndLegacyInputs() throws {
        let values = try vectors()
        for row in values.invalid {
            XCTAssertThrowsError(try PairingInvitationV2.decode(hex(row.hex)), row.name)
        }
        let row = try XCTUnwrap(values.valid.first)
        let invitation = try PairingInvitationV2.importText(row.text)
        XCTAssertThrowsError(try PairingInvitationV2.importText(invitation.invitation.exportText()))
        XCTAssertThrowsError(try PairingInvitationV2.importText(row.text + "="))
        XCTAssertThrowsError(try PairingInvitationV2.importText(row.text + " "))
        XCTAssertThrowsError(try PairingInvitationV2.decode(Data(count: PairingInvitationV2.maximumBytes + 1)))

        let challenge = hex(values.challengePrelude)
        guard case .challenge(let value) = try PairingSetupPreludeV2.decode(challenge) else { return XCTFail() }
        XCTAssertEqual(value, hex(values.challenge))
        XCTAssertEqual(try PairingSetupPreludeV2.challenge(value).encode(), challenge)
        for row in values.valid {
            let data = hex(row.proposalPrelude)
            guard case .proposal(let proposal, let tag) = try PairingSetupPreludeV2.decode(data) else { return XCTFail(row.name) }
            XCTAssertEqual(try proposal.encode(), hex(row.proposal))
            XCTAssertEqual(tag, hex(row.tag))
            XCTAssertEqual(try PairingSetupPreludeV2.proposal(proposal, tag: tag).encode(), data)
        }
        for prelude in values.invalidPreludes {
            XCTAssertThrowsError(try PairingSetupPreludeV2.decode(hex(prelude)))
        }
    }

    func testV2SetupRetainsRecoveryAndSignedExpirySemantics() throws {
        let values = try vectors()
        let row = try XCTUnwrap(values.valid.last)
        let proposal = try PairingPhoneProposal.decode(hex(row.proposal))
        let transcript = try PairingTranscript.decode(hex(row.transcript))
        try proposal.validate(transcript)
        let recovery = values.recovery
        guard case .lookup(let query) = try PairingRecoveryFrame.decode(hex(recovery.lookup)),
              case .proof(let proof) = try PairingRecoveryFrame.decode(hex(recovery.proof)),
              case .committed(let signature) = try PairingRecoveryFrame.decode(hex(recovery.committed)),
              case .expired(let receipt) = try PairingRecoveryFrame.decode(hex(recovery.expired)) else { return XCTFail() }
        XCTAssertEqual(query.setupID, transcript.setupID)
        XCTAssertEqual(query.scope, transcript.phone.scope)
        XCTAssertEqual(query.transcriptDigest, try transcript.digest())
        let input = try query.signingInput(exporter: hex(recovery.exporter), challenge: hex(recovery.challenge))
        XCTAssertEqual(input, hex(recovery.signingInput))
        XCTAssertTrue(P256Verification.verify(signature: proof, publicKey: transcript.transportKey.publicKey, input: input))
        XCTAssertTrue(try transcript.verify(signature: signature, publicKey: transcript.macAuthorityKey, purpose: .macCommit))
        XCTAssertTrue(try receipt.verify(transcript: transcript))
        XCTAssertEqual(try PairingExpiryReceipt.signingInput(transcript: transcript, reason: .deadlineElapsed), hex(recovery.expiryInput))
        let other = try PairingTranscript.decode(hex(try XCTUnwrap(values.valid.first).transcript))
        XCTAssertFalse(try receipt.verify(transcript: other))
    }
}
