import CryptoKit
import Foundation
import Synchronization
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class PairingSetupNetworkSessionTests: XCTestCase {
    private struct Fixture {
        let transport = P256.Signing.PrivateKey(), decision = P256.Signing.PrivateKey(), biometric = P256.Signing.PrivateKey()
        let authority = P256.Signing.PrivateKey(), macTransport = P256.Signing.PrivateKey()
        let proposal: PairingPhoneProposal
        let transcript: PairingTranscript
        let invitation: PairingInvitation
        init() throws {
            let scope = try ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
            let phone = try ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: 5, count: 32),
                envelopeVersions: [1], requests: [], auditVersions: [])
            let mac = try ChannelOffer(role: .mac, scope: scope, nonce: Data(repeating: 6, count: 32),
                envelopeVersions: [1], requests: [], auditVersions: [])
            proposal = try .init(phone: phone, transportKey: .init(keyID: Data(repeating: 7, count: 16), publicKey: transport.publicKey.x963Representation),
                decisionKey: .init(keyID: Data(repeating: 8, count: 16), publicKey: decision.publicKey.x963Representation),
                biometricKey: .init(keyID: Data(repeating: 9, count: 16), publicKey: biometric.publicKey.x963Representation))
            transcript = try .init(setupID: Data(repeating: 10, count: 16), challenge: Data(repeating: 11, count: 32), phone: phone, mac: mac,
                minimumEnvelopeVersion: 1, selectedEnvelopeVersion: 1, macAuthorityKey: authority.publicKey.x963Representation,
                macTransportKey: macTransport.publicKey.x963Representation, transportKey: proposal.transportKey,
                decisionKey: proposal.decisionKey, biometricKey: proposal.biometricKey, enrollmentTag: Data(repeating: 12, count: 32),
                replacement: nil, expectedTrustRevision: Data(repeating: 13, count: 16), issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000)
            invitation = try .init(macID: scope.macID, accountID: scope.accountID, label: "Fixture",
                authorityPublicKey: authority.publicKey.x963Representation, transportPublicKey: macTransport.publicKey.x963Representation,
                minimumEnvelopeVersion: 1)
        }
        func proof() throws -> Data { try biometric.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation }
        func receipt() throws -> Data { try authority.signature(for: transcript.signingInput(purpose: .macCommit)).rawRepresentation }
        func proofFrame() throws -> PairingSetupFrame { try .proof(setupID: transcript.setupID, digest: transcript.digest(), signature: proof()) }
    }
    private func wire(_ frame: PairingSetupFrame) throws -> Data {
        try wire(frame.encode())
    }
    private func wire(_ bytes: Data) -> Data {
        let n = UInt32(bytes.count)
        return Data([UInt8(n >> 24), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)]) + bytes
    }
    private actor Stream: ApprovalByteStream {
        var input: [Data]
        var output = Data()
        var closes = 0
        var waiting: CheckedContinuation<Data?, any Error>?
        var isWaiting: Bool { waiting != nil }
        init(_ input: [Data]) { self.input = input }
        func awaitOpen(timeoutMilliseconds: UInt64) async throws {}
        func send(_ bytes: Data) async throws { output.append(bytes) }
        func receive() async throws -> Data? {
            guard closes == 0 else { return nil }
            if !input.isEmpty { return input.removeFirst() }
            return try await withCheckedThrowingContinuation { waiting = $0 }
        }
        func close() async { closes += 1; let old = waiting; waiting = nil; old?.resume(returning: nil) }
        func frames() throws -> [PairingSetupFrame] {
            var result: [PairingSetupFrame] = [], offset = 0
            while offset < output.count {
                let n = output[offset..<offset + 4].reduce(0) { ($0 << 8) | Int($1) }
                result.append(try .decode(output.subdata(in: offset + 4..<offset + 4 + n))); offset += n + 4
            }
            return result
        }
    }
    private func accept(_ stream: Stream, _ f: Fixture, peer: Data? = nil, timeout: UInt64 = 300000) async throws -> PairingSetupNetworkSession {
        try await .accept(stream: stream, invitation: f.invitation, peerPoint: peer ?? f.transport.publicKey.x963Representation,
            timeoutMilliseconds: timeout)
    }
    func testSingleByteAndCoalescedFramesVerifyOneProofAndReceipt() async throws {
        for fragment in [true, false] {
            let f = try Fixture(), bytes = try wire(.proposal(f.proposal)) + wire(f.proofFrame())
            let stream = Stream(fragment ? bytes.map { Data([$0]) } : [bytes])
            let session = try await accept(stream, f)
            let proposed = try await session.proposal()
            XCTAssertEqual(try proposed.encode(), try f.proposal.encode())
            try await session.stage(f.transcript)
            let proof = try await session.receiveProof()
            XCTAssertTrue(try f.transcript.verify(signature: proof, publicKey: f.biometric.publicKey.x963Representation, purpose: .phoneBiometric))
            try await session.sendReceipt(f.receipt())
            let frames = try await stream.frames(); XCTAssertEqual(frames.count, 3)
            guard case .hello = frames[0], case .transcript(let staged) = frames[1], case .receipt(let id, let digest, let receipt) = frames[2] else { return XCTFail() }
            XCTAssertEqual(try staged.encode(), try f.transcript.encode()); XCTAssertEqual(id, f.transcript.setupID)
            XCTAssertEqual(digest, try f.transcript.digest())
            XCTAssertTrue(try f.transcript.verify(signature: receipt, publicKey: f.authority.publicKey.x963Representation, purpose: .macCommit))
            do { _ = try await session.receiveProof(); XCTFail() } catch {}
            await session.close(); await session.close()
            let closes = await stream.closes; XCTAssertEqual(closes, 1)
        }
    }
    func testWrongTLSKeyAndNonProposalFramesCannotEnterSetup() async throws {
        let f = try Fixture()
        for (frame, peer) in [(PairingSetupFrame.proposal(f.proposal), f.decision.publicKey.x963Representation),
                              (.hello, f.transport.publicKey.x963Representation), (try f.proofFrame(), f.transport.publicKey.x963Representation)] {
            let stream = Stream([try wire(frame)])
            do { _ = try await accept(stream, f, peer: peer); XCTFail() } catch {}
            let closes = await stream.closes; XCTAssertEqual(closes, 1)
        }
    }
    func testCrossedOrInvalidProofNeverEmitsAReceipt() async throws {
        let f = try Fixture()
        let invalid: [PairingSetupFrame] = [try .proof(setupID: Data(repeating: 99, count: 16), digest: f.transcript.digest(), signature: f.proof()),
            try .proof(setupID: f.transcript.setupID, digest: Data(count: 32), signature: f.proof()),
            try .proof(setupID: f.transcript.setupID, digest: f.transcript.digest(), signature: Data(count: 64))]
        for frame in invalid {
            let stream = Stream([try wire(.proposal(f.proposal)), try wire(frame)])
            let session = try await accept(stream, f); try await session.stage(f.transcript)
            do { _ = try await session.receiveProof(); XCTFail() } catch {}
            do { try await session.sendReceipt(f.receipt()); XCTFail() } catch {}
            let frames = try await stream.frames(); XCTAssertEqual(frames.count, 2)
        }
    }
    func testWrongReceiptPurposeCannotFinishSetup() async throws {
        let f = try Fixture(), stream = Stream([try wire(.proposal(f.proposal)), try wire(f.proofFrame())])
        let session = try await accept(stream, f); try await session.stage(f.transcript); _ = try await session.receiveProof()
        let signature = try f.authority.signature(for: f.transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation
        do { try await session.sendReceipt(signature); XCTFail() } catch {}
        let frames = try await stream.frames(); XCTAssertEqual(frames.count, 2)
    }
    func testCancelAndElapsedDeadlineCloseSuspendedReads() async throws {
        for timeout in [UInt64(500), 300000] {
            let f = try Fixture(), stream = Stream([try wire(.proposal(f.proposal))]), aborted = Mutex(0)
            let session = try await PairingSetupNetworkSession.accept(stream: stream, invitation: f.invitation,
                peerPoint: f.transport.publicKey.x963Representation, timeoutMilliseconds: timeout,
                abortIO: { aborted.withLock { $0 += 1 } })
            try await session.stage(f.transcript)
            let receive = Task { try await session.receiveProof() }
            if timeout == 300000 {
                let deadline = ContinuousClock.now.advanced(by: .seconds(2))
                while !(await stream.isWaiting), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(5)) }
                session.abort()
            }
            do { _ = try await receive.value; XCTFail() } catch {}
            XCTAssertGreaterThan(aborted.withLock { $0 }, 0)
            await session.close(); let closes = await stream.closes; XCTAssertEqual(closes, 1)
        }
    }

    private func setupV2(_ fixture: Fixture, proposal: PairingPhoneProposal? = nil) throws
        -> (AuthorityPairingV2Window, AuthorityMoment, PairingSetupV2Connection, PairingSetupPreludeV2) {
        let invitation = try PairingInvitationV2(invitation: fixture.invitation, windowID: Data(repeating: 14, count: 16),
            secret: Data(repeating: 15, count: 32), lifetimeMilliseconds: 120_000)
        let start = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        let window = try AuthorityPairingV2Window(invitation: invitation, predecessor: nil, started: start)
        let challenge = Data(repeating: 16, count: 32), exporter = Data(repeating: 17, count: 32)
        let proposal = proposal ?? fixture.proposal
        let tag = try invitation.proof(proposal: proposal, challenge: challenge, exporter: exporter)
        let context = PairingSetupV2Connection(windowID: invitation.windowID, connection: UUID(),
            challenge: challenge, exporter: exporter,
            reserve: { try window.reserve($0, at: start) })
        return (window, start, context, .proposal(proposal, tag: tag))
    }

    func testRejectedConfirmationAfterVerificationRetiresTheLink() async throws {
        let f = try Fixture(), calls = Mutex<[String]>([])
        let challenge = Data(repeating: 16, count: 32)
        let context = PairingSetupV2Connection(connection: UUID(), challenge: challenge,
            publicationDeadline: ContinuousClock.now.advanced(by: .seconds(3)),
            verify: { _, _, _ in calls.withLock { $0.append("verify") } },
            confirm: {
                calls.withLock { $0.append("confirm") }
                throw PairingSetupChannelError.rejected
            }, invalidateLink: { calls.withLock { $0.append("retire") } }, retire: { _ in })
        let proposal = PairingSetupPreludeV2.proposal(f.proposal, tag: Data(repeating: 17, count: 32))
        do {
            _ = try await PairingSetupNetworkSession.accept(stream: Stream([wire(proposal.encode())]),
                invitation: f.invitation, peerPoint: f.transport.publicKey.x963Representation, v2: context)
            XCTFail("A rejected confirmation published a candidate")
        } catch PairingSetupChannelError.rejected {}
        XCTAssertEqual(calls.withLock { $0 }, ["verify", "confirm", "retire"])
    }

    func testConfirmedProofPastThePublicationDeadlineRetiresTheLink() async throws {
        let f = try Fixture(), calls = Mutex<[String]>([])
        let challenge = Data(repeating: 16, count: 32)
        let context = PairingSetupV2Connection(connection: UUID(), challenge: challenge,
            publicationDeadline: ContinuousClock.now.advanced(by: .milliseconds(-1)),
            verify: { _, _, _ in calls.withLock { $0.append("verify") } },
            confirm: { calls.withLock { $0.append("confirm") } },
            invalidateLink: { calls.withLock { $0.append("retire") } }, retire: { _ in })
        let proposal = PairingSetupPreludeV2.proposal(f.proposal, tag: Data(repeating: 17, count: 32))
        do {
            _ = try await PairingSetupNetworkSession.accept(stream: Stream([wire(proposal.encode())]),
                invitation: f.invitation, peerPoint: f.transport.publicKey.x963Representation, v2: context)
            XCTFail("An expired proof was published")
        } catch PairingSetupChannelError.rejected {}
        XCTAssertEqual(calls.withLock { $0 }, ["verify", "confirm", "retire"])
    }

    func testV2ChallengeAndProvedProposalReplaceTheLegacyPrelude() async throws {
        let f = try Fixture()
        let (window, moment, context, proposal) = try setupV2(f)
        let stream = Stream([try wire(proposal.encode()), try wire(f.proofFrame())])
        let session = try await PairingSetupNetworkSession.accept(stream: stream, invitation: f.invitation,
            peerPoint: f.transport.publicKey.x963Representation, v2: context)
        let connection = await session.provedConnection
        XCTAssertEqual(connection, context.connection)
        let retained = try await session.proposal()
        XCTAssertEqual(try retained.encode(), try f.proposal.encode())
        XCTAssertEqual(try window.takeProposal(connection: context.connection, matching: retained.encode(), at: moment).encode(),
            try f.proposal.encode())
        let output = await stream.output
        XCTAssertEqual(output, try wire(PairingSetupPreludeV2.challenge(context.challenge).encode()))
        try await session.stage(f.transcript)
        let proof = try await session.receiveProof()
        XCTAssertTrue(try f.transcript.verify(signature: proof, publicKey: f.biometric.publicKey.x963Representation, purpose: .phoneBiometric))
        try await session.sendReceipt(f.receipt())
        await session.closeAndWait()
    }

    func testV2RefusesLegacyProposalAndCannotReplaceAProvedProposal() async throws {
        let f = try Fixture()
        let (_, _, context, proposal) = try setupV2(f)
        let legacy = try wire(PairingSetupFrame.proposal(f.proposal))
        let oldStream = Stream([legacy])
        do {
            _ = try await PairingSetupNetworkSession.accept(stream: oldStream, invitation: f.invitation,
                peerPoint: f.transport.publicKey.x963Representation, v2: context)
            XCTFail("Accepted a legacy proposal before proof")
        } catch PairingError.invalidTranscript {}
        let legacyCloses = await oldStream.closes
        XCTAssertEqual(legacyCloses, 1)

        let stream = Stream([try wire(proposal.encode()), legacy])
        let session = try await PairingSetupNetworkSession.accept(stream: stream, invitation: f.invitation,
            peerPoint: f.transport.publicKey.x963Representation, v2: context)
        try await session.stage(f.transcript)
        do {
            _ = try await session.receiveProof()
            XCTFail("Accepted a second proposal")
        } catch PairingSetupChannelError.rejected {}
        await session.closeAndWait()
        let closes = await stream.closes
        XCTAssertEqual(closes, 1)
    }
}
