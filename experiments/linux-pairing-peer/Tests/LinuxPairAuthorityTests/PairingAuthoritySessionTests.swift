import Crypto
import Foundation
import PairingCommitState
import RemozioProtocol
import XCTest
@testable import LinuxPairAuthority

/// A scripted phone on an in-memory stream. Each frame the authority writes produces the phone's next frame.
private final class ScriptedPhone: PairingByteStream {
    enum Proof { case valid, badSignature, wrongSetupID, wrongDigest, none }
    let transport = P256.Signing.PrivateKey()
    let decision = P256.Signing.PrivateKey()
    let biometric: P256.Signing.PrivateKey
    var scope: ChannelScope
    var transportClaim: Data?
    var firstFrame: PairingSetupFrame?
    var proof = Proof.valid
    var failReceiptWrite = false
    private(set) var written: [PairingSetupFrame] = []
    private(set) var transcript: PairingTranscript?
    private(set) var sentProposal: PairingPhoneProposal?
    private var inbound = Data()
    var onTranscript: (() -> Void)?

    init(identity: PairingIdentity, phoneTag: UInt8, biometric: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) throws {
        self.biometric = biometric
        scope = try ChannelScope(macID: identity.macID, accountID: identity.accountID,
                                 phoneID: Data(repeating: phoneTag, count: 16), enrollmentEpoch: Data(repeating: 0x44, count: 16))
    }

    var peerPoint: Data { transport.publicKey.x963Representation }

    func proposal() throws -> PairingPhoneProposal {
        let offer = try ChannelOffer(role: .phone, scope: scope, nonce: randomBytes(32), envelopeVersions: [1],
                                     requests: [], auditVersions: [])
        return try PairingPhoneProposal(phone: offer,
            transportKey: PairingKey(keyID: Data(repeating: 5, count: 16), publicKey: transportClaim ?? peerPoint),
            decisionKey: PairingKey(keyID: Data(repeating: 6, count: 16), publicKey: decision.publicKey.x963Representation),
            biometricKey: PairingKey(keyID: Data(repeating: 7, count: 16), publicKey: biometric.publicKey.x963Representation))
    }

    func write(_ bytes: Data, deadline: Int64) throws {
        let length = bytes.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        XCTAssertEqual(bytes.count, length + 4)
        let frame = try PairingSetupFrame.decode(Data(bytes.dropFirst(4)))
        if case .receipt = frame, failReceiptWrite { throw PairingSessionError.stream("peer closed") }
        written.append(frame)
        switch frame {
        case .hello:
            if let firstFrame { try queue(firstFrame) } else {
                let proposal = try proposal()
                sentProposal = proposal
                try queue(.proposal(proposal))
            }
        case .transcript(let value):
            transcript = value
            onTranscript?()
            let input = try value.signingInput(purpose: .phoneBiometric)
            switch proof {
            case .valid: try queue(.proof(setupID: value.setupID, digest: value.digest(),
                                          signature: biometric.signature(for: input).rawRepresentation))
            case .badSignature: try queue(.proof(setupID: value.setupID, digest: value.digest(),
                                                 signature: P256.Signing.PrivateKey().signature(for: input).rawRepresentation))
            case .wrongSetupID: try queue(.proof(setupID: Data(repeating: 9, count: 16), digest: value.digest(),
                                                 signature: biometric.signature(for: input).rawRepresentation))
            case .wrongDigest: try queue(.proof(setupID: value.setupID, digest: Data(repeating: 9, count: 32),
                                                signature: biometric.signature(for: input).rawRepresentation))
            case .none: break
            }
        default: break
        }
    }

    func read(maximum: Int, deadline: Int64) throws -> Data {
        guard !inbound.isEmpty else { throw PairingSessionError.stream("peer closed") }
        // Deliver in small pieces to exercise reassembly.
        let count = min(maximum, 7, inbound.count)
        defer { inbound = Data(inbound.dropFirst(count)) }
        return Data(inbound.prefix(count))
    }

    private func queue(_ frame: PairingSetupFrame) throws {
        let body = try frame.encode()
        let size = UInt32(body.count)
        inbound.append(contentsOf: [UInt8(size >> 24), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)])
        inbound.append(body)
    }
}

private final class ScriptedConsole: PairingOperatorConsole {
    var answer: () -> String?
    private(set) var lines: [String] = []
    private(set) var discardedBeforeTranscript: Bool?
    weak var phone: ScriptedPhone?
    init(answer: @escaping () -> String?) { self.answer = answer }
    func show(_ line: String) { lines.append(line) }
    func discardPendingInput() { discardedBeforeTranscript = phone?.transcript == nil }
    func readLine(deadline: Int64) throws -> String? { answer() }
}

private final class ManualClock {
    var value: Int64 = 1_000_000
}

final class PairingAuthoritySessionTests: XCTestCase {
    private var root: URL!
    private var store: PairingCommitStore!
    private var identity: PairingIdentity!
    private let clock = ManualClock()

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("linux-pair-session-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        store = makeStore()
        identity = try PairingIdentity.create(in: store, label: "money-maker")
        _ = try store.trustRevision()  // the initial state exists before any test hooks a write
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    private func makeStore(maximumEnrollments: Int = PairingCommitStore.defaultMaximumEnrollments) -> PairingCommitStore {
        let clock = clock
        return PairingCommitStore(directory: root.appendingPathComponent("state"), maximumEnrollments: maximumEnrollments,
                                  clock: { UInt64(clock.value) })
    }

    /// The operator types the code the phone shows, as the phone computes it from its own copy of the transcript.
    private func phoneCode(_ phone: ScriptedPhone) -> () -> String? {
        { [weak phone] in try? phone?.transcript?.verificationCode() }
    }

    private func session(_ phone: ScriptedPhone, console: ScriptedConsole, store: PairingCommitStore? = nil,
                         peerPoint: Data? = nil) -> PairingAuthoritySession {
        console.phone = phone
        let clock = clock
        return PairingAuthoritySession(identity: identity, store: store ?? self.store, stream: phone,
                                       peerPoint: peerPoint ?? phone.peerPoint, console: console,
                                       now: { clock.value }, wallMilliseconds: { 1_700_000_000_000 })
    }

    private func failure(_ session: PairingAuthoritySession) -> PairingSessionFailure? {
        do { _ = try session.run(); XCTFail("expected a failure"); return nil } catch { return error }
    }

    func testOperatorMatchedCodeCommitsAndSendsAVerifiableReceipt() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        let console = ScriptedConsole(answer: phoneCode(phone))
        let outcome = try session(phone, console: console).run()
        let transcript = try XCTUnwrap(phone.transcript)
        XCTAssertEqual(outcome, .enrolled(setupID: transcript.setupID, phoneID: phone.scope.phoneID))
        guard phone.written.count == 3, case .hello = phone.written[0], case .transcript = phone.written[1],
              case .receipt(let setupID, let digest, let signature) = phone.written[2] else {
            return XCTFail("frames out of order: \(phone.written)")
        }
        XCTAssertEqual(setupID, transcript.setupID)
        XCTAssertEqual(digest, try transcript.digest())
        XCTAssertTrue(try transcript.verify(signature: signature, publicKey: identity.authorityPublicKey, purpose: .macCommit))
        XCTAssertFalse(try transcript.verify(signature: signature, publicKey: identity.authorityPublicKey, purpose: .phoneBiometric))
        XCTAssertEqual(try store.list().map(\.phoneID), [phone.scope.phoneID])
        XCTAssertEqual(console.discardedBeforeTranscript, true)
        XCTAssertFalse(console.lines.joined().contains(try transcript.verificationCode()), "the terminal must not show the code")
    }

    func testMintedTranscriptCarriesFreshMacValuesAndThePhoneClaimsUnchanged() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        _ = try session(phone, console: ScriptedConsole(answer: phoneCode(phone))).run()
        let transcript = try XCTUnwrap(phone.transcript)
        let proposal = try XCTUnwrap(phone.sentProposal)
        XCTAssertNoThrow(try proposal.validate(transcript))
        XCTAssertNoThrow(try identity.invitation().validateMacClaims(in: transcript))
        XCTAssertNil(transcript.replacement)
        XCTAssertEqual(transcript.mac.role, .mac)
        XCTAssertEqual(transcript.mac.scope, phone.scope)
        XCTAssertNotEqual(transcript.mac.nonce, transcript.phone.nonce)
        XCTAssertEqual(transcript.expiresAtUnixMillis - transcript.issuedAtUnixMillis, 300_000)
        let other = try ScriptedPhone(identity: identity, phoneTag: 2)
        _ = try session(other, console: ScriptedConsole(answer: phoneCode(other))).run()
        let second = try XCTUnwrap(other.transcript)
        XCTAssertNotEqual(second.setupID, transcript.setupID)
        XCTAssertNotEqual(second.challenge, transcript.challenge)
        XCTAssertNotEqual(second.enrollmentTag, transcript.enrollmentTag)
        XCTAssertNotEqual(second.expectedTrustRevision, transcript.expectedTrustRevision, "each commit moves the trust revision")
    }

    func testCodeIsAcceptedInLowercaseWithSpacesButNotWithAnySymbolChanged() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        let lowercase = ScriptedConsole(answer: { [weak phone] in try? phone?.transcript?.verificationCode().lowercased() })
        XCTAssertNoThrow(try session(phone, console: lowercase).run())

        let wrong = try ScriptedPhone(identity: identity, phoneTag: 2)
        let console = ScriptedConsole(answer: { [weak wrong] in
            guard var code = try? wrong?.transcript?.verificationCode() else { return nil }
            let last = code.removeLast()
            return code + (last == "2" ? "3" : "2")
        })
        let result = failure(session(wrong, console: console))
        XCTAssertEqual(result, PairingSessionFailure(error: .codeMismatch, transcriptSent: true))
        XCTAssertEqual(try store.list().map(\.phoneID), [phone.scope.phoneID])
        XCTAssertFalse(wrong.written.contains { if case .receipt = $0 { return true }; return false })
    }

    func testEndOfInputConfirmsNothing() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        let result = failure(session(phone, console: ScriptedConsole(answer: { nil })))
        XCTAssertEqual(result, PairingSessionFailure(error: .notConfirmed, transcriptSent: true))
        XCTAssertEqual(try store.list().count, 0)
    }

    func testConfirmationOfOneTranscriptCannotCommitAnother() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        let first = try session(phone, console: ScriptedConsole(answer: { nil })).mint(phone.proposal())
        let second = try session(phone, console: ScriptedConsole(answer: { nil })).mint(phone.proposal())
        let confirmation = try PairingAuthoritySession.confirm(first, console: ScriptedConsole(answer: { try? first.verificationCode() }),
                                                               deadline: clock.value + 1000)
        let proof = try phone.biometric.signature(for: second.signingInput(purpose: .phoneBiometric)).rawRepresentation
        XCTAssertThrowsError(try session(phone, console: ScriptedConsole(answer: { nil }))
            .commitConfirmed(second, confirmation: confirmation, proof: proof, deadline: clock.value + 1000)) {
            XCTAssertEqual($0 as? PairingSessionError, .confirmationMismatch)
        }
        XCTAssertEqual(try store.list().count, 0)
    }

    func testProposalTransportKeyMustBeTheTLSClientKey() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        phone.transportClaim = P256.Signing.PrivateKey().publicKey.x963Representation
        let result = failure(session(phone, console: ScriptedConsole(answer: phoneCode(phone))))
        XCTAssertEqual(result, PairingSessionFailure(error: .wrongTransportKey, transcriptSent: false))
        XCTAssertNil(phone.transcript)
    }

    func testProposalForAnotherMacOrAccountIsRefused() throws {
        for (mac, account) in [(Data(repeating: 1, count: 16), identity.accountID), (identity.macID, Data(repeating: 1, count: 16))] {
            let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
            phone.scope = try ChannelScope(macID: mac, accountID: account, phoneID: Data(repeating: 1, count: 16),
                                           enrollmentEpoch: Data(repeating: 2, count: 16))
            let result = failure(session(phone, console: ScriptedConsole(answer: phoneCode(phone))))
            XCTAssertEqual(result, PairingSessionFailure(error: .wrongScope, transcriptSent: false))
        }
    }

    func testFramesOutOfOrderAreRefused() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        phone.firstFrame = .proof(setupID: Data(repeating: 1, count: 16), digest: Data(repeating: 2, count: 32),
                                  signature: Data(repeating: 3, count: 64))
        let result = failure(session(phone, console: ScriptedConsole(answer: phoneCode(phone))))
        XCTAssertEqual(result, PairingSessionFailure(error: .unexpectedFrame, transcriptSent: false))
    }

    func testInvalidProofsCommitNothing() throws {
        for kind in [ScriptedPhone.Proof.badSignature, .wrongSetupID, .wrongDigest] {
            let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
            phone.proof = kind
            let result = failure(session(phone, console: ScriptedConsole(answer: phoneCode(phone))))
            XCTAssertEqual(result, PairingSessionFailure(error: .invalidProof, transcriptSent: true), "\(kind)")
        }
        XCTAssertEqual(try store.list().count, 0)
    }

    func testDisconnectBeforeTheProofCommitsNothing() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        phone.proof = .none
        let result = failure(session(phone, console: ScriptedConsole(answer: phoneCode(phone))))
        XCTAssertEqual(result, PairingSessionFailure(error: .stream("peer closed"), transcriptSent: true))
        XCTAssertEqual(try store.list().count, 0)
    }

    func testExpiryDuringConfirmationCommitsNothing() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        let clock = clock
        let console = ScriptedConsole(answer: { [weak phone] in
            clock.value += 300_001
            return try? phone?.transcript?.verificationCode()
        })
        let result = failure(session(phone, console: console))
        XCTAssertEqual(result, PairingSessionFailure(error: .expired, transcriptSent: true))
        XCTAssertEqual(try store.list().count, 0)
    }

    func testTheSamePhoneCannotEnrollTwice() throws {
        let biometric = P256.Signing.PrivateKey()
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1, biometric: biometric)
        _ = try session(phone, console: ScriptedConsole(answer: phoneCode(phone))).run()
        let again = try ScriptedPhone(identity: identity, phoneTag: 1, biometric: biometric)
        let result = failure(session(again, console: ScriptedConsole(answer: phoneCode(again))))
        XCTAssertEqual(result, PairingSessionFailure(error: .commit(.alreadyEnrolled), transcriptSent: true))
        XCTAssertEqual(try store.list().count, 1)
    }

    func testFullStateIsRefusedBeforeWriting() throws {
        let small = makeStore(maximumEnrollments: 1)
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        _ = try session(phone, console: ScriptedConsole(answer: phoneCode(phone)), store: small).run()
        let next = try ScriptedPhone(identity: identity, phoneTag: 2)
        let result = failure(session(next, console: ScriptedConsole(answer: phoneCode(next)), store: small))
        XCTAssertEqual(result, PairingSessionFailure(error: .commit(.stateFull), transcriptSent: true))
        XCTAssertEqual(try small.list().count, 1)
    }

    func testUndeliveredReceiptLeavesTheEnrollmentAndIsNotRetried() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        phone.failReceiptWrite = true
        let outcome = try session(phone, console: ScriptedConsole(answer: phoneCode(phone))).run()
        let transcript = try XCTUnwrap(phone.transcript)
        guard case .enrolledReceiptUndelivered(let setupID, let phoneID, _) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(setupID, transcript.setupID)
        XCTAssertEqual(phoneID, phone.scope.phoneID)
        XCTAssertEqual(phone.written.count, 2, "one receipt attempt, never retried")
        XCTAssertEqual(try store.list().map(\.setupID), [transcript.setupID])
    }

    func testLateCommitReportsUnknownStateAndSendsNoReceipt() throws {
        let phone = try ScriptedPhone(identity: identity, phoneTag: 1)
        let clock = clock
        // The store's clock passes the deadline between its write and its final check.
        let late = PairingCommitStore(directory: root.appendingPathComponent("state"), clock: { UInt64(clock.value) },
                                      crashHook: { step in if step == .finished { clock.value += 400_000 } })
        let outcome = try session(phone, console: ScriptedConsole(answer: phoneCode(phone)), store: late).run()
        guard case .enrolledStateUnknown(_, .committedLate) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertFalse(phone.written.contains { if case .receipt = $0 { return true }; return false })
    }
}
