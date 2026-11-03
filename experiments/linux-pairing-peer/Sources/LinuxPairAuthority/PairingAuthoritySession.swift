import Crypto
import Foundation
import PairingCommitState
import RemozioProtocol

/// Bytes of one setup connection. Deadlines are absolute milliseconds on `CLOCK_BOOTTIME`.
public protocol PairingByteStream: AnyObject {
    /// Writes every byte or throws. After a throw the stream is dead and must not be used again.
    func write(_ bytes: Data, deadline: Int64) throws
    /// Returns at least one byte and at most `maximum`, or throws.
    func read(maximum: Int, deadline: Int64) throws -> Data
}

/// The operator's terminal. Deadlines are absolute milliseconds on `CLOCK_BOOTTIME`.
public protocol PairingOperatorConsole: AnyObject {
    func show(_ line: String)
    /// Discards input that arrived before the transcript was sent, so earlier input cannot confirm it.
    func discardPendingInput()
    /// One typed line without its newline, or nil at end of input.
    func readLine(deadline: Int64) throws -> String?
}

public enum PairingSessionError: Error, Equatable {
    case unexpectedFrame
    case malformedFrame
    case wrongTransportKey
    case wrongScope
    case invalidTranscript
    case notConfirmed
    case codeMismatch
    case confirmationMismatch
    case invalidProof
    case expired
    case stream(String)
    case commit(PairingCommitError)
}

/// Why a setup attempt ended without a confirmed enrollment, and whether the phone ever saw a transcript.
public struct PairingSessionFailure: Error, Equatable {
    public let error: PairingSessionError
    /// False when the attempt failed before the transcript was sent. Such a candidate never reached the operator.
    public let transcriptSent: Bool
}

public enum PairingSessionOutcome: Equatable {
    /// Committed, and the signed receipt was written to the phone.
    case enrolled(setupID: Data, phoneID: Data)
    /// Committed, but the receipt could not be signed or written. Never retried; the phone keeps PREPARED.
    case enrolledReceiptUndelivered(setupID: Data, phoneID: Data, reason: String)
    /// The commit wrote state but finished late or unconfirmed. No receipt; the enrolled state is unknown.
    case enrolledStateUnknown(setupID: Data, error: PairingCommitError)
}

/// The operator's match of the phone's comparison code against one exact transcript. Only `confirm` creates it.
public struct OperatorConfirmation: Equatable, Sendable {
    public let digest: Data
    fileprivate init(digest: Data) { self.digest = digest }
}

/// The authority role of the restricted pairing exchange for the software-key experiment, in the order of
/// `protocol/pairing-setup.md`: hello, one proposal, a fresh transcript, operator confirmation, one proof, commit,
/// receipt. Nothing here skips the confirmation.
public final class PairingAuthoritySession {
    public static let maximumLimitMilliseconds: Int64 = 300_000
    private let identity: PairingIdentity
    private let store: PairingCommitStore
    private let stream: PairingByteStream
    private let peerPoint: Data
    private let console: PairingOperatorConsole
    private let limitMilliseconds: Int64
    private let now: () -> Int64
    private let wallMilliseconds: () -> UInt64
    private var pending = Data()
    private var transcriptSent = false

    /// - Parameters:
    ///   - peerPoint: the TLS client certificate's P-256 point. The proposal's transport key must equal it.
    ///   - limitMilliseconds: the setup limit and the transcript lifetime, 1 through 300,000.
    ///   - now: `CLOCK_BOOTTIME` milliseconds, the same clock as the commit store and the TLS deadlines.
    public init(identity: PairingIdentity, store: PairingCommitStore, stream: PairingByteStream, peerPoint: Data,
                console: PairingOperatorConsole, limitMilliseconds: Int64 = PairingAuthoritySession.maximumLimitMilliseconds,
                now: @escaping () -> Int64, wallMilliseconds: @escaping () -> UInt64 = PairingAuthoritySession.unixMilliseconds) {
        precondition((1...Self.maximumLimitMilliseconds).contains(limitMilliseconds))
        self.identity = identity; self.store = store; self.stream = stream; self.peerPoint = peerPoint
        self.console = console; self.limitMilliseconds = limitMilliseconds
        self.now = now; self.wallMilliseconds = wallMilliseconds
    }

    public static func unixMilliseconds() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }

    public func run() throws(PairingSessionFailure) -> PairingSessionOutcome {
        do { return try exchange() }
        catch let error as PairingSessionError { throw PairingSessionFailure(error: error, transcriptSent: transcriptSent) }
        catch { throw PairingSessionFailure(error: .stream(String(describing: error)), transcriptSent: transcriptSent) }
    }

    private func exchange() throws -> PairingSessionOutcome {
        var deadline = now() + limitMilliseconds
        try write(.hello, deadline: deadline)
        guard case .proposal(let proposal) = try read(deadline: deadline) else { throw PairingSessionError.unexpectedFrame }
        guard proposal.transportKey.publicKey == peerPoint else { throw PairingSessionError.wrongTransportKey }
        guard proposal.phone.scope.macID == identity.macID, proposal.phone.scope.accountID == identity.accountID else {
            throw PairingSessionError.wrongScope
        }

        let transcript = try mint(proposal)
        // The transcript expiry starts now; the deadline is the earlier of it and the setup limit.
        deadline = min(deadline, now() + Int64(transcript.expiresAtUnixMillis - transcript.issuedAtUnixMillis))
        // Discard typed-ahead input before the phone can see the transcript, so only later input can confirm it.
        console.discardPendingInput()
        transcriptSent = true
        try write(.transcript(transcript), deadline: deadline)

        let confirmation = try Self.confirm(transcript, console: console, deadline: deadline)
        guard case .proof(let setupID, let digest, let signature) = try read(deadline: deadline) else {
            throw PairingSessionError.unexpectedFrame
        }
        guard setupID == transcript.setupID, try digest == transcript.digest(),
              try transcript.verify(signature: signature, publicKey: transcript.biometricKey.publicKey, purpose: .phoneBiometric) else {
            throw PairingSessionError.invalidProof
        }
        let phoneID = transcript.phone.scope.phoneID
        do {
            _ = try commitConfirmed(transcript, confirmation: confirmation, proof: signature, deadline: deadline)
        } catch PairingSessionError.commit(let error) {
            switch error {
            case .committedLate, .committedUnconfirmed:
                return .enrolledStateUnknown(setupID: transcript.setupID, error: error)
            default: throw PairingSessionError.commit(error)
            }
        }
        // Sign and send once. A failure here leaves the enrollment in place and is never retried.
        do {
            let receipt = try identity.receiptSignature(for: transcript)
            try write(.receipt(setupID: transcript.setupID, digest: transcript.digest(), signature: receipt), deadline: deadline)
        } catch {
            return .enrolledReceiptUndelivered(setupID: transcript.setupID, phoneID: phoneID, reason: String(describing: error))
        }
        return .enrolled(setupID: transcript.setupID, phoneID: phoneID)
    }

    /// Fresh setup ID, challenge, enrollment tag and Mac offer; the phone's claims copied unchanged; the store's
    /// current trust revision. The Linux experiment offers no request contracts and no audit versions.
    func mint(_ proposal: PairingPhoneProposal) throws -> PairingTranscript {
        var nonce = randomBytes(32)
        while nonce == proposal.phone.nonce { nonce = randomBytes(32) }
        let issued = wallMilliseconds()
        do {
            let offer = try ChannelOffer(role: .mac, scope: proposal.phone.scope, nonce: nonce, envelopeVersions: [1],
                                         requests: [], auditVersions: [])
            let minimum = PairingIdentity.minimumEnvelopeVersion
            let transcript = try PairingTranscript(setupID: randomBytes(16), challenge: randomBytes(32), phone: proposal.phone,
                mac: offer, minimumEnvelopeVersion: minimum,
                selectedEnvelopeVersion: CompatibilityPolicy.envelopeVersion(local: [1], peer: proposal.phone.envelopeVersions,
                                                                             trustedMinimum: minimum),
                macAuthorityKey: identity.authorityPublicKey, macTransportKey: identity.transportPublicKey,
                transportKey: proposal.transportKey, decisionKey: proposal.decisionKey, biometricKey: proposal.biometricKey,
                enrollmentTag: randomBytes(32), replacement: nil, expectedTrustRevision: try store.trustRevision(),
                issuedAtUnixMillis: issued, expiresAtUnixMillis: issued + UInt64(limitMilliseconds))
            try proposal.validate(transcript)
            try identity.invitation().validateMacClaims(in: transcript)
            return transcript
        } catch let error as PairingCommitError { throw PairingSessionError.commit(error) }
        catch { throw PairingSessionError.invalidTranscript }
    }

    /// Asks the operator to type the code the phone shows. The terminal does not display the expected code, so a
    /// match means the operator read it from the phone. One attempt; end of input or a mismatch confirms nothing.
    public static func confirm(_ transcript: PairingTranscript, console: PairingOperatorConsole,
                               deadline: Int64) throws -> OperatorConfirmation {
        console.show("Compare on the phone. Type the 20-character code the phone shows, then press Enter.")
        guard let typed = try console.readLine(deadline: deadline) else { throw PairingSessionError.notConfirmed }
        let normalized = String(typed.uppercased().filter { !$0.isWhitespace && $0 != "-" })
        let expected = try transcript.verificationCode().replacingOccurrences(of: " ", with: "")
        guard normalized == expected else { throw PairingSessionError.codeMismatch }
        return OperatorConfirmation(digest: try transcript.digest())
    }

    /// Commits only the transcript the operator confirmed: the confirmation's digest must equal this transcript's.
    func commitConfirmed(_ transcript: PairingTranscript, confirmation: OperatorConfirmation, proof: Data,
                         deadline: Int64) throws -> Data {
        guard try confirmation.digest == transcript.digest() else { throw PairingSessionError.confirmationMismatch }
        do {
            return try store.commit(transcript: transcript, biometricProof: proof,
                                    deadlineMilliseconds: UInt64(max(deadline, 0)), isCancelled: { false })
        } catch let error as PairingCommitError { throw PairingSessionError.commit(error) }
    }

    // MARK: Framing

    private func write(_ frame: PairingSetupFrame, deadline: Int64) throws {
        let body = try frame.encode()
        let size = UInt32(body.count)
        var output = Data([UInt8(size >> 24), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)])
        output.append(body)
        guard now() < deadline else { throw PairingSessionError.expired }
        try stream.write(output, deadline: deadline)
    }

    private func read(deadline: Int64) throws -> PairingSetupFrame {
        try fill(4, deadline: deadline)
        let length = pending.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, length <= PairingSetupFrame.maximumBytes else { throw PairingSessionError.malformedFrame }
        try fill(4 + Int(length), deadline: deadline)
        let body = pending.subdata(in: pending.startIndex + 4..<pending.startIndex + 4 + Int(length))
        pending = Data(pending.dropFirst(4 + Int(length)))
        guard let frame = try? PairingSetupFrame.decode(body) else { throw PairingSessionError.malformedFrame }
        return frame
    }

    private func fill(_ count: Int, deadline: Int64) throws {
        while pending.count < count {
            guard now() < deadline else { throw PairingSessionError.expired }
            pending.append(try stream.read(maximum: count - pending.count, deadline: deadline))
        }
    }
}
