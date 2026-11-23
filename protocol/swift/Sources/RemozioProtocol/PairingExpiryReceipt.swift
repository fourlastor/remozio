import Foundation

public enum PairingExpiryReceiptError: Error { case invalidReceipt }

public enum PairingExpiryReason: UInt64, Sendable {
    case deadlineElapsed = 0
    case retiredIncarnation = 1
}

/// A terminal no-commit result. Verification requires the exact locally retained re-pair transcript.
public struct PairingExpiryReceipt: Sendable, CustomStringConvertible {
    private static let domain = "dev.remozio.pairing.expired-without-commit"
    public static let maximumBytes = 1_024
    private let claims: Claims
    public let signature: Data

    public var setupID: Data { claims.setupID }
    public var reason: PairingExpiryReason { claims.reason }
    public var description: String { "PairingExpiryReceipt(redacted)" }

    public init(transcript: PairingTranscript, reason: PairingExpiryReason, signature: Data) throws {
        try self.init(claims: Claims(transcript: transcript, reason: reason), signature: signature)
    }

    private init(claims: Claims, signature: Data) throws {
        guard signature.count == 64 else { throw PairingExpiryReceiptError.invalidReceipt }
        self.claims = claims
        self.signature = signature
    }

    public static func signingInput(transcript: PairingTranscript, reason: PairingExpiryReason) throws -> Data {
        try Claims(transcript: transcript, reason: reason).encode()
    }

    public func verify(transcript: PairingTranscript) throws -> Bool {
        guard let expected = try? Claims(transcript: transcript, reason: reason), expected == claims else { return false }
        return P256Verification.verify(signature: signature, publicKey: transcript.macAuthorityKey, input: try claims.encode())
    }

    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .bytes(claims.encode()), 1: .bytes(signature)]), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), fields.count == 2,
              case .bytes(let input) = fields[0], case .bytes(let signature) = fields[1] else {
            throw PairingExpiryReceiptError.invalidReceipt
        }
        let result = try Self(claims: Claims.decode(input), signature: signature)
        guard try result.encode() == bytes else { throw PairingExpiryReceiptError.invalidReceipt }
        return result
    }

    private static var limits: CBORLimits {
        get throws { try .init(maxBytes: maximumBytes, maxDepth: 1, maxItems: 8) }
    }

    private struct Claims: Equatable, Sendable {
        let setupID: Data
        let transcriptDigest: Data
        let scope: ChannelScope
        let predecessorEpoch: Data
        let revision: Data
        let expiry: UInt64
        let reason: PairingExpiryReason

        init(transcript: PairingTranscript, reason: PairingExpiryReason) throws {
            let scope = transcript.phone.scope
            guard let predecessor = transcript.replacement, predecessor.phoneID == scope.phoneID else {
                throw PairingExpiryReceiptError.invalidReceipt
            }
            try self.init(setupID: transcript.setupID, transcriptDigest: transcript.digest(), scope: scope,
                predecessorEpoch: predecessor.epoch, revision: transcript.expectedTrustRevision,
                expiry: transcript.expiresAtUnixMillis, reason: reason)
        }

        private init(setupID: Data, transcriptDigest: Data, scope: ChannelScope, predecessorEpoch: Data,
                     revision: Data, expiry: UInt64, reason: PairingExpiryReason) throws {
            guard setupID.count == 16, transcriptDigest.count == 32, predecessorEpoch.count == 16,
                  predecessorEpoch != scope.enrollmentEpoch, revision.count == 16, expiry > 0 else {
                throw PairingExpiryReceiptError.invalidReceipt
            }
            self.setupID = setupID; self.transcriptDigest = transcriptDigest; self.scope = scope
            self.predecessorEpoch = predecessorEpoch; self.revision = revision; self.expiry = expiry; self.reason = reason
        }

        func encode() throws -> Data {
            let scopeFields = [scope.macID, scope.accountID, scope.phoneID, scope.enrollmentEpoch]
            return try DeterministicCBOR.encode(.map([
                0: .text(domain), 1: .unsigned(1), 2: .bytes(setupID), 3: .bytes(transcriptDigest),
                4: .array(scopeFields.map(CBORValue.bytes)), 5: .bytes(predecessorEpoch), 6: .bytes(revision),
                7: .unsigned(expiry), 8: .unsigned(reason.rawValue),
            ]), limits: Self.limits)
        }

        static func decode(_ input: Data) throws -> Self {
            guard case .map(let fields) = try DeterministicCBOR.decode(input, limits: limits),
                  fields.count == 9, fields[0] == .text(domain), fields[1] == .unsigned(1),
                  case .bytes(let setupID) = fields[2], case .bytes(let digest) = fields[3],
                  case .array(let scope) = fields[4], scope.count == 4,
                  case .bytes(let mac) = scope[0], case .bytes(let account) = scope[1],
                  case .bytes(let phone) = scope[2], case .bytes(let epoch) = scope[3],
                  case .bytes(let predecessor) = fields[5], case .bytes(let revision) = fields[6],
                  case .unsigned(let expiry) = fields[7], case .unsigned(let rawReason) = fields[8],
                  let reason = PairingExpiryReason(rawValue: rawReason) else {
                throw PairingExpiryReceiptError.invalidReceipt
            }
            return try Self(setupID: setupID, transcriptDigest: digest,
                scope: ChannelScope(macID: mac, accountID: account, phoneID: phone, enrollmentEpoch: epoch),
                predecessorEpoch: predecessor, revision: revision, expiry: expiry, reason: reason)
        }

        private static var limits: CBORLimits {
            get throws { try .init(maxBytes: 512, maxDepth: 2, maxItems: 32) }
        }
    }
}
