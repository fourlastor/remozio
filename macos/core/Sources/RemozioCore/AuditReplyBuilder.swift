import CryptoKit
import Foundation
import RemozioProtocol
import RemozioHostCore

// Preserve the Mac reply API and its error identity alongside the shared table types.
public typealias AuditReplyError = RemozioHostCore.AuditReplyError
public typealias AuditEpochRead = RemozioHostCore.AuditEpochRead

public struct AuditHistoryRequest: Sendable {
    public let nonce: Data
    public let epoch: Data?
    public let after: UInt64?
    public init(nonce: Data, epoch: Data?, after: UInt64?) throws {
        guard nonce.count == 32, (epoch == nil) == (after == nil), epoch == nil || epoch?.count == 16 else {
            throw AuditReplyError.invalidQuery
        }
        self.nonce = nonce; self.epoch = epoch; self.after = after
    }
}

public struct AuditPageRequest: Sendable {
    public let nonce: Data
    public let epoch: Data
    public let generation: UInt64
    public let after: UInt64
    public init(nonce: Data, epoch: Data, generation: UInt64, after: UInt64) throws {
        guard nonce.count == 32, epoch.count == 16 else { throw AuditReplyError.invalidQuery }
        self.nonce = nonce; self.epoch = epoch; self.generation = generation; self.after = after
    }
}

public struct AuditReplyLimits: Sendable {
    public let batch: CBORLimits
    public let record: CBORLimits
    public let history: CBORLimits
    public let descriptor: CBORLimits
    public let signing: CBORLimits
    public let maximumRecords: Int
    public init(batch: CBORLimits, record: CBORLimits, history: CBORLimits, descriptor: CBORLimits,
                signing: CBORLimits, maximumRecords: Int) throws {
        guard maximumRecords > 0 else { throw AuditReplyError.invalidBounds }
        self.batch = batch; self.record = record; self.history = history; self.descriptor = descriptor
        self.signing = signing; self.maximumRecords = maximumRecords
    }
}

public enum AuditReplyKind: Equatable, Sendable { case page, history }
public struct SignedAuditReply: Sendable {
    public let kind: AuditReplyKind
    public let wireVersion: UInt64
    public let canonicalBody: Data
    public let signature: Data
}

/// Builds bounded, audit-only replies after the service authorizes the enrolled phone and account.
/// It does not establish channel authorization, select current trust or write history.
public struct AuditReplyBuilder {
    private let macID: Data
    private let accountID: Data
    private let authorityPublicKey: Data
    private let limits: AuditReplyLimits
    private let signer: (Data) throws -> Data

    /// The signer signs these bytes with P-256/SHA-256 once and returns raw 64-byte R||S.
    /// Production supplies the non-exportable authority key. The expected public key comes from local trust.
    public init(macID: Data, accountID: Data, authorityPublicKey: Data, limits: AuditReplyLimits,
                signer: @escaping (Data) throws -> Data) throws {
        guard macID.count == 16, accountID.count == 16 else { throw AuditReplyError.invalidScope }
        guard authorityPublicKey.count == 65, authorityPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: authorityPublicKey)) != nil else {
            throw AuditReplyError.invalidAuthorityKey
        }
        self.macID = macID; self.accountID = accountID; self.authorityPublicKey = authorityPublicKey
        self.limits = limits; self.signer = signer
    }

    /// Read both epoch descriptions in one snapshot. The owner supplies its current epoch after startup recovery.
    /// Authorize the enrolled caller first and serialize this call with trust and epoch changes.
    public func history(_ query: AuditHistoryRequest, journal: JournalDatabase, currentEpoch: Data) throws -> SignedAuditReply {
        let reads = try journal.read { transaction in
            guard let current = try transaction.epoch(currentEpoch) else { throw AuditJournalError.unavailableEpoch }
            let queried = try query.epoch.flatMap { try transaction.epoch($0) }
            return (current, queried)
        }
        return try history(query, current: reads.0, queried: reads.1)
    }

    /// Read a bounded page, then sign after the transaction closes. No storage failure becomes an empty success.
    public func page(_ query: AuditPageRequest, journal: JournalDatabase) throws -> SignedAuditReply {
        let read = try journal.read { transaction in
            guard let epoch = try transaction.epoch(query.epoch) else { throw AuditJournalError.unavailableEpoch }
            try checkPageQuery(query, epoch: epoch)
            return try transaction.page(epoch: query.epoch, after: query.after,
                maximumRecords: min(limits.maximumRecords, Int(Int32.max)), maximumBytes: limits.batch.maxBytes)
        }
        if read.canonicalRecords.isEmpty { return try page(query, epoch: read.epoch, canonicalRecords: []) }
        // Find a nonempty prefix that fits the complete body and signing envelope, including CBOR framing.
        var lower = 1, upper = read.canonicalRecords.count
        var fitted: Data?
        var lastLimit: Error = AuditReplyError.invalidBounds
        while lower <= upper {
            let count = lower + (upper - lower) / 2
            do {
                let body = try pageBody(query, epoch: read.epoch, canonicalRecords: Array(read.canonicalRecords.prefix(count)))
                _ = try signingInput(body, kind: .page)
                fitted = body
                lower = count + 1
            } catch CBORError.limitExceeded(let limit) where limit == .bytes || limit == .items {
                lastLimit = CBORError.limitExceeded(limit); upper = count - 1
            } catch AuditReplyError.invalidBounds {
                lastLimit = AuditReplyError.invalidBounds; upper = count - 1
            }
        }
        guard let fitted else { throw lastLimit }
        return try sign(fitted, kind: .page)
    }

    /// Records are one bounded contiguous page, never an entire journal loaded for pagination.
    public func page(_ query: AuditPageRequest, epoch: AuditEpochRead, canonicalRecords: [Data]) throws -> SignedAuditReply {
        try sign(pageBody(query, epoch: epoch, canonicalRecords: canonicalRecords), kind: .page)
    }

    private func checkPageQuery(_ query: AuditPageRequest, epoch: AuditEpochRead) throws {
        try checkScope(epoch)
        guard query.epoch == epoch.descriptor.epoch, query.generation == epoch.descriptor.generation else {
            throw AuditReplyError.epochMismatch
        }
        guard query.after <= epoch.head else { throw AuditReplyError.reconciliationRequired }
    }

    private func pageBody(_ query: AuditPageRequest, epoch: AuditEpochRead, canonicalRecords: [Data]) throws -> Data {
        try checkPageQuery(query, epoch: epoch)
        guard canonicalRecords.count <= limits.maximumRecords else { throw AuditReplyError.invalidBounds }
        var recordBytes = 0
        for record in canonicalRecords {
            guard record.count <= limits.record.maxBytes, record.count <= limits.batch.maxBytes - recordBytes else {
                throw AuditReplyError.invalidBounds
            }
            recordBytes += record.count
        }
        let body = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(query.epoch),
            4: .unsigned(query.generation), 5: .unsigned(query.after), 6: .unsigned(epoch.retainedAfter),
            7: .unsigned(epoch.head), 8: .bytes(query.nonce), 9: .array(canonicalRecords.map(CBORValue.bytes)),
        ]), limits: limits.batch)
        _ = try AuditBatch.decode(body, batchLimits: limits.batch, recordLimits: limits.record, maximumRecords: limits.maximumRecords)
        return body
    }

    /// A nil queried read means an old epoch is unavailable. The current epoch always uses its current read.
    public func history(_ query: AuditHistoryRequest, current: AuditEpochRead, queried supplied: AuditEpochRead? = nil) throws -> SignedAuditReply {
        try checkScope(current)
        if let supplied { try checkScope(supplied) }
        let queried: AuditEpochRead?
        let disposition: AuditHistoryDisposition
        if let requested = query.epoch {
            if requested == current.descriptor.epoch {
                if let supplied {
                    guard try supplied.descriptor.encode(limits: limits.descriptor) == current.descriptor.encode(limits: limits.descriptor),
                          supplied.retainedAfter == current.retainedAfter, supplied.head == current.head else {
                        throw AuditReplyError.epochMismatch
                    }
                }
                queried = current
            } else {
                guard supplied == nil || supplied?.descriptor.epoch == requested else { throw AuditReplyError.epochMismatch }
                queried = supplied
            }
            if let queried { disposition = query.after! > queried.head ? .cursorAhead : .available }
            else { disposition = .unavailable }
        } else {
            guard supplied == nil else { throw AuditReplyError.invalidQuery }
            queried = nil; disposition = .discovery
        }
        let body = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(query.nonce),
            4: query.epoch.map(CBORValue.bytes) ?? .null, 5: query.after.map(CBORValue.unsigned) ?? .null,
            6: .unsigned(disposition.rawValue), 7: .bytes(try current.descriptor.encode(limits: limits.descriptor)),
            8: .unsigned(current.retainedAfter), 9: .unsigned(current.head),
            10: try queried.map { .bytes(try $0.descriptor.encode(limits: limits.descriptor)) } ?? .null,
            11: queried.map { .unsigned($0.retainedAfter) } ?? .null, 12: queried.map { .unsigned($0.head) } ?? .null,
        ]), limits: limits.history)
        _ = try AuditHistoryStatus.decode(body, limits: limits.history, descriptorLimits: limits.descriptor)
        return try sign(body, kind: .history)
    }

    private func checkScope(_ epoch: AuditEpochRead) throws {
        guard epoch.descriptor.macID == macID, epoch.descriptor.accountID == accountID else { throw AuditReplyError.scopeMismatch }
    }

    private func signingInput(_ body: Data, kind: AuditReplyKind) throws -> Data {
        switch kind {
        case .page: return try AuditBatchSigningInput.make(wireVersion: 1, canonicalPayload: body,
            payloadLimits: limits.batch, inputLimits: limits.signing)
        case .history: return try AuditHistoryStatusSigningInput.make(wireVersion: 1, canonicalPayload: body,
            payloadLimits: limits.history, inputLimits: limits.signing)
        }
    }

    private func sign(_ body: Data, kind: AuditReplyKind) throws -> SignedAuditReply {
        let signature = try signer(signingInput(body, kind: kind))
        let valid: Bool
        switch kind {
        case .page: valid = try AuditBatchSignature.verify(signature: signature, publicKey: authorityPublicKey, wireVersion: 1,
            canonicalPayload: body, payloadLimits: limits.batch, inputLimits: limits.signing)
        case .history: valid = try AuditHistoryStatusSignature.verify(signature: signature, publicKey: authorityPublicKey, wireVersion: 1,
            canonicalPayload: body, payloadLimits: limits.history, inputLimits: limits.signing)
        }
        guard valid else { throw AuditReplyError.invalidSignature }
        return SignedAuditReply(kind: kind, wireVersion: 1, canonicalBody: body, signature: signature)
    }
}
