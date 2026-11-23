import Foundation

public enum GatewayHistoryCollectionError: Error, Equatable {
    case invalidConfiguration, wrongQueryOwner, wrongRange, invalidClock, incompleteHistory
    case duplicateOperation, conflictingHead, capacityExceeded, stopped
}

/// A complete receipt sequence anchored to one authenticated head. It grants no authority or counter change.
/// The host must recheck current registration, enrollment history, and local revision before recovery.
public struct VerifiedGatewayHistory: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let head: VerifiedGatewayHead
    public let afterRevision: UInt64
    public let records: [GatewayControlReceipt]
    public let receivedAt: AuthorityMoment
    fileprivate init(head: VerifiedGatewayHead, afterRevision: UInt64, records: [GatewayControlReceipt], receivedAt: AuthorityMoment) {
        self.head = head; self.afterRevision = afterRevision; self.records = records; self.receivedAt = receivedAt
    }
    public var description: String { "VerifiedGatewayHistory(redacted)" }
    public var debugDescription: String { description }
}

/// Serialized, bounded collection for one recovery attempt. Discard it when the query owner's trust changes.
/// Every accepted page must come from the same owner as the head. A failure permanently stops collection.
public final class GatewayHistoryCollector {
    public let throughRevision: UInt64
    /// The exclusive lower bound for the next query. Nil after completion, failure, or invalidation.
    public var nextAfterRevision: UInt64? { stopped ? nil : cursor }
    private let head: VerifiedGatewayHead
    private let afterRevision: UInt64
    private let maximumRecords: Int
    private let maximumBytes: Int
    private var cursor: UInt64
    private var lastMoment: AuthorityMoment
    private var records: [GatewayControlReceipt] = []
    private var operations: Set<Data> = []
    private var bytes = 0
    private var stopped = false

    public init(head: VerifiedGatewayHead, afterRevision: UInt64,
                maximumRecords: Int = 100_000, maximumBytes: Int = 64 * 1024 * 1024) throws {
        guard (1...100_000).contains(maximumRecords), (1...64 * 1024 * 1024).contains(maximumBytes),
              afterRevision < head.evidence.revision, head.evidence.receipt != nil else {
            throw GatewayHistoryCollectionError.invalidConfiguration
        }
        guard head.evidence.revision - afterRevision <= UInt64(maximumRecords) else {
            throw GatewayHistoryCollectionError.capacityExceeded
        }
        self.head = head; self.afterRevision = afterRevision; cursor = afterRevision
        throughRevision = head.evidence.revision; lastMoment = head.receivedAt
        self.maximumRecords = maximumRecords; self.maximumBytes = maximumBytes
    }

    /// Returns a complete history only once. Nil means that another page is required.
    public func accept(_ verified: VerifiedGatewayControlHistory) throws -> VerifiedGatewayHistory? {
        guard !stopped else { throw GatewayHistoryCollectionError.stopped }
        do {
            let page = verified.page
            guard verified.queryOwnerID == head.queryOwnerID else { throw GatewayHistoryCollectionError.wrongQueryOwner }
            guard page.registration == head.evidence.registration, page.afterRevision == cursor,
                  page.throughRevision == throughRevision else { throw GatewayHistoryCollectionError.wrongRange }
            guard verified.receivedAt.epoch == lastMoment.epoch, verified.receivedAt.milliseconds >= lastMoment.milliseconds else {
                throw GatewayHistoryCollectionError.invalidClock
            }
            guard !page.records.isEmpty else { throw GatewayHistoryCollectionError.incompleteHistory }
            for record in page.records {
                guard cursor < throughRevision, record.revision == cursor + 1 else { throw GatewayHistoryCollectionError.incompleteHistory }
                guard operations.insert(record.operationID).inserted else { throw GatewayHistoryCollectionError.duplicateOperation }
                let size = record.canonicalPayload.count + record.signature.count
                guard records.count < maximumRecords, size <= maximumBytes - bytes else {
                    throw GatewayHistoryCollectionError.capacityExceeded
                }
                records.append(record); bytes += size; cursor = record.revision
            }
            lastMoment = verified.receivedAt
            if page.hasMore {
                guard cursor < throughRevision else { throw GatewayHistoryCollectionError.incompleteHistory }
                return nil
            }
            guard cursor == throughRevision, let terminal = records.last, let anchor = head.evidence.receipt else {
                throw GatewayHistoryCollectionError.incompleteHistory
            }
            guard kind(terminal) == kind(anchor), terminal.operationID == anchor.operationID,
                  terminal.canonicalPayload == anchor.canonicalPayload,
                  terminal.kind != GatewayControlTombstone.receiptKind || terminal.signature == anchor.signature else { throw GatewayHistoryCollectionError.conflictingHead }
            let result = VerifiedGatewayHistory(head: head, afterRevision: afterRevision, records: records, receivedAt: lastMoment)
            invalidate()
            return result
        } catch {
            invalidate()
            throw error
        }
    }

    public func invalidate() { stopped = true; records.removeAll(); operations.removeAll(); bytes = 0 }

    private func kind(_ receipt: GatewayControlReceipt) -> UInt64 {
        receipt.kind
    }
}
