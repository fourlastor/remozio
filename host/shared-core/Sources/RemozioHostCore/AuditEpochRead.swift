import Foundation
import RemozioProtocol

public enum AuditReplyError: Error, Equatable {
    case invalidScope, invalidQuery, invalidBounds, invalidAuthorityKey
    case scopeMismatch, epochMismatch, reconciliationRequired, invalidSignature
}

/// A coherent read from one account's journal. The caller obtains all reads for a reply in one transaction.
public struct AuditEpochRead: Sendable {
    public let descriptor: AuditEpochDescriptor
    public let retainedAfter: UInt64
    public let head: UInt64
    public init(descriptor: AuditEpochDescriptor, retainedAfter: UInt64, head: UInt64) throws {
        guard retainedAfter <= head else { throw AuditReplyError.invalidBounds }
        self.descriptor = descriptor; self.retainedAfter = retainedAfter; self.head = head
    }
}
