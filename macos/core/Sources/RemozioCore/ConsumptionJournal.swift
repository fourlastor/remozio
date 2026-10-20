import Foundation
import RemozioHostCore
import RemozioProtocol

public typealias ConsumptionJournalError = RemozioHostCore.ConsumptionJournalError
public typealias ConsumptionReceipt = RemozioHostCore.ConsumptionReceipt

/// Private adapter for the Mac connection owner; keep its storage errors and transaction failure handling.
final class ConsumptionJournal {
    private let tables: ConsumptionJournalTables

    init(connection: OpaquePointer, macID: Data, accountID: Data, decisionLimits: CBORLimits,
         recordLimits: CBORLimits, maximumRows: Int) throws {
        tables = try ConsumptionJournalTables(connection: connection, macID: macID, accountID: accountID,
            decisionLimits: decisionLimits, recordLimits: recordLimits, maximumRows: maximumRows)
    }

    func createSchema() throws { try adapt { try tables.createSchema() } }
    func createOutcomeSchema() throws { try adapt { try tables.createOutcomeSchema() } }

    func consume(canonicalDecision: Data, signature: Data, retained: RetainedApprovalRequest,
                 trust: ApprovalTrustSnapshot, now: AuthorityMoment, eventID: Data, receiptTimeMs: UInt64?,
                 writer: AuditEpochWriter, expectedHead: UInt64, audit: AuditJournalTables,
                 requestLimits: CBORLimits, signingLimits: CBORLimits) throws -> ConsumptionReceipt {
        try adapt {
            try tables.consume(canonicalDecision: canonicalDecision, signature: signature, retained: retained,
                trust: trust, now: now, eventID: eventID, receiptTimeMs: receiptTimeMs, writer: writer,
                expectedHead: expectedHead, audit: audit, requestLimits: requestLimits, signingLimits: signingLimits)
        }
    }

    func receipt(requestID: Data) throws -> ConsumptionReceipt? {
        try adapt { try tables.receipt(requestID: requestID) }
    }
    func outcome(requestID: Data) throws -> ConsumptionOutcome? {
        try adapt { try tables.outcome(requestID: requestID) }
    }
    func outcomePage(after: Data?, maximumRecords: Int, maximumBytes: Int) throws -> ConsumptionOutcomePage {
        try adapt { try tables.outcomePage(after: after, maximumRecords: maximumRecords, maximumBytes: maximumBytes) }
    }
    func transition(requestID: Data, expectedRevision: UInt64, event: RequestEvent, eventID: Data,
                    receiptTimeMs: UInt64?, writer: AuditEpochWriter, expectedHead: UInt64,
                    audit: AuditJournalTables) throws -> ConsumptionOutcome {
        try adapt {
            try tables.transition(requestID: requestID, expectedRevision: expectedRevision, event: event,
                eventID: eventID, receiptTimeMs: receiptTimeMs, writer: writer, expectedHead: expectedHead, audit: audit)
        }
    }

    private func adapt<T>(_ operation: () throws -> T) throws -> T {
        do { return try operation() }
        catch ConsumptionJournalError.storage(let code) { throw JournalDatabaseError.storage(code) }
    }
}
