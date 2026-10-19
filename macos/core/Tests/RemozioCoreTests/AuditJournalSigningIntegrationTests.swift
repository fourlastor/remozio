import CryptoKit
import Foundation
import RemozioCore
import RemozioProtocol
import SQLite3
import XCTest

final class AuditJournalSigningIntegrationTests: XCTestCase {
    private var bound: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private func descriptor(_ epoch: UInt8 = 3, account: UInt8 = 2) throws -> AuditEpochDescriptor {
        try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(account)), 3: .bytes(id(epoch)),
            4: .unsigned(UInt64.max), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: bound), limits: bound)
    }
    private func record(_ sequence: UInt64, epoch: UInt8 = 3, account: UInt8 = 2, event: UInt8? = nil) throws -> Data {
        try AuditEventMetadata(eventID: id(event ?? UInt8(truncatingIfNeeded: sequence)), macID: id(1), accountID: id(account),
            journalEpoch: id(epoch), sequence: sequence, requestID: id(8), eventTimeMs: nil, authorityReceiptTimeMs: nil,
            kind: .consumed, category: .command, action: nil, decisionPhoneID: nil, authentication: .system,
            outcome: .accepted, reason: .none, droppedEventCount: nil, peerDeviceID: nil).encode(limits: bound)
    }
    private func tables(_ db: DB, account: UInt8 = 2) throws -> AuditJournalTables {
        try AuditJournalTables(connection: db.handle, macID: id(1), accountID: id(account), recordLimits: bound, descriptorLimits: bound)
    }
    private func initial(_ db: DB) throws -> (AuditJournalTables, AuditEpochWriter) {
        let table = try tables(db)
        try db.exec("BEGIN IMMEDIATE")
        try table.createSchema()
        let writer = try table.createEpoch(descriptor())
        try db.exec("COMMIT")
        return (table, writer)
    }
    private func page(_ table: AuditJournalTables, epoch: UInt8 = 3, after: UInt64 = 0,
                      count: Int = 10, bytes: Int = 16384) throws -> AuditJournalPage {
        try table.page(epoch: id(epoch), after: after, maximumRecords: count, maximumBytes: bytes)
    }

    func testSharedTableRetentionProducesSignableGapsThroughMacAliases() throws {
        let db = try DB(), (table, writer) = try initial(db)
        try db.exec("BEGIN IMMEDIATE")
        for n in 1...4 { try table.append(record(UInt64(n)), writer: writer, expectedHead: UInt64(n - 1)) }
        try table.prune(epoch: id(3), through: 2, expectedHead: 4)
        let retained = try page(table)
        XCTAssertEqual(retained.epoch.retainedAfter, 2)
        XCTAssertEqual(retained.canonicalRecords, try [record(3), record(4)])
        let key = P256.Signing.PrivateKey()
        let builder = try AuditReplyBuilder(macID: id(1), accountID: id(2), authorityPublicKey: key.publicKey.x963Representation,
            limits: AuditReplyLimits(batch: bound, record: bound, history: bound, descriptor: bound, signing: bound, maximumRecords: 10)) {
                try key.signature(for: $0).rawRepresentation
            }
        let reply = try builder.page(AuditPageRequest(nonce: Data(repeating: 1, count: 32), epoch: id(3), generation: .max, after: 0),
                                     epoch: retained.epoch, canonicalRecords: retained.canonicalRecords)
        XCTAssertTrue(try AuditBatchSignature.verify(signature: reply.signature, publicKey: key.publicKey.x963Representation,
            wireVersion: 1, canonicalPayload: reply.canonicalBody, payloadLimits: bound, inputLimits: bound))
        try db.exec("COMMIT")
    }

    private final class DB {
        let handle: OpaquePointer
        init(_ path: String = ":memory:") throws {
            var value: OpaquePointer?
            let rc = sqlite3_open(path, &value)
            guard rc == SQLITE_OK, let value else { if let value { sqlite3_close(value) }; throw AuditJournalError.storage(rc) }
            handle = value
        }
        deinit { sqlite3_close(handle) }
        func exec(_ sql: String) throws {
            let rc = sqlite3_exec(handle, sql, nil, nil, nil)
            guard rc == SQLITE_OK else { throw AuditJournalError.storage(rc) }
        }

    }
}
