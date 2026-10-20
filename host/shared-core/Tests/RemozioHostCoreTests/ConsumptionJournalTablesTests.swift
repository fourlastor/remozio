#if os(Linux)
import Crypto
import CSQLite
#else
import CryptoKit
import SQLite3
#endif
import Foundation
import RemozioHostCore
import RemozioProtocol
import XCTest

final class ConsumptionJournalTablesTests: XCTestCase {
    private let clock = UUID()
    private let key = P256.Signing.PrivateKey()
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private var bounds: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 12, maxItems: 512) } }
    private struct Context {
        let ledger: ConsumptionJournalTables
        let audit: AuditJournalTables
        let writer: AuditEpochWriter
    }
    private func context(_ db: DB, initialize: Bool = true, epoch: UInt8 = 3,
                         account: UInt8 = 2, maximum: Int = 10) throws -> Context {
        let ledger = try ConsumptionJournalTables(connection: db.handle, macID: id(1), accountID: id(account),
            decisionLimits: bounds, recordLimits: bounds, maximumRows: maximum)
        let audit = try AuditJournalTables(connection: db.handle, macID: id(1), accountID: id(account),
            recordLimits: bounds, descriptorLimits: bounds)
        let writer = try db.write {
            if initialize {
                try audit.createSchema()
                try ledger.createSchema()
                try ledger.createOutcomeSchema()
            }
            return try audit.createEpoch(AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(account)), 3: .bytes(id(epoch)),
                4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
            ]), limits: bounds), limits: bounds))
        }
        return Context(ledger: ledger, audit: audit, writer: writer)
    }
    private func request(_ number: UInt8 = 4, kind: RequestKind = .command,
                         action: CapturedAction? = nil, phase: RequestPhase = .presented,
                         challenge: UInt8 = 9) throws -> RetainedApprovalRequest {
        let selected = action ?? CapturedAction(choice: .execute, scope: .currentRequest)
        let payload = try IssuedRequestPayload(contract: RequestContract(requestKind: kind, wireVersion: 1, schemaVersion: 1),
            macID: id(1), accountID: id(2), requestID: id(number), challenge: id(challenge, count: 32), requiredFeatures: [],
            createdUnixMilliseconds: 100, expiresUnixMilliseconds: 200,
            canonicalCapture: DeterministicCBOR.encode(.map([0: .text("private synthetic capture never persisted")]), limits: bounds),
            permittedActions: [selected, CapturedAction(choice: .decline, scope: .currentRequest)], bodyLimits: bounds, captureLimits: bounds)
        return try RetainedApprovalRequest(payload: payload, phase: phase,
            admittedAt: AuthorityMoment(epoch: clock, milliseconds: 100), deadlineMilliseconds: 200)
    }
    private func trust(_ request: RetainedApprovalRequest, active: Bool = true) throws -> ApprovalTrustSnapshot {
        let capabilities = ContractCapabilities(contracts: [request.payload.contract: []])
        let keys = try [EnrolledApprovalKey(id: id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                        EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: key.publicKey.x963Representation)]
        return try ApprovalTrustSnapshot(macID: id(1), accountID: id(2), revision: UUID(), authorityCapabilities: capabilities,
            allowedContracts: [request.payload.contract], enrollments: [5, 8].map {
                try ApprovalEnrollment(phoneID: id($0), active: active, capabilities: capabilities, keys: keys)
            })
    }
    private func consume(_ context: Context, request: RetainedApprovalRequest? = nil, head: UInt64 = 0,
                         phone: UInt8 = 5, action: CapturedAction? = nil, event: UInt8 = 10, now: UInt64 = 150,
                         active: Bool = true, damageSignature: Bool = false, audit: AuditJournalTables? = nil) throws -> ConsumptionReceipt {
        let request = try request ?? self.request()
        let selected = action ?? request.payload.permittedActions[0]
        let requirement = try ActionPolicy.requirement(for: selected, requestKind: request.payload.contract.requestKind,
            retainedPermittedActions: Set(request.payload.permittedActions))
        let decision = try DecisionPayload(macID: id(1), accountID: id(2), requestID: request.payload.requestID,
            requestDigest: request.payload.requestDigest(bodyLimits: bounds, signingLimits: bounds), challenge: request.payload.challenge,
            phoneID: id(phone), keyID: id(requirement.keyClass == .biometric ? 6 : 7), action: selected).encode(limits: bounds)
        let purpose: SigningPurpose
        switch requirement.purpose {
        case .cancellation: purpose = .cancellation
        case .oneTimeUI: purpose = .oneTimeUI
        case .biometricAuthorization: purpose = .biometricAuthorization
        }
        var signature = try key.signature(for: SigningInput.make(wireVersion: 1, messageType: .decision, purpose: purpose,
            canonicalPayload: decision, payloadLimits: bounds, inputLimits: bounds)).rawRepresentation
        if damageSignature { signature[0] ^= 1 }
        return try context.ledger.consume(canonicalDecision: decision, signature: signature, retained: request,
            trust: trust(request, active: active), now: AuthorityMoment(epoch: clock, milliseconds: now),
            eventID: id(event), receiptTimeMs: 12345, writer: context.writer, expectedHead: head,
            audit: audit ?? context.audit, requestLimits: bounds, signingLimits: bounds)
    }
    private func transition(_ context: Context, request: UInt8 = 4, revision: UInt64 = 0,
                            event: RequestEvent = .beginDispatch, eventID: UInt8 = 11, head: UInt64 = 1,
                            audit: AuditJournalTables? = nil) throws -> ConsumptionOutcome {
        try context.ledger.transition(requestID: id(request), expectedRevision: revision, event: event, eventID: id(eventID),
            receiptTimeMs: 12346, writer: context.writer, expectedHead: head, audit: audit ?? context.audit)
    }

    func testApprovalOrDeclineWinsOnceAndSurvivesReopenWithoutCapture() throws {
        for decline in [false, true] {
            let directory = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: directory) }
            let path = directory.appendingPathComponent("journal.sqlite").path
            let winner: ConsumptionReceipt
            do {
                let db = try DB(path), c = try context(db)
                winner = try db.write { try consume(c, action: decline ? .init(choice: .decline, scope: .currentRequest) : nil) }
                XCTAssertEqual(winner.event.outcome, decline ? .noDispatch : .accepted)
                XCTAssertEqual(winner.event.authentication, decline ? .decisionKey : .biometricKey)
                try db.write {
                    XCTAssertThrowsError(try consume(c, head: 1, phone: 8)) {
                        XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed)
                    }
                }
                XCTAssertEqual(try db.read { try c.ledger.receipt(requestID: id(4)) }, winner)
            }
            let db = try DB(path), c = try context(db, initialize: false, epoch: 12)
            XCTAssertEqual(try db.read { try c.ledger.receipt(requestID: id(4)) }, winner)
            try db.write {
                XCTAssertThrowsError(try consume(c, request: request(challenge: 20))) {
                    XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed)
                }
            }
            XCTAssertEqual(try db.read { try c.audit.epoch(id(12))?.head }, 0)
            XCTAssertNil(try Data(contentsOf: URL(fileURLWithPath: path)).range(of: Data("private synthetic capture never persisted".utf8)))
        }
    }

    func testExplicitTransactionsAndWriteLocksAreRequired() throws {
        let db = try DB(), c = try context(db)
        XCTAssertThrowsError(try c.ledger.receipt(requestID: id(4))) { XCTAssertEqual($0 as? ConsumptionJournalError, .transactionRequired) }
        XCTAssertThrowsError(try c.ledger.outcome(requestID: id(4))) { XCTAssertEqual($0 as? ConsumptionJournalError, .transactionRequired) }
        XCTAssertThrowsError(try c.ledger.outcomePage(after: nil, maximumRecords: 10, maximumBytes: 16384)) {
            XCTAssertEqual($0 as? ConsumptionJournalError, .transactionRequired)
        }
        XCTAssertThrowsError(try consume(c)) { XCTAssertEqual($0 as? ConsumptionJournalError, .transactionRequired) }
        XCTAssertThrowsError(try c.ledger.createSchema()) { XCTAssertEqual($0 as? ConsumptionJournalError, .transactionRequired) }
        XCTAssertThrowsError(try c.ledger.createOutcomeSchema()) { XCTAssertEqual($0 as? ConsumptionJournalError, .transactionRequired) }
        try db.read {
            XCTAssertNil(try c.ledger.receipt(requestID: id(4)))
            XCTAssertThrowsError(try consume(c)) { XCTAssertEqual($0 as? ConsumptionJournalError, .writeTransactionRequired) }
            XCTAssertThrowsError(try transition(c)) { XCTAssertEqual($0 as? ConsumptionJournalError, .writeTransactionRequired) }
            XCTAssertThrowsError(try c.ledger.createSchema()) { XCTAssertEqual($0 as? ConsumptionJournalError, .writeTransactionRequired) }
            XCTAssertThrowsError(try c.ledger.createOutcomeSchema()) { XCTAssertEqual($0 as? ConsumptionJournalError, .writeTransactionRequired) }
        }
    }

    func testScopeAndAuditConnectionMustMatchBeforeAnyMutation() throws {
        let db = try DB(), c = try context(db), otherDB = try DB(), other = try context(otherDB)
        let wrongAudit = try AuditJournalTables(connection: db.handle, macID: id(1), accountID: id(9), recordLimits: bounds, descriptorLimits: bounds)
        try db.write {
            for audit in [other.audit, wrongAudit] {
                XCTAssertThrowsError(try consume(c, audit: audit)) { XCTAssertEqual($0 as? ConsumptionJournalError, .auditContextMismatch) }
            }
            XCTAssertNil(try c.ledger.receipt(requestID: id(4)))
            _ = try consume(c)
            for audit in [other.audit, wrongAudit] {
                XCTAssertThrowsError(try transition(c, audit: audit)) { XCTAssertEqual($0 as? ConsumptionJournalError, .auditContextMismatch) }
            }
            XCTAssertEqual(try c.ledger.outcome(requestID: id(4))?.phase, .authorized)
            XCTAssertEqual(try c.audit.epoch(id(3))?.head, 1)
        }
        let scopedDB = try DB(), scoped = try context(scopedDB, account: 9)
        try scopedDB.write {
            XCTAssertThrowsError(try consume(scoped)) { XCTAssertEqual($0 as? ConsumptionJournalError, .wrongScope) }
            XCTAssertNil(try scoped.ledger.receipt(requestID: id(4)))
        }
    }

    func testVerificationFailuresNeverConsumeOrAppend() throws {
        let db = try DB(), c = try context(db)
        for (phase, now, active, damaged, expected) in [
            (RequestPhase.cancelled, UInt64(150), true, false, DecisionVerificationError.unavailableRequest),
            (.presented, 200, true, false, .expired), (.presented, 99, true, false, .invalidClock),
            (.presented, 150, false, false, .unavailableEnrollment), (.presented, 150, true, true, .invalidSignature),
        ] {
            try db.write {
                XCTAssertThrowsError(try consume(c, request: request(phase: phase), now: now, active: active, damageSignature: damaged)) {
                    XCTAssertEqual($0 as? DecisionVerificationError, expected)
                }
            }
            XCTAssertNil(try db.read { try c.ledger.receipt(requestID: id(4)) })
            XCTAssertEqual(try db.read { try c.audit.epoch(id(3))?.head }, 0)
        }
        _ = try db.write { try consume(c, phone: 8) }
    }

    func testUIActionsKeepTheirAuthenticationCategoryAndCanonicalAuditRecord() throws {
        let cases: [(RequestKind, CapturedAction, AuditCategory, AuditAuthentication)] = [
            (.littleSnitch, .init(choice: .allowOnce, scope: .currentRequest), .littleSnitch, .decisionKey),
            (.littleSnitch, .init(choice: .denyOnce, scope: .currentRequest), .littleSnitch, .decisionKey),
            (.littleSnitch, .init(choice: .allowRule, scope: .forever), .littleSnitch, .biometricKey),
            (.onePasswordAccess, .init(choice: .approveAccess, scope: .currentRequest), .onePasswordAccess, .biometricKey),
            (.onePasswordUnlock, .init(choice: .unlockVault, scope: .currentRequest), .onePasswordUnlock, .biometricKey),
        ]
        for (kind, action, category, authentication) in cases {
            let db = try DB(), c = try context(db)
            let receipt = try db.write { try consume(c, request: request(kind: kind, action: action)) }
            XCTAssertEqual(receipt.event.category, category)
            XCTAssertEqual(receipt.event.authentication, authentication)
            XCTAssertEqual(receipt.event.action, AuditActionMetadata(action: action))
            let records = try db.read { try c.audit.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }
            XCTAssertEqual(records, try [receipt.event.encode(limits: bounds)])
        }
    }

    func testCaughtFailureInEitherTableCannotCommitPartialConsumption() throws {
        for table in ["consumptions_v1", "audit_records_v1"] {
            let db = try DB(), c = try context(db)
            try db.exec("CREATE TRIGGER fail_write BEFORE INSERT ON \(table) BEGIN SELECT RAISE(ABORT,'injected'); END")
            try db.write { XCTAssertThrowsError(try consume(c)) }
            try db.read {
                XCTAssertNil(try c.ledger.receipt(requestID: id(4)))
                XCTAssertEqual(try c.audit.epoch(id(3))?.head, 0)
            }
            try db.exec("DROP TRIGGER fail_write")
            _ = try db.write { try consume(c) }
        }
    }

    func testDuplicateAuditEventAndHeadMismatchCannotLeaveAnotherConsumption() throws {
        let db = try DB(), c = try context(db)
        let winner = try db.write { try consume(c) }
        try db.write {
            XCTAssertThrowsError(try consume(c, request: request(20), head: 1))
            XCTAssertThrowsError(try consume(c, request: request(21), event: 11)) {
                XCTAssertEqual($0 as? AuditJournalError, .headMismatch)
            }
        }
        try db.read {
            XCTAssertEqual(try c.ledger.receipt(requestID: id(4)), winner)
            XCTAssertNil(try c.ledger.receipt(requestID: id(20)))
            XCTAssertNil(try c.ledger.receipt(requestID: id(21)))
            XCTAssertEqual(try c.audit.epoch(id(3))?.head, 1)
        }
    }

    func testOuterAndSQLiteAutomaticRollbackLeaveNoConsumption() throws {
        let db = try DB(), c = try context(db)
        try db.exec("BEGIN IMMEDIATE")
        _ = try consume(c)
        try db.exec("ROLLBACK")
        try db.exec("CREATE TRIGGER fail_write BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ROLLBACK,'injected'); END")
        try db.exec("BEGIN IMMEDIATE")
        XCTAssertThrowsError(try consume(c))
        XCTAssertEqual(sqlite3_get_autocommit(db.handle), 1)
        try db.read {
            XCTAssertNil(try c.ledger.receipt(requestID: id(4)))
            XCTAssertEqual(try c.audit.epoch(id(3))?.head, 0)
        }
    }

    func testCompetingConnectionCannotOvertakeFirstWriteTransaction() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("journal.sqlite").path
        let first = try DB(path), c = try context(first)
        let second = try DB(path), d = try context(second, initialize: false, epoch: 12)
        try first.exec("BEGIN IMMEDIATE")
        let winner = try consume(c)
        XCTAssertThrowsError(try second.exec("BEGIN IMMEDIATE")) { XCTAssertEqual($0 as? DB.Failure, .storage(SQLITE_BUSY)) }
        try first.exec("COMMIT")
        try second.write {
            XCTAssertThrowsError(try consume(d, phone: 8)) { XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed) }
            XCTAssertEqual(try d.ledger.receipt(requestID: id(4)), winner)
            XCTAssertEqual(try d.audit.epoch(id(12))?.head, 0)
        }
    }

    func testCapacityAndAuditPruningPreserveConsumedIdentity() throws {
        let db = try DB(), c = try context(db, maximum: 1)
        let winner = try db.write { try consume(c) }
        try db.write {
            try c.audit.prune(epoch: id(3), through: 1, expectedHead: 1)
            XCTAssertThrowsError(try consume(c, request: request(20), head: 1, event: 11)) {
                XCTAssertEqual($0 as? ConsumptionJournalError, .capacityExceeded)
            }
        }
        XCTAssertEqual(try db.read { try c.ledger.receipt(requestID: id(4)) }, winner)
        XCTAssertNil(try db.read { try c.ledger.receipt(requestID: id(20)) })
    }

    func testOutcomeTransitionsAndRestartUncertaintyAreTerminalAcrossReopen() throws {
        for dispatched in [false, true] {
            let directory = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: directory) }
            let path = directory.appendingPathComponent("journal.sqlite").path
            let unknown: ConsumptionOutcome
            do {
                let db = try DB(path), c = try context(db)
                _ = try db.write { try consume(c) }
                if dispatched { _ = try db.write { try transition(c) } }
                unknown = try db.write { try transition(c, revision: dispatched ? 1 : 0, event: .restartAuthority,
                    eventID: 12, head: dispatched ? 2 : 1) }
                XCTAssertEqual(unknown.phase, .unknown)
                try db.write {
                    XCTAssertThrowsError(try transition(c, revision: unknown.revision, eventID: 13, head: dispatched ? 3 : 2)) {
                        XCTAssertEqual($0 as? LifecycleError, .terminal)
                    }
                }
            }
            let db = try DB(path), c = try context(db, initialize: false, epoch: 12)
            XCTAssertEqual(try db.read { try c.ledger.outcome(requestID: id(4)) }, unknown)
            try db.write {
                XCTAssertThrowsError(try consume(c)) { XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed) }
            }
        }
    }

    func testOutcomeAuditFailureRollsBackInsertAndUpdateEvenWhenCaught() throws {
        let db = try DB(), c = try context(db)
        _ = try db.write { try consume(c) }
        for revision in UInt64(0)...1 {
            let before = try db.read { try c.ledger.outcome(requestID: id(4)) }
            try db.exec("CREATE TRIGGER fail_write BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
            try db.write {
                XCTAssertThrowsError(try transition(c, revision: revision, event: revision == 0 ? .beginDispatch : .verifySuccess,
                    eventID: UInt8(11 + revision), head: 1 + revision))
            }
            XCTAssertEqual(try db.read { try c.ledger.outcome(requestID: id(4)) }, before)
            XCTAssertEqual(try db.read { try c.audit.epoch(id(3))?.head }, 1 + revision)
            try db.exec("DROP TRIGGER fail_write")
            let next = try db.write { try transition(c, revision: revision, event: revision == 0 ? .beginDispatch : .verifySuccess,
                eventID: UInt8(11 + revision), head: 1 + revision) }
            XCTAssertEqual(next.phase, revision == 0 ? .executing : .succeeded)
        }
        try db.write {
            XCTAssertThrowsError(try transition(c, revision: 0, eventID: 13, head: 3)) {
                XCTAssertEqual($0 as? ConsumptionOutcomeError, .staleRevision)
            }
        }
    }

    func testOutcomePagesAreBoundedAndCorruptionCannotBecomeAnEmptyPage() throws {
        let db = try DB(), c = try context(db)
        let receipt = try db.write { try consume(c) }
        _ = try db.write { try consume(c, request: request(20), head: 1, event: 11) }
        try db.read {
            let page = try c.ledger.outcomePage(after: nil, maximumRecords: 1, maximumBytes: 16384)
            XCTAssertEqual(page.outcomes.map(\.receipt), [receipt])
            XCTAssertEqual(page.nextRequestID, id(4))
            let second = try c.ledger.outcomePage(after: page.nextRequestID, maximumRecords: 1, maximumBytes: 16384)
            XCTAssertEqual(second.outcomes.map { $0.receipt.decision.requestID }, [id(20)])
            XCTAssertNil(second.nextRequestID)
            XCTAssertThrowsError(try c.ledger.outcomePage(after: nil, maximumRecords: 1, maximumBytes: 1)) {
                XCTAssertEqual($0 as? ConsumptionOutcomeError, .pageTooSmall)
            }
            XCTAssertThrowsError(try c.ledger.outcomePage(after: nil, maximumRecords: 0, maximumBytes: 16384)) {
                XCTAssertEqual($0 as? ConsumptionJournalError, .invalidConfiguration)
            }
        }
        try db.exec("UPDATE consumptions_v1 SET event=x'00' WHERE request=x'14141414141414141414141414141414'")
        try db.read {
            XCTAssertThrowsError(try c.ledger.outcomePage(after: id(4), maximumRecords: 1, maximumBytes: 16384))
        }
    }

    func testInvalidConfigurationAndOversizedStoredRecordsFailClosed() throws {
        let db = try DB()
        for maximum in [0, -1, Int(Int32.max) + 1] {
            XCTAssertThrowsError(try ConsumptionJournalTables(connection: db.handle, macID: id(1), accountID: id(2),
                decisionLimits: bounds, recordLimits: bounds, maximumRows: maximum)) {
                XCTAssertEqual($0 as? ConsumptionJournalError, .invalidConfiguration)
            }
        }
        XCTAssertThrowsError(try ConsumptionJournalTables(connection: db.handle, macID: Data(), accountID: id(2),
            decisionLimits: bounds, recordLimits: bounds, maximumRows: 10)) {
            XCTAssertEqual($0 as? ConsumptionJournalError, .invalidConfiguration)
        }
        let c = try context(db)
        _ = try db.write { try consume(c) }
        try db.exec("UPDATE consumptions_v1 SET event=zeroblob(17000)")
        try db.read {
            XCTAssertThrowsError(try c.ledger.receipt(requestID: id(4))) { XCTAssertEqual($0 as? ConsumptionJournalError, .corruptData) }
        }
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        return url
    }

    private final class DB {
        enum Failure: Error, Equatable { case storage(Int32) }
        let handle: OpaquePointer
        init(_ path: String = ":memory:") throws {
            var connection: OpaquePointer?
            let rc = sqlite3_open_v2(path, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
            guard rc == SQLITE_OK, let connection else {
                if let connection { sqlite3_close(connection) }
                throw Failure.storage(rc)
            }
            handle = connection
            try exec("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF")
        }
        deinit { sqlite3_close(handle) }
        func exec(_ sql: String) throws {
            let rc = sqlite3_exec(handle, sql, nil, nil, nil)
            guard rc == SQLITE_OK else { throw Failure.storage(rc) }
        }
        func write<T>(_ body: () throws -> T) throws -> T { try transaction("BEGIN IMMEDIATE", body) }
        func read<T>(_ body: () throws -> T) throws -> T { try transaction("BEGIN", body) }
        private func transaction<T>(_ begin: String, _ body: () throws -> T) throws -> T {
            try exec(begin)
            do {
                let value = try body()
                try exec("COMMIT")
                return value
            } catch {
                try? exec("ROLLBACK")
                throw error
            }
        }
    }
}
