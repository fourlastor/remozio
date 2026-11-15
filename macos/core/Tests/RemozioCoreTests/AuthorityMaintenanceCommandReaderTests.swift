import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Real SQLite reads over synthetic protected records. No installed Root factory or stop authority is exercised.
final class AuthorityMaintenanceCommandReaderTests: XCTestCase {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private typealias Request = AuthorityMaintenanceChannelRequest
    private func data(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    private func fixture(phase: Record.Phase = .draining, service: Record.ServiceOutcome = .notStopped,
        gateIncarnation: Data? = nil, bound: Bool = true, _ body: (RuntimeMaintenanceReaderFixture, Record, PreparationFileIdentity) throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceReaderFixture { f in
            let snapshot = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let gate = try XCTUnwrap(snapshot.admission.accounts.first { $0.accountID == f.authority.accountID }).identity
            let scope = try Record.Scope(macID: snapshot.inventory.macID, installationID: snapshot.inventory.installationID,
                authority: f.authority, target: .init(accountID: data(92), ownerUID: 65001, directoryID: data(93)),
                releaseDigest: snapshot.inventory.releaseDigest, candidateDigest: data(2, 32), authorityPolicyDigest: data(3, 32),
                operationDigest: data(4, 32), restorationDigest: data(5, 32), mutationFootprintDigest: data(6, 32),
                authorityGrantDigest: data(7, 32), targetConsentDigest: data(8, 32), administratorIntentDigest: data(9, 32))
            let readback = try gateIncarnation.map { try Record.GateReadback(attemptID: data(90), requestRevision: bound ? data(80) : data(91),
                identity: gate, authorityIncarnation: $0, challenge: data(6), responseDigest: data(9, 32), hold: .held, admission: .busy) }
            let binding = try bound ? AuthorityMaintenanceBinding(accountID: f.authority.accountID, attemptID: data(90),
                revision: data(80), incarnation: gateIncarnation ?? data(4), connectionID: data(5)) : nil
            let record = try Record(id: data(90), revision: data(91), purpose: .retainedRuntime, scope: scope, phase: phase,
                service: service, failure: phase == .needsOwnerRecovery ? .repairRequired : nil, gate: readback, shutdownBinding: binding)
            try f.edit([RuntimeMaintenanceWindowStorage.createSQL, "PRAGMA user_version=29",
                "INSERT INTO runtime_maintenance_windows_v1 VALUES(X'\(hex(f.authority.accountID))',X'\(hex(record.id))',X'\(hex(record.revision))',\(phase.rawValue),X'\(try hex(record.encoded))')"])
            try body(f, record, gate)
        }
    }
    private func request(_ record: Record, gate: PreparationFileIdentity, action: Request.Action = .open,
        installation: Data? = nil, attempt: Data? = nil, revision: Data? = nil, incarnation: Data? = nil,
        bindingRevision: Data? = nil) throws -> Request {
        let current = revision ?? ([.open, .reopen].contains(action) ? record.revision : record.shutdownBinding?.revision ?? record.revision), attempt = attempt ?? record.id
        let binding = try action == .open ? nil : AuthorityMaintenanceBinding(accountID: record.scope.authority.accountID,
            attemptID: attempt, revision: bindingRevision ?? record.shutdownBinding?.revision ?? current, incarnation: incarnation ?? data(4), connectionID: data(5))
        return try .init(action: action, accountID: record.scope.authority.accountID, attemptID: attempt, revision: current,
            installationID: installation ?? record.scope.installationID, gate: gate, binding: binding, challenge: data(6, 32))
    }
    private func read(_ f: RuntimeMaintenanceReaderFixture, _ q: Request, account: Record.Account? = nil,
        incarnation: Data? = nil, armed: AuthorityMaintenanceBinding? = nil) throws -> Record {
        try f.machine().runtimeMaintenanceCommandRecord(q, account: account ?? f.authority,
            incarnation: incarnation ?? data(4), armedBinding: armed, candidate: f.candidate)
    }
    func testCommandReadsExactlyOneProtectedFrameInOneReadTransaction() throws {
        try fixture { f, record, gate in
            var reads: [PreparationIntentStore.InitialRuntimeRead] = []
            f.machine().observeStoreRead = { reads.append($0) }; defer { f.machine().observeStoreRead = nil }
            XCTAssertEqual(try read(f, request(record, gate: gate)), record)
            XCTAssertEqual(reads.filter { $0 == .readTransaction }.count, 1)
            XCTAssertEqual(reads.filter { $0 == .frame }.count, 1); XCTAssertFalse(reads.contains(.writeTransaction))
        }
    }
    func testInstallationAndActualRegisteredGateMustMatchTheRequest() throws {
        try fixture { f, record, gate in
            XCTAssertThrowsError(try read(f, request(record, gate: gate, installation: data(99))))
            for foreign in [PreparationFileIdentity(device: gate.device, inode: gate.inode + 1), .init(device: gate.device + 1, inode: gate.inode)] {
                XCTAssertThrowsError(try read(f, request(record, gate: foreign)))
            }
            XCTAssertEqual(try read(f, request(record, gate: gate)), record)
        }
    }
    func testAttemptRevisionAndLocalIncarnationCannotBeAdoptedFromTheReadback() throws {
        try fixture { f, record, gate in
            XCTAssertThrowsError(try read(f, request(record, gate: gate, attempt: data(99))))
            XCTAssertThrowsError(try read(f, request(record, gate: gate, revision: data(99))))
            XCTAssertThrowsError(try read(f, request(record, gate: gate, action: .observe, incarnation: data(99))))
            XCTAssertThrowsError(try read(f, request(record, gate: gate), incarnation: data(4, 15)))
        }
    }
    func testAccountOwnerAndDirectoryMustMatchTheActualPreparation() throws {
        try fixture { f, record, gate in
            let otherUID = try Record.Account(accountID: f.authority.accountID, ownerUID: f.authority.ownerUID + 1, directoryID: f.authority.directoryID)
            let otherDirectory = try Record.Account(accountID: f.authority.accountID, ownerUID: f.authority.ownerUID, directoryID: data(99))
            let otherAccount = try Record.Account(accountID: data(99), ownerUID: f.authority.ownerUID, directoryID: f.authority.directoryID)
            for account in [otherUID, otherDirectory, otherAccount] { XCTAssertThrowsError(try read(f, request(record, gate: gate), account: account)) }
        }
    }
    func testDrainingAllowsOnlyOpenObserveArmAndCancel() throws {
        try fixture { f, record, gate in
            for action in [Request.Action.open, .observe, .arm, .cancel] { XCTAssertEqual(try read(f, request(record, gate: gate, action: action)), record) }
            let reopen = try request(record, gate: gate, action: .reopen)
            XCTAssertThrowsError(try read(f, reopen, armed: reopen.binding))
        }
    }
    func testStoppingRefusesEveryActionIncludingCancelAndReopen() throws {
        try fixture(phase: .stopping) { f, record, gate in
            for action in Request.Action.allCases {
                let q = try request(record, gate: gate, action: action); XCTAssertThrowsError(try read(f, q, armed: q.binding))
            }
        }
    }
    func testPrestopReopenUsesTheExactSavedBindingInsteadOfTheCurrentWindowRevision() throws {
        try fixture(phase: .reopenPending) { f, record, gate in
            let q = try request(record, gate: gate, action: .reopen, bindingRevision: data(80)), binding = try XCTUnwrap(q.binding)
            XCTAssertNotEqual(q.revision, binding.revision); XCTAssertEqual(try read(f, q, armed: binding), record)
            XCTAssertThrowsError(try read(f, q))
            let other = try AuthorityMaintenanceBinding(accountID: binding.accountID, attemptID: binding.attemptID,
                revision: binding.revision, incarnation: binding.incarnation, connectionID: data(99))
            XCTAssertThrowsError(try read(f, q, armed: other))
            let stale = try request(record, gate: gate, action: .reopen, revision: data(79), bindingRevision: binding.revision)
            XCTAssertEqual(try read(f, stale, armed: binding), record)
            for action in [Request.Action.open, .observe, .arm, .cancel] { XCTAssertThrowsError(try read(f, request(record, gate: gate, action: action))) }
        }
    }
    func testHealthyReopenBelongsToM09AndCannotUseThePrestopReader() throws {
        try fixture(phase: .reopenPending, service: .healthy) { f, record, gate in
            let q = try request(record, gate: gate, action: .reopen, bindingRevision: data(80))
            XCTAssertThrowsError(try read(f, q, armed: q.binding)); XCTAssertThrowsError(try read(f, request(record, gate: gate)))
        }
    }
    func testForeignRetainedIncarnationAndCorruptIndexedColumnsCannotPass() throws {
        try fixture(gateIncarnation: data(99)) { f, record, gate in
            XCTAssertThrowsError(try read(f, request(record, gate: gate)))
            try f.mutate("UPDATE runtime_maintenance_windows_v1 SET revision=randomblob(16)")
            XCTAssertThrowsError(try read(f, request(record, gate: gate)))
        }
    }
    func testMissingRecordClosedStoreAndTransactionReentryStayUnavailable() throws {
        try fixture { f, record, gate in
            let q = try request(record, gate: gate); var refused = false
            f.machine().observeStoreRead = { kind in
                if kind == .readTransaction {
                    do { _ = try self.read(f, q) } catch PreparationStoreError.transactionActive { refused = true } catch { XCTFail("Wrong reentry error") }
                }
            }
            _ = try read(f, q); f.machine().observeStoreRead = nil; XCTAssertTrue(refused)
            try f.mutate("DELETE FROM runtime_maintenance_windows_v1"); XCTAssertThrowsError(try read(f, q))
            try f.machine().close(); XCTAssertThrowsError(try read(f, q))
        }
    }
    func testGateReadbackMustUseTheActualAuthorityClockEpochNotAnotherStartupUUID() throws {
        let clock = try AuthorityClock(), other = try AuthorityClock()
        var epoch = clock.epoch.uuid, foreign = other.epoch.uuid
        let actual = withUnsafeBytes(of: &epoch) { Data($0) }, wrong = withUnsafeBytes(of: &foreign) { Data($0) }
        XCTAssertNotEqual(actual, wrong)
        try fixture(gateIncarnation: actual) { f, record, gate in
            XCTAssertEqual(try read(f, request(record, gate: gate), incarnation: actual), record)
            XCTAssertThrowsError(try read(f, request(record, gate: gate), incarnation: wrong))
        }
    }

    func testAnUnboundVersionOneWindowAllowsOpenButNoBoundAction() throws {
        try fixture(bound: false) { f, record, gate in
            XCTAssertEqual(try read(f, request(record, gate: gate)), record)
            for action in [Request.Action.observe, .arm, .cancel, .reopen] {
                XCTAssertThrowsError(try read(f, request(record, gate: gate, action: action)))
            }
        }
    }
    func testObserveArmAndCancelUseTheSavedRevisionAndRefuseANewConnectionBinding() throws {
        try fixture { f, record, gate in
            let saved = try XCTUnwrap(record.shutdownBinding)
            XCTAssertNotEqual(record.revision, saved.revision)
            XCTAssertEqual(try read(f, request(record, gate: gate)), record)
            for action in [Request.Action.observe, .arm, .cancel] {
                XCTAssertEqual(try read(f, request(record, gate: gate, action: action)), record)
                XCTAssertThrowsError(try read(f, request(record, gate: gate, action: action, bindingRevision: record.revision)))
                for index in 0..<5 {
                    XCTAssertThrowsError(try {
                        let bad = try AuthorityMaintenanceBinding(accountID: index == 0 ? self.data(99) : saved.accountID,
                            attemptID: index == 1 ? self.data(99) : saved.attemptID, revision: index == 2 ? self.data(99) : saved.revision,
                            incarnation: index == 3 ? self.data(99) : saved.incarnation, connectionID: index == 4 ? self.data(99) : saved.connectionID)
                        let q = try Request(action: action, accountID: saved.accountID, attemptID: saved.attemptID,
                            revision: saved.revision, installationID: record.scope.installationID, gate: gate,
                            binding: bad, challenge: self.data(6, 32))
                        _ = try self.read(f, q)
                    }())
                }
            }
        }
    }

}
