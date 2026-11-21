import Darwin
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceUnboundOperationTests: XCTestCase, @unchecked Sendable {
    private func fixture(startupHeld: Bool = true, _ body: (UnboundAuthorityMachine) throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { writer in
            let source = try writer.machine().stableRuntimeSource(candidate: writer.candidate)
            let target = try XCTUnwrap(source.preparations.first { $0.accountID == writer.target.accountID })
            let f = RuntimeMaintenanceReaderFixture(machine: writer.machine, candidate: writer.candidate,
                account: target, authority: writer.authority, databasePath: writer.databasePath,
                reopen: { try writer.reopen(nil) }, edit: writer.edit)
            try AuthorityMaintenanceUnboundRequest.requireFormats(f.candidate)
            try RuntimeMaintenanceWindowStorage.requireReaderFormats(f.candidate, recordVersions: [1, 3])
            let owner = try UnboundAuthorityMachine(f, startupHeld: startupHeld); defer { owner.close() }; try body(owner)
        }
    }
    func testChangingOnlyTheRequestIncarnationTouchesNoStoreHoldOrAdmission() throws {
        try fixture { owner in
            let operation = try owner.operation(), before = try runtimeMaintenanceFixtureRows(owner.fixture.databasePath)
            let original = try owner.records.request(.release)
            let limits = try CBORLimits(maxBytes: 1024, maxDepth: 2, maxItems: 32)
            guard case .map(var fields) = try DeterministicCBOR.decode(original.encoded, limits: limits) else { return XCTFail() }
            fields[10] = .bytes(unboundAuthorityBytes(99))
            let changed = try AuthorityMaintenanceUnboundRequest.decode(DeterministicCBOR.encode(.map(fields), limits: limits))
            XCTAssertNotEqual(changed.authorityIncarnation, original.authorityIncarnation)
            XCTAssertThrowsError(try operation.release(changed)); XCTAssertEqual(owner.reads.withLock { $0 }, 0)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(owner.fixture.databasePath), before)
            XCTAssertEqual(try owner.hold.unboundObservation(owner.records.pending, incarnation: unboundAuthorityBytes(41)), .held)
            XCTAssertThrowsError(try owner.startup.boundary.acquireAdmission())
            XCTAssertEqual(try owner.admission.connectionReservations(), 0); XCTAssertEqual(try owner.admission.stagedReservations(), 0)
        }
    }
    func testActualReleaseDuplicateAndFreshOrdinaryGateObservationLeaveSQLiteUnchanged() throws {
        try fixture { owner in
            let operation = try owner.operation(), before = try runtimeMaintenanceFixtureRows(owner.fixture.databasePath)
            let release = try owner.records.request(.release), gate = try owner.records.request(.gate)
            XCTAssertEqual(try operation.release(release).outcome, .released)
            XCTAssertEqual(try operation.release(release).outcome, .alreadyReleased)
            let observed = try operation.observeGate(gate)
            XCTAssertEqual(observed.request, gate); XCTAssertEqual(observed.hold, .released); XCTAssertEqual(observed.admission, .available)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(owner.fixture.databasePath), before)
            XCTAssertEqual(owner.reads.withLock { $0 }, 6)
        }
    }
    func testNeverHeldSkipsReleaseAndKeepsItsActualGateDisposition() throws {
        try fixture(startupHeld: false) { owner in
            let operation = try owner.operation(), request = try owner.records.request(.gate)
            let observed = try operation.observeGate(request)
            XCTAssertEqual(observed.hold, .neverHeld); XCTAssertEqual(observed.admission, .available)
            XCTAssertThrowsError(try operation.release(owner.records.request(.release)))
            XCTAssertEqual(try operation.observeGate(request).hold, .neverHeld)
        }
    }
    func testAChangedSecondReadReportsNoSuccessAndDoesNotUndoTheActualRelease() throws {
        try fixture { owner in
            let operation = try owner.operation { count, row in
                if count == 1 {
                    let recovery = try RuntimeMaintenanceWindowRecord(id: row.id, revision: unboundAuthorityBytes(70),
                        purpose: row.purpose, scope: row.scope, phase: .needsOwnerRecovery,
                        failure: .admissionUnconfirmed, unboundRelease: row.unboundRelease)
                    try owner.persist(recovery)
                }
            }
            XCTAssertThrowsError(try operation.release(owner.records.request(.release)))
            try owner.hold.requireOpen()
            XCTAssertEqual(try owner.hold.unboundObservation(owner.records.pending, incarnation: unboundAuthorityBytes(41)), .released)
            let current = try owner.fixture.machine().runtimeMaintenanceStartupWindows(candidate: owner.fixture.candidate)
            XCTAssertEqual(current.first?.phase, .needsOwnerRecovery)
        }
    }
    func testAnotherAccountDrainLeavesThisAccountAvailableAndRetainsItsOwnClosure() throws {
        let files = try UpdateAdmissionTestFixture(), original = try UnboundAuthorityRecords(), otherID = unboundAuthorityBytes(84)
        let id = original.authorized.scope.authority.accountID
        let (account, identity) = try files.provisionAccount(id), (other, otherIdentity) = try files.provisionAccount(otherID)
        let scope = original.authorized.scope
        let registration = try UpdateAdmissionRegistrationRecord(macID: scope.macID, installationID: scope.installationID,
            machine: files.identity, accounts: [.init(accountID: id, identity: identity), .init(accountID: otherID, identity: otherIdentity)],
            designatedOwner: nil)
        let records = try UnboundAuthorityRecords(registration: registration)
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(nil))
        let admission = try AuthorityMaintenancePairingAdmission(accountID: id, incarnation: unboundAuthorityBytes(41))
        let boundary = try UpdateAdmissionBoundary(machine: files.open(), account: account)
        let otherBoundary = try UpdateAdmissionBoundary(machine: files.open(), account: other)
        let operation = try AuthorityMaintenanceUnboundOperation.openOwned(admission: admission, commands: .init(), hold: hold,
            boundary: boundary, accountID: id, gateIdentity: identity, read: { _, _ in records.pending })
        let drain = try other.beginDrain(); defer { drain.close() }
        let observed = try operation.observeGate(records.request(.gate))
        XCTAssertEqual(observed.hold, .neverHeld); XCTAssertEqual(observed.admission, .available)
        XCTAssertThrowsError(try otherBoundary.acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        try drain.validate(); try hold.requireOpen()
    }
    func testThisAccountDrainIsReportedBusyAndIsNotReleased() throws {
        try fixture(startupHeld: false) { owner in
            let drain = try owner.accountObserver.beginDrain(); defer { drain.close() }
            let observed = try owner.operation().observeGate(owner.records.request(.gate))
            XCTAssertEqual(observed.hold, .neverHeld); XCTAssertEqual(observed.admission, .busy); try drain.validate()
        }
    }
    func testACompetingCommandReturnsBusyBeforeAnyProtectedRead() throws {
        try fixture { owner in
            let operation = try owner.operation(), command = try owner.commands.acquire(); defer { command.close() }
            XCTAssertEqual(try operation.release(owner.records.request(.release)).outcome, .busy)
            let request = try owner.records.request(.gate), observed = try operation.observeGate(request)
            XCTAssertEqual(observed.request, request); XCTAssertEqual(observed.hold, .held); XCTAssertEqual(observed.admission, .busy)
            XCTAssertEqual(owner.reads.withLock { $0 }, 0); try command.validate()
        }
    }
    func testWrongGateIdentityRefusesBeforeAnyProtectedRead() throws {
        try fixture { owner in
            let operation = try owner.operation(), request = try owner.records.request(.release,
                gate: .init(device: owner.records.gate.device, inode: owner.records.gate.inode + 1))
            XCTAssertThrowsError(try operation.release(request)); XCTAssertEqual(owner.reads.withLock { $0 }, 0)
            XCTAssertThrowsError(try owner.hold.requireOpen())
        }
    }
    func testReleaseReplyIsCanonicalAndCannotStandForGateAvailability() throws {
        let records = try UnboundAuthorityRecords(), request = try records.request(.release)
        for outcome in [AuthorityMaintenanceUnboundReleaseResponse.Outcome.released, .alreadyReleased, .busy, .refused] {
            let reply = try AuthorityMaintenanceUnboundReleaseResponse(request: request, outcome: outcome)
            XCTAssertEqual(try AuthorityMaintenanceUnboundReleaseResponse.decode(reply.encoded), reply)
            XCTAssertThrowsError(try AuthorityMaintenanceUnboundGateResponse.decode(reply.encoded))
        }
        let reply = try AuthorityMaintenanceUnboundReleaseResponse(request: request, outcome: .released)
        XCTAssertThrowsError(try AuthorityMaintenanceUnboundReleaseResponse.decode(Data([0xb8, 0x04]) + reply.encoded.dropFirst()))
        XCTAssertThrowsError(try AuthorityMaintenanceUnboundReleaseResponse(request: records.request(.gate), outcome: .released))
    }
    func testNewLibraryMessagesDoNotDecodeAsExistingTransportRequests() throws {
        let records = try UnboundAuthorityRecords()
        for kind in [AuthorityMaintenanceUnboundRequest.Kind.release, .gate] {
            let bytes = try records.request(kind).encoded
            XCTAssertThrowsError(try AuthorityMaintenanceChannelRequest.decode(bytes))
            XCTAssertThrowsError(try AuthorityMaintenanceGateRequest.decode(bytes))
        }
    }
    func testStopRefusesReleaseAndPairingBusyRemainsRetryable() async throws {
        try fixture { owner in
            let operation = try owner.operation(), stage = try owner.admission.reserveStage()
            XCTAssertEqual(try operation.release(owner.records.request(.release)).outcome, .busy)
            XCTAssertEqual(try operation.observeGate(owner.records.request(.gate)).hold, .held)
            stage.close(); XCTAssertEqual(try operation.release(owner.records.request(.release)).outcome, .released)
        }
        let commands = AuthorityMaintenanceCommandExclusion(), records = try UnboundAuthorityRecords()
        let files = try UpdateAdmissionTestFixture(), reads = Mutex(0)
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(records.authorized))
        let admission = try AuthorityMaintenancePairingAdmission(accountID: records.authorized.scope.authority.accountID,
            incarnation: unboundAuthorityBytes(41))
        let operation = try AuthorityMaintenanceUnboundOperation.openOwned(admission: admission, commands: commands, hold: hold,
            boundary: .init(machine: files.open()), accountID: records.authorized.scope.authority.accountID, gateIdentity: records.gate,
            read: { _, _ in reads.withLock { $0 += 1 }; return records.pending })
        let stop = try await commands.beginStop(); try stop.validate()
        XCTAssertEqual(try operation.release(records.request(.release)).outcome, .refused)
        XCTAssertEqual(reads.withLock { $0 }, 0)
    }
    func testProtectedStoreProjectionComparisonsRemainStableForTheSameRowsAndDetectChanges() throws {
        try fixture { owner in
            func projection() -> RuntimeMaintenanceAdmissionProjection {
                owner.fixture.machine().runtimeMaintenanceStartupProjection(account: owner.fixture.authority, candidate: owner.fixture.candidate)
            }
            let pending = projection(); XCTAssertFalse(pending.needsOwnerRecovery)
            XCTAssertTrue(pending.requiresLocalHold); XCTAssertEqual(pending, projection())
            let row = owner.records.pending
            let recovery = try RuntimeMaintenanceWindowRecord(id: row.id, revision: unboundAuthorityBytes(85),
                purpose: row.purpose, scope: row.scope, phase: .needsOwnerRecovery,
                failure: .admissionUnconfirmed, unboundRelease: row.unboundRelease)
            try owner.persist(recovery)
            let changed = projection(); XCTAssertNotEqual(changed, pending); XCTAssertTrue(changed.needsOwnerRecovery)
            XCTAssertEqual(changed, projection()); XCTAssertEqual(changed.startupRecord, recovery)
            try owner.persist(row); XCTAssertEqual(pending, projection())
        }
    }

    func testClosedAndClosingPairingOwnersRefuseBeforeAnyProtectedRead() throws {
        for closing in [false, true] {
            try fixture { owner in
                let operation = try owner.operation()
                var shutdown: AuthorityMaintenancePairingAdmission.Shutdown?
                if closing {
                    let connection = try owner.admission.openConnection(attemptID: owner.records.authorized.id,
                        revision: owner.records.authorized.revision)
                    _ = try connection.blockNewStages(matching: connection.binding)
                    shutdown = try connection.transferToShutdown(matching: connection.binding)
                    let marker = try maintenanceCloseMarker(binding: XCTUnwrap(shutdown).binding)
                    try shutdown?.retainCloseMarker(marker); XCTAssertEqual(try owner.admission.claimCloseMarker(), marker)
                } else { owner.admission.close() }
                XCTAssertEqual(try operation.release(owner.records.request(.release)).outcome, .refused)
                let competing = try owner.commands.acquire(); defer { competing.close() }
                XCTAssertEqual(try operation.release(owner.records.request(.release)).outcome, .refused)
                XCTAssertEqual(owner.reads.withLock { $0 }, 0); XCTAssertThrowsError(try owner.hold.requireOpen())
                withExtendedLifetime(shutdown) {}
            }
        }
    }

}
