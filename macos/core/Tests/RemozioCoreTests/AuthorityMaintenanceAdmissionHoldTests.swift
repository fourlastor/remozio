import Darwin
import Dispatch
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Actual owned gates and SQLite reads exercise the local hold. Peer verification is synthetic, not installed Root evidence.
final class AuthorityMaintenanceAdmissionHoldTests: XCTestCase {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private typealias Request = AuthorityMaintenanceChannelRequest
    private final class Reader: @unchecked Sendable {
        let fixture: RuntimeMaintenanceReaderFixture
        let admission: AuthorityMaintenancePairingAdmission
        let incarnation: Data
        init(_ fixture: RuntimeMaintenanceReaderFixture, admission: AuthorityMaintenancePairingAdmission, incarnation: Data) {
            self.fixture = fixture; self.admission = admission; self.incarnation = incarnation
        }
        func read(_ q: Request) throws -> Record {
            let target: AuthorityMaintenanceBinding?
            if q.action == .reopen, let binding = q.binding {
                _ = try admission.reopenTarget(matching: binding); target = binding
            } else { target = nil }
            return try fixture.machine().runtimeMaintenanceCommandRecord(q, account: fixture.authority,
                incarnation: incarnation, armedBinding: target, candidate: fixture.candidate)
        }
    }
    private final class LegacyReader: @unchecked Sendable {
        let fixture: BoundAdmissionRegistrationFixture
        init(_ fixture: BoundAdmissionRegistrationFixture) { self.fixture = fixture }
    }
    private func data(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    private func call(_ e: AuthorityMaintenanceXPCEndpoint, _ q: Request) throws -> AuthorityMaintenanceChannelResponse {
        let done = DispatchSemaphore(value: 0), result = Mutex<Data?>(nil)
        e.exchange(try q.encoded) { bytes in result.withLock { $0 = bytes }; done.signal() }
        XCTAssertEqual(done.wait(timeout: .now() + 3), .success)
        return try .decode(XCTUnwrap(result.withLock { $0 }), expected: q)
    }
    func testActualStartupHoldAndAuthenticatedSavedTargetReopenAdmitWithoutRestartOrOpen() throws {
        try MachineUpdateReplacementTests.withMaintenanceReaderFixture(releasingRestartAdmission: true) { f in
            let before = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let gate = try XCTUnwrap(before.admission.accounts.first { $0.accountID == f.authority.accountID }).identity
            let incarnation = data(4), admission = try AuthorityMaintenancePairingAdmission(accountID: f.authority.accountID, incarnation: incarnation)
            let original = try admission.openConnection(attemptID: data(90), revision: data(80))
            _ = try original.blockNewStages(matching: original.binding)
            _ = try original.transferToShutdown(matching: original.binding)
            let binding = original.binding; original.close()
            let scope = try Record.Scope(macID: before.inventory.macID, installationID: before.inventory.installationID,
                authority: f.authority, target: .init(accountID: data(92), ownerUID: 65001, directoryID: data(93)),
                releaseDigest: before.inventory.releaseDigest, candidateDigest: data(1, 32), authorityPolicyDigest: data(2, 32),
                operationDigest: data(3, 32), restorationDigest: data(4, 32), mutationFootprintDigest: data(5, 32),
                authorityGrantDigest: data(6, 32), targetConsentDigest: data(7, 32), administratorIntentDigest: data(8, 32))
            let row = try Record(id: binding.attemptID, revision: data(91), purpose: .retainedRuntime, scope: scope,
                phase: .reopenPending, service: .notStopped, shutdownBinding: binding)
            try f.edit([RuntimeMaintenanceWindowStorage.createSQL, "PRAGMA user_version=29",
                "INSERT INTO runtime_maintenance_windows_v1 VALUES(X'\(hex(f.authority.accountID))',X'\(hex(row.id))',X'\(hex(row.revision))',\(row.phase.rawValue),X'\(try hex(row.encoded))')"])
            let path = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent(), anchor = path.deletingLastPathComponent().path
            func directory() throws -> ReleaseDestinationLease { try .init(anchor: anchor, relativeDirectory: path.lastPathComponent, owner: getuid()) }
            let reader = Reader(f, admission: admission, incarnation: incarnation)
            let activity = try ReleaseActivityBarrier(directory: directory(), owner: getuid())
            let startup = try XCTUnwrap(AuthorityUpdateAdmissionStartup.capture(machine: f.machine(), macID: before.inventory.macID,
                installationID: before.inventory.installationID, accountID: f.authority.accountID, activity: activity, candidate: f.candidate,
                readCurrent: { try reader.fixture.machine().updateAdmissionState(candidate: reader.fixture.candidate) }, readMaintenance: { machine in
                    machine.runtimeMaintenanceStartupProjection(account: reader.fixture.authority, candidate: reader.fixture.candidate)
                }, openBarrier: { scope, identity in
                    try .init(directory: directory(), owner: getuid(), expected: identity, scope: scope)
                }))
            let hold = try XCTUnwrap(startup.maintenanceHold)
            XCTAssertThrowsError(try startup.boundary.acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
            let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: admission,
                check: { _ = try reader.read($0) }, observe: { _ in XCTFail("Recovery must not open a new reservation"); throw RuntimePreparationError.changedScope },
                reopen: { q, release in
                    let record = try reader.read(q), target = try XCTUnwrap(q.binding)
                    try hold.reopen(record, binding: target, incarnation: incarnation) {
                        try release(); XCTAssertEqual(try reader.read(q), record)
                    }
                })
            let verified = Mutex(0), endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access,
                budget: .init(maximum: 1), verify: { verified.withLock { $0 += 1 } })
            defer { endpoint.close(); startup.recovery.close(); hold.close() }
            let hello = DispatchSemaphore(value: 0)
            endpoint.hello { version in XCTAssertEqual(version, AuthorityMaintenanceChannelScope.protocolVersion); hello.signal() }
            XCTAssertEqual(hello.wait(timeout: .now() + 3), .success)
            let q = try Request(action: .reopen, accountID: f.authority.accountID, attemptID: row.id, revision: row.revision,
                installationID: scope.installationID, gate: gate, binding: binding, challenge: data(6, 32))
            let rows = try runtimeMaintenanceFixtureRows(f.databasePath)
            XCTAssertEqual(try admission.connectionReservations(), 0)
            XCTAssertEqual(try call(endpoint, q).outcome, .applied)
            XCTAssertEqual(try admission.connectionReservations(), 0)
            let fresh = try startup.boundary.acquireAdmission(); try fresh.validate(); fresh.close()
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
            XCTAssertGreaterThanOrEqual(verified.withLock { $0 }, 2)
            endpoint.close()
            let retryEndpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1))
            defer { retryEndpoint.close() }
            let foreign = try UpdateAdmissionBarrier(directory: directory(), owner: getuid(), expected: gate,
                scope: .account(f.authority.accountID)).beginDrain()
            XCTAssertThrowsError(try startup.boundary.acquireAdmission())
            XCTAssertEqual(try call(retryEndpoint, q).outcome, .applied)
            XCTAssertThrowsError(try startup.boundary.acquireAdmission())
            try foreign.validate(); foreign.close()
            let afterRetry = try startup.boundary.acquireAdmission(); afterRetry.close()
            XCTAssertEqual(try admission.connectionReservations(), 0)
        }
    }
    private enum Fault: Error { case injected }
    private func ownedHoldFixture(_ body: (AuthorityMaintenanceAdmissionHold, Record, AuthorityMaintenanceBinding,
        UpdateAdmissionRegistrationRecord) throws -> Void) throws {
        let authority = try Record.Account(accountID: data(1), ownerUID: 501, directoryID: data(2))
        let scope = try Record.Scope(macID: data(3), installationID: data(4), authority: authority,
            target: .init(accountID: data(5), ownerUID: 1501, directoryID: data(6)), releaseDigest: data(1, 32),
            candidateDigest: data(2, 32), authorityPolicyDigest: data(3, 32), operationDigest: data(4, 32),
            restorationDigest: data(5, 32), mutationFootprintDigest: data(6, 32), authorityGrantDigest: data(7, 32),
            targetConsentDigest: data(8, 32), administratorIntentDigest: data(9, 32))
        let binding = try AuthorityMaintenanceBinding(accountID: authority.accountID, attemptID: data(10),
            revision: data(11), incarnation: data(12), connectionID: data(13))
        let row = try Record(id: binding.attemptID, revision: data(14), purpose: .retainedRuntime, scope: scope,
            phase: .reopenPending, service: .notStopped, shutdownBinding: binding)
        let registration = try UpdateAdmissionRegistrationRecord(macID: scope.macID, installationID: scope.installationID,
            machine: .init(device: 1, inode: 2), accounts: [.init(accountID: authority.accountID, identity: .init(device: 1, inode: 3))],
            designatedOwner: nil)
        let projection = try RuntimeMaintenanceAdmissionProjection(record: row, macID: scope.macID,
            installationID: scope.installationID, account: authority, registration: registration)
        try body(.init(projection: projection), row, binding, registration)
    }
    func testFailedPairingReleaseCannotOpenTheLocalHold() throws {
        try ownedHoldFixture { hold, row, binding, _ in
            var calls = 0
            XCTAssertThrowsError(try hold.reopen(row, binding: binding, incarnation: binding.incarnation) {
                calls += 1; throw Fault.injected
            })
            XCTAssertEqual(calls, 1); XCTAssertThrowsError(try hold.requireOpen())
            try hold.reopen(row, binding: binding, incarnation: binding.incarnation, releaseBinding: {})
            XCTAssertNoThrow(try hold.requireOpen())
        }
    }
    func testChangedBindingAndIncarnationCannotReleaseOrInvokeTheCallback() throws {
        try ownedHoldFixture { hold, row, binding, _ in
            for field in 0..<5 {
                var fields = [binding.accountID, binding.attemptID, binding.revision, binding.incarnation, binding.connectionID]
                fields[field] = data(99)
                let foreign = try AuthorityMaintenanceBinding(accountID: fields[0], attemptID: fields[1], revision: fields[2],
                    incarnation: fields[3], connectionID: fields[4])
                XCTAssertThrowsError(try hold.reopen(row, binding: foreign, incarnation: binding.incarnation) { XCTFail("Foreign release") })
            }
            XCTAssertThrowsError(try hold.reopen(row, binding: binding, incarnation: data(99)) { XCTFail("Foreign incarnation") })
            XCTAssertThrowsError(try hold.requireOpen())
        }
    }
    func testHealthyAndWrongPhaseCannotUseThePrestopRelease() throws {
        try ownedHoldFixture { hold, row, binding, _ in
            let healthy = try Record(id: row.id, revision: row.revision, purpose: row.purpose, scope: row.scope,
                phase: .reopenPending, service: .healthy, shutdownBinding: binding)
            let draining = try Record(id: row.id, revision: row.revision, purpose: row.purpose, scope: row.scope,
                phase: .draining, service: .notStopped, shutdownBinding: binding)
            for wrong in [healthy, draining] {
                XCTAssertThrowsError(try hold.reopen(wrong, binding: binding, incarnation: binding.incarnation) { XCTFail("Wrong phase release") })
            }
            XCTAssertThrowsError(try hold.requireOpen())
        }
    }
    func testUnreadableStartupAndClosedOwnerStayClosed() throws {
        try ownedHoldFixture { hold, row, binding, _ in
            let unknown = AuthorityMaintenanceAdmissionHold(projection: .startup { throw Fault.injected })
            XCTAssertThrowsError(try unknown.reopen(row, binding: binding, incarnation: binding.incarnation) { XCTFail("Unknown release") })
            XCTAssertThrowsError(try unknown.requireOpen())
            hold.close()
            XCTAssertThrowsError(try hold.reopen(row, binding: binding, incarnation: binding.incarnation) { XCTFail("Closed release") })
            XCTAssertThrowsError(try hold.requireOpen())
        }
    }

    func testLegacySchema16StartupHasNoWindowAndDoesNotRequireAStableUpdate() throws {
        let f = try BoundAdmissionRegistrationFixture(); _ = try f.prepare()
        let inventory = try XCTUnwrap(f.machine.store.inventory()), account = try XCTUnwrap(inventory.accounts.first)
        let a = try Record.Account(accountID: account.accountID, ownerUID: account.ownerUID, directoryID: data(9))
        let before = try runtimeMaintenanceFixtureRows(f.machinePath + "/installation.sqlite")
        XCTAssertEqual(try f.machine.f.f.sql("PRAGMA user_version"), 16)
        let value = f.machine.store.runtimeMaintenanceStartupProjection(account: a, candidate: f.machine.release)
        XCTAssertFalse(value.requiresLocalHold); XCTAssertFalse(value.needsOwnerRecovery)
        let reader = LegacyReader(f)
        let startup = try XCTUnwrap(AuthorityUpdateAdmissionStartup.capture(machine: f.machine.store, macID: inventory.macID,
            installationID: inventory.installationID, accountID: account.accountID, activity: f.activity(), candidate: f.machine.release,
            readCurrent: { try reader.fixture.machine.store.updateAdmissionState(candidate: reader.fixture.machine.release) },
            readMaintenance: { machine in
                machine.runtimeMaintenanceStartupProjection(account: a, candidate: reader.fixture.machine.release)
            }, openBarrier: { scope, identity in
                try .init(directory: f.directory(), owner: getuid(), expected: identity, scope: scope)
            }))
        defer { startup.recovery.close(); startup.maintenanceHold?.close() }
        let admitted = try startup.boundary.acquireAdmission(); try admitted.validate(); admitted.close()
        XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.machinePath + "/installation.sqlite"), before)
    }
    func testLegacyStartupStillRefusesForeignAccountScope() throws {
        let f = try BoundAdmissionRegistrationFixture(); _ = try f.prepare()
        let inventory = try XCTUnwrap(f.machine.store.inventory()), account = try XCTUnwrap(inventory.accounts.first)
        let wrong = try Record.Account(accountID: account.accountID, ownerUID: account.ownerUID + 1, directoryID: data(9))
        let value = f.machine.store.runtimeMaintenanceStartupProjection(account: wrong, candidate: f.machine.release)
        XCTAssertTrue(value.requiresLocalHold); XCTAssertTrue(value.needsOwnerRecovery)
    }

    func testMaintenanceTableOnLegacySchemaRefusesInsteadOfIgnoringItsPresence() throws {
        let f = try BoundAdmissionRegistrationFixture(); _ = try f.prepare()
        let inventory = try XCTUnwrap(f.machine.store.inventory()), account = try XCTUnwrap(inventory.accounts.first)
        let a = try Record.Account(accountID: account.accountID, ownerUID: account.ownerUID, directoryID: data(9))
        try f.machine.sql(RuntimeMaintenanceWindowStorage.createSQL)
        XCTAssertEqual(try f.machine.f.f.sql("PRAGMA user_version"), 16)
        let value = f.machine.store.runtimeMaintenanceStartupProjection(account: a, candidate: f.machine.release)
        XCTAssertTrue(value.requiresLocalHold); XCTAssertTrue(value.needsOwnerRecovery)
    }
    func testUnknownFutureSchemaCannotOpenTheLocalHold() throws {
        let f = try BoundAdmissionRegistrationFixture(); _ = try f.prepare()
        let inventory = try XCTUnwrap(f.machine.store.inventory()), account = try XCTUnwrap(inventory.accounts.first)
        let a = try Record.Account(accountID: account.accountID, ownerUID: account.ownerUID, directoryID: data(9))
        try f.machine.sql("PRAGMA user_version=30")
        let value = f.machine.store.runtimeMaintenanceStartupProjection(account: a, candidate: f.machine.release)
        XCTAssertTrue(value.requiresLocalHold); XCTAssertTrue(value.needsOwnerRecovery)
    }

    func testOpenCancelAndExplicitPendingWriteRequireReopenBeforeAdmission() throws {
        try MachineUpdateReplacementTests.withMaintenanceReaderFixture(releasingRestartAdmission: true) { f in
            let before = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let gate = try XCTUnwrap(before.admission.accounts.first { $0.accountID == f.authority.accountID }).identity
            let incarnation = data(4), admission = try AuthorityMaintenancePairingAdmission(accountID: f.authority.accountID, incarnation: incarnation)
            let binding = try AuthorityMaintenanceBinding(accountID: f.authority.accountID, attemptID: data(90),
                revision: data(80), incarnation: incarnation, connectionID: data(5))
            let scope = try Record.Scope(macID: before.inventory.macID, installationID: before.inventory.installationID,
                authority: f.authority, target: .init(accountID: data(92), ownerUID: 65001, directoryID: data(93)),
                releaseDigest: before.inventory.releaseDigest, candidateDigest: data(1, 32), authorityPolicyDigest: data(2, 32),
                operationDigest: data(3, 32), restorationDigest: data(4, 32), mutationFootprintDigest: data(5, 32),
                authorityGrantDigest: data(6, 32), targetConsentDigest: data(7, 32), administratorIntentDigest: data(8, 32))
            let row = try Record(id: binding.attemptID, revision: data(91), purpose: .retainedRuntime, scope: scope,
                phase: .draining, service: .notStopped)
            try f.edit([RuntimeMaintenanceWindowStorage.createSQL, "PRAGMA user_version=29",
                "INSERT INTO runtime_maintenance_windows_v1 VALUES(X'\(hex(f.authority.accountID))',X'\(hex(row.id))',X'\(hex(row.revision))',\(row.phase.rawValue),X'\(try hex(row.encoded))')"])
            let path = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent(), anchor = path.deletingLastPathComponent().path
            func directory() throws -> ReleaseDestinationLease { try .init(anchor: anchor, relativeDirectory: path.lastPathComponent, owner: getuid()) }
            let reader = Reader(f, admission: admission, incarnation: incarnation)
            let activity = try ReleaseActivityBarrier(directory: directory(), owner: getuid())
            let startup = try XCTUnwrap(AuthorityUpdateAdmissionStartup.capture(machine: f.machine(), macID: before.inventory.macID,
                installationID: before.inventory.installationID, accountID: f.authority.accountID, activity: activity, candidate: f.candidate,
                readCurrent: { try reader.fixture.machine().updateAdmissionState(candidate: reader.fixture.candidate) }, readMaintenance: { machine in
                    machine.runtimeMaintenanceStartupProjection(account: reader.fixture.authority, candidate: reader.fixture.candidate)
                }, openBarrier: { scope, identity in
                    try .init(directory: directory(), owner: getuid(), expected: identity, scope: scope)
                }))
            let hold = try XCTUnwrap(startup.maintenanceHold)
            XCTAssertThrowsError(try startup.boundary.acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
            let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: admission,
                check: { q in let actual = try reader.read(q); if q.action == .open { try hold.retain(actual) } }, observe: { q in
                    guard q.action == .open else { throw RuntimePreparationError.changedScope }
                    return try .init(journal: .init(requests: .init(liveRequests: 0, commandCaptures: 0, activityOwners: 0),
                        exchanges: .init(active: 0, stopped: false), nativeExecutions: 0, executionActivityOwners: 0),
                        execution: .init(started: true, stopping: false, failed: false, queuedTurns: 0, rejectedTurns: 0),
                        pairing: .init(ready: true, stagedAttempts: 0, activityOwners: 0, operationActive: false))
                },
                reopen: { q, release in
                    let record = try reader.read(q), target = try XCTUnwrap(q.binding)
                    try hold.reopen(record, binding: target, incarnation: incarnation) {
                        try release(); XCTAssertEqual(try reader.read(q), record)
                    }
                })
            let verified = Mutex(0), endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access,
                budget: .init(maximum: 1), verify: { verified.withLock { $0 += 1 } })
            defer { endpoint.close(); startup.recovery.close(); hold.close() }
            let hello = DispatchSemaphore(value: 0)
            endpoint.hello { version in XCTAssertEqual(version, AuthorityMaintenanceChannelScope.protocolVersion); hello.signal() }
            XCTAssertEqual(hello.wait(timeout: .now() + 3), .success)
            let open = try Request(action: .open, accountID: f.authority.accountID, attemptID: row.id, revision: row.revision,
                installationID: scope.installationID, gate: gate, binding: nil, challenge: data(6, 32))
            let opened = try call(endpoint, open); XCTAssertEqual(opened.outcome, .applied)
            let saved = opened.binding
            XCTAssertEqual(try admission.connectionReservations(), 1)
            let bound = try row.retainingShutdownBinding(saved)
            func persist(_ value: Record) throws {
                // Explicit owned SQL stands for the future native client's durable window writer.
                try f.mutate("UPDATE runtime_maintenance_windows_v1 SET revision=X'\(hex(value.revision))',phase=\(value.phase.rawValue),record=X'\(try hex(value.encoded))'")
            }
            try persist(bound)
            let cancel = try Request(action: .cancel, accountID: f.authority.accountID, attemptID: row.id, revision: saved.revision,
                installationID: scope.installationID, gate: gate, binding: saved, challenge: data(7, 32))
            XCTAssertEqual(try call(endpoint, cancel).outcome, .applied)
            XCTAssertEqual(try admission.connectionReservations(), 0)
            XCTAssertThrowsError(try startup.boundary.acquireAdmission())
            let pending = try Record(id: row.id, revision: AccountPreparationIntent.randomID(), purpose: row.purpose, scope: row.scope,
                phase: .reopenPending, service: .notStopped, shutdownBinding: saved)
            try persist(pending)
            XCTAssertThrowsError(try startup.boundary.acquireAdmission())
            endpoint.close()
            let recovery = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1))
            defer { recovery.close() }
            let reopen = try Request(action: .reopen, accountID: f.authority.accountID, attemptID: row.id, revision: pending.revision,
                installationID: scope.installationID, gate: gate, binding: saved, challenge: data(8, 32))
            let unchanged = try runtimeMaintenanceFixtureRows(f.databasePath)
            XCTAssertEqual(try call(recovery, reopen).outcome, .applied)
            XCTAssertEqual(try admission.connectionReservations(), 0)
            let fresh = try startup.boundary.acquireAdmission(); try fresh.validate(); fresh.close()
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), unchanged)
        }
    }
    func testLegacyCatalogSchemas16Through28KeepAdmissionOpen() throws {
        try MachineUpdateReplacementTests.withMaintenanceReaderFixture(releasingRestartAdmission: true) { f in
            let reader = Reader(f, admission: try .init(accountID: f.authority.accountID, incarnation: data(4)), incarnation: data(4))
            let path = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent(), anchor = path.deletingLastPathComponent().path
            func directory() throws -> ReleaseDestinationLease { try .init(anchor: anchor, relativeDirectory: path.lastPathComponent, owner: getuid()) }
            // The fixture uses canonical catalogs, not upgrades from historical releases.
            // At schemas 16...23 the activation is absent. A completed activation is valid only at schema 24 or later.
            let tables: [Int: String] = [28: "retained_setup_promotion_ready_v1", 27: "retained_setup_promotion_intents_v1",
                26: "retained_setup_completion_intents_v1", 25: "retained_setup_policy_intents_v1", 24: "stable_release_state_v1",
                23: "installed_release_state_v1", 22: "machine_update_completion_publication_v1", 21: "machine_update_completion_intent_v1",
                20: "machine_update_backend_epoch_v1", 19: "machine_update_configuration_epoch_v1", 18: "machine_update_replacement_v1",
                17: "machine_update_activation_v1"]
            XCTAssertEqual(Set(tables.keys).union([16]), Set(16...28))
            for version in stride(from: 28, through: 16, by: -1) {
                XCTAssertEqual(try runtimeMaintenanceFixtureSchemaVersion(f.databasePath), Int64(version))
                let before = try runtimeMaintenanceFixtureRows(f.databasePath)
                let projection = f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate)
                guard !projection.requiresLocalHold else { XCTFail("Valid legacy schema \(version) retained a hold"); return }
                XCTAssertFalse(projection.needsOwnerRecovery)
                let inventory = try XCTUnwrap(f.machine().inventory())
                let startup = try XCTUnwrap(AuthorityUpdateAdmissionStartup.capture(machine: f.machine(), macID: inventory.macID,
                    installationID: inventory.installationID, accountID: f.authority.accountID,
                    activity: .init(directory: directory(), owner: getuid()), candidate: f.candidate,
                    readCurrent: { try reader.fixture.machine().updateAdmissionState(candidate: reader.fixture.candidate) },
                    readMaintenance: { machine in machine.runtimeMaintenanceStartupProjection(account: reader.fixture.authority, candidate: reader.fixture.candidate) },
                    openBarrier: { scope, identity in try .init(directory: directory(), owner: getuid(), expected: identity, scope: scope) }))
                let fresh = try startup.boundary.acquireAdmission(); try fresh.validate(); fresh.close()
                startup.recovery.close(); startup.maintenanceHold?.close()
                XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), before)
                if version > 16 {
                    var edits = ["DROP TABLE " + (try XCTUnwrap(tables[version])), "PRAGMA user_version=\(version - 1)"]
                    if version == 24 { edits.insert("DELETE FROM machine_update_activation_v1", at: 0) }
                    try f.edit(edits)
                }
            }
        }
    }

}
