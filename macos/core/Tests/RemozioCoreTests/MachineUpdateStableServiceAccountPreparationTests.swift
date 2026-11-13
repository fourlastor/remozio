import CryptoKit
import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Real owned SQL and in-memory directory records. They establish no native initialization, OS identity, or service proof.
final class MachineUpdateStableServiceAccountPreparationTests: XCTestCase {
    private typealias Fixture = StableAccountReservationWriterFixture
    private typealias Snapshot = MachineUpdateStableServiceAccountSnapshot
    private typealias Owner = MachineUpdateStableServiceAccountPreparation
    private typealias SQLStage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Fault: Error { case interrupted }
    private final class Directory: ServiceAccountDirectoryAccess {
        let fixture = ServiceAccountDirectoryFixture()
        var reads = 0, validations = 0
        func lookup(kind: ServiceDirectoryKind, index: ServiceDirectoryIndex) throws -> [ServiceDirectoryRecord] {
            reads += 1; return try fixture.lookup(kind: kind, index: index)
        }
        func createGroup(_ claim: ServiceAccountClaim) throws { try fixture.createGroup(claim) }
        func createUser(_ claim: ServiceAccountClaim) throws { try fixture.createUser(claim) }
        func validateGroup(_ claim: ServiceAccountClaim) throws { validations += 1; try fixture.validateGroup(claim) }
        func validateUser(_ claim: ServiceAccountClaim, ownerUID: UInt32) throws {
            validations += 1; try fixture.validateUser(claim, ownerUID: ownerUID)
        }
    }
    private final class CallbackBox: @unchecked Sendable {
        let callback: () throws -> Void
        private let lock = NSLock()
        private var failure: JournalLeaseError?
        init(_ callback: @escaping () throws -> Void) { self.callback = callback }
        func invoke() {
            let caught: JournalLeaseError?
            do { try callback(); caught = nil } catch { caught = error as? JournalLeaseError }
            lock.lock(); failure = caught; lock.unlock()
        }
        func result() -> JournalLeaseError? { lock.lock(); defer { lock.unlock() }; return failure }
    }
    private func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
    private func setup(_ f: Fixture, owner: LocalAccountIdentity? = nil) throws -> MachineUpdateStableAccountSetupSnapshot {
        try f.machine().stableAccountSetupSnapshot(owner: owner ?? f.owner, candidate: f.candidate)
    }
    private func snapshot(_ f: Fixture) throws -> Snapshot {
        try f.machine().stableServiceAccountSnapshot(owner: f.owner, candidate: f.candidate)
    }
    private func fixture(prepared: Bool = true, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withStableAccountReservationWriterFixture { f in
            _ = try f.machine().beginStableAccountPreparation(owner: f.owner, allowedTargetUIDs: [0], disclosureAccepted: true,
                expected: setup(f), candidate: f.candidate, directory: f.directory, admission: f.admission,
                makeInitial: f.initial, verifyScoped: { _, _ in })
            if prepared {
                let pinned = try f.machine().pinStableAccountPreparation(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                    expected: setup(f), candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
                let root = try AccountPreparationController.authorityDirectory(accountID: pinned.accountID)
                let initial = try f.machine().beginStableAccountInitialization(journalPath: root + "/Journal/journal.sqlite",
                    continuityPath: root + "/Continuity/continuity.sqlite", expected: setup(f), candidate: f.candidate,
                    directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
                // This checkpoint is a value fixture. No production initialization writer consumes it.
                let checkpoint = try ContinuityCheckpoint(generation: 1, authorityDigest: Data(repeating: 201, count: 32),
                    ledgerDigest: Data(repeating: 202, count: 32), journalEpoch: initial.initialAuthority.descriptor.epoch,
                    journalHead: 0, authorityGeneration: 1)
                let complete = try initial.advancing(checkpoint: checkpoint, complete: true)
                let value = try pinned.prepared(initialization: complete)
                try f.mutate("UPDATE authority_initialization_v1 SET revision=x'\(hex(complete.revision))',record=x'\(try hex(complete.bytes))' WHERE account=x'\(hex(value.accountID))'")
                try f.mutate("UPDATE account_preparation_v1 SET revision=x'\(hex(value.revision))',record=x'\(try hex(value.bytes))' WHERE owner=\(value.ownerUID)")
            }
            try body(f)
        }
    }
    private func plan(_ account: AccountPreparationIntent, reserved: Set<UInt32>) throws -> ServiceAccountPlan {
        var next: UInt32 = 39999
        return try ServiceAccountAllocator.plan(account: account, reserved: reserved,
            candidate: { next += 1; return next }, available: { _ in true })
    }
    private func resume(_ f: Fixture, directory: Directory, expected: Snapshot? = nil,
        makePlan: ((AccountPreparationIntent, Set<UInt32>) throws -> ServiceAccountPlan)? = nil,
        verify: @escaping (Snapshot) throws -> Void = { _ in },
        didStage: (ServiceAccountPreparation.Stage) throws -> Void = { _ in },
        didSQL: (SQLStage) throws -> Void = { _ in },
        inspect: (ServiceAccountPlanStorage) throws -> Void = { _ in }) throws -> ServiceAccountPlanStorage.State {
        try Owner.resume(machine: f.machine(), expected: expected ?? snapshot(f), candidate: f.candidate,
            directory: f.directory, admission: f.admission, serviceDirectory: directory,
            makePlan: makePlan ?? { try self.plan($0, reserved: $1) }, verifyCurrent: verify,
            didStage: didStage, didStorageStage: didSQL, inspectStorage: inspect)
    }

    func testActualSQLCallbacksBorrowTheExactFrameWithoutReenteringTheMachineReader() throws {
        try fixture { f in
            let before = try snapshot(f), directory = Directory()
            var storage: ServiceAccountPlanStorage?, seen: [SQLStage] = [], completeReads = 0, gateRefusals = 0
            XCTAssertNoThrow(try f.machine().requireRetainedSetupPromotionWriterAvailable())
            let result = try resume(f, directory: directory, verify: { actual in
                try f.admission.validate()
                XCTAssertEqual(actual.setup.source.actual.inventory, before.setup.source.actual.inventory)
            }, didStage: { _ in
                XCTAssertNoThrow(try f.machine().requireRetainedSetupPromotionWriterAvailable())
            }, didSQL: { stage in
                XCTAssertThrowsError(try f.machine().requireRetainedSetupPromotionWriterAvailable()) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                gateRefusals += 1
                seen.append(stage)
                let state = try XCTUnwrap(storage).load()
                if state.complete { completeReads += 1 }
                XCTAssertThrowsError(try f.machine().stableServiceAccountSnapshot(owner: f.owner, candidate: f.candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                if let retained = state.plan {
                    XCTAssertThrowsError(try XCTUnwrap(storage).retain(retained, verify: {})) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                }
            }, inspect: { storage = $0 })
            XCTAssertEqual(seen, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit,
                .beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(completeReads, 2); XCTAssertTrue(result.complete)
            XCTAssertEqual(gateRefusals, 8)
            XCTAssertNoThrow(try f.machine().requireRetainedSetupPromotionWriterAvailable())
            let after = try snapshot(f)
            try after.requirePrepared(from: before)
            XCTAssertEqual(after.state, result); XCTAssertEqual(directory.fixture.writes.count, 4)
            XCTAssertGreaterThan(directory.validations, 0)
        }
    }

    func testCompletedRecoveryValidatesRecordsWithoutRecreatingMissingDirectoryEntries() throws {
        try fixture { f in
            let directory = Directory(), first = try resume(f, directory: directory), before = try snapshot(f)
            let writes = directory.fixture.writes, validations = directory.validations
            var commits = 0
            try f.reopen { commits += 1 }
            XCTAssertEqual(try resume(f, directory: directory, makePlan: { _, _ in
                XCTFail("Completed recovery reached allocation"); throw Fault.interrupted
            }), first)
            XCTAssertEqual(directory.fixture.writes, writes); XCTAssertGreaterThan(directory.validations, validations)
            XCTAssertEqual(commits, 0)
            directory.fixture.users.removeFirst()
            XCTAssertThrowsError(try resume(f, directory: directory)) {
                XCTAssertEqual($0 as? ServiceAccountProvisioningError, .missingRecord)
            }
            XCTAssertEqual(directory.fixture.writes, writes); XCTAssertEqual(commits, 0)
            try snapshot(f).requireSame(as: before)
        }
    }

    func testLostDirectoryAcknowledgmentResumesTheOriginalClaimsWithoutDuplicateCreation() throws {
        try fixture { f in
            let directory = Directory(); var allocations = 0
            directory.fixture.lostWrite = "group-\(ServiceAccountRole.transport.rawValue)"
            let allocate: (AccountPreparationIntent, Set<UInt32>) throws -> ServiceAccountPlan = { account, reserved in
                allocations += 1; return try self.plan(account, reserved: reserved)
            }
            XCTAssertThrowsError(try resume(f, directory: directory, makePlan: allocate)) {
                XCTAssertTrue($0 is ServiceAccountDirectoryFixtureError)
            }
            let retained = try snapshot(f), chosen = try XCTUnwrap(retained.state.plan)
            XCTAssertFalse(retained.state.complete); XCTAssertEqual(directory.fixture.writes.count, 1)
            let result = try resume(f, directory: directory, makePlan: allocate)
            XCTAssertEqual(result, .init(plan: chosen, complete: true)); XCTAssertEqual(allocations, 1)
            XCTAssertEqual(directory.fixture.writes.count, 4); XCTAssertEqual(directory.fixture.groups.count, 2)
            XCTAssertEqual(directory.fixture.users.count, 2)
        }
    }

    func testEachOwnerStageCanResumeWithoutReplacingPlanOrDirectoryClaims() throws {
        try fixture { f in
            let directory = Directory()
            let stages: [ServiceAccountPreparation.Stage] = [.planRetained, .groupCreated(.transport), .userCreated(.transport),
                .validated(.transport), .groupCreated(.gateway), .userCreated(.gateway), .validated(.gateway), .completed]
            var chosen: ServiceAccountPlan?
            for failure in stages {
                XCTAssertThrowsError(try resume(f, directory: directory, didStage: { if $0 == failure { throw Fault.interrupted } })) {
                    XCTAssertTrue($0 is Fault)
                }
                let actual = try snapshot(f)
                if let chosen { XCTAssertEqual(actual.state.plan, chosen) } else { chosen = actual.state.plan }
                try f.admission.validate()
            }
            XCTAssertEqual(try resume(f, directory: directory), .init(plan: try XCTUnwrap(chosen), complete: true))
            XCTAssertEqual(directory.fixture.writes.count, 4)
            XCTAssertEqual(directory.fixture.users.count, 2); XCTAssertEqual(directory.fixture.groups.count, 2)
        }
    }

    func testSQLFailureBeforeReservationAndCompletionLeavesOnlyActualDurableProgress() throws {
        try fixture { f in
            let directory = Directory(), before = try snapshot(f)
            XCTAssertThrowsError(try resume(f, directory: directory, didSQL: { if $0 == .afterMutation { throw Fault.interrupted } })) {
                XCTAssertTrue($0 is Fault)
            }
            try snapshot(f).requireSame(as: before); XCTAssertTrue(directory.fixture.writes.isEmpty)
            var mutations = 0
            XCTAssertThrowsError(try resume(f, directory: directory, didSQL: { stage in
                if stage == .afterMutation { mutations += 1; if mutations == 2 { throw Fault.interrupted } }
            })) { XCTAssertTrue($0 is Fault) }
            try f.reopen(nil)
            let retained = try snapshot(f), chosen = try XCTUnwrap(retained.state.plan)
            XCTAssertFalse(retained.state.complete); XCTAssertEqual(directory.fixture.writes.count, 4)
            let writes = directory.fixture.writes
            XCTAssertEqual(try resume(f, directory: directory), .init(plan: chosen, complete: true))
            XCTAssertEqual(directory.fixture.writes, writes)
        }
    }

    func testForeignNamesNumbersAndUUIDsRefuseBeforeAnyDirectoryCreation() throws {
        try fixture { f in
            let directory = Directory(), before = try snapshot(f), chosen = try plan(before.preparation, reserved: before.reservedNumbers)
            let claim = try XCTUnwrap(chosen.claims.first)
            directory.fixture.users = [.init(number: 61000, id: UUID(), names: [claim.name])]
            var allocations = 0
            let allocate: (AccountPreparationIntent, Set<UInt32>) throws -> ServiceAccountPlan = { _, _ in allocations += 1; return chosen }
            XCTAssertThrowsError(try resume(f, directory: directory, makePlan: allocate))
            XCTAssertEqual(allocations, 0); XCTAssertTrue(directory.fixture.writes.isEmpty)
            try snapshot(f).requireSame(as: before); directory.fixture.users = []
            for kind in [ServiceDirectoryKind.group, .user] {
                let id = kind == .user ? claim.userID : claim.groupID
                for record in [ServiceDirectoryRecord(number: claim.number, id: UUID(), names: ["owned-foreign"]),
                    ServiceDirectoryRecord(number: 61000, id: id, names: ["owned-foreign"])] {
                    if kind == .user { directory.fixture.users = [record] } else { directory.fixture.groups = [record] }
                    XCTAssertThrowsError(try resume(f, directory: directory, makePlan: allocate))
                    XCTAssertTrue(directory.fixture.writes.isEmpty)
                    XCTAssertFalse(try snapshot(f).state.complete)
                    directory.fixture.users = []; directory.fixture.groups = []
                }
            }
            XCTAssertEqual(try resume(f, directory: directory, makePlan: allocate), .init(plan: chosen, complete: true))
            XCTAssertEqual(directory.fixture.writes.count, 4)
        }
    }

    func testBorrowedStorageRejectsAnotherThreadAndExpiresOnErrorAndSuccess() throws {
        try fixture { f in
            let directory = Directory(), before = try snapshot(f)
            var escaped: ServiceAccountPlanStorage?
            XCTAssertThrowsError(try resume(f, directory: directory, inspect: { escaped = $0; throw Fault.interrupted })) {
                XCTAssertTrue($0 is Fault)
            }
            XCTAssertThrowsError(try XCTUnwrap(escaped).load()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            try snapshot(f).requireSame(as: before); XCTAssertTrue(directory.fixture.writes.isEmpty)
            let result = try resume(f, directory: directory, inspect: { storage in
                escaped = storage
                let box = CallbackBox { _ = try storage.load() }, semaphore = DispatchSemaphore(value: 0)
                DispatchQueue.global().async { box.invoke(); semaphore.signal() }
                XCTAssertEqual(semaphore.wait(timeout: .now() + 5), .success)
                XCTAssertEqual(box.result(), .invalidated)
            })
            XCTAssertTrue(result.complete)
            XCTAssertThrowsError(try XCTUnwrap(escaped).load()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try XCTUnwrap(escaped).retain(XCTUnwrap(result.plan), verify: {})) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
        }
    }

    func testStaleFrameClosedAdmissionAndOrdinaryUIDRefuseBeforeDirectoryAccess() throws {
        try fixture { f in
            let directory = Directory(), before = try snapshot(f)
            try f.mutate("UPDATE runtime_activation_v1 SET registered=1-registered")
            XCTAssertThrowsError(try resume(f, directory: directory, expected: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            let actual = try snapshot(f)
            f.admission.close()
            XCTAssertThrowsError(try resume(f, directory: directory, expected: actual))
            XCTAssertEqual(directory.reads, 0); XCTAssertTrue(directory.fixture.writes.isEmpty)
            guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner fixture") }
            XCTAssertThrowsError(try Owner.resumeNative(machine: f.machine(), expected: actual, candidate: f.candidate,
                currentCodePolicy: actual.preparation.initialAuthority.codePolicy, directory: f.directory,
                admission: f.admission, verifyCurrent: { _ in XCTFail("Ordinary native verification reached") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            try snapshot(f).requireSame(as: actual)
        }
    }
}
