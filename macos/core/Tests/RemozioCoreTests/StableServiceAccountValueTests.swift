import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Modeled completion rows test values and SQLite reads. They establish no native initialization or service account authority.
final class StableServiceAccountValueTests: XCTestCase {
    private typealias Fixture = StableAccountReservationWriterFixture
    private typealias Snapshot = MachineUpdateStableServiceAccountSnapshot
    private enum Fault: Error { case refused }
    private func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
    private func setup(_ f: Fixture, owner: LocalAccountIdentity? = nil) throws -> MachineUpdateStableAccountSetupSnapshot {
        try f.machine().stableAccountSetupSnapshot(owner: owner ?? f.owner, candidate: f.candidate)
    }
    private func snapshot(_ f: Fixture, owner: LocalAccountIdentity? = nil) throws -> Snapshot {
        try f.machine().stableServiceAccountSnapshot(owner: owner ?? f.owner, candidate: f.candidate)
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
    private func plan(_ before: Snapshot, startingAt start: UInt32 = 40000) throws -> ServiceAccountPlan {
        var next = start - 1
        return try ServiceAccountAllocator.plan(account: before.preparation, reserved: before.reservedNumbers,
            candidate: { next += 1; return next }, available: { _ in true })
    }
    private func value(_ before: Snapshot, plan: ServiceAccountPlan?, complete: Bool,
        numbers: Set<UInt32>? = nil) throws -> Snapshot {
        try .init(setup: before.setup, state: .init(plan: plan, complete: complete),
            reservedNumbers: numbers ?? before.reservedNumbers.union(plan.map { Set($0.claims.map(\.number)) } ?? []))
    }

    func testActualStableReaderReturnsOneCurrentFrameWithoutCommittingOrCreatingServices() throws {
        try fixture { f in
            let before = try setup(f), rows = try f.scalar("SELECT COUNT(*) FROM service_accounts_v1")
            let numbers = try f.machine().reservedServiceAccountNumbers()
            var commits = 0
            try f.reopen { commits += 1 }
            let first = try snapshot(f), second = try snapshot(f)
            try first.setup.requireSame(as: before); try second.requireSame(as: first)
            try first.requireCurrent(machine: f.machine(), candidate: f.candidate)
            XCTAssertNil(first.state.plan); XCTAssertFalse(first.state.complete)
            XCTAssertEqual(first.reservedNumbers, numbers); XCTAssertFalse(numbers.isEmpty)
            XCTAssertEqual(first.preparation, before.preparation)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM service_accounts_v1"), rows)
            XCTAssertEqual(commits, 0); XCTAssertFalse(try XCTUnwrap(first.setup.account).inInventory)
        }
    }

    func testCurrentReleaseAndCompletedStorageAreRequiredBeforeAServiceSnapshotExists() throws {
        try fixture(prepared: false) { f in
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? ServiceAccountProvisioningError, .incomplete) }
            XCTAssertThrowsError(try Snapshot(setup: setup(f), state: .init(plan: nil, complete: false), reservedNumbers: [])) {
                XCTAssertEqual($0 as? ServiceAccountProvisioningError, .incomplete)
            }
            let retained = try setup(f, owner: f.retainedOwner)
            XCTAssertEqual(retained.account?.origin, .retained)
            XCTAssertThrowsError(try snapshot(f, owner: f.retainedOwner)) {
                XCTAssertEqual($0 as? ServiceAccountProvisioningError, .changedScope)
            }
            XCTAssertThrowsError(try Snapshot(setup: retained, state: .init(plan: nil, complete: false), reservedNumbers: [])) {
                XCTAssertEqual($0 as? ServiceAccountProvisioningError, .changedScope)
            }
            try setup(f, owner: f.retainedOwner).requireSame(as: retained)
        }
    }

    func testRetentionAndCompletionValuesKeepTheExactPlanAndReservationUnion() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try plan(before)
            let retained = try value(before, plan: selected, complete: false)
            try retained.requireChange(plan: selected, complete: false, from: before)
            let complete = try value(retained, plan: selected, complete: true)
            try complete.requireChange(plan: selected, complete: true, from: retained)
            try complete.requirePrepared(from: before)
            XCTAssertEqual(complete.reservedNumbers, before.reservedNumbers.union(selected.claims.map(\.number)))
            XCTAssertThrowsError(try retained.requireChange(plan: selected, complete: false, from: complete))
            let another = try plan(before)
            XCTAssertNotEqual(another, selected)
            XCTAssertThrowsError(try value(retained, plan: another, complete: true).requireChange(plan: another,
                complete: true, from: retained))
            try snapshot(f).requireSame(as: before)
        }
    }

    func testMissingExtraAndConflictingNumbersCannotAuthorizeValueTransitions() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try plan(before), owned = Set(selected.claims.map(\.number))
            XCTAssertThrowsError(try value(before, plan: selected, complete: false, numbers: before.reservedNumbers))
            let extra = try value(before, plan: selected, complete: false,
                numbers: before.reservedNumbers.union(owned).union([61000]))
            XCTAssertThrowsError(try extra.requireChange(plan: selected, complete: false, from: before))
            let missing = try value(before, plan: selected, complete: false, numbers: owned)
            XCTAssertThrowsError(try missing.requireChange(plan: selected, complete: false, from: before))
            XCTAssertThrowsError(try value(before, plan: nil, complete: true))
            XCTAssertThrowsError(try value(before, plan: nil, complete: false, numbers: Set(UInt32(1)...129)))
            let premature = try value(before, plan: selected, complete: true)
            XCTAssertThrowsError(try premature.requireChange(plan: selected, complete: true, from: before))
            try snapshot(f).requireSame(as: before)
        }
    }

    func testChangedActualFrameInvalidatesThePreviousServiceRead() throws {
        try fixture { f in
            let before = try snapshot(f)
            try f.mutate("UPDATE runtime_activation_v1 SET registered=1-registered")
            let changed = try snapshot(f)
            XCTAssertThrowsError(try changed.requireSame(as: before)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            XCTAssertThrowsError(try before.requireCurrent(machine: f.machine(), candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try changed.requireCurrent(machine: f.machine(), candidate: f.candidate)
        }
    }

    func testOwnedOperationsRetainTheCheckedPlanAndStopWhenVerificationRefuses() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try plan(before)
            var state = ServiceAccountPlanStorage.State(plan: nil, complete: false), writes = 0, checks = 0
            let storage = try ServiceAccountPlanStorage(account: before.preparation, operations: .init(load: { state },
                retain: { plan, verify in try verify(); writes += 1; state = .init(plan: plan, complete: false); try verify() },
                complete: { plan, verify in try verify(); writes += 1; state = .init(plan: plan, complete: true); try verify() }))
            XCTAssertThrowsError(try storage.retain(selected, verify: { throw Fault.refused })) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(writes, 0); XCTAssertNil(try storage.load().plan)
            try storage.retain(selected, verify: { checks += 1 })
            XCTAssertEqual(try storage.load(), .init(plan: selected, complete: false))
            let retained = try storage.load()
            XCTAssertThrowsError(try storage.complete(selected, verify: { throw Fault.refused })) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(try storage.load(), retained); XCTAssertEqual(writes, 1)
            try storage.complete(selected, verify: { checks += 1 })
            XCTAssertEqual(try storage.load(), .init(plan: selected, complete: true))
            XCTAssertEqual(writes, 2); XCTAssertGreaterThanOrEqual(checks, 4)
            try snapshot(f).requireSame(as: before)
        }
    }

    func testOperationsRejectUnpreparedAccountsAndImpossibleCompletionStates() throws {
        try fixture(prepared: false) { f in
            let account = try XCTUnwrap(setup(f).preparation)
            var loads = 0
            XCTAssertThrowsError(try ServiceAccountPlanStorage(account: account, operations: .init(load: {
                loads += 1; return .init(plan: nil, complete: false)
            }, retain: { _, _ in XCTFail("Unprepared retain reached") }, complete: { _, _ in XCTFail("Unprepared complete reached") }))) {
                XCTAssertEqual($0 as? ServiceAccountProvisioningError, .incomplete)
            }
            XCTAssertEqual(loads, 0)
        }
        try fixture { f in
            let account = try snapshot(f).preparation
            XCTAssertThrowsError(try ServiceAccountPlanStorage(account: account, operations: .init(load: {
                .init(plan: nil, complete: true)
            }, retain: { _, _ in XCTFail("Invalid retain reached") }, complete: { _, _ in XCTFail("Invalid complete reached") }))) {
                XCTAssertEqual($0 as? ServiceAccountProvisioningError, .incomplete)
            }
        }
    }

    func testLegacyStorageStillUsesActualRowsAndItsStableWritersRemainClosed() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try plan(before)
            let storage = try ServiceAccountPlanStorage(machine: f.machine(), account: before.preparation)
            XCTAssertEqual(try storage.load(), before.state)
            XCTAssertThrowsError(try storage.retain(selected, verify: {})) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try snapshot(f).requireSame(as: before)
            guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner fixture") }
            XCTAssertThrowsError(try ServiceAccountPlanStorage.open(machine: f.machine(), account: before.preparation)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
}
