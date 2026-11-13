import CryptoKit
import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned SQL models completed account and service metadata. It proves no native initialization, directory state, or runtime file publication.
final class StableRuntimeImportTests: XCTestCase {
    private typealias Fixture = StableAccountReservationWriterFixture
    private typealias Snapshot = MachineUpdateStableRuntimePreparationSnapshot
    private func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
    private func setup(_ f: Fixture) throws -> MachineUpdateStableAccountSetupSnapshot {
        try f.machine().stableAccountSetupSnapshot(owner: f.owner, candidate: f.candidate)
    }
    private func snapshot(_ f: Fixture) throws -> Snapshot {
        try f.machine().stableRuntimePreparationSnapshot(owner: f.owner, candidate: f.candidate)
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withStableAccountReservationWriterFixture { f in
            _ = try f.machine().beginStableAccountPreparation(owner: f.owner, allowedTargetUIDs: [0], disclosureAccepted: true,
                expected: setup(f), candidate: f.candidate, directory: f.directory, admission: f.admission,
                makeInitial: f.initial, verifyScoped: { _, _ in })
            let pinned = try f.machine().pinStableAccountPreparation(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                expected: setup(f), candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
            let root = try AccountPreparationController.authorityDirectory(accountID: pinned.accountID)
            let initial = try f.machine().beginStableAccountInitialization(journalPath: root + "/Journal/journal.sqlite",
                continuityPath: root + "/Continuity/continuity.sqlite", expected: setup(f), candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
            // Fixture SQL installs this modeled checkpoint. No production initialization writer consumes it.
            let checkpoint = try ContinuityCheckpoint(generation: 1, authorityDigest: Data(repeating: 201, count: 32),
                ledgerDigest: Data(repeating: 202, count: 32), journalEpoch: initial.initialAuthority.descriptor.epoch,
                journalHead: 0, authorityGeneration: 1)
            let complete = try initial.advancing(checkpoint: checkpoint, complete: true)
            let account = try pinned.prepared(initialization: complete)
            try f.mutate("UPDATE authority_initialization_v1 SET revision=x'\(hex(complete.revision))',record=x'\(try hex(complete.bytes))' WHERE account=x'\(hex(account.accountID))'")
            try f.mutate("UPDATE account_preparation_v1 SET revision=x'\(hex(account.revision))',record=x'\(try hex(account.bytes))' WHERE owner=\(account.ownerUID)")
            let services = try f.machine().stableServiceAccountSnapshot(owner: f.owner, candidate: f.candidate)
            var next: UInt32 = 39999
            let plan = try ServiceAccountAllocator.plan(account: account, reserved: services.reservedNumbers,
                candidate: { next += 1; return next }, available: { _ in true })
            _ = try f.machine().retainStableServiceAccountPlan(plan, expected: services, candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
            _ = try f.machine().completeStableServiceAccountPlan(plan,
                expected: f.machine().stableServiceAccountSnapshot(owner: f.owner, candidate: f.candidate), candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
            try body(f)
        }
    }
    private func reference(_ plan: ServiceAccountPlan) throws -> RuntimeMaterialReference {
        try .init(materialID: AccountPreparationIntent.randomID(), services: plan, materialDigest: Data(repeating: 171, count: 32),
            transportPublicKeyInfo: P256.Signing.PrivateKey().publicKey.derRepresentation,
            gateway: GatewayRegistrationIdentity(ownerID: AccountPreparationIntent.randomID(), macID: plan.macID,
                accountID: plan.accountID, gatewayID: AccountPreparationIntent.randomID(),
                lifecycleEpoch: AccountPreparationIntent.randomID(), rootPublicKey: plan.authorityPublicKey))
    }
    private enum Fault: Error { case body, commit }
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
    private func proposal() throws -> PortableSetup {
        let defaults = try SharedSetupDefaults(presence: .init(idleMilliseconds: 540_000, observationLifetimeMilliseconds: 7000,
            unavailableGraceMilliseconds: 45_000), gateway: GatewaySetupForm().settingsSelection())
        return .init(defaults: defaults)
    }
    private func journal(_ f: Fixture, account: AccountPreparationIntent, initialize: Bool,
        component: String = "SharedSetupImport", installationID: Data? = nil,
        hook: (() throws -> Void)? = nil) throws -> SharedSetupImportJournal {
        let machine = URL(fileURLWithPath: f.directory.path), anchor = machine.deletingLastPathComponent().path
        let relative = machine.lastPathComponent + "/" + component
        if initialize {
            let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: relative, owner: getuid())
            defer { directory.close() }
            _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .sharedSetupImport, owner: getuid())
        }
        return try .init(lease: .init(anchor: anchor, relativeDirectory: relative, owner: getuid(), ancestorOwner: getuid(),
            databaseName: "setup-import.sqlite"), owner: getuid(), macID: account.macID,
            installationID: installationID ?? account.installationID, initialize: initialize, didCommit: hook)
    }
    private func importFixture(published: Bool = true, hook: ((Fixture) throws -> Void)? = nil,
        _ body: (Fixture, SharedSetupImportIntent, SharedSetupImportJournal) throws -> Void) throws {
        try fixture { f in
            let before = try snapshot(f), selected = try reference(before.plan)
            if published {
                _ = try f.machine().retainStableRuntimeMaterial(selected, expected: before, candidate: f.candidate,
                    directory: f.directory, admission: f.admission, fileCustodyAccepted: true, verifyScoped: { _, _ in })
                _ = try f.machine().completeStableRuntimePublication(selected, expected: snapshot(f), candidate: f.candidate,
                    directory: f.directory, admission: f.admission, fileCustodyAccepted: true, verifyScoped: { _, _ in })
            }
            let intent = try SharedSetupImportIntent(scope: .init(account: before.preparation, inventory: before.setup.source.actual.inventory),
                proposal: proposal())
            let store = try journal(f, account: before.preparation, initialize: true, hook: { try hook?(f) })
            defer { try? store.close() }
            try store.begin(intent); try body(f, intent, store)
        }
    }
    private func advance(_ f: Fixture, expected: Snapshot, previous: SharedSetupImportIntent,
        journal: SharedSetupImportJournal) throws -> (intent: SharedSetupImportIntent, snapshot: Snapshot) {
        try f.machine().advanceStableRuntimeImport(expected: expected, previous: previous, journal: journal,
            candidate: f.candidate, directory: f.directory, admission: f.admission)
    }

    func testAbsentImportReadsDoNotCreateAJournalOrDirectory() throws {
        try fixture { f in
            let path = f.directory.path + "/SharedSetupImport", before = try snapshot(f)
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            try f.machine().withSharedImportJournal { XCTAssertNil($0) }
            try snapshot(f).requireSame(as: before)
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }

    func testHeldJournalCapturesFreshFullRecordsAndNestedReadsUseTheSameDirectory() throws {
        try importFixture { f, intent, store in
            var captured: SharedSetupImportCompatibilitySnapshot?
            var escaped: ProtectedSetupDirectory?
            let account = try f.machine().withSharedImportSnapshot(journal: store) { directory, owner in
                XCTAssertEqual(owner, getuid()); escaped = directory
                let first = try store.compatibilitySnapshot(directory: directory)
                let record = try XCTUnwrap(first.records.first)
                XCTAssertEqual(record.accountID, intent.scope.accountID); XCTAssertEqual(record.operationID, intent.operationID)
                XCTAssertEqual(record.revision, intent.revision); XCTAssertEqual(record.phase, intent.phase.rawValue)
                XCTAssertEqual(record.digest, Data(SHA256.hash(data: try intent.bytes)))
                XCTAssertEqual(record.portableVersion, intent.originalPortableVersion)
                XCTAssertEqual(record.settingsVersion, try intent.recipe.settingsVersion)
                XCTAssertNil(record.relay); XCTAssertNil(record.relayProvisioning); XCTAssertNil(record.accessApplication)
                XCTAssertNil(record.dnsRecord); XCTAssertNil(record.runCredential)
                let before = try snapshot(f)
                try f.machine().withSharedImportSnapshot(journal: store) { nested, nestedOwner in
                    XCTAssertTrue(nested === directory); XCTAssertEqual(nestedOwner, owner)
                    try snapshot(f).requireSame(as: before)
                }
                let next = try store.advance(intent, to: .runtimePublished)
                let after = try store.compatibilitySnapshot(directory: directory)
                XCTAssertNotEqual(after, first)
                XCTAssertEqual(after.records.first?.revision, next.revision)
                XCTAssertEqual(after.records.first?.phase, SharedSetupImportIntent.Phase.runtimePublished.rawValue)
                let actual = try snapshot(f)
                XCTAssertThrowsError(try actual.requireSame(as: before)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
                try actual.requirePublished(from: before); XCTAssertEqual(actual.state, before.state)
                captured = after; return before.preparation
            }
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            try store.close()
            let machine = URL(fileURLWithPath: f.directory.path)
            let outside = try SharedSetupImportCompatibilitySnapshot.capture(anchor: machine.deletingLastPathComponent().path,
                relativeMachineDirectory: machine.lastPathComponent, owner: getuid(), macID: account.macID,
                installationID: account.installationID)
            XCTAssertEqual(outside, captured)
            try snapshot(f).requireCurrent(machine: f.machine(), candidate: f.candidate)
        }
    }

    func testImportAdvanceChangesOnlyTheHeldJournalAndKeepsMachineBytesExact() throws {
        try importFixture { f, intent, store in
            try f.machine().withSharedImportSnapshot(journal: store) { _, _ in
                let before = try snapshot(f)
                let database = URL(fileURLWithPath: f.directory.path + "/installation.sqlite")
                let bytes = try Data(contentsOf: database)
                let result = try advance(f, expected: before, previous: intent, journal: store)
                XCTAssertEqual(result.intent.phase, .runtimePublished)
                XCTAssertEqual(result.intent.operationID, intent.operationID)
                XCTAssertEqual(result.intent.proposalDigest, intent.proposalDigest)
                XCTAssertNotEqual(result.intent.revision, intent.revision)
                XCTAssertEqual(result.snapshot.state, before.state)
                try result.snapshot.requirePublished(from: before)
                XCTAssertEqual(try Data(contentsOf: database), bytes)
                XCTAssertEqual(try store.current(scope: intent.scope), result.intent)
                XCTAssertThrowsError(try advance(f, expected: before, previous: intent, journal: store)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertEqual(try store.current(scope: intent.scope), result.intent)
                try result.snapshot.requireCurrent(machine: f.machine(), candidate: f.candidate)
                try f.admission.validate()
            }
        }
    }

    func testMissingPublicationBorrowForeignScopeAndChangedRevisionRefuseWithoutReplay() throws {
        try importFixture(published: false) { f, intent, store in
            let before = try f.machine().withSharedImportSnapshot(journal: store) { _, _ in
                let before = try snapshot(f)
                XCTAssertThrowsError(try advance(f, expected: before, previous: intent, journal: store)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .incomplete)
                }
                XCTAssertEqual(try store.current(scope: intent.scope), intent)
                try snapshot(f).requireSame(as: before); return before
            }
            XCTAssertThrowsError(try advance(f, expected: before, previous: intent, journal: store)) {
                XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope)
            }
        }
        try importFixture { f, intent, store in
            try f.machine().withSharedImportSnapshot(journal: store) { _, _ in
                let retained = try f.machine().stableRuntimePreparationSnapshot(owner: f.retainedOwner, candidate: f.candidate)
                XCTAssertThrowsError(try advance(f, expected: retained, previous: intent, journal: store)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                }
                let inventory = try retained.setup.source.provisioningInventory(accountID: retained.preparation.accountID,
                    ownerUID: retained.preparation.ownerUID, releaseDigest: retained.preparation.releaseDigest)
                let other = try SharedSetupImportIntent(scope: .init(account: retained.preparation, inventory: inventory), proposal: proposal())
                try store.begin(other)
                let before = try snapshot(f)
                XCTAssertThrowsError(try advance(f, expected: before, previous: other, journal: store)) {
                    XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope)
                }
                XCTAssertEqual(try store.current(scope: other.scope), other)
                let next = try store.advance(intent, to: .runtimePublished)
                XCTAssertThrowsError(try advance(f, expected: before, previous: intent, journal: store)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertEqual(try store.current(scope: intent.scope), next)
            }
        }
    }

    func testBorrowBindsTheJournalDestinationThreadAndDirectoryAndExpiresOnBothReturns() throws {
        try importFixture { f, intent, store in
            var escaped: ProtectedSetupDirectory?
            XCTAssertThrowsError(try f.machine().withSharedImportSnapshot(journal: store) { directory, _ -> Bool in
                escaped = directory; throw Fault.body
            }) { XCTAssertTrue($0 is Fault) }
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            try f.machine().withSharedImportSnapshot(journal: store) { directory, _ in
                escaped = directory
                let account = try snapshot(f).preparation
                let foreign = try journal(f, account: account, initialize: true, component: "ForeignImport")
                defer { try? foreign.close() }
                XCTAssertThrowsError(try f.machine().withSharedImportSnapshot(journal: foreign) { _, _ in XCTFail("Foreign journal body") }) {
                    XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                }
                XCTAssertThrowsError(try foreign.compatibilitySnapshot(directory: directory)) {
                    XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope)
                }
                let wrong = try journal(f, account: account, initialize: true, component: "WrongDestination",
                    installationID: AccountPreparationIntent.randomID())
                defer { try? wrong.close() }
                XCTAssertThrowsError(try wrong.requireDestination(macID: account.macID, installationID: account.installationID)) {
                    XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope)
                }
                let box = CallbackBox {
                    try f.machine().withSharedImportSnapshot(journal: store) { _, _ in XCTFail("Foreign thread body") }
                }, semaphore = DispatchSemaphore(value: 0)
                DispatchQueue.global().async { box.invoke(); semaphore.signal() }
                XCTAssertEqual(semaphore.wait(timeout: .now() + 5), .success)
                XCTAssertEqual(box.result(), .invalidated)
                XCTAssertEqual(try store.current(scope: intent.scope), intent)
                try snapshot(f).requireCurrent(machine: f.machine(), candidate: f.candidate)
            }
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try store.compatibilitySnapshot(directory: XCTUnwrap(escaped)))
        }
    }

    func testUncertainJournalCommitKeepsTheActualMarkerAndNeverRepeatsItsWrite() throws {
        var fail = false, commits = 0
        try importFixture(hook: { _ in if fail { commits += 1; throw Fault.commit } }) { f, intent, store in
            var account: AccountPreparationIntent?
            XCTAssertThrowsError(try f.machine().withSharedImportSnapshot(journal: store) { _, _ in
                let before = try snapshot(f); account = before.preparation; fail = true
                _ = try advance(f, expected: before, previous: intent, journal: store)
            }) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(commits, 1)
            let reopened = try journal(f, account: XCTUnwrap(account), initialize: false)
            defer { try? reopened.close() }
            try f.machine().withSharedImportSnapshot(journal: reopened) { _, _ in
                let actual = try snapshot(f), recorded = try XCTUnwrap(reopened.current(scope: intent.scope))
                XCTAssertEqual(recorded.phase, .runtimePublished); XCTAssertEqual(recorded.operationID, intent.operationID)
                XCTAssertThrowsError(try advance(f, expected: actual, previous: intent, journal: reopened)) {
                    XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision)
                }
                XCTAssertEqual(try reopened.current(scope: intent.scope), recorded)
                XCTAssertEqual(commits, 1); try actual.requireCurrent(machine: f.machine(), candidate: f.candidate)
            }
        }
    }

    func testMachineRowMutationDuringImportCommitRefusesWithoutRepairOrJournalReplay() throws {
        var mutate = false, commits = 0
        let flip = "UPDATE runtime_activation_v1 SET registered=1-registered"
        try importFixture(hook: { f in if mutate { commits += 1; _ = try f.scalar(flip) } }) { f, intent, store in
            try f.machine().withSharedImportSnapshot(journal: store) { _, _ in
                let before = try snapshot(f); mutate = true
                XCTAssertThrowsError(try advance(f, expected: before, previous: intent, journal: store)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertEqual(commits, 1)
                let recorded = try XCTUnwrap(store.current(scope: intent.scope))
                XCTAssertEqual(recorded.phase, .runtimePublished)
                _ = try f.scalar(flip)
                let actual = try snapshot(f)
                XCTAssertThrowsError(try advance(f, expected: actual, previous: intent, journal: store)) {
                    XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision)
                }
                XCTAssertEqual(commits, 1); XCTAssertEqual(try store.current(scope: intent.scope), recorded)
                try actual.requirePublished(from: before)
            }
        }
    }
}
