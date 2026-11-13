import CryptoKit
import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned files and injected verification exercise composition. They establish no installed native authority.
final class MachineUpdateStableAccountPreparationTests: XCTestCase {
    private typealias Base = StableAccountReservationWriterFixture
    private typealias Snapshot = MachineUpdateStableAccountSetupSnapshot
    private typealias Owner = MachineUpdateStableAccountPreparation
    private typealias Storage = AuthorityAccountInitialization.Storage
    private enum Fault: Error { case interrupted, wrongFixturePath }
    private final class Counts {
        var key = 0, created = 0, paths = 0, initialization = 0, journalInitialized = 0, directories = 0
    }
    private struct Fixture {
        let base: Base
        let root: URL
        let key: AuthoritySigningKeyRecord
        let counts: Counts
    }
    private final class CallbackBox: @unchecked Sendable {
        let callback: () throws -> Void
        private let lock = NSLock()
        private var error: JournalLeaseError?
        init(_ callback: @escaping () throws -> Void) { self.callback = callback }
        func invoke() {
            let failure: JournalLeaseError?
            do { try callback(); failure = nil } catch { failure = error as? JournalLeaseError }
            lock.lock(); error = failure; lock.unlock()
        }
        func result() -> JournalLeaseError? { lock.lock(); defer { lock.unlock() }; return error }
    }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 262144, maxDepth: 16, maxItems: 10000) } }
    private func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    private func snapshot(_ f: Fixture, owner: LocalAccountIdentity? = nil) throws -> Snapshot {
        try f.base.machine().stableAccountSetupSnapshot(owner: owner ?? f.base.owner, candidate: f.base.candidate)
    }
    private func keyStore(_ f: Fixture) throws -> AuthorityKeyProvisioningStorage {
        try .init(anchor: f.root.path, relativeDirectory: "Key", owner: getuid())
    }
    private func openJournal(_ f: Fixture, preparation: AccountPreparationIntent, initialize: Bool) throws -> JournalDatabase {
        try JournalDatabase(lease: .init(anchor: f.root.path, relativeDirectory: "Journal", owner: getuid()),
            macID: preparation.macID, accountID: preparation.accountID, recordLimits: limits,
            descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 10, busyMilliseconds: 100,
            initialize: initialize, initialAuthority: initialize ? preparation.initialAuthority : nil)
    }
    private func fixture(existingInitialization: Bool = true, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withStableAccountReservationWriterFixture { base in
            _ = try base.machine().beginStableAccountPreparation(owner: base.owner, allowedTargetUIDs: [0], disclosureAccepted: true,
                expected: base.machine().stableAccountSetupSnapshot(owner: base.owner, candidate: base.candidate),
                candidate: base.candidate, directory: base.directory, admission: base.admission,
                makeInitial: base.initial, verifyScoped: { _, _ in })
            let reserved = try XCTUnwrap(base.machine().stableAccountSetupSnapshot(owner: base.owner,
                candidate: base.candidate).preparation)
            let root = URL(fileURLWithPath: "/private/tmp/remozio-A03-owned-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            XCTAssertEqual(chmod(root.path, 0o700), 0)
            defer { try? FileManager.default.removeItem(at: root) }
            let keyDirectory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Key", owner: getuid())
            keyDirectory.close()
            for (name, kind): (String, SetupDatabaseKind) in [("Journal", .journal), ("Continuity", .continuity)] {
                let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: name, owner: getuid())
                defer { directory.close() }
                _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: kind, owner: getuid())
            }
            // The representation is fixture data. Hardware verification is not replaced in the native entry.
            let record = try AuthoritySigningKeyRecord(macID: reserved.macID, accountID: reserved.accountID,
                publicKey: P256.Signing.PrivateKey().publicKey.x963Representation, representation: Data(repeating: 7, count: 32))
            let f = Fixture(base: base, root: root, key: record, counts: Counts())
            if existingInitialization {
                let key = try keyStore(f)
                _ = try key.restoreOrCreate(macID: reserved.macID, accountID: reserved.accountID, create: { record }, verify: { _ in })
                key.close()
                let pinned = try base.machine().pinStableAccountPreparation(publicKey: record.publicKey,
                    expected: snapshot(f), candidate: base.candidate, directory: base.directory,
                    admission: base.admission, verifyScoped: { _, _ in })
                let journal = try openJournal(f, preparation: pinned, initialize: true)
                try journal.close()
                let initial = try AuthorityInitializationIntent(setupID: AccountPreparationIntent.randomID(),
                    revision: AccountPreparationIntent.randomID(), installationID: pinned.installationID, macID: pinned.macID,
                    accountID: pinned.accountID, releaseDigest: pinned.releaseDigest,
                    initializationDigest: pinned.initialAuthority.initializationDigest, initializationBytes: pinned.initializationBytes,
                    journalPath: root.path + "/Journal/journal.sqlite", continuityPath: root.path + "/Continuity/continuity.sqlite")
                try base.mutate("INSERT INTO authority_initialization_v1 VALUES(x'\(hex(initial.accountID))',x'\(hex(initial.revision))',x'\(try hex(initial.bytes))')")
            }
            try body(f)
        }
    }
    private func initialize(_ f: Fixture, expected: AuthorityInitializationIntent, storage: Storage,
        didStage: (AuthorityAccountInitialization.Stage) throws -> Void = { _ in }) throws -> AuthorityInitializationIntent {
        guard expected.journalPath == f.root.path + "/Journal/journal.sqlite",
              expected.continuityPath == f.root.path + "/Continuity/continuity.sqlite" else { throw Fault.wrongFixturePath }
        return try AuthorityAccountInitialization.resume(machine: f.base.machine(), expected: expected, storage: storage,
            prepareJournal: {
                let directory = try ProtectedSetupDirectory(anchor: f.root.path, relativePath: "Journal", owner: getuid())
                defer { directory.close() }
                _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .journal, owner: getuid())
            }, openDirectories: {
                f.counts.directories += 1
                let journal = try ProtectedSetupDirectory(anchor: f.root.path, relativePath: "Journal", owner: getuid(), createIfMissing: false)
                do { return try .init(journal: journal,
                    continuity: ProtectedSetupDirectory(anchor: f.root.path, relativePath: "Continuity", owner: getuid())) }
                catch { journal.close(); throw error }
            }, openJournal: { initialize, seed, directories in
                if initialize { f.counts.journalInitialized += 1 }
                let lease = try ProtectedJournalLease(anchor: f.root.path, relativeDirectory: "Journal", owner: getuid())
                do { try directories.validate(journal: lease) } catch { lease.close(); throw error }
                return try JournalDatabase(lease: lease, macID: expected.macID, accountID: expected.accountID,
                    recordLimits: limits, descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 10,
                    busyMilliseconds: 100, initialize: initialize, initialAuthority: initialize ? seed : nil)
            }, prepareContinuity: {
                let directory = try ProtectedSetupDirectory(anchor: f.root.path, relativePath: "Continuity", owner: getuid())
                defer { directory.close() }
                _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .continuity, owner: getuid())
            }, openContinuity: { checkpoint, directories in
                let lease = try ProtectedContinuityLease(anchor: f.root.path, relativeDirectory: "Continuity", owner: getuid())
                do { try directories.validate(continuity: lease) } catch { lease.close(); throw error }
                return try ContinuityStore(lease: lease, macID: expected.macID, accountID: expected.accountID, initialize: checkpoint)
            }, didStage: didStage)
    }
    private func resume(_ f: Fixture, expected: Snapshot? = nil, keyOverride: Data? = nil,
        verify: @escaping (Snapshot) throws -> Void = { _ in }, afterKey: (() throws -> Void)? = nil,
        initialization: ((AuthorityInitializationIntent, Storage) throws -> AuthorityInitializationIntent)? = nil,
        didStage: (Owner.Stage) throws -> Void = { _ in }) throws -> AccountPreparationIntent {
        try Owner.resume(machine: f.base.machine(), expected: expected ?? snapshot(f), candidate: f.base.candidate,
            directory: f.base.directory, admission: f.base.admission, verifyCurrent: verify,
            initializationPaths: { preparation in
                f.counts.paths += 1
                if let existing = try self.snapshot(f).account?.initialization { return (existing.journalPath, existing.continuityPath) }
                let root = try AccountPreparationController.authorityDirectory(accountID: preparation.accountID)
                return (root + "/Journal/journal.sqlite", root + "/Continuity/continuity.sqlite")
            }, provisionKey: { preparation, validate in
                f.counts.key += 1; try validate()
                if let keyOverride { return keyOverride }
                let key = try self.keyStore(f); defer { key.close() }
                let value = try key.restoreOrCreate(macID: preparation.macID, accountID: preparation.accountID,
                    expectedPublicKey: preparation.authorityPublicKey, create: { f.counts.created += 1; return f.key },
                    verify: { _ in try validate() })
                try validate(); try afterKey?(); return value.publicKey
            }, resumeInitialization: { initial, storage in
                f.counts.initialization += 1
                if let initialization { return try initialization(initial, storage) }
                return try self.initialize(f, expected: initial, storage: storage)
            }, didStage: didStage)
    }
    private func requireReleased(_ f: Fixture) throws {
        let journal = try ProtectedJournalLease(anchor: f.root.path, relativeDirectory: "Journal", owner: getuid())
        journal.close()
        let continuity = try ProtectedContinuityLease(anchor: f.root.path, relativeDirectory: "Continuity", owner: getuid())
        continuity.close()
        let key = try keyStore(f); key.close()
    }

    func testOwnedExistingPairCompletesInOrderAndKeepsTheOriginalPolicyAndBytes() throws {
        try fixture { f in
            let before = try snapshot(f), initial = try XCTUnwrap(before.account?.initialization)
            let journalBytes = try Data(contentsOf: URL(fileURLWithPath: initial.journalPath))
            let keyPath = f.root.appendingPathComponent("Key/" + AuthorityKeyProvisioning.recordFileName)
            let keyBytes = try Data(contentsOf: keyPath)
            var stages: [Owner.Stage] = []
            let completed = try resume(f, verify: { _ in
                try f.base.admission.validate()
                XCTAssertThrowsError(try f.base.gate.beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
            }, didStage: { stages.append($0) })
            XCTAssertEqual(stages, Owner.Stage.allCases); XCTAssertTrue(completed.storagePrepared)
            XCTAssertEqual(completed.policyBytes, before.preparation?.policyBytes)
            XCTAssertEqual(completed.initializationBytes, before.preparation?.initializationBytes)
            XCTAssertEqual(completed.authorityPublicKey, f.key.publicKey)
            let after = try snapshot(f)
            try after.requireAccountStorageState(preparation: completed, initialization: after.account?.initialization, from: before)
            XCTAssertTrue(try XCTUnwrap(after.account?.initialization).complete)
            XCTAssertFalse(try XCTUnwrap(after.account).inInventory)
            XCTAssertEqual(f.counts.created, 0); XCTAssertEqual(f.counts.journalInitialized, 0)
            XCTAssertEqual(try Data(contentsOf: keyPath), keyBytes)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: initial.journalPath)), journalBytes)
            try requireReleased(f)
        }
    }

    func testEveryOwnerInterruptionRecoversActualProgressWithoutReplacingKeyOrJournal() throws {
        try fixture { f in
            let initial = try XCTUnwrap(snapshot(f).account?.initialization)
            let keyBytes = try Data(contentsOf: f.root.appendingPathComponent("Key/" + AuthorityKeyProvisioning.recordFileName))
            for stage in Owner.Stage.allCases {
                XCTAssertThrowsError(try resume(f, didStage: { if $0 == stage { throw Fault.interrupted } })) {
                    XCTAssertTrue($0 is Fault)
                }
                try requireReleased(f)
                let actual = try snapshot(f)
                XCTAssertEqual(actual.preparation?.authorityPublicKey, f.key.publicKey)
                XCTAssertEqual(actual.account?.initialization?.setupID, initial.setupID)
                if stage == .storesInitialized || stage == .completed { XCTAssertTrue(try XCTUnwrap(actual.account?.initialization).complete) }
            }
            let keyCalls = f.counts.key, directories = f.counts.directories
            XCTAssertTrue(try resume(f).storagePrepared)
            XCTAssertEqual(f.counts.key, keyCalls); XCTAssertEqual(f.counts.directories, directories)
            XCTAssertEqual(f.counts.created, 0); XCTAssertEqual(f.counts.journalInitialized, 0)
            XCTAssertEqual(try Data(contentsOf: f.root.appendingPathComponent("Key/" + AuthorityKeyProvisioning.recordFileName)), keyBytes)
        }
    }

    func testFreshKeyAndIntentProgressUseCanonicalMetadataWithoutClaimingNativeStorageCreation() throws {
        try fixture(existingInitialization: false) { f in
            let before = try snapshot(f)
            for stage in [Owner.Stage.keyProvisioned, .keyPinned, .initializationRetained] {
                XCTAssertThrowsError(try resume(f, didStage: { if $0 == stage { throw Fault.interrupted } })) {
                    XCTAssertTrue($0 is Fault)
                }
            }
            XCTAssertEqual(f.counts.created, 1); XCTAssertEqual(f.counts.initialization, 0)
            let after = try snapshot(f), preparation = try XCTUnwrap(after.preparation)
            let initial = try XCTUnwrap(after.account?.initialization)
            let root = try AccountPreparationController.authorityDirectory(accountID: preparation.accountID)
            XCTAssertEqual(initial.journalPath, root + "/Journal/journal.sqlite")
            XCTAssertEqual(initial.continuityPath, root + "/Continuity/continuity.sqlite")
            XCTAssertNil(initial.checkpoint); XCTAssertFalse(initial.complete); XCTAssertFalse(preparation.storagePrepared)
            XCTAssertEqual(preparation.policyBytes, before.preparation?.policyBytes)
            XCTAssertEqual(preparation.initializationBytes, before.preparation?.initializationBytes)
            XCTAssertEqual(try Data(contentsOf: f.root.appendingPathComponent("Journal/journal.sqlite")), Data())
        }
    }

    func testPreparedProgressNeverRecreatesMissingKeyOrAccountFiles() throws {
        try fixture { f in
            let completed = try resume(f), before = try snapshot(f)
            let counts = (f.counts.key, f.counts.paths, f.counts.initialization)
            for path in ["Key/" + AuthorityKeyProvisioning.recordFileName, "Journal/journal.sqlite", "Continuity/continuity.sqlite"] {
                try FileManager.default.removeItem(at: f.root.appendingPathComponent(path))
            }
            XCTAssertEqual(try resume(f), completed); try snapshot(f).requireSame(as: before)
            XCTAssertEqual(f.counts.key, counts.0); XCTAssertEqual(f.counts.paths, counts.1)
            XCTAssertEqual(f.counts.initialization, counts.2)
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.root.appendingPathComponent("Journal/journal.sqlite").path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.root.appendingPathComponent("Key/" + AuthorityKeyProvisioning.recordFileName).path))
        }
    }

    func testRetainedOriginAndOrdinaryNativeEntriesRefuseBeforeAnyFactory() throws {
        try fixture { f in
            let retained = try snapshot(f, owner: f.base.retainedOwner)
            XCTAssertEqual(retained.account?.origin, .retained)
            XCTAssertThrowsError(try resume(f, expected: retained)) { XCTAssertEqual($0 as? AccountPreparationError, .conflict) }
            try snapshot(f, owner: f.base.retainedOwner).requireSame(as: retained)
            guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner fixture") }
            let before = try snapshot(f), initial = try XCTUnwrap(before.account?.initialization)
            XCTAssertThrowsError(try Owner.resumeNative(machine: f.base.machine(), expected: before,
                candidate: f.base.candidate, currentCodePolicy: initial.initialAuthority.codePolicy,
                directory: f.base.directory, admission: f.base.admission, verifyCurrent: { _ in XCTFail("Native verification reached") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            let storage = Storage(validate: { _ in XCTFail("Stable native validation reached") },
                capture: { _, _, _ in throw Fault.interrupted }, complete: { _, _, _ in throw Fault.interrupted })
            XCTAssertThrowsError(try AuthorityAccountInitialization.resumeStable(machine: f.base.machine(), expected: initial, storage: storage)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertEqual(f.counts.key, 0); XCTAssertEqual(f.counts.paths, 0); XCTAssertEqual(f.counts.initialization, 0)
            try snapshot(f).requireSame(as: before)
        }
    }

    func testAnotherValidKeyAndMalformedKeyCannotReachInitializationOrChangeThePin() throws {
        try fixture { f in
            let before = try snapshot(f)
            for key in [P256.Signing.PrivateKey().publicKey.x963Representation, Data([4, 0])] {
                XCTAssertThrowsError(try resume(f, keyOverride: key))
                try snapshot(f).requireSame(as: before)
            }
            XCTAssertEqual(f.counts.initialization, 0); XCTAssertEqual(f.counts.paths, 0)
            XCTAssertTrue(try resume(f).storagePrepared)
        }
    }

    func testChangedFrameAndClosedAdmissionStopBeforeKeyAndStorageFactories() throws {
        try fixture { f in
            let before = try snapshot(f)
            try f.base.mutate("UPDATE runtime_activation_v1 SET registered=1-registered")
            XCTAssertThrowsError(try resume(f, expected: before)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            let actual = try snapshot(f)
            f.base.admission.close()
            XCTAssertThrowsError(try resume(f, expected: actual))
            XCTAssertEqual(f.counts.key, 0); XCTAssertEqual(f.counts.paths, 0); XCTAssertEqual(f.counts.initialization, 0)
            try snapshot(f).requireSame(as: actual)
        }
    }

    func testFactoryCannotReturnAnUnrecordedCompletionOrKeepItsCallbacksAlive() throws {
        try fixture { f in
            let before = try snapshot(f), original = try XCTUnwrap(before.account?.initialization)
            var escaped: Storage?
            XCTAssertThrowsError(try resume(f, initialization: { initial, storage in
                escaped = storage
                let journal = try self.openJournal(f, preparation: XCTUnwrap(before.preparation), initialize: false)
                defer { try? journal.close() }
                let checkpoint = try journal.initialAuthorityCheckpoint(initial: initial.initialAuthority, databasePath: initial.journalPath)
                return try initial.advancing(checkpoint: checkpoint, complete: true)
            })) { XCTAssertEqual($0 as? AuthorityInitializationError, .staleRevision) }
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate(original)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            try snapshot(f).requireSame(as: before)
            XCTAssertTrue(try resume(f).storagePrepared); try requireReleased(f)
        }
    }

    func testStorageCallbacksRejectAnotherThreadAndExpireAfterSuccessfulReturn() throws {
        try fixture { f in
            var escaped: Storage?, retained: AuthorityInitializationIntent?
            let completed = try resume(f, initialization: { initial, storage in
                escaped = storage; retained = initial
                let box = CallbackBox { try storage.validate(initial) }
                let semaphore = DispatchSemaphore(value: 0)
                DispatchQueue.global().async { box.invoke(); semaphore.signal() }
                XCTAssertEqual(semaphore.wait(timeout: .now() + 5), .success)
                XCTAssertEqual(box.result(), .invalidated)
                return try self.initialize(f, expected: initial, storage: storage)
            })
            XCTAssertTrue(completed.storagePrepared)
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate(XCTUnwrap(retained))) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            try requireReleased(f)
        }
    }

    func testInitializerFailureClosesActualStoresAndExpiresItsStorageCallbacks() throws {
        try fixture { f in
            var escaped: Storage?, retained: AuthorityInitializationIntent?
            XCTAssertThrowsError(try resume(f, initialization: { initial, storage in
                escaped = storage; retained = initial
                return try self.initialize(f, expected: initial, storage: storage, didStage: { stage in
                    if stage == .continuityOpened { throw Fault.interrupted }
                })
            })) { XCTAssertTrue($0 is Fault) }
            try requireReleased(f)
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate(XCTUnwrap(retained))) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            let partial = try snapshot(f)
            XCTAssertNotNil(partial.account?.initialization?.checkpoint)
            XCTAssertFalse(try XCTUnwrap(partial.account?.initialization).complete)
            XCTAssertFalse(try XCTUnwrap(partial.preparation).storagePrepared)
            XCTAssertTrue(try resume(f).storagePrepared)
            XCTAssertEqual(f.counts.created, 0); XCTAssertEqual(f.counts.journalInitialized, 0)
        }
    }
}
