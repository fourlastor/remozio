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

    private typealias RetainedInputs = MachineUpdateRetainedSetupRuntimeInputs
    private typealias RelaySelection = MachineUpdateStableRuntimeImportPreparation.RelaySelection
    private func withPublicRelaySelection(_ body: (RelaySelection, SharedSetupImportRelayPlan,
        SharedSetupImportRelayStorage.Snapshot) throws -> Void) throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent()
        let directory = try ProtectedSetupDirectory(anchor: f.accountFixture.root.path,
            relativePath: f.relativeDirectory, owner: getuid(), createIfMissing: false)
        defer { directory.close() }
        let plan = try SharedSetupImportRelayPlan(expected: intent, port: 51001)
        _ = try AdministrativeSetupPublication.publish(plan.bytes,
            file: .importRelayPlan(accountID: intent.scope.accountID), directory: directory, owner: getuid())
        let actual = try RelaySelection.read(intent, directory: directory, owner: getuid())
        try body(actual, plan, XCTUnwrap(actual.snapshot))
    }

    func testRetainedRuntimeInputsDistinguishAbsentAndEmptyJournalsWithoutCreatingMissingStorage() throws {
        try fixture { f in
            let before = try snapshot(f), path = f.directory.path + "/SharedSetupImport"
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            let absent = try RetainedInputs.capture(expected: before, journal: nil,
                verifyCurrent: { try before.requireCurrent(machine: f.machine(), candidate: f.candidate) },
                readRelay: { _ in XCTFail("Absent journal read a relay"); throw Fault.body })
            XCTAssertFalse(absent.journalPresent); XCTAssertNil(absent.intent); XCTAssertNil(absent.relay)
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            let store = try journal(f, account: before.preparation, initialize: true)
            defer { try? store.close() }
            try f.machine().withSharedImportSnapshot(journal: store) { _, _ in
                let current = try snapshot(f)
                let empty = try RetainedInputs.capture(expected: current, journal: store,
                    verifyCurrent: { try current.requireCurrent(machine: f.machine(), candidate: f.candidate) },
                    readRelay: { _ in XCTFail("Empty journal read a relay"); throw Fault.body })
                XCTAssertTrue(empty.journalPresent); XCTAssertNil(empty.intent); XCTAssertNil(empty.relay)
                XCTAssertThrowsError(try empty.requireSame(as: absent)) {
                    XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
                }
                try empty.requireSource(current)
                XCTAssertEqual(empty.description, "MachineUpdateRetainedSetupRuntimeInputs(redacted)")
                XCTAssertEqual(empty.debugDescription, empty.description)
            }
        }
    }

    func testRetainedRuntimeInputAcknowledgementUsesTheActualImportWriterAndRejectsReplay() throws {
        try importFixture { f, intent, store in
            try f.machine().withSharedImportSnapshot(journal: store) { _, _ in
                let expected = try snapshot(f)
                var reads = 0
                let before = try RetainedInputs.capture(expected: expected, journal: store,
                    verifyCurrent: { try expected.requireCurrent(machine: f.machine(), candidate: f.candidate) },
                    readRelay: { value in reads += 1; XCTAssertEqual(value, intent); return try .init(plan: nil, snapshot: nil) })
                XCTAssertEqual(reads, 2)
                let changed = try advance(f, expected: expected, previous: intent, journal: store)
                let after = try RetainedInputs.capture(expected: changed.snapshot, journal: store,
                    verifyCurrent: { try changed.snapshot.requireCurrent(machine: f.machine(), candidate: f.candidate) },
                    readRelay: { _ in try .init(plan: nil, snapshot: nil) })
                XCTAssertEqual(after.intent, changed.intent)
                XCTAssertEqual(try store.current(scope: intent.scope), changed.intent)
                try after.requirePublicationAcknowledgement(from: before)
                for (actual, previous) in [(before, before), (after, after), (before, after)] {
                    XCTAssertThrowsError(try actual.requirePublicationAcknowledgement(from: previous)) {
                        XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
                    }
                }
            }
        }
    }

    func testRetainedRuntimeInputsRejectJournalAndRelayChangesDuringTheDoubleRead() throws {
        try importFixture { f, intent, store in
            try f.machine().withSharedImportSnapshot(journal: store) { _, _ in
                let expected = try snapshot(f)
                var reads = 0
                XCTAssertThrowsError(try RetainedInputs.capture(expected: expected, journal: store,
                    verifyCurrent: { try f.directory.validate() }, readRelay: { _ in
                        reads += 1
                        _ = try store.advance(intent, to: .runtimePublished)
                        return try .init(plan: nil, snapshot: nil)
                    })) {
                    XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope)
                }
                XCTAssertEqual(reads, 1)
                let published = try snapshot(f)
                try withPublicRelaySelection { foreignRelay, _, _ in
                    reads = 0
                    XCTAssertThrowsError(try RetainedInputs.capture(expected: published, journal: store,
                        verifyCurrent: { try published.requireCurrent(machine: f.machine(), candidate: f.candidate) },
                        readRelay: { _ in
                            reads += 1
                            if reads == 1 { return try .init(plan: nil, snapshot: nil) }
                            return foreignRelay
                        })) {
                        XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
                    }
                    XCTAssertEqual(reads, 2)
                }
            }
        }
    }

    func testRetainedRuntimeInputsRejectWrongDestinationsPrematurePhasesAndNativeOrdinaryUID() throws {
        try importFixture(published: false) { f, intent, store in
            try f.machine().withSharedImportSnapshot(journal: store) { _, _ in
                let expected = try snapshot(f)
                let foreign = try journal(f, account: expected.preparation, initialize: true,
                    component: "ForeignInputDestination", installationID: AccountPreparationIntent.randomID())
                defer { try? foreign.close() }
                XCTAssertThrowsError(try RetainedInputs.capture(expected: expected, journal: foreign,
                    verifyCurrent: { try f.directory.validate() }, readRelay: { _ in try .init(plan: nil, snapshot: nil) })) {
                    XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope)
                }
                _ = try store.advance(intent, to: .runtimePublished)
                XCTAssertThrowsError(try RetainedInputs.capture(expected: snapshot(f), journal: store,
                    verifyCurrent: { try f.directory.validate() }, readRelay: { _ in try .init(plan: nil, snapshot: nil) })) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .incomplete)
                }
                guard getuid() != 0 else { return XCTFail("The fixture requires an ordinary owner") }
                var verifications = 0
                XCTAssertThrowsError(try RetainedInputs.captureNative(expected: expected, verifyCurrent: { verifications += 1 })) {
                    XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                }
                XCTAssertEqual(verifications, 0)
            }
        }
    }

    func testRetainedRuntimeInputsPropagateOwnerFailuresAndRelaySelectionPinsActualPublicBytes() throws {
        try importFixture { f, _, store in
            try f.machine().withSharedImportSnapshot(journal: store) { _, _ in
                let expected = try snapshot(f)
                for failAt in 1...3 {
                    var calls = 0
                    XCTAssertThrowsError(try RetainedInputs.capture(expected: expected, journal: store,
                        verifyCurrent: {
                            calls += 1
                            if calls == failAt { throw Fault.body }
                            try expected.requireCurrent(machine: f.machine(), candidate: f.candidate)
                        }, readRelay: { _ in try .init(plan: nil, snapshot: nil) })) { XCTAssertTrue($0 is Fault) }
                    XCTAssertEqual(calls, failAt)
                }
            }
        }
        try withPublicRelaySelection { actual, plan, snapshot in
            XCTAssertEqual(actual.plan, plan)
            XCTAssertEqual(snapshot.digest, Data(SHA256.hash(data: plan.bytes)))
            XCTAssertThrowsError(try RelaySelection(plan: plan, snapshot: nil))
            XCTAssertThrowsError(try RelaySelection(plan: nil, snapshot: snapshot))
            let changed = SharedSetupImportRelayStorage.Snapshot(identity: snapshot.identity, digest: Data(repeating: 0, count: 32))
            XCTAssertThrowsError(try RelaySelection(plan: plan, snapshot: changed)) {
                XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
            }
        }
    }

    private typealias ImportPreparation = MachineUpdateStableRuntimeImportPreparation
    private func prepareImport(_ f: Fixture, expected: Snapshot, journal: SharedSetupImportJournal? = nil, publish: ImportPreparation.Publish,
        validate: ImportPreparation.Validate) throws -> RuntimePreparationState {
        if let journal {
            return try ImportPreparation.prepareInJournal(machine: f.machine(), expected: expected, candidate: f.candidate,
                directory: f.directory, admission: f.admission, journal: journal, fileCustodyAccepted: true,
                verifyCurrent: { _ in try f.directory.validate() }, readRelay: { _ in try .init(plan: nil, snapshot: nil) },
                publish: publish, validatePublished: validate)
        }
        return try ImportPreparation.prepare(machine: f.machine(), expected: expected, candidate: f.candidate,
            directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
            verifyCurrent: { _ in try f.directory.validate() }, publish: publish, validatePublished: validate)
    }

    func testStableImportPreparationOrdersValidationBeforeActualAcknowledgementAndDoesNotReplayIt() throws {
        var armed = false, commits = 0
        try importFixture(hook: { _ in if armed { commits += 1 } }) { f, intent, store in
            var events: [String] = [], escaped: (() throws -> Void)?
            let expected = try f.machine().withSharedImportSnapshot(journal: store) { _, _ in try snapshot(f) }
            armed = true
            let result = try prepareImport(f, expected: expected, journal: store, publish: { retained, relay, verify in
                events.append("publish"); escaped = verify
                XCTAssertEqual(retained, intent); XCTAssertNil(relay)
                let box = CallbackBox(verify), semaphore = DispatchSemaphore(value: 0)
                DispatchQueue.global().async { box.invoke(); semaphore.signal() }
                XCTAssertEqual(semaphore.wait(timeout: .now() + 5), .success)
                XCTAssertEqual(box.result(), .invalidated)
                try verify(); return expected.state
            }, validate: { retained, relay, state, verify in
                events.append("validate"); XCTAssertEqual(retained, intent); XCTAssertNil(relay)
                XCTAssertEqual(state, expected.state)
                XCTAssertEqual(try store.current(scope: intent.scope)?.phase, .retained)
                try verify()
            })
            XCTAssertEqual(events, ["publish", "validate"])
            XCTAssertEqual(result, expected.state); XCTAssertEqual(commits, 1)
            XCTAssertEqual(try store.current(scope: intent.scope)?.phase, .runtimePublished)
            XCTAssertThrowsError(try XCTUnwrap(escaped)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            let acknowledged = try XCTUnwrap(store.current(scope: intent.scope))
            let current = try f.machine().withSharedImportSnapshot(journal: store) { _, _ in try snapshot(f) }
            _ = try prepareImport(f, expected: current, publish: { _, _, verify in try verify(); return current.state },
                validate: { _, _, state, verify in XCTAssertEqual(state, current.state); try verify() })
            XCTAssertEqual(commits, 1)
            XCTAssertEqual(try store.current(scope: intent.scope), acknowledged)
        }
    }

    func testStableImportPreparationWithoutAJournalUsesTheActualMetadataWriters() throws {
        try fixture { f in
            let expected = try snapshot(f), selected = try reference(expected.plan)
            let path = f.directory.path + "/SharedSetupImport"
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            let result = try prepareImport(f, expected: expected, publish: { retained, relay, verify in
                XCTAssertNil(retained); XCTAssertNil(relay); try verify()
                // Owned SQL models publication metadata. A native file producer remains a separate prerequisite.
                _ = try f.machine().retainStableRuntimeMaterial(selected, expected: expected, candidate: f.candidate,
                    directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                    verifyScoped: { _, _ in try f.directory.validate() })
                _ = try f.machine().completeStableRuntimePublication(selected, expected: snapshot(f), candidate: f.candidate,
                    directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                    verifyScoped: { _, _ in try f.directory.validate() })
                try verify(); return try snapshot(f).state
            }, validate: { retained, relay, state, verify in
                XCTAssertNil(retained); XCTAssertNil(relay)
                XCTAssertEqual(state, try snapshot(f).state); try verify()
            })
            XCTAssertEqual(result.reference, selected); XCTAssertTrue(result.configurationPublished)
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }

    func testStableImportPreparationRequiresCustodyAndRefusesNativeOrdinaryUIDBeforeCallbacks() throws {
        try fixture { f in
            let expected = try snapshot(f)
            var callbacks = 0
            let publish: ImportPreparation.Publish = { _, _, _ in callbacks += 1; return expected.state }
            let validate: ImportPreparation.Validate = { _, _, _, _ in callbacks += 1 }
            XCTAssertThrowsError(try ImportPreparation.prepare(machine: f.machine(), expected: expected,
                candidate: f.candidate, directory: f.directory, admission: f.admission, fileCustodyAccepted: false,
                verifyCurrent: { _ in callbacks += 1 }, publish: publish, validatePublished: validate)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
            }
            XCTAssertEqual(callbacks, 0)
            guard getuid() != 0 else { return XCTFail("The fixture requires an ordinary owner") }
            XCTAssertThrowsError(try ImportPreparation.prepareNative(machine: f.machine(), expected: expected,
                candidate: f.candidate, directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                verifyCurrent: { _ in callbacks += 1 }, publish: publish, validatePublished: validate)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertEqual(callbacks, 0)
            try snapshot(f).requireSame(as: expected)
        }
    }

    func testStableImportPreparationExpiresEscapedVerificationOnPublishAndValidationFailure() throws {
        for failDuringPublish in [true, false] {
            try importFixture { f, intent, store in
                let expected = try f.machine().withSharedImportSnapshot(journal: store) { _, _ in try snapshot(f) }
                var escaped: (() throws -> Void)?, validations = 0
                XCTAssertThrowsError(try prepareImport(f, expected: expected, publish: { _, _, verify in
                    escaped = verify; try verify()
                    if failDuringPublish { throw Fault.body }
                    return expected.state
                }, validate: { _, _, _, verify in
                    validations += 1; escaped = verify; try verify(); throw Fault.body
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertEqual(validations, failDuringPublish ? 0 : 1)
                XCTAssertEqual(try store.current(scope: intent.scope), intent)
                XCTAssertThrowsError(try XCTUnwrap(escaped)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            }
        }
    }

    func testStableImportPreparationRejectsUnexpectedJournalWritesWithoutRepeatingThem() throws {
        var armed = false, commits = 0
        try importFixture(hook: { _ in if armed { commits += 1 } }) { f, intent, store in
            let expected = try f.machine().withSharedImportSnapshot(journal: store) { _, _ in try snapshot(f) }
            armed = true
            var validations = 0
            XCTAssertThrowsError(try prepareImport(f, expected: expected, publish: { _, _, verify in
                try verify(); _ = try store.advance(intent, to: .runtimePublished); return expected.state
            }, validate: { _, _, _, _ in validations += 1 })) {
                XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope)
            }
            XCTAssertEqual(validations, 0); XCTAssertEqual(commits, 1)
            XCTAssertEqual(try store.current(scope: intent.scope)?.phase, .runtimePublished)
        }
    }

    func testStableImportPreparationRefusesAnIncorrectPublishedStateBeforeValidationOrAcknowledgement() throws {
        try importFixture { f, intent, store in
            let expected = try f.machine().withSharedImportSnapshot(journal: store) { _, _ in try snapshot(f) }
            var validations = 0
            XCTAssertThrowsError(try prepareImport(f, expected: expected, publish: { _, _, verify in
                try verify(); return .init(reference: nil, configurationPublished: false)
            }, validate: { _, _, _, _ in validations += 1 })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            XCTAssertEqual(validations, 0)
            XCTAssertEqual(try store.current(scope: intent.scope), intent)
        }
    }

    func testStableImportPreparationRefusesAChangedRelayBeforeThePublicationCallback() throws {
        try importFixture { f, intent, store in
            let expected = try f.machine().withSharedImportSnapshot(journal: store) { _, _ in try snapshot(f) }
            try withPublicRelaySelection { foreignRelay, _, _ in
                var reads = 0, publications = 0
                XCTAssertThrowsError(try ImportPreparation.prepareInJournal(machine: f.machine(), expected: expected,
                    candidate: f.candidate, directory: f.directory, admission: f.admission, journal: store,
                    fileCustodyAccepted: true, verifyCurrent: { _ in try f.directory.validate() }, readRelay: { _ in
                        reads += 1
                        if reads == 1 { return try .init(plan: nil, snapshot: nil) }
                        return foreignRelay
                    }, publish: { _, _, _ in publications += 1; return expected.state }, validatePublished: { _, _, _, _ in
                        XCTFail("Changed relay reached validation")
                    })) {
                    XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
                }
                XCTAssertEqual(reads, 2); XCTAssertEqual(publications, 0)
                XCTAssertEqual(try store.current(scope: intent.scope), intent)
            }
        }
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
            // The scope closes the directory; validate checks closed before retired.
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate()) { XCTAssertEqual($0 as? JournalLeaseError, .closed) }
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
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate()) { XCTAssertEqual($0 as? JournalLeaseError, .closed) }
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
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate()) { XCTAssertEqual($0 as? JournalLeaseError, .closed) }
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
