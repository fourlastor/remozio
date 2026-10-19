import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class GatewayJournalSetupStoreTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Counter { var calls = 0; var creations = 0 }
    private static let pem = Result { () throws -> String in
        let p = Process(), out = Pipe(); p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run(); let bytes = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw Interrupted() }; return String(decoding: bytes, as: UTF8.self)
    }
    private final class Fixture {
        let runtime: RuntimeActivationFixture
        let root: URL
        let parent: ProtectedSetupDirectory
        let material: GatewayPreparationMaterial
        let bundle: GatewayConfigurationBundle
        let intent: GatewayJournalSetupIntent
        let epoch = UUID()
        var machine: PreparationIntentStore { runtime.machine }
        var path: String { parent.path + "/Gateway/gateway.sqlite" }
        init(retainMaterial: Bool = true) throws {
            guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner SQLite and file fixture") }
            runtime = try .init()
            try runtime.machine.retainRuntimeActivation(runtime.plan)
            _ = try runtime.machine.enrollRuntimeActivation(runtime.plan)
            try runtime.machine.markRuntimeJobsRegistered(runtime.plan)
            let provider = try SetupFCMConfiguration(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
                privateKeyID: "fixture-key", privateKeyPEM: GatewayJournalSetupStoreTests.pem.get())
            material = try .create(runtime: runtime.material.reference, provider: provider, senderID: "123",
                packageName: "dev.remozio.android", fileWakeCustodyAccepted: true)
            if retainMaterial { try runtime.machine.retainGatewayMaterial(material.reference) }
            let settings = try GatewayServiceSettings(delivery: .init(maximumFlights: 4, minimumSendIntervalMillis: 1000),
                probe: .init(maximumAttempts: 3, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 300),
                wake: .init(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000,
                    maximumLifetimeMillis: 300000, maximumTTLSeconds: 300))
            bundle = try .init(foreground: runtime.plan, material: material.reference,
                inventory: XCTUnwrap(runtime.machine.inventory()), settings: settings)
            root = URL(fileURLWithPath: "/private/tmp/remozio-gateway-state-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            parent = try .init(anchor: root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
            let files = try GatewayJournalFileProvisioning.prepare(parent: parent, processOwner: getuid(), serviceUID: getuid(), serviceGID: getgid(),
                mode: .createIfAbsent, expected: nil, verifyCurrent: {}).identity
            intent = try .init(id: AccountPreparationIntent.randomID(), material: material.reference, configuration: bundle.gateway, files: files)
        }
        deinit { parent.close(); try? FileManager.default.removeItem(at: root) }
        func state(_ machine: PreparationIntentStore? = nil) throws -> GatewayJournalPreparationState {
            try (machine ?? self.machine).gatewayJournalPreparation(accountID: intent.accountID)
        }
        func lease() throws -> ProtectedGatewayLease {
            try .init(anchor: root.path, relativeDirectory: "Service/Gateway", serviceUID: getuid(), ancestorUID: getuid())
        }
        func initialize(_ allowed: Bool) throws -> GatewayJournalInitialization.Result {
            try GatewayJournalInitialization.resume(registration: intent.configuration.registration, mayInitializeEmpty: allowed, verifyCurrent: {},
                openJournal: { initialize in
                    let lease = try self.lease()
                    do {
                        guard try lease.fileIdentity() == self.intent.files else { throw JournalLeaseError.identityChanged }
                        let settings = self.intent.configuration.settings, limits = try CBORLimits(maxBytes: 65536, maxDepth: 8, maxItems: 256)
                        return try GatewayDatabase(lease: lease, identity: self.intent.configuration.registration, payloadLimits: limits, signingLimits: limits,
                            maximumOperations: settings.maximumStoredControls, maximumPendingPerEnrollment: settings.maximumPendingPerEnrollment,
                            maximumLifetimeMillis: settings.maximumCandidateLifetimeMillis, clockEpoch: self.epoch,
                            busyMilliseconds: settings.databaseBusyMillis, initialize: initialize, probePolicy: settings.probe)
                    } catch { lease.close(); throw error }
                })
        }
        func resume(_ counter: Counter, expected: GatewayJournalPreparationState? = nil,
                    verify: () throws -> Void = {}, stage: (GatewayJournalPreparationController.Stage) throws -> Void = { _ in }) throws -> GatewayJournalPreparationState {
            try GatewayJournalPreparationController.resume(machine: machine, expected: expected ?? state(), verifyCurrent: verify,
                inspectFiles: { intent in
                    _ = try GatewayJournalFileProvisioning.prepare(parent: self.parent, processOwner: getuid(), serviceUID: getuid(), serviceGID: getgid(),
                        mode: .requireExisting, expected: intent.files, verifyCurrent: {})
                }, initialize: { intent, allowed in
                    XCTAssertEqual(intent, self.intent); XCTAssertTrue(allowed); counter.calls += 1
                    let result = try self.initialize(allowed); if result.initialized { counter.creations += 1 }; return result
                }, didStage: stage)
        }
    }

    func testIntentRoundTripContainsNoPrivateCredentialAndRejectsAliasedFiles() throws {
        let f = try Fixture(), intent = f.intent, bytes = try intent.encoded
        XCTAssertEqual(try GatewayJournalSetupIntent.decode(bytes), intent)
        XCTAssertNil(bytes.range(of: f.material.providerJSON)); XCTAssertNil(bytes.range(of: f.material.receiptKeyRecord))
        XCTAssertNil(bytes.range(of: try f.material.wakeKeyRecord.encode()))
        XCTAssertEqual(String(reflecting: intent), "GatewayJournalSetupIntent(redacted)")
        XCTAssertEqual(try intent.digest, Data(SHA256.hash(data: bytes)))
        XCTAssertThrowsError(try GatewayJournalSetupIntent(id: intent.id, material: intent.material, configuration: intent.configuration,
            files: .init(directory: intent.files.directory, writer: intent.files.writer, database: intent.files.writer)))
        let limits = try GatewayJournalSetupIntent.limits
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw Interrupted() }
        fields[0] = .unsigned(2)
        XCTAssertThrowsError(try GatewayJournalSetupIntent.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }
    func testReadDoesNotUpgradeAndRetentionPreservesForegroundState() throws {
        let f = try Fixture(retainMaterial: false), machine = f.machine
        XCTAssertNil(try f.state().intent); XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 7)
        XCTAssertThrowsError(try machine.retainGatewayJournalIntent(f.intent))
        try machine.retainGatewayMaterial(f.material.reference)
        XCTAssertNil(try f.state().intent); XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 8)
        let inventory = try machine.inventory(), activation = try machine.runtimeActivation(accountID: f.intent.accountID)
        try machine.retainGatewayJournalIntent(f.intent)
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 9)
        XCTAssertEqual(try f.state(), .init(intent: f.intent, initialized: false))
        try machine.retainGatewayJournalIntent(f.intent)
        XCTAssertEqual(try f.runtime.f.sql("SELECT COUNT(*) FROM gateway_journal_preparation_v1"), 1)
        XCTAssertEqual(try machine.inventory(), inventory)
        XCTAssertEqual(try machine.runtimeActivation(accountID: f.intent.accountID).plan?.encoded, try activation.plan?.encoded)
        XCTAssertEqual(PreparationIntentStore.supportedSchemaVersions, [1,2,3,4,5,6,7,8,9,10,11])
    }
    func testAnAlreadyDeclaredGatewayCannotAcquireANewInitializationIntent() throws {
        let f = try Fixture(), old = try XCTUnwrap(f.machine.inventory()), proposed = try f.bundle.enrolledInventory(old)
        _ = try f.machine.writeInventory(proposed, expectedRevision: old.revision)
        XCTAssertThrowsError(try f.machine.retainGatewayJournalIntent(f.intent)) { XCTAssertEqual($0 as? GatewayPreparationError, .changedScope) }
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 8)
        XCTAssertNil(try f.state().intent)
    }
    func testIntentReplacementAndForeignCodePinsCannotReplaceRetainedScope() throws {
        let f = try Fixture(), intent = f.intent
        try f.machine.retainGatewayJournalIntent(intent)
        let replacement = try GatewayJournalSetupIntent(id: AccountPreparationIntent.randomID(), material: intent.material,
            configuration: intent.configuration, files: intent.files)
        XCTAssertThrowsError(try f.machine.retainGatewayJournalIntent(replacement)) { XCTAssertEqual($0 as? GatewayPreparationError, .conflictingMaterial) }
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 8, maxItems: 256)
        guard case .map(var fields) = try DeterministicCBOR.decode(intent.configuration.canonicalBytes, limits: limits),
              case .array(var peer) = fields[9] else { throw Interrupted() }
        peer[2] = .array([.bytes(Data(repeating: 99, count: 20))]); fields[9] = .array(peer)
        let changed = try GatewayServiceConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: limits))
        let wrong = try GatewayJournalSetupIntent(id: intent.id, material: intent.material, configuration: changed, files: intent.files)
        XCTAssertThrowsError(try f.machine.retainGatewayJournalIntent(wrong)) { XCTAssertEqual($0 as? GatewayPreparationError, .changedScope) }
        XCTAssertEqual(try f.state().intent, intent)
    }
    func testLostIntentAndCompletionRepliesRetainTheirDurableState() throws {
        let f = try Fixture(); try f.machine.close(); var armed = false
        let writer = try f.runtime.f.open(hook: { if armed { throw Interrupted() } }); armed = true
        XCTAssertThrowsError(try writer.retainGatewayJournalIntent(f.intent)) { XCTAssertTrue($0 is Interrupted) }
        try writer.close()
        let restored = try f.runtime.f.open(); XCTAssertEqual(try f.state(restored).intent, f.intent); try restored.close()
        let head = try f.initialize(true).head; armed = false
        let completer = try f.runtime.f.open(hook: { if armed { throw Interrupted() } }); armed = true
        XCTAssertThrowsError(try completer.completeGatewayJournalInitialization(f.intent, head: head)) { XCTAssertTrue($0 is Interrupted) }
        try completer.close(); let completed = try f.runtime.f.open(); defer { try? completed.close() }
        XCTAssertTrue(try f.state(completed).initialized)
        let lease = try f.lease(); defer { lease.close() }
        let state = try f.state(completed)
        let again = try GatewayJournalPreparationController.resume(machine: completed, expected: state, verifyCurrent: {},
            inspectFiles: { _ in XCTFail("Completed setup must not acquire the active service writer") },
            initialize: { _, _ in XCTFail("Completed setup must not initialize again"); throw Interrupted() })
        XCTAssertEqual(again, state)
    }
    func testEveryControllerInterruptionRecoversWithoutReplacingTheJournalOrForegroundState() throws {
        for stop in 0...3 {
            let f = try Fixture(); try f.machine.retainGatewayJournalIntent(f.intent)
            let inventory = try f.machine.inventory(), counter = Counter()
            XCTAssertThrowsError(try f.resume(counter, stage: {
                switch (stop, $0) {
                case (0,.verified), (1,.journalReady), (2,.completionRetained), (3,.completed): throw Interrupted()
                default: break
                }
            })) { XCTAssertTrue($0 is Interrupted) }
            let recovered = try f.resume(counter)
            XCTAssertTrue(recovered.initialized); XCTAssertEqual(counter.creations, 1)
            XCTAssertEqual(recovered.intent?.files, f.intent.files)
            XCTAssertEqual(try f.machine.inventory(), inventory)
            XCTAssertEqual(try f.machine.runtimeActivation(accountID: f.intent.accountID).plan?.encoded, try f.runtime.plan.encoded)
        }
    }
    func testMissingOrReplacedFilesCannotReopenCreationPermission() throws {
        for replace in [false,true] {
            let f = try Fixture(); try f.machine.retainGatewayJournalIntent(f.intent); let counter = Counter()
            try FileManager.default.moveItem(atPath: f.path, toPath: f.path + ".original")
            if replace { XCTAssertTrue(FileManager.default.createFile(atPath: f.path, contents: Data(), attributes: [.posixPermissions: 0o600])) }
            XCTAssertThrowsError(try f.resume(counter))
            XCTAssertEqual(counter.calls, 0); XCTAssertFalse(try f.state().initialized)
            XCTAssertEqual(FileManager.default.fileExists(atPath: f.path), replace)
        }
    }
    func testCompletedRetryDoesNotReadMissingJournalAndANewIntentCannotResetCompletion() throws {
        let f = try Fixture(); try f.machine.retainGatewayJournalIntent(f.intent); let counter = Counter()
        let state = try f.resume(counter); XCTAssertTrue(state.initialized)
        try FileManager.default.removeItem(atPath: f.path)
        XCTAssertEqual(try f.resume(counter), state); XCTAssertEqual(counter.calls, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.path))
        let other = try GatewayJournalSetupIntent(id: AccountPreparationIntent.randomID(), material: f.intent.material,
            configuration: f.intent.configuration, files: f.intent.files)
        XCTAssertThrowsError(try f.machine.retainGatewayJournalIntent(other))
        XCTAssertTrue(try f.state().initialized)
    }
    func testWrongHeadAndStaleCallerCannotCompleteInitialization() throws {
        let f = try Fixture(); try f.machine.retainGatewayJournalIntent(f.intent)
        let head = GatewayHeadEvidence(registration: f.intent.configuration.registration, revision: 1, receipt: nil)
        XCTAssertThrowsError(try f.machine.completeGatewayJournalInitialization(f.intent, head: head))
        let counter = Counter(), expected = try f.state()
        XCTAssertThrowsError(try f.resume(counter, expected: expected, verify: { throw Interrupted() })) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertEqual(counter.calls, 0); XCTAssertFalse(try f.state().initialized)
        _ = try f.resume(counter)
        XCTAssertThrowsError(try f.resume(counter, expected: expected)) { XCTAssertEqual($0 as? GatewayPreparationError, .changedScope) }
    }
    func testInvalidCompletionFlagCannotReopenInitialization() throws {
        let f = try Fixture(); try f.machine.retainGatewayJournalIntent(f.intent)
        let expected = try f.state(), counter = Counter()
        var database: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(f.runtime.f.root.path + "/machine/installation.sqlite", &database,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil), SQLITE_OK)
        let db = try XCTUnwrap(database); defer { sqlite3_close(db) }
        XCTAssertEqual(sqlite3_exec(db, "PRAGMA ignore_check_constraints=ON; UPDATE gateway_journal_preparation_v1 SET initialized=2", nil, nil, nil), SQLITE_OK)
        XCTAssertThrowsError(try f.state()) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
        XCTAssertThrowsError(try f.resume(counter, expected: expected)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
        XCTAssertEqual(counter.calls, 0)
    }
    func testCorruptRecordIndexesIncludingAccountCannotHideEstablishedIntent() throws {
        for change in ["account=zeroblob(16)","intent=zeroblob(16)","material=zeroblob(16)","files=zeroblob(32)","digest=zeroblob(32)","record=x'00'"] {
            let f = try Fixture(); try f.machine.retainGatewayJournalIntent(f.intent)
            _ = try f.runtime.f.sql("UPDATE gateway_journal_preparation_v1 SET " + change)
            XCTAssertThrowsError(try f.state()) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
            XCTAssertThrowsError(try f.state()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            XCTAssertEqual(try f.runtime.f.sql("SELECT COUNT(*) FROM gateway_journal_preparation_v1"), 1)
        }
    }
}
