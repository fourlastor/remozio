import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned files and journals prove acknowledgement ordering. They grant no native custody, provider or caller evidence.
final class RetainedSetupImportAcknowledgementOwnerTests: XCTestCase {
    private typealias Entry = MachineUpdateRetainedSetupInitialRuntimeEntry
    private typealias Inputs = MachineUpdateRetainedSetupRuntimeInputs
    private typealias Frame = PreparationIntentStore.RetainedImportFrame
    private typealias Owner = MachineUpdateRetainedSetupImportAcknowledgement
    private typealias Scope = Owner.Scope
    private typealias Artifact = Owner.Artifact
    private typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    private typealias Stage = PreparationIntentStore.RetainedImportStage
    private typealias Read = PreparationIntentStore.InitialRuntimeRead
    private enum Fault: Error { case before, afterCommit }
    private final class SharedScope: @unchecked Sendable {
        let scope: Scope
        private let lock = NSLock()
        private var failure: JournalLeaseError?
        init(_ scope: Scope) { self.scope = scope }
        func invoke() {
            let caught: JournalLeaseError?
            do { _ = try scope.read(); caught = nil } catch { caught = error as? JournalLeaseError }
            lock.lock(); failure = caught; lock.unlock()
        }
        func result() -> JournalLeaseError? { lock.lock(); defer { lock.unlock() }; return failure }
    }
    private final class State {
        let f: RetainedPolicyWriterFixture
        let initial: SharedSetupImportIntent
        var journal: SharedSetupImportJournal!
        init(_ f: RetainedPolicyWriterFixture) throws {
            self.f = f
            let runtime = f.source.runtime, account = runtime.preparation
            let inventory = try runtime.setup.source.provisioningInventory(accountID: account.accountID,
                ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
            let defaults = try SharedSetupDefaults(presence: .init(idleMilliseconds: 123_000,
                observationLifetimeMilliseconds: 7000, unavailableGraceMilliseconds: 45_000),
                gateway: GatewaySetupForm().settingsSelection())
            let cloud = try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32),
                zoneID: String(repeating: "b", count: 32), dnsSuffix: "owned.example", apiToken: "synthetic-only")
            initial = try .init(scope: .init(account: account, inventory: inventory),
                proposal: .init(defaults: defaults, cloudflare: cloud))
            try open(initialize: true); try journal.begin(initial); try journal.close()
            let machine = URL(fileURLWithPath: f.directory.path)
            let directory = try ProtectedSetupDirectory(anchor: machine.deletingLastPathComponent().path,
                relativePath: machine.lastPathComponent + "/SharedSetupImport", owner: getuid())
            defer { directory.close() }
            let relay = try SharedSetupImportRelayPlan(expected: initial, port: 45678)
            _ = try AdministrativeSetupPublication.publish(relay.bytes, file: .importRelayPlan(accountID: account.accountID),
                directory: directory, owner: getuid())
        }
        func open(initialize: Bool) throws {
            let machine = URL(fileURLWithPath: f.directory.path), anchor = machine.deletingLastPathComponent().path
            let relative = machine.lastPathComponent + "/SharedSetupImport"
            if initialize {
                let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: relative, owner: getuid())
                defer { directory.close() }
                _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .sharedSetupImport, owner: getuid())
            }
            journal = try .init(lease: .init(anchor: anchor, relativeDirectory: relative, owner: getuid(), ancestorOwner: getuid(),
                databaseName: "setup-import.sqlite"), owner: getuid(), macID: initial.scope.macID,
                installationID: initial.scope.installationID, initialize: initialize)
        }
        func reopen() throws { try? journal.close(); try f.reopen(nil) }
        func current() throws -> SharedSetupImportIntent? {
            try open(initialize: false); defer { try? journal.close() }
            return try journal.current(scope: initial.scope)
        }
    }
    private func fixture(_ body: (State) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(sharedImportFormats: true) { f in
            let before = try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
            let recorded = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: before, candidate: f.candidate,
                directory: f.directory, admission: f.admission, useMachine: { body in
                    try f.reopen(nil); let machine = f.machine(); defer { try? machine.close() }; return try body(machine)
                }, openJournal: { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) }, verifySnapshot: { _ in })
            try f.reopen(nil)
            _ = try f.machine().completeRetainedSetupRuntimePublication(f.material.reference,
                expected: recorded.activation.runtime, policy: XCTUnwrap(recorded.intent), candidate: f.candidate,
                directory: f.directory, admission: f.admission, fileCustodyAccepted: true, verifyScoped: { _, _ in })
            let state = try State(f); defer { try? state.journal.close(); try? f.machine().close() }
            try body(state)
        }
    }

    private final class Files {
        let root: URL, artifacts: [Artifact]
        init(_ artifacts: [Artifact]) throws {
            self.artifacts = artifacts
            root = URL(fileURLWithPath: "/private/tmp/remozio-ack-owner-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
            for artifact in artifacts { try put(artifact, bytes: artifact.bytes) }
        }
        func url(_ artifact: Artifact) -> URL { root.appendingPathComponent(URL(fileURLWithPath: artifact.path).lastPathComponent) }
        func put(_ artifact: Artifact, bytes: Data) throws {
            try bytes.write(to: url(artifact))
            guard chmod(url(artifact).path, artifact.access == .publicRoot ? 0o644 : 0o600) == 0 else {
                throw JournalLeaseError.system(errno)
            }
        }
        func read(_ artifact: Artifact) throws -> Data? {
            try ProtectedServiceConfiguration.readOptional(anchor: root.path, relativePath: url(artifact).lastPathComponent, owner: getuid())
        }
        func stamps() throws -> [[UInt64]] {
            try artifacts.map { artifact in
                var s = stat(); guard lstat(url(artifact).path, &s) == 0 else { throw JournalLeaseError.system(errno) }
                return [UInt64(s.st_ino), UInt64(s.st_mtimespec.tv_sec), UInt64(s.st_mtimespec.tv_nsec),
                    UInt64(s.st_ctimespec.tv_sec), UInt64(s.st_ctimespec.tv_nsec)]
            }
        }
        func close() throws { try FileManager.default.removeItem(at: root) }
    }
    private final class Checks {
        var pair = 0, material = 0, artifacts = 0, source = 0
        var scopes: [Scope] = [], counts: [Read: Int] = [:]
        var onMaterial: ((Scope) throws -> RuntimePreparationMaterial?)?
        var onPair: ((Int, Boundary) throws -> Boundary)?
        var onFile: ((Artifact, Scope) throws -> Data?)?
    }
    private func entry(_ s: State) throws -> Entry {
        try s.f.machine().retainedSetupInitialRuntimeEntry(owner: s.f.source.runtime.setup.owner, candidate: s.f.candidate)
    }
    private func pair(_ s: State) throws -> Boundary {
        let journal = try s.f.openPolicyJournal(.readOnly); defer { try? journal.close() }
        return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(s.f.source.runtime.setup.account?.initialization))
    }
    private func withFiles(_ body: (State, Files) throws -> Void) throws {
        try fixture { s in
            let expected = try entry(s), current = try pair(s), machine = s.f.machine()
            let bundle = try machine.withSharedImportJournal { journal in
                try machine.withSharedImportSnapshot(journal: XCTUnwrap(journal)) { directory, owner in
                    let actual = try entry(s)
                    let inputs = try Inputs.capture(expected: actual.runtime, journal: journal,
                        verifyCurrent: { try machine.validateStorageLease() }, readRelay: { try .read($0, directory: directory, owner: owner) })
                    return try RuntimeConfigurationBundle.retainedSetupInitialObservation(snapshot: XCTUnwrap(actual.policy),
                        current: current, candidate: s.f.candidate, inputs: inputs)
                }
            }
            XCTAssertEqual(bundle.command.presence.presence.policy.idleMilliseconds, 123_000)
            XCTAssertEqual(bundle.transport.relayPort, 45678)
            let files = try Files(RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: s.f.material))
            defer { XCTAssertNoThrow(try files.close()) }
            try expected.requireSame(as: entry(s)); try body(s, files)
        }
    }
    private func invoke(_ s: State, _ files: Files, checks: Checks = Checks(), custody: Bool = true)
        throws -> (frame: Frame, advanced: Bool) {
        let expected = try entry(s), machine = s.f.machine()
        machine.observeStoreRead = { checks.counts[$0, default: 0] += 1 }
        defer { machine.observeStoreRead = nil }
        let start = ContinuousClock.now
        defer {
            let elapsed = start.duration(to: .now)
            print("A10c ACK invocation upper bound for either read transaction: \(elapsed)")
            XCTAssertLessThanOrEqual(elapsed, .seconds(60), "Report to Toni before any further validation")
        }
        return try Owner.acknowledge(machine: machine, expected: expected, candidate: s.f.candidate,
            directory: s.f.directory, admission: s.f.admission, fileCustodyAccepted: custody,
            readPolicyBoundary: {
                checks.pair += 1; let actual = try pair(s)
                return try checks.onPair?(checks.pair, actual) ?? actual
            }, verifyCurrent: { scope in
                checks.source += 1; let before = checks.counts
                _ = try scope.read(); _ = try scope.read(); try scope.withActive { try scope.requireActive() }
                XCTAssertEqual(before, checks.counts)
                XCTAssertThrowsError(try machine.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            }, verifyServices: { XCTAssertEqual(try $0.encoded, try s.f.material.services.encoded) },
            readMaterial: { scope in try scope.withActive {
                checks.scopes.append(scope); checks.material += 1
                return try checks.onMaterial?(scope) ?? s.f.material
            } }, verifyActivity: { activity, scope in try scope.withActive {
                XCTAssertEqual(activity, s.f.material.serviceActivity)
            } }, readArtifact: { artifact, scope in try scope.withActive {
                checks.artifacts += 1; XCTAssertEqual(scope.artifact?.path, artifact.path)
                if let onFile = checks.onFile { return try onFile(artifact, scope) }
                return try files.read(artifact)
            } })
    }
    private func budget(_ checks: Checks) {
        XCTAssertEqual(checks.pair, 4); XCTAssertEqual(checks.material, 4)
        XCTAssertEqual(checks.artifacts, 16); XCTAssertEqual(checks.source, 4)
        XCTAssertEqual(checks.pair / 2, 2); XCTAssertLessThanOrEqual(checks.pair / 2, 4)
        XCTAssertEqual(checks.counts[.writeTransaction, default: 0], 0)
        XCTAssertEqual(checks.counts[.importInputs], 2)
        for scope in checks.scopes { XCTAssertThrowsError(try scope.read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) } }
    }
    func testRealFilesAdvanceOnceAndFreshRecoveryHasTwoObservationsWithoutRepair() throws {
        try withFiles { s, files in
            let original = try files.artifacts.map { try files.read($0) }, stamps = try files.stamps(), first = Checks()
            let advanced = try invoke(s, files, checks: first); budget(first)
            XCTAssertTrue(advanced.advanced); XCTAssertEqual(advanced.frame.inputs.intent?.phase, .runtimePublished)
            XCTAssertNotEqual(advanced.frame.inputs.intent?.revision, s.initial.revision)
            let second = Checks(), recovered = try invoke(s, files, checks: second); budget(second)
            XCTAssertFalse(recovered.advanced); try recovered.frame.entry.requireSame(as: advanced.frame.entry)
            try recovered.frame.inputs.requireSame(as: advanced.frame.inputs)
            XCTAssertEqual(try files.artifacts.map { try files.read($0) }, original)
            XCTAssertEqual(try files.stamps(), stamps)
        }
    }
    func testEachMissingFileRefusesBeforeAdvanceWithoutCreatingBytes() throws {
        try withFiles { s, files in
            for artifact in files.artifacts {
                try FileManager.default.removeItem(at: files.url(artifact))
                XCTAssertThrowsError(try invoke(s, files)) {
                    XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
                }
                XCTAssertFalse(FileManager.default.fileExists(atPath: files.url(artifact).path))
                try s.reopen(); XCTAssertEqual(try s.current(), s.initial)
                try files.put(artifact, bytes: artifact.bytes)
            }
        }
    }
    func testEachConflictingFileInAcknowledgedRecoveryRefusesWithoutRepairOrReplay() throws {
        try withFiles { s, files in
            let committed = try invoke(s, files).frame.inputs.intent
            for artifact in files.artifacts {
                try files.put(artifact, bytes: Data([0]))
                XCTAssertThrowsError(try invoke(s, files))
                XCTAssertEqual(try files.read(artifact), Data([0]))
                try s.reopen(); XCTAssertEqual(try s.current(), committed)
                try files.put(artifact, bytes: artifact.bytes)
            }
        }
    }
    func testChangedPairRefusesBeforeCommitAndAFreshExactInvocationCanAdvance() throws {
        try withFiles { s, files in
            let checks = Checks()
            checks.onPair = { n, current in
                n == 1 ? current : Boundary(macID: current.macID, accountID: current.accountID,
                    policy: .init(revision: UUID(), policy: current.policy.policy, roleRevisions: current.policy.roleRevisions),
                    checkpoint: current.checkpoint)
            }
            XCTAssertThrowsError(try invoke(s, files, checks: checks))
            try s.reopen(); XCTAssertEqual(try s.current(), s.initial)
            XCTAssertTrue(try invoke(s, files).advanced)
        }
    }
    func testChangedMaterialAfterCommitRequiresFreshReadOnlyRecovery() throws {
        try withFiles { s, files in
            let material = s.f.material, checks = Checks()
            let foreign = try RuntimePreparationMaterial(materialID: AccountPreparationIntent.randomID(), services: material.services,
                transportIdentity: material.transportIdentity, transportPublicKeyInfo: material.transportPublicKeyInfo,
                gateway: material.gateway, serviceActivity: material.serviceActivity, auditDeliveryVersion: material.auditDeliveryVersion)
            checks.onMaterial = { scope in try scope.read().inputs.intent?.phase == .runtimePublished ? foreign : material }
            XCTAssertThrowsError(try invoke(s, files, checks: checks)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertThrowsError(try s.f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try s.reopen(); let committed = try XCTUnwrap(s.current())
            XCTAssertEqual(committed.phase, .runtimePublished); XCTAssertNotEqual(committed.revision, s.initial.revision)
            let result = try invoke(s, files)
            XCTAssertFalse(result.advanced); XCTAssertEqual(result.frame.inputs.intent, committed)
        }
    }
    func testPostCommitFileFailureDoesNotRepairAndFreshRecoveryDoesNotAdvance() throws {
        try withFiles { s, files in
            let checks = Checks(), artifact = try XCTUnwrap(files.artifacts.last)
            checks.onFile = { actual, scope in
                if try scope.read().inputs.intent?.phase == .runtimePublished && actual.path == artifact.path {
                    try files.put(artifact, bytes: Data([0]))
                }
                return try files.read(actual)
            }
            XCTAssertThrowsError(try invoke(s, files, checks: checks))
            XCTAssertEqual(try files.read(artifact), Data([0])); try s.reopen()
            let committed = try s.current(); XCTAssertEqual(committed?.phase, .runtimePublished)
            XCTAssertThrowsError(try invoke(s, files)); try s.reopen()
            XCTAssertEqual(try s.current(), committed)
            try files.put(artifact, bytes: artifact.bytes)
            XCTAssertFalse(try invoke(s, files).advanced); XCTAssertEqual(try s.current(), committed)
        }
    }
    func testMissingCustodyInvokesNoProviderAndKeepsTheRetainedIntent() throws {
        try withFiles { s, files in
            let checks = Checks()
            XCTAssertThrowsError(try invoke(s, files, checks: checks, custody: false)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
            }
            XCTAssertEqual(checks.pair + checks.material + checks.artifacts + checks.source, 0)
            XCTAssertTrue(checks.counts.isEmpty); XCTAssertEqual(try s.current(), s.initial)
        }
    }
    func testReentryPoisonsTheLoanAndForeignThreadsCannotUseIt() throws {
        try withFiles { s, files in
            let checks = Checks()
            checks.onMaterial = { scope in
                let shared = SharedScope(scope), done = DispatchSemaphore(value: 0)
                DispatchQueue.global().async { shared.invoke(); done.signal() }
                XCTAssertEqual(done.wait(timeout: .now() + 2), .success)
                XCTAssertEqual(shared.result(), JournalLeaseError.invalidated)
                XCTAssertThrowsError(try scope.withActive {}) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
                return s.f.material
            }
            XCTAssertThrowsError(try invoke(s, files, checks: checks))
            try s.reopen(); XCTAssertEqual(try s.current(), s.initial)
            XCTAssertTrue(try invoke(s, files).advanced)
        }
    }
}
