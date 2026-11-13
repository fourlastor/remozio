import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned files model the eight artifacts. These tests grant no Root, installed placement or service identity evidence.
final class RetainedSetupInitialObservationTests: XCTestCase {
    private typealias Observer = MachineUpdateRetainedSetupInitialObservation
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    private typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    private enum Fault: Error { case stopped }
    private final class SharedScope: @unchecked Sendable {
        let scope: Observer.Scope
        init(_ scope: Observer.Scope) { self.scope = scope }
    }
    private final class Files {
        let root: URL
        let artifacts: [Artifact]
        init(_ artifacts: [Artifact]) throws {
            self.artifacts = artifacts
            root = URL(fileURLWithPath: "/private/tmp/remozio-initial-observation-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
            for artifact in artifacts { try put(artifact, bytes: artifact.bytes) }
        }
        func close() throws { try FileManager.default.removeItem(at: root) }
        func url(_ artifact: Artifact) -> URL { root.appendingPathComponent(URL(fileURLWithPath: artifact.path).lastPathComponent) }
        func put(_ artifact: Artifact, bytes: Data) throws {
            try bytes.write(to: url(artifact))
            let mode: mode_t = artifact.access == .publicRoot ? 0o644 : 0o600
            guard chmod(url(artifact).path, mode) == 0 else { throw JournalLeaseError.system(errno) }
        }
        func read(_ artifact: Artifact) throws -> Data? {
            try ProtectedServiceConfiguration.readOptional(anchor: root.path,
                relativePath: url(artifact).lastPathComponent, owner: getuid())
        }
        func stamps() throws -> [[UInt64]] {
            try artifacts.map { artifact in
                var s = stat(); guard lstat(url(artifact).path, &s) == 0 else { throw JournalLeaseError.system(errno) }
                return [UInt64(s.st_ino), UInt64(s.st_mtimespec.tv_sec), UInt64(s.st_mtimespec.tv_nsec),
                    UInt64(s.st_ctimespec.tv_sec), UInt64(s.st_ctimespec.tv_nsec)]
            }
        }
    }
    private final class State {
        var pairReads = 0, materialReads = 0, artifactReads = 0, inputCaptures = 0, sourceChecks = 0
        var materialReader: ((Int) throws -> RuntimePreparationMaterial)?
        var pairReader: ((Int, Boundary) throws -> Boundary)?
        var inspect: ((Observer.Scope) throws -> Void)?
        var scope: Observer.Scope?
        var inputs: MachineUpdateRetainedSetupRuntimeInputs?
    }
    private func snapshot(_ f: Fixture) throws -> Snapshot {
        try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
    }
    private func pair(_ f: Fixture) throws -> Boundary {
        let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
        return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(f.source.runtime.setup.account?.initialization))
    }
    private func fixture(_ body: (Fixture, Snapshot, Boundary) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture { f in
            let before = try snapshot(f)
            let recorded = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: before, candidate: f.candidate,
                directory: f.directory, admission: f.admission, useMachine: { body in
                    try f.reopen(nil); let machine = f.machine(); defer { try? machine.close() }; return try body(machine)
                }, openJournal: { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) }, verifySnapshot: { _ in })
            try f.reopen(nil); defer { try? f.machine().close() }
            try body(f, recorded, pair(f))
        }
    }
    private func files(_ f: Fixture, _ before: Snapshot, _ current: Boundary,
        intent: SharedSetupImportIntent? = nil, relay: SharedSetupImportRelayPlan? = nil) throws -> Files {
        let configuration = try RuntimeRetainedSetupInitialConfiguration(snapshot: before, current: current,
            candidate: f.candidate, currentCodePolicy: current.policy.policy, importIntent: intent, relayPlan: relay)
        return try Files(RuntimePublishedArtifactValidation.artifacts(bundle: configuration.bundle, material: f.material))
    }
    private func markPublished(_ f: Fixture, _ before: Snapshot) throws -> Snapshot {
        try f.machine().completeRetainedSetupRuntimePublication(XCTUnwrap(before.activation.runtime.state.reference),
            expected: before.activation.runtime, policy: XCTUnwrap(before.intent), candidate: f.candidate,
            directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
            verifyScoped: { _, _ in try XCTUnwrap(before.intent).requireRecorded(self.pair(f)) })
    }
    private func observe<Result>(_ f: Fixture, _ expected: Snapshot, _ files: Files, state: State = State(),
        custody: Bool = true, _ body: (Observer.Observation) throws -> Result) throws -> Result {
        try Observer.withCurrent(machine: f.machine(), expected: expected, candidate: f.candidate,
            directory: f.directory, admission: f.admission, fileCustodyAccepted: custody,
            readPolicyBoundary: {
                state.pairReads += 1; let actual = try self.pair(f)
                return try state.pairReader?(state.pairReads, actual) ?? actual
            }, verifyCurrent: { _ in state.sourceChecks += 1 }, verifyServices: { plan in
                XCTAssertEqual(try plan.encoded, try f.material.services.encoded)
            }, readMaterial: { scope in
                state.scope = scope; try state.inspect?(scope)
                return try scope.withActive {
                    state.materialReads += 1
                    return try state.materialReader?(state.materialReads) ?? f.material
                }
            }, verifyActivity: { activity, scope in try scope.withActive {
                XCTAssertEqual(activity, f.material.serviceActivity)
            } }, readArtifact: { artifact, scope in try scope.withActive {
                XCTAssertEqual(scope.artifact?.path, artifact.path); state.artifactReads += 1
                return try files.read(artifact)
            } }, inspectInputs: { state.inputCaptures += 1; state.inputs = $0 }, body: body)
    }

    func testBothActualPublicationBitsReadTheSameEightDerivedBytesWithoutWrites() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let stamps = try files.stamps(), first = State()
            try observe(f, before, files, state: first) { observation in
                let frame = try observation.read(before)
                XCTAssertFalse(frame.snapshot.activation.runtime.state.configurationPublished)
                XCTAssertFalse(frame.inputs.journalPresent)
            }
            let published = try markPublished(f, before), second = State()
            try observe(f, published, files, state: second) { observation in
                let frame = try observation.read(published)
                XCTAssertTrue(frame.snapshot.activation.runtime.state.configurationPublished)
                XCTAssertThrowsError(try RuntimeRetainedSetupInitialConfiguration(snapshot: published, current: current,
                    candidate: f.candidate, currentCodePolicy: current.policy.policy, importIntent: nil, relayPlan: nil))
                XCTAssertThrowsError(try RuntimeConfigurationBundle.stableInitial(snapshot: published.activation.runtime,
                    reference: XCTUnwrap(published.activation.runtime.state.reference), candidate: f.candidate,
                    currentCodePolicy: current.policy.policy))
            }
            XCTAssertEqual(try files.stamps(), stamps)
            for state in [first, second] {
                XCTAssertEqual(state.pairReads, 2); XCTAssertEqual(state.materialReads, 2)
                XCTAssertEqual(state.artifactReads, 8); XCTAssertEqual(state.inputCaptures, 1)
            }
            try snapshot(f).requireSame(as: published)
        }
    }

    func testTenObservationsUseBorrowedWriterFramesWithoutPublicMachineQueries() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let stamps = try files.stamps(), state = State(); var count = 0, stages = 0
            var escaped: Observer.Observation?
            try observe(f, before, files, state: state) { observation in
                escaped = observation; _ = try observation.read(before); count += 1
                let result = try f.machine().completeRetainedSetupRuntimePublication(XCTUnwrap(before.activation.runtime.state.reference),
                    expected: before.activation.runtime, policy: XCTUnwrap(before.intent), candidate: f.candidate,
                    directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                    verifyScoped: { _, actual in
                        stages += 1
                        _ = try observation.read(actual); _ = try observation.read(actual); count += 2
                    })
                let actual = try snapshot(f); try actual.requireSame(as: result)
                _ = try observation.read(actual); count += 1
                XCTAssertEqual(count, 10); XCTAssertEqual(stages, 4)
            }
            XCTAssertEqual(state.inputCaptures, 1); XCTAssertEqual(state.pairReads, 20)
            XCTAssertEqual(state.materialReads, 20); XCTAssertEqual(state.artifactReads, 80)
            XCTAssertEqual(state.sourceChecks, 20); XCTAssertEqual(try files.stamps(), stamps)
            XCTAssertThrowsError(try XCTUnwrap(escaped).read(before)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testFreshPublishedRecoveryUsesOneBorrowedCallbackAndFourObservations() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let published = try markPublished(f, before), state = State(); var stages = 0, commits = 0
            try f.reopen { commits += 1 }
            try observe(f, published, files, state: state) { observation in
                _ = try observation.read(published)
                let result = try f.machine().completeRetainedSetupRuntimePublication(XCTUnwrap(published.activation.runtime.state.reference),
                    expected: published.activation.runtime, policy: XCTUnwrap(published.intent), candidate: f.candidate,
                    directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                    verifyScoped: { stage, actual in
                        XCTAssertEqual(stage, .beforeTransaction); stages += 1
                        _ = try observation.read(actual); _ = try observation.read(actual)
                    })
                try result.requireSame(as: published); _ = try observation.read(snapshot(f))
            }
            XCTAssertEqual(stages, 1); XCTAssertEqual(commits, 0); XCTAssertEqual(state.inputCaptures, 1)
            XCTAssertEqual(state.pairReads, 8); XCTAssertEqual(state.materialReads, 8); XCTAssertEqual(state.artifactReads, 32)
        }
    }

    func testEachMissingOrConflictingPublishedFileRefusesWithoutRepair() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let published = try markPublished(f, before)
            for artifact in files.artifacts {
                for missing in [true, false] {
                    if missing { try FileManager.default.removeItem(at: files.url(artifact)) }
                    else { try files.put(artifact, bytes: Data([0])) }
                    XCTAssertThrowsError(try observe(f, published, files) { _ = try $0.read(published) }) {
                        XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
                    }
                    if missing { XCTAssertFalse(FileManager.default.fileExists(atPath: files.url(artifact).path)) }
                    else { XCTAssertEqual(try files.read(artifact), Data([0])) }
                    try files.put(artifact, bytes: artifact.bytes)
                }
            }
            try snapshot(f).requireSame(as: published)
        }
    }

    func testChangedPairMaterialAndSourceRefuseAndEndTheInvocation() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let changed = Boundary(macID: current.macID, accountID: current.accountID,
                policy: .init(revision: UUID(), policy: current.policy.policy, roleRevisions: current.policy.roleRevisions),
                checkpoint: current.checkpoint)
            let pairState = State(); pairState.pairReader = { n, actual in n == 1 ? actual : changed }
            XCTAssertThrowsError(try observe(f, before, files, state: pairState) { observation in
                XCTAssertThrowsError(try observation.read(before))
                XCTAssertThrowsError(try observation.read(before)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertEqual(pairState.pairReads, 2); XCTAssertEqual(pairState.materialReads, 2)
            let material = f.material
            let foreign = try RuntimePreparationMaterial(materialID: AccountPreparationIntent.randomID(), services: material.services,
                transportIdentity: material.transportIdentity, transportPublicKeyInfo: material.transportPublicKeyInfo,
                gateway: material.gateway, serviceActivity: material.serviceActivity, auditDeliveryVersion: material.auditDeliveryVersion)
            let materialState = State(); materialState.materialReader = { $0 == 1 ? material : foreign }
            XCTAssertThrowsError(try observe(f, before, files, state: materialState) { _ = try $0.read(before) }) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertEqual(materialState.materialReads, 2); XCTAssertEqual(materialState.artifactReads, 8)
            let changedSource = try Snapshot(activation: before.activation, intent: nil, candidate: f.candidate), sourceState = State()
            XCTAssertThrowsError(try observe(f, before, files, state: sourceState) { _ = try $0.read(changedSource) })
            XCTAssertEqual(sourceState.pairReads, 0); XCTAssertEqual(sourceState.materialReads, 0)
            try snapshot(f).requireSame(as: before)
        }
    }

    func testCallbackLoansExpireAndReentryPoisonsTheInvocation() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let state = State(); var previous: Observer.Scope?
            state.inspect = { scope in
                if let previous { XCTAssertThrowsError(try previous.requireActive()) }
                previous = scope; let counts = [state.pairReads, state.materialReads, state.artifactReads]
                try scope.requireActive(); try scope.withActive { try scope.requireActive() }
                XCTAssertEqual([state.pairReads, state.materialReads, state.artifactReads], counts)
            }
            try observe(f, before, files, state: state) { _ = try $0.read(before) }
            XCTAssertThrowsError(try XCTUnwrap(previous).requireActive())
            let recursive = State()
            recursive.inspect = { scope in try scope.withActive {
                XCTAssertThrowsError(try scope.withActive {}) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            } }
            XCTAssertThrowsError(try observe(f, before, files, state: recursive) { _ = try $0.read(before) }) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            XCTAssertEqual(recursive.materialReads, 0)
        }
    }

    func testForeignThreadAndCustodyRefusalCannotUseAReadLoan() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let state = State()
            state.inspect = { scope in
                let shared = SharedScope(scope), rejected = Mutex(false), done = DispatchSemaphore(value: 0)
                DispatchQueue.global().async {
                    defer { done.signal() }
                    do { try shared.scope.requireActive() } catch { rejected.withLock { $0 = error as? JournalLeaseError == .invalidated } }
                }
                XCTAssertEqual(done.wait(timeout: .now() + 5), .success); XCTAssertTrue(rejected.withLock { $0 })
                try scope.requireActive()
            }
            try observe(f, before, files, state: state) { _ = try $0.read(before) }
            let refused = State()
            XCTAssertThrowsError(try observe(f, before, files, state: refused, custody: false) { _ = try $0.read(before) }) {
                XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
            }
            XCTAssertEqual(refused.inputCaptures, 0); XCTAssertEqual(refused.pairReads, 0)
            XCTAssertEqual(refused.materialReads, 0); XCTAssertEqual(refused.artifactReads, 0)
        }
    }

    func testObservationElevenRefusesBeforeAnotherReadAndEndsTheInvocation() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }; let state = State()
            XCTAssertThrowsError(try observe(f, before, files, state: state) { observation in
                for _ in 0..<10 { _ = try observation.read(before) }
                XCTAssertThrowsError(try observation.read(before)) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertEqual(state.inputCaptures, 1); XCTAssertEqual(state.pairReads, 20)
            XCTAssertEqual(state.materialReads, 20); XCTAssertEqual(state.artifactReads, 80)
        }
    }

    func testActualImportAndRelayDeterminePublishedBytesInsteadOfFileTunables() throws {
        try fixture { f, initial, current in
            let account = initial.activation.runtime.preparation
            let inventory = try initial.activation.runtime.setup.source.provisioningInventory(accountID: account.accountID,
                ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
            let presence = try PresenceConfiguration(idleMilliseconds: 123000, observationLifetimeMilliseconds: 9000,
                unavailableGraceMilliseconds: 41000)
            let cloud = try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32),
                zoneID: String(repeating: "b", count: 32), dnsSuffix: "owned.example", apiToken: "synthetic-only")
            let proposal = PortableSetup(defaults: try .init(presence: presence, gateway: GatewaySetupForm().settingsSelection()), cloudflare: cloud)
            let intent = try SharedSetupImportIntent(scope: .init(account: account, inventory: inventory), proposal: proposal)
            let relay = try SharedSetupImportRelayPlan(expected: intent, port: 45678)
            let machine = URL(fileURLWithPath: f.directory.path), relative = machine.lastPathComponent + "/SharedSetupImport"
            let directory = try ProtectedSetupDirectory(anchor: machine.deletingLastPathComponent().path, relativePath: relative, owner: getuid())
            defer { directory.close() }; _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .sharedSetupImport, owner: getuid())
            do {
                let journal = try SharedSetupImportJournal(lease: .init(anchor: machine.deletingLastPathComponent().path,
                    relativeDirectory: relative, owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"),
                    owner: getuid(), macID: account.macID, installationID: account.installationID, initialize: true)
                defer { try? journal.close() }; try journal.begin(intent)
            }
            _ = try AdministrativeSetupPublication.publish(relay.bytes, file: .importRelayPlan(accountID: account.accountID),
                directory: directory, owner: getuid())
            let before = try snapshot(f), files = try files(f, before, current, intent: intent, relay: relay)
            defer { XCTAssertNoThrow(try files.close()) }; let published = try markPublished(f, before), state = State()
            try observe(f, published, files, state: state) { observation in
                let frame = try observation.read(published)
                XCTAssertEqual(frame.inputs.intent, intent); XCTAssertEqual(frame.inputs.relay?.plan, relay)
                XCTAssertEqual(frame.bundle.command.presence.presence.policy.idleMilliseconds, 123000)
                XCTAssertEqual(frame.bundle.transport.relayPort, 45678)
            }
            XCTAssertEqual(state.inputCaptures, 1)
            let defaults = try RuntimeRetainedSetupInitialConfiguration(snapshot: before, current: current,
                candidate: f.candidate, currentCodePolicy: current.policy.policy, importIntent: nil, relayPlan: nil)
            let command = try XCTUnwrap(files.artifacts.first { $0.path == defaults.bundle.paths.commandConfiguration })
            try files.put(command, bytes: defaults.bundle.command.canonicalBytes)
            XCTAssertThrowsError(try observe(f, published, files) { _ = try $0.read(published) }) {
                XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
            }
            XCTAssertEqual(try files.read(command), defaults.bundle.command.canonicalBytes)
            try snapshot(f).requireSame(as: published)
        }
    }
}
