import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned files and stores prove ordering and recovery. They grant no Root, installed placement or service identity evidence.
final class RetainedSetupInitialCompletionTests: XCTestCase {
    private typealias Completion = MachineUpdateRetainedSetupInitialCompletion
    private typealias Observer = MachineUpdateRetainedSetupInitialObservation
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    private typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Fault: Error { case stopped, commit }
    private final class SharedScope: @unchecked Sendable {
        let scope: Completion.Scope
        init(_ scope: Completion.Scope) { self.scope = scope }
    }
    private final class Files {
        let root: URL
        let directory: ProtectedSetupDirectory
        let artifacts: [Artifact]
        let names: [String: AdministrativeSetupPublication.File]
        var publicationCalls = 0
        init(_ artifacts: [Artifact], owner: UInt32, seed: Bool = true) throws {
            self.artifacts = artifacts
            root = URL(fileURLWithPath: "/private/tmp/remozio-initial-completion-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            directory = try .init(anchor: root.path, relativePath: "Files", owner: getuid(), visibility: .sharedMetadata)
            let fixed: [AdministrativeSetupPublication.File] = [.elevationPolicy, .commandConfiguration,
                .transportIdentity(ownerUID: getuid(), groupID: getgid()), .transportConfiguration, .gatewaySettingsHost,
                .presenceClient(ownerUID: owner), .pairingClient(ownerUID: owner), .frontendClient(ownerUID: owner)]
            names = Dictionary(uniqueKeysWithValues: fixed.map { ($0.name, $0) })
            if seed { for artifact in artifacts { try put(artifact, bytes: artifact.bytes) } }
        }
        func close() throws { directory.close(); try FileManager.default.removeItem(at: root) }
        func file(_ artifact: Artifact) throws -> AdministrativeSetupPublication.File {
            try XCTUnwrap(names[URL(fileURLWithPath: artifact.path).lastPathComponent])
        }
        func url(_ artifact: Artifact) -> URL {
            URL(fileURLWithPath: directory.path).appendingPathComponent(URL(fileURLWithPath: artifact.path).lastPathComponent)
        }
        func put(_ artifact: Artifact, bytes: Data) throws {
            try bytes.write(to: url(artifact))
            guard chmod(url(artifact).path, try file(artifact).mode) == 0 else { throw JournalLeaseError.system(errno) }
        }
        func read(_ artifact: Artifact) throws -> Data? {
            try ProtectedServiceConfiguration.readOptional(anchor: directory.path,
                relativePath: url(artifact).lastPathComponent, owner: getuid())
        }
        func publish(_ artifact: Artifact, verify: () throws -> Void) throws {
            publicationCalls += 1
            _ = try AdministrativeSetupPublication.publish(artifact.bytes, file: file(artifact),
                directory: directory, owner: getuid(), verify: verify)
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
        var pairReads = 0, materialReads = 0, artifactReads = 0, inputCaptures = 0, snapshotReads = 0
        var callbackDepth = 0, failFinalArtifacts = false
        var stages: [Stage] = []
        var scopes: [Completion.Scope] = []
        var frames: [Observer.Frame] = []
        var onStage: ((Stage, Completion.Scope) throws -> Void)?
        var pairReader: ((Int, Boundary) throws -> Boundary)?
        var materialReader: ((Int) throws -> RuntimePreparationMaterial)?
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
            try f.reopen(nil); defer { try? f.machine().close() }; try body(f, recorded, pair(f))
        }
    }
    private func files(_ f: Fixture, _ before: Snapshot, _ current: Boundary, seed: Bool = true) throws -> Files {
        let configuration = try RuntimeRetainedSetupInitialConfiguration(snapshot: before, current: current,
            candidate: f.candidate, currentCodePolicy: current.policy.policy, importIntent: nil, relayPlan: nil)
        return try Files(RuntimePublishedArtifactValidation.artifacts(bundle: configuration.bundle, material: f.material),
            owner: before.activation.runtime.preparation.ownerUID, seed: seed)
    }
    private func complete(_ f: Fixture, _ expected: Snapshot, _ files: Files, state: State = State(),
        custody: Bool = true) throws -> Snapshot {
        try Completion.complete(machine: f.machine(), expected: expected, candidate: f.candidate,
            directory: f.directory, admission: f.admission, fileCustodyAccepted: custody,
            readPolicyBoundary: {
                state.pairReads += 1; let actual = try self.pair(f)
                return try state.pairReader?(state.pairReads, actual) ?? actual
            }, verifyCurrent: { _ in }, verifyServices: { plan in
                XCTAssertEqual(try plan.encoded, try f.material.services.encoded)
            }, readMaterial: { scope in try scope.withActive {
                state.materialReads += 1; return try state.materialReader?(state.materialReads) ?? f.material
            } }, verifyActivity: { activity, scope in try scope.withActive {
                XCTAssertEqual(activity, f.material.serviceActivity)
            } }, readArtifact: { artifact, scope in try scope.withActive {
                state.artifactReads += 1
                if state.failFinalArtifacts && state.snapshotReads == 2 { return nil }
                return try files.read(artifact)
            } }, didReadSnapshot: { _ in
                XCTAssertEqual(state.callbackDepth, 0); state.snapshotReads += 1
            }, inspectInputs: { _ in state.inputCaptures += 1 }, didStorageStage: { stage, scope in
                state.callbackDepth += 1; defer { state.callbackDepth -= 1 }
                if let previous = state.scopes.last { XCTAssertThrowsError(try previous.read()) }
                let counts = [state.snapshotReads, state.pairReads, state.materialReads, state.artifactReads, state.inputCaptures]
                let frame = try scope.read(); try scope.requireActive(); try scope.withActive { _ = try scope.read() }
                XCTAssertEqual([state.snapshotReads, state.pairReads, state.materialReads, state.artifactReads, state.inputCaptures], counts)
                state.stages.append(stage); state.scopes.append(scope); state.frames.append(frame)
                try state.onStage?(stage, scope)
            })
    }
    private func counts(_ state: State, observations: Int, stages: Int) {
        XCTAssertEqual(state.snapshotReads, 2); XCTAssertEqual(state.inputCaptures, 1)
        XCTAssertEqual(state.pairReads, 2 * observations); XCTAssertEqual(state.materialReads, 2 * observations)
        XCTAssertEqual(state.artifactReads, 8 * observations); XCTAssertEqual(state.stages.count, stages)
        XCTAssertLessThanOrEqual(observations, 10)
    }

    func testExactFilesCompleteOnceAndPublishedRecoveryKeepsEveryInitialByte() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let stamps = try files.stamps(); var commits = 0; try f.reopen { commits += 1 }
            let state = State(), published = try complete(f, before, files, state: state)
            try published.requirePublication(from: before, reference: XCTUnwrap(before.activation.runtime.state.reference))
            XCTAssertEqual(commits, 1); counts(state, observations: 10, stages: 4)
            XCTAssertEqual(state.stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            for frame in state.frames {
                let actual = try RuntimePublishedArtifactValidation.artifacts(bundle: frame.bundle, material: f.material)
                XCTAssertEqual(actual.map(\.path), files.artifacts.map(\.path))
                XCTAssertEqual(actual.map(\.bytes), files.artifacts.map(\.bytes))
                XCTAssertEqual(actual.map(\.access), files.artifacts.map(\.access))
            }
            let recovered = State(), result = try complete(f, published, files, state: recovered)
            try result.requireSame(as: published); counts(recovered, observations: 4, stages: 1)
            XCTAssertEqual(recovered.stages, [.beforeTransaction]); XCTAssertEqual(commits, 1)
            XCTAssertEqual(files.publicationCalls, 0); XCTAssertEqual(try files.stamps(), stamps)
            XCTAssertFalse(result.activation.state.jobsRegistered); XCTAssertNil(result.activation.state.plan)
        }
    }

    func testEveryMissingOrConflictingPublishedFileRefusesWithoutRepairOrUpdate() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let published = try complete(f, before, files); var commits = 0; try f.reopen { commits += 1 }
            for artifact in files.artifacts {
                for missing in [true, false] {
                    if missing { try FileManager.default.removeItem(at: files.url(artifact)) }
                    else { try files.put(artifact, bytes: Data([0])) }
                    let state = State()
                    XCTAssertThrowsError(try complete(f, published, files, state: state)) {
                        XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
                    }
                    XCTAssertEqual(state.snapshotReads, 1); XCTAssertEqual(state.stages.count, 0); XCTAssertEqual(commits, 0)
                    if missing { XCTAssertFalse(FileManager.default.fileExists(atPath: files.url(artifact).path)) }
                    else { XCTAssertEqual(try files.read(artifact), Data([0])) }
                    try files.put(artifact, bytes: artifact.bytes)
                }
            }
            try snapshot(f).requireSame(as: published); XCTAssertEqual(files.publicationCalls, 0)
        }
    }

    func testEachPrecommitFailureRollsBackAndAFreshInvocationCompletes() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }; var commits = 0
            for stopped: Stage in [.beforeTransaction, .inTransaction, .afterMutation] {
                try f.reopen { commits += 1 }; let actual = try snapshot(f), state = State()
                state.onStage = { stage, _ in if stage == stopped { throw Fault.stopped } }
                XCTAssertThrowsError(try complete(f, actual, files, state: state)) { XCTAssertTrue($0 is Fault) }
                try snapshot(f).requireSame(as: before); XCTAssertEqual(commits, 0)
                for scope in state.scopes { XCTAssertThrowsError(try scope.read()) }
            }
            try f.reopen { commits += 1 }; let actual = try snapshot(f)
            XCTAssertTrue(try complete(f, actual, files).activation.runtime.state.configurationPublished)
            XCTAssertEqual(commits, 1); XCTAssertEqual(files.publicationCalls, 0)
        }
    }

    func testLostCommitAcknowledgementRequiresFreshPublishedRecovery() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let stamps = try files.stamps(); var commits = 0; try f.reopen { commits += 1; throw Fault.commit }
            let state = State()
            XCTAssertThrowsError(try complete(f, before, files, state: state)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            for scope in state.scopes { XCTAssertThrowsError(try scope.read()) }
            try f.reopen { commits += 1 }; let actual = try snapshot(f), recovery = State()
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished)
            try complete(f, actual, files, state: recovery).requireSame(as: actual)
            counts(recovery, observations: 4, stages: 1); XCTAssertEqual(commits, 1)
            XCTAssertEqual(try files.stamps(), stamps); XCTAssertEqual(files.publicationCalls, 0)
        }
    }

    func testAfterCommitCallbackFailureClosesTheStoreAndExpiresItsLoans() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }; let state = State()
            state.onStage = { stage, _ in if stage == .afterCommit { throw Fault.stopped } }
            XCTAssertThrowsError(try complete(f, before, files, state: state)) { XCTAssertTrue($0 is Fault) }
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            for scope in state.scopes { XCTAssertThrowsError(try scope.read()) }
            try f.reopen(nil); let actual = try snapshot(f)
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished)
            try complete(f, actual, files).requireSame(as: actual); XCTAssertEqual(files.publicationCalls, 0)
        }
    }

    func testFinalObservationFailureClosesTheStoreAndFreshRecoveryDoesNotRepair() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let state = State(); state.failFinalArtifacts = true
            XCTAssertThrowsError(try complete(f, before, files, state: state)) {
                XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
            }
            XCTAssertEqual(state.snapshotReads, 2)
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
            try f.reopen(nil); let actual = try snapshot(f)
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished)
            try complete(f, actual, files).requireSame(as: actual); XCTAssertEqual(files.publicationCalls, 0)
        }
    }

    func testChangedPairMaterialOrFileAfterMutationRollsBackBeforeANewInvocation() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let material = f.material, artifact = try XCTUnwrap(files.artifacts.last)
            let foreign = try RuntimePreparationMaterial(materialID: AccountPreparationIntent.randomID(), services: material.services,
                transportIdentity: material.transportIdentity, transportPublicKeyInfo: material.transportPublicKeyInfo,
                gateway: material.gateway, serviceActivity: material.serviceActivity, auditDeliveryVersion: material.auditDeliveryVersion)
            let changed = Boundary(macID: current.macID, accountID: current.accountID,
                policy: .init(revision: UUID(), policy: current.policy.policy, roleRevisions: current.policy.roleRevisions), checkpoint: current.checkpoint)
            var commits = 0
            for kind in 0..<3 {
                try f.reopen { commits += 1 }; let actual = try snapshot(f), state = State(); var advanced = false
                state.pairReader = { _, pair in advanced && kind == 0 ? changed : pair }
                state.materialReader = { _ in advanced && kind == 1 ? foreign : material }
                state.onStage = { stage, _ in
                    if stage == .afterMutation { advanced = true; if kind == 2 { try files.put(artifact, bytes: Data([0])) } }
                }
                XCTAssertThrowsError(try complete(f, actual, files, state: state))
                try snapshot(f).requireSame(as: before); XCTAssertEqual(commits, 0)
                if kind == 2 { XCTAssertEqual(try files.read(artifact), Data([0])); try files.put(artifact, bytes: artifact.bytes) }
            }
            try f.reopen { commits += 1 }; let actual = try snapshot(f)
            XCTAssertTrue(try complete(f, actual, files).activation.runtime.state.configurationPublished)
            XCTAssertEqual(commits, 1); XCTAssertEqual(files.publicationCalls, 0)
        }
    }

    func testRecursiveAndForeignThreadLoansRefuseAndEveryEscapedLoanExpires() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }; let recursive = State()
            recursive.onStage = { _, scope in try scope.withActive {
                XCTAssertThrowsError(try scope.withActive {}) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            } }
            XCTAssertThrowsError(try complete(f, before, files, state: recursive)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil)
            try snapshot(f).requireSame(as: before)
            let state = State(); state.onStage = { _, scope in
                let shared = SharedScope(scope), rejected = Mutex(false), done = DispatchSemaphore(value: 0)
                DispatchQueue.global().async {
                    defer { done.signal() }
                    do { _ = try shared.scope.read() } catch { rejected.withLock { $0 = error as? JournalLeaseError == .invalidated } }
                }
                XCTAssertEqual(done.wait(timeout: .now() + 5), .success); XCTAssertTrue(rejected.withLock { $0 })
                try scope.requireActive()
            }
            _ = try complete(f, before, files, state: state); counts(state, observations: 10, stages: 4)
            for scope in state.scopes { XCTAssertThrowsError(try scope.read()) }
            let refused = State()
            XCTAssertThrowsError(try complete(f, try snapshot(f), files, state: refused, custody: false)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
            }
            XCTAssertEqual(refused.snapshotReads, 0); XCTAssertEqual(refused.inputCaptures, 0)
        }
    }

    func testRealInitialPublicationThenCompletionPerformsNoFurtherFileWrites() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current, seed: false); defer { XCTAssertNoThrow(try files.close()) }
            _ = try MachineUpdateRetainedSetupInitialPublication.prepare(withSelection: { body in
                try MachineUpdateRetainedSetupInitialSelection.withCurrent(machine: f.machine(), expected: before,
                    candidate: f.candidate, recordedStartupPolicy: current.policy.policy,
                    readPolicyBoundary: { try self.pair(f) }, verifyCurrent: { _ in }, body: body)
            }, machine: f.machine(), expected: before, candidate: f.candidate, directory: f.directory,
                admission: f.admission, fileCustodyAccepted: true, verifyCurrent: { _ in }, verifyServices: { _ in },
                readMaterial: { scope in try scope.withActive { f.material } },
                verifyActivity: { _, scope in try scope.requireActive() },
                readArtifact: { artifact, scope in try scope.withActive { try files.read(artifact) } },
                publish: { scope in try scope.withActive {
                    try files.publish(XCTUnwrap(scope.artifact), verify: scope.requireActive)
                } })
            XCTAssertEqual(files.publicationCalls, 8); let stamps = try files.stamps(); var commits = 0
            try f.reopen { commits += 1 }; let actual = try snapshot(f), state = State()
            XCTAssertTrue(try complete(f, actual, files, state: state).activation.runtime.state.configurationPublished)
            counts(state, observations: 10, stages: 4); XCTAssertEqual(commits, 1)
            XCTAssertEqual(files.publicationCalls, 8); XCTAssertEqual(try files.stamps(), stamps)
        }
    }
}
