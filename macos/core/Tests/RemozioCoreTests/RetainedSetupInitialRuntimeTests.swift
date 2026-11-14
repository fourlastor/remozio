import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned files and stores prove ordering and recovery. They grant no Root, installed placement or service identity evidence.
final class RetainedSetupInitialRuntimeTests: XCTestCase {
    private typealias Runtime = MachineUpdateRetainedSetupInitialRuntime
    private typealias Completion = MachineUpdateRetainedSetupInitialCompletion
    private typealias Read = PreparationIntentStore.InitialRuntimeRead
    private typealias Observer = MachineUpdateRetainedSetupInitialObservation
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    private typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Fault: Error { case stopped, commit }
    private final class SharedScope: @unchecked Sendable {
        let scope: Runtime.Scope
        init(_ scope: Runtime.Scope) { self.scope = scope }
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
            let metadata = try file(artifact)
            if let group = metadata.groupID {
                guard chown(url(artifact).path, uid_t.max, group) == 0 else { throw JournalLeaseError.system(errno) }
            }
            guard chmod(url(artifact).path, metadata.mode) == 0 else { throw JournalLeaseError.system(errno) }
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

    private final class State {
        var calls = 0, captures = 0, pairReads = 0, materialReads = 0, artifactReads = 0, commits = 0
        var counts: [Read: Int] = [:], byCall: [[Read: Int]] = []
        var stages: [Runtime.Stage] = [], scopes: [Runtime.Scope] = []
        var bodies: [MachineUpdateRetainedSetupPolicyFrame.MachineBody] = []
        var failPublicationAt: Int?, loseCommit = false, staleReturn = false
        var onScope: ((Runtime.Scope) throws -> Void)?
    }
    private func markPublished(_ f: Fixture, _ before: Snapshot) throws -> Snapshot {
        try f.machine().completeRetainedSetupRuntimePublication(XCTUnwrap(before.activation.runtime.state.reference),
            expected: before.activation.runtime, policy: XCTUnwrap(before.intent), candidate: f.candidate,
            directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
            verifyScoped: { _, _ in try XCTUnwrap(before.intent).requireRecorded(self.pair(f)) })
    }
    private func prepare(_ f: Fixture, _ expected: Snapshot, _ files: Files, state: State = State(), custody: Bool = true) throws -> Snapshot {
        try Runtime.prepare(expected: expected, candidate: f.candidate, directory: f.directory,
            admission: f.admission, fileCustodyAccepted: custody, useMachine: { body in
                state.calls += 1; state.bodies.append(body)
                try f.reopen {
                    state.commits += 1
                    if state.loseCommit { throw Fault.commit }
                }
                let machine = f.machine(); var counts: [Read: Int] = [:]
                machine.observeStoreRead = { state.counts[$0, default: 0] += 1; counts[$0, default: 0] += 1 }
                defer { state.byCall.append(counts); machine.observeStoreRead = nil; try? machine.close() }
                let actual = try body(machine)
                if state.staleReturn && actual.activation.runtime.state.configurationPublished { return expected }
                return actual
            }, readPolicyBoundary: { state.pairReads += 1; return try self.pair(f) },
            verifyCurrent: { _ in }, verifyServices: { XCTAssertEqual(try $0.encoded, try f.material.services.encoded) },
            readMaterial: { scope in
                state.scopes.append(scope); state.materialReads += 1
                let counts = state.counts
                try scope.requireActive(); try scope.withActive { try scope.requireActive() }
                XCTAssertEqual(counts, state.counts)
                try state.onScope?(scope)
                return try scope.withActive { f.material }
            }, verifyActivity: { activity, scope in try scope.withActive { XCTAssertEqual(activity, f.material.serviceActivity) } },
            readArtifact: { artifact, scope in try scope.withActive {
                state.artifactReads += 1; XCTAssertEqual(scope.artifact?.path, artifact.path)
                return try files.read(artifact)
            } }, publish: { scope in try scope.withActive {
                try files.publish(XCTUnwrap(scope.artifact), verify: scope.requireActive)
                if state.failPublicationAt == files.publicationCalls { throw Fault.stopped }
            } }, didReadSnapshot: { _ in state.captures += 1 }, didStage: { stage in
                state.stages.append(stage)
                XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
                let counts = state.counts
                for scope in state.scopes { XCTAssertThrowsError(try scope.requireActive()) }
                XCTAssertEqual(counts, state.counts)
            })
    }
    private func budget(_ state: State, published: Bool) {
        XCTAssertEqual(state.captures, published ? 2 : 3)
        XCTAssertEqual(state.calls, published ? 3 : 5)
        XCTAssertEqual(state.counts[.readTransaction], published ? 6 : 51)
        XCTAssertEqual(state.counts[.writeTransaction, default: 0], published ? 0 : 1)
        XCTAssertEqual(state.materialReads, published ? 8 : 38)
        XCTAssertEqual(state.artifactReads, published ? 32 : 104)
        XCTAssertEqual(state.pairReads, published ? 8 : 64)
        guard state.byCall.count == (published ? 3 : 5) else {
            XCTFail("The expected machine calls did not finish"); return
        }
        for i in published ? [0, 2] : [0, 2, 4] {
            XCTAssertEqual(state.byCall[i][.readTransaction], 1)
            XCTAssertEqual(state.byCall[i][.runtime], 2)
            XCTAssertEqual(state.byCall[i][.frame], 6)
            XCTAssertEqual(state.byCall[i][.activation], 2)
            XCTAssertEqual(state.byCall[i][.policyScan], 7)
        }
        if !published {
            XCTAssertEqual(state.byCall[1][.readTransaction], 43)
            XCTAssertEqual(state.byCall[1][.runtime], 84)
        }
        XCTAssertEqual(state.byCall[published ? 1 : 3][.readTransaction], published ? 4 : 5)
        XCTAssertEqual(state.stages, published ? [.publicationCompleted] : [.filesPublished, .publicationCompleted])
        for scope in state.scopes { XCTAssertThrowsError(try scope.requireActive()) }
    }
    func testRealPublicationClosesSelectionBeforeCompletionAndAssertsTheReadBudget() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current, seed: false); defer { XCTAssertNoThrow(try files.close()) }
            let state = State(), actual = try prepare(f, before, files, state: state)
            try actual.requirePublication(from: before, reference: XCTUnwrap(before.activation.runtime.state.reference))
            budget(state, published: false); XCTAssertEqual(files.publicationCalls, 8); XCTAssertEqual(state.commits, 1)
            XCTAssertNil(actual.activation.state.plan); XCTAssertFalse(actual.activation.state.jobsRegistered)
            for artifact in files.artifacts { XCTAssertEqual(try files.read(artifact), artifact.bytes) }
            for body in state.bodies { XCTAssertThrowsError(try body(f.machine())) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) } }
        }
    }
    func testExactPublicationAlsoRejectsMissingCustodyAndInvalidScopes() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let refused = State()
            XCTAssertThrowsError(try prepare(f, before, files, state: refused, custody: false)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
            }
            XCTAssertEqual(refused.calls + refused.captures + refused.pairReads + refused.materialReads + refused.artifactReads, 0)
            XCTAssertTrue(refused.counts.isEmpty)
            let recursive = State(); recursive.onScope = { scope in
                let shared = SharedScope(scope), rejected = Mutex(false), done = DispatchSemaphore(value: 0)
                DispatchQueue.global().async {
                    defer { done.signal() }
                    do { try shared.scope.requireActive() } catch { rejected.withLock { $0 = error as? JournalLeaseError == .invalidated } }
                }
                XCTAssertEqual(done.wait(timeout: .now() + 2), .success); XCTAssertTrue(rejected.withLock { $0 })
                try scope.withActive { XCTAssertThrowsError(try scope.withActive {}) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) } }
            }
            XCTAssertThrowsError(try prepare(f, before, files, state: recursive))
            XCTAssertEqual(recursive.commits, 0); XCTAssertEqual(files.publicationCalls, 0)
            let stamps = try files.stamps(), state = State()
            XCTAssertTrue(try prepare(f, before, files, state: state).activation.runtime.state.configurationPublished)
            XCTAssertEqual(try files.stamps(), stamps); XCTAssertEqual(state.commits, 1); budget(state, published: false)
        }
    }
    func testPartialPublicationFailureThenFreshPartialCompletion() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current, seed: false); defer { XCTAssertNoThrow(try files.close()) }
            let failed = State(); failed.failPublicationAt = 3
            XCTAssertThrowsError(try prepare(f, before, files, state: failed)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(files.publicationCalls, 3); XCTAssertTrue(failed.stages.isEmpty); XCTAssertEqual(failed.commits, 0)
            try f.reopen(nil); try snapshot(f).requireSame(as: before)
            for artifact in files.artifacts.prefix(4) { try files.put(artifact, bytes: artifact.bytes) }
            let callsBeforeCompletion = files.publicationCalls
            let actual = try prepare(f, before, files)
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished); XCTAssertEqual(files.publicationCalls, 11)
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished)
            XCTAssertEqual(files.publicationCalls - callsBeforeCompletion, 8)
            for artifact in files.artifacts { XCTAssertEqual(try files.read(artifact), artifact.bytes) }
        }
    }
    func testPublishedRecoveryAndAllMissingOrConflictingFilesDoNotWrite() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let published = try markPublished(f, before), state = State(), stamps = try files.stamps()
            try prepare(f, published, files, state: state).requireSame(as: published)
            budget(state, published: true); XCTAssertEqual(files.publicationCalls, 0); XCTAssertEqual(state.commits, 0)
            XCTAssertEqual(try files.stamps(), stamps)
            for artifact in files.artifacts {
                try FileManager.default.removeItem(at: files.url(artifact)); let state = State()
                XCTAssertThrowsError(try prepare(f, published, files, state: state))
                XCTAssertEqual(state.commits, 0); XCTAssertEqual(files.publicationCalls, 0)
                XCTAssertFalse(FileManager.default.fileExists(atPath: files.url(artifact).path))
                try files.put(artifact, bytes: artifact.bytes)
            }
            for artifact in files.artifacts {
                try files.put(artifact, bytes: Data([0])); let state = State()
                XCTAssertThrowsError(try prepare(f, published, files, state: state))
                XCTAssertEqual(state.commits, 0); XCTAssertEqual(files.publicationCalls, 0)
                XCTAssertEqual(try files.read(artifact), Data([0])); try files.put(artifact, bytes: artifact.bytes)
            }
        }
    }
    func testLostCompletionCommitAcknowledgementRequiresReadOnlyRecoveryWithoutPublication() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let state = State(); state.loseCommit = true
            XCTAssertThrowsError(try prepare(f, before, files, state: state)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(state.commits, 1); XCTAssertEqual(files.publicationCalls, 8)
            try f.reopen(nil); let actual = try snapshot(f), recovered = State(), stamps = try files.stamps()
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished)
            try prepare(f, actual, files, state: recovered).requireSame(as: actual)
            budget(recovered, published: true); XCTAssertEqual(recovered.commits, 0)
            XCTAssertEqual(files.publicationCalls, 8); XCTAssertEqual(try files.stamps(), stamps)
        }
    }
    func testStaleProviderResultCannotMasqueradeAsTheActualCompletedFrame() throws {
        try fixture { f, before, current in
            let files = try files(f, before, current); defer { XCTAssertNoThrow(try files.close()) }
            let state = State(); state.staleReturn = true
            XCTAssertThrowsError(try prepare(f, before, files, state: state))
            XCTAssertEqual(state.commits, 1); XCTAssertEqual(state.captures, 2)
            try f.reopen(nil); let actual = try snapshot(f)
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished)
            let recovered = State(); try prepare(f, actual, files, state: recovered).requireSame(as: actual)
            budget(recovered, published: true); XCTAssertEqual(files.publicationCalls, 8)
        }
    }
}
