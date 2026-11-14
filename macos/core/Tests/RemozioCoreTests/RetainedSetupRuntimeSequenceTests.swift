import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned owners and files prove sequencing. Synthetic callbacks grant no native provider, caller or installed custody evidence.
final class RetainedSetupRuntimeSequenceTests: XCTestCase {
    private typealias Sequence = MachineUpdateRetainedSetupRuntimeSequence
    private typealias Entry = Sequence.Entry
    private typealias Frame = Sequence.Frame
    private typealias Inputs = Sequence.Inputs
    private typealias Policy = Sequence.Policy
    private typealias Material = Sequence.Material
    private typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    private typealias Read = PreparationIntentStore.InitialRuntimeRead
    private enum Fault: Error { case policy, afterAcknowledgement, unexpected }
    private final class SharedVerification: @unchecked Sendable {
        let body: (Material) throws -> Void
        let value: Material
        let refused = Mutex(false)
        init(_ body: @escaping (Material) throws -> Void, _ value: Material) { self.body = body; self.value = value }
        func invoke() { do { try body(value) } catch { refused.withLock { $0 = error as? JournalLeaseError == .invalidated } } }
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
        let owner: LocalAccountIdentity, candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease
        let admission: UpdateOrdinaryAdmissionLease, material: RuntimePreparationMaterial
        let machine: () throws -> PreparationIntentStore
        let reopen: ((() throws -> Void)?) throws -> Void
        let initialRuntime: MachineUpdateStableRuntimePreparationSnapshot
        let openPolicy: ((MachineUpdateRetainedSetupPolicyOwner.JournalAccess) throws -> AuthorityJournal)?
        var files: Files?, intent: SharedSetupImportIntent?
        var events: [String] = [], captures: [Frame] = [], outerReads: [[Read: Int]] = []
        var reads: [Read: Int] = [:], commits = 0, startupOpens = 0, hostChecks = 0
        var advanced: [Bool] = [], lastAcknowledged: Frame?
        var stopPolicy = false, staleMaterial = false, stalePolicy = false, stalePublication = false, loseAcknowledgement = false
        var poisonMaterial = false, foreignMaterial = false
        var escapedMaterial: ((Material) throws -> Void)?
        init(_ f: RetainedPolicyWriterFixture) {
            owner = f.source.runtime.setup.owner; candidate = f.candidate; directory = f.directory; admission = f.admission
            material = f.material; machine = f.machine; reopen = f.reopen; initialRuntime = f.source.runtime
            openPolicy = { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) }
        }
        init(_ f: RetainedMaterialWriterFixture, runtime: MachineUpdateStableRuntimePreparationSnapshot) {
            owner = f.owner; candidate = f.candidate; directory = f.directory; admission = f.admission
            material = f.material; machine = f.machine; reopen = f.reopen; initialRuntime = runtime; openPolicy = nil
        }
        func reset() { events = []; captures = []; outerReads = []; reads = [:]; commits = 0; startupOpens = 0; hostChecks = 0; advanced = [] }
        func withMachine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            try reopen { self.commits += 1 }; let actual = try machine()
            actual.observeStoreRead = { self.reads[$0, default: 0] += 1 }
            defer { actual.observeStoreRead = nil; try? actual.close() }
            return try body(actual)
        }
        func pair() throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
            guard let openPolicy else { throw Fault.unexpected }
            let journal = try openPolicy(.readOnly); defer { try? journal.close() }
            return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(initialRuntime.setup.account?.initialization))
        }
        func seedImport(empty: Bool = false) throws {
            let runtime = initialRuntime, account = runtime.preparation
            let inventory = try runtime.setup.source.provisioningInventory(accountID: account.accountID,
                ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
            let defaults = try SharedSetupDefaults(presence: .init(idleMilliseconds: 123_000,
                observationLifetimeMilliseconds: 9000, unavailableGraceMilliseconds: 41_000), gateway: GatewaySetupForm().settingsSelection())
            let cloud = try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32),
                zoneID: String(repeating: "b", count: 32), dnsSuffix: "owned.example", apiToken: "synthetic-only")
            let selected = try SharedSetupImportIntent(scope: .init(account: account, inventory: inventory),
                proposal: .init(defaults: defaults, cloudflare: cloud))
            let path = URL(fileURLWithPath: directory.path), relative = path.lastPathComponent + "/SharedSetupImport"
            let held = try ProtectedSetupDirectory(anchor: path.deletingLastPathComponent().path, relativePath: relative, owner: getuid())
            defer { held.close() }; _ = try SetupDatabaseFileProvisioning.prepare(directory: held, kind: .sharedSetupImport, owner: getuid())
            do {
                let journal = try SharedSetupImportJournal(lease: .init(anchor: path.deletingLastPathComponent().path,
                    relativeDirectory: relative, owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"),
                    owner: getuid(), macID: account.macID, installationID: account.installationID, initialize: true)
                defer { try? journal.close() }; if !empty { try journal.begin(selected) }
            }
            if !empty {
                let relay = try SharedSetupImportRelayPlan(expected: selected, port: 45678)
                _ = try AdministrativeSetupPublication.publish(relay.bytes, file: .importRelayPlan(accountID: account.accountID),
                    directory: held, owner: getuid()); intent = selected
            }
        }
        func prepareFiles(_ expected: Policy) throws {
            guard files == nil else { return }
            let frame = try XCTUnwrap(captures.last); try XCTUnwrap(frame.entry.policy).requireSame(as: expected)
            let bundle = try RuntimeConfigurationBundle.retainedSetupInitialObservation(snapshot: expected,
                current: pair(), candidate: candidate, inputs: frame.inputs)
            if intent != nil {
                XCTAssertEqual(bundle.command.presence.presence.policy.idleMilliseconds, 123_000)
                XCTAssertEqual(bundle.transport.relayPort, 45678)
            }
            files = try Files(RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: material),
                owner: owner.uid, seed: false)
        }
        func currentIntent() throws -> SharedSetupImportIntent? {
            try withMachine { machine in try machine.withSharedImportJournal { journal in
                guard let journal else { return nil }
                let account = initialRuntime.preparation
                let inventory = try initialRuntime.setup.source.provisioningInventory(accountID: account.accountID,
                    ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
                return try journal.current(scope: .init(account: account, inventory: inventory))
            } }
        }
    }
    private func fixture(_ body: (State) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(sharedImportFormats: true) { f in
            let state = State(f); defer { if let files = state.files { XCTAssertNoThrow(try files.close()) }; try? f.machine().close() }
            try body(state)
        }
    }
    private func verify<Loan>(_ s: State, _ actual: Loan, _ callback: (Loan) throws -> Void) throws {
        let before = s.reads; try callback(actual); XCTAssertEqual(s.reads, before, "A borrowed verifier queried the machine")
    }
    private func providers(_ s: State) -> Sequence.Providers {
        .init(material: { expected, callback in
            s.events.append("material"); s.escapedMaterial = callback
            if s.foreignMaterial {
                let shared = SharedVerification(callback, expected), done = DispatchSemaphore(value: 0)
                DispatchQueue.global().async { shared.invoke(); done.signal() }
                XCTAssertEqual(done.wait(timeout: .now() + 2), .success); XCTAssertTrue(shared.refused.withLock { $0 })
            }
            if s.poisonMaterial {
                try self.verify(s, expected, callback)
                let runtime = expected.runtime
                let value = try MachineUpdateStableRuntimePreparationSnapshot(setup: runtime.setup,
                    services: .init(plan: runtime.plan, complete: true), state: .init(reference: nil, configurationPublished: false),
                    reservedNumbers: runtime.reservedNumbers)
                let foreign = try Material(runtime: value, activation: expected.activation)
                XCTAssertThrowsError(try callback(foreign)); return runtime.state
            }
            let result = try s.withMachine { machine in
                try MachineUpdateRetainedSetupMaterialPreparation.prepare(machine: machine, expected: expected, candidate: s.candidate,
                    directory: s.directory, admission: s.admission, fileCustodyAccepted: true,
                    verifyCurrent: { try self.verify(s, $0, callback) }, verifyServices: { XCTAssertEqual($0, s.material.services) },
                    verifyAuthority: { _ in }, restoreMaterial: { _, _, scope in try scope.verify(); return s.material },
                    validateMaterial: { actual, scope in try scope.verify(); XCTAssertEqual(try actual.encoded, try s.material.encoded) })
            }
            return s.staleMaterial ? .init(reference: result.reference, configurationPublished: true) : result
        }, policy: { expected, callback in
            s.events.append("policy"); if s.stopPolicy { throw Fault.policy }
            guard let open = s.openPolicy else { throw Fault.unexpected }
            let result = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: expected, candidate: s.candidate,
                directory: s.directory, admission: s.admission, useMachine: { body in try s.withMachine(body) },
                openJournal: { mode in if mode == .startup { s.startupOpens += 1 }; return try open(mode) },
                verifySnapshot: { try self.verify(s, $0, callback) })
            return s.stalePolicy ? expected : result
        }, publication: { expected, callback in
            s.events.append("publication"); try s.prepareFiles(expected)
            let files = try XCTUnwrap(s.files)
            let result = try MachineUpdateRetainedSetupInitialRuntime.prepare(expected: expected, candidate: s.candidate,
                directory: s.directory, admission: s.admission, fileCustodyAccepted: true,
                useMachine: { body in try s.withMachine(body) }, readPolicyBoundary: s.pair,
                verifyCurrent: { try self.verify(s, $0, callback) }, verifyServices: { XCTAssertEqual($0, s.material.services) },
                readMaterial: { scope in try scope.withActive { s.material } },
                verifyActivity: { actual, scope in try scope.withActive { XCTAssertEqual(actual, s.material.serviceActivity) } },
                readArtifact: { artifact, scope in try scope.withActive { try files.read(artifact) } },
                publish: { scope in try scope.withActive { try files.publish(XCTUnwrap(scope.artifact), verify: scope.requireActive) } })
            return s.stalePublication ? expected : result
        }, acknowledgement: { before, callback in
            s.events.append("acknowledgement"); let files = try XCTUnwrap(s.files)
            let start = ContinuousClock.now
            defer { let duration = start.duration(to: .now); print("A10e ACK invocation upper bound: \(duration)"); XCTAssertLessThanOrEqual(duration, .seconds(60)) }
            let result = try s.withMachine { machine in
                try MachineUpdateRetainedSetupImportAcknowledgement.acknowledge(machine: machine, expected: before.entry,
                    candidate: s.candidate, directory: s.directory, admission: s.admission, fileCustodyAccepted: true,
                    readPolicyBoundary: s.pair, verifyCurrent: { scope in try self.verify(s, scope.read(), callback) },
                    verifyServices: { XCTAssertEqual($0, s.material.services) }, readMaterial: { scope in try scope.withActive { s.material } },
                    verifyActivity: { actual, scope in try scope.withActive { XCTAssertEqual(actual, s.material.serviceActivity) } },
                    readArtifact: { artifact, scope in try scope.withActive { try files.read(artifact) } })
            }
            s.advanced.append(result.advanced); s.lastAcknowledged = result.frame
            if s.loseAcknowledgement { throw Fault.afterAcknowledgement }
            return result
        })
    }
    private func run(_ s: State, custody: Bool = true) throws -> Frame {
        try Sequence.prepare(owner: s.owner, candidate: s.candidate, directory: s.directory, admission: s.admission,
            fileCustodyAccepted: custody, useMachine: { body in
                try s.withMachine { machine in
                    let before = s.reads
                    let result = try body(machine)
                    let keys = Set(s.reads.keys).union(before.keys)
                    s.outerReads.append(Dictionary(uniqueKeysWithValues: keys.map { ($0, s.reads[$0, default: 0] - before[$0, default: 0]) }))
                    return result
                }
            }, providers: providers(s), verifyCurrent: { _ in s.hostChecks += 1 }, didCapture: { s.captures.append($0) })
    }
    private func budget(_ s: State, captures: Int, journal: Bool) {
        XCTAssertEqual(s.captures.count, captures); XCTAssertEqual(s.outerReads.count, captures)
        XCTAssertLessThanOrEqual(s.captures.count, 6)
        for counts in s.outerReads {
            XCTAssertEqual(counts[.readTransaction], journal ? 3 : 2)
            XCTAssertEqual(counts[.runtime], 2); XCTAssertEqual(counts[.frame], 6); XCTAssertEqual(counts[.activation], 2)
            XCTAssertEqual(counts[.writeTransaction, default: 0], 0)
        }
    }
    func testOwnedFullChainAndFreshPublishedRecoveryPreserveEveryFileWithoutReplay() throws {
        try fixture { s in
            try s.seedImport(); let original = try XCTUnwrap(s.intent)
            let first = try run(s)
            XCTAssertEqual(s.events, ["material", "policy", "publication", "acknowledgement"])
            budget(s, captures: 6, journal: true)
            XCTAssertTrue(first.entry.runtime.state.configurationPublished); XCTAssertEqual(first.inputs.intent?.phase, .runtimePublished)
            XCTAssertNotEqual(first.inputs.intent?.revision, original.revision); XCTAssertEqual(s.advanced, [true])
            XCTAssertNil(first.entry.activation.plan); XCTAssertFalse(first.entry.activation.jobsRegistered)
            let files = try XCTUnwrap(s.files), stamps = try files.stamps(), publications = files.publicationCalls
            XCTAssertEqual(publications, 8); s.reset()
            let second = try run(s); budget(s, captures: 5, journal: true)
            XCTAssertEqual(s.events, ["policy", "publication", "acknowledgement"])
            XCTAssertEqual(s.advanced, [false]); XCTAssertEqual(s.commits, 0); XCTAssertEqual(s.startupOpens, 0)
            try second.entry.requireSame(as: first.entry); try second.inputs.requireSame(as: first.inputs)
            XCTAssertEqual(files.publicationCalls, publications); XCTAssertEqual(try files.stamps(), stamps)
            let artifact = try XCTUnwrap(files.artifacts.last)
            for missing in [true, false] {
                if missing { try FileManager.default.removeItem(at: files.url(artifact)) } else { try files.put(artifact, bytes: Data([0])) }
                s.reset(); XCTAssertThrowsError(try run(s))
                XCTAssertEqual(s.events, ["policy", "publication"]); XCTAssertEqual(s.commits, 0)
                XCTAssertEqual(files.publicationCalls, publications)
                if missing { XCTAssertFalse(FileManager.default.fileExists(atPath: files.url(artifact).path)) }
                else { XCTAssertEqual(try files.read(artifact), Data([0])) }
                try files.put(artifact, bytes: artifact.bytes)
            }
        }
    }
    func testCustodyRefusesBeforeReadsAndAbsentThenEmptyStorageSkipAcknowledgement() throws {
        try fixture { s in
            XCTAssertThrowsError(try run(s, custody: false)) { XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted) }
            XCTAssertTrue(s.events.isEmpty); XCTAssertTrue(s.reads.isEmpty); XCTAssertTrue(s.captures.isEmpty); XCTAssertEqual(s.hostChecks, 0)
            let absent = try run(s); budget(s, captures: 5, journal: false)
            XCTAssertFalse(absent.inputs.journalPresent); XCTAssertNil(absent.inputs.intent)
            XCTAssertEqual(s.events, ["material", "policy", "publication"]); XCTAssertTrue(s.advanced.isEmpty)
            try s.seedImport(empty: true); s.reset()
            let empty = try run(s); budget(s, captures: 4, journal: true)
            XCTAssertTrue(empty.inputs.journalPresent); XCTAssertNil(empty.inputs.intent)
            XCTAssertEqual(s.events, ["policy", "publication"]); XCTAssertTrue(s.advanced.isEmpty)
            XCTAssertEqual(s.commits, 0); XCTAssertEqual(s.startupOpens, 0)
        }
    }
    func testUnresolvedWritingRefusesBeforeMaterialPublicationOrAcknowledgement() throws {
        try fixture { s in
            let expected = try s.withMachine { try $0.retainedSetupPolicySnapshot(owner: s.owner, candidate: s.candidate) }
            let open = try XCTUnwrap(s.openPolicy)
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPolicyOwner.resume(expected: expected, candidate: s.candidate,
                directory: s.directory, admission: s.admission, useMachine: { body in try s.withMachine(body) },
                openJournal: open, verifySnapshot: { _ in }, didStage: { if $0 == .writingRetained { throw Fault.policy } }))
            let before = try s.pair(); s.reset()
            XCTAssertThrowsError(try run(s)) { XCTAssertEqual($0 as? RuntimeActivationError, .unavailable) }
            XCTAssertEqual(s.events, ["policy"]); budget(s, captures: 1, journal: false)
            XCTAssertEqual(s.commits, 0); XCTAssertEqual(s.startupOpens, 0); XCTAssertNil(s.files)
            XCTAssertEqual(try s.pair(), before)
        }
    }
    func testMissingMaterialIsRetainedBeforePolicyAndEscapedOrPoisonedLoansRefuse() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let runtime = try f.machine().stableRuntimePreparationSnapshot(owner: f.owner, candidate: f.candidate)
            let s = State(f, runtime: runtime); s.stopPolicy = true
            XCTAssertNil(runtime.state.reference)
            XCTAssertThrowsError(try run(s)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(s.events, ["material", "policy"]); budget(s, captures: 2, journal: false)
            XCTAssertEqual(s.captures.last?.entry.runtime.state.reference, try f.material.reference)
            let material = try Material(runtime: XCTUnwrap(s.captures.last).entry.runtime, activation: XCTUnwrap(s.captures.last).entry.activation)
            XCTAssertThrowsError(try XCTUnwrap(s.escapedMaterial)(material)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            s.reset(); s.poisonMaterial = true
            XCTAssertThrowsError(try run(s)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertEqual(s.events, ["material"]); XCTAssertEqual(s.commits, 0); s.poisonMaterial = false
            s.reset(); s.foreignMaterial = true
            XCTAssertThrowsError(try run(s)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(s.events, ["material", "policy"]); XCTAssertEqual(s.commits, 0)
            try? f.machine().close()
        }
    }
    func testStaleMaterialAndPolicyResultsStopBeforePublicationThenFreshStateRecovers() throws {
        try fixture { s in
            s.staleMaterial = true
            XCTAssertThrowsError(try run(s)); XCTAssertEqual(s.events, ["material"])
            XCTAssertNil(s.files); XCTAssertEqual(s.commits, 0); s.staleMaterial = false
            s.reset(); s.stalePolicy = true
            XCTAssertThrowsError(try run(s)); XCTAssertEqual(s.events, ["material", "policy"])
            XCTAssertNil(s.files); XCTAssertEqual(s.startupOpens, 1); s.stalePolicy = false
            s.reset(); let actual = try run(s); budget(s, captures: 5, journal: false)
            XCTAssertTrue(actual.entry.runtime.state.configurationPublished)
            XCTAssertEqual(s.events, ["material", "policy", "publication"]); XCTAssertEqual(s.startupOpens, 0)
        }
    }
    func testStalePublicationAndLostAcknowledgementRequireFreshReadOnlyRecovery() throws {
        try fixture { s in
            try s.seedImport(); s.stalePublication = true
            XCTAssertThrowsError(try run(s)); XCTAssertEqual(s.events, ["material", "policy", "publication"])
            XCTAssertEqual(try s.currentIntent()?.phase, .retained); s.stalePublication = false
            let files = try XCTUnwrap(s.files), publications = files.publicationCalls, stamps = try files.stamps()
            s.reset(); s.loseAcknowledgement = true
            XCTAssertThrowsError(try run(s)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(s.events, ["policy", "publication", "acknowledgement"])
            XCTAssertEqual(s.advanced, [true]); let committed = try XCTUnwrap(s.lastAcknowledged); s.loseAcknowledgement = false
            XCTAssertEqual(files.publicationCalls, publications); s.reset()
            let actual = try run(s); budget(s, captures: 5, journal: true)
            try actual.entry.requireSame(as: committed.entry); try actual.inputs.requireSame(as: committed.inputs)
            XCTAssertEqual(s.advanced, [false]); XCTAssertEqual(s.commits, 0)
            XCTAssertEqual(files.publicationCalls, publications); XCTAssertEqual(try files.stamps(), stamps)
        }
    }
}
