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
    private typealias Assembly = MachineUpdateRetainedSetupRuntimeNativeEntry
    private typealias Native = MachineUpdateRetainedSetupRuntimeNativeContext
    private typealias Facade = MachineUpdateRetainedSetupInitialRuntimeNative
    private typealias Entry = Sequence.Entry
    private typealias Frame = Sequence.Frame
    private typealias Inputs = Sequence.Inputs
    private typealias Policy = Sequence.Policy
    private typealias Material = Sequence.Material
    private typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    private typealias Read = PreparationIntentStore.InitialRuntimeRead
    private enum Fault: Error, Equatable { case policy, afterAcknowledgement, materialHost, unexpected, assemblyPair }
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
    private final class State {
        let owner: LocalAccountIdentity, candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease
        let admission: UpdateOrdinaryAdmissionLease, material: RuntimePreparationMaterial
        let machine: () throws -> PreparationIntentStore
        let reopen: ((() throws -> Void)?) throws -> Void
        let initialRuntime: MachineUpdateStableRuntimePreparationSnapshot
        let openPolicy: ((MachineUpdateRetainedSetupPolicyOwner.JournalAccess) throws -> AuthorityJournal)?
        var files: Files?, intent: SharedSetupImportIntent?
        var machines: [PreparationIntentStore] = [], startupWriters: [AuthorityJournal] = []
        var assemblyPairOpens = 0, assemblyPairReads = 0
        var failAfterPolicy = false, refuseAssemblyHost = false, stopAtAssemblyPair = false
        var events: [String] = [], captures: [Frame] = [], outerReads: [[Read: Int]] = []
        var reads: [Read: Int] = [:], commits = 0, startupOpens = 0, hostChecks = 0
        var advanced: [Bool] = [], lastAcknowledged: Frame?
        var stopPolicy = false, staleMaterial = false, stalePolicy = false, stalePublication = false, loseAcknowledgement = false
        var poisonMaterial = false, foreignMaterial = false
        var refuseMaterialHost = false, swallowMaterialHostFailure = false
        var materialHostStates: [RuntimePreparationState] = []
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
        func reset() { events = []; captures = []; outerReads = []; reads = [:]; commits = 0; startupOpens = 0; hostChecks = 0; advanced = []; materialHostStates = [] }
        func withMachine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            try reopen { self.commits += 1 }; let actual = try machine()
            machines.append(actual)
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
    static func withImportedPublicationFixture(_ body: (RetainedPolicyWriterFixture, MachineUpdateRetainedSetupPolicySnapshot,
        AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(sharedImportFormats: true) { f in
            let state = State(f); try state.seedImport()
            let before = try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
            let recorded = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: before, candidate: f.candidate,
                directory: f.directory, admission: f.admission, useMachine: { callback in
                    try f.reopen(nil); let machine = f.machine(); defer { try? machine.close() }; return try callback(machine)
                }, openJournal: { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) }, verifySnapshot: { _ in })
            try f.reopen(nil); defer { try? f.machine().close() }; try body(f, recorded, state.pair())
        }
    }
    private func fixture(_ body: (State) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(sharedImportFormats: true) { f in
            let state = State(f); defer { if let files = state.files { XCTAssertNoThrow(try files.close()) }; try? f.machine().close() }
            try body(state)
        }
    }
    private func verify<Loan>(_ s: State, _ actual: Loan, _ callback: (Loan) throws -> Void) throws {
        let before = s.reads
        defer { XCTAssertEqual(s.reads, before, "A borrowed verifier queried the machine") }
        try callback(actual)
    }
    private func providers(_ s: State) -> Sequence.Providers {
        .init(material: { expected, callback in
            s.events.append("material"); s.escapedMaterial = callback
            if s.swallowMaterialHostFailure {
                XCTAssertThrowsError(try self.verify(s, expected, callback)) { XCTAssertEqual($0 as? Fault, .materialHost) }
                XCTAssertThrowsError(try self.verify(s, expected, callback)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                return expected.runtime.state
            }
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
                openJournal: { mode in
                    let journal = try open(mode)
                    if mode == .startup {
                        s.startupOpens += 1
                        XCTAssertTrue(try journal.read { _ in true }); s.startupWriters.append(journal)
                    }
                    return journal
                },
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
            }, providers: providers(s), verifyCurrent: { _ in s.hostChecks += 1 }, verifyMaterialCurrent: { actual in
                s.materialHostStates.append(actual.runtime.state)
                if s.refuseMaterialHost { throw Fault.materialHost }
            }, didCapture: { s.captures.append($0) })
    }
    private func assemblyProviders(_ s: State, _ context: Native.Context) -> Sequence.Providers {
        let owned = providers(s)
        return .init(material: { expected, verify in
            try owned.material(expected) { actual in
                try context.verifyMaterial(actual); try verify(actual)
            }
        }, policy: { expected, verify in
            let actual = try owned.policy(expected) { actual in
                try context.verifyPolicy(actual); try verify(actual)
            }
            if s.failAfterPolicy { s.refuseAssemblyHost = true }
            return actual
        }, publication: { expected, verify in
            s.events.append("publication"); try s.prepareFiles(expected)
            let files = try XCTUnwrap(s.files)
            let host: (Policy) throws -> Void = { actual in
                try context.verifyPublication(actual); try self.verify(s, actual, verify)
            }
            let publication = MachineUpdateRetainedSetupInitialPublicationNative.Callbacks(verifyCurrent: host,
                verifyServices: { XCTAssertEqual($0, s.material.services) },
                readMaterial: { scope in try scope.withActive { s.material } },
                verifyActivity: { activity, scope in try scope.withActive { XCTAssertEqual(activity, s.material.serviceActivity) } },
                readArtifact: { artifact, scope in try scope.withActive { try files.read(artifact) } },
                publish: { scope in try scope.withActive {
                    try files.publish(XCTUnwrap(scope.artifact), verify: scope.requireActive)
                } })
            let completion = MachineUpdateRetainedSetupInitialCompletionNative.Callbacks(verifyCurrent: host,
                verifyServices: { XCTAssertEqual($0, s.material.services) },
                readMaterial: { scope in try scope.withActive { s.material } },
                verifyActivity: { activity, scope in try scope.withActive { XCTAssertEqual(activity, s.material.serviceActivity) } },
                readArtifact: { artifact, scope in try scope.withActive { try files.read(artifact) } },
                didStorageStage: { _, scope in
                    try scope.requireActive(); try host(scope.read().snapshot); try scope.requireActive()
                })
            return try Facade.withA10d(expected: expected, candidate: s.candidate, directory: s.directory,
                admission: s.admission, withTargetPair: { body in
                    s.assemblyPairOpens += 1
                    for machine in s.machines { XCTAssertNoThrow(try machine.requireClosedForRetainedSetupPolicyWrite()) }
                    for writer in s.startupWriters { XCTAssertThrowsError(try writer.read { _ in true }) }
                    let journal = try XCTUnwrap(s.openPolicy)(.readOnly); defer { try? journal.close() }
                    let initial = try XCTUnwrap(expected.activation.runtime.setup.account?.initialization)
                    func read() throws -> Facade.Boundary {
                        s.assemblyPairReads += 1
                        let actual = try journal.captureRetainedSetupPolicyBoundary(expected: initial)
                        try XCTUnwrap(expected.intent).requireRecorded(actual); return actual
                    }
                    if s.stopAtAssemblyPair { _ = try read(); throw Fault.assemblyPair }
                    return try body(read)
                }, useMachine: { body in try s.withMachine(body) }, publication: publication, completion: completion)
        }, acknowledgement: { expected, verify in
            try owned.acknowledgement(expected) { actual in
                try context.verifyAcknowledgement(actual); try verify(actual)
            }
        })
    }
    private func assemblyFrame(_ s: State) throws -> Frame {
        try s.withMachine { machine in
            let actual = try machine.retainedSetupInitialRuntimeEntry(owner: s.owner, candidate: s.candidate)
            let inputs = try machine.withSharedImportJournal { journal in
                if let journal { return try machine.withSharedImportSnapshot(journal: journal) { path, owner in
                    try Inputs.capture(expected: actual.runtime, journal: journal,
                        verifyCurrent: { try machine.validateStorageLease() }, readRelay: { try .read($0, directory: path, owner: owner) })
                } }
                return try Inputs.capture(expected: actual.runtime, journal: nil,
                    verifyCurrent: { try machine.validateStorageLease() }, readRelay: { _ in throw SharedSetupImportError.wrongScope })
            }
            return (actual, inputs)
        }
    }
    private func withAssembly(_ s: State, _ body: (Native.Context, () throws -> Frame) throws -> Void) throws {
        let expected = try assemblyFrame(s); s.reset()
        try expected.entry.runtime.setup.source.actual.inventory.compareRelease(s.candidate)
        let inventoryDigest = MachineUpdateActivationRecord.digest(expected.entry.runtime.setup.source.actual.inventory.canonicalBytes)
        let controls = Native.TestControls(validateCustody: {
            try s.admission.validateMachineBoundary(directory: s.directory,
                expected: expected.entry.runtime.setup.source.actual.admission.machine)
        }, validateRelease: { actual in
            s.hostChecks += 1
            XCTAssertEqual(actual.runtime.preparation.accountID, expected.entry.runtime.preparation.accountID)
            guard MachineUpdateActivationRecord.digest(actual.runtime.setup.source.actual.inventory.canonicalBytes) == inventoryDigest else {
                throw Fault.materialHost
            }
        }, validateExecutingCode: {
            if s.refuseAssemblyHost { throw Fault.materialHost }
        }, lookupOwner: { uid in XCTAssertEqual(uid, s.owner.uid); return s.owner },
        validateServices: { XCTAssertEqual($0, s.material.services) })
        try Native.withTestContext(expected: expected, candidate: s.candidate, controls: controls) { context in
            try body(context, {
                try Assembly.withSequence(context: context, owner: s.owner, candidate: s.candidate,
                    directory: s.directory, admission: s.admission, useMachine: { callback in
                        try s.withMachine { machine in
                            let before = s.reads, result = try callback(machine)
                            let keys = Set(s.reads.keys).union(before.keys)
                            s.outerReads.append(Dictionary(uniqueKeysWithValues: keys.map { ($0, s.reads[$0, default: 0] - before[$0, default: 0]) }))
                            s.captures.append(result)
                            try machine.requireClosedForRetainedSetupPolicyWrite(); return result
                        }
                    }, providers: self.assemblyProviders(s, context))
            })
        }
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
    func testCaptureBudgetRefusesSeventhCaptureAndStaysExhausted() throws {
        var budget = Sequence.CaptureBudget()
        for _ in 0..<6 { XCTAssertNoThrow(try budget.claim()) }
        for _ in 0..<2 {
            XCTAssertThrowsError(try budget.claim()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
        var fresh = Sequence.CaptureBudget()
        XCTAssertNoThrow(try fresh.claim())
    }
    func testActualRuntimeBodyPreservesAllRowsAndFilesOutsideItsDeclaredFootprint() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(sharedImportFormats: true, schema29: true) { f in
            let s = State(f)
            defer { if let files = s.files { XCTAssertNoThrow(try files.close()) }; try? f.machine().close() }
            XCTAssertEqual(s.initialRuntime.setup.source.actual.schemaVersion, 29)
            let root = URL(fileURLWithPath: s.directory.path).deletingLastPathComponent()
            let sentinel = root.appendingPathComponent("outside-maintenance-profile.cbor")
            try Data([1, 3, 5, 7]).write(to: sentinel)
            let target = s.initialRuntime.preparation.accountID
            let initial = try XCTUnwrap(s.initialRuntime.setup.account?.initialization)
            let database = s.directory.path + "/installation.sqlite"
            let mutable = Set([database, initial.journalPath, initial.continuityPath].flatMap { [$0, $0 + "-journal"] })
            func outsideFiles() throws -> [String: Data] {
                let enumerator = try XCTUnwrap(FileManager.default.enumerator(at: root,
                    includingPropertiesForKeys: [.isRegularFileKey], options: []))
                var result: [String: Data] = [:]
                for case let url as URL in enumerator {
                    if try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true,
                       !mutable.contains(url.path) {
                        result[String(url.path.dropFirst(root.path.count + 1))] = MachineUpdateActivationRecord.digest(try Data(contentsOf: url))
                    }
                }
                return result
            }
            let excluded = ["runtime_preparation_v1": target, MachineUpdateRetainedSetupPolicyStorage.tableName: target]
            let rows = try runtimeMaintenanceFixtureRows(database, excludingRowsForAccounts: excluded)
            let files = try outsideFiles()
            XCTAssertFalse(rows.isEmpty); XCTAssertFalse(files.isEmpty)
            let actual = try run(s)
            XCTAssertTrue(actual.entry.runtime.state.configurationPublished)
            XCTAssertEqual(try XCTUnwrap(s.files).publicationCalls, 8)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(database, excludingRowsForAccounts: excluded), rows)
            XCTAssertEqual(try outsideFiles(), files)
            XCTAssertNil(actual.entry.activation.plan); XCTAssertFalse(actual.entry.activation.jobsRegistered)
        }
    }
    func testOwnedFullChainAndFreshPublishedRecoveryPreserveEveryFileWithoutReplay() throws {
        try fixture { s in
            try s.seedImport(); let original = try XCTUnwrap(s.intent)
            let first = try run(s)
            XCTAssertEqual(s.events, ["material", "policy", "publication", "acknowledgement"])
            XCTAssertFalse(s.materialHostStates.isEmpty)
            budget(s, captures: 6, journal: true)
            XCTAssertTrue(first.entry.runtime.state.configurationPublished); XCTAssertEqual(first.inputs.intent?.phase, .runtimePublished)
            XCTAssertNotEqual(first.inputs.intent?.revision, original.revision); XCTAssertEqual(s.advanced, [true])
            XCTAssertNil(first.entry.activation.plan); XCTAssertFalse(first.entry.activation.jobsRegistered)
            let files = try XCTUnwrap(s.files), stamps = try files.stamps(), publications = files.publicationCalls
            XCTAssertEqual(publications, 8); s.reset()
            let second = try run(s); budget(s, captures: 5, journal: true)
            XCTAssertEqual(s.events, ["policy", "publication", "acknowledgement"])
            XCTAssertTrue(s.materialHostStates.isEmpty)
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
            XCTAssertTrue(s.events.isEmpty); XCTAssertTrue(s.reads.isEmpty); XCTAssertTrue(s.captures.isEmpty); XCTAssertEqual(s.hostChecks, 0); XCTAssertTrue(s.materialHostStates.isEmpty)
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
            XCTAssertTrue(s.materialHostStates.isEmpty)
            XCTAssertEqual(s.commits, 0); XCTAssertEqual(s.startupOpens, 0); XCTAssertNil(s.files)
            XCTAssertEqual(try s.pair(), before)
        }
    }
    func testMissingMaterialIsRetainedBeforePolicyAndEscapedOrPoisonedLoansRefuse() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let runtime = try f.machine().stableRuntimePreparationSnapshot(owner: f.owner, candidate: f.candidate)
            let s = State(f, runtime: runtime); s.stopPolicy = true
            XCTAssertNil(runtime.state.reference)
            s.refuseMaterialHost = true
            XCTAssertThrowsError(try run(s)) { XCTAssertEqual($0 as? Fault, .materialHost) }
            XCTAssertEqual(s.events, ["material"]); budget(s, captures: 1, journal: false)
            XCTAssertEqual(s.materialHostStates.count, 1); XCTAssertNil(s.materialHostStates.first?.reference)
            XCTAssertEqual(s.commits, 0); XCTAssertEqual(s.startupOpens, 0); XCTAssertNil(s.files)
            let refused = try XCTUnwrap(s.captures.last)
            let refusedMaterial = try Material(runtime: refused.entry.runtime, activation: refused.entry.activation)
            XCTAssertThrowsError(try XCTUnwrap(s.escapedMaterial)(refusedMaterial)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            s.reset(); s.swallowMaterialHostFailure = true
            XCTAssertThrowsError(try run(s)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertEqual(s.events, ["material"]); budget(s, captures: 1, journal: false)
            XCTAssertEqual(s.materialHostStates.count, 1); XCTAssertEqual(s.commits, 0)
            XCTAssertEqual(s.startupOpens, 0); XCTAssertNil(s.files)
            try f.reopen(nil)
            try f.machine().stableRuntimePreparationSnapshot(owner: f.owner, candidate: f.candidate).requireSame(as: runtime)
            try f.machine().close()
            s.reset(); s.refuseMaterialHost = false; s.swallowMaterialHostFailure = false
            XCTAssertThrowsError(try run(s)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(s.events, ["material", "policy"]); budget(s, captures: 2, journal: false)
            let retainedReference = try f.material.reference
            XCTAssertEqual(s.captures.last?.entry.runtime.state.reference, retainedReference)
            XCTAssertTrue(s.materialHostStates.contains { $0.reference == nil })
            XCTAssertTrue(s.materialHostStates.contains { $0.reference == retainedReference })
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
    func testAssemblyClosesP04StartupBeforeOpeningTheTargetReadOnlyPair() throws {
        try fixture { s in
            s.stopAtAssemblyPair = true
            XCTAssertThrowsError(try withAssembly(s) { _, run in _ = try run() }) {
                XCTAssertEqual($0 as? Fault, .assemblyPair)
            }
            XCTAssertEqual(s.events, ["material", "policy", "publication"])
            XCTAssertEqual(s.startupOpens, 1); XCTAssertFalse(s.startupWriters.isEmpty)
            XCTAssertEqual(s.assemblyPairOpens, 1); XCTAssertEqual(s.assemblyPairReads, 1)
            budget(s, captures: 3, journal: false)
            let actual = try assemblyFrame(s)
            XCTAssertEqual(actual.entry.intent?.phase, .recorded)
            XCTAssertFalse(actual.entry.runtime.state.configurationPublished); XCTAssertNil(actual.inputs.intent)
            XCTAssertNil(actual.entry.activation.plan); XCTAssertFalse(actual.entry.activation.jobsRegistered)
            XCTAssertEqual(s.files?.publicationCalls, 0)
            for writer in s.startupWriters { XCTAssertThrowsError(try writer.read { _ in true }) }
            for machine in s.machines { XCTAssertNoThrow(try machine.requireClosedForRetainedSetupPolicyWrite()) }
        }
    }
    func testAssemblyCarriesActualImportChoicesThroughPublicationAndAcknowledgement() throws {
        try fixture { s in
            try s.seedImport(); let before = try XCTUnwrap(s.intent)
            var escaped: Native.Context?, final: Frame?
            try withAssembly(s) { context, run in
                escaped = context; let actual = try run(); final = actual
                budget(s, captures: 6, journal: true)
                XCTAssertEqual(s.events, ["material", "policy", "publication", "acknowledgement"])
                XCTAssertEqual(s.advanced, [true]); XCTAssertEqual(actual.inputs.intent?.phase, .runtimePublished)
                XCTAssertNotEqual(actual.inputs.intent?.revision, before.revision)
                XCTAssertEqual(s.assemblyPairOpens, 1); XCTAssertEqual(s.assemblyPairReads, 63)
                XCTAssertEqual(s.files?.publicationCalls, 8)
            }
            XCTAssertThrowsError(try XCTUnwrap(escaped).verifyFrame(XCTUnwrap(final))) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
        }
    }
    private enum SeedFault { case bytes, mode }
    /// P04 and D2 write the policy and marker. The test seeds owned files directly.
    /// Owned callbacks use production retention readers. They do not execute the Root-only native callback.
    /// D2 compares actual bytes with its derived artifacts. The owned reader checks each file's owner and mode.
    private func seedPublishedAssembly(_ s: State, fault: SeedFault? = nil, beforeMarker: (() throws -> Void)? = nil) throws {
        try withAssembly(s) { context, _ in
            let before = try XCTUnwrap(assemblyFrame(s).entry.policy)
            let recorded = try providers(s).policy(before, context.verifyPolicy)
            s.captures = [try assemblyFrame(s)]; try s.prepareFiles(recorded)
            let files = try XCTUnwrap(s.files)
            for artifact in files.artifacts { try files.put(artifact, bytes: artifact.bytes) }
            if let fault {
                let artifact = try XCTUnwrap(files.artifacts.first)
                switch fault {
                case .bytes: try files.put(artifact, bytes: Data([0]))
                case .mode: guard chmod(files.url(artifact).path, 0o666) == 0 else { throw JournalLeaseError.system(errno) }
                }
            }
            try beforeMarker?()
            var checkedPaths = Set<String>()
            _ = try s.withMachine { machine in
                try MachineUpdateRetainedSetupInitialCompletion.complete(machine: machine, expected: recorded,
                    candidate: s.candidate, directory: s.directory, admission: s.admission, fileCustodyAccepted: true,
                    readPolicyBoundary: s.pair, verifyCurrent: context.verifyPublication,
                    verifyServices: { XCTAssertEqual($0, s.material.services) },
                    readMaterial: { scope in try scope.withActive { s.material } },
                    verifyActivity: { actual, scope in try scope.withActive { XCTAssertEqual(actual, s.material.serviceActivity) } },
                    readArtifact: { artifact, scope in try scope.withActive {
                        guard let bytes = try files.read(artifact) else { return nil }
                        try AdministrativeSetupPublication.validateRetained(bytes, file: files.file(artifact),
                            directory: files.directory, owner: getuid(), verify: scope.requireActive)
                        checkedPaths.insert(artifact.path); return bytes
                    } })
            }
            XCTAssertEqual(checkedPaths, Set(files.artifacts.map(\.path)))
        }
    }
    private func assemblyPublishedRecovery(empty: Bool) throws {
        try fixture { s in
            try seedPublishedAssembly(s); let files = try XCTUnwrap(s.files), stamps = try files.stamps()
            if empty { try s.seedImport(empty: true) }
            try withAssembly(s) { _, run in
                let actual = try run(); budget(s, captures: 4, journal: empty)
                XCTAssertEqual(actual.inputs.journalPresent, empty); XCTAssertNil(actual.inputs.intent)
                XCTAssertEqual(s.events, ["policy", "publication"]); XCTAssertEqual(s.commits, 0)
                XCTAssertEqual(s.startupOpens, 0); XCTAssertTrue(s.advanced.isEmpty)
            }
            XCTAssertEqual(files.publicationCalls, 0); XCTAssertEqual(try files.stamps(), stamps)
        }
    }
    func testAssemblyPublishedRecoverySkipsMaterialAndAbsentAcknowledgement() throws {
        try assemblyPublishedRecovery(empty: false)
    }
    func testAssemblyPublishedRecoverySkipsMaterialAndEmptyAcknowledgement() throws {
        try assemblyPublishedRecovery(empty: true)
    }
    func testAssemblyHostChangeAfterP04StopsBeforePublicationAndExpiresTheContext() throws {
        try fixture { s in
            s.failAfterPolicy = true
            var escaped: Native.Context?
            XCTAssertThrowsError(try withAssembly(s) { context, run in escaped = context; _ = try run() }) {
                XCTAssertEqual($0 as? Fault, .materialHost)
            }
            XCTAssertEqual(s.events, ["material", "policy"]); XCTAssertEqual(s.assemblyPairOpens, 0)
            XCTAssertNil(s.files); XCTAssertTrue(s.advanced.isEmpty)
            for writer in s.startupWriters { XCTAssertThrowsError(try writer.read { _ in true }) }
            for machine in s.machines { XCTAssertNoThrow(try machine.requireClosedForRetainedSetupPolicyWrite()) }
            let actual = try assemblyFrame(s)
            XCTAssertEqual(actual.entry.intent?.phase, .recorded)
            XCTAssertFalse(actual.entry.runtime.state.configurationPublished)
            XCTAssertThrowsError(try XCTUnwrap(escaped).verifyFrame(actual)) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
        }
    }
    func testAssemblyRejectsAnotherActualInventoryBetweenLoansAndPoisonsTheContext() throws {
        try fixture { first in
            try fixture { second in
                let original = try assemblyFrame(first), changed = try assemblyFrame(second)
                XCTAssertNotEqual(original.entry.runtime.setup.source.actual.inventory.canonicalBytes,
                    changed.entry.runtime.setup.source.actual.inventory.canonicalBytes)
                XCTAssertThrowsError(try withAssembly(first) { context, _ in
                    try context.verifyFrame(original)
                    let checks = first.hostChecks
                    XCTAssertThrowsError(try context.verifyFrame(changed))
                    XCTAssertEqual(first.hostChecks, checks)
                    XCTAssertThrowsError(try context.verifyFrame(original)) {
                        XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                    }
                }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                XCTAssertEqual(first.commits, 0); XCTAssertTrue(first.events.isEmpty)
                XCTAssertEqual(second.commits, 0); XCTAssertTrue(second.events.isEmpty)
            }
        }
    }
    func testAssemblyRecoveryFixtureRejectsBadSeedBytesAndModeBeforeItsMarker() throws {
        try fixture { s in
            for fault in [SeedFault.bytes, .mode] {
                var beforeMarkerCommits: Int?
                XCTAssertThrowsError(try seedPublishedAssembly(s, fault: fault, beforeMarker: { beforeMarkerCommits = s.commits })) { error in
                    switch fault {
                    case .bytes: XCTAssertEqual(error as? AdministrativeSetupPublicationError, .conflictingConfiguration)
                    case .mode: XCTAssertEqual(error as? JournalLeaseError, .unsafeMetadata)
                    }
                }
                XCTAssertEqual(s.commits, try XCTUnwrap(beforeMarkerCommits))
                let actual = try assemblyFrame(s), files = try XCTUnwrap(s.files), artifact = try XCTUnwrap(files.artifacts.first)
                XCTAssertEqual(actual.entry.intent?.phase, .recorded)
                XCTAssertFalse(actual.entry.runtime.state.configurationPublished)
                XCTAssertEqual(files.publicationCalls, 0)
                switch fault {
                case .bytes: XCTAssertEqual(try Data(contentsOf: files.url(artifact)), Data([0]))
                case .mode:
                    var info = stat(); XCTAssertEqual(lstat(files.url(artifact).path, &info), 0)
                    XCTAssertEqual(info.st_mode & 0o777, 0o666)
                }
                for machine in s.machines { XCTAssertNoThrow(try machine.requireClosedForRetainedSetupPolicyWrite()) }
            }
        }
    }
}
