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
        let mapped: Bool
        init(_ artifacts: [Artifact], owner: UInt32, seed: Bool = true, mappedRoot: URL? = nil) throws {
            self.artifacts = artifacts
            mapped = mappedRoot != nil
            root = mappedRoot ?? URL(fileURLWithPath: "/private/tmp/remozio-initial-completion-" + UUID().uuidString)
            if !mapped { try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false) }
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            directory = try .init(anchor: root.path, relativePath: mapped ? "Services" : "Files", owner: getuid(), visibility: .sharedMetadata)
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
            if mapped { return root.appendingPathComponent(try! RuntimeMaintenanceCommitments.MutationFootprint.relative(artifact.path)) }
            return URL(fileURLWithPath: directory.path).appendingPathComponent(URL(fileURLWithPath: artifact.path).lastPathComponent)
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
            try ProtectedServiceConfiguration.readOptional(anchor: mapped ? root.path : directory.path,
                relativePath: mapped ? RuntimeMaintenanceCommitments.MutationFootprint.relative(artifact.path) : url(artifact).lastPathComponent, owner: getuid())
        }
        func publish(_ artifact: Artifact, verify: () throws -> Void) throws {
            publicationCalls += 1
            let target: ProtectedSetupDirectory
            if mapped {
                let relative = try RuntimeMaintenanceCommitments.MutationFootprint.relative(artifact.path)
                let parent = (relative as NSString).deletingLastPathComponent
                target = try .init(anchor: parent.isEmpty ? root.deletingLastPathComponent().path : root.path,
                    relativePath: parent.isEmpty ? root.lastPathComponent : parent,
                    owner: getuid(), visibility: .sharedMetadata)
            } else { target = directory }
            defer { if mapped { target.close() } }
            _ = try AdministrativeSetupPublication.publish(artifact.bytes, file: file(artifact),
                directory: target, owner: getuid(), verify: verify)
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
        var observationRoot: URL?
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
                owner: owner.uid, seed: false, mappedRoot: observationRoot)
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
            XCTAssertEqual(counts[.runtime], 2); XCTAssertEqual(counts[.frame], 1) /* stable frame read cache: was 6 */; XCTAssertEqual(counts[.activation], 2)
            XCTAssertEqual(counts[.writeTransaction, default: 0], 0)
        }
    }
    private typealias Observation = RuntimeMaintenanceRuntimeObservation
    private typealias Window = RuntimeMaintenanceWindowRecord
    private func inventory(_ root: URL) throws -> [String: Data] {
        let items = try XCTUnwrap(FileManager.default.enumerator(at: root,
            includingPropertiesForKeys: [.isRegularFileKey], options: []))
        var result: [String: Data] = [:]
        for case let url as URL in items {
            if try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
                var metadata = stat()
                guard lstat(url.path, &metadata) == 0 else { throw JournalLeaseError.system(errno) }
                var value = MachineUpdateActivationRecord.digest(try Data(contentsOf: url))
                for field in [UInt64(metadata.st_ino), UInt64(metadata.st_mode), UInt64(metadata.st_uid), UInt64(metadata.st_gid),
                    UInt64(metadata.st_mtimespec.tv_sec), UInt64(metadata.st_mtimespec.tv_nsec),
                    UInt64(metadata.st_ctimespec.tv_sec), UInt64(metadata.st_ctimespec.tv_nsec)] {
                    var big = field.bigEndian; withUnsafeBytes(of: &big) { value.append(contentsOf: $0) }
                }
                result[url.path] = value
            }
        }
        return result
    }
    private func prepareObservationFiles(_ s: State, frame: Frame) throws {
        let root = URL(fileURLWithPath: s.directory.path).deletingLastPathComponent().appendingPathComponent("ObservedPublications")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
        s.observationRoot = root
        let declaration = try RuntimeMaintenanceCommitments.MutationFootprint(runtime: frame.entry.runtime, inputs: frame.inputs).declaration
        for directory in Set(declaration.files.map { ($0 as NSString).deletingLastPathComponent }) {
            try FileManager.default.createDirectory(at: root.appendingPathComponent(directory), withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755])
        }
        // This fixture already owns retained material. Put its actual bytes at the declared leaf before the body.
        if frame.entry.runtime.state.reference != nil {
            let paths = try RuntimePreparationPaths(accountID: s.initialRuntime.preparation.accountID)
            let relative = try RuntimeMaintenanceCommitments.MutationFootprint.relative(paths.privateDirectory + "/" + AdministrativeSetupPublication.File.runtimeRecord.name)
            let file = root.appendingPathComponent(relative)
            try s.material.encoded.write(to: file); XCTAssertEqual(chmod(file.path, 0o600), 0)
        }
    }
    private func owners(_ frame: Frame, authorityID: Data) throws -> (LocalAccountIdentity, LocalAccountIdentity) {
        let a = try XCTUnwrap(frame.entry.runtime.setup.source.preparations.first { $0.accountID == authorityID })
        return (.init(uid: a.ownerUID, primaryGroupID: getgid(), directoryID: a.directoryID), frame.entry.runtime.setup.owner)
    }
    private func commitments(_ s: State, frame: Frame, authorityID: Data) throws -> RuntimeMaintenanceCommitments {
        let (a, b) = try owners(frame, authorityID: authorityID)
        return try .observing(entry: frame.entry, inputs: frame.inputs, authorityAccountID: authorityID,
            authorityOwner: a, targetOwner: b, candidate: s.candidate, purpose: .retainedRuntime)
    }
    private func window(_ scope: Window.Scope, phase: Window.Phase = .executing) throws -> Window {
        try .init(id: AccountPreparationIntent.randomID(), revision: AccountPreparationIntent.randomID(), purpose: .retainedRuntime,
            scope: scope, phase: phase, operation: phase == .executing ? .unknown : .notStarted, service: .stopped)
    }
    private func observe(_ s: State, window: Window, frame: Frame? = nil, refuseRead: Bool = false,
        readPolicy: (() throws -> AuthorityJournal.MachineUpdatePolicyBoundary)? = nil) throws -> Observation.State {
        let actual = try frame ?? assemblyFrame(s), (a, b) = try owners(actual, authorityID: window.scope.authority.accountID)
        let root = try XCTUnwrap(s.observationRoot)
        return Observation.observeOwned(window: window, candidate: s.candidate, readFrame: {
            if refuseRead { throw Fault.unexpected }; return try frame ?? self.assemblyFrame(s)
        }, readPolicy: readPolicy ?? s.pair, readMaterial: { runtime in
            let paths = try RuntimePreparationPaths(accountID: runtime.preparation.accountID)
            let relative = try RuntimeMaintenanceCommitments.MutationFootprint.relative(paths.privateDirectory + "/" + AdministrativeSetupPublication.File.runtimeRecord.name)
            return try ProtectedServiceConfiguration.readOptional(anchor: root.path, relativePath: relative, owner: getuid())
                .map { try RuntimePreparationMaterial.decode($0) }
        }, readFile: { path, _ in
            try ProtectedServiceConfiguration.readOptional(anchor: root.path,
                relativePath: RuntimeMaintenanceCommitments.MutationFootprint.relative(path), owner: getuid())
        }, lookup: { uid in if uid == a.uid { return a }; guard uid == b.uid else { throw Fault.unexpected }; return b }, verifyCurrent: {})
    }
    private func initialPair(_ s: State) throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
        let initial = try XCTUnwrap(s.initialRuntime.setup.account?.initialization)
        let anchor = URL(fileURLWithPath: s.directory.path).deletingLastPathComponent().path
        let journal = (initial.journalPath as NSString).deletingLastPathComponent
        let continuity = (initial.continuityPath as NSString).deletingLastPathComponent
        let storage = try MachineUpdateRetainedSetupPromotionNativeSupport.openExistingStorage(initial: initial,
            openJournalLease: { try .init(anchor: anchor, relativeDirectory: String(journal.dropFirst(anchor.count + 1)), owner: getuid()) },
            openContinuityLease: { try .init(anchor: anchor, relativeDirectory: String(continuity.dropFirst(anchor.count + 1)),
                owner: getuid(), excludingDirectory: $0) })
        let pair = try AuthorityJournal(updateHealthStorage: storage, validateSelf: { _ in })
        defer { try? pair.close() }
        return try pair.captureRetainedSetupPolicyBoundary(expected: initial)
    }
    private func stableOperation(_ frame: Frame, preparation: Data? = nil, plan: Data? = nil) throws -> Data {
        let inputs = frame.inputs, runtime = frame.entry.runtime
        let intent: CBORValue
        if let value = inputs.intent {
            let scope = value.scope
            intent = .array([.bytes(scope.macID), .bytes(scope.installationID), .bytes(scope.releaseDigest),
                .bytes(scope.accountID), .unsigned(UInt64(scope.ownerUID)), .bytes(scope.accountBinding),
                .bytes(value.operationID), .bytes(value.proposalDigest), .bytes(try value.recipe.bytes), .unsigned(value.originalPortableVersion)])
        } else { intent = .null }
        let choices = CBORValue.array([.unsigned(inputs.journalPresent ? 1 : 0), intent,
            inputs.relay?.plan.map { .bytes($0.bytes) } ?? .null,
            inputs.relay?.snapshot.map { .bytes($0.digest) } ?? .null])
        return try maintenanceDigest("operation.v2", .array([.unsigned(Window.Purpose.retainedRuntime.rawValue),
            .bytes(try preparation ?? runtime.preparation.bytes), .bytes(try XCTUnwrap(runtime.setup.account?.initialization).bytes),
            .bytes(try plan ?? runtime.plan.encoded), choices]))
    }
    private func maintenanceDigest(_ domain: String, _ value: CBORValue) throws -> Data {
        MachineUpdateActivationRecord.digest(try DeterministicCBOR.encode(.array([.text("remozio.maintenance." + domain), value]),
            limits: .init(maxBytes: 2 * 1024 * 1024, maxDepth: 8, maxItems: 4096)))
    }
    private func changedOperation(_ scope: Window.Scope, operation: Data) throws -> Window.Scope {
        let intent = try maintenanceDigest("administratorIntent.v1", .array([.unsigned(Window.Purpose.retainedRuntime.rawValue),
            .bytes(scope.authority.accountID), .bytes(scope.target.accountID), .bytes(scope.releaseDigest),
            .bytes(scope.candidateDigest), .bytes(operation)]))
        return try .init(macID: scope.macID, installationID: scope.installationID, authority: scope.authority, target: scope.target,
            releaseDigest: scope.releaseDigest, candidateDigest: scope.candidateDigest, authorityPolicyDigest: scope.authorityPolicyDigest,
            operationDigest: operation, restorationDigest: scope.restorationDigest, mutationFootprintDigest: scope.mutationFootprintDigest,
            authorityGrantDigest: scope.authorityGrantDigest, targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: intent)
    }
    func testActualEmptyRuntimeIsOldInEveryPermittedObservationPhase() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(schema29: true) { f in
            let runtime = try f.machine().stableRuntimePreparationSnapshot(owner: f.owner, candidate: f.candidate)
            let s = State(f, runtime: runtime); defer { try? f.machine().close() }
            let frame = try assemblyFrame(s); try prepareObservationFiles(s, frame: frame)
            XCTAssertNil(frame.entry.runtime.state.reference); XCTAssertNil(frame.entry.intent)
            let a = try XCTUnwrap(frame.entry.runtime.setup.source.actual.inventory.accounts.first).accountID
            let selected = try commitments(s, frame: frame, authorityID: a)
            let rows = try runtimeMaintenanceFixtureRows(f.databasePath)
            for phase in [Window.Phase.stopping, .stopped, .executing] {
                XCTAssertEqual(try observe(s, window: window(selected.scope, phase: phase), readPolicy: { try self.initialPair(s) }), .old)
            }
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
            XCTAssertEqual(s.commits, 0); XCTAssertEqual(s.startupOpens, 0)
        }
    }
    private func observeStoppedPolicyStage(_ stop: MachineUpdateRetainedSetupPolicyOwner.Stage) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(schema29: true) { f in
            let s = State(f); defer { try? f.machine().close() }
            let before = try assemblyFrame(s); try prepareObservationFiles(s, frame: before)
            let record = try window(commitments(s, frame: before, authorityID: f.currentAuthorityAccountID).scope)
            let expected = try XCTUnwrap(before.entry.policy)
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPolicyOwner.resume(expected: expected, candidate: f.candidate,
                directory: f.directory, admission: f.admission, useMachine: { try s.withMachine($0) },
                openJournal: { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) }, verifySnapshot: { _ in },
                didStage: { if $0 == stop { throw Fault.policy } })) { XCTAssertEqual($0 as? Fault, .policy) }
            let actual = try assemblyFrame(s), encoded = try XCTUnwrap(actual.entry.intent).encoded
            let rows = try runtimeMaintenanceFixtureRows(f.databasePath), pair = try s.pair()
            s.reset()
            XCTAssertEqual(try observe(s, window: record), .partial)
            XCTAssertEqual(try assemblyFrame(s).entry.intent?.encoded, encoded)
            XCTAssertEqual(try s.pair(), pair); XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
            XCTAssertEqual(s.commits, 0); XCTAssertEqual(s.startupOpens, 0)
        }
    }
    func testPreparedPolicyObservationIsPartialAndDoesNotGenerateARevision() throws { try observeStoppedPolicyStage(.intentRetained) }
    func testWritingPolicyObservationIsPartialAndDoesNotGenerateAReceipt() throws { try observeStoppedPolicyStage(.writingRetained) }
    func testRecordedPolicyObservationIsPartialUntilPublicationCompletes() throws { try observeStoppedPolicyStage(.recorded) }
    func testRealBodyAndAcknowledgementKeepStableBytesAndObserveNewWithoutWrites() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(sharedImportFormats: true, schema29: true) { f in
            let s = State(f); defer { if let files = s.files { try? files.close() }; try? f.machine().close() }
            try s.seedImport(); let before = try assemblyFrame(s)
            try prepareObservationFiles(s, frame: before)
            let selected = try commitments(s, frame: before, authorityID: f.currentAuthorityAccountID)
            let actual = try run(s)
            XCTAssertEqual(s.advanced, [true]); XCTAssertEqual(actual.inputs.intent?.phase, .runtimePublished)
            XCTAssertEqual(try actual.entry.runtime.preparation.bytes, try before.entry.runtime.preparation.bytes)
            XCTAssertEqual(try actual.entry.runtime.setup.account?.initialization?.bytes, try before.entry.runtime.setup.account?.initialization?.bytes)
            XCTAssertEqual(try actual.entry.runtime.plan.encoded, try before.entry.runtime.plan.encoded)
            let after = try commitments(s, frame: actual, authorityID: f.currentAuthorityAccountID)
            XCTAssertEqual(after.scope.operationDigest, selected.scope.operationDigest)
            XCTAssertEqual(after.scope.targetConsentDigest, selected.scope.targetConsentDigest)
            XCTAssertNotEqual(actual.inputs.intent?.revision, before.inputs.intent?.revision)
            let record = try window(selected.scope), bytes = try record.encoded
            let rows = try runtimeMaintenanceFixtureRows(f.databasePath), disk = try inventory(URL(fileURLWithPath: f.databasePath).deletingLastPathComponent().deletingLastPathComponent())
            s.reset()
            XCTAssertEqual(try observe(s, window: record), .new)
            XCTAssertEqual(s.commits, 0); XCTAssertEqual(s.startupOpens, 0); XCTAssertEqual(s.events, [])
            XCTAssertEqual(try record.encoded, bytes)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
            XCTAssertEqual(try inventory(URL(fileURLWithPath: f.databasePath).deletingLastPathComponent().deletingLastPathComponent()), disk)
            // Change stable inputs in the original commitment only. The actual ACK and all observed operands stay valid.
            XCTAssertEqual(try stableOperation(before), selected.scope.operationDigest)
            let prep = before.entry.runtime.preparation
            let changedPreparation = try AccountPreparationIntent(setupID: prep.setupID, revision: AccountPreparationIntent.randomID(),
                macID: prep.macID, installationID: prep.installationID, releaseDigest: prep.releaseDigest, accountID: prep.accountID,
                ownerUID: prep.ownerUID, directoryID: prep.directoryID, policyBytes: prep.policyBytes, initializationBytes: prep.initializationBytes,
                authorityPublicKey: prep.authorityPublicKey, storagePrepared: prep.storagePrepared)
            let changedPlan = try ServiceAccountPlan(account: prep, planID: AccountPreparationIntent.randomID(), claims: before.entry.runtime.plan.claims)
            for operation in [try stableOperation(before, preparation: changedPreparation.bytes), try stableOperation(before, plan: changedPlan.encoded)] {
                XCTAssertNotEqual(operation, selected.scope.operationDigest)
                let wrong = try changedOperation(selected.scope, operation: operation)
                XCTAssertThrowsError(try after.requireImmutableScope(wrong, purpose: .retainedRuntime))
                XCTAssertEqual(try observe(s, window: window(wrong)), .unknown)
            }
        }
    }
    func testRecordedPolicyWithActualPartialFilesIsPartialAndTamperedFilesAreUnknown() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(sharedImportFormats: true, schema29: true) { f in
            let s = State(f); defer { if let files = s.files { try? files.close() }; try? f.machine().close() }
            let before = try assemblyFrame(s); try prepareObservationFiles(s, frame: before)
            let record = try window(commitments(s, frame: before, authorityID: f.currentAuthorityAccountID).scope)
            let completed = try run(s), files = try XCTUnwrap(s.files), artifact = try XCTUnwrap(files.artifacts.last)
            XCTAssertEqual(completed.entry.intent?.phase, .recorded)
            try FileManager.default.removeItem(at: files.url(artifact)); s.reset()
            XCTAssertEqual(try observe(s, window: record), .partial)
            try files.put(artifact, bytes: Data([0]))
            XCTAssertEqual(try observe(s, window: record), .unknown)
            XCTAssertEqual(s.commits, 0); XCTAssertEqual(s.startupOpens, 0)
        }
    }
    func testUnrecordedFilesAndUnprovableReadsNeverObserveNew() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(schema29: true) { f in
            let s = State(f); defer { try? f.machine().close() }
            let before = try assemblyFrame(s); try prepareObservationFiles(s, frame: before)
            XCTAssertNil(before.entry.intent)
            let record = try window(commitments(s, frame: before, authorityID: f.currentAuthorityAccountID).scope)
            XCTAssertEqual(try observe(s, window: record), .partial)
            let path = try RuntimePreparationPaths(accountID: before.entry.runtime.preparation.accountID).policy
            let leaf = try XCTUnwrap(s.observationRoot).appendingPathComponent(RuntimeMaintenanceCommitments.MutationFootprint.relative(path))
            try Data([0]).write(to: leaf); XCTAssertEqual(chmod(leaf.path, 0o600), 0)
            XCTAssertEqual(try observe(s, window: record), .unknown)
            XCTAssertEqual(try observe(s, window: record, refuseRead: true), .unknown)
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
            let frame = try assemblyFrame(s)
            let declaration = try RuntimeMaintenanceCommitments.MutationFootprint(runtime: frame.entry.runtime, inputs: frame.inputs).declaration
            try prepareObservationFiles(s, frame: frame)
            let target = s.initialRuntime.preparation.accountID
            let initial = try XCTUnwrap(s.initialRuntime.setup.account?.initialization)
            let database = s.directory.path + "/installation.sqlite"
            let publicationRoot = try XCTUnwrap(s.observationRoot)
            func logical(_ path: String) throws -> String {
                if path.hasPrefix(publicationRoot.path + "/") { return String(path.dropFirst(publicationRoot.path.count + 1)) }
                for (actual, declared) in [(database, MachineBootstrap.machineDirectory + "/installation.sqlite"),
                    (initial.journalPath, try RuntimePreparationPaths(accountID: target).authorityDirectory + "/Journal/journal.sqlite"),
                    (initial.continuityPath, try RuntimePreparationPaths(accountID: target).authorityDirectory + "/Continuity/continuity.sqlite")] {
                    if path == actual || path == actual + "-journal" {
                        return try RuntimeMaintenanceCommitments.MutationFootprint.relative(declared) + (path == actual ? "" : "-journal")
                    }
                }
                return "outside/" + String(path.dropFirst(root.path.count + 1))
            }
            let excluded = ["runtime_preparation_v1": target, MachineUpdateRetainedSetupPolicyStorage.tableName: target]
            let rows = try runtimeMaintenanceFixtureRows(database, excludingRowsForAccounts: excluded)
            let before = try inventory(root)
            XCTAssertFalse(rows.isEmpty); XCTAssertFalse(before.isEmpty)
            let actual = try run(s)
            XCTAssertTrue(actual.entry.runtime.state.configurationPublished)
            let files = try XCTUnwrap(s.files)
            XCTAssertEqual(files.publicationCalls, 8)
            XCTAssertTrue(files.artifacts.allSatisfy { files.url($0).path.hasPrefix(root.path + "/") })
            let after = try inventory(root), changed = Set(before.keys).union(after.keys).filter { before[$0] != after[$0] }
            XCTAssertFalse(changed.isEmpty)
            for path in changed { XCTAssertTrue(try declaration.containsFile(logical(path)), "Undeclared mutation: \(path)") }
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(database, excludingRowsForAccounts: excluded), rows)
            let outside = try before.filter { try !declaration.containsFile(logical($0.key)) }
            XCTAssertEqual(try after.filter { try !declaration.containsFile(logical($0.key)) }, outside)
            try Data([2, 4, 6]).write(to: sentinel)
            XCTAssertNotEqual(try inventory(root)[sentinel.path], after[sentinel.path])
            XCTAssertFalse(try declaration.containsFile(logical(sentinel.path)))
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
