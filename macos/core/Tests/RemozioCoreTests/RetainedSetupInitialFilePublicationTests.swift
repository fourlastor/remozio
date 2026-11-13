import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned files use the interactive UID, including the modeled transport file. They prove no Root or native service identity.
final class RetainedSetupInitialFilePublicationTests: XCTestCase {
    private typealias Selection = MachineUpdateRetainedSetupInitialSelection
    private typealias Publication = MachineUpdateRetainedSetupInitialPublication
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    private typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    private enum Fault: Error { case stopped }
    private final class SharedScope: @unchecked Sendable {
        let scope: Publication.Scope
        init(_ scope: Publication.Scope) { self.scope = scope }
    }
    private final class Files {
        let root: URL
        let directory: ProtectedSetupDirectory
        let names: [String: AdministrativeSetupPublication.File]
        init(owner: UInt32) throws {
            root = URL(fileURLWithPath: "/private/tmp/remozio-initial-files-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            directory = try .init(anchor: root.path, relativePath: "Shared", owner: getuid(), visibility: .sharedMetadata)
            let files: [AdministrativeSetupPublication.File] = [.elevationPolicy, .commandConfiguration,
                .transportIdentity(ownerUID: getuid(), groupID: getgid()), .transportConfiguration, .gatewaySettingsHost,
                .presenceClient(ownerUID: owner), .pairingClient(ownerUID: owner), .frontendClient(ownerUID: owner)]
            names = Dictionary(uniqueKeysWithValues: files.map { ($0.name, $0) })
        }
        func close() throws { directory.close(); try FileManager.default.removeItem(at: root) }
        func file(_ artifact: Artifact) throws -> AdministrativeSetupPublication.File {
            try XCTUnwrap(names[URL(fileURLWithPath: artifact.path).lastPathComponent])
        }
        func url(_ artifact: Artifact) throws -> URL {
            URL(fileURLWithPath: directory.path).appendingPathComponent(try file(artifact).name)
        }
        func read(_ artifact: Artifact) throws -> Data? {
            let file = try file(artifact)
            guard try ProtectedServiceConfiguration.readOptional(anchor: directory.path, relativePath: file.name, owner: getuid()) != nil else { return nil }
            return try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
                owner: getuid(), privateFile: file.mode == 0o600)
        }
        func publish(_ artifact: Artifact, verify: () throws -> Void = {}) throws -> AdministrativeSetupPublicationResult {
            try AdministrativeSetupPublication.publish(artifact.bytes, file: file(artifact), directory: directory,
                owner: getuid(), verify: verify)
        }
        func stamp(_ artifact: Artifact) throws -> [UInt64] {
            var value = stat(); guard lstat(try url(artifact).path, &value) == 0 else { throw JournalLeaseError.system(errno) }
            return [UInt64(value.st_ino), UInt64(value.st_mtimespec.tv_sec), UInt64(value.st_mtimespec.tv_nsec),
                UInt64(value.st_ctimespec.tv_sec), UInt64(value.st_ctimespec.tv_nsec)]
        }
    }
    private final class State {
        var bytes: [String: Data] = [:]
        var files: Files?
        var created = 0, publishCalls = 0, materialReads = 0, pairReads = 0, artifactReads = 0
        var fullReads = 0, callbackDepth = 0, borrowedCallbacks = 0, c1SnapshotReads = 0
        var stopAfterCreated: Int?, corruptReadback = false, didPublish = false
        var materialReader: ((Int) throws -> RuntimePreparationMaterial)?
        var afterFile: ((Int) throws -> Void)?
        var pairReader: ((Int) throws -> Boundary)?
        var scope: Publication.Scope?
        func read(_ artifact: Artifact) throws -> Data? {
            artifactReads += 1
            if corruptReadback && didPublish { return Data([0]) }
            if let files { return try files.read(artifact) }
            return bytes[artifact.path]
        }
        func borrowed<Result>(_ scope: Publication.Scope, _ body: () throws -> Result) throws -> Result {
            callbackDepth += 1; borrowedCallbacks += 1; defer { callbackDepth -= 1 }
            return try scope.withActive(body)
        }
        func publish(_ scope: Publication.Scope) throws {
            publishCalls += 1
            let artifact = try XCTUnwrap(scope.artifact)
            try scope.requireActive()
            let result: AdministrativeSetupPublicationResult
            if let files { result = try files.publish(artifact, verify: scope.requireActive) }
            else if let previous = bytes[artifact.path] {
                guard previous == artifact.bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
                result = .retained
            } else { bytes[artifact.path] = artifact.bytes; result = .created }
            if result == .created { created += 1 }
            didPublish = true; try afterFile?(created)
            if created == stopAfterCreated { throw Fault.stopped }
            try scope.requireActive()
        }
    }
    private func fixture(seed: (Fixture) throws -> Void = { _ in },
        _ body: (Fixture, Snapshot, Boundary) throws -> Void) throws {
        try RetainedSetupInitialPublicationWriterTests.withRecordedInitialSelectionFixture(seed: seed, body: body)
    }
    private func withSelection<Result>(_ f: Fixture, _ snapshot: Snapshot, _ current: Boundary, state: State? = nil,
        body: (Selection, Selection.Scope) throws -> Result) throws -> Result {
        try Selection.withCurrent(machine: f.machine(), expected: snapshot, candidate: f.candidate,
            recordedStartupPolicy: current.policy.policy, readPolicyBoundary: {
                let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
                let actual = try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(snapshot.activation.runtime.setup.account?.initialization))
                if let state { state.pairReads += 1; return try state.pairReader?(state.pairReads) ?? actual }
                return actual
            }, verifyCurrent: { _ in state?.c1SnapshotReads += 1; if let state { XCTAssertEqual(state.callbackDepth, 0) } }, body: body)
    }
    private func artifacts(_ f: Fixture, _ snapshot: Snapshot, _ current: Boundary) throws -> [Artifact] {
        try withSelection(f, snapshot, current) { selection, _ in
            try RuntimePublishedArtifactValidation.artifacts(bundle: selection.configuration.bundle, material: f.material)
        }
    }
    private func prepare(_ f: Fixture, _ snapshot: Snapshot, _ current: Boundary, state: State,
        custody: Bool = true, verify: @escaping (Snapshot) throws -> Void = { _ in },
        didStage: @escaping (RuntimePublicationController.Stage) throws -> Void = { _ in },
        inspect: @escaping (Publication.Scope) throws -> Void = { _ in }) throws -> Selection {
        try Publication.prepare(withSelection: { body in
            try self.withSelection(f, snapshot, current, state: state, body: body)
        },
            machine: f.machine(), expected: snapshot, candidate: f.candidate,
            directory: f.directory, admission: f.admission, fileCustodyAccepted: custody,
            verifyCurrent: { actual in
                state.fullReads += 1; XCTAssertEqual(state.callbackDepth, 0); try verify(actual)
            }, verifyServices: { XCTAssertEqual($0, snapshot.activation.runtime.plan) },
            readMaterial: { scope in try state.borrowed(scope) {
                state.materialReads += 1
                return try state.materialReader?(state.materialReads) ?? f.material
            } }, verifyActivity: { activity, scope in try state.borrowed(scope) {
                XCTAssertEqual(activity, f.material.serviceActivity); try scope.requireActive()
            } }, readArtifact: { artifact, scope in try state.borrowed(scope) { try state.read(artifact) } },
            publish: { scope in try state.borrowed(scope) { try state.publish(scope) } }, didStage: didStage,
            inspectScope: { scope in state.scope = scope; try inspect(scope) })
    }
    private func seed(_ f: Fixture) throws {
        let runtime = f.source.runtime, account = runtime.preparation
        let inventory = try runtime.setup.source.provisioningInventory(accountID: account.accountID,
            ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
        let presence = try PresenceConfiguration(idleMilliseconds: 123000, observationLifetimeMilliseconds: 9000,
            unavailableGraceMilliseconds: 41000)
        let cloud = try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32),
            zoneID: String(repeating: "b", count: 32), dnsSuffix: "owned.example", apiToken: "synthetic-only")
        let proposal = PortableSetup(defaults: try .init(presence: presence, gateway: GatewaySetupForm().settingsSelection()), cloudflare: cloud)
        let intent = try SharedSetupImportIntent(scope: .init(account: account, inventory: inventory), proposal: proposal)
        let machine = URL(fileURLWithPath: f.directory.path), anchor = machine.deletingLastPathComponent().path
        let relative = machine.lastPathComponent + "/SharedSetupImport"
        let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: relative, owner: getuid())
        defer { directory.close() }
        _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .sharedSetupImport, owner: getuid())
        let journal = try SharedSetupImportJournal(lease: .init(anchor: anchor, relativeDirectory: relative,
            owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(),
            macID: account.macID, installationID: account.installationID, initialize: true)
        defer { try? journal.close() }; try journal.begin(intent)
        let relay = try SharedSetupImportRelayPlan(expected: intent, port: 45678)
        _ = try AdministrativeSetupPublication.publish(relay.bytes, file: .importRelayPlan(accountID: account.accountID),
            directory: directory, owner: getuid())
    }

    func testAllEightRecordedArtifactsAndAccessKindsLeaveTheSQLBitUnchanged() throws {
        try fixture { f, snapshot, current in
            let state = State(); var stages: [RuntimePublicationController.Stage] = []
            let selected = try prepare(f, snapshot, current, state: state, didStage: { stages.append($0) })
            let expected = try RuntimePublishedArtifactValidation.artifacts(bundle: selected.configuration.bundle, material: f.material)
            XCTAssertEqual(expected.count, 8); XCTAssertEqual(state.created, 8); XCTAssertEqual(state.publishCalls, 8)
            XCTAssertEqual(stages, [.materialRestored, .filesPublished]); XCTAssertGreaterThanOrEqual(state.materialReads, 2)
            XCTAssertEqual(expected.filter { $0.access == .privateRoot }.count, 2)
            XCTAssertEqual(expected.filter { $0.access == .publicRoot }.count, 5)
            XCTAssertEqual(expected.filter { if case .servicePrivate = $0.access { return true }; return false }.count, 1)
            for artifact in expected { XCTAssertEqual(state.bytes[artifact.path], artifact.bytes) }
            XCTAssertFalse(expected.contains { $0.path.hasSuffix("/command-host.cbor") || $0.path.hasSuffix(".plist") })
            XCTAssertFalse(try f.machine().retainedSetupPolicySnapshot(owner: snapshot.activation.runtime.setup.owner,
                candidate: f.candidate).activation.runtime.state.configurationPublished)
        }
    }

    func testPartialOwnedPublicationKeepsExactInodesAndCreatesOnlyMissingFiles() throws {
        try fixture { f, snapshot, current in
            let state = State(), files = try Files(owner: snapshot.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; state.files = files
            let expected = try artifacts(f, snapshot, current), retained = Array(expected.prefix(3))
            for artifact in retained { XCTAssertEqual(try files.publish(artifact), .created) }
            let stamps = try retained.map { try files.stamp($0) }
            _ = try prepare(f, snapshot, current, state: state)
            XCTAssertEqual(state.created, 5)
            for (index, artifact) in retained.enumerated() { XCTAssertEqual(try files.stamp(artifact), stamps[index]) }
            for artifact in expected { XCTAssertEqual(try files.read(artifact), artifact.bytes) }
        }
    }

    func testAConflictingLastFileRefusesBeforePublishingOrTouchingAnyOtherFile() throws {
        try fixture { f, snapshot, current in
            let state = State(), files = try Files(owner: snapshot.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; state.files = files
            let expected = try artifacts(f, snapshot, current), first = expected[0], last = try XCTUnwrap(expected.last)
            _ = try files.publish(first)
            _ = try AdministrativeSetupPublication.publish(Data([0]), file: files.file(last), directory: files.directory, owner: getuid())
            let before = try [files.stamp(first), files.stamp(last)]
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state)) {
                XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
            }
            XCTAssertEqual(state.publishCalls, 0); XCTAssertEqual(state.created, 0)
            XCTAssertEqual(try files.stamp(first), before[0]); XCTAssertEqual(try files.stamp(last), before[1])
            for artifact in expected.dropFirst().dropLast() { XCTAssertNil(try files.read(artifact)) }
        }
    }

    func testEveryRetryByteComesFromTheSameRecordedMaterialAndKeepsClientTunables() throws {
        try fixture(seed: seed) { f, snapshot, current in
            let state = State(), presence = try PresenceConfiguration(idleMilliseconds: 123000,
                observationLifetimeMilliseconds: 9000, unavailableGraceMilliseconds: 41000)
            let first = try prepare(f, snapshot, current, state: state)
            let bytes = state.bytes
            let second = try prepare(f, snapshot, current, state: state)
            XCTAssertEqual(first.digest, second.digest); XCTAssertEqual(state.bytes, bytes); XCTAssertEqual(state.created, 8)
            XCTAssertEqual(first.configuration.bundle.command.presence.presence.policy.idleMilliseconds, presence.idleMilliseconds)
            XCTAssertEqual(first.configuration.bundle.command.presence.presence.policy.observationLifetimeMilliseconds, presence.observationLifetimeMilliseconds)
            XCTAssertEqual(first.configuration.bundle.command.presence.presence.policy.unavailableGraceMilliseconds, presence.unavailableGraceMilliseconds)
            XCTAssertEqual(first.configuration.bundle.transport.relayPort, 45678)
            for artifact in try RuntimePublishedArtifactValidation.artifacts(bundle: second.configuration.bundle, material: f.material) {
                XCTAssertEqual(state.bytes[artifact.path], artifact.bytes)
            }
        }
    }

    func testPreparedWritingAndMissingCustodyCannotReachMaterialOrArtifactReads() throws {
        try fixture { f, snapshot, current in
            let original = try XCTUnwrap(snapshot.intent)
            for phase in [MachineUpdateRetainedSetupPolicyIntentRecord.Phase.prepared, .writing] {
                var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: original.encoded) as? [String: Any])
                fields["phase"] = phase.rawValue; fields["committedPolicy"] = nil; fields["committedCheckpoint"] = nil
                let record = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
                let proposed = try Snapshot(activation: snapshot.activation, intent: record, candidate: f.candidate), state = State()
                XCTAssertThrowsError(try prepare(f, proposed, current, state: state)) { XCTAssertEqual($0 as? RuntimeActivationError, .incomplete) }
                XCTAssertEqual(state.materialReads, 0); XCTAssertEqual(state.artifactReads, 0); XCTAssertEqual(state.publishCalls, 0)
            }
            let state = State()
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state, custody: false)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
            }
            XCTAssertEqual(state.pairReads, 0); XCTAssertEqual(state.materialReads, 0)
        }
    }

    func testChangedPairAndMaterialBeforeWritingRefusePublication() throws {
        try fixture { f, snapshot, current in
            let state = State()
            let changed = Boundary(macID: current.macID, accountID: current.accountID,
                policy: .init(revision: UUID(), policy: current.policy.policy, roleRevisions: current.policy.roleRevisions),
                checkpoint: current.checkpoint)
            state.pairReader = { $0 == 1 ? current : changed }
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            XCTAssertEqual(state.publishCalls, 0); XCTAssertEqual(state.artifactReads, 0)
            let material = f.material
            let foreign = try RuntimePreparationMaterial(materialID: AccountPreparationIntent.randomID(), services: material.services,
                transportIdentity: material.transportIdentity, transportPublicKeyInfo: material.transportPublicKeyInfo,
                gateway: material.gateway, serviceActivity: material.serviceActivity, auditDeliveryVersion: material.auditDeliveryVersion)
            let next = State(); next.materialReader = { $0 == 1 ? material : foreign }
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: next)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertGreaterThanOrEqual(next.materialReads, 2); XCTAssertEqual(next.publishCalls, 0); XCTAssertEqual(next.artifactReads, 8)
        }
    }

    func testAnInterruptedOwnedPublicationRequiresAFreshInvocationAndKeepsTheExistingFiles() throws {
        try fixture { f, snapshot, current in
            let state = State(), files = try Files(owner: snapshot.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; state.files = files; state.stopAfterCreated = 3
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state)) { XCTAssertTrue($0 is Fault) }
            let retained = Array(try artifacts(f, snapshot, current).prefix(3)), stamps = try retained.map { try files.stamp($0) }
            XCTAssertThrowsError(try XCTUnwrap(state.scope).requireActive()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            state.stopAfterCreated = nil
            _ = try prepare(f, snapshot, current, state: state); XCTAssertEqual(state.created, 8)
            for (index, artifact) in retained.enumerated() { XCTAssertEqual(try files.stamp(artifact), stamps[index]) }
        }
    }

    func testReadbackMustMatchEveryPublishedByteAndFailureExpiresItsScope() throws {
        try fixture { f, snapshot, current in
            let state = State(); state.corruptReadback = true
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state)) {
                XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
            }
            XCTAssertEqual(state.created, 1)
            XCTAssertThrowsError(try XCTUnwrap(state.scope).requireActive()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            state.corruptReadback = false
            _ = try prepare(f, snapshot, current, state: state); XCTAssertEqual(state.created, 8)
        }
    }

    func testVerificationLoansExpireOnReturnAndOnCallbackFailure() throws {
        try fixture { f, snapshot, current in
            let state = State(); _ = try prepare(f, snapshot, current, state: state)
            XCTAssertThrowsError(try XCTUnwrap(state.scope).requireActive()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            let failed = State()
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: failed, didStage: { _ in throw Fault.stopped })) { XCTAssertTrue($0 is Fault) }
            XCTAssertThrowsError(try XCTUnwrap(failed.scope).requireActive()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testRecursiveVerificationPoisonsTheInvocationAndAnotherThreadCannotReadTheScope() throws {
        try fixture { f, snapshot, current in
            let state = State()
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state, inspect: { scope in
                try scope.withActive {
                    XCTAssertThrowsError(try scope.withActive {}) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                }
            })) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertEqual(state.materialReads, 0)
            let next = State()
            _ = try prepare(f, snapshot, current, state: next, inspect: { scope in
                let shared = SharedScope(scope), rejected = Mutex(false), done = DispatchSemaphore(value: 0)
                DispatchQueue.global().async {
                    defer { done.signal() }
                    do { try shared.scope.requireActive() } catch { rejected.withLock { $0 = error as? JournalLeaseError == .invalidated } }
                }
                XCTAssertEqual(done.wait(timeout: .now() + 5), .success); XCTAssertTrue(rejected.withLock { $0 })
                try scope.requireActive()
            })
        }
    }

    func testSymlinkAndWrongPrivateModeRefuseBeforePublication() throws {
        try fixture { f, snapshot, current in
            let state = State(), files = try Files(owner: snapshot.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; state.files = files
            let first = try XCTUnwrap(artifacts(f, snapshot, current).first), path = try files.url(first)
            _ = try files.publish(first); XCTAssertEqual(chmod(path.path, 0o644), 0)
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state)); XCTAssertEqual(state.publishCalls, 0)
            XCTAssertEqual(chmod(path.path, 0o600), 0)
            let target = files.root.appendingPathComponent("owned-target"); try Data([1, 2, 3]).write(to: target)
            try FileManager.default.removeItem(at: path); try FileManager.default.createSymbolicLink(at: path, withDestinationURL: target)
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state)); XCTAssertEqual(state.publishCalls, 0)
            XCTAssertEqual(try Data(contentsOf: target), Data([1, 2, 3]))
        }
    }

    func testTheFixedNativeWrapperRequiresRootBeforeItsVerifierOrFileAccess() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Owned fixture requires an ordinary user") }
        try fixture { f, snapshot, current in
            var called = false
            _ = try prepare(f, snapshot, current, state: State(), inspect: { scope in
                XCTAssertThrowsError(try RuntimePublicationController.publishRetainedInitialNative(scope,
                    verifyCurrent: { called = true })) {
                    XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                }
            })
            XCTAssertFalse(called)
        }
    }

    func testChangedMaterialAfterTheFirstFileStopsBeforeTheSecondFile() throws {
        try fixture { f, snapshot, current in
            let state = State(), material = f.material
            let foreign = try RuntimePreparationMaterial(materialID: AccountPreparationIntent.randomID(), services: material.services,
                transportIdentity: material.transportIdentity, transportPublicKeyInfo: material.transportPublicKeyInfo,
                gateway: material.gateway, serviceActivity: material.serviceActivity, auditDeliveryVersion: material.auditDeliveryVersion)
            state.materialReader = { _ in state.created == 0 ? material : foreign }
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertEqual(state.created, 1); XCTAssertEqual(state.bytes.count, 1)
            XCTAssertThrowsError(try XCTUnwrap(state.scope).requireActive()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }
    func testChangedPairAfterTheFirstFileStopsBeforeTheSecondFile() throws {
        try fixture { f, snapshot, current in
            let state = State()
            let changed = Boundary(macID: current.macID, accountID: current.accountID,
                policy: .init(revision: UUID(), policy: current.policy.policy, roleRevisions: current.policy.roleRevisions),
                checkpoint: current.checkpoint)
            state.pairReader = { _ in state.created == 0 ? current : changed }
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(state.created, 1); XCTAssertEqual(state.bytes.count, 1)
        }
    }

    func testChangedActualRelayAfterTheFirstFileStopsBeforeTheSecondFile() throws {
        try fixture(seed: seed) { f, snapshot, current in
            let state = State()
            let name = AdministrativeSetupPublication.File.importRelayPlan(accountID: snapshot.activation.runtime.preparation.accountID).name
            let path = f.directory.path + "/SharedSetupImport/" + name
            let original = try Data(contentsOf: URL(fileURLWithPath: path))
            let imported = try withSelection(f, snapshot, current) { selected, _ in try XCTUnwrap(selected.inputs.intent) }
            func replace(_ bytes: Data) throws {
                let fd = Darwin.open(path, O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }; defer { Darwin.close(fd) }
                var offset = 0
                while offset < bytes.count {
                    let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw Fault.stopped }; offset += count
                }
                guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
            }
            defer { XCTAssertNoThrow(try replace(original)) }
            state.afterFile = { count in
                if count == 1 {
                    let changed = try SharedSetupImportRelayPlan(expected: imported, port: 45679)
                    try replace(changed.bytes)
                }
            }
            XCTAssertThrowsError(try prepare(f, snapshot, current, state: state))
            XCTAssertEqual(state.created, 1); XCTAssertEqual(state.bytes.count, 1)
            XCTAssertThrowsError(try XCTUnwrap(state.scope).requireActive()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testOwnerReadsTheSnapshotEighteenTimesAndBorrowedCallbacksMakeNoFullRead() throws {
        try fixture { f, snapshot, current in
            let state = State()
            _ = try prepare(f, snapshot, current, state: state, inspect: { scope in
                let before = state.fullReads
                try scope.requireActive(); try scope.withActive { try scope.requireActive() }
                XCTAssertEqual(state.fullReads, before)
            })
            XCTAssertEqual(state.created, 8); XCTAssertEqual(state.publishCalls, 8)
            XCTAssertEqual(state.fullReads, 2 * 8 + 2); XCTAssertLessThanOrEqual(state.fullReads, 18)
            XCTAssertEqual(state.materialReads, 18)
            XCTAssertEqual(state.c1SnapshotReads, 2 * (18 + 3))
            XCTAssertEqual(state.pairReads, 1 + state.c1SnapshotReads)
            XCTAssertGreaterThan(state.borrowedCallbacks, 0); XCTAssertEqual(state.callbackDepth, 0)
        }
    }
}
