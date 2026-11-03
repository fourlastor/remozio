import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned SQLite and synthetic role identities only. Native collector and platform custody remain unqualified.
final class RuntimeAuditUpgradeCollectorTests: XCTestCase {
    private struct InvalidOwner: Error {}
    final class Fixture {
        let files: RuntimeAuditUpgradeArtifactTests.Fixture
        var record: RuntimeAuditUpgradeRecord
        var ownerValid = true
        var platformValid = true
        init(imported: RuntimeAuditUpgradeImportTests.Fixture? = nil, registered: Bool = true) throws {
            files = try .init(imported: imported)
            let f = files.f, source = files.preparation.source
            try f.machine.retainRuntimeActivation(source)
            _ = try f.machine.enrollRuntimeActivation(source)
            if registered { try f.machine.markRuntimeJobsRegistered(source) }
            record = try f.machine.retainRuntimeAuditUpgrade(files.preparation.intent, currentPolicy: source.host.codePolicy,
                installedRelease: XCTUnwrap(f.nativeRelease))
            let graph = try files.plan(imported: imported?.capture(), transport: imported?.source.runCredential?.reference)
            try files.install(graph)
        }
        func gateway(pending: Bool = false) throws -> RuntimeAuditUpgradeArtifactPlan.GatewayInputs {
            let source = try files.gateway(), machine = files.f.machine
            let material = try XCTUnwrap(source.material), intent = try XCTUnwrap(source.journal.intent)
            let activation = try XCTUnwrap(source.activation.plan)
            try machine.retainGatewayMaterial(material.reference)
            try machine.retainGatewayJournalIntent(intent)
            _ = try machine.completeGatewayJournalInitialization(intent,
                head: .init(registration: intent.configuration.registration, revision: 0, receipt: nil))
            try machine.retainGatewayRuntimeActivation(activation)
            try machine.markGatewayRuntimePublished(activation)
            _ = try machine.enrollGatewayRuntimeActivation(activation)
            try machine.markGatewayRuntimeRegistered(activation)
            try files.install(files.plan(gateway: source))
            if pending {
                let revision = try GatewayRuntimeSettingsRevision(id: Data(repeating: 31, count: 16),
                    selection: GatewaySetupForm().settingsSelection(), activation: activation, previous: nil,
                    journal: source.journal, foreground: files.preparation.source, inventory: XCTUnwrap(machine.inventory()))
                try machine.retainGatewaySettingsTransition(revision)
                try machine.markGatewaySettingsTransition(revision, phase: .quiesced)
                let publication = try GatewayRuntimeSettingsPublicationPlan(revision: revision, previous: nil, activation: activation,
                    journal: source.journal, foreground: files.preparation.source, inventory: XCTUnwrap(machine.inventory()))
                for artifact in publication.artifacts where artifact.file.name == "transport-gateway-runtime.cbor" {
                    try files.write(artifact.selected, files.entry(artifact.file.name, files.plan(gateway: source)))
                }
                let fence = try GatewayRuntimeSettingsFence(publication)
                try files.write(fence.encoded, files.entry("gateway-settings-fence.cbor", files.plan(gateway: source)))
                return .init(material: source.material, reference: source.reference, journal: source.journal, activation: source.activation,
                    settings: .init(active: nil, pending: revision, phase: .quiesced), service: source.service, fence: fence)
            }
            return source
        }
        func scope() throws -> RuntimeAuditUpgradeCaptureScope {
            try .captureOwned(machine: files.f.machine, expected: record, installedRelease: XCTUnwrap(files.f.nativeRelease),
                currentPolicy: files.preparation.source.host.codePolicy, owner: getuid(),
                verifyOwner: { guard self.ownerValid else { throw InvalidOwner() } },
                verifyPlatform: { account, activity in
                    guard self.platformValid, account == self.files.f.account,
                          activity == self.record.intent.target.serviceActivity else { throw InvalidOwner() }
                })
        }
        func collect(_ scope: RuntimeAuditUpgradeCaptureScope,
                     journal: () throws -> GatewayJournalFileIdentity? = { nil }) throws -> RuntimeAuditUpgradeCollector.Result {
            try RuntimeAuditUpgradeCollector.captureOwned(scope: scope, directories: files.directories, owner: getuid(), observeJournal: journal)
        }
    }
    func testCollectorUsesTheActualRetainedMachineStateAndLeavesItUnchanged() throws {
        let f = try Fixture(), before = try f.files.f.machine.retainedRuntimeCompatibilityInputs(), scope = try f.scope()
        let result = try f.collect(scope)
        XCTAssertEqual(result.artifacts.plan.sourceAccount, f.files.f.account)
        XCTAssertEqual(result.artifacts.plan.sourceInventory, try f.files.f.machine.inventory())
        XCTAssertEqual(result.artifacts.plan.preparation.intent, f.record.intent)
        XCTAssertEqual(result.artifacts.plan.preparation.target.reference, f.record.intent.target)
        XCTAssertNil(result.gatewayJournalIdentity)
        XCTAssertEqual(try f.files.f.machine.retainedRuntimeCompatibilityInputs(), before)
        XCTAssertEqual(String(reflecting: result), "RuntimeAuditUpgradeCollector.Result(redacted)")
        XCTAssertEqual(Mirror(reflecting: result).children.count, 0)
        XCTAssertEqual(Mirror(reflecting: scope).children.count, 0)
    }
    func testPendingForegroundPublicationRetainsMissingHostAndJobs() throws {
        let f = try Fixture(registered: false)
        for entry in try f.files.plan().entries {
            if entry.file.name == "command-host.cbor" || entry.directory == .jobs {
                let path = try XCTUnwrap(f.files.directories[entry.directory]).path + "/" + entry.file.name
                if FileManager.default.fileExists(atPath: path) { XCTAssertEqual(unlink(path), 0) }
            }
        }
        let scope = try f.scope(), result = try f.collect(scope)
        XCTAssertFalse(result.artifacts.plan.sourceJobsRegistered)
        for leaf in result.artifacts.leaves where leaf.entry.file.name == "command-host.cbor" || leaf.entry.directory == .jobs {
            XCTAssertNil(leaf.source); XCTAssertNil(leaf.target)
        }
        XCTAssertFalse(try f.files.f.machine.runtimeActivation(accountID: f.files.f.account.accountID).jobsRegistered)
    }
    func testClosedScopeCannotReadAndDoesNotCloseTheBorrowedStore() throws {
        let f = try Fixture(), scope = try f.scope(); scope.close()
        XCTAssertThrowsError(try f.collect(scope)); XCTAssertThrowsError(try scope.validateLifetime())
        XCTAssertNotNil(try f.files.f.machine.inventory())
    }
    func testClosingTheActualMachineLeaseInvalidatesCapture() throws {
        let f = try Fixture(), scope = try f.scope(); try f.files.f.machine.close()
        XCTAssertThrowsError(try scope.validateLifetime()); XCTAssertThrowsError(try f.collect(scope))
    }
    func testOwnerAndPlatformChecksFailBeforeReturningAnObservation() throws {
        for platform in [false, true] {
            let f = try Fixture(), scope = try f.scope()
            if platform { f.platformValid = false } else { f.ownerValid = false }
            XCTAssertThrowsError(try f.collect(scope))
            XCTAssertThrowsError(try scope.validateCurrent())
        }
    }
    func testChangedInventoryOrUpgradeRevisionCannotMatchTheSourceScope() throws {
        for marker in [false, true] {
            let f = try Fixture(), scope = try f.scope()
            if marker {
                _ = try f.files.f.machine.markRuntimeAuditMaterialStaged(f.record,
                    currentPolicy: f.files.preparation.source.host.codePolicy, installedRelease: XCTUnwrap(f.files.f.nativeRelease))
            } else {
                let before = try XCTUnwrap(f.files.f.machine.inventory())
                _ = try f.files.f.machine.writeInventory(before, expectedRevision: before.revision)
            }
            XCTAssertThrowsError(try f.collect(scope)); XCTAssertThrowsError(try scope.validateCurrent())
        }
    }
    func testCollectorBindsTheRealImportJournalAndItsProviderLeaves() throws {
        let imported = try RuntimeAuditUpgradeImportTests.Fixture(), f = try Fixture(imported: imported), scope = try f.scope()
        let result = try f.collect(scope)
        XCTAssertEqual(result.artifacts.plan.sourceImport?.intent, imported.expected)
        XCTAssertEqual(result.artifacts.plan.sourceImport?.source, scope.importRecord)
        XCTAssertEqual(result.artifacts.plan.sourceImport?.targetReference?.runtime, f.record.intent.target)
        try imported.runtime.machine.withSharedImportJournal { journal in
            _ = try XCTUnwrap(journal).advance(imported.expected, to: .gatewayPrepared)
        }
        XCTAssertThrowsError(try f.collect(scope))
    }
    func testChangedPrivateMaterialAndUnsafeClientFilesCannotBeAdopted() throws {
        for client in [false, true] {
            let f = try Fixture(), scope = try f.scope()
            if client {
                let entry = try XCTUnwrap(f.files.plan().entries.first { $0.directory == .clients })
                let path = try XCTUnwrap(f.files.directories[entry.directory]).path + "/" + entry.file.name
                XCTAssertEqual(chmod(path, 0o600), 0)
            } else {
                let entry = try f.files.entry("runtime-material.cbor", f.files.plan())
                try f.files.write(Data("invalid private fixture".utf8), entry)
            }
            XCTAssertThrowsError(try f.collect(scope))
        }
    }
    func testGatewayJournalIdentityChangesDuringCaptureAreRejected() throws {
        let f = try Fixture(), scope = try f.scope(); var calls = 0
        let first = GatewayJournalFileIdentity(directory: .init(device: 1, inode: 100),
            writer: .init(device: 1, inode: 101), database: .init(device: 1, inode: 102))
        XCTAssertThrowsError(try f.collect(scope) {
            calls += 1
            return calls == 1 ? first : nil
        })
        XCTAssertEqual(calls, 2)
    }
    func testActualGatewayRowsAndMixedPendingFilesKeepTheirSelectedVariants() throws {
        let f = try Fixture(), gateway = try f.gateway(pending: true), scope = try f.scope()
        let before = try f.files.f.machine.retainedRuntimeCompatibilityInputs()
        let result = try f.collect(scope, journal: { gateway.journal.intent?.files })
        XCTAssertEqual(result.gatewayJournalIdentity, gateway.journal.intent?.files)
        XCTAssertEqual(result.artifacts.plan.sourceGateway.journal, gateway.journal)
        XCTAssertEqual(result.artifacts.plan.gateway.service?.maximumLifetimeMilliseconds, 45678)
        XCTAssertEqual(result.artifacts.plan.gateway.settings.phase, .quiesced)
        XCTAssertEqual(result.artifacts.plan.gateway.settings.pending?.id, gateway.settings.pending?.id)
        let revision = try XCTUnwrap(result.artifacts.leaves.first { $0.entry.file.name == "gateway-settings-revision.cbor" })
        XCTAssertNil(revision.source); XCTAssertNil(revision.target)
        let transport = try XCTUnwrap(result.artifacts.leaves.first { $0.entry.file.name == "transport-gateway-runtime.cbor" })
        XCTAssertEqual(try GatewayRuntimeExtension.decode(XCTUnwrap(transport.target)).material.runtime, f.record.intent.target)
        XCTAssertNotNil(result.artifacts.plan.gateway.fence)
        XCTAssertEqual(try f.files.f.machine.retainedRuntimeCompatibilityInputs(), before)
    }
    func testGatewayPhaseChangeDuringReadsCannotReturnACurrentSnapshot() throws {
        let f = try Fixture(), gateway = try f.gateway(pending: true), scope = try f.scope()
        let pending = try XCTUnwrap(gateway.settings.pending); var changed = false
        XCTAssertThrowsError(try f.collect(scope, journal: {
            if !changed {
                changed = true
                try f.files.f.machine.markGatewaySettingsTransition(pending, phase: .filesPublished)
            }
            return gateway.journal.intent?.files
        }))
        XCTAssertTrue(changed); XCTAssertThrowsError(try scope.validateCurrent())
        XCTAssertEqual(try f.files.f.machine.gatewaySettingsTransition(accountID: f.files.f.account.accountID).phase, .filesPublished)
    }
    func testNativeEntryPointsRefuseBeforeOwnerCallbacksOrScopeReads() throws {
        let f = try Fixture(), scope = try f.scope(); var calls = 0
        XCTAssertThrowsError(try RuntimeAuditUpgradeCaptureScope.capture(machine: f.files.f.machine, expected: f.record,
            installedRelease: XCTUnwrap(f.files.f.nativeRelease), currentPolicy: f.files.preparation.source.host.codePolicy,
            verifyOwner: { calls += 1 })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try RuntimeAuditUpgradeCollector.capture(scope: scope)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertEqual(calls, 0)
    }
    func testJournalObserverRejectsInvalidServiceIdentitiesBeforeCallbacks() throws {
        let f = try Fixture(), parent = try XCTUnwrap(f.files.directories[.services])
        var calls = 0
        let identities: [(uid_t, gid_t)] = [(0, getgid()), (UInt32.max, getgid()), (getuid(), 0), (getuid(), UInt32.max)]
        for (uid, gid) in identities {
            XCTAssertThrowsError(try GatewayJournalFileProvisioning.observe(parent: parent, processOwner: getuid(),
                serviceUID: uid, serviceGID: gid, expected: nil, verifyCurrent: { calls += 1 })) {
                XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
            }
        }
        XCTAssertEqual(calls, 0)
    }
    func testJournalObserverRequiresTheRetainedDirectoryWithoutCreatingIt() throws {
        let f = try Fixture(), parent = try XCTUnwrap(f.files.directories[.services])
        let expected = GatewayJournalFileIdentity(directory: .init(device: 1, inode: 100),
            writer: .init(device: 1, inode: 101), database: .init(device: 1, inode: 102))
        XCTAssertThrowsError(try GatewayJournalFileProvisioning.observe(parent: parent, processOwner: getuid(),
            serviceUID: getuid(), serviceGID: getgid(), expected: expected, verifyCurrent: {})) {
            XCTAssertEqual($0 as? GatewayPreparationError, .missingMaterial)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: parent.path + "/Gateway"))
    }
    func testJournalObserverTakesNoWriterLockAndNeverCreatesMissingFiles() throws {
        let f = try Fixture(), parent = try XCTUnwrap(f.files.directories[.services])
        XCTAssertNil(try GatewayJournalFileProvisioning.observe(parent: parent, processOwner: getuid(), serviceUID: getuid(),
            serviceGID: getgid(), expected: nil, verifyCurrent: {}))
        XCTAssertFalse(FileManager.default.fileExists(atPath: parent.path + "/Gateway"))
        let created = try GatewayJournalFileProvisioning.prepare(parent: parent, processOwner: getuid(), serviceUID: getuid(),
            serviceGID: getgid(), mode: .createIfAbsent, expected: nil, verifyCurrent: {})
        let writer = open(parent.path + "/Gateway/writer.lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(writer, 0); defer { _ = Darwin.close(writer) }
        XCTAssertEqual(flock(writer, LOCK_EX | LOCK_NB), 0)
        XCTAssertEqual(try GatewayJournalFileProvisioning.observe(parent: parent, processOwner: getuid(), serviceUID: getuid(),
            serviceGID: getgid(), expected: created.identity, verifyCurrent: {}), created.identity)
        let rival = open(parent.path + "/Gateway/writer.lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(rival, 0); defer { _ = Darwin.close(rival) }
        XCTAssertEqual(flock(rival, LOCK_EX | LOCK_NB), -1)
        XCTAssertTrue(errno == EWOULDBLOCK || errno == EAGAIN)
    }
}
