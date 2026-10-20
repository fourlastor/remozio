import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Real owned artifacts test immutable validation. Native Root, service access and launchd observation remain unproven.
final class SharedSetupImportCompletionValidationTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Harness {
        let f: SharedSetupImportGatewayApplicationTests.Fixture
        let proposal: PortableSetup
        let owner: SetupAccountOwner
        let foregroundPrivate: ProtectedSetupDirectory
        let jobs: ProtectedSetupDirectory
        let shared: ProtectedSetupDirectory
        let artifacts: URL
        var foregroundReads = 0, gatewayReads = 0
        var afterGateway: ((PreparationIntentStore, SharedSetupImportCompletionValidation.Gateway) throws -> Void)?
        init(gateway: Bool = false, phase: SetupPortableImportProgress.Phase = .rootComplete,
             cloudflare: Bool = false, changedSelection: Bool = false) throws {
            f = try .init(prepared: gateway)
            let core = f.core, runtime = core.runtime
            guard chmod(runtime.f.root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            let base = f.proposal()
            let selection = changedSelection ? try GatewayRuntimeSettingsSelection(service: f.selection.service,
                activation: .init(wakePollMilliseconds: 2000, wakeTimeoutMilliseconds: 6000)) : f.selection
            let defaults = SharedSetupDefaults(presence: base.defaults.presence, gateway: selection)
            proposal = .init(defaults: defaults, fcm: gateway ? base.fcm : nil,
                cloudflare: cloudflare ? try .init(accountID: String(repeating: "a", count: 32),
                    zoneID: String(repeating: "b", count: 32), dnsSuffix: "fixture.example", apiToken: "synthetic-not-a-secret") : nil,
                pushClient: gateway ? base.pushClient : nil)
            foregroundPrivate = try .init(anchor: runtime.f.root.path, relativePath: "CompletionPrivate", owner: getuid())
            jobs = try .init(anchor: runtime.f.root.path, relativePath: "CompletionJobs", owner: getuid(), visibility: .sharedMetadata)
            shared = try .init(anchor: runtime.f.root.path, relativePath: "CompletionShared", owner: getuid(), visibility: .sharedMetadata)
            try RuntimeActivationFiles.publish(plan: runtime.plan, privateState: foregroundPrivate, jobs: jobs, owner: getuid(), verifyCurrent: {})
            artifacts = runtime.f.root.appendingPathComponent("completion-artifacts")
            try FileManager.default.createDirectory(at: artifacts, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let bundle = try runtime.plan.configurationBundle(account: runtime.account,
                initialization: XCTUnwrap(core.machine.initialization(accountID: runtime.account.accountID)), inventory: XCTUnwrap(core.machine.inventory()))
            for artifact in try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: runtime.material) {
                let path = artifacts.appendingPathComponent(Self.name(artifact.path))
                try artifact.bytes.write(to: path); guard chmod(path.path, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
            }
            if gateway {
                let initialized = try core.initialize(true)
                _ = try core.machine.completeGatewayJournalInitialization(core.intent, head: initialized.head)
                let plan = try GatewayRuntimeActivationPlan(journal: core.state(), foreground: runtime.plan, inventory: XCTUnwrap(core.machine.inventory()))
                try core.machine.retainGatewayRuntimeActivation(plan)
                _ = try GatewayRuntimeActivationFiles.publish(plan, journal: core.state(), foreground: runtime.plan,
                    inventory: XCTUnwrap(core.machine.inventory()), shared: shared, jobs: jobs, owner: getuid(), mode: .publishPending, verifyCurrent: {})
                try core.machine.markGatewayRuntimePublished(plan); _ = try core.machine.enrollGatewayRuntimeActivation(plan)
                try core.machine.markGatewayRuntimeRegistered(plan)
            }
            owner = try f.owner(proposal: proposal)
            try machine { machine in
                let inventory = try XCTUnwrap(machine.inventory())
                let scope = try SharedSetupImportIntent.Scope(account: runtime.account, inventory: inventory)
                try machine.withSharedImportJournal { journal in
                    let journal = try XCTUnwrap(journal); var retained = try XCTUnwrap(journal.current(scope: scope))
                    while retained.phase.rawValue < phase.rawValue {
                        retained = try journal.advance(retained, to: XCTUnwrap(.init(rawValue: retained.phase.rawValue + 1)))
                    }
                }
            }
        }
        deinit { try? owner.close(); foregroundPrivate.close(); jobs.close(); shared.close() }
        static func name(_ path: String) -> String { SHA256.hash(data: Data(path.utf8)).map { String(format: "%02x", $0) }.joined() }
        func machine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            let machine = try f.core.runtime.f.open(); defer { try? machine.close() }; return try body(machine)
        }
        func progress() throws -> SetupPortableImportProgress { try XCTUnwrap(owner.portableImportProgress(callerUID: getuid())) }
        var operations: SharedSetupImportCompletionValidation.Operations {
            .init(foreground: { value, verify in
                self.foregroundReads += 1; try verify()
                let bundle = try value.plan.configurationBundle(account: value.account, initialization: value.initialization, inventory: value.inventory)
                try RuntimePublishedArtifactValidation.validate(bundle: bundle, material: self.f.core.runtime.material, verifyCurrent: verify, read: { artifact in
                    try ProtectedServiceConfiguration.read(anchor: self.artifacts.path, relativePath: Self.name(artifact.path), owner: getuid())
                })
                try AdministrativeSetupPublication.validateRetained(value.plan.host.canonicalBytes, file: .commandHost,
                    directory: self.foregroundPrivate, owner: getuid(), verify: verify)
                for job in [value.plan.authorityJob, value.plan.transportJob] {
                    try AdministrativeSetupPublication.validateRetained(job.bytes, file: .accountJob(accountID: value.account.accountID, role: job.declaration.role),
                        directory: self.jobs, owner: getuid(), verify: verify)
                }
            }, gateway: { machine, value, verify in
                self.gatewayReads += 1; try verify()
                try self.f.validate(on: machine, choices: value.choices, selection: value.selection, verify: verify)
                _ = try GatewayRuntimeActivationFiles.publish(value.plan, journal: value.journal, foreground: value.foreground.plan,
                    inventory: value.foreground.inventory, shared: self.shared, jobs: self.jobs, owner: getuid(), mode: .validateRetained, verifyCurrent: verify)
                try self.afterGateway?(machine, value); try verify()
            })
        }
        func verify(expected: SetupPortableImportProgress? = nil) throws -> SetupPortableImportProgress {
            try owner.verifiedPortableImportCompletion(callerUID: getuid(), expected: expected ?? progress(), proposal: proposal, operations: operations)
        }
        func pendingSettings(_ machine: PreparationIntentStore, _ value: SharedSetupImportCompletionValidation.Gateway? = nil) throws {
            let account = f.core.runtime.account, activation = try machine.gatewayRuntimeActivation(accountID: account.accountID)
            let revision = try GatewayRuntimeSettingsRevision(id: AccountPreparationIntent.randomID(), selection: f.selection,
                activation: XCTUnwrap(activation.plan), journal: f.core.state(machine), foreground: f.core.runtime.plan,
                inventory: XCTUnwrap(machine.inventory()))
            try machine.retainGatewaySettingsTransition(revision)
        }
    }
    func testProviderFreeCompletionValidatesActualFilesWithoutChangingProgress() throws {
        let h = try Harness(), before = try h.progress()
        XCTAssertEqual(try h.verify(), before); XCTAssertEqual(try h.verify(), before)
        XCTAssertEqual(try h.progress(), before); XCTAssertEqual(h.foregroundReads, 2); XCTAssertEqual(h.gatewayReads, 0)
    }
    func testGatewayCompletionValidatesActualPrivateAndRuntimeArtifacts() throws {
        let h = try Harness(gateway: true), before = try h.progress()
        XCTAssertEqual(try h.verify(), before); XCTAssertEqual(try h.verify(), before)
        XCTAssertEqual(h.foregroundReads, 2); XCTAssertEqual(h.gatewayReads, 2); XCTAssertEqual(try h.progress(), before)
    }
    func testACompleteMarkerCannotReplaceTheMissingForegroundJob() throws {
        let h = try Harness(), before = try h.progress()
        let path = h.jobs.path + "/" + AdministrativeSetupPublication.File.accountJob(accountID: h.f.core.runtime.account.accountID, role: .transport).name
        XCTAssertEqual(unlink(path), 0); XCTAssertThrowsError(try h.verify())
        XCTAssertFalse(FileManager.default.fileExists(atPath: path)); XCTAssertEqual(try h.progress(), before)
    }
    func testMissingPublishedRuntimeConfigurationIsNotRepaired() throws {
        let h = try Harness()
        // Remove an actual selected artifact without assuming its generated destination path.
        let file = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: h.artifacts, includingPropertiesForKeys: nil).first)
        XCTAssertEqual(unlink(file.path), 0); XCTAssertThrowsError(try h.verify())
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }
    func testMissingGatewayRuntimeSiblingCannotBeRepairedByReadback() throws {
        for file: AdministrativeSetupPublication.File in [.gatewayConfiguration, .authorityGatewayRuntime, .transportGatewayRuntime, .gatewayRuntimeCommit] {
            let h = try Harness(gateway: true), path = h.shared.path + "/" + file.name
            XCTAssertEqual(unlink(path), 0); XCTAssertThrowsError(try h.verify()); XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }
    func testMissingGatewayCredentialCannotBeReplacedByACompleteMarker() throws {
        let h = try Harness(gateway: true), path = h.f.core.parent.path + "/gateway-provider.json"
        XCTAssertEqual(unlink(path), 0); XCTAssertThrowsError(try h.verify()); XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }
    func testPendingProgressNeverEntersTheCompletionVerifier() throws {
        let h = try Harness(phase: .gatewayPrepared)
        XCTAssertThrowsError(try h.verify()) { XCTAssertEqual($0 as? SharedSetupImportCompletionValidation.Failure, .incomplete) }
        XCTAssertEqual(h.foregroundReads, 0); XCTAssertEqual(h.gatewayReads, 0)
    }
    func testWrongCallerAndChangedProposalStopBeforeFileAccess() throws {
        let h = try Harness(), before = try h.progress()
        XCTAssertThrowsError(try h.owner.verifiedPortableImportCompletion(callerUID: getuid() + 1, expected: before, proposal: h.proposal, operations: h.operations))
        let changed = PortableSetup(defaults: .init(presence: try .init(idleMilliseconds: 240_000,
            observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 30_000), gateway: h.f.selection))
        XCTAssertThrowsError(try h.owner.verifiedPortableImportCompletion(callerUID: getuid(), expected: before, proposal: changed, operations: h.operations))
        XCTAssertEqual(h.foregroundReads, 0); XCTAssertEqual(h.gatewayReads, 0)
    }
    func testConfiguredRelayCannotSilentlyCompleteWithoutNativeVerification() throws {
        let h = try Harness(cloudflare: true)
        XCTAssertThrowsError(try h.verify()) { XCTAssertEqual($0 as? SharedSetupImportCompletionValidation.Failure, .relayNotImplemented) }
        XCTAssertEqual(h.foregroundReads, 0); XCTAssertEqual(h.gatewayReads, 0)
    }
    func testPendingSettingsPreventCompletionBeforeFileValidation() throws {
        let h = try Harness(gateway: true); try h.machine { try h.pendingSettings($0) }
        XCTAssertThrowsError(try h.verify()) { XCTAssertEqual($0 as? SharedSetupImportCompletionValidation.Failure, .changedOutputs) }
        XCTAssertEqual(h.foregroundReads, 0); XCTAssertEqual(h.gatewayReads, 0)
    }
    func testASettingsChangeDuringFileValidationCannotReturnCompletion() throws {
        let h = try Harness(gateway: true); h.afterGateway = { try h.pendingSettings($0, $1) }
        XCTAssertThrowsError(try h.verify()) { XCTAssertEqual($0 as? SharedSetupImportCompletionValidation.Failure, .changedOutputs) }
        XCTAssertEqual(h.gatewayReads, 1)
    }
    func testTheActualGatewayActivationMustMatchEveryImportedSetting() throws {
        let h = try Harness(gateway: true, changedSelection: true)
        XCTAssertThrowsError(try h.verify()) { XCTAssertEqual($0 as? SharedSetupImportCompletionValidation.Failure, .changedOutputs) }
        XCTAssertEqual(h.gatewayReads, 0)
    }
    func testTheNativeVerifierRejectsAnOrdinaryUIDBeforeOpeningInstalledFiles() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary UID refusal") }
        let h = try Harness(), before = try h.progress()
        XCTAssertThrowsError(try h.owner.verifiedPortableImportCompletion(callerUID: getuid(), expected: before, proposal: h.proposal)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
