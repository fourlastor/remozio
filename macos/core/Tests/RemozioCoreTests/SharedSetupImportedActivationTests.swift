import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Actual owned files and injected registration prove import composition. Native Root custody, launchd and physical devices remain unproven.
final class SharedSetupImportedActivationTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Harness {
        let f: RuntimeActivationFixture
        let initial: AuthorityInitializationIntent
        let proposal: PortableSetup
        let importedBundle: RuntimeConfigurationBundle
        var retained: SharedSetupImportIntent
        let artifactDirectory: URL
        let privateState: ProtectedSetupDirectory
        let jobs: ProtectedSetupDirectory
        var preparations = 0, registrations = 0
        var labels = Set<String>()
        var onPrepare: (() throws -> Void)?
        var onRegister: (() throws -> Void)?
        init(phase: SharedSetupImportIntent.Phase = .runtimePublished) throws {
            f = try .init()
            guard chmod(f.f.root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            initial = try XCTUnwrap(f.machine.initialization(accountID: f.account.accountID))
            proposal = try .init(defaults: .init(presence: .init(idleMilliseconds: 540_000,
                observationLifetimeMilliseconds: 7000, unavailableGraceMilliseconds: 45_000), gateway: GatewaySetupForm().settingsSelection()))
            let inventory = try XCTUnwrap(f.machine.inventory())
            var intent = try SharedSetupImportIntent(scope: .init(account: f.account, inventory: inventory), proposal: proposal)
            try f.f.prepare("machine/SharedSetupImport", .sharedSetupImport)
            let journal = try SharedSetupImportJournal(lease: .init(anchor: f.f.root.path, relativeDirectory: "machine/SharedSetupImport",
                owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(),
                macID: f.account.macID, installationID: f.account.installationID, initialize: true)
            try journal.begin(intent)
            if phase == .runtimePublished { intent = try journal.advance(intent, to: .runtimePublished) }
            try journal.close(); retained = intent
            importedBundle = try .initial(account: f.account, initialization: initial, reference: f.material.reference,
                inventory: inventory, importIntent: intent)
            artifactDirectory = f.f.root.appendingPathComponent("published-import-fixture")
            try FileManager.default.createDirectory(at: artifactDirectory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            privateState = try .init(anchor: f.f.root.path, relativePath: "activation-private", owner: getuid())
            jobs = try .init(anchor: f.f.root.path, relativePath: "activation-jobs", owner: getuid(), visibility: .sharedMetadata)
            for artifact in try RuntimePublishedArtifactValidation.artifacts(bundle: importedBundle, material: f.material) {
                let name = SHA256.hash(data: Data(artifact.path.utf8)).map { String(format: "%02x", $0) }.joined()
                let path = artifactDirectory.appendingPathComponent(name)
                try artifact.bytes.write(to: path); XCTAssertEqual(chmod(path.path, 0o600), 0)
            }
            try f.machine.close()
        }
        deinit { privateState.close(); jobs.close() }
        func machine<T>(_ body: (PreparationIntentStore) throws -> T) throws -> T {
            let machine = try f.f.open(); defer { try? machine.close() }; return try body(machine)
        }
        func journal() throws -> SharedSetupImportJournal {
            try .init(lease: .init(anchor: f.f.root.path, relativeDirectory: "machine/SharedSetupImport", owner: getuid(),
                ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(),
                macID: f.account.macID, installationID: f.account.installationID, initialize: false)
        }
        func advance() throws {
            let journal = try journal(); defer { try? journal.close() }; retained = try journal.advance(retained, to: .gatewayPrepared)
        }
        var operations: RuntimeActivationOperations {
            .init(prepare: { plan, account, initial, inventory, verify in
                self.preparations += 1; try self.onPrepare?(); try verify()
                let actual = try plan.configurationBundle(account: account, initialization: initial, inventory: inventory)
                try RuntimePublishedArtifactValidation.validate(bundle: actual, material: self.f.material, verifyCurrent: verify, read: { artifact in
                    let name = SHA256.hash(data: Data(artifact.path.utf8)).map { String(format: "%02x", $0) }.joined()
                    return try ProtectedServiceConfiguration.read(anchor: self.artifactDirectory.path, relativePath: name, owner: getuid())
                })
                try RuntimeActivationFiles.publish(plan: plan, privateState: self.privateState, jobs: self.jobs, owner: getuid(), verifyCurrent: verify)
            }, validate: { plan, _, _, _, verify in
                try AdministrativeSetupPublication.validateRetained(plan.host.canonicalBytes, file: .commandHost,
                    directory: self.privateState, owner: getuid(), verify: verify)
                for job in [plan.authorityJob, plan.transportJob] {
                    try AdministrativeSetupPublication.validateRetained(job.bytes, file: .accountJob(accountID: plan.accountID, role: job.declaration.role),
                        directory: self.jobs, owner: getuid(), verify: verify)
                }
            }, register: { job, verify in
                try verify(); self.registrations += 1; self.labels.insert(job.declaration.label); try self.onRegister?(); try verify()
            }, didStage: { _ in })
        }
        func owner() throws -> SetupAccountOwner {
            try .init(openMachine: { try self.f.f.open() }, expectedReleaseDigest: f.f.release, resume: { _, _ in throw Interrupted() },
                accountCodePolicy: f.f.policy, lookupAccount: { uid in
                    guard uid == self.f.f.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return self.f.f.identity
                }, activationOperations: operations)
        }
    }
    func testImportedPresenceReachesActivationAndActualOwnedPublishedFileValidation() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
        let after = try owner.resumeActivation(callerUID: getuid(), expected: before)
        XCTAssertTrue(after.jobsRegistered); XCTAssertEqual(h.labels.count, 2)
        let plan = try h.machine { try XCTUnwrap($0.runtimeActivation(accountID: h.f.account.accountID).plan) }
        XCTAssertEqual(plan.host.command.presence.presence.policy.idleMilliseconds, 540_000)
        XCTAssertEqual(plan.host.command.presence.presence.policy.observationLifetimeMilliseconds, 7000)
        XCTAssertEqual(plan.host.command.presence.presence.policy.unavailableGraceMilliseconds, 45_000)
        let journal = try h.journal(); defer { try? journal.close() }
        XCTAssertEqual(try journal.current(scope: h.retained.scope), h.retained); XCTAssertEqual(h.retained.phase, .runtimePublished)
    }
    func testExplicitRetryKeepsTheImportedPlanAndExistingPublishedBytes() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid())), after = try owner.resumeActivation(callerUID: getuid(), expected: before)
        let bytes = try Data(contentsOf: URL(fileURLWithPath: h.privateState.path + "/" + AdministrativeSetupPublication.File.commandHost.name))
        XCTAssertEqual(try owner.resumeActivation(callerUID: getuid(), expected: after), after)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: h.privateState.path + "/" + AdministrativeSetupPublication.File.commandHost.name)), bytes)
        XCTAssertEqual(h.labels.count, 2)
    }
    func testAnExistingDefaultPlanCannotReplaceTheReviewedImportedPresence() throws {
        let h = try Harness(); try h.machine { try $0.retainRuntimeActivation(h.f.plan) }
        let owner = try h.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
        XCTAssertThrowsError(try owner.resumeActivation(callerUID: getuid(), expected: before)) { XCTAssertEqual($0 as? RuntimeActivationError, .changedScope) }
        XCTAssertEqual(h.preparations, 0); XCTAssertEqual(h.registrations, 0)
    }
    func testAnImportWithoutVerifiedRuntimePublicationCannotStartActivation() throws {
        let h = try Harness(phase: .retained), owner = try h.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
        XCTAssertThrowsError(try owner.resumeActivation(callerUID: getuid(), expected: before)) { XCTAssertEqual($0 as? RuntimeActivationError, .incomplete) }
        XCTAssertEqual(h.preparations, 0); XCTAssertEqual(h.registrations, 0)
        XCTAssertNil(try h.machine { try $0.runtimeActivation(accountID: h.f.account.accountID).plan })
    }
    func testChangingTheImportDuringPreparationPreventsFilePublicationAndRegistration() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid())); h.onPrepare = { try h.advance() }
        XCTAssertThrowsError(try owner.resumeActivation(callerUID: getuid(), expected: before)) { XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision) }
        XCTAssertEqual(h.registrations, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: h.privateState.path + "/" + AdministrativeSetupPublication.File.commandHost.name))
    }
    func testChangingTheImportBetweenRegistrationsCannotMarkActivationComplete() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid())); h.onRegister = { try h.advance() }
        XCTAssertThrowsError(try owner.resumeActivation(callerUID: getuid(), expected: before)) { XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision) }
        XCTAssertEqual(h.registrations, 1)
        XCTAssertFalse(try h.machine { try $0.runtimeActivation(accountID: h.f.account.accountID).jobsRegistered })
        h.onRegister = nil
        let current = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
        XCTAssertTrue(try owner.resumeActivation(callerUID: getuid(), expected: current).jobsRegistered)
        XCTAssertEqual(h.labels.count, 2)
    }
    func testPlanRoundTripAndNativeBundleReconstructionKeepTheImportedPresence() throws {
        let h = try Harness()
        let plan = try h.machine { machine in
            try RuntimeActivationPlan(account: h.f.account, initialization: h.initial,
                runtime: machine.runtimePreparation(accountID: h.f.account.accountID), inventory: XCTUnwrap(machine.inventory()), importIntent: h.retained)
        }
        let decoded = try RuntimeActivationPlan.decode(plan.encoded)
        let bundle = try h.machine { try decoded.configurationBundle(account: h.f.account, initialization: h.initial, inventory: XCTUnwrap($0.inventory())) }
        XCTAssertEqual(bundle.command.canonicalBytes, h.importedBundle.command.canonicalBytes)
        XCTAssertEqual(bundle.transport.canonicalBytes, h.importedBundle.transport.canonicalBytes)
    }
    func testAnExplicitPresenceOverrideCannotConflictWithAReviewedImport() throws {
        let h = try Harness(), other = try PresenceConfiguration(idleMilliseconds: 120_000, observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 30_000)
        XCTAssertThrowsError(try h.machine { try RuntimeConfigurationBundle.initial(account: h.f.account, initialization: h.initial,
            reference: h.f.material.reference, inventory: XCTUnwrap($0.inventory()), importIntent: h.retained, presencePolicyOverride: other) }) {
            XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
        }
    }
}
