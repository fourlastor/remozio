import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayRuntimeSettingsRecoveryPublicationTests: XCTestCase {
    private struct Interrupted: Error {}
    private typealias Publication = GatewayRuntimeSettingsRecoveryPublication
    private final class Fixture {
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let transition: GatewayRuntimeSettingsPublicationPlan
        let scope: Publication.Scope
        let root: URL
        let directory: ProtectedSetupDirectory
        var path: String { directory.path + "/gateway-settings-fence.cbor" }
        init(complete: Bool = true) throws {
            ready = try .init()
            let f = ready.fixture, revision = try ready.revision(), inventory = try XCTUnwrap(f.runtime.machine.inventory())
            transition = try .init(revision: revision, previous: nil, activation: ready.activation, journal: f.state(),
                foreground: f.runtime.plan, inventory: inventory)
            try f.runtime.machine.retainGatewaySettingsTransition(revision)
            if complete {
                for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() { try f.runtime.machine.markGatewaySettingsTransition(revision, phase: phase) }
                try f.runtime.machine.completeGatewaySettingsTransition(revision)
            }
            // Constructing a plan does not authenticate this supplied state. Scope.validate reads the real store again.
            let plan = try GatewayRuntimeSettingsRecoveryPlan(state: .init(active: revision, pending: nil, phase: nil),
                activation: ready.activation, journal: f.state(), foreground: f.runtime.plan, inventory: inventory,
                attemptID: Data(repeating: 7, count: 16))
            scope = .init(plan: plan, activation: ready.activation, machine: f.runtime.machine, account: f.runtime.account,
                foreground: f.runtime.plan, inventory: inventory)
            root = URL(fileURLWithPath: "/private/tmp/remozio-recovery-publication-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw Interrupted() }
            directory = try .init(anchor: root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
            for artifact in transition.artifacts {
                _ = try AdministrativeSetupPublication.publish(artifact.selected, file: artifact.file, directory: directory, owner: getuid())
            }
        }
        deinit { directory.close(); try? FileManager.default.removeItem(at: root) }
        func next(_ attempt: UInt8 = 8) throws -> Publication.Scope {
            let plan = try GatewayRuntimeSettingsRecoveryPlan(state: scope.machine.gatewaySettingsTransition(accountID: scope.account.accountID),
                activation: ready.activation, journal: ready.fixture.state(), foreground: scope.foreground, inventory: scope.inventory,
                attemptID: Data(repeating: attempt, count: 16))
            return .init(plan: plan, activation: ready.activation, machine: scope.machine, account: scope.account,
                foreground: scope.foreground, inventory: scope.inventory)
        }
        func publish(_ selected: Publication.Scope? = nil, paused: () throws -> Void = {},
                     stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> GatewayRuntimeSettingsFileResult {
            try Publication.publish(selected ?? scope, directory: directory, owner: getuid(), verifyCurrent: {}, requireRootPaused: paused, didStage: stage)
        }
        func remove(_ selected: Publication.Scope? = nil, accepted: () throws -> Void = {},
                    validated: () throws -> Void = {}, removed: () throws -> Void = {}) throws -> Publication.Removal {
            try Publication.remove(selected ?? scope, directory: directory, owner: getuid(), verifyCurrent: {},
                requireFreshAcceptance: accepted, didValidate: validated, didRemove: removed)
        }
        func bytes() throws -> Data { try Data(contentsOf: URL(fileURLWithPath: path)) }
        func write(_ bytes: Data) throws { try bytes.write(to: URL(fileURLWithPath: path)); guard chmod(path, 0o644) == 0 else { throw Interrupted() } }
    }
    func testAbsentFenceCreationMatchingRetryAndNewAttemptKeepTheSettingsAndRoleFiles() throws {
        let f = try Fixture(), machine = f.scope.machine, before = try machine.gatewaySettingsTransition(accountID: f.scope.account.accountID)
        let files = try f.transition.artifacts.map { try Data(contentsOf: URL(fileURLWithPath: f.directory.path + "/" + $0.file.name)) }
        XCTAssertEqual(try f.publish(), .created); var original = stat(); XCTAssertEqual(lstat(f.path, &original), 0)
        XCTAssertEqual(original.st_mode & 0o7777, 0o644)
        XCTAssertEqual(try f.publish(), .retained); var retained = stat(); XCTAssertEqual(lstat(f.path, &retained), 0)
        XCTAssertEqual(original.st_ino, retained.st_ino)
        let next = try f.next(); XCTAssertEqual(try f.publish(next), .replaced)
        XCTAssertEqual(try f.bytes(), try next.plan.fence.encoded)
        XCTAssertEqual(try machine.gatewaySettingsTransition(accountID: f.scope.account.accountID).active?.encoded, try before.active?.encoded)
        XCTAssertNil(try machine.gatewaySettingsTransition(accountID: f.scope.account.accountID).pending)
        for (index, artifact) in f.transition.artifacts.enumerated() {
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.directory.path + "/" + artifact.file.name)), files[index])
        }
        XCTAssertThrowsError(try f.remove()); XCTAssertEqual(try f.remove(next), .removed)
    }
    func testOnlyCompletedMatchingScopeCanPublishAndTheSettingsAPIStillRejectsFences() throws {
        let pending = try Fixture(complete: false), f = try Fixture(), other = try Fixture()
        XCTAssertThrowsError(try pending.publish()); XCTAssertFalse(FileManager.default.fileExists(atPath: pending.path))
        let wrong = Publication.Scope(plan: other.scope.plan, activation: f.scope.activation, machine: f.scope.machine,
            account: f.scope.account, foreground: f.scope.foreground, inventory: f.scope.inventory)
        XCTAssertThrowsError(try f.publish(wrong)); XCTAssertFalse(FileManager.default.fileExists(atPath: f.path))
        XCTAssertThrowsError(try AdministrativeSetupPublication.replaceSettings(f.scope.plan.fence.encoded, expected: nil,
            file: .gatewaySettingsFence, directory: f.directory, owner: getuid(), verify: {}))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.path))
    }
    func testCompletedTransitionFenceCanBecomeRecoveryButAnotherRevisionCannotBeReplaced() throws {
        let f = try Fixture(), old = try GatewayRuntimeSettingsFence(f.transition)
        _ = try AdministrativeSetupPublication.publish(old.encoded, file: .gatewaySettingsFence, directory: f.directory, owner: getuid())
        XCTAssertEqual(try f.publish(), .replaced); XCTAssertEqual(try f.bytes(), try f.scope.plan.fence.encoded)
        let next = try f.ready.revision(2, previous: f.scope.plan.revision)
        try f.scope.machine.retainGatewaySettingsTransition(next)
        let original = try f.bytes()
        XCTAssertThrowsError(try f.publish()); XCTAssertThrowsError(try f.remove()); XCTAssertEqual(try f.bytes(), original)
    }
    func testForeignMalformedLinkedAndWrongModeRecordsArePreserved() throws {
        for mode in 0...4 {
            let f = try Fixture(); _ = try f.publish()
            if mode == 0 { try f.write(Data("unrelated".utf8)) }
            if mode == 1 { XCTAssertEqual(chmod(f.path, 0o600), 0) }
            if mode == 2 { XCTAssertEqual(link(f.path, f.path + ".linked"), 0) }
            if mode == 3 {
                try FileManager.default.moveItem(atPath: f.path, toPath: f.path + ".preserved")
                try FileManager.default.createSymbolicLink(atPath: f.path, withDestinationPath: f.path + ".preserved")
            }
            if mode == 4 { try f.write(Fixture().scope.plan.fence.encoded) }
            let original = try f.bytes()
            XCTAssertThrowsError(try f.publish()); XCTAssertThrowsError(try f.remove())
            XCTAssertEqual(try f.bytes(), original)
        }
    }
    func testEverySelectedRoleArtifactMustMatchBeforePublicationAndRemoval() throws {
        for index in 0..<5 {
            let f = try Fixture(); _ = try f.publish()
            let artifact = f.transition.artifacts[index], path = f.directory.path + "/" + artifact.file.name
            let original = try f.bytes()
            try FileManager.default.removeItem(atPath: path)
            XCTAssertThrowsError(try f.publish()); XCTAssertThrowsError(try f.remove()); XCTAssertEqual(try f.bytes(), original)
        }
    }
    func testInterruptedReplacementReconcilesExactBytesWithoutAdvancingSettings() throws {
        for stop in [AdministrativeSetupPublication.Stage.staged, .published] {
            let f = try Fixture(); _ = try f.publish(); let next = try f.next()
            XCTAssertThrowsError(try f.publish(next, stage: { if $0 == stop { throw Interrupted() } }))
            _ = try f.publish(next); XCTAssertEqual(try f.bytes(), try next.plan.fence.encoded)
            XCTAssertEqual(try f.scope.machine.gatewaySettingsTransition(accountID: f.scope.account.accountID).active?.encoded, try f.scope.plan.revision.encoded)
        }
    }
    func testPauseAndFreshAcceptanceAreRequiredAndLostRemovalRepliesReconcileAbsence() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.publish(paused: { throw Interrupted() })); XCTAssertFalse(FileManager.default.fileExists(atPath: f.path))
        _ = try f.publish()
        XCTAssertThrowsError(try f.remove(accepted: { throw Interrupted() })); XCTAssertEqual(try f.bytes(), try f.scope.plan.fence.encoded)
        XCTAssertThrowsError(try f.remove(removed: { throw Interrupted() }))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.path)); XCTAssertEqual(try f.remove(), .absent)
    }
    func testReplacedIdentityAndLateForeignFenceNeverProduceASuccessfulRemoval() throws {
        for late in [false, true] {
            let f = try Fixture(); _ = try f.publish(); let original = try f.bytes(), foreign = try f.next().plan.fence.encoded
            if late {
                XCTAssertThrowsError(try f.remove(removed: { try f.write(foreign) }))
                XCTAssertEqual(try f.bytes(), foreign)
            } else {
                XCTAssertThrowsError(try f.remove(validated: {
                    try FileManager.default.moveItem(atPath: f.path, toPath: f.path + ".preserved")
                    try f.write(original)
                }))
                XCTAssertEqual(try f.bytes(), original)
            }
        }
        let f = try Fixture(), foreign = try f.next().plan.fence.encoded
        var checks = 0
        XCTAssertThrowsError(try GatewaySettingsFenceRemoval.remove(f.scope.plan.fence.encoded, directory: f.directory, owner: getuid(), verifyCurrent: {
            checks += 1
            if checks == 2 { try f.write(foreign) }
        }))
        XCTAssertEqual(try f.bytes(), foreign)
    }
    func testARevisionStartingDuringStagingAndRevokedAcceptanceBeforeUnlinkPreserveTheFence() throws {
        let staged = try Fixture(); _ = try staged.publish(); let original = try staged.bytes(), selected = try staged.next()
        let revision = try staged.ready.revision(2, previous: staged.scope.plan.revision)
        XCTAssertThrowsError(try staged.publish(selected, stage: {
            if $0 == .staged { try staged.scope.machine.retainGatewaySettingsTransition(revision) }
        }))
        XCTAssertEqual(try staged.bytes(), original)
        XCTAssertEqual(try staged.scope.machine.gatewaySettingsTransition(accountID: staged.scope.account.accountID).pending?.encoded, try revision.encoded)
        let f = try Fixture(); _ = try f.publish(); var accepted = true
        XCTAssertThrowsError(try f.remove(accepted: { if !accepted { throw Interrupted() } }, validated: { accepted = false }))
        XCTAssertEqual(try f.bytes(), try f.scope.plan.fence.encoded)
    }
    func testNativePublicationAndRemovalRefuseAnOrdinaryCallerBeforeAnyScopeAccess() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("This control requires an ordinary account") }
        let f = try Fixture(), app = try ReleaseComponent(role: .app, identifier: "dev.remozio.fixture", generation: 1,
            relativePath: "Contents/MacOS/fixture", codeDirectoryHash: nil, build: "1", teamID: "ABCDEFGHIJ", formats: [])
        let release = SignedReleaseEvidence(manifest: try .init(release: "0.1.0", build: "1", components: [app]), codeDirectoryHashes: [:])
        XCTAssertThrowsError(try Publication.prepare(f.scope, release: release, verifyCurrent: { XCTFail() }, requireRootPaused: { XCTFail() })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertThrowsError(try Publication.removeAccepted(f.scope, release: release, verifyCurrent: { XCTFail() }, requireFreshAcceptance: { XCTFail() })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
