import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayRuntimeSettingsFencePublicationTests: XCTestCase {
    private struct Interrupted: Error {}
    private typealias Publication = GatewayRuntimeSettingsFencePublication
    private final class Fixture {
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let scope: Publication.Scope
        let root: URL
        let directory: ProtectedSetupDirectory
        var fencePath: String { directory.path + "/gateway-settings-fence.cbor" }
        init(retain: Bool = true) throws {
            ready = try .init()
            let f = ready.fixture, revision = try ready.revision()
            let plan = try GatewayRuntimeSettingsPublicationPlan(revision: revision, previous: nil,
                activation: ready.activation, journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()))
            scope = .init(plan: plan, machine: f.runtime.machine, account: f.runtime.account,
                foreground: f.runtime.plan, inventory: try XCTUnwrap(f.runtime.machine.inventory()))
            if retain { try f.runtime.machine.retainGatewaySettingsTransition(revision) }
            root = URL(fileURLWithPath: "/private/tmp/remozio-settings-fence-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw Interrupted() }
            directory = try .init(anchor: root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
        }
        deinit { directory.close(); try? FileManager.default.removeItem(at: root) }
        func publish(stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
            try Publication.publish(scope, directory: directory, owner: getuid(), verifyCurrent: {}, didStage: stage)
        }
        func selected() throws {
            for artifact in scope.plan.artifacts {
                if let old = artifact.previous {
                    _ = try AdministrativeSetupPublication.publish(old, file: artifact.file, directory: directory, owner: getuid())
                }
            }
            _ = try GatewayRuntimeSettingsPublication.publish(scope.plan, directory: directory, owner: getuid(),
                verifyCurrent: {}, requireQuiesced: {})
        }
        func complete() throws {
            for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() {
                try scope.machine.markGatewaySettingsTransition(scope.plan.revision, phase: phase)
            }
            try scope.machine.completeGatewaySettingsTransition(scope.plan.revision)
        }
        func remove(validated: () throws -> Void = {}, removed: () throws -> Void = {}) throws -> Publication.Removal {
            try Publication.remove(scope, directory: directory, owner: getuid(), verifyCurrent: {}, didValidate: validated, didRemove: removed)
        }
        func bytes() throws -> Data { try Data(contentsOf: URL(fileURLWithPath: fencePath)) }
    }
    func testOnlyRetainedPendingScopeCanPublishAndMatchingRetryKeepsItsInode() throws {
        let f = try Fixture(retain: false), store = f.scope.machine
        XCTAssertThrowsError(try f.publish()); XCTAssertFalse(FileManager.default.fileExists(atPath: f.fencePath))
        try store.retainGatewaySettingsTransition(f.scope.plan.revision)
        let foreground = try f.scope.foreground.encoded, inventory = try store.inventory()
        XCTAssertEqual(try f.publish(), .created); var first = stat(); XCTAssertEqual(lstat(f.fencePath, &first), 0)
        XCTAssertEqual(first.st_mode & 0o7777, 0o644)
        XCTAssertEqual(try f.publish(), .retained); var after = stat(); XCTAssertEqual(lstat(f.fencePath, &after), 0)
        XCTAssertEqual(first.st_ino, after.st_ino); XCTAssertEqual(try f.bytes(), try f.scope.fence.encoded)
        XCTAssertEqual(try store.gatewaySettingsTransition(accountID: f.scope.account.accountID).phase, .retained)
        XCTAssertEqual(try store.inventory(), inventory); XCTAssertEqual(try f.scope.foreground.encoded, foreground)
    }
    func testInterruptedPublicationRecoversTheExactRecordWithoutAdvancingTheRow() throws {
        for stop in [AdministrativeSetupPublication.Stage.staged, .published] {
            let f = try Fixture()
            XCTAssertThrowsError(try f.publish { if $0 == stop { throw Interrupted() } })
            _ = try f.publish(); XCTAssertEqual(try f.bytes(), try f.scope.fence.encoded)
            XCTAssertEqual(try f.scope.machine.gatewaySettingsTransition(accountID: f.scope.account.accountID).phase, .retained)
        }
    }
    func testPendingStateCannotRemoveTheFenceAndCompletionCannotRecreateIt() throws {
        let f = try Fixture(); _ = try f.publish(); try f.selected()
        XCTAssertThrowsError(try f.remove()); XCTAssertTrue(FileManager.default.fileExists(atPath: f.fencePath))
        try f.complete(); XCTAssertThrowsError(try f.publish())
        XCTAssertEqual(try f.remove(), .removed); XCTAssertEqual(try f.remove(), .absent)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.fencePath))
    }
    func testCompletionWithoutTheExactSelectedRoleFilesKeepsItsFence() throws {
        let f = try Fixture(); _ = try f.publish(); try f.complete()
        XCTAssertThrowsError(try f.remove()); XCTAssertTrue(FileManager.default.fileExists(atPath: f.fencePath))
        try f.selected()
        let path = f.directory.path + "/transport-gateway-runtime.cbor", original = try Data(contentsOf: URL(fileURLWithPath: path))
        try FileManager.default.removeItem(atPath: path)
        XCTAssertThrowsError(try f.remove()); XCTAssertTrue(FileManager.default.fileExists(atPath: f.fencePath))
        _ = try AdministrativeSetupPublication.publish(original, file: .transportGatewayRuntime, directory: f.directory, owner: getuid())
        XCTAssertEqual(try f.remove(), .removed)
    }
    func testLostCleanupReplyCanReconcileAbsenceButCannotEraseAnotherPendingRevision() throws {
        let f = try Fixture(); _ = try f.publish(); try f.selected(); try f.complete()
        XCTAssertThrowsError(try f.remove(removed: { throw Interrupted() }))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.fencePath)); XCTAssertEqual(try f.remove(), .absent)
        let next = try f.ready.revision(2, previous: f.scope.plan.revision)
        try f.scope.machine.retainGatewaySettingsTransition(next)
        XCTAssertThrowsError(try f.remove())
    }
    func testReplacedFenceIdentityAndAConcurrentNewRevisionPreventUnlink() throws {
        for mode in 0...1 {
            let f = try Fixture(); _ = try f.publish(); try f.selected(); try f.complete()
            let original = try f.bytes()
            XCTAssertThrowsError(try f.remove(validated: {
                if mode == 0 {
                    try FileManager.default.moveItem(atPath: f.fencePath, toPath: f.fencePath + ".preserved")
                    try original.write(to: URL(fileURLWithPath: f.fencePath)); XCTAssertEqual(chmod(f.fencePath, 0o644), 0)
                } else {
                    try f.scope.machine.retainGatewaySettingsTransition(f.ready.revision(2, previous: f.scope.plan.revision))
                }
            }))
            XCTAssertTrue(FileManager.default.fileExists(atPath: f.fencePath)); XCTAssertEqual(try f.bytes(), original)
        }
    }
    func testMalformedLinkedAndWrongModeRecordsAreNeverOverwrittenOrRemoved() throws {
        for mode in 0...3 {
            let f = try Fixture(); _ = try f.publish(); try f.selected(); try f.complete()
            if mode == 0 { try Data("unrelated".utf8).write(to: URL(fileURLWithPath: f.fencePath)) }
            if mode == 1 { XCTAssertEqual(chmod(f.fencePath, 0o600), 0) }
            if mode == 2 { XCTAssertEqual(link(f.fencePath, f.fencePath + ".linked"), 0) }
            if mode == 3 {
                try FileManager.default.moveItem(atPath: f.fencePath, toPath: f.fencePath + ".preserved")
                try FileManager.default.createSymbolicLink(atPath: f.fencePath, withDestinationPath: f.fencePath + ".preserved")
            }
            XCTAssertThrowsError(try f.remove()); XCTAssertTrue(FileManager.default.fileExists(atPath: f.fencePath))
        }
    }
    func testForeignRetainedScopeAndAnOrdinaryNativeCallerCannotPublish() throws {
        let f = try Fixture(), other = try Fixture()
        let wrong = Publication.Scope(plan: other.scope.plan, machine: f.scope.machine, account: f.scope.account,
            foreground: f.scope.foreground, inventory: f.scope.inventory)
        XCTAssertThrowsError(try Publication.publish(wrong, directory: f.directory, owner: getuid(), verifyCurrent: {}))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.fencePath))
        guard getuid() != 0 else { throw XCTSkip("Ordinary native caller refusal requires a non-Root process") }
        let app = try ReleaseComponent(role: .app, identifier: "dev.remozio.fixture", generation: 1,
            relativePath: "Contents/MacOS/fixture", codeDirectoryHash: nil, build: "1", teamID: "ABCDEFGHIJ", formats: [])
        let release = SignedReleaseEvidence(manifest: try ReleaseManifest(release: "0.1.0", build: "1", components: [app]), codeDirectoryHashes: [:])
        XCTAssertThrowsError(try Publication.prepare(f.scope, release: release, verifyCurrent: { XCTFail("No native access") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertThrowsError(try Publication.removeCompleted(f.scope, release: release, verifyCurrent: { XCTFail("No native access") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
