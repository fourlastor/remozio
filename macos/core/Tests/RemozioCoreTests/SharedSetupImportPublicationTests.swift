import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned directory publication and injected failures do not prove native Root admission or survival of actual power loss.
final class SharedSetupImportPublicationTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Fixture {
        let f: SharedSetupImportFixture
        let intent: SharedSetupImportIntent
        var finalPath: String { f.accountFixture.root.path + "/machine/SharedSetupImport" }
        init() throws { f = try .init(relativeDirectory: "unused-fixture"); intent = try f.intent() }
        func create(_ selected: SharedSetupImportIntent? = nil,
                    verify: () throws -> Void = {}, stage: (SharedSetupImportPublication.Stage) throws -> Void = { _ in }) throws -> SharedSetupImportIntent {
            try SharedSetupImportPublication.create(anchor: f.accountFixture.root.path, relativeMachineDirectory: "machine",
                owner: getuid(), expectedScope: f.scope, intent: selected ?? intent, verifyCurrent: verify, didStage: stage)
        }
        func read() throws -> SharedSetupImportIntent? {
            try SharedSetupImportJournal.withExisting(anchor: f.accountFixture.root.path, relativeMachineDirectory: "machine",
                owner: getuid(), macID: f.scope.macID, installationID: f.scope.installationID) { try $0?.current(scope: f.scope) }
        }
    }
    func testOnlyACompleteInitializedJournalAppearsAtTheActiveName() throws {
        let f = try Fixture(); var observed: [SharedSetupImportPublication.Stage] = []
        XCTAssertEqual(try f.create(stage: { stage in
            observed.append(stage)
            if stage == .published || stage == .durable { XCTAssertEqual(try f.read(), f.intent) }
            else { XCTAssertNil(try f.read()); XCTAssertFalse(FileManager.default.fileExists(atPath: f.finalPath)) }
        }), f.intent)
        XCTAssertEqual(observed, SharedSetupImportPublication.Stage.allCases)
        XCTAssertEqual(try f.read(), f.intent)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.finalPath).sorted(), ["setup-import.sqlite", "writer.lock"])
        let attributes = try FileManager.default.attributesOfItem(atPath: f.finalPath)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    }
    func testEveryUnpublishedFailureLeavesNoActiveImportAndAReplacementCanPublish() throws {
        for point in [SharedSetupImportPublication.Stage.directoryPrepared, .filesPrepared, .intentRetained, .beforePublication] {
            let f = try Fixture()
            XCTAssertThrowsError(try f.create(stage: { if $0 == point { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertNil(try f.read()); XCTAssertFalse(FileManager.default.fileExists(atPath: f.finalPath))
            XCTAssertEqual(try f.create(), f.intent); XCTAssertEqual(try f.read(), f.intent)
        }
    }
    func testLostRepliesAfterPublicationRetainTheSameOperationAndNeverOverwriteIt() throws {
        for point in [SharedSetupImportPublication.Stage.published, .durable] {
            let f = try Fixture()
            XCTAssertThrowsError(try f.create(stage: { if $0 == point { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertEqual(try f.read(), f.intent)
            let before = try Data(contentsOf: URL(fileURLWithPath: f.finalPath + "/setup-import.sqlite"))
            XCTAssertThrowsError(try f.create()) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.finalPath + "/setup-import.sqlite")), before)
        }
    }
    func testAnExistingUnexplainedPartialDirectoryIsNeverRepairedOrInitialized() throws {
        let f = try Fixture(), directory = try ProtectedSetupDirectory(anchor: f.f.accountFixture.root.path,
            relativePath: "machine/SharedSetupImport", owner: getuid())
        directory.close()
        XCTAssertThrowsError(try f.create()) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
        XCTAssertThrowsError(try f.read())
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.finalPath), [])
    }
    func testAPublishedImportCannotBeReplacedByAnotherProposalOrOperation() throws {
        let f = try Fixture(); _ = try f.create()
        let replacement = try SharedSetupImportIntent(scope: f.f.scope, proposal: f.f.proposal())
        XCTAssertNotEqual(replacement.operationID, f.intent.operationID)
        XCTAssertThrowsError(try f.create(replacement)) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
        XCTAssertEqual(try f.read(), f.intent)
    }
    func testNoCredentialBytesEnterActiveOrUnpublishedJournalFiles() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.create(stage: { if $0 == .intentRetained { throw Interrupted() } }))
        _ = try f.create()
        let machine = f.f.accountFixture.root.appendingPathComponent("machine")
        for name in try FileManager.default.contentsOfDirectory(atPath: machine.path)
            where name == "SharedSetupImport" || name.hasPrefix(".remozio-import-") {
            let directory = machine.appendingPathComponent(name)
            for file in try FileManager.default.contentsOfDirectory(atPath: directory.path) {
                let bytes = try Data(contentsOf: directory.appendingPathComponent(file))
                XCTAssertNil(bytes.range(of: Data("synthetic-provider-token-only".utf8)))
            }
        }
    }
    func testDeniedScopeOrVerificationCannotCreateAnyImportDirectory() throws {
        let f = try Fixture(), other = try Fixture()
        XCTAssertThrowsError(try f.create(other.intent)) { XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope) }
        XCTAssertThrowsError(try f.create(verify: { throw Interrupted() })) { XCTAssertTrue($0 is Interrupted) }
        let entries = try FileManager.default.contentsOfDirectory(atPath: f.f.accountFixture.root.path + "/machine")
        XCTAssertFalse(entries.contains("SharedSetupImport")); XCTAssertFalse(entries.contains { $0.hasPrefix(".remozio-import-") })
    }
    func testAnAdvancedPhaseCannotCreateANewJournal() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.create(f.intent.advanced(to: .runtimePublished))) {
            XCTAssertEqual($0 as? SharedSetupImportError, .invalidTransition)
        }
        XCTAssertNil(try f.read())
    }
    func testAChangedScopeImmediatelyBeforePublicationLeavesOnlyPrivateStaging() throws {
        let f = try Fixture(); var valid = true
        XCTAssertThrowsError(try f.create(verify: { if !valid { throw Interrupted() } }, stage: { if $0 == .beforePublication { valid = false } })) {
            XCTAssertTrue($0 is Interrupted)
        }
        XCTAssertNil(try f.read()); XCTAssertFalse(FileManager.default.fileExists(atPath: f.finalPath))
    }
}
