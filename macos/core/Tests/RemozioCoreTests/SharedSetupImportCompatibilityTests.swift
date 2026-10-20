import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SharedSetupImportCompatibilityTests: XCTestCase {
    private func retain(_ f: SharedSetupImportFixture) throws -> SharedSetupImportIntent {
        let intent = try f.intent(), journal = try f.open(initialize: true)
        defer { try? journal.close() }; try journal.begin(intent); return intent
    }
    func testAbsentJournalCreatesNoFilesOrImportRequirements() throws {
        let f = try SharedSetupImportFixture(), machine = try f.accountFixture.open()
        defer { try? machine.close() }
        let before = try FileManager.default.contentsOfDirectory(atPath: f.accountFixture.root.path + "/machine").sorted()
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine)
        XCTAssertNil(snapshot.inputs.sharedImport)
        XCTAssertFalse(snapshot.requirements.formats.contains { $0.name == SharedSetupImportJournal.formatName })
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.accountFixture.root.path + "/machine").sorted(), before)
        try snapshot.requireCurrent(machine: machine)
    }
    func testJournalAndBothPortableVersionsBecomeRequiredBeforeRuntimePublication() throws {
        let f = try SharedSetupImportFixture(relativeDirectory: "machine/SharedSetupImport")
        let intent = try retain(f), machine = try f.accountFixture.open()
        defer { try? machine.close() }
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine)
        XCTAssertTrue(snapshot.inputs.runtimes.isEmpty)
        let imports = try XCTUnwrap(snapshot.inputs.sharedImport)
        XCTAssertEqual(imports.records.count, 1)
        XCTAssertEqual(imports.records.first?.operationID, intent.operationID)
        XCTAssertEqual(imports.records.first?.phase, SharedSetupImportIntent.Phase.retained.rawValue)
        let journal = try XCTUnwrap(snapshot.requirements.formats.first { $0.name == SharedSetupImportJournal.formatName })
        XCTAssertEqual(journal.role, .setupController)
        XCTAssertEqual(journal.readVersions, [2]); XCTAssertEqual(journal.writeVersions, [2])
        let portable = try XCTUnwrap(snapshot.requirements.formats.first { $0.name == PortableSetup.formatName })
        XCTAssertEqual(portable.readVersions, [4]); XCTAssertEqual(portable.writeVersions, [4])
        XCTAssertFalse(snapshot.requirements.formats.contains { $0.name == SharedSetupImportJournal.formatName && $0.role != .setupController })
        try snapshot.requireCurrent(machine: machine)
    }
    func testChangedRecordInvalidatesAnEarlierCompatibilitySnapshot() throws {
        let f = try SharedSetupImportFixture(relativeDirectory: "machine/SharedSetupImport")
        let intent = try retain(f), machine = try f.accountFixture.open()
        defer { try? machine.close() }
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine)
        let journal = try f.open(); _ = try journal.advance(intent, to: .runtimePublished); try journal.close()
        XCTAssertThrowsError(try snapshot.requireCurrent(machine: machine)) {
            XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
        }
    }
    func testHeldAndPartialJournalsAreErrorsInsteadOfAbsentState() throws {
        let f = try SharedSetupImportFixture(relativeDirectory: "machine/SharedSetupImport")
        _ = try retain(f)
        let machine = try f.accountFixture.open(); defer { try? machine.close() }
        let journal = try f.open()
        XCTAssertThrowsError(try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine)) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        try journal.close()
        let path = f.accountFixture.root.path + "/machine/SharedSetupImport/writer.lock"
        XCTAssertEqual(unlink(path), 0)
        XCTAssertThrowsError(try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine))
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }
    func testUnrecognizedFilesPreventCompatibilityWithoutDeletingThem() throws {
        let f = try SharedSetupImportFixture(relativeDirectory: "machine/SharedSetupImport")
        _ = try retain(f)
        let machine = try f.accountFixture.open(); defer { try? machine.close() }
        let file = URL(fileURLWithPath: f.accountFixture.root.path + "/machine/SharedSetupImport/import-relay-future")
        let bytes = Data("synthetic future format".utf8); try bytes.write(to: file)
        XCTAssertEqual(chmod(file.path, 0o600), 0)
        XCTAssertThrowsError(try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine)) {
            XCTAssertEqual($0 as? SharedSetupImportError, .incompatibleStore)
        }
        XCTAssertEqual(try Data(contentsOf: file), bytes)
    }
    func testReplacingTheWriterInvalidatesAnEarlierSnapshot() throws {
        let f = try SharedSetupImportFixture(relativeDirectory: "machine/SharedSetupImport")
        _ = try retain(f)
        let machine = try f.accountFixture.open(); defer { try? machine.close() }
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine)
        let directory = URL(fileURLWithPath: f.accountFixture.root.path + "/machine/SharedSetupImport")
        let writer = directory.appendingPathComponent("writer.lock"), saved = directory.appendingPathComponent("saved-writer")
        try FileManager.default.moveItem(at: writer, to: saved)
        try Data().write(to: writer); XCTAssertEqual(chmod(writer.path, 0o600), 0)
        try FileManager.default.removeItem(at: saved)
        XCTAssertThrowsError(try snapshot.requireCurrent(machine: machine)) {
            XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
        }
    }
    func testStorePublicationRejectsASubstitutedAccountBeforeCreatingFiles() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent(), machine = try f.accountFixture.open()
        defer { try? machine.close() }
        let foreign = try f.another(intent, account: 0x72)
        var stages = 0
        XCTAssertThrowsError(try machine.publishSharedImport(foreign, verifyCurrent: {}, didStage: { _ in stages += 1 })) {
            XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope)
        }
        XCTAssertEqual(stages, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.accountFixture.root.path + "/machine/SharedSetupImport"))
    }
    func testStorePublicationRetainsTheExactLocalIntentForReadback() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent(), machine = try f.accountFixture.open()
        defer { try? machine.close() }
        let before = try machine.retainedRuntimeCompatibilityInputs()
        XCTAssertNil(before.sharedImport)
        let result = try machine.publishSharedImport(intent, verifyCurrent: {}, didStage: { _ in })
        XCTAssertEqual(result, intent)
        let read = try machine.withSharedImportJournal { try $0?.current(scope: f.scope) }
        XCTAssertEqual(read, intent)
        let after = try machine.retainedRuntimeCompatibilityInputs()
        XCTAssertEqual(before.schemaVersion, after.schemaVersion)
        XCTAssertEqual(before.inventory, after.inventory)
        XCTAssertEqual(before.runtimes, after.runtimes)
        XCTAssertEqual(before.gateways, after.gateways)
        XCTAssertNotNil(after.sharedImport)
    }
}
