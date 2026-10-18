import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayJournalSetupPreparationTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Harness {
        let fixture: GatewayJournalSetupExchangeTests.Fixture
        var privateModes: [Bool] = []
        var filePins: [GatewayJournalFileIdentity?] = []
        var invalidHost = false
        var invalidServices = false
        init(fresh: Bool = false) throws {
            fixture = try .init()
            if fresh { _ = try fixture.runtime.f.sql("DELETE FROM gateway_journal_preparation_v1") }
        }
        func run(expected: GatewayJournalPreparationState? = nil,
                 stage: (GatewayJournalSetupPreparation.Stage) throws -> Void = { _ in }) throws -> GatewayJournalPreparationState {
            try GatewayJournalSetupPreparation.prepare(machine: fixture.runtime.machine, account: fixture.runtime.account,
                material: fixture.intent.material, configuration: fixture.intent.configuration, expected: expected ?? fixture.state(),
                verifyCurrent: { if self.invalidHost { throw Interrupted() } }, verifyServices: { if self.invalidServices { throw Interrupted() } },
                publishPrivate: { retained, verify in self.privateModes.append(retained); try verify() },
                provisionFiles: { retained, verify in
                    self.filePins.append(retained)
                    return try GatewayJournalFileProvisioning.prepare(parent: self.fixture.parent, processOwner: getuid(),
                        serviceUID: getuid(), serviceGID: getgid(), mode: retained == nil ? .createIfAbsent : .requireExisting,
                        expected: retained, verifyCurrent: verify).identity
                }, didStage: stage)
        }
    }
    func testFreshPreparationRetainsOneIntentAndPreservesTheForegroundRuntime() throws {
        let h = try Harness(fresh: true), inventory = try h.fixture.runtime.machine.inventory()
        let result = try h.run(), intent = try XCTUnwrap(result.intent)
        XCTAssertFalse(result.initialized); XCTAssertNotEqual(intent.id, h.fixture.intent.id)
        XCTAssertEqual(intent.files, h.fixture.intent.files)
        XCTAssertEqual(h.privateModes, [false]); XCTAssertEqual(h.filePins.count, 1); XCTAssertNil(h.filePins[0])
        XCTAssertEqual(try h.fixture.runtime.machine.inventory(), inventory)
        XCTAssertEqual(try h.fixture.runtime.machine.runtimeActivation(accountID: intent.accountID).plan?.encoded, try h.fixture.runtime.plan.encoded)
        XCTAssertEqual(try h.run(), result); XCTAssertEqual(h.privateModes, [false, true])
        XCTAssertEqual(h.filePins.last!, intent.files)
        XCTAssertEqual(try h.fixture.runtime.f.sql("SELECT COUNT(*) FROM gateway_journal_preparation_v1"), 1)
    }
    func testEveryInterruptedStageRetainsOrRecoversTheSameFilesAndIntent() throws {
        for stop in [GatewayJournalSetupPreparation.Stage.privateFilesPublished, .journalFilesPrepared, .intentRetained, .completed] {
            let h = try Harness(fresh: true)
            XCTAssertThrowsError(try h.run(stage: { if $0 == stop { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            let pending = try h.fixture.state()
            let result = try h.run()
            XCTAssertFalse(result.initialized); XCTAssertEqual(result.intent?.files, h.fixture.intent.files)
            if let retained = pending.intent { XCTAssertEqual(result.intent, retained); XCTAssertEqual(h.privateModes.last, true) }
            else { XCTAssertEqual(h.privateModes.last, false) }
        }
    }
    func testPendingPreparationValidatesRetainedFilesAndCannotRecreateMissingStorage() throws {
        let h = try Harness(), path = h.fixture.parent.path + "/Gateway/gateway.sqlite"
        try FileManager.default.removeItem(atPath: path)
        XCTAssertThrowsError(try h.run())
        XCTAssertEqual(h.privateModes, [true]); XCTAssertEqual(h.filePins, [h.fixture.intent.files])
        XCTAssertFalse(FileManager.default.fileExists(atPath: path)); XCTAssertFalse(try h.fixture.state().initialized)
    }
    func testCompletedPreparationDoesNotTouchPrivateFilesOrTheActiveJournalWriter() throws {
        let h = try Harness()
        let report = try GatewayJournalSetupReport.decode(h.fixture.initialize())
        try h.fixture.retainCompletion(report)
        let lease = try ProtectedGatewayLease(anchor: h.fixture.root.path, relativeDirectory: "Service/Gateway", serviceUID: getuid(), ancestorUID: getuid())
        defer { lease.close() }
        XCTAssertTrue(try h.run().initialized)
        XCTAssertTrue(h.privateModes.isEmpty); XCTAssertTrue(h.filePins.isEmpty)
    }
    func testStaleExpectedStateCannotPublishOrProvision() throws {
        let h = try Harness()
        XCTAssertThrowsError(try h.run(expected: .init(intent: nil, initialized: false))) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
        XCTAssertTrue(h.privateModes.isEmpty); XCTAssertTrue(h.filePins.isEmpty)
        XCTAssertEqual(try h.fixture.state().intent, h.fixture.intent)
    }
    func testChangedHostAfterProvisioningDoesNotRetainAnIntent() throws {
        let h = try Harness(fresh: true)
        XCTAssertThrowsError(try h.run(stage: { if $0 == .journalFilesPrepared { h.invalidHost = true } })) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertNil(try h.fixture.state().intent)
        h.invalidHost = false
        XCTAssertEqual(try h.run().intent?.files, h.fixture.intent.files)
    }
    func testChangedServicesAfterPublicationOrProvisioningCannotRetainAnIntent() throws {
        for stop in [GatewayJournalSetupPreparation.Stage.privateFilesPublished, .journalFilesPrepared] {
            let h = try Harness(fresh: true)
            XCTAssertThrowsError(try h.run(stage: { if $0 == stop { h.invalidServices = true } })) {
                XCTAssertTrue($0 is Interrupted)
            }
            XCTAssertNil(try h.fixture.state().intent)
            h.invalidServices = false
            XCTAssertEqual(try h.run().intent?.files, h.fixture.intent.files)
        }
    }
    func testCompletedRetryStillValidatesServiceIdentitiesWithoutOpeningTheJournal() throws {
        let h = try Harness()
        try h.fixture.retainCompletion(.decode(h.fixture.initialize()))
        h.invalidServices = true
        XCTAssertThrowsError(try h.run()) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertTrue(h.privateModes.isEmpty); XCTAssertTrue(h.filePins.isEmpty)
        XCTAssertTrue(try h.fixture.state().initialized)
    }
    func testNativeEntryRejectsAnOrdinaryCallerBeforeFilesystemAccess() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner native entry refusal") }
        let h = try Harness()
        XCTAssertThrowsError(try GatewayJournalSetupPreparation.prepare(machine: h.fixture.runtime.machine,
            account: h.fixture.runtime.account, material: h.fixture.intent.material, configuration: h.fixture.intent.configuration,
            expected: h.fixture.state(), verifyCurrent: { XCTFail("Native Root guard must run first") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
