import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewaySetupOwnerTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Harness {
        let fixture: GatewayJournalSetupExchangeTests.Fixture
        let owner: SetupAccountOwner
        var calls = 0
        init(fresh: Bool = false) throws {
            fixture = try .init()
            if fresh { _ = try fixture.runtime.f.sql("DELETE FROM gateway_journal_preparation_v1") }
            let identity = fixture.runtime.f.identity
            owner = try .init(machine: fixture.runtime.machine, expectedReleaseDigest: fixture.runtime.f.release,
                resume: { _, _ in throw Interrupted() }, accountCodePolicy: fixture.runtime.f.policy,
                lookupAccount: { uid in guard uid == identity.uid else { throw AdministrativeSetupError.wrongAccount }; return identity })
        }
        deinit { try? owner.close() }
        func read() throws -> SetupGatewayProgress { try XCTUnwrap(owner.gatewayProgress(callerUID: getuid())) }
        func prepare(_ expected: SetupGatewayProgress, interruptAfterRetain: Bool = false) throws -> SetupGatewayProgress {
            try owner.prepareGateway(callerUID: getuid(), expected: expected) { machine, account, verify in
                self.calls += 1
                XCTAssertThrowsError(try self.fixture.runtime.f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
                try withoutActuallyEscaping(verify) { verify in
                    _ = try GatewayJournalSetupPreparation.prepare(machine: machine, account: account,
                        material: self.fixture.intent.material, configuration: self.fixture.intent.configuration,
                        expected: self.fixture.state(), verifyCurrent: verify, verifyServices: {},
                        publishPrivate: { _, verify in try verify() }, provisionFiles: { retained, verify in
                            try GatewayJournalFileProvisioning.prepare(parent: self.fixture.parent, processOwner: getuid(),
                                serviceUID: getuid(), serviceGID: getgid(), mode: retained == nil ? .createIfAbsent : .requireExisting,
                                expected: retained, verifyCurrent: verify).identity
                        })
                }
                if interruptAfterRetain { throw Interrupted() }
            }
        }
    }
    func testProgressReadsArePassiveAndRevealNoCredentialOrPath() throws {
        let h = try Harness(fresh: true), initial = try h.read()
        XCTAssertNotNil(initial.gatewayMaterialID); XCTAssertNil(initial.journalIntentDigest); XCTAssertFalse(initial.journalInitialized)
        XCTAssertEqual(h.calls, 0); XCTAssertEqual(try h.fixture.runtime.f.sql("SELECT COUNT(*) FROM gateway_journal_preparation_v1"), 0)
        XCTAssertEqual(try h.read(), initial)
        XCTAssertNil(try initial.bytes.range(of: Data(h.fixture.root.path.utf8)))
        XCTAssertNil(try initial.bytes.range(of: h.fixture.runtime.material.transportIdentity))
    }
    func testPreparationUsesTheCurrentAccountAndRetainsOneJournalIntent() throws {
        let h = try Harness(fresh: true), initial = try h.read(), inventory = try h.fixture.runtime.machine.inventory()
        let pending = try h.prepare(initial)
        XCTAssertNotNil(pending.journalIntentDigest); XCTAssertFalse(pending.journalInitialized)
        XCTAssertEqual(pending.gatewayMaterialID, initial.gatewayMaterialID); XCTAssertEqual(pending.foregroundDigest, initial.foregroundDigest)
        XCTAssertEqual(try h.fixture.runtime.machine.inventory(), inventory)
        XCTAssertEqual(try h.prepare(pending), pending); XCTAssertEqual(h.calls, 2)
        XCTAssertEqual(try h.fixture.runtime.f.sql("SELECT COUNT(*) FROM gateway_journal_preparation_v1"), 1)
    }
    func testWrongCallerAndStaleProgressCannotInvokePreparation() throws {
        let h = try Harness(fresh: true), initial = try h.read()
        XCTAssertThrowsError(try h.owner.prepareGateway(callerUID: getuid() + 1, expected: initial, prepare: { _, _, _ in XCTFail() })) {
            XCTAssertEqual($0 as? AdministrativeSetupError, .wrongAccount)
        }
        _ = try h.prepare(initial)
        XCTAssertThrowsError(try h.prepare(initial)) { XCTAssertEqual($0 as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(h.calls, 1)
    }
    func testLostPreparationReplyLeavesReadableProgressAndRejectsTheOldRequest() throws {
        let h = try Harness(fresh: true), initial = try h.read()
        XCTAssertThrowsError(try h.prepare(initial, interruptAfterRetain: true)) { XCTAssertTrue($0 is Interrupted) }
        let retained = try h.read(); XCTAssertNotNil(retained.journalIntentDigest)
        XCTAssertThrowsError(try h.prepare(initial)) { XCTAssertEqual($0 as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(try h.prepare(retained), retained); XCTAssertEqual(h.calls, 2)
    }
    func testAnIncompleteBackendCannotReportPreparationSuccess() throws {
        let h = try Harness(fresh: true), initial = try h.read()
        XCTAssertThrowsError(try h.owner.prepareGateway(callerUID: getuid(), expected: initial, prepare: { _, _, verify in try verify() })) {
            XCTAssertEqual($0 as? AdministrativeSetupChannelError, .invalidMessage)
        }
        XCTAssertEqual(try h.read(), initial)
    }
    func testCompletedRetryDoesNotInvokePreparationOrAcquireTheJournalWriter() throws {
        let h = try Harness()
        try h.fixture.retainCompletion(.decode(h.fixture.initialize()))
        let done = try h.read()
        let lease = try ProtectedGatewayLease(anchor: h.fixture.root.path, relativeDirectory: "Service/Gateway", serviceUID: getuid(), ancestorUID: getuid())
        defer { lease.close() }
        XCTAssertEqual(try h.owner.prepareGateway(callerUID: getuid(), expected: done, prepare: { _, _, _ in XCTFail() }), done)
        XCTAssertEqual(h.calls, 0)
    }
    func testClosedOwnerRefusesReadsAndPreparation() throws {
        let h = try Harness(), initial = try h.read(); try h.owner.close()
        XCTAssertThrowsError(try h.owner.gatewayProgress(callerUID: getuid())) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        XCTAssertThrowsError(try h.owner.prepareGateway(callerUID: getuid(), expected: initial, prepare: { _, _, _ in XCTFail() })) {
            XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable)
        }
    }
    func testAnUnregisteredForegroundRuntimeHasNoGatewaySetupProgress() throws {
        let f = try RuntimeActivationFixture(), identity = f.f.identity
        let owner = try SetupAccountOwner(machine: f.machine, expectedReleaseDigest: f.f.release, resume: { _, _ in throw Interrupted() },
            accountCodePolicy: f.f.policy, lookupAccount: { uid in guard uid == identity.uid else { throw AdministrativeSetupError.wrongAccount }; return identity })
        defer { try? owner.close() }
        XCTAssertNil(try owner.gatewayProgress(callerUID: getuid()))
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 6)
    }
}
