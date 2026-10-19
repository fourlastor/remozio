import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayRuntimeActivationRootOperationTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Fixture {
        let f: GatewayJournalSetupExchangeTests.Fixture
        let identity: LocalAccountIdentity
        let initial: SetupGatewayActivationProgress
        let selected: GatewayRuntimeActivationSettings
        var registrations = 0
        var publications = 0
        var loseReply = false
        var refuseHost = false
        init() throws {
            f = try .init(); try f.retainCompletion(.decode(f.initialize())); identity = f.runtime.f.identity
            selected = try .init(wakePollMilliseconds: 2000, wakeTimeoutMilliseconds: 6000)
            let machine = f.runtime.machine, account = f.runtime.account
            let setup = try SetupGatewayProgress(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
                activation: machine.runtimeActivation(accountID: account.accountID), material: machine.gatewayPreparation(accountID: account.accountID), journal: f.state())
            initial = try .init(setup: setup, state: machine.gatewayRuntimeActivation(accountID: account.accountID))
            try machine.close()
        }
        func read() throws -> SetupGatewayActivationProgress {
            let machine = try f.runtime.f.open(); defer { try? machine.close() }; let account = f.runtime.account
            let setup = try SetupGatewayProgress(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
                activation: machine.runtimeActivation(accountID: account.accountID), material: machine.gatewayPreparation(accountID: account.accountID),
                journal: machine.gatewayJournalPreparation(accountID: account.accountID))
            return try .init(setup: setup, state: machine.gatewayRuntimeActivation(accountID: account.accountID))
        }
        var operations: GatewayRuntimeActivationOperations {
            .init(verifyInitializerAbsent: { _, verify in
                try verify(); let extra = try self.f.runtime.f.open(); try extra.close(); try verify()
            }, prepare: { context, _, verify in
                try verify(); self.publications += 1
                XCTAssertEqual(context.plan.extensions.transport.wake?.pollMilliseconds, self.selected.wakePollMilliseconds)
                XCTAssertEqual(context.plan.extensions.transport.wake?.wake.timeoutMilliseconds, self.selected.wakeTimeoutMilliseconds)
                try verify()
            }, validate: { _, verify in try verify() }, register: { job, verify in
                try verify(); let machine = try self.f.runtime.f.open(); defer { try? machine.close() }
                XCTAssertTrue(try XCTUnwrap(machine.inventory()).services.contains(job.declaration)); try machine.close()
                self.registrations += 1
                if self.loseReply { self.loseReply = false; throw Interrupted() }
                try verify()
            })
        }
        func run(_ expected: SetupGatewayActivationProgress? = nil, settings: GatewayRuntimeActivationSettings? = nil,
                 ownerUID: UInt32? = nil) throws -> SetupGatewayActivationProgress {
            try GatewayRuntimeActivationRootOperation.resume(ownerUID: ownerUID ?? identity.uid, expected: expected ?? initial,
                settings: settings ?? selected, openMachine: { try self.f.runtime.f.open() }, verifyHost: { inventory in
                    if self.refuseHost { throw Interrupted() }
                    guard inventory.releaseDigest == self.f.runtime.f.release else { throw AdministrativeSetupError.changedInstallation }
                }, lookupAccount: { uid in guard uid == self.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return self.identity }, operations: operations)
        }
    }
    func testScopedFactoryCompletesWithSelectedTimingsAndAReleasedWriter() throws {
        let f = try Fixture(), done = try f.run()
        XCTAssertTrue(done.filesPublished); XCTAssertTrue(done.jobRegistered); XCTAssertEqual(done.settings, f.selected)
        XCTAssertNotNil(done.planDigest); XCTAssertEqual(try f.read(), done)
        let machine = try f.f.runtime.f.open(); defer { try? machine.close() }
        XCTAssertTrue(try machine.runtimeActivation(accountID: f.f.intent.accountID).jobsRegistered)
        XCTAssertEqual(try machine.gatewayJournalPreparation(accountID: f.f.intent.accountID).intent, f.f.intent)
        XCTAssertEqual(f.registrations, 1)
    }
    func testWrongCallerAndForeignProgressCannotPublishOrAdvanceTheSchema() throws {
        let f = try Fixture(), other = try Fixture()
        XCTAssertThrowsError(try f.run(ownerUID: getuid() + 1))
        XCTAssertThrowsError(try f.run(other.initial))
        XCTAssertEqual(f.publications, 0); XCTAssertEqual(f.registrations, 0); XCTAssertEqual(try f.read(), f.initial)
        XCTAssertEqual(try f.f.runtime.f.sql("PRAGMA user_version"), 9)
    }
    func testLostReplyRequiresFreshProgressThenResumesTheSamePlan() throws {
        let f = try Fixture(); f.loseReply = true
        XCTAssertThrowsError(try f.run()) { XCTAssertTrue($0 is Interrupted) }
        let pending = try f.read(); XCTAssertTrue(pending.filesPublished); XCTAssertFalse(pending.jobRegistered)
        XCTAssertEqual(pending.settings, f.selected)
        XCTAssertThrowsError(try f.run()) { XCTAssertEqual($0 as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(f.registrations, 1)
        let done = try f.run(pending); XCTAssertTrue(done.jobRegistered); XCTAssertEqual(done.planDigest, pending.planDigest)
    }
    func testChangedTimingCannotReplaceACommittedPlanOrClearItsMarkers() throws {
        let f = try Fixture(), done = try f.run(), different = try GatewayRuntimeActivationSettings(wakePollMilliseconds: 3000)
        let registrations = f.registrations, publications = f.publications
        XCTAssertThrowsError(try f.run(done, settings: different)) { XCTAssertEqual($0 as? GatewayPreparationError, .conflictingMaterial) }
        XCTAssertEqual(try f.read(), done); XCTAssertEqual(f.registrations, registrations); XCTAssertEqual(f.publications, publications)
        XCTAssertEqual(try f.run(done), done)
    }
    func testFailedHostVerificationLeavesTheInitialStateAndSchemaUnchanged() throws {
        let f = try Fixture(); f.refuseHost = true
        XCTAssertThrowsError(try f.run()) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertEqual(try f.read(), f.initial); XCTAssertEqual(try f.f.runtime.f.sql("PRAGMA user_version"), 9)
        XCTAssertEqual(f.publications, 0); XCTAssertEqual(f.registrations, 0)
    }
    func testNativeFactoryRejectsOrdinaryProcessesBeforeAnyHostAccess() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary-owner refusal") }
        let f = try Fixture()
        XCTAssertThrowsError(try GatewayRuntimeActivationRootOperation.resumeNative(machineDirectory: "/must-not-open", macID: f.initial.setup.macID,
            ownerUID: getuid(), expected: f.initial, settings: f.selected, verifyHost: { _ in XCTFail("Root check must run first") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
    }
}
