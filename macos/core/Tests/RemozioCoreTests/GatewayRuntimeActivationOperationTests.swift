import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayRuntimeActivationOperationTests: XCTestCase {
    override class func tearDown() {
        defer { super.tearDown() }
        do { try GatewayRuntimeActivationTestProfile.writeReport() }
        catch { XCTFail("Could not write opt-in gateway activation test profile") }
    }
    private struct Interrupted: Error {}
    private final class Fixture {
        let profile: GatewayRuntimeActivationTestProfile.Scope
        let f: GatewayJournalSetupExchangeTests.Fixture
        let plan: GatewayRuntimeActivationPlan
        let shared: ProtectedSetupDirectory
        let jobs: ProtectedSetupDirectory
        var activeMachine = false
        var prepareModes: [GatewayRuntimeActivationFiles.Mode] = []
        var registrationCalls = 0
        var registered = false
        var loseRegistrationReply = false
        var refuseRegistration = false
        var initializerAbsent = true
        var initializerInspections = 0
        init(profileLabel: String = #function) throws {
            let profile = GatewayRuntimeActivationTestProfile.scope(profileLabel)
            self.profile = profile
            let f = try profile.measure("fixture.gatewaySetup") {
                try GatewayJournalSetupExchangeTests.Fixture(profile: profile.child("fixture.gatewaySetup"))
            }
            self.f = f
            let report = try profile.measure("fixture.gatewayInitialize") { try f.initialize() }
            try profile.measure("fixture.gatewayRetainCompletion") { try f.retainCompletion(.decode(report)) }
            plan = try profile.measure("fixture.plan") {
                try .init(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()))
            }
            shared = try profile.measure("fixture.sharedDirectory") {
                try .init(anchor: f.root.path, relativePath: "Runtime", owner: getuid(), visibility: .sharedMetadata)
            }
            jobs = try profile.measure("fixture.jobsDirectory") {
                try .init(anchor: f.root.path, relativePath: "Jobs", owner: getuid(), visibility: .sharedMetadata)
            }
            try profile.measure("fixture.machineClose") { try f.runtime.machine.close() }
        }
        deinit { profile.measure("fixture.directoryClose") { shared.close(); jobs.close() } }
        func use(_ body: (PreparationIntentStore) throws -> Void) throws {
            XCTAssertFalse(activeMachine)
            let machine = try profile.measure("machine.open") { try f.runtime.f.open() }; activeMachine = true
            defer { try? profile.measure("machine.close") { try machine.close() }; activeMachine = false }
            try profile.measure("machine.body") { try body(machine) }
        }
        func state() throws -> GatewayRuntimeActivationState {
            try profile.measure("assertion.state") {
                var result: GatewayRuntimeActivationState?
                try use { result = try $0.gatewayRuntimeActivation(accountID: self.plan.accountID) }; return try XCTUnwrap(result)
            }
        }
        func inventory() throws -> InstallationInventory {
            try profile.measure("assertion.inventory") {
                var result: InstallationInventory?; try use { result = try $0.inventory() }; return try XCTUnwrap(result)
            }
        }
        func files(_ context: GatewayRuntimeActivationContext, _ mode: GatewayRuntimeActivationFiles.Mode,
                   _ verify: () throws -> Void) throws {
            XCTAssertTrue(activeMachine)
            try profile.measure(mode == .publishPending ? "files.publishPending" : "files.validateRetained") {
                _ = try GatewayRuntimeActivationFiles.publish(context.plan, journal: context.journal, foreground: context.foreground,
                    inventory: context.inventory, shared: shared, jobs: jobs, owner: getuid(), mode: mode,
                    verifyCurrent: { try self.profile.measure("files.verifyCurrent", verify) })
            }
        }
        var operations: GatewayRuntimeActivationOperations {
            .init(verifyInitializerAbsent: { context, verify in
                try self.profile.measure("initializer.callback") {
                    XCTAssertFalse(self.activeMachine); try self.profile.measure("initializer.verify", verify); XCTAssertFalse(self.activeMachine)
                    XCTAssertEqual(try context.plan.encoded, try self.plan.encoded)
                    self.initializerInspections += 1
                    guard self.initializerAbsent else { throw GatewayPreparationError.incomplete }
                    try self.profile.measure("initializer.verify", verify); XCTAssertFalse(self.activeMachine)
                }
            }, prepare: { context, mode, verify in
                self.prepareModes.append(mode); try self.files(context, mode, verify)
            }, validate: { try self.files($0, .validateRetained, $1) }, register: { job, verify in
                try self.profile.measure("registration.callback") {
                    XCTAssertFalse(self.activeMachine)
                    XCTAssertEqual(try job.bytes, try self.plan.gatewayJob.bytes)
                    try self.profile.measure("registration.verify", verify); XCTAssertFalse(self.activeMachine)
                    try self.use { machine in
                        let state = try machine.gatewayRuntimeActivation(accountID: self.plan.accountID)
                        XCTAssertTrue(state.filesPublished)
                        XCTAssertTrue(try XCTUnwrap(machine.inventory()).services.contains(job.declaration))
                    }
                    self.registrationCalls += 1
                    if self.refuseRegistration { throw Interrupted() }
                    self.registered = true
                    if self.loseRegistrationReply { self.loseRegistrationReply = false; throw Interrupted() }
                    try self.profile.measure("registration.verify", verify); XCTAssertFalse(self.activeMachine)
                }
            })
        }
        func run(verify: (PreparationIntentStore) throws -> Void = { _ in },
                 stage: (GatewayRuntimeActivationOperation.Stage) throws -> Void = { _ in }) throws -> GatewayRuntimeActivationState {
            try profile.measure("run") {
                try GatewayRuntimeActivationOperation.resume(plan: plan, withMachine: use,
                    verifyScope: { machine in try self.profile.measure("run.verifyScope") { try verify(machine) } },
                    operations: operations, didStage: stage)
            }
        }
    }
    func testCompleteOperationPublishesOnlyTheOptionalGatewayAndReleasesTheWriterBeforeRegistration() throws {
        let f = try Fixture(), original = try f.inventory(), state = try f.run(), enrolled = try f.inventory()
        XCTAssertTrue(state.filesPublished); XCTAssertTrue(state.jobRegistered); XCTAssertTrue(f.registered)
        XCTAssertFalse(f.activeMachine); XCTAssertEqual(f.registrationCalls, 1)
        XCTAssertEqual(try state.plan?.encoded, try f.plan.encoded)
        XCTAssertEqual(enrolled.accounts, original.accounts)
        XCTAssertEqual(enrolled.services.filter { $0.role != .notificationGateway }, original.services)
        XCTAssertEqual(enrolled.services.count, original.services.count + 1)
        XCTAssertEqual(f.prepareModes, [.publishPending])
        _ = try f.run(); XCTAssertEqual(f.prepareModes, [.publishPending, .validateRetained]); XCTAssertEqual(try f.inventory(), enrolled)
    }
    func testEveryInterruptedStageResumesTheSameIntentAndArtifacts() throws {
        for interrupted in GatewayRuntimeActivationOperation.Stage.allCases {
            let f = try Fixture(profileLabel: "testEveryInterruptedStageResumesTheSameIntentAndArtifacts.\(interrupted)")
            XCTAssertThrowsError(try f.run(stage: { if $0 == interrupted { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertFalse(f.activeMachine)
            let retained = try f.state(); XCTAssertEqual(try retained.plan?.encoded, try f.plan.encoded)
            let state = try f.run(); XCTAssertTrue(state.jobRegistered); XCTAssertTrue(state.filesPublished)
        }
    }
    func testLostRegistrationReplyLeavesPublicationAndEnrollmentForMatchingRetry() throws {
        let f = try Fixture(); f.loseRegistrationReply = true
        XCTAssertThrowsError(try f.run()); XCTAssertTrue(f.registered)
        let pending = try f.state(), inventory = try f.inventory()
        XCTAssertTrue(pending.filesPublished); XCTAssertFalse(pending.jobRegistered)
        XCTAssertTrue(try f.run().jobRegistered); XCTAssertEqual(try f.inventory(), inventory)
        XCTAssertEqual(f.prepareModes, [.publishPending, .validateRetained])
    }
    func testRegistrationFailureDoesNotClaimCompletionOrUndoPublishedForegroundState() throws {
        let f = try Fixture(); f.refuseRegistration = true
        XCTAssertThrowsError(try f.run()); XCTAssertFalse(f.registered)
        XCTAssertTrue(try f.state().filesPublished); XCTAssertFalse(try f.state().jobRegistered)
        XCTAssertTrue(try f.inventory().services.contains { $0.role == .notificationGateway })
        f.refuseRegistration = false; XCTAssertTrue(try f.run().jobRegistered)
    }
    func testFailedHostVerificationCannotRetainAnIntentOrPublishFiles() throws {
        let f = try Fixture(), original = try f.inventory()
        XCTAssertThrowsError(try f.run(verify: { _ in throw Interrupted() })) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertNil(try f.state().plan); XCTAssertEqual(try f.inventory(), original)
        XCTAssertEqual(f.registrationCalls, 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.shared.path), [])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.jobs.path), [])
    }
    func testPresentOrUncertainInitializerBlocksPublicationAndCanRetryAfterAbsence() throws {
        let f = try Fixture(), inventory = try f.inventory(); f.initializerAbsent = false
        XCTAssertThrowsError(try f.run())
        XCTAssertEqual(f.registrationCalls, 0); XCTAssertEqual(try f.inventory(), inventory)
        XCTAssertFalse(try f.state().filesPublished); XCTAssertFalse(try f.state().jobRegistered)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.shared.path), [])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.jobs.path), [])
        f.initializerAbsent = true; XCTAssertTrue(try f.run().jobRegistered)
    }
    func testAnInitializerAppearingAfterPublicationPreventsNormalRegistration() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .inventoryEnrolled { f.initializerAbsent = false } }))
        XCTAssertEqual(f.registrationCalls, 0); XCTAssertTrue(try f.state().filesPublished)
        XCTAssertFalse(try f.state().jobRegistered)
        f.initializerAbsent = true; XCTAssertTrue(try f.run().jobRegistered)
    }
    func testAnInitializerAppearingAfterRegistrationDoesNotRetainCompletion() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.run(stage: { if $0 == .jobRegistered { f.initializerAbsent = false } }))
        XCTAssertTrue(f.registered); XCTAssertFalse(try f.state().jobRegistered)
        f.initializerAbsent = true; XCTAssertTrue(try f.run().jobRegistered)
    }
    func testMissingPublishedFileRefusesInsteadOfRepairingOrRegistering() throws {
        let f = try Fixture(); _ = try f.run(); let calls = f.registrationCalls
        let path = f.shared.path + "/" + AdministrativeSetupPublication.File.transportGatewayRuntime.name
        try FileManager.default.removeItem(atPath: path)
        XCTAssertThrowsError(try f.run()); XCTAssertEqual(f.registrationCalls, calls)
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        XCTAssertTrue(try f.state().jobRegistered)
    }
}
