import Foundation
import XCTest
@testable import RemozioCore

@MainActor
final class MacGatewaySetupControlsTests: XCTestCase {
    private enum Failure: Error { case lostReply }
    private enum Step: Sendable { case prepare, journal, activate }
    private static let pem = Result { () throws -> String in
        let process = Process(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Failure.lostReply }
        return String(decoding: bytes, as: UTF8.self)
    }
    private struct Snapshots: @unchecked Sendable {
        let fixture: GatewayJournalSetupExchangeTests.Fixture
        let empty: SetupGatewayActivationProgress
        let pending: SetupGatewayActivationProgress
        let journal: SetupGatewayActivationProgress
        let done: SetupGatewayActivationProgress
        init() throws {
            fixture = try .init(); let f = fixture, machine = f.runtime.machine, account = f.runtime.account
            func setup(_ material: GatewayPreparationState, _ journal: GatewayJournalPreparationState) throws -> SetupGatewayProgress {
                try .init(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
                    activation: machine.runtimeActivation(accountID: account.accountID), material: material, journal: journal)
            }
            empty = try .init(setup: setup(.init(reference: nil), .init(intent: nil, initialized: false)), state: .init(plan: nil, filesPublished: false, jobRegistered: false))
            let material = try machine.gatewayPreparation(accountID: account.accountID)
            pending = try .init(setup: setup(material, f.state()), state: .init(plan: nil, filesPublished: false, jobRegistered: false))
            try f.retainCompletion(.decode(f.initialize()))
            let current = try setup(material, f.state())
            journal = try .init(setup: current, state: .init(plan: nil, filesPublished: false, jobRegistered: false))
            let plan = try GatewayRuntimeActivationPlan(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(machine.inventory()))
            done = try .init(setup: current, state: .init(plan: plan, filesPublished: true, jobRegistered: true))
        }
        @MainActor func choices(accepted: Bool = true) throws -> GatewaySetupPreparationChoices {
            let provider = try SetupFCMConfiguration(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
                privateKeyID: "fixture-key", privateKeyPEM: MacGatewaySetupControlsTests.pem.get())
            return try .init(provider: provider, senderID: "123", packageName: "dev.remozio.android",
                settings: fixture.intent.configuration.settings, fileWakeCustodyAccepted: accepted)
        }
    }
    private actor Hold {
        var continuation: CheckedContinuation<Void, Never>?
        func wait(_ started: XCTestExpectation) async {
            await withCheckedContinuation { continuation in self.continuation = continuation; started.fulfill() }
        }
        func release() { continuation?.resume(); continuation = nil }
    }
    private actor Driver: MacGatewaySetupDriver {
        let snapshots: Snapshots
        var state: SetupGatewayActivationProgress?
        var reads = 0, preparations = 0, journals = 0, activations = 0
        var loss: Step?
        var cancelConsent = false
        var missingAfterWrite = false
        var foreignAfterWrite: SetupGatewayActivationProgress?
        var cleanup = true
        var gate: Hold?
        var started: XCTestExpectation?
        init(_ snapshots: Snapshots, initial: SetupGatewayActivationProgress? = nil) {
            self.snapshots = snapshots; state = initial ?? snapshots.empty
        }
        func configure(loss: Step? = nil, cancelConsent: Bool = false, missingAfterWrite: Bool = false,
                       foreignAfterWrite: SetupGatewayActivationProgress? = nil, cleanup: Bool = true) {
            self.loss = loss; self.cancelConsent = cancelConsent; self.missingAfterWrite = missingAfterWrite
            self.foreignAfterWrite = foreignAfterWrite; self.cleanup = cleanup
        }
        func hold(_ gate: Hold, _ started: XCTestExpectation) { self.gate = gate; self.started = started }
        func progress() throws -> SetupGatewayActivationProgress? {
            reads += 1
            if preparations + journals + activations > 0 {
                if missingAfterWrite { return nil }
                if let foreignAfterWrite { return foreignAfterWrite }
            }
            return state
        }
        func prepare(_ expected: SetupGatewayProgress, choices: GatewaySetupPreparationChoices) throws -> SetupGatewayProgress {
            preparations += 1
            if cancelConsent { throw SetupAdministratorAuthorizationError.cancelled }
            guard choices.fileWakeCustodyAccepted, expected == state?.setup else { throw Failure.lostReply }
            state = snapshots.pending; if loss == .prepare { throw Failure.lostReply }; return snapshots.pending.setup
        }
        func initializeJournal(_ expected: SetupGatewayProgress) throws -> SetupGatewayJournalResult {
            journals += 1; guard expected == state?.setup else { throw Failure.lostReply }
            state = snapshots.journal; if loss == .journal { throw Failure.lostReply }
            return try .init(progress: snapshots.journal.setup, cleanupComplete: cleanup)
        }
        func activate(_ expected: SetupGatewayActivationProgress, settings: GatewayRuntimeActivationSettings) async throws -> SetupGatewayActivationProgress {
            activations += 1; guard expected == state else { throw Failure.lostReply }
            if let gate, let started { await gate.wait(started) }
            state = snapshots.done; if loss == .activate { throw Failure.lostReply }; return snapshots.done
        }
        func settingsProgress() throws -> SetupGatewaySettingsProgress? {
            guard let state, state.jobRegistered, let settings = state.settings else { return nil }
            return try .init(activation: state, state: .empty,
                initialSelection: .init(service: snapshots.fixture.intent.configuration.settings, activation: settings),
                supportsSettingsChanges: snapshots.fixture.runtime.plan.consumerHosts != nil)
        }
        func applySettings(_ expected: SetupGatewaySettingsProgress, selection: GatewayRuntimeSettingsSelection) throws -> SetupGatewaySettingsProgress {
            throw Failure.lostReply
        }
        func counts() -> [Int] { [reads, preparations, journals, activations] }
    }
    func testRefreshReadsOnlyAndEveryMutationNeedsAnInitialRead() async throws {
        let snapshots = try Snapshots(), driver = Driver(snapshots), controls = MacGatewaySetupControls(driver: driver)
        await controls.prepare(try snapshots.choices()); await controls.initializeJournal(); await controls.activate(settings: try .init())
        var counts = await driver.counts(); XCTAssertEqual(counts, [0, 0, 0, 0])
        await controls.refresh(); counts = await driver.counts(); XCTAssertEqual(counts, [1, 0, 0, 0])
        XCTAssertTrue(controls.loaded); XCTAssertFalse(controls.working); XCTAssertNil(controls.notice)
    }
    func testEverySetupStageNeedsAnExplicitActionAndRecordsOnlyHistoricalProgress() async throws {
        let snapshots = try Snapshots(), driver = Driver(snapshots), controls = MacGatewaySetupControls(driver: driver)
        await controls.refresh(); await controls.prepare(try snapshots.choices(accepted: false))
        var counts = await driver.counts(); XCTAssertEqual(counts, [1, 0, 0, 0])
        await controls.prepare(try snapshots.choices()); XCTAssertEqual(controls.progress, snapshots.pending)
        await controls.initializeJournal(); XCTAssertEqual(controls.progress, snapshots.journal); XCTAssertEqual(controls.lastJournalCleanupComplete, true)
        await controls.activate(settings: try .init()); XCTAssertEqual(controls.progress, snapshots.done)
        XCTAssertTrue(controls.loaded); XCTAssertNil(controls.notice)
        counts = await driver.counts(); XCTAssertEqual(Array(counts.dropFirst()), [1, 1, 1])
        await controls.refresh(); XCTAssertNil(controls.lastJournalCleanupComplete)
        let after = await driver.counts(); XCTAssertEqual(Array(after.dropFirst()), [1, 1, 1])
    }
    func testLostRepliesRequireFreshProgressBeforeAnyFurtherMutation() async throws {
        for step in [Step.prepare, .journal, .activate] {
            let snapshots = try Snapshots(), initial = step == .prepare ? snapshots.empty : step == .journal ? snapshots.pending : snapshots.journal
            let driver = Driver(snapshots, initial: initial), controls = MacGatewaySetupControls(driver: driver)
            await driver.configure(loss: step); await controls.refresh()
            func act() async throws {
                switch step {
                case .prepare: await controls.prepare(try snapshots.choices())
                case .journal: await controls.initializeJournal()
                case .activate: await controls.activate(settings: try .init())
                }
            }
            try await act(); XCTAssertFalse(controls.loaded); XCTAssertEqual(controls.notice, .operationFailed)
            let before = await driver.counts(); try await act(); let after = await driver.counts(); XCTAssertEqual(after, before)
            await controls.refresh(); XCTAssertTrue(controls.loaded); XCTAssertNil(controls.notice)
            XCTAssertEqual(controls.progress, step == .prepare ? snapshots.pending : step == .journal ? snapshots.journal : snapshots.done)
        }
    }
    func testMissingOrForeignReadAfterPreparationDisablesMutation() async throws {
        for missing in [false, true] {
            let snapshots = try Snapshots(), other = try Snapshots(), driver = Driver(snapshots), controls = MacGatewaySetupControls(driver: driver)
            await driver.configure(missingAfterWrite: missing, foreignAfterWrite: missing ? nil : other.pending)
            await controls.refresh(); await controls.prepare(try snapshots.choices())
            XCTAssertFalse(controls.loaded); XCTAssertEqual(controls.notice, .operationFailed)
            let before = await driver.counts(); await controls.initializeJournal(); let after = await driver.counts(); XCTAssertEqual(after, before)
        }
    }
    func testCancellingAdministratorConsentDoesNotReportFailureOrRetry() async throws {
        let snapshots = try Snapshots(), driver = Driver(snapshots), controls = MacGatewaySetupControls(driver: driver)
        await driver.configure(cancelConsent: true); await controls.refresh(); await controls.prepare(try snapshots.choices())
        XCTAssertFalse(controls.loaded); XCTAssertNil(controls.notice); XCTAssertFalse(controls.working)
        await controls.prepare(try snapshots.choices()); let counts = await driver.counts(); XCTAssertEqual(counts, [1, 1, 0, 0])
    }
    func testChangedRetainedTimingsRequireATransitionWithoutSendingAnotherAction() async throws {
        let snapshots = try Snapshots(), driver = Driver(snapshots, initial: snapshots.done), controls = MacGatewaySetupControls(driver: driver)
        await controls.refresh(); await controls.activate(settings: try .init(wakePollMilliseconds: 2000))
        XCTAssertTrue(controls.loaded); XCTAssertEqual(controls.progress, snapshots.done); XCTAssertEqual(controls.notice, .settingsTransitionRequired)
        let counts = await driver.counts(); XCTAssertEqual(counts, [1, 0, 0, 0])
    }
    func testAnActiveActionBlocksRefreshAndDuplicateActionsUntilItSettles() async throws {
        let snapshots = try Snapshots(), driver = Driver(snapshots, initial: snapshots.journal), controls = MacGatewaySetupControls(driver: driver)
        let gate = Hold(), started = expectation(description: "activation entered"), settings = try GatewayRuntimeActivationSettings()
        await driver.hold(gate, started); await controls.refresh()
        let task = Task { await controls.activate(settings: settings) }
        await fulfillment(of: [started], timeout: 5)
        XCTAssertEqual(controls.operation, .activating); XCTAssertTrue(controls.working)
        let before = await driver.counts()
        await controls.refresh(); await controls.initializeJournal(); await controls.prepare(try snapshots.choices()); await controls.activate(settings: settings)
        let after = await driver.counts(); XCTAssertEqual(after, before)
        await gate.release(); await task.value
        XCTAssertFalse(controls.working); XCTAssertTrue(controls.loaded); XCTAssertEqual(controls.progress, snapshots.done)
    }
    func testPendingCleanupCanBeRetriedExplicitlyAndRefreshDoesNotAssumeAbsence() async throws {
        let snapshots = try Snapshots(), driver = Driver(snapshots, initial: snapshots.pending), controls = MacGatewaySetupControls(driver: driver)
        await driver.configure(cleanup: false); await controls.refresh(); await controls.initializeJournal()
        XCTAssertTrue(try XCTUnwrap(controls.progress).setup.journalInitialized); XCTAssertEqual(controls.lastJournalCleanupComplete, false)
        await driver.configure(cleanup: true); await controls.initializeJournal(); XCTAssertEqual(controls.lastJournalCleanupComplete, true)
        let counts = await driver.counts(); XCTAssertEqual(Array(counts.dropFirst()), [0, 2, 0])
        await controls.refresh(); XCTAssertNil(controls.lastJournalCleanupComplete)
    }
}
