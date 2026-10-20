import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Injected operations write owned store markers. Native files, launchd and Root admission need separate validation.
final class SharedSetupImportGatewayRuntimeOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    private final class Harness: @unchecked Sendable {
        struct State {
            var initializeCalls = 0, initializeEffects = 0, activateCalls = 0, activateEffects = 0
            var cleanup = true, skipInitialization = false, wrongIntent = false, wrongPlan = false
            var failAfterInitialization = false, failAfterActivation = false, changeImport = false, losePrivateFile = false
            var suspendInitialization = false, waiting = false, released = false
            var gate: CheckedContinuation<Void, Never>?
        }
        let fixture: SharedSetupImportGatewayApplicationTests.Fixture
        init() throws { fixture = try .init(prepared: false) }
        let state = Mutex(State())
        func machine<Value>(_ operation: (PreparationIntentStore) throws -> Value) throws -> Value {
            let store = try fixture.core.runtime.f.open(); defer { try? store.close() }; return try operation(store)
        }
        var operations: GatewaySetupImportedRuntimeOperations {
            .init(initialize: { [self] uid, digest, retained, verify in
                state.withLock { $0.initializeCalls += 1 }
                try machine { store in
                    try verify(XCTUnwrap(store.inventory()))
                    try SharedSetupImportGatewayRuntimeScope.validate(machine: store, account: fixture.core.runtime.account, expected: retained)
                    XCTAssertEqual(uid, getuid()); XCTAssertEqual(digest, try fixture.core.intent.digest)
                    if !state.withLock({ $0.skipInitialization }), !(try fixture.core.state(store).initialized) {
                        _ = try store.completeGatewayJournalInitialization(fixture.core.intent,
                            head: .init(registration: fixture.core.intent.configuration.registration, revision: 0, receipt: nil))
                        state.withLock { $0.initializeEffects += 1 }
                    }
                    if state.withLock({ $0.changeImport }) {
                        try store.withSharedImportJournal { journal in
                            _ = try XCTUnwrap(journal).advance(retained, to: .relayPrepared)
                        }
                    }
                }
                if state.withLock({ $0.losePrivateFile }) {
                    XCTAssertEqual(unlink(fixture.core.parent.path + "/gateway-provider.json"), 0)
                }
                if state.withLock({ $0.suspendInitialization }) {
                    await withCheckedContinuation { gate in
                        let released = state.withLock { value in
                            if value.released { return true }
                            value.gate = gate; value.waiting = true; return false
                        }
                        if released { gate.resume() }
                    }
                }
                if state.withLock({ $0.failAfterInitialization }) { throw Interrupted() }
                return .init(intentDigest: state.withLock { $0.wrongIntent } ? Data(repeating: 9, count: 32) : digest,
                    cleanupComplete: state.withLock { $0.cleanup })
            }, activate: { [self] uid, expected, settings, retained, verify in
                state.withLock { $0.activateCalls += 1 }
                let digest = try machine { store -> Data in
                    try verify(XCTUnwrap(store.inventory())); XCTAssertEqual(uid, getuid())
                    try SharedSetupImportGatewayRuntimeScope.validate(machine: store, account: fixture.core.runtime.account,
                        expected: retained, activationSettings: settings)
                    let current = try store.gatewayRuntimeActivation(accountID: fixture.core.runtime.account.accountID)
                    let plan = try current.plan ?? GatewayRuntimeActivationPlan(journal: fixture.core.state(store),
                        foreground: fixture.core.runtime.plan, inventory: XCTUnwrap(store.inventory()),
                        wakePollMilliseconds: settings.wakePollMilliseconds, wakeTimeoutMilliseconds: settings.wakeTimeoutMilliseconds)
                    if !current.jobRegistered {
                        try store.retainGatewayRuntimeActivation(plan); try store.markGatewayRuntimePublished(plan)
                        _ = try store.enrollGatewayRuntimeActivation(plan); try store.markGatewayRuntimeRegistered(plan)
                        state.withLock { $0.activateEffects += 1 }
                    }
                    return try plan.digest
                }
                if state.withLock({ $0.failAfterActivation }) { throw Interrupted() }
                return .init(planDigest: state.withLock { $0.wrongPlan } ? Data(repeating: 7, count: 32) : digest)
            })
        }
        func owner(proposal: PortableSetup? = nil) throws -> SetupAccountOwner {
            try fixture.owner(proposal: proposal, importedRuntime: operations)
        }
        func progress(_ owner: SetupAccountOwner) throws -> SetupPortableImportProgress {
            try XCTUnwrap(owner.portableImportProgress(callerUID: getuid()))
        }
        func validate(_ machine: PreparationIntentStore, _ account: AccountPreparationIntent, _ choices: GatewaySetupPreparationChoices,
                      _ selection: GatewayRuntimeSettingsSelection, _ verify: () throws -> Void) throws {
            XCTAssertEqual(account.accountID, fixture.core.runtime.account.accountID)
            try fixture.validate(on: machine, choices: choices, selection: selection, verify: verify)
        }
        func prepare(_ owner: SetupAccountOwner) throws -> SetupPortableImportProgress {
            try owner.prepareImportedGateway(callerUID: getuid(), expected: progress(owner), proposal: fixture.proposal(),
                fileWakeCustodyAccepted: true, prepare: { [self] machine, _, _, _, verify in try verify(); try fixture.prepare(on: machine) },
                validate: validate)
        }
        func run(_ owner: SetupAccountOwner, _ expected: SetupPortableImportProgress) async throws -> SetupImportedGatewayRuntimeResult {
            try await owner.resumeImportedGateway(callerUID: getuid(), expected: expected, proposal: fixture.proposal(), validatePrepared: validate)
        }
        func release() { state.withLock { s in s.released = true; let gate = s.gate; s.gate = nil; return gate }?.resume() }
    }
    func testInitializationAndActivationUseReadbackWithoutCompletingTheImport() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.prepare(owner), result = try await h.run(owner, expected)
        XCTAssertEqual(result.progress, expected); XCTAssertEqual(result.progress.phase, .gatewayPrepared)
        XCTAssertTrue(result.cleanupComplete); XCTAssertTrue(try XCTUnwrap(result.activation).jobRegistered)
        XCTAssertEqual(try h.progress(owner), expected)
        _ = try await h.run(owner, expected)
        XCTAssertEqual(h.state.withLock { $0.initializeEffects }, 1); XCTAssertEqual(h.state.withLock { $0.activateEffects }, 1)
    }
    func testPendingInitializerCleanupStopsBeforeActivationAndAllowsExplicitRetry() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.prepare(owner); h.state.withLock { $0.cleanup = false }
        let pending = try await h.run(owner, expected)
        XCTAssertFalse(pending.cleanupComplete); XCTAssertNil(pending.activation); XCTAssertEqual(h.state.withLock { $0.activateCalls }, 0)
        h.state.withLock { $0.cleanup = true }; let result = try await h.run(owner, expected)
        XCTAssertTrue(result.cleanupComplete); XCTAssertEqual(h.state.withLock { $0.initializeEffects }, 1)
    }
    func testAnInitializationReportCannotSubstituteForTheDurableMarker() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.prepare(owner); h.state.withLock { $0.skipInitialization = true }
        do { _ = try await h.run(owner, expected); XCTFail() } catch {}
        XCTAssertEqual(h.state.withLock { $0.activateCalls }, 0); XCTAssertEqual(try h.progress(owner), expected)
    }
    func testAReportForAnotherIntentCannotStartActivation() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.prepare(owner); h.state.withLock { $0.wrongIntent = true }
        do { _ = try await h.run(owner, expected); XCTFail() } catch {}
        XCTAssertEqual(h.state.withLock { $0.activateCalls }, 0)
    }
    func testAnActivationReportMustMatchTheRetainedPlan() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.prepare(owner); h.state.withLock { $0.wrongPlan = true }
        do { _ = try await h.run(owner, expected); XCTFail() } catch {}
        XCTAssertEqual(try h.progress(owner), expected); XCTAssertEqual(h.state.withLock { $0.activateEffects }, 1)
    }
    func testUnknownInitializationOutcomeRequiresReadbackAndNoAutomaticRetry() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.prepare(owner); h.state.withLock { $0.failAfterInitialization = true }
        do { _ = try await h.run(owner, expected); XCTFail() } catch { XCTAssertTrue(error is Interrupted) }
        XCTAssertEqual(h.state.withLock { $0.initializeCalls }, 1); XCTAssertEqual(h.state.withLock { $0.activateCalls }, 0)
        h.state.withLock { $0.failAfterInitialization = false }; _ = try await h.run(owner, expected)
        XCTAssertEqual(h.state.withLock { $0.initializeEffects }, 1)
    }
    func testUnknownActivationOutcomeDoesNotRepeatActivationEffectsOnExplicitRetry() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.prepare(owner); h.state.withLock { $0.failAfterActivation = true }
        do { _ = try await h.run(owner, expected); XCTFail() } catch { XCTAssertTrue(error is Interrupted) }
        XCTAssertEqual(h.state.withLock { $0.activateCalls }, 1); XCTAssertEqual(try h.progress(owner), expected)
        h.state.withLock { $0.failAfterActivation = false }; _ = try await h.run(owner, expected)
        XCTAssertEqual(h.state.withLock { $0.activateEffects }, 1)
    }
    func testAnImportRevisionChangedBetweenOperationsStopsActivation() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.prepare(owner); h.state.withLock { $0.changeImport = true }
        do { _ = try await h.run(owner, expected); XCTFail() } catch {}
        XCTAssertEqual(h.state.withLock { $0.activateCalls }, 0); XCTAssertEqual(try h.progress(owner).phase, .relayPrepared)
    }
    func testMissingPrivateFilesAfterInitializationAreNotRepairedOrActivated() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.prepare(owner); h.state.withLock { $0.losePrivateFile = true }
        do { _ = try await h.run(owner, expected); XCTFail() } catch {}
        XCTAssertEqual(h.state.withLock { $0.activateCalls }, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: h.fixture.core.parent.path + "/gateway-provider.json"))
    }
    func testChangedProposalAndWrongCallerFailBeforeNativeOperations() async throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let expected = try h.prepare(owner), changed = PortableSetup(defaults: h.fixture.proposal().defaults)
        do { _ = try await owner.resumeImportedGateway(callerUID: getuid(), expected: expected, proposal: changed, validatePrepared: h.validate); XCTFail() } catch {}
        do { _ = try await owner.resumeImportedGateway(callerUID: getuid() + 1, expected: expected, proposal: h.fixture.proposal(), validatePrepared: h.validate); XCTFail() } catch {}
        XCTAssertEqual(h.state.withLock { $0.initializeCalls }, 0); XCTAssertEqual(h.state.withLock { $0.activateCalls }, 0)
    }
    func testCancellationAfterInitializationCannotFallThroughToActivation() async throws {
        let h = try Harness(), owner = try h.owner(); defer { h.release(); try? owner.close() }
        let expected = try h.prepare(owner); h.state.withLock { $0.suspendInitialization = true }
        let operation = Task { @Sendable in try await h.run(owner, expected) }
        defer { operation.cancel(); h.release() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !h.state.withLock({ $0.waiting }) {
            guard ContinuousClock.now < deadline else { XCTFail(); return }
            try await Task.sleep(for: .milliseconds(2))
        }
        operation.cancel(); h.release()
        do { _ = try await operation.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(h.state.withLock { $0.activateCalls }, 0)
    }
    func testProviderFreeImportCannotInventGatewayRuntimeOperations() async throws {
        let h = try Harness(), proposal = PortableSetup(defaults: h.fixture.proposal().defaults), owner = try h.owner(proposal: proposal)
        defer { try? owner.close() }
        let expected = try owner.prepareImportedGateway(callerUID: getuid(), expected: h.progress(owner), proposal: proposal,
            fileWakeCustodyAccepted: false, prepare: { _, _, _, _, _ in XCTFail() }, validate: { _, _, _, _, _ in XCTFail() })
        do { _ = try await owner.resumeImportedGateway(callerUID: getuid(), expected: expected, proposal: proposal, validatePrepared: h.validate); XCTFail() } catch {}
        XCTAssertEqual(h.state.withLock { $0.initializeCalls }, 0); XCTAssertEqual(try h.progress(owner), expected)
    }
}
