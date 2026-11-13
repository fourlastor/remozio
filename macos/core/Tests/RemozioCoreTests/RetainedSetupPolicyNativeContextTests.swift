import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned controls prove validation and scope lifetime. Installed Root custody and the native commit remain attended checks.
final class RetainedSetupPolicyNativeContextTests: XCTestCase {
    private typealias Native = MachineUpdateRetainedSetupPolicyNativeContext
    private typealias Fixture = RetainedPolicyWriterFixture
    private enum Fault: Error { case injected }
    private final class Trace {
        var events: [String] = []
        var fail: String?
        var activity: Native.Verify?
        var services: ((Native.Snapshot) throws -> Void)?
        func event(_ name: String) throws { events.append(name); if fail == name { throw Fault.injected } }
    }
    private final class ThreadUse: @unchecked Sendable {
        let context: Native.Context
        let snapshot: Native.Snapshot
        var error: Error?
        init(_ context: Native.Context, _ snapshot: Native.Snapshot) { self.context = context; self.snapshot = snapshot }
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(body)
    }
    private func snapshot(_ f: Fixture) throws -> Native.Snapshot {
        try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
    }
    private func controls(_ f: Fixture, _ trace: Trace) -> Native.Controls {
        .init(validateCustody: { try trace.event("custody") }, inspectRelease: {
            try trace.event("release"); return f.candidate
        }, validateExecutingCode: { try trace.event("code") }, lookupOwner: { _ in
            try trace.event("owner"); return f.source.runtime.setup.owner
        }, validateServices: { frame in try trace.event("services"); try trace.services?(frame) }, readMaterial: { _ in
            try trace.event("material"); return try f.material.encoded
        }, validateActivity: { _, _, current in
            try trace.event("activity"); trace.activity = current; try current()
        })
    }
    private func scope(_ f: Fixture, trace: Trace, _ body: (Native.Context) throws -> Void) throws {
        try Native.withOwnedContext(expected: snapshot(f), candidate: f.candidate,
            currentCodePolicy: f.source.policy.startupPolicy, controls: controls(f, trace), perform: body)
    }

    func testOrdinaryIdentityRefusesBeforeOpeningAnyNativePath() throws {
        try fixture { f in
            XCTAssertNotEqual(getuid(), 0)
            XCTAssertThrowsError(try Native.withNativeScope(machineDirectory: "/does-not-exist", expected: snapshot(f),
                candidate: f.candidate, currentCodePolicy: f.source.policy.startupPolicy) { _ in
                    XCTFail("An ordinary identity acquired native custody")
                }) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
            XCTAssertNoThrow(try f.machine().inventory())
        }
    }

    func testOwnedScopeVerifiesActualRetentionFramesWithoutQueryingTheOpenTransaction() throws {
        try fixture { f in
            let before = try snapshot(f), prepared = try MachineUpdateRetainedSetupPolicyIntentRecord(source: f.source)
            let trace = Trace(); var stages: [PreparationIntentStore.CompletionIntentStorageStage] = []
            try scope(f, trace: trace) { context in
                _ = try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: before, candidate: f.candidate,
                    directory: f.directory, admission: f.admission, verifyScoped: { stage, actual in
                        stages.append(stage); try context.verify(actual)
                        if stage == .inTransaction || stage == .afterMutation {
                            XCTAssertThrowsError(try self.snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
                        }
                    })
                try context.verify(snapshot(f))
            }
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(try snapshot(f).intent?.phase, .prepared); try f.verifyPair()
            XCTAssertTrue(trace.events.contains("activity")); XCTAssertTrue(trace.events.contains("code"))
        }
    }

    func testOwnedReleasePinsBothAppAndSetupPolicies() throws {
        try fixture { f in
            let frame = try snapshot(f), policy = f.source.policy.startupPolicy
            XCTAssertNoThrow(try Native.requireRelease(f.candidate, approved: frame, candidate: f.candidate, currentCodePolicy: policy))
            for role in [AuthorityCodeRole.app, .setupController] {
                let missing = try AuthorityCodePolicy(entries: policy.entries.filter { $0.role != role })
                XCTAssertThrowsError(try Native.requireRelease(f.candidate, approved: frame, candidate: f.candidate, currentCodePolicy: missing))
                let changed = try policy.retainingFormat(with: policy.entries.map { e in
                    guard e.role == role else { return e }
                    return try .init(role: e.role, teamID: e.teamID, identifier: e.identifier,
                        installedGeneration: e.installedGeneration, minimumGeneration: e.minimumGeneration,
                        codeDirectoryHash: Data(repeating: 77, count: 20), active: e.active)
                })
                XCTAssertThrowsError(try Native.requireRelease(f.candidate, approved: frame, candidate: f.candidate, currentCodePolicy: changed))
            }
        }
    }

    func testOwnedMaterialRejectsMalformedAndAnotherAccountsValidMaterial() throws {
        try fixture { f in
            let frame = try snapshot(f)
            XCTAssertNoThrow(try Native.requireMaterial(f.material.encoded, approved: frame))
            XCTAssertThrowsError(try Native.requireMaterial(Data(), approved: frame))
            XCTAssertThrowsError(try Native.requireMaterial(f.material.encoded + Data([0]), approved: frame))
            try fixture { other in
                XCTAssertNotEqual(f.source.runtime.preparation.accountID, other.source.runtime.preparation.accountID)
                XCTAssertThrowsError(try Native.requireMaterial(other.material.encoded, approved: frame))
            }
        }
    }

    func testCustodyFailureStopsBeforeAnyExternalReadOrBody() throws {
        try fixture { f in
            let trace = Trace(); trace.fail = "custody"
            XCTAssertThrowsError(try scope(f, trace: trace) { _ in XCTFail("A failed custody check entered the body") }) {
                XCTAssertTrue($0 is Fault)
            }
            XCTAssertEqual(trace.events, ["custody"])
        }
    }

    func testCodeOwnerServicesMaterialAndActivityFailuresNeverEnterTheBody() throws {
        try fixture { f in
            for failed in ["release", "code", "owner", "services", "material", "activity"] {
                let trace = Trace(); trace.fail = failed
                XCTAssertThrowsError(try scope(f, trace: trace) { _ in XCTFail("A failed check entered the body") }) {
                    XCTAssertTrue($0 is Fault)
                }
                XCTAssertTrue(trace.events.contains(failed))
            }
        }
    }

    func testActivityLoansExpireBeforeTheBodyAndContextExpiresAtReturn() throws {
        try fixture { f in
            let trace = Trace(), frame = try snapshot(f); var escaped: Native.Context?
            try scope(f, trace: trace) { context in
                escaped = context
                XCTAssertThrowsError(try XCTUnwrap(trace.activity)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                try context.verify(frame)
            }
            XCTAssertThrowsError(try XCTUnwrap(escaped).verify(frame)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try XCTUnwrap(trace.activity)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testBodyFailureExpiresTheRetainedContext() throws {
        try fixture { f in
            let frame = try snapshot(f); var escaped: Native.Context?
            XCTAssertThrowsError(try scope(f, trace: Trace()) { context in escaped = context; throw Fault.injected }) {
                XCTAssertTrue($0 is Fault)
            }
            XCTAssertThrowsError(try XCTUnwrap(escaped).verify(frame)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testSwallowedRecursiveVerificationExpiresTheContext() throws {
        try fixture { f in
            let trace = Trace(), frame = try snapshot(f); var escaped: Native.Context?
            XCTAssertThrowsError(try scope(f, trace: trace) { context in
                escaped = context
                trace.services = { actual in
                    XCTAssertThrowsError(try context.verify(actual)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                }
                try context.verify(frame)
            }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try XCTUnwrap(escaped).verify(frame)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testForeignThreadRefusesBeforeRunningOwnedControls() throws {
        try fixture { f in
            let trace = Trace(), frame = try snapshot(f)
            try scope(f, trace: trace) { context in
                let before = trace.events.count, use = ThreadUse(context, frame), done = DispatchSemaphore(value: 0)
                Thread.detachNewThread { do { try use.context.verify(use.snapshot) } catch { use.error = error }; done.signal() }
                XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
                XCTAssertEqual(use.error as? JournalLeaseError, .invalidated); XCTAssertEqual(trace.events.count, before)
                try context.verify(frame)
            }
        }
    }
}
