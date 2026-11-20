import Darwin
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

/// Real ordinary-owner SQLite, claims and admission. No installed peer or live Authority is qualified here.
final class RuntimeMaintenanceUnboundWriterTests: XCTestCase {
    private typealias Row = RuntimeMaintenanceWindowRecord
    private typealias Joined = SetupRetainedOrphanClaim.Joined
    private typealias Transition = PreparationIntentStore.RuntimeMaintenanceTransition
    private enum Failure: Error, Equatable { case afterCommit }

    private static func intent(_ f: ExplicitStartupFixture, joined: Joined) throws -> Transition {
        let previous = try XCTUnwrap(f.h.frame().window)
        return try f.h.f.machine().writeRuntimeMaintenanceUnboundIntent(replacing: previous, joined: joined,
            expected: f.h.frame().source.actual, candidate: f.h.f.candidate,
            directory: f.h.f.directory, admission: f.h.f.admission)
    }
    private final class GateDriver: AuthorityMaintenanceClientDriver, Sendable {
        enum Fault: Equatable, Sendable { case none, forged, challenge, incarnation, held, unknown, busy, noncanonical }
        let fault: Fault
        let hold: AuthorityMaintenanceUnboundGateResponse.Hold
        init(fault: Fault, hold: AuthorityMaintenanceUnboundGateResponse.Hold) { self.fault = fault; self.hold = hold }
        func start(_ invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            reply(.hello(AuthorityMaintenanceChannelScope.protocolVersion))
        }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) { reply(.bytes(nil)) }
        func observeIncarnation(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let request = try AuthorityMaintenanceIncarnationRequest.decode(bytes)
                reply(.bytes(try AuthorityMaintenanceIncarnationResponse(request: request,
                    incarnation: Data(repeating: 41, count: 16)).encoded))
            } catch { reply(.bytes(nil)) }
        }
        func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let original = try AuthorityMaintenanceUnboundRequest.decode(bytes)
                let request = try AuthorityMaintenanceUnboundRequest(kind: original.kind,
                    installationID: original.installationID, accountID: original.accountID,
                    attemptID: original.attemptID, revision: original.revision, rowDigest: original.rowDigest,
                    pendingRevision: original.pendingRevision, intentID: original.intentID, gate: original.gate,
                    authorityIncarnation: fault == .incarnation ? Data(repeating: 42, count: 16) : original.authorityIncarnation,
                    challenge: fault == .challenge ? AccountPreparationIntent.randomID() : original.challenge)
                let observedHold: AuthorityMaintenanceUnboundGateResponse.Hold = fault == .held ? .held : fault == .unknown ? .unknown : hold
                let response = try AuthorityMaintenanceUnboundGateResponse(request: request, hold: observedHold,
                    admission: fault == .busy ? .busy : .available).encoded
                if fault == .noncanonical {
                    reply(.bytes(Data([0xb8, 0x05]) + response.dropFirst()))
                } else { reply(.bytes(response)) }
            } catch { reply(.bytes(nil)) }
        }
        func close() {}
    }
    private static func observation(_ f: ExplicitStartupFixture, joined: Joined, row: Row,
        hold: AuthorityMaintenanceUnboundGateResponse.Hold = .neverHeld,
        fault: GateDriver.Fault = .none) async throws -> VerifiedUnboundGateObservation {
        let source = try f.h.frame().source.actual
        let gate = try XCTUnwrap(source.admission.accounts.first { $0.accountID == row.scope.authority.accountID })
        let context = try AuthorityMaintenanceChannelRequest(action: .open, accountID: row.scope.authority.accountID,
            attemptID: row.id, revision: row.revision, installationID: row.scope.installationID,
            gate: gate.identity, binding: nil, challenge: AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID())
        let client = try AuthorityMaintenanceXPCClient.openOwned(context: context,
            driver: GateDriver(fault: fault, hold: hold), verify: {
                if fault == .forged { throw RuntimePreparationError.changedScope }
            })
        do {
            let result = try await client.observeUnboundGate(joined: joined, row: row, gate: gate.identity,
                until: .now.advanced(by: RuntimeMaintenanceExplicitRestorationTests.unboundPhaseBudget))
            await client.close(); return result
        } catch { await client.close(); throw error }
    }
    private static func complete(_ f: ExplicitStartupFixture, joined: Joined,
        observation: VerifiedUnboundGateObservation) throws -> Transition {
        let frame = try f.h.frame(), previous = try XCTUnwrap(frame.window)
        return try f.h.f.machine().writeRuntimeMaintenanceUnboundCompletion(replacing: previous,
            joined: joined, observation: observation, expected: frame.source.actual,
            candidate: f.h.f.candidate, directory: f.h.f.directory, admission: f.h.f.admission)
    }
    private func fixture(_ body: @escaping @Sendable (ExplicitStartupFixture) async throws -> Void) throws {
        try RuntimeMaintenanceExplicitRestorationTests().withFixture(body)
    }

    func testTypedWriterNormalizesNeverHeldWithoutSettlingTheReservation() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let receipt = try await phases.run { try Self.intent(f, joined: joined) }
            XCTAssertEqual(receipt.record.formatVersion, 3)
            let observation = try await Self.observation(f, joined: joined, row: receipt.record)
            let completed = try await phases.run { try Self.complete(f, joined: joined, observation: observation) }
            XCTAssertEqual(completed.record.phase, .restored)
            XCTAssertEqual(completed.record.formatVersion, 1)
            XCTAssertEqual(completed.record.gate?.hold, .released)
            XCTAssertNil(completed.record.unboundRelease)
            f.retained.assertHeld()
        }
    }
    func testAuthorizedRecoveryNeedsItsSeparateActualReceipt() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let a = f.h.initial
            let recovery = try RuntimeMaintenanceStartupPolicy.row(a, phase: .needsOwnerRecovery,
                service: .notStopped, failure: .cleanupPending)
            _ = try f.h.write(recovery, previous: a)
            let original = try XCTUnwrap(f.h.lastTransition)
            XCTAssertThrowsError(try XCTUnwrap(f.invocation).retainMaintenanceRecoveryTransition(original))
            try XCTUnwrap(f.invocation).retainUnboundAuthorizedOriginTransition(original)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let receipt = try await phases.run { try Self.intent(f, joined: joined) }
            XCTAssertEqual(receipt.record.unboundRelease?.authorizedRevision, a.revision)
            XCTAssertEqual(receipt.record.unboundRelease?.origin, .retainedAuthorizedRecovery)
            XCTAssertThrowsError(try receipt.requireSavedTargetReconnectOrigin(receipt.record))
        }
    }
    func testRecoveryWithoutRetainedOriginRefusesWithoutWriting() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let recovery = try RuntimeMaintenanceStartupPolicy.row(f.h.initial, phase: .needsOwnerRecovery,
                service: .notStopped, failure: .cleanupPending)
            _ = try f.h.write(recovery, previous: f.h.initial)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            do { _ = try await phases.run { try Self.intent(f, joined: joined) }; XCTFail("Missing origin was accepted") }
            catch { XCTAssertEqual(try f.h.frame().window, recovery) }
            f.retained.assertHeld()
        }
    }
    func testAnEnteredBodyCannotMintAnUnboundIntentAfterJoining() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            try XCTUnwrap(f.invocation).run(work: {}, reply: { _, _ in })
            let joined = try await f.join(), phases = try joined.restorationPhases()
            XCTAssertFalse(joined.evidence.neverEntered)
            do { _ = try await phases.run { try Self.intent(f, joined: joined) }; XCTFail("Entered body was accepted") }
            catch { XCTAssertEqual(try f.h.frame().window, f.h.initial) }
        }
    }
    func testRecoveryReadbackKeepsThePendingAnchorAndRejectsAStaleRequest() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let pending = try await phases.run { try Self.intent(f, joined: joined).record }
            let stale = try await Self.observation(f, joined: joined, row: pending)
            let recovery = try RuntimeMaintenanceStartupPolicy.row(pending, phase: .needsOwnerRecovery,
                service: .notStopped, failure: .admissionUnconfirmed)
            _ = try await phases.run { try f.h.write(recovery, previous: pending) }
            do {
                _ = try await phases.run { try Self.complete(f, joined: joined, observation: stale) }
                XCTFail("Stale pending readback was accepted")
            } catch { XCTAssertEqual(try f.h.frame().window, recovery) }
            let observation = try await Self.observation(f, joined: joined, row: recovery, hold: .released)
            let confirmed = try await phases.run {
                try f.h.f.machine().runtimeMaintenanceUnboundCommandRecord(observation.request,
                    account: f.h.f.authority, incarnation: observation.request.authorityIncarnation, candidate: f.h.f.candidate)
            }
            XCTAssertEqual(confirmed, recovery)
            let result = try await phases.run { try Self.complete(f, joined: joined, observation: observation) }
            XCTAssertEqual(result.record.gate?.requestRevision, pending.revision)
            XCTAssertNotEqual(result.record.gate?.requestRevision, recovery.revision)
        }
    }

    private final class StartupScope: @unchecked Sendable {
        let h: StartupHarness, activity: ReleaseActivityFixture, owner: SetupAccountOwner, placement: ReleaseDestinationLease
        let processLease: SetupProcessLease, shutdown: AdministrativeSetupShutdown
        let scope: SetupAccountOwner.MaintenanceRecoveryScope
        let phases: SetupRetainedInvocationReservation.RestorationPhases
        init(_ f: RuntimeMaintenanceWriterFixture, recovery: Bool) throws {
            h = try StartupHarness(f)
            try h.seed(.authorized)
            let a = h.initial
            let descriptor = try RuntimeMaintenanceUnboundRelease(authorized: a, previous: a,
                pendingRevision: AccountPreparationIntent.randomID())
            let pending = try Row(id: a.id, revision: descriptor.pendingRevision, purpose: a.purpose,
                scope: a.scope, phase: .reopenPending, unboundRelease: descriptor)
            let row = recovery ? try RuntimeMaintenanceStartupPolicy.row(pending, phase: .needsOwnerRecovery,
                service: .notStopped, failure: .admissionUnconfirmed) : pending
            func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
            try f.edit(["UPDATE runtime_maintenance_windows_v1 SET revision=X'\(hex(row.revision))', phase=\(row.phase.rawValue), record=X'\(try hex(row.encoded))'"])
            activity = try ReleaseActivityFixture()
            owner = try .init(machine: f.machine(), expectedReleaseDigest: InstallationInventory.digest(f.candidate),
                resume: { _, value in value }, releaseActivity: activity.open())
            placement = try .init(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid())
            processLease = try .openOwned(directory: .init(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid()))
            shutdown = .init(owner: owner, placement: placement, processLease: processLease)
            scope = try owner.acquireMaintenanceRecoveryScope(custody: shutdown)
            phases = try owner.maintenanceRecoveryPhases(scope: scope)
        }
        deinit { scope.close(); try? owner.close(); placement.close(); processLease.close() }
    }
    private func startupFixture(recovery: Bool = false,
        _ body: @escaping @Sendable (StartupScope) async throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let startup = try StartupScope(f, recovery: recovery)
            let done = DispatchSemaphore(value: 0), result = Mutex<Result<Void, any Error>?>(nil)
            Task {
                do { try await body(startup); result.withLock { $0 = .success(()) } }
                catch { result.withLock { $0 = .failure(error) } }
                done.signal()
            }
            guard done.wait(timeout: .now() + RuntimeMaintenanceExplicitRestorationTests.fixtureWaitSeconds) == .success else {
                return XCTFail("Startup did not return")
            }
            try XCTUnwrap(result.withLock { $0 }).get()
        }
    }
    private static func discard(_ startup: StartupScope, failAfterCommit: Bool = false) throws -> Row {
        let h = startup.h, frame = try h.frame(), drain = try h.barrier.beginDrain()
        defer { drain.close() }
        let result = try RuntimeMaintenanceStartupRecovery.openUnboundStartupOwned(frame: frame,
            processLease: startup.processLease, startupPhases: startup.phases,
            directory: h.f.directory, admission: h.f.admission, drain: drain,
            read: { try h.frame() }, persistFailure: { next, previous, _ in
                _ = try h.write(next, previous: previous); return try XCTUnwrap(h.lastTransition)
            }, persistDiscard: { previous, authorization, current in
                let receipt = try h.f.machine().writeRuntimeMaintenanceUnboundStartupDiscard(replacing: previous,
                    authorization: authorization, expected: current.source.actual, candidate: h.f.candidate,
                    directory: h.f.directory, admission: h.f.admission, verifyScoped: { stage in
                        if failAfterCommit && stage == .afterCommit { throw Failure.afterCommit }
                    })
                return receipt
            })
        guard case .terminal(let row) = result else { throw RuntimePreparationError.changedScope }
        return try XCTUnwrap(row)
    }
    func testStartupDiscardRemovesDeadIntentBeforeTerminalHandlingAndKeepsRepairClosure() throws {
        try startupFixture { startup in
            let row = try await startup.phases.run { try Self.discard(startup) }
            XCTAssertEqual(row.phase, .needsOwnerRecovery); XCTAssertEqual(row.failure, .repairRequired)
            XCTAssertEqual(row.formatVersion, 1); XCTAssertNil(row.unboundRelease); XCTAssertNil(row.gate)
            XCTAssertEqual(startup.h.registrations, 0); XCTAssertEqual(startup.h.classifications, 0)
            XCTAssertEqual(startup.h.observations, 0)
        }
    }
    func testStartupCanResumeTheDropAfterPendingAlreadyBecameRecovery() throws {
        try startupFixture(recovery: true) { startup in
            let row = try await startup.phases.run { try Self.discard(startup) }
            XCTAssertEqual(row.formatVersion, 1); XCTAssertEqual(row.failure, .repairRequired)
        }
    }
    func testStartupAfterCommitFailureStopsWithoutClaimingCleanupAndNextRunSeesR1() throws {
        try startupFixture { startup in
            do {
                _ = try await startup.phases.run { try Self.discard(startup, failAfterCommit: true) }
                XCTFail("An after-commit failure was accepted")
            } catch { XCTAssertEqual(error as? Failure, .afterCommit) }
            // Reopen the unavailable SQLite writer. The one Setup owner retains its admission throughout.
            try startup.h.f.reopen(nil)
            let row = try XCTUnwrap(startup.h.frame().window)
            XCTAssertNil(row.unboundRelease); XCTAssertEqual(row.failure, .repairRequired)
            XCTAssertEqual(startup.h.registrations, 0)
            let next = try await startup.phases.run { try Self.discard(startup) }
            XCTAssertEqual(next, row)
        }
    }
    func testTheSameOwnerRefusesStartupScopeWhileItsClaimIsLive() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let pending = try await phases.run { try Self.intent(f, joined: joined).record }
            let placement = try ReleaseDestinationLease(anchor: f.activity.root.path, relativeDirectory: "Machine", owner: getuid())
            defer { placement.close() }
            let shutdown = AdministrativeSetupShutdown(owner: f.retained.owner, placement: placement, processLease: f.processLease)
            XCTAssertThrowsError(try f.retained.owner.acquireMaintenanceRecoveryScope(custody: shutdown)) {
                guard case SetupAccountOwner.MaintenanceRecoveryAdmissionError.busyBeforeOwner = $0 else {
                    return XCTFail("Unexpected error: \($0)")
                }
            }
            XCTAssertThrowsError(try phases.requireUnboundStartupPhase()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertEqual(try f.h.frame().window, pending)
        }
    }
    func testReleasedSupervisorCannotAuthorizeStartupDiscard() throws {
        try startupFixture { startup in
            let before = try startup.h.frame().window
            startup.scope.close()
            XCTAssertThrowsError(try Self.discard(startup)) { XCTAssertTrue($0 is SetupAccountOwner.ExecutorAdmission.Released) }
            XCTAssertEqual(try startup.h.frame().window, before)
        }
    }
    func testRestartPhaseCannotAuthorizeStartupDiscard() throws {
        try RuntimeMaintenanceRestartRestorationTests().withFixture { f in
            let claim = try await RuntimeMaintenanceRestartRestorationTests.claim(f)
            XCTAssertThrowsError(try claim.restorationPhases().requireUnboundStartupPhase()) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            let released = try await claim.releaseWithoutRestoration(); XCTAssertTrue(released)
        }
    }
    private final class Resources: @unchecked Sendable {
        let directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease
        init(_ directory: ReleaseDestinationLease, _ admission: UpdateOrdinaryAdmissionLease) {
            self.directory = directory; self.admission = admission
        }
    }
    private static func custody(_ f: ExplicitStartupFixture, joined: Joined,
        deadline: ContinuousClock.Instant, afterIntent: (@Sendable (Transition) throws -> Void)? = nil,
        beforeIntent: (@Sendable () -> Void)? = nil, beforeCompletion: (@Sendable () -> Void)? = nil)
        throws -> RuntimeMaintenanceStartupRecovery.Custody {
        let (directory, admission) = try f.resources(), h = f.h
        let resources = Resources(directory, admission)
        do {
            return try RuntimeMaintenanceStartupRecovery.makeUnboundJoinedCustodyOwned(joined: joined,
                processLease: f.processLease, frame: h.frame(), release: h.f.candidate, admission: admission,
                directory: directory, accountBarrier: h.barrier, read: { try h.frame() },
                persist: { try h.persistForRecovery($0, previous: $1) },
                writeIntent: { previous, actualJoined, frame in
                    beforeIntent?()
                    let receipt = try h.f.machine().writeRuntimeMaintenanceUnboundIntent(replacing: previous,
                        joined: actualJoined, expected: frame.source.actual, candidate: h.f.candidate,
                        directory: resources.directory, admission: resources.admission)
                    try afterIntent?(receipt)
                    return receipt
                }, writeCompletion: { previous, actualJoined, observation, frame in
                    beforeCompletion?()
                    return try h.f.machine().writeRuntimeMaintenanceUnboundCompletion(replacing: previous,
                        joined: actualJoined, observation: observation, expected: frame.source.actual,
                        candidate: h.f.candidate, directory: resources.directory, admission: resources.admission)
                }, verify: { try h.verifyCurrent() }, until: deadline)
        } catch { admission.close(); directory.close(); throw error }
    }
    func testRealWorkCompletionClosesCustodyAndAdoptsWithoutAnotherSlot() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let deadline = ContinuousClock.now.advanced(by: RuntimeMaintenanceExplicitRestorationTests.unboundPhaseBudget)
            let work = try await joined.startRestoration { workID in
                let custody = try await phases.run { try Self.custody(f, joined: joined, deadline: deadline) }
                let outcome: Result<RuntimeMaintenanceStartupRecovery.ExplicitCompletion, any Error>
                do {
                    _ = try await phases.run { try custody.persistUnboundIntent() }
                    try await phases.run { try custody.releaseUnboundCleanupDrain() }
                    try await phases.run {
                        let admission = try f.h.barrier.acquireAdmission()
                        defer { admission.close() }; try admission.validate()
                    }
                    let observation = try await Self.observation(f, joined: joined, row: custody.current)
                    _ = try await phases.run { try custody.persistUnboundCompletion(observation) }
                    let completed = try await phases.run {
                        try RuntimeMaintenanceStartupRecovery.makeUnboundExplicitCompletion(custody: custody, workID: workID)
                    }
                    outcome = .success(completed)
                } catch { outcome = .failure(error) }
                try await phases.closeActual { custody.closeUnboundCustody() }
                return try outcome.get()
            }
            let completed = try await joined.finishRestorationOwned(work: work, processLease: f.processLease)
            XCTAssertEqual(completed.phase, .restored); XCTAssertEqual(completed.formatVersion, 1)
            try f.retained.assertReleased()
            XCTAssertEqual(f.h.registrations, 0); XCTAssertEqual(f.h.observations, 0)
        }
    }
    func testAfterCommitFailureRetainsUncertaintyAndCannotWriteAgain() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let custody = try await phases.run {
                try Self.custody(f, joined: joined, deadline: .now.advanced(by: RuntimeMaintenanceExplicitRestorationTests.unboundPhaseBudget),
                    afterIntent: { _ in throw Failure.afterCommit })
            }
            do {
                _ = try await phases.run { try custody.persistUnboundIntent() }
                XCTFail("The actual after-commit failure was lost")
            } catch {
                XCTAssertEqual(try f.h.frame().window?.phase, .reopenPending)
                XCTAssertThrowsError(try custody.persistUnboundFailure(.serviceUnavailable))
                XCTAssertThrowsError(try custody.releaseUnboundCleanupDrain())
                XCTAssertEqual(try f.h.frame().window?.phase, .reopenPending)
            }
            try await phases.closeActual { custody.closeUnboundCustody() }
            f.retained.assertHeld()
        }
    }
    func testRepeatedRecoveryFailureDoesNotChangeItsRowOrFailureValue() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let pending = try await phases.run { try Self.intent(f, joined: joined).record }
            let recovery = try RuntimeMaintenanceStartupPolicy.row(pending, phase: .needsOwnerRecovery,
                service: .notStopped, failure: .admissionUnconfirmed)
            _ = try await phases.run { try f.h.write(recovery, previous: pending) }
            let custody = try await phases.run {
                try Self.custody(f, joined: joined, deadline: .now.advanced(by: RuntimeMaintenanceExplicitRestorationTests.unboundPhaseBudget))
            }
            let result = try await phases.run { try custody.persistUnboundFailure(.serviceUnavailable) }
            XCTAssertEqual(result, recovery); XCTAssertEqual(try f.h.frame().window, recovery)
            try await phases.closeActual { custody.closeUnboundCustody() }
        }
    }
    func testVerifierRefusesForgedForeignChallengeAndForeignIncarnationBeforeWriting() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let pending = try await phases.run { try Self.intent(f, joined: joined).record }
            for fault in [GateDriver.Fault.forged, .challenge, .incarnation] {
                do {
                    _ = try await Self.observation(f, joined: joined, row: pending, fault: fault)
                    XCTFail("The invalid exchange minted an observation")
                } catch {
                    if fault == .forged { XCTAssertEqual(error as? AuthorityMaintenanceClientError, .needsOwnerRecovery) }
                    else { XCTAssertEqual(error as? RuntimePreparationError, .changedScope) }
                }
                XCTAssertEqual(try f.h.frame().window, pending)
            }
            f.retained.assertHeld()
        }
    }
    func testMismatchedVerifiedObservationDoesNotPoisonTheFailureWriter() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let custody = try await phases.run {
                try Self.custody(f, joined: joined, deadline: .now.advanced(by: RuntimeMaintenanceExplicitRestorationTests.unboundPhaseBudget))
            }
            let pending = try await phases.run { try custody.persistUnboundIntent().record }
            try await phases.run { try custody.releaseUnboundCleanupDrain() }
            let foreign = try RuntimeMaintenanceStartupPolicy.row(pending, phase: .needsOwnerRecovery,
                service: .notStopped, failure: .admissionUnconfirmed)
            let stale = try await Self.observation(f, joined: joined, row: foreign)
            do {
                _ = try await phases.run { try custody.persistUnboundCompletion(stale) }
                XCTFail("A mismatched observation was accepted")
            } catch { XCTAssertEqual(error as? RuntimePreparationError, .changedScope) }
            XCTAssertEqual(try f.h.frame().window, pending)
            let recovered = try await phases.run { try custody.persistUnboundFailure(.admissionUnconfirmed) }
            XCTAssertEqual(recovered.phase, .needsOwnerRecovery); XCTAssertEqual(recovered.unboundRelease, pending.unboundRelease)
            try await phases.closeActual { custody.closeUnboundCustody() }
        }
    }
    func testRightsExpiryAfterCommitDoesNotMakeTheWriterUncertain() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let pending = try await phases.run { try Self.intent(f, joined: joined).record }
            let observation = try await Self.observation(f, joined: joined, row: pending)
            let receipt = try await phases.run {
                let frame = try f.h.frame()
                return try f.h.f.machine().writeRuntimeMaintenanceUnboundCompletion(replacing: pending,
                    joined: joined, observation: observation, expected: frame.source.actual,
                    candidate: f.h.f.candidate, directory: f.h.f.directory, admission: f.h.f.admission,
                    verifyScoped: { stage in
                        if stage == .afterCommit { f.rightsLive.value.withLock { $0 = false } }
                    })
            }
            XCTAssertEqual(receipt.record.phase, .restored); XCTAssertEqual(try f.h.frame().window, receipt.record)
            XCTAssertThrowsError(try joined.requireCurrentAuthorization())
            f.retained.assertHeld()
        }
    }
    func testUnboundReceiptCannotEnterAnExecutingTransitionChain() throws {
        try fixture { f in
            let before = try f.h.frame().source.actual
            try f.h.seed(.authorized)
            let initial = try XCTUnwrap(f.h.lastTransition)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let pending = try await phases.run { try Self.intent(f, joined: joined) }
            XCTAssertThrowsError(try Transition.requireChain([initial, pending], from: before, to: f.h.frame().source.actual)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
        }
    }
    func testTypedIntentRefusesDrainingAndBoundRows() throws {
        for phase in [Row.Phase.draining, .stopping] {
            try fixture { f in
                if phase == .draining {
                    try f.h.seed(.authorized)
                    let drain = try f.h.barrier.beginDrain(); defer { drain.close() }
                    _ = try f.h.write(RuntimeMaintenanceStartupPolicy.row(f.h.initial, phase: .draining,
                        service: .notStopped), previous: f.h.initial, drain: drain)
                } else { try f.h.seed(phase) }
                let previous = try f.h.frame().window
                let joined = try await f.join(), phases = try joined.restorationPhases()
                do { _ = try await phases.run { try Self.intent(f, joined: joined) }; XCTFail("A bound row was accepted") }
                catch { XCTAssertEqual(error as? RuntimePreparationError, .changedScope) }
                XCTAssertEqual(try f.h.frame().window, previous)
            }
        }
    }

    func testVerifierRefusesHeldUnknownBusyAndNoncanonicalRepliesBeforeWriting() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            let joined = try await f.join(), phases = try joined.restorationPhases()
            let pending = try await phases.run { try Self.intent(f, joined: joined).record }
            for fault in [GateDriver.Fault.held, .unknown, .busy, .noncanonical] {
                do {
                    _ = try await Self.observation(f, joined: joined, row: pending, fault: fault)
                    XCTFail("A refused gate reply minted a verified observation")
                } catch {
                    if fault == .noncanonical { XCTAssertEqual(error as? CBORError, .nonCanonical) }
                    else if fault == .busy { XCTAssertEqual(error as? AuthorityMaintenanceClientError, .busy) }
                    else { XCTAssertEqual(error as? RuntimePreparationError, .changedScope) }
                }
                XCTAssertEqual(try f.h.frame().window, pending)
            }
        }
    }
    func testVerifiedObservationDoesNotRetainItsJoinedAndRefusesAFreshClaim() throws {
        try fixture { f in
            try f.h.seed(.authorized)
            weak var original: Joined?
            let observation: VerifiedUnboundGateObservation
            let pending: Row
            do {
                let joined = try await f.join(), phases = try joined.restorationPhases()
                original = joined
                pending = try await phases.run { try Self.intent(f, joined: joined).record }
                observation = try await Self.observation(f, joined: joined, row: pending)
                f.claim?.abandon(); f.claim = nil
            }
            XCTAssertNil(original)
            let replacement = try await f.freshJoined(), phases = try replacement.restorationPhases()
            do {
                _ = try await phases.run { try Self.complete(f, joined: replacement, observation: observation) }
                XCTFail("An old observation accepted another Joined")
            } catch { XCTAssertEqual(error as? RuntimePreparationError, .changedScope) }
            XCTAssertEqual(try f.h.frame().window, pending)
        }
    }
    func testRightsRefusalBeforeTransactionDoesNotPoisonEitherTypedWrite() throws {
        for expireIntent in [true, false] {
            try fixture { f in
                try f.h.seed(.authorized)
                let joined = try await f.join(), phases = try joined.restorationPhases()
                let expireOnce = Mutex(false)
                let expire: @Sendable () -> Void = {
                    let shouldExpire = expireOnce.withLock { value in
                        guard !value else { return false }; value = true; return true
                    }
                    if shouldExpire { f.rightsLive.value.withLock { $0 = false } }
                }
                let custody = try await phases.run {
                    try Self.custody(f, joined: joined,
                        deadline: .now.advanced(by: RuntimeMaintenanceExplicitRestorationTests.unboundPhaseBudget),
                        beforeIntent: expireIntent ? expire : nil, beforeCompletion: expireIntent ? nil : expire)
                }
                let before: Row
                let observation: VerifiedUnboundGateObservation?
                if expireIntent { before = custody.current; observation = nil }
                else {
                    before = try await phases.run { try custody.persistUnboundIntent().record }
                    try await phases.run { try custody.releaseUnboundCleanupDrain() }
                    observation = try await Self.observation(f, joined: joined, row: before)
                }
                do {
                    if let observation { _ = try await phases.run { try custody.persistUnboundCompletion(observation) } }
                    else { _ = try await phases.run { try custody.persistUnboundIntent() } }
                    XCTFail("Expired rights were accepted")
                } catch { XCTAssertFalse(error is PreparationIntentStore.RuntimeMaintenancePretransactionRefusal) }
                XCTAssertEqual(try f.h.frame().window, before)
                f.rightsLive.value.withLock { $0 = true }
                let recovered = try await phases.run { try custody.persistUnboundFailure(.admissionUnconfirmed) }
                XCTAssertEqual(recovered.phase, expireIntent ? .authorized : .needsOwnerRecovery)
                try await phases.closeActual { custody.closeUnboundCustody() }
            }
        }
    }
    private static func openSupervisor(_ startup: StartupScope,
        supervisor: RuntimeMaintenanceStartupRecovery.OwnedSupervisorWork?) throws -> RuntimeMaintenanceStartupRecovery {
        let h = startup.h
        return try .openOwned(frame: h.frame(), release: h.f.candidate, admission: h.f.admission,
            directory: h.f.directory, accountBarrier: h.barrier, read: { try h.frame() },
            persist: { try h.persistForRecovery($0, previous: $1) }, verify: { try startup.processLease.validate() },
            inspect: { _ in h.observations += 1; return .absent },
            observe: { _, _, _ in h.observations += 1; return h.witness },
            observeOperation: { _ in h.classifications += 1; return .unknown }, register: { h.registrations += 1 },
            supervisorWork: supervisor, startupWriters: .init(failure: { next, previous, _ in
                _ = try h.write(next, previous: previous); return try XCTUnwrap(h.lastTransition)
            }, discard: { previous, authorization, frame in
                try h.f.machine().writeRuntimeMaintenanceUnboundStartupDiscard(replacing: previous,
                    authorization: authorization, expected: frame.source.actual, candidate: h.f.candidate,
                    directory: h.f.directory, admission: h.f.admission)
            }))
    }
    func testOwnedSupervisorOpeningUsesTheNativeDescriptorGuardAndDrop() throws {
        try startupFixture { startup in
            let before = try startup.h.frame().window
            XCTAssertThrowsError(try Self.openSupervisor(startup, supervisor: nil)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            XCTAssertEqual(try startup.h.frame().window, before)
            let supervisor = try RuntimeMaintenanceStartupRecovery.OwnedSupervisorWork(phases: startup.phases,
                cancellation: .init())
            let recovery = try await startup.phases.run { try Self.openSupervisor(startup, supervisor: supervisor) }
            defer { recovery.closeNativeCustody() }
            XCTAssertEqual(recovery.window.phase, .needsOwnerRecovery); XCTAssertEqual(recovery.window.failure, .repairRequired)
            XCTAssertNil(recovery.window.unboundRelease); XCTAssertEqual(recovery.window.formatVersion, 1)
            XCTAssertEqual(startup.h.classifications, 0); XCTAssertEqual(startup.h.registrations, 0)
            XCTAssertEqual(startup.h.observations, 0)
        }
    }

}
