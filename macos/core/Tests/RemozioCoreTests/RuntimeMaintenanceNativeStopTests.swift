import Darwin
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

private final class MaintenanceBodyStores {
    let root: URL, mac: Data, account: Data, epoch = maintenanceCloseBytes(12)
    let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
    init(mac: Data, account: Data, policy: AuthorityCodePolicy) throws {
        self.mac = mac; self.account = account
        root = URL(fileURLWithPath: "/private/tmp/remozio-maintenance-pair-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        for name in ["Journal", "Continuity"] {
            let p = root.appendingPathComponent(name)
            try FileManager.default.createDirectory(at: p, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for file in ["writer.lock", name == "Journal" ? "journal.sqlite" : "continuity.sqlite"] {
                let fd = Darwin.open(p.appendingPathComponent(file).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }; Darwin.close(fd)
            }
        }
        let journal = try openJournal(initialize: true); defer { try? journal.close() }
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(epoch), 4: .unsigned(1), 5: .unsigned(1),
            6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
        _ = try journal.write { try $0.createEpoch(descriptor) }
        let checkpoint = try journal.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: epoch, generation: 1, authorityGeneration: 1) }
        let continuity = try openContinuity(initial: checkpoint); defer { continuity.close() }
        _ = try CheckpointedJournal(journal: journal, continuity: continuity).write(epoch: epoch) {
            try $0.installCodePolicy(policy, expectedRevision: nil)
        }
    }
    deinit { try? FileManager.default.removeItem(at: root) }
    func openJournal(initialize: Bool = false, readOnly: Bool = false) throws -> sending JournalDatabase {
        try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "Journal", owner: getuid()),
            macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 10, busyMilliseconds: 100, initialize: initialize, readOnlyForCutover: readOnly)
    }
    func openContinuity(initial: ContinuityCheckpoint? = nil, excluding: ProtectedStorageLease.DirectoryIdentity? = nil,
        readOnly: Bool = false) throws -> sending ContinuityStore {
        try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "Continuity", owner: getuid(), excludingDirectory: excluding),
            macID: mac, accountID: account, initialize: initial, readOnlyForCutover: readOnly)
    }
    func pair(policy: AuthorityCodePolicy) throws -> AuthorityJournalCutoverInspection {
        let storage = try AuthorityStorage(openJournal: { try self.openJournal(readOnly: true) },
            openContinuity: { try self.openContinuity(excluding: $0, readOnly: true) })
        return try .init(storage: storage, expectedPolicy: policy, verifyCurrent: {})
    }
    func maintenancePair(policy: AuthorityCodePolicy, scope: UpdateOrdinaryAdmissionLease.Scope,
        fixture: MaintenanceStopTestFixture) throws -> AuthorityJournalCutoverInspection {
        try AuthorityJournalCutoverInspection.openOwnedForMaintenance(accountID: account, policy: policy, scope: scope,
            drain: fixture.drain, directory: fixture.directory, machineIdentity: fixture.cohort.machineIdentity,
            accountIdentity: fixture.cohort.accountIdentity, verifyOwner: {}, openStorage: {
                try AuthorityStorage(openJournal: { try self.openJournal(readOnly: true) },
                    openContinuity: { try self.openContinuity(excluding: $0, readOnly: true) })
            })
    }
    func requireReleased() throws {
        let journal = try openJournal(); try journal.close()
        let continuity = try openContinuity(); continuity.close()
    }
}

private final class MaintenanceNativeStopHarness: @unchecked Sendable {
    let f: MaintenanceStopTestFixture, client: AuthorityMaintenanceXPCClient
    let capture: RuntimeMaintenanceStopCapture, file: MaintenanceCloseFileFixture, stores: MaintenanceBodyStores
    var observation: RuntimeJobStopSession.Observation = .matching(100)
    var removals = 0, inspections = 0, pairOpens = 0, bodyCalls = 0
    var useMaintenancePair = false
    var onInspect: () throws -> Void = {}
    var onRemove: () throws -> Void = {}
    var onOpenPair: () -> Void = {}
    init() async throws {
        let f = try MaintenanceStopTestFixture(), client = try f.client()
        self.f = f; self.client = client; capture = try await f.capture(client)
        file = try .init(); try file.publish(capture.marker)
        stores = try .init(mac: f.window.scope.macID, account: f.cohort.accountID, policy: f.runtime.plan.host.codePolicy)
    }
    deinit { try? file.close() }
    func permit(until deadline: ContinuousClock.Instant = .now.advanced(by: .seconds(5))) throws -> RuntimeMaintenanceStopPermit {
        try .openOwned(capture: capture, until: deadline, readMarker: { try self.file.readback(self.capture.marker) })
    }
    func open(_ scope: UpdateOrdinaryAdmissionLease.Scope, permit: RuntimeMaintenanceStopPermit) throws -> RuntimeMaintenanceAuthorityStop {
        try .openOwnedBound(permit: permit, purpose: .retainedPolicy, cohort: f.cohort, scope: scope,
            drain: f.drain, directory: f.directory, inspect: {
                self.inspections += 1; try self.onInspect(); return self.observation
            }, remove: {
                self.removals += 1; try self.onRemove()
            }, openPair: { initialization, policy in
                XCTAssertEqual(initialization.accountID, self.f.cohort.accountID)
                self.pairOpens += 1; self.onOpenPair()
                if self.useMaintenancePair { return try self.stores.maintenancePair(policy: policy, scope: scope, fixture: self.f) }
                return try self.stores.pair(policy: policy)
            })
    }
    func stopped(_ session: RuntimeMaintenanceAuthorityStop) throws {
        onRemove = { [unowned self] in self.observation = .absent; self.f.witness.exited.withLock { $0 = true } }
        XCTAssertEqual(try session.poll(), .registrationRemoved); try session.requireRemoved()
    }
    func body<Value>(_ session: RuntimeMaintenanceAuthorityStop, _ body: (AuthorityJournalCutoverInspection) throws -> Value) throws -> Value {
        try session.withNativeBody(purpose: .retainedPolicy, initialization: f.initialization, policy: f.runtime.plan.host.codePolicy) { pair in
            self.bodyCalls += 1; return try body(pair)
        }
    }
}

private final class MaintenanceForeignPolicyRead: @unchecked Sendable {
    let pair: AuthorityJournalCutoverInspection, initial: AuthorityInitializationIntent
    let refused = Mutex(false)
    init(pair: AuthorityJournalCutoverInspection, initial: AuthorityInitializationIntent) { self.pair = pair; self.initial = initial }
    func invoke() {
        do { _ = try pair.maintenancePolicyBoundary(initialization: initial) }
        catch { refused.withLock { $0 = error as? JournalDatabaseError == .unavailable } }
    }
}

final class RuntimeMaintenanceNativeStopTests: XCTestCase, @unchecked Sendable {
    func testActualPermitOpensItsOnlyMaintenancePairOnTheBodyThreadAndKeepsTheLiveCheckpoint() async throws {
        let h = try await MaintenanceNativeStopHarness(); h.useMaintenancePair = true
        try h.f.ordinary.withMachineAdmission { scope in
            let session = try h.open(scope, permit: h.permit()); defer { session.close() }
            try h.stopped(session)
            let initial = h.f.initialization
            let declared = try AuthorityInitializationIntent(setupID: initial.setupID, revision: initial.revision,
                installationID: initial.installationID, macID: initial.macID, accountID: initial.accountID,
                releaseDigest: initial.releaseDigest, initializationDigest: initial.initializationDigest,
                initializationBytes: initial.initializationBytes,
                journalPath: h.stores.root.path + "/Journal/journal.sqlite",
                continuityPath: h.stores.root.path + "/Continuity/continuity.sqlite", checkpoint: initial.checkpoint, complete: true)
            try h.body(session) { pair in
                let live = try pair.maintenancePolicyBoundary(initialization: declared)
                XCTAssertEqual(live.checkpoint, pair.snapshot.checkpoint)
                XCTAssertNotEqual(live.checkpoint, declared.checkpoint)
                XCTAssertEqual(live.policy.policy, h.f.runtime.plan.host.codePolicy)
                let foreign = MaintenanceForeignPolicyRead(pair: pair, initial: declared)
                let done = DispatchSemaphore(value: 0)
                DispatchQueue.global().async { foreign.invoke(); done.signal() }
                XCTAssertEqual(done.wait(timeout: .now() + 2), .success)
                XCTAssertTrue(foreign.refused.withLock { $0 })
                XCTAssertEqual(try pair.maintenancePolicyBoundary(initialization: declared), live)
            }
            XCTAssertEqual(h.pairOpens, 1); XCTAssertEqual(h.bodyCalls, 1)
        }
        try h.stores.requireReleased(); await h.client.close()
    }
    func testBootoutIsIssuedOnlyOnceAcrossPendingPollsAndALostReply() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let p = try h.permit(), s = try h.open(scope, permit: p); defer { s.close() }
            h.onRemove = { throw MaintenanceStopTestFault.expected }
            for _ in 0..<3 { XCTAssertEqual(try s.poll(), .removingRegistration) }
            XCTAssertEqual(h.removals, 1)
            h.observation = .absent; h.f.witness.exited.withLock { $0 = true }
            XCTAssertEqual(try s.poll(), .registrationRemoved); try s.requireRemoved()
        }
    }
    func testCaughtReentryPoisonsTheOuterPollBeforeAnyBootout() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let s = try h.open(scope, permit: h.permit()); defer { s.close(); h.onInspect = {} }
            h.onInspect = { XCTAssertThrowsError(try s.poll()) }
            XCTAssertThrowsError(try s.poll()); XCTAssertEqual(h.removals, 0)
            h.onInspect = {}; XCTAssertThrowsError(try s.poll())
        }
    }
    func testPermitConsumptionCannotBeRepeatedEvenWhenTheFirstConsumeFails() async throws {
        let h = try await MaintenanceNativeStopHarness(), p = try h.permit(until: .now.advanced(by: .milliseconds(-1)))
        try h.f.ordinary.withMachineAdmission { scope in
            XCTAssertThrowsError(try h.open(scope, permit: p))
            XCTAssertThrowsError(try h.open(scope, permit: p)); XCTAssertEqual(h.inspections, 0); XCTAssertEqual(h.removals, 0)
        }
    }
    func testAConsumedPermitAndExpiredMachineScopeCannotOpenAnotherSession() async throws {
        let h = try await MaintenanceNativeStopHarness(), p = try h.permit()
        let session = try h.f.ordinary.withMachineAdmission { try h.open($0, permit: p) }
        defer { session.close() }
        XCTAssertThrowsError(try session.poll())
        try h.f.ordinary.withMachineAdmission { scope in XCTAssertThrowsError(try h.open(scope, permit: p)) }
        XCTAssertEqual(h.removals, 0)
    }
    func testOriginalProcessAliveOrTheAuthorityStillRegisteredCannotStartTheBody() async throws {
        for keepRegistered in [false, true] {
            let h = try await MaintenanceNativeStopHarness()
            try h.f.ordinary.withMachineAdmission { scope in
                let s = try h.open(scope, permit: h.permit()); defer { s.close() }
                h.onRemove = { [unowned h] in if !keepRegistered { h.observation = .absent } }
                _ = try s.poll()
                XCTAssertThrowsError(try h.body(s) { _ in XCTFail() }) {
                    XCTAssertEqual($0 as? AuthorityMaintenanceClientError, .needsOwnerRecovery)
                }
                XCTAssertEqual(h.bodyCalls, 0); XCTAssertEqual(h.pairOpens, 0); XCTAssertEqual(h.removals, 1)
            }
        }
    }
    func testNewPIDAndReusedOriginalPIDAreRejectedWithoutAnotherRemoval() async throws {
        for reuse in [false, true] {
            let h = try await MaintenanceNativeStopHarness()
            try h.f.ordinary.withMachineAdmission { scope in
                let s = try h.open(scope, permit: h.permit()); defer { s.close() }
                h.onRemove = { [unowned h] in h.observation = .matching(reuse ? 100 : 101); h.f.witness.exited.withLock { $0 = true } }
                XCTAssertThrowsError(try s.poll()); XCTAssertEqual(h.removals, 1)
                XCTAssertThrowsError(try s.poll()); XCTAssertEqual(h.removals, 1); XCTAssertEqual(h.bodyCalls, 0)
            }
        }
    }
    func testMissingStaleAndForeignIncarnationMarkersPreventTheBodyAndPairOpening() async throws {
        for kind in 0..<3 {
            let h = try await MaintenanceNativeStopHarness(), m = h.capture.marker
            try FileManager.default.removeItem(atPath: h.file.path)
            if kind > 0 {
                let binding = try AuthorityMaintenanceBinding(accountID: m.binding.accountID,
                    attemptID: kind == 1 ? maintenanceCloseBytes(111) : m.binding.attemptID, revision: m.binding.revision,
                    incarnation: kind == 2 ? maintenanceCloseBytes(112) : m.binding.incarnation, connectionID: m.binding.connectionID)
                let wrong = try AuthorityMaintenanceCloseMarker(binding: binding, macID: m.macID, installationID: m.installationID,
                    releaseDigest: m.releaseDigest, codeHash: m.codeHash, directoryID: m.directoryID, ownerUID: m.ownerUID, gate: m.gate)
                try h.file.publish(wrong)
            }
            try h.f.ordinary.withMachineAdmission { scope in
                let s = try h.open(scope, permit: h.permit()); defer { s.close() }
                h.onRemove = { [unowned h] in h.observation = .absent; h.f.witness.exited.withLock { $0 = true } }; _ = try s.poll()
                XCTAssertThrowsError(try h.body(s) { _ in XCTFail() }); XCTAssertEqual(h.pairOpens, 0); XCTAssertEqual(h.bodyCalls, 0)
            }
        }
    }
    func testBothRealStoreLocksRemainHeldForTheBodyAndCloseBeforeRestoration() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let s = try h.open(scope, permit: h.permit()); defer { s.close() }; try h.stopped(s)
            let value = try h.body(s) { pair in
                try pair.validate(); XCTAssertThrowsError(try h.stores.openJournal()); XCTAssertThrowsError(try h.stores.openContinuity()); return 42
            }
            XCTAssertEqual(value, 42); XCTAssertEqual(h.bodyCalls, 1); try h.stores.requireReleased()
            XCTAssertThrowsError(try h.body(s) { _ in XCTFail() }); XCTAssertEqual(h.bodyCalls, 1)
        }
    }
    func testSuccessfulBodyAfterThePermitDeadlineKeepsItsResult() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let s = try h.open(scope, permit: h.permit(until: .now.advanced(by: .seconds(1)))); defer { s.close() }; try h.stopped(s)
            let result = try h.body(s) { _ in Thread.sleep(forTimeInterval: 1.1); return 19 }
            XCTAssertEqual(result, 19); try h.stores.requireReleased()
        }
    }
    func testThrowingBodyAfterThePermitDeadlineKeepsItsOriginalErrorAndClosesThePair() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let s = try h.open(scope, permit: h.permit(until: .now.advanced(by: .seconds(1)))); defer { s.close() }; try h.stopped(s)
            do { _ = try h.body(s) { _ -> Int in Thread.sleep(forTimeInterval: 1.1); throw MaintenanceStopTestFault.expected }; XCTFail() }
            catch { XCTAssertTrue(error is MaintenanceStopTestFault); XCTAssertNil(error as? JournalLeaseError) }
            try h.stores.requireReleased(); XCTAssertThrowsError(try h.body(s) { _ in XCTFail() })
        }
    }
    func testExpiredStopDeadlineCannotIssueBootoutOrStartTheBody() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let s = try h.open(scope, permit: h.permit(until: .now.advanced(by: .seconds(1)))); defer { s.close() }
            Thread.sleep(forTimeInterval: 1.1); XCTAssertThrowsError(try s.poll())
            XCTAssertEqual(h.removals, 0); XCTAssertEqual(h.bodyCalls, 0)
        }
    }
    func testPostBodyJobReappearanceRefusesSuccessAndReleasesBothLocks() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let s = try h.open(scope, permit: h.permit()); defer { s.close() }; try h.stopped(s)
            XCTAssertThrowsError(try h.body(s) { _ in h.observation = .matching(101); return 7 })
            XCTAssertEqual(h.bodyCalls, 1); try h.stores.requireReleased()
        }
    }
    func testPostBodyMarkerLossAndOwnerLossCannotReleaseAResult() async throws {
        for loseOwner in [false, true] {
            let h = try await MaintenanceNativeStopHarness()
            try h.f.ordinary.withMachineAdmission { scope in
                let s = try h.open(scope, permit: h.permit()); defer { s.close() }; try h.stopped(s)
                XCTAssertThrowsError(try h.body(s) { _ in
                    if loseOwner { h.f.ownerValid.withLock { $0 = false } }
                    else { try FileManager.default.removeItem(atPath: h.file.path) }; return 7
                })
                XCTAssertEqual(h.bodyCalls, 1); try h.stores.requireReleased()
            }
        }
    }
    func testOwnedCaptureCannotSelectEitherNativeFactory() async throws {
        let h = try await MaintenanceNativeStopHarness()
        XCTAssertThrowsError(try RuntimeMaintenanceStopPermit.openNative(capture: h.capture, until: .now.advanced(by: .seconds(1)))) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        try h.f.ordinary.withMachineAdmission { scope in
            XCTAssertThrowsError(try RuntimeMaintenanceAuthorityStop.openNative(permit: h.permit(), purpose: .retainedPolicy,
                cohort: h.f.cohort, scope: scope, drain: h.f.drain, directory: h.f.directory)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
    func testTheLastDeadlineCheckRejectsALatePairOpenBeforeTheBody() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let s = try h.open(scope, permit: h.permit(until: .now.advanced(by: .seconds(1)))); defer { s.close() }; try h.stopped(s)
            h.onOpenPair = { Thread.sleep(forTimeInterval: 1.1) }
            XCTAssertThrowsError(try h.body(s) { _ in XCTFail() })
            XCTAssertEqual(h.pairOpens, 1); XCTAssertEqual(h.bodyCalls, 0); try h.stores.requireReleased()
        }
    }
    func testConsumedPermitRefusesAnotherThreadWithoutInspectingOrRemovingTheJob() async throws {
        final class Transfer: @unchecked Sendable {
            let permit: RuntimeMaintenanceStopPermit, done = DispatchSemaphore(value: 0), rejected = Mutex(false)
            init(_ permit: RuntimeMaintenanceStopPermit) { self.permit = permit }
        }
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let p = try h.permit(), s = try h.open(scope, permit: p), transfer = Transfer(p); defer { s.close() }
            DispatchQueue.global().async {
                do { try transfer.permit.validate() } catch { transfer.rejected.withLock { $0 = true } }
                transfer.done.signal()
            }
            XCTAssertEqual(transfer.done.wait(timeout: .now() + 3), .success)
            XCTAssertTrue(transfer.rejected.withLock { $0 }); XCTAssertEqual(h.inspections, 0); XCTAssertEqual(h.removals, 0)
            try p.validate()
        }
    }
    func testForkedPermitCannotValidateOrReleaseTheParentAdmission() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let p = try h.permit(), s = try h.open(scope, permit: p); defer { s.close() }
            let child = Self.forkProcess(); XCTAssertGreaterThanOrEqual(child, 0)
            if child == 0 { do { try p.validate(); _exit(11) } catch { _exit(0) } }
            guard child > 0 else { throw MaintenanceStopTestFault.expected }
            let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
            var reaped = false, status: Int32 = 0
            while DispatchTime.now().uptimeNanoseconds < deadline {
                if waitpid(child, &status, WNOHANG) == child { reaped = true; break }; usleep(10_000)
            }
            if !reaped { _ = kill(child, SIGKILL); while waitpid(child, &status, 0) < 0 && errno == EINTR {} }
            XCTAssertTrue(reaped); XCTAssertEqual(status, 0); XCTAssertEqual(h.removals, 0)
            try h.f.drain.validate(); try p.validate()
        }
    }
    private static let forkProcess: @convention(c) () -> pid_t = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork") else { preconditionFailure("fork is unavailable") }
        return unsafeBitCast(symbol, to: (@convention(c) () -> pid_t).self)
    }()
    func testPollWaitsForRegistrationRemovalBeforeRequireRemoved() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let session = try h.open(scope, permit: h.permit()); defer { session.close() }
            XCTAssertEqual(try session.poll(), .removingRegistration)
            h.observation = .absent
            XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
            h.f.witness.exited.withLock { $0 = true }
            XCTAssertEqual(try session.poll(), .registrationRemoved)
            try session.requireRemoved(); XCTAssertEqual(h.removals, 1)
        }
    }
    func testOneBoundInspectionFailureNeedsRecoveryAndCannotRetryTheNativeCommand() async throws {
        let h = try await MaintenanceNativeStopHarness()
        try h.f.ordinary.withMachineAdmission { scope in
            let session = try h.open(scope, permit: h.permit()); defer { session.close() }
            h.onInspect = { throw MaintenanceStopTestFault.expected }
            XCTAssertThrowsError(try session.poll()) { XCTAssertEqual($0 as? AuthorityMaintenanceClientError, .needsOwnerRecovery) }
            let inspected = h.inspections; h.onInspect = {}
            XCTAssertThrowsError(try session.poll()) { XCTAssertEqual($0 as? AuthorityMaintenanceClientError, .needsOwnerRecovery) }
            XCTAssertEqual(h.inspections, inspected); XCTAssertEqual(h.removals, 0); XCTAssertEqual(h.bodyCalls, 0)
        }
    }

}
