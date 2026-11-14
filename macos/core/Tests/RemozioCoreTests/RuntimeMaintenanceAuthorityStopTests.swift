import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeMaintenanceAuthorityStopTests: XCTestCase {
    private enum Failure: Error { case expected }
    private final class Witness: RuntimeJobExitWitness {
        let processID: pid_t
        var exited = false, unknown = false
        init(_ pid: pid_t) { processID = pid }
        func hasExited() throws -> Bool { if unknown { throw Failure.expected }; return exited }
    }
    private final class Harness {
        let runtime: RuntimeActivationFixture
        let files: UpdateAdmissionTestFixture
        let account: UpdateAdmissionBarrier
        let other: UpdateAdmissionBarrier
        let drain: UpdateDrainToken
        let directory: ReleaseDestinationLease
        let ordinary: UpdateOrdinaryAdmissionLease
        let inventory: InstallationInventory
        let registration: UpdateAdmissionRegistrationRecord
        let cohort: RuntimeMaintenanceAuthorityCohort
        let target = Data(repeating: 98, count: 16), otherID = Data(repeating: 99, count: 16)
        var observation: RuntimeJobStopSession.Observation = .matching(100)
        var witnesses = [Witness(100)]
        var captures = 0, removals = 0, inspections = 0
        var verify: () throws -> Void = {}
        var onInspect: () throws -> Void = {}
        var onRemove: () throws -> Void = {}
        init(native: Bool = false) throws {
            runtime = try .init(nativeConsumerHosts: native)
            files = try .init()
            let (a, aIdentity) = try files.provisionAccount(runtime.account.accountID)
            let (c, cIdentity) = try files.provisionAccount(otherID)
            account = a; other = c; drain = try a.beginDrain()
            directory = try .init(anchor: files.activity.root.path, relativeDirectory: "Machine", owner: getuid())
            ordinary = try .init(activity: files.activity.open(), admission: files.open(),
                directory: .init(anchor: files.activity.root.path, relativeDirectory: "Machine", owner: getuid()), expected: files.identity)
            inventory = try runtime.plan.enrolledInventory(XCTUnwrap(runtime.machine.inventory()))
            registration = try .init(macID: inventory.macID, installationID: inventory.installationID,
                machine: files.identity, accounts: [.init(accountID: runtime.account.accountID, identity: aIdentity),
                    .init(accountID: otherID, identity: cIdentity)], designatedOwner: nil)
            cohort = try .init(plan: runtime.plan, inventory: inventory, registration: registration, targetAccountID: target)
        }
        deinit { drain.close(); ordinary.close(); directory.close() }
        func make(_ scope: UpdateOrdinaryAdmissionLease.Scope, drain: UpdateDrainToken? = nil,
                  directory: ReleaseDestinationLease? = nil) throws -> RuntimeMaintenanceAuthorityStop {
            try .openOwned(cohort: cohort, scope: scope, drain: drain ?? self.drain, directory: directory ?? self.directory,
                verify: { try self.verify() }, inspect: { job in
                    XCTAssertEqual(job.bytes, self.runtime.plan.authorityJob.bytes)
                    XCTAssertEqual(job.declaration.role, .authority)
                    XCTAssertEqual(job.declaration.accountID, self.runtime.account.accountID)
                    self.inspections += 1; try self.onInspect(); return self.observation
                }, capture: { job, pid in
                    XCTAssertEqual(job.bytes, self.cohort.job.bytes)
                    let witness = self.witnesses[min(self.captures, self.witnesses.count - 1)]
                    XCTAssertEqual(pid, witness.processID); self.captures += 1; return witness
                }, remove: { job in
                    XCTAssertEqual(job.bytes, self.cohort.job.bytes)
                    self.removals += 1; self.observation = .absent; try self.onRemove()
                })
        }
        func run(_ body: (RuntimeMaintenanceAuthorityStop) throws -> Void) throws {
            try ordinary.withMachineAdmission { scope in
                let session = try make(scope); defer { session.close(); verify = {}; onInspect = {}; onRemove = {} }; try body(session)
            }
        }
    }
    func testCohortDerivesOnlyCurrentAuthorityAndPreservesItsSettingsServices() throws {
        let h = try Harness(native: true)
        XCTAssertEqual(h.cohort.job.bytes, h.runtime.plan.authorityJob.bytes)
        XCTAssertTrue(h.cohort.job.machServices.contains(try RuntimePreparationPaths(accountID: h.cohort.accountID).gatewaySettingsControlService))
        XCTAssertNotEqual(h.cohort.job.bytes, h.runtime.plan.transportJob.bytes)
        XCTAssertEqual(h.cohort.accountIdentity, h.registration.accounts.first { $0.accountID == h.cohort.accountID }?.identity)
        XCTAssertEqual(h.cohort.targetAccountID, h.target)
    }
    func testMissingCurrentEnrollmentAndForeignRegistrationCannotSelectACohort() throws {
        let h = try Harness(), p = h.runtime.plan
        XCTAssertThrowsError(try RuntimeMaintenanceAuthorityCohort(plan: p, inventory: XCTUnwrap(h.runtime.machine.inventory()),
            registration: h.registration, targetAccountID: h.target))
        let foreign = try UpdateAdmissionRegistrationRecord(macID: Data(repeating: 12, count: 16),
            installationID: h.inventory.installationID, machine: h.files.identity, accounts: h.registration.accounts, designatedOwner: nil)
        XCTAssertThrowsError(try RuntimeMaintenanceAuthorityCohort(plan: p, inventory: h.inventory,
            registration: foreign, targetAccountID: h.target))
        let missing = try UpdateAdmissionRegistrationRecord(macID: h.inventory.macID, installationID: h.inventory.installationID,
            machine: h.files.identity, accounts: h.registration.accounts.filter { $0.accountID != p.accountID }, designatedOwner: nil)
        XCTAssertThrowsError(try RuntimeMaintenanceAuthorityCohort(plan: p, inventory: h.inventory,
            registration: missing, targetAccountID: h.target))
    }
    func testSameTargetAndRegisteredTargetJobsAreRejectedWithoutRemoval() throws {
        let h = try Harness()
        for target in [Data(), h.cohort.accountID] {
            XCTAssertThrowsError(try RuntimeMaintenanceAuthorityCohort(plan: h.runtime.plan, inventory: h.inventory,
                registration: h.registration, targetAccountID: target))
        }
        let targetJob = try InstalledAccountJobManifest(accountID: h.target, role: .authority, executionUID: 0,
            userName: "root", bundlePath: h.inventory.bundlePath)
        let inventory = try InstallationInventory(macID: h.inventory.macID, installationID: h.inventory.installationID,
            revision: h.inventory.revision, bundlePath: h.inventory.bundlePath, releaseDigest: h.inventory.releaseDigest,
            accounts: h.inventory.accounts + [.init(accountID: h.target, ownerUID: h.runtime.account.ownerUID + 1)],
            services: h.inventory.services + [targetJob.declaration], formatVersion: h.inventory.formatVersion)
        XCTAssertThrowsError(try RuntimeMaintenanceAuthorityCohort(plan: h.runtime.plan, inventory: inventory,
            registration: h.registration, targetAccountID: h.target))
        XCTAssertEqual(h.removals, 0)
    }
    func testAccountDrainLeavesOtherAccountsAndMachineAdmissionOpenWhileActivityStaysShared() throws {
        let h = try Harness()
        try h.run { session in
            XCTAssertThrowsError(try h.account.acquireAdmission())
            let other = try h.other.acquireAdmission(), machine = try h.files.open().acquireAdmission()
            defer { other.close(); machine.close() }
            try other.validate(); try machine.validate()
            XCTAssertThrowsError(try h.files.activity.open().acquireExclusive())
            XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
            XCTAssertEqual(h.removals, 1)
            h.witnesses[0].exited = true; try session.requireRemoved()
        }
        try h.drain.validate(); try h.ordinary.validate()
    }
    func testWrongAccountMachineDrainAndDirectoryCannotReachAnyObservation() throws {
        let h = try Harness(), foreign = try UpdateAdmissionTestFixture()
        let otherDrain = try h.other.beginDrain(); defer { otherDrain.close() }
        let machineDrain = try foreign.open().beginDrain(); defer { machineDrain.close() }
        let foreignDirectory = try ReleaseDestinationLease(anchor: foreign.activity.root.path, relativeDirectory: "Machine", owner: getuid())
        defer { foreignDirectory.close() }
        try h.ordinary.withMachineAdmission { scope in
            XCTAssertThrowsError(try h.make(scope, drain: otherDrain))
            XCTAssertThrowsError(try h.make(scope, drain: machineDrain))
            XCTAssertThrowsError(try h.make(scope, directory: foreignDirectory))
        }
        XCTAssertEqual(h.inspections, 0); XCTAssertEqual(h.removals, 0)
    }
    func testAbsentRegistrationStillWaitsForEveryObservedProcessAndPIDReuse() throws {
        let h = try Harness(), first = h.witnesses[0], reused = Witness(100)
        h.witnesses.append(reused)
        h.onRemove = { h.observation = .matching(100) }
        try h.run { session in
            XCTAssertEqual(try session.poll(), .removingRegistration); XCTAssertEqual(h.captures, 1)
            first.exited = true
            XCTAssertEqual(try session.poll(), .removingRegistration); XCTAssertEqual(h.captures, 2)
            h.observation = .absent
            XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
            reused.exited = true
            XCTAssertEqual(try session.poll(), .registrationRemoved); try session.requireRemoved()
        }
    }
    func testUnknownWitnessRetiresTheSessionWithoutInventingSuccess() throws {
        let h = try Harness()
        try h.run { session in
            XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
            h.witnesses[0].unknown = true
            XCTAssertThrowsError(try session.poll())
            h.witnesses[0].unknown = false; h.witnesses[0].exited = true
            XCTAssertThrowsError(try session.poll()); XCTAssertEqual(h.removals, 1)
        }
    }
    func testLostRemovalReplyUsesWitnessReconciliationWithoutAnotherRemoval() throws {
        let h = try Harness(); h.onRemove = { throw Failure.expected }
        try h.run { session in
            XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
            h.witnesses[0].exited = true
            XCTAssertEqual(try session.poll(), .registrationRemoved); try session.requireRemoved()
            XCTAssertEqual(h.removals, 1)
        }
    }
    func testReappearingOrConflictingRegistrationNeverMutatesDuringValidation() throws {
        for observation in [RuntimeJobStopSession.Observation.matching(nil), .conflicting] {
            let h = try Harness(); h.observation = .absent
            try h.run { session in
                try session.requireRemoved(); h.observation = observation
                XCTAssertThrowsError(try session.requireRemoved())
                h.observation = .absent; XCTAssertThrowsError(try session.poll())
                XCTAssertEqual(h.removals, 0); XCTAssertEqual(h.captures, 0)
            }
        }
    }
    func testExpiredBorrowAndClosedSessionCannotObserveOrReleaseCallerTokens() throws {
        let h = try Harness()
        let escaped = try h.ordinary.withMachineAdmission { try h.make($0) }
        XCTAssertThrowsError(try escaped.poll()); XCTAssertEqual(h.inspections, 0)
        try h.run { session in
            session.close(); session.close(); XCTAssertThrowsError(try session.poll())
        }
        try h.drain.validate(); try h.ordinary.validate()
    }
    func testDrainLossDuringVerificationBlocksRemovalAndPoisonsTheSession() throws {
        let h = try Harness()
        try h.run { session in
            h.verify = { h.drain.close() }
            XCTAssertThrowsError(try session.poll()); XCTAssertEqual(h.inspections, 0); XCTAssertEqual(h.removals, 0)
            h.verify = {}; XCTAssertThrowsError(try session.poll())
        }
    }
    func testCaughtReentryStillPoisonsTheOuterOperationBeforeRemoval() throws {
        let h = try Harness()
        try h.run { session in
            h.onInspect = { XCTAssertThrowsError(try session.poll()) }
            XCTAssertThrowsError(try session.poll()); XCTAssertEqual(h.removals, 0)
            h.onInspect = {}; XCTAssertThrowsError(try session.poll())
        }
    }
    func testForeignThreadCannotInspectOrRemoveTheJob() throws {
        final class Transfer: @unchecked Sendable {
            let session: RuntimeMaintenanceAuthorityStop
            let done = DispatchSemaphore(value: 0)
            var rejected = false
            init(_ session: RuntimeMaintenanceAuthorityStop) { self.session = session }
        }
        let h = try Harness()
        try h.run { session in
            let transfer = Transfer(session)
            DispatchQueue.global().async {
                do { _ = try transfer.session.poll() } catch { transfer.rejected = true }
                transfer.done.signal()
            }
            XCTAssertEqual(transfer.done.wait(timeout: .now() + 3), .success)
            XCTAssertTrue(transfer.rejected); XCTAssertEqual(h.inspections, 0); XCTAssertEqual(h.removals, 0)
            h.observation = .absent; try session.requireRemoved()
        }
    }
    func testForkedSessionCannotInspectRemoveOrReleaseTheParentDrain() throws {
        let h = try Harness()
        try h.run { session in
            let child = Self.forkProcess(); XCTAssertGreaterThanOrEqual(child, 0)
            if child == 0 {
                do { _ = try session.poll(); _exit(11) } catch { session.close(); _exit(0) }
            }
            guard child > 0 else { throw Failure.expected }
            var status: Int32 = 0
            let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
            var reaped = false
            while DispatchTime.now().uptimeNanoseconds < deadline {
                if waitpid(child, &status, WNOHANG) == child { reaped = true; break }
                usleep(10_000)
            }
            if !reaped {
                _ = kill(child, SIGKILL)
                while waitpid(child, &status, 0) < 0 && errno == EINTR {}
            }
            XCTAssertTrue(reaped); XCTAssertEqual(status, 0)
            XCTAssertEqual(h.inspections, 0); XCTAssertEqual(h.removals, 0)
            try h.drain.validate(); h.observation = .absent; try session.requireRemoved()
        }
    }

    private static let forkProcess: @convention(c) () -> pid_t = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork") else {
            preconditionFailure("fork is not available")
        }
        return unsafeBitCast(symbol, to: (@convention(c) () -> pid_t).self)
    }()

}
