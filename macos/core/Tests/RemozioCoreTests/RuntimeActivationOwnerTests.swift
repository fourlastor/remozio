import Darwin
import Foundation
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

final class RuntimeActivationOwnerTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Harness {
        let f: RuntimeActivationFixture
        let privateState: ProtectedSetupDirectory
        let jobs: ProtectedSetupDirectory
        var bootstrapLabels = Set<String>()
        var prepares = 0, registrations = 0
        var stoppedAt: RuntimeActivationOperations.Stage?
        var rejectNextRegistration = false
        init() throws {
            f = try .init(); try f.machine.close()
            // Only the owned fixture anchor becomes traversable. Each database and private output remains private.
            guard chmod(f.f.root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            privateState = try .init(anchor: f.f.root.path, relativePath: "activation-private", owner: getuid())
            jobs = try .init(anchor: f.f.root.path, relativePath: "activation-jobs", owner: getuid(), visibility: .sharedMetadata)
        }
        deinit { privateState.close(); jobs.close() }
        func withMachine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            let machine = try f.f.open(); defer { try? machine.close() }; return try body(machine)
        }
        var operations: RuntimeActivationOperations {
            .init(prepare: { plan, _, _, _, verify in
                self.prepares += 1
                XCTAssertEqual(try plan.encoded, try self.f.plan.encoded)
                XCTAssertThrowsError(try self.f.f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
                try RuntimeActivationFiles.publish(plan: plan, privateState: self.privateState, jobs: self.jobs,
                    owner: getuid(), verifyCurrent: verify)
            }, validate: { plan, _, _, _, verify in
                XCTAssertThrowsError(try self.f.f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
                try AdministrativeSetupPublication.validateRetained(plan.host.canonicalBytes, file: .commandHost,
                    directory: self.privateState, owner: getuid(), verify: verify)
                for job in [plan.authorityJob, plan.transportJob] {
                    try AdministrativeSetupPublication.validateRetained(job.bytes,
                        file: .accountJob(accountID: plan.accountID, role: job.declaration.role), directory: self.jobs,
                        owner: getuid(), verify: verify)
                }
            }, register: { job, verify in
                try verify()
                // A separate real writer must be available before any registration call, including verification callbacks.
                try self.withMachine { machine in
                    let inventory = try XCTUnwrap(machine.inventory())
                    XCTAssertTrue(inventory.services.contains(job.declaration))
                }
                self.registrations += 1; self.bootstrapLabels.insert(job.declaration.label)
                if self.rejectNextRegistration { self.rejectNextRegistration = false; throw Interrupted() }
                try verify()
            }, didStage: { if $0 == self.stoppedAt { throw Interrupted() } })
        }
        func owner(open: (() throws -> PreparationIntentStore)? = nil) throws -> SetupAccountOwner {
            try .init(openMachine: open ?? { try self.f.f.open() }, expectedReleaseDigest: f.f.release,
                resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.f.policy,
                lookupAccount: { uid in
                    guard uid == self.f.f.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return self.f.f.identity
                }, activationOperations: operations)
        }
    }
    private func harness() throws -> Harness {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Owned SQLite/files and logical registration only") }
        return try .init()
    }
    func testReadsArePassiveAndNativeCommandsReceiveNoMachineWriterLease() throws {
        let h = try harness(), owner = try h.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
        XCTAssertNil(before.planDigest); XCTAssertFalse(before.jobsRegistered)
        XCTAssertEqual(h.prepares, 0); XCTAssertEqual(h.registrations, 0)
        XCTAssertEqual(try h.withMachine { _ in try h.f.f.sql("PRAGMA user_version") }, 6)
        let done = try owner.resumeActivation(callerUID: getuid(), expected: before)
        XCTAssertTrue(done.jobsRegistered); XCTAssertNotNil(done.planDigest)
        XCTAssertEqual(h.bootstrapLabels.count, 2)
        XCTAssertEqual(try owner.activationProgress(callerUID: getuid()), done)
        XCTAssertEqual(try owner.resumeActivation(callerUID: getuid(), expected: done), done)
        XCTAssertEqual(h.bootstrapLabels.count, 2)
        XCTAssertEqual(try h.withMachine { try $0.runtimePreparation(accountID: h.f.account.accountID).reference }, try h.f.material.reference)
    }
    func testEachInterruptedStageResumesTheSamePlanFilesAndRegistrations() throws {
        let stages: [RuntimeActivationOperations.Stage] = [.intentRetained, .filesPublished, .inventoryEnrolled,
            .authorityRegistered, .transportRegistered, .completed]
        for stage in stages {
            let h = try harness(), owner = try h.owner(); defer { try? owner.close() }
            h.stoppedAt = stage
            let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
            XCTAssertThrowsError(try owner.resumeActivation(callerUID: getuid(), expected: before)) { XCTAssertTrue($0 is Interrupted) }
            h.stoppedAt = nil
            let retained = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
            let done = try owner.resumeActivation(callerUID: getuid(), expected: retained)
            XCTAssertTrue(done.jobsRegistered); XCTAssertEqual(done.materialID, before.materialID)
            XCTAssertEqual(done.planDigest, retained.planDigest); XCTAssertEqual(h.bootstrapLabels.count, 2)
            let original = try h.withMachine { try $0.runtimeActivation(accountID: h.f.account.accountID).plan?.encoded }
            XCTAssertEqual(original, try h.f.plan.encoded)
            try h.withMachine { _ in } // Every failure and success released the real writer.
        }
    }
    func testLostRegistrationReplyKeepsIdentityAndResumesOnlyTheClaimedJobs() throws {
        let h = try harness(), owner = try h.owner(); defer { try? owner.close() }
        h.rejectNextRegistration = true
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
        XCTAssertThrowsError(try owner.resumeActivation(callerUID: getuid(), expected: before))
        let current = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
        XCTAssertFalse(current.jobsRegistered); XCTAssertNotNil(current.planDigest)
        XCTAssertThrowsError(try owner.resumeActivation(callerUID: getuid(), expected: before)) {
            XCTAssertEqual($0 as? AdministrativeSetupError, .staleProgress)
        }
        let done = try owner.resumeActivation(callerUID: getuid(), expected: current)
        XCTAssertTrue(done.jobsRegistered); XCTAssertEqual(done.materialID, before.materialID); XCTAssertEqual(h.bootstrapLabels.count, 2)
    }
    func testWrongCallerCannotRetainIntentPublishOrRegister() throws {
        let h = try harness(), owner = try h.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
        XCTAssertThrowsError(try owner.resumeActivation(callerUID: getuid() + 1, expected: before))
        XCTAssertEqual(h.prepares, 0); XCTAssertEqual(h.registrations, 0)
        XCTAssertNil(try h.withMachine { try $0.runtimeActivation(accountID: h.f.account.accountID).plan })
    }
    func testLeaseAcquisitionRetryNeverRepeatsAnOperationBody() throws {
        let h = try harness(); var armed = false, busy = 2
        let owner = try h.owner(open: {
            if armed && busy > 0 { busy -= 1; throw JournalLeaseError.busy }; return try h.f.f.open()
        }); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid())); armed = true
        XCTAssertTrue(try owner.resumeActivation(callerUID: getuid(), expected: before).jobsRegistered)
        XCTAssertEqual(busy, 0); XCTAssertEqual(h.prepares, 1); XCTAssertEqual(h.registrations, 2)
    }
    func testNativeFileOperationsRefuseOrdinaryOwnersBeforeAnyScopeOrKeyAccess() throws {
        let h = try harness()
        try h.withMachine { machine in
            let initial = try XCTUnwrap(machine.initialization(accountID: h.f.account.accountID)), inventory = try XCTUnwrap(machine.inventory())
            XCTAssertThrowsError(try RuntimeActivationFiles.prepare(plan: h.f.plan, account: h.f.account, initialization: initial,
                inventory: inventory, verifyCurrent: { XCTFail("Native Root guard precedes all access") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
    private final class Driver: SetupClientDriver, @unchecked Sendable {
        let endpoint: AdministrativeSetupXPCEndpoint
        init(_ endpoint: AdministrativeSetupXPCEndpoint) { self.endpoint = endpoint }
        func start(closed: @escaping @Sendable () -> Void) {}
        func close() { endpoint.close() }
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            switch call {
            case .activationHello: endpoint.activationHello { reply(.version($0)) }
            case .activationProgress: endpoint.activationProgress { reply(.progress($0)) }
            case .activateRuntime(let expected, let authorization):
                do { endpoint.activateRuntime(try expected.bytes, authorization: authorization) { reply(.progress($0)) } }
                catch { reply(.failed) }
            default: reply(.failed)
            }
        }
    }
    func testVersionFiveReadsWithoutAuthorizationAndActivatesOnlyOnAnExplicitAuthorizedCall() async throws {
        let h = try harness(), owner = try h.owner(); defer { try? owner.close() }
        var rights = 0
        let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in rights += 1 }, invalidate: {})
        let channel = AdministrativeSetupChannel(driver: Driver(endpoint), activation: true)
        try await channel.start()
        let read = try await channel.activationProgress(), before = try XCTUnwrap(read)
        XCTAssertEqual(rights, 0); XCTAssertEqual(h.prepares, 0); XCTAssertEqual(h.registrations, 0)
        let form = Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)
        let done = try await channel.activateRuntime(before, authorization: form)
        XCTAssertTrue(done.jobsRegistered); XCTAssertEqual(rights, 1); XCTAssertEqual(h.bootstrapLabels.count, 2)
        let after = try await channel.activationProgress(); XCTAssertEqual(after, done); XCTAssertEqual(rights, 1)
        XCTAssertNil(try done.bytes.range(of: Data(h.f.f.root.path.utf8)))
        XCTAssertNil(try done.bytes.range(of: h.f.material.transportIdentity))
        await channel.close()
    }
    func testOldHandshakesAndDeniedRightsCannotPublishOrRegister() throws {
        for version in 1...5 {
            let h = try harness(), owner = try h.owner(); defer { try? owner.close() }
            let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
            var rights = 0
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in
                rights += 1; throw Interrupted()
            }, invalidate: {})
            switch version {
            case 1: endpoint.hello { _ in }
            case 2: endpoint.enrollmentHello { _ in }
            case 3: endpoint.serviceAccountsHello { _ in }
            case 4: endpoint.runtimeHello { _ in }
            default: endpoint.activationHello { _ in }
            }
            endpoint.activateRuntime(try before.bytes, authorization: Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)) {
                XCTAssertNil($0)
            }
            XCTAssertEqual(rights, version == 5 ? 1 : 0)
            XCTAssertEqual(h.prepares, 0); XCTAssertEqual(h.registrations, 0)
            XCTAssertNil(try h.withMachine { try $0.runtimeActivation(accountID: h.f.account.accountID).plan })
        }
    }
    func testActivationCodecRejectsForeignOwnerAndMalformedProgressBeforeNativeRights() throws {
        let h = try harness(), owner = try h.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.activationProgress(callerUID: getuid()))
        XCTAssertEqual(try SetupActivationProgress.decode(before.bytes), before)
        let limits = try CBORLimits(maxBytes: 384, maxDepth: 1, maxItems: 23)
        guard case .map(let fields) = try DeterministicCBOR.decode(before.bytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (10, .null), (8, .bytes(Data())),
            (9, .boolean(true)), (5, .unsigned(UInt64(getuid() + 1)))] {
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() },
                authorize: { _ in XCTFail("Invalid or foreign input must precede native authorization") }, invalidate: {})
            endpoint.activationHello { _ in }
            var changed = fields; changed[key] = value
            endpoint.activateRuntime(try DeterministicCBOR.encode(.map(changed), limits: limits),
                authorization: Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)) { XCTAssertNil($0) }
        }
        XCTAssertEqual(h.registrations, 0); XCTAssertEqual(h.prepares, 0)
    }

}
