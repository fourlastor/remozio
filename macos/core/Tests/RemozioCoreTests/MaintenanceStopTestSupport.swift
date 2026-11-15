import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

enum MaintenanceStopTestFault: Error { case expected, changedProcess }
final class MaintenanceStopTestWitness: RuntimeJobExitWitness, Sendable {
    let processID: pid_t = 100
    let exited = Mutex(false)
    func hasExited() throws -> Bool { exited.withLock { $0 } }
}
final class MaintenanceStopTestDriver: AuthorityMaintenanceClientDriver, Sendable {
    struct State {
        var invalidated: (@Sendable () -> Void)?
        var requests: [AuthorityMaintenanceChannelRequest] = []
        var incarnation = maintenanceCloseBytes(61), busyObservations = 0
    }
    let state = Mutex(State())
    var requests: [AuthorityMaintenanceChannelRequest] { state.withLock { $0.requests } }
    static func work(busy: Bool = false, ready: Bool = true) throws -> AuthorityMaintenanceChannelWork {
        try .init(journal: .init(requests: .init(liveRequests: busy ? 1 : 0, commandCaptures: 0, activityOwners: 0),
            exchanges: .init(active: 0, stopped: false), nativeExecutions: 0, executionActivityOwners: 0),
            execution: .init(started: true, stopping: false, failed: false, queuedTurns: 0, rejectedTurns: 0),
            pairing: .init(ready: ready, stagedAttempts: 0, activityOwners: 0, operationActive: false))
    }
    func start(_ invalidated: @escaping @Sendable () -> Void) { state.withLock { $0.invalidated = invalidated } }
    func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) { reply(.hello(1)) }
    func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        do {
            let q = try AuthorityMaintenanceChannelRequest.decode(bytes)
            let observed = state.withLock { s in
                s.requests.append(q)
                let busy = q.action == .observe && s.busyObservations > 0
                if busy { s.busyObservations -= 1 }
                return (s.incarnation, busy)
            }
            let binding = try q.binding ?? .init(accountID: q.accountID, attemptID: q.attemptID, revision: q.revision,
                incarnation: observed.0, connectionID: maintenanceCloseBytes(62))
            let refused = q.binding != nil && q.binding?.incarnation != observed.0
            let observes = [.open, .observe, .arm].contains(q.action)
            let value = try AuthorityMaintenanceChannelResponse(request: q, binding: binding,
                work: observes && !refused ? Self.work(busy: observed.1) : nil, outcome: refused ? .refused : .applied)
            reply(.bytes(try value.encoded))
        } catch { reply(.bytes(nil)) }
    }
    func close() { let f = state.withLock { $0.invalidated }; f?() }
}

/// Real owned admission files and synthetic installed metadata. No callback grants Root authority.
final class MaintenanceStopTestFixture: @unchecked Sendable {
    let runtime: RuntimeActivationFixture, files: UpdateAdmissionTestFixture
    let directory: ReleaseDestinationLease, ordinary: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken
    let cohort: RuntimeMaintenanceAuthorityCohort, window: RuntimeMaintenanceWindowRecord
    let initialization: AuthorityInitializationIntent
    let driver = MaintenanceStopTestDriver(), witness = MaintenanceStopTestWitness()
    let ownerValid = Mutex(true)
    init() throws {
        runtime = try .init(); files = try .init()
        initialization = try XCTUnwrap(runtime.machine.initialization(accountID: runtime.account.accountID))
        let (barrier, identity) = try files.provisionAccount(runtime.account.accountID)
        drain = try barrier.beginDrain()
        directory = try .init(anchor: files.activity.root.path, relativeDirectory: "Machine", owner: getuid())
        ordinary = try .init(activity: files.activity.open(), admission: files.open(),
            directory: .init(anchor: files.activity.root.path, relativeDirectory: "Machine", owner: getuid()), expected: files.identity)
        let inventory = try runtime.plan.enrolledInventory(XCTUnwrap(runtime.machine.inventory()))
        let registration = try UpdateAdmissionRegistrationRecord(macID: inventory.macID, installationID: inventory.installationID,
            machine: files.identity, accounts: [.init(accountID: runtime.account.accountID, identity: identity)], designatedOwner: nil)
        let target = try RuntimeMaintenanceWindowRecord.Account(accountID: maintenanceCloseBytes(98),
            ownerUID: runtime.account.ownerUID + 1, directoryID: maintenanceCloseBytes(97))
        var directoryUUID = runtime.account.directoryID.uuid
        let account = try RuntimeMaintenanceWindowRecord.Account(accountID: runtime.account.accountID,
            ownerUID: runtime.account.ownerUID, directoryID: withUnsafeBytes(of: &directoryUUID) { Data($0) })
        let scope = try RuntimeMaintenanceWindowRecord.Scope(macID: inventory.macID, installationID: inventory.installationID,
            authority: account, target: target, releaseDigest: inventory.releaseDigest,
            candidateDigest: maintenanceCloseBytes(71, 32), authorityPolicyDigest: maintenanceCloseBytes(72, 32),
            operationDigest: maintenanceCloseBytes(73, 32), restorationDigest: maintenanceCloseBytes(74, 32),
            mutationFootprintDigest: maintenanceCloseBytes(75, 32), authorityGrantDigest: maintenanceCloseBytes(76, 32),
            targetConsentDigest: maintenanceCloseBytes(77, 32), administratorIntentDigest: maintenanceCloseBytes(78, 32))
        window = try .init(id: maintenanceCloseBytes(80), revision: maintenanceCloseBytes(81),
            purpose: .retainedPolicy, scope: scope, phase: .draining)
        cohort = try .init(plan: runtime.plan, inventory: inventory, registration: registration, targetAccountID: target.accountID)
    }
    deinit { drain.close(); ordinary.close(); directory.close() }
    func client(revision: Data? = nil) throws -> AuthorityMaintenanceXPCClient {
        let q = try AuthorityMaintenanceChannelRequest(action: .open, accountID: cohort.accountID, attemptID: window.id,
            revision: revision ?? window.revision, installationID: window.scope.installationID,
            gate: cohort.accountIdentity, binding: nil, challenge: maintenanceCloseBytes(90, 32))
        return try .openOwned(context: q, driver: driver, timeoutMilliseconds: 100, intervalMilliseconds: 1)
    }
    func capture(_ client: AuthorityMaintenanceXPCClient,
        requireProcess: (@Sendable (any RuntimeJobExitWitness) throws -> Void)? = nil) async throws -> RuntimeMaintenanceStopCapture {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        _ = try await client.start(until: deadline)
        return try await client.captureOwnedStop(window: window, cohort: cohort, admission: ordinary, drain: drain,
            directory: directory, configuration: runtime.plan.host, until: deadline, capture: { self.witness },
            requireProcess: { value in
                if let requireProcess { try requireProcess(value) }
                else { guard try !value.hasExited() else { throw MaintenanceStopTestFault.changedProcess } }
            }, verifyOwner: {
                guard self.ownerValid.withLock({ $0 }) else { throw JournalLeaseError.invalidated }
            })
    }
}
