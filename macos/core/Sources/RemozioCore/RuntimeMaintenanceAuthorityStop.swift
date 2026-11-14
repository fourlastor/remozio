import Darwin
import Foundation

/// Derived stop inputs only. Metadata grants no idle proof, native removal or journal custody.
struct RuntimeMaintenanceAuthorityCohort {
    let job: InstalledAccountJobManifest
    let accountID: Data
    let targetAccountID: Data
    let machineIdentity: PreparationFileIdentity
    let accountIdentity: PreparationFileIdentity

    init(plan: RuntimeActivationPlan, inventory: InstallationInventory,
         registration: UpdateAdmissionRegistrationRecord, targetAccountID: Data) throws {
        let services = plan.reference.services
        guard targetAccountID.count == 16, targetAccountID != plan.accountID,
              registration.macID == inventory.macID, registration.installationID == inventory.installationID,
              services.macID == inventory.macID, services.installationID == inventory.installationID,
              services.releaseDigest == inventory.releaseDigest, plan.bundlePath == inventory.bundlePath,
              plan.host.jobPlacement == .systemAccount,
              try plan.enrolledInventory(inventory) == inventory,
              !inventory.services.contains(where: { $0.accountID == targetAccountID }),
              let gate = registration.accounts.first(where: { $0.accountID == plan.accountID }) else {
            throw RuntimeActivationError.changedScope
        }
        let selected = plan.authorityJob
        guard selected.declaration.role == .authority, selected.declaration.accountID == plan.accountID,
              selected.declaration.executionUID == 0, selected.declaration.domainUID == nil,
              selected.declaration.label == plan.host.label, selected.declaration.plistName == plan.host.plistName,
              selected.bundlePath == plan.bundlePath else { throw RuntimeActivationError.changedScope }
        job = selected; accountID = plan.accountID; self.targetAccountID = targetAccountID
        machineIdentity = registration.machine; accountIdentity = gate.identity
    }
}

/// Retains every observed process witness. Registration removal alone is not whole-runtime settlement.
/// Only ordinary-owner fixtures can construct this session until the live idle proof and native permit exist.
final class RuntimeMaintenanceAuthorityStop {
    private final class Boundary {
        let processID = getpid(), thread = pthread_self()
        let lock = NSLock()
        let scope: UpdateOrdinaryAdmissionLease.Scope
        let drain: UpdateDrainToken
        let directory: ReleaseDestinationLease
        let cohort: RuntimeMaintenanceAuthorityCohort
        let verify: () throws -> Void
        var active = false, retired = false
        init(scope: UpdateOrdinaryAdmissionLease.Scope, drain: UpdateDrainToken, directory: ReleaseDestinationLease,
             cohort: RuntimeMaintenanceAuthorityCohort, verify: @escaping () throws -> Void) {
            self.scope = scope; self.drain = drain; self.directory = directory; self.cohort = cohort; self.verify = verify
        }
        func check() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else {
                throw JournalLeaseError.invalidated
            }
            try lock.withLock { guard active, !retired else { throw JournalLeaseError.invalidated } }
            try scope.validateMachineBoundary(directory: directory, expected: cohort.machineIdentity)
            try drain.validateAccountBoundary(directory: directory, accountID: cohort.accountID, expected: cohort.accountIdentity)
            try verify()
            try scope.validateMachineBoundary(directory: directory, expected: cohort.machineIdentity)
            try drain.validateAccountBoundary(directory: directory, accountID: cohort.accountID, expected: cohort.accountIdentity)
            try lock.withLock { guard active, !retired else { throw JournalLeaseError.invalidated } }
        }
        func perform<Value>(_ body: () throws -> Value) throws -> Value {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else {
                throw JournalLeaseError.invalidated
            }
            try lock.withLock {
                guard !active, !retired else { retired = true; throw JournalLeaseError.invalidated }
                active = true
            }
            defer { lock.withLock { active = false } }
            do { try check(); let result = try body(); try check(); return result }
            catch { lock.withLock { retired = true }; throw error }
        }
        func close() {
            guard getpid() == processID else { return }
            lock.withLock { retired = true }
        }
    }
    private let boundary: Boundary
    private let session: RuntimeJobStopSession
    private init(boundary: Boundary, session: RuntimeJobStopSession) { self.boundary = boundary; self.session = session }

    /// The callbacks model observations only. Root cannot use this seam to authorize a system job removal.
    static func openOwned(cohort: RuntimeMaintenanceAuthorityCohort, scope: UpdateOrdinaryAdmissionLease.Scope,
        drain: UpdateDrainToken, directory: ReleaseDestinationLease, verify: @escaping () throws -> Void = {},
        inspect: @escaping (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation,
        capture: @escaping (InstalledAccountJobManifest, pid_t) throws -> any RuntimeJobExitWitness,
        remove: @escaping (InstalledAccountJobManifest) throws -> Void) throws -> RuntimeMaintenanceAuthorityStop {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        let boundary = Boundary(scope: scope, drain: drain, directory: directory, cohort: cohort, verify: verify)
        return try boundary.perform {
            let session = RuntimeJobStopSession(verifyCurrent: boundary.check,
                inspect: { try inspect(cohort.job) }, capture: { try capture(cohort.job, $0) },
                bootout: { try remove(cohort.job) })
            return .init(boundary: boundary, session: session)
        }
    }
    func poll() throws -> RuntimeJobStopSession.Progress { try boundary.perform { try session.poll() } }
    /// Fresh observation only. This method never issues removal or captures another process.
    func requireRemoved() throws { try boundary.perform { try session.requireRemoved() } }
    /// Retires the session without releasing the caller's admission or drain ownership.
    func close() { boundary.close() }
    deinit { close() }
}
