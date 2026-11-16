import Darwin
import Foundation

/// Derived stop inputs only. Metadata grants no idle proof, native removal or journal custody.
struct RuntimeMaintenanceAuthorityCohort {
    let job: InstalledAccountJobManifest
    let accountID: Data
    let targetAccountID: Data
    let machineIdentity: PreparationFileIdentity
    let accountIdentity: PreparationFileIdentity

    /// Checked startup declarations only. The fresh custody is issued separately.
    init(startupJob job: InstalledAccountJobManifest, host: InstalledAuthorityCommandConfiguration,
        inventory: InstallationInventory, registration: UpdateAdmissionRegistrationRecord, targetAccountID: Data) throws {
        let accountID = host.command.accountID
        guard targetAccountID.count == 16, targetAccountID != accountID,
              registration.macID == inventory.macID, registration.installationID == inventory.installationID,
              host.jobPlacement == .systemAccount, host.installationID == inventory.installationID,
              host.releaseDigest == inventory.releaseDigest, host.command.macID == inventory.macID,
              inventory.accounts.contains(where: { $0.accountID == accountID && $0.ownerUID == host.command.callerUID }),
              !inventory.accounts.contains(where: { $0.accountID == targetAccountID }),
              inventory.services.contains(job.declaration), job.bundlePath == inventory.bundlePath,
              job.declaration.role == .authority, job.declaration.accountID == accountID,
              job.declaration.executionUID == 0, job.declaration.domainUID == nil,
              job.declaration.label == host.label, job.declaration.plistName == host.plistName,
              let gate = registration.accounts.first(where: { $0.accountID == accountID }) else {
            throw RuntimePreparationError.changedScope
        }
        self.job = job; self.accountID = accountID; self.targetAccountID = targetAccountID
        machineIdentity = registration.machine; accountIdentity = gate.identity
    }
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
/// The native factory requires its private arm permit. Owned fixtures cannot authorize a system job removal.
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
    private var permit: RuntimeMaintenanceStopPermit?
    private var bodyUsed = false, bodySettled = false, restorationStarted = false, restorationIssued = false
    private let restorationLock = NSLock()
    private var restorationClosed = false
    private var isRestorationClosed: Bool {
        guard getpid() == boundary.processID else { return true }
        return restorationLock.withLock { restorationClosed }
    }
    /// nil until a body pair opens. Only closed proves that storage.close returned for that pair.
    private(set) var bodyPairClose: AuthorityJournalCutoverInspection.CloseOutcome?
    private var openPair: ((AuthorityInitializationIntent, AuthorityCodePolicy) throws -> AuthorityJournalCutoverInspection)?
    private init(boundary: Boundary, session: RuntimeJobStopSession) { self.boundary = boundary; self.session = session }

    static func openNative(permit: RuntimeMaintenanceStopPermit, purpose: RuntimeMaintenanceWindowRecord.Purpose,
        cohort: RuntimeMaintenanceAuthorityCohort, scope: UpdateOrdinaryAdmissionLease.Scope,
        drain: UpdateDrainToken, directory: ReleaseDestinationLease) throws -> RuntimeMaintenanceAuthorityStop {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let target = "system/" + cohort.job.declaration.label
        return try openBound(permit: permit, purpose: purpose, cohort: cohort, scope: scope, drain: drain, directory: directory,
            inspect: { try RuntimeJobStopSession.classify(BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["print", target]), job: cohort.job) },
            remove: { _ = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["bootout", target]) })
    }
    /// Exercises the shared stop and loan with actual owned locks. Root cannot inject these callbacks.
    static func openOwnedBound(permit: RuntimeMaintenanceStopPermit, purpose: RuntimeMaintenanceWindowRecord.Purpose,
        cohort: RuntimeMaintenanceAuthorityCohort, scope: UpdateOrdinaryAdmissionLease.Scope, drain: UpdateDrainToken,
        directory: ReleaseDestinationLease, inspect: @escaping () throws -> RuntimeJobStopSession.Observation,
        remove: @escaping () throws -> Void,
        openPair: @escaping (AuthorityInitializationIntent, AuthorityCodePolicy) throws -> AuthorityJournalCutoverInspection) throws -> RuntimeMaintenanceAuthorityStop {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return try openBound(permit: permit, purpose: purpose, cohort: cohort, scope: scope, drain: drain, directory: directory,
            inspect: inspect, remove: remove, openPair: openPair)
    }
    private static func openBound(permit: RuntimeMaintenanceStopPermit, purpose: RuntimeMaintenanceWindowRecord.Purpose,
        cohort: RuntimeMaintenanceAuthorityCohort, scope: UpdateOrdinaryAdmissionLease.Scope, drain: UpdateDrainToken,
        directory: ReleaseDestinationLease, inspect: @escaping () throws -> RuntimeJobStopSession.Observation,
        remove: @escaping () throws -> Void,
        openPair: ((AuthorityInitializationIntent, AuthorityCodePolicy) throws -> AuthorityJournalCutoverInspection)? = nil) throws -> RuntimeMaintenanceAuthorityStop {
        let witness = try permit.consume(cohort: cohort, purpose: purpose)
        let boundary = Boundary(scope: scope, drain: drain, directory: directory, cohort: cohort, verify: permit.validate)
        return try boundary.perform {
            var removalIssued = false
            let session = RuntimeJobStopSession(verifyCurrent: boundary.check, inspect: {
                let observed = try inspect()
                if case .matching(let pid) = observed {
                    guard pid == witness.processID, try !witness.hasExited() else { throw RuntimePreparationError.changedScope }
                }
                return observed
            }, capture: { pid in
                guard pid == witness.processID else { throw RuntimePreparationError.changedScope }; return witness
            }, bootout: {
                guard !removalIssued else { return }; try permit.requireUnexpired(); removalIssued = true; try remove()
            })
            let owner = RuntimeMaintenanceAuthorityStop(boundary: boundary, session: session)
            owner.permit = permit
            owner.openPair = openPair ?? { initialization, policy in
                try AuthorityJournalCutoverInspection.openForMaintenance(initialization: initialization, policy: policy,
                    scope: scope, drain: drain, directory: directory, machineIdentity: cohort.machineIdentity,
                    accountIdentity: cohort.accountIdentity, verifyOwner: boundary.check)
            }
            return owner
        }
    }
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
    /// Poll until registrationRemoved before requireRemoved. A bound poll error requires recovery without retry.
    func poll() throws -> RuntimeJobStopSession.Progress { try performBound { try permit?.requireUnexpired(); return try session.poll() } }
    /// Fresh observation only. This method never issues removal or captures another process.
    func requireRemoved() throws { try performBound { try permit?.requireUnexpired(); try session.requireRemoved(); try permit?.requireClosed() } }
    private func performBound<Value>(_ body: () throws -> Value) throws -> Value {
        do { return try boundary.perform(body) }
        catch {
            if permit != nil { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            throw error
        }
    }
    /// One synchronous body loan. The pair closes before restoration, including when the body throws.
    func withNativeBody<Value>(purpose: RuntimeMaintenanceWindowRecord.Purpose, initialization: AuthorityInitializationIntent,
        policy: AuthorityCodePolicy, capture expectedCapture: RuntimeMaintenanceStopCapture? = nil,
        _ body: (AuthorityJournalCutoverInspection) throws -> Value) throws -> Value {
        var bodyFailure: Error?
        do { return try performBound {
            guard !bodyUsed, let permit, let openPair, expectedCapture == nil || expectedCapture === permit.capture,
                  permit.capture.window.purpose == purpose,
                  initialization.macID == permit.capture.window.scope.macID, initialization.installationID == permit.capture.window.scope.installationID,
                  initialization.accountID == permit.capture.window.scope.authority.accountID,
                  initialization.releaseDigest == permit.capture.window.scope.releaseDigest,
                  try policy.bytes == permit.capture.configuration.codePolicy.bytes else {
                throw RuntimePreparationError.changedScope
            }
            try session.requireRemoved(); try permit.requireClosed()
            try permit.requireUnexpired()
            let pair = try openPair(initialization, policy)
            bodyPairClose = .open
            defer { try? pair.close(); bodyPairClose = pair.closeOutcome }
            try pair.validate(); try session.requireRemoved(); try permit.requireClosed(); try boundary.check()
            try permit.requireUnexpired(); bodyUsed = true
            let result: Value
            do { result = try body(pair) } catch { bodyFailure = error; bodySettled = true; throw error }
            try pair.validate(); try session.requireRemoved(); try permit.requireClosed(); try boundary.check()
            try pair.close(); bodySettled = true; return result
        } } catch { throw bodyFailure ?? error }
    }
    /// The captured window and whether restoration may start. Ready needs a settled body and a proved pair close.
    var restorationWindow: RuntimeMaintenanceWindowRecord? { permit?.capture.window }
    var restorationReady: Bool { bodyUsed && bodySettled && bodyPairClose == .closed && !restorationIssued && !isRestorationClosed }
    /// Once per stop owner, on its thread. True only for a settled body whose pair close was proved; a repeat never writes.
    func beginRestoration() throws -> Bool {
        guard getpid() == boundary.processID, pthread_equal(pthread_self(), boundary.thread) != 0, !restorationStarted, !isRestorationClosed else {
            throw JournalLeaseError.invalidated
        }
        restorationStarted = true; return restorationReady
    }
    /// One restoration registration after a settled body and a proved pair close. The real writer receipt binds the row.
    func issueNativeRestorationPermit(restoring: PreparationIntentStore.RuntimeMaintenanceTransition,
        replacing settled: RuntimeMaintenanceWindowRecord, admission: UpdateOrdinaryAdmissionLease) throws -> RuntimeMaintenanceRestorationPermit {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let path = boundary.cohort.job.configurationPath, configuration = permit?.capture.configuration
        guard let configuration, let setup = configuration.codePolicy.entries.first(where: { $0.role == .setupController && $0.active }) else {
            throw RuntimePreparationError.changedScope
        }
        let setupPolicy = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
            approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
        return try issueRestorationPermit(restoring: restoring.record, settled: settled, admission: admission, requireReceipt: {
            try restoring.requireReplacement(restoring.record, replacing: settled)
        }, verifyConfiguration: {
            guard getuid() == 0, geteuid() == 0,
                  try InstalledAuthorityCommandConfiguration.load(path: path).canonicalBytes == configuration.canonicalBytes,
                  try DynamicCodeValidation.selfPath() == MachineBootstrap.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath else {
                throw InstalledAuthorityCommandError.changedConfiguration
            }
            try DynamicCodeValidation.validateSelf(requirement: setupPolicy.requirement
                + " and info[\"RemozioSecurityGeneration\"] = \"\(setup.installedGeneration)\"")
        })
    }
    /// Record-only rows for ordinary-owner tests. Root cannot select this issuance.
    func issueOwnedRestorationPermit(restoring: RuntimeMaintenanceWindowRecord, replacing settled: RuntimeMaintenanceWindowRecord,
        admission: UpdateOrdinaryAdmissionLease) throws -> RuntimeMaintenanceRestorationPermit {
        try RuntimeMaintenanceOwnedControl.require()
        return try issueRestorationPermit(restoring: restoring, settled: settled, admission: admission,
            requireReceipt: { try restoring.requireReplacing(settled) }, verifyConfiguration: {})
    }
    private func issueRestorationPermit(restoring: RuntimeMaintenanceWindowRecord, settled: RuntimeMaintenanceWindowRecord,
        admission: UpdateOrdinaryAdmissionLease, requireReceipt: () throws -> Void,
        verifyConfiguration: @escaping @Sendable () throws -> Void) throws -> RuntimeMaintenanceRestorationPermit {
        guard getpid() == boundary.processID, pthread_equal(pthread_self(), boundary.thread) != 0, !restorationIssued, !isRestorationClosed else {
            throw JournalLeaseError.invalidated
        }
        restorationIssued = true
        guard bodyUsed, bodySettled, bodyPairClose == .closed, let permit else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        let window = permit.capture.window, cohort = boundary.cohort
        guard window.purpose == .retainedRuntime, let binding = window.shutdownBinding,
              settled.phase == .workSettled, restoring.phase == .restoring,
              restoring.id == window.id, restoring.purpose == window.purpose, restoring.scope == window.scope,
              restoring.shutdownBinding == binding, settled.shutdownBinding == binding, binding.attemptID == window.id,
              restoring.scope.authority.accountID == cohort.accountID, binding.accountID == cohort.accountID,
              restoring.scope.target.accountID == cohort.targetAccountID,
              restoring.operation != .notStarted, restoring.operation == settled.operation,
              let code = permit.capture.configuration.codePolicy.entries.first(where: { $0.role == .authority && $0.active }) else {
            throw RuntimePreparationError.changedScope
        }
        try settled.requireSameScope(as: restoring); try restoring.requireReplacing(settled); try requireReceipt()
        let held = RuntimeMaintenanceRestorationHold(window: restoring, cohort: cohort, code: code, stopped: permit.capture.witness,
            admission: admission, drain: boundary.drain, directory: boundary.directory, verifyConfiguration: verifyConfiguration)
        let value = RuntimeMaintenanceRestorationPermit(owner: self, held: held)
        try value.validate(); return value
    }
    fileprivate func requireRestorationOpen() throws {
        guard getpid() == boundary.processID, !isRestorationClosed else { throw JournalLeaseError.invalidated }
    }
    /// Retires the session and any restoration permit without releasing the caller's admission or drain ownership.
    func close() {
        guard getpid() == boundary.processID else { return }
        restorationLock.withLock { restorationClosed = true }; boundary.close()
    }
    deinit { close() }
}

/// One Authority registration for the exact restoring row. Setup's held account drain replaces the ordinary shared account
/// lease. It grants no stop, body, journal or continuity custody, healthy open or admission reopen.
/// Registration runs on the stop owner's thread while the stop owner and capture remain valid.
final class RuntimeMaintenanceRestorationPermit {
    private let held: RuntimeMaintenanceRestorationHold
    var window: RuntimeMaintenanceWindowRecord { held.window }
    var cohort: RuntimeMaintenanceAuthorityCohort { held.cohort }
    var code: AuthorityCodeEntry { held.code }
    private weak var owner: RuntimeMaintenanceAuthorityStop?
    private let processID = getpid(), thread = pthread_self()
    private let lock = NSLock()
    private var consumed = false, transferred = false
    fileprivate init(owner: RuntimeMaintenanceAuthorityStop, held: RuntimeMaintenanceRestorationHold) {
        self.owner = owner; self.held = held
    }
    func validate() throws {
        guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0, let owner else { throw JournalLeaseError.invalidated }
        try owner.requireRestorationOpen(); try held.validate(); try owner.requireRestorationOpen()
    }
    /// Single use, including when the first registration fails. No shared account lease is taken.
    func withRegistration(_ body: (InstalledAccountJobManifest, () throws -> Void) throws -> Void) throws {
        guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
        try lock.withLock { guard !consumed else { throw JournalLeaseError.invalidated }; consumed = true }
        try validate(); try body(held.cohort.job, validate); try validate()
    }
    /// Once, on the stop owner's thread, after this permit was consumed. The hold keeps no stop owner, boundary, scope or capture.
    func transferHold() throws -> RuntimeMaintenanceRestorationHold {
        try validate()
        try lock.withLock { guard consumed, !transferred else { throw JournalLeaseError.invalidated }; transferred = true }
        return held
    }
}

/// Process-bound restoration evidence after registration. Every check is fresh and thread-free: machine activity,
/// the account drain, the installed configuration and the original process exit. It holds no stop owner or scope.
final class RuntimeMaintenanceRestorationHold: @unchecked Sendable {
    let window: RuntimeMaintenanceWindowRecord, cohort: RuntimeMaintenanceAuthorityCohort, code: AuthorityCodeEntry
    private enum Origin {
        case stop(any RuntimeJobExitWitness)
        case startup(RuntimeMaintenanceStartupRecovery.Custody)
    }
    private let origin: Origin
    private let admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken, directory: ReleaseDestinationLease
    private let verifyConfiguration: @Sendable () throws -> Void
    private let processID = getpid(), ownerUID = getuid()
    fileprivate init(window: RuntimeMaintenanceWindowRecord, cohort: RuntimeMaintenanceAuthorityCohort, code: AuthorityCodeEntry,
        stopped: any RuntimeJobExitWitness, admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken,
        directory: ReleaseDestinationLease, verifyConfiguration: @escaping @Sendable () throws -> Void) {
        self.window = window; self.cohort = cohort; self.code = code; self.origin = .stop(stopped); self.admission = admission
        self.drain = drain; self.directory = directory; self.verifyConfiguration = verifyConfiguration
    }
    private init(custody: RuntimeMaintenanceStartupRecovery.Custody, window: RuntimeMaintenanceWindowRecord) {
        self.window = window; cohort = custody.floor.cohort; code = custody.floor.code
        origin = .startup(custody); admission = custody.admission; drain = custody.drain; directory = custody.directory
        verifyConfiguration = custody.verifyConfiguration
    }
    static func startup(_ custody: RuntimeMaintenanceStartupRecovery.Custody,
        window: RuntimeMaintenanceWindowRecord) throws -> RuntimeMaintenanceRestorationHold {
        try custody.requireRestoring(window)
        return .init(custody: custody, window: window)
    }
    func requireStartupOrigin() throws {
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        guard case .startup(let custody) = origin else { throw JournalLeaseError.invalidated }
        try custody.validateResources(recovery: true)
    }
    func requireNewProcess(_ pid: pid_t) throws {
        if case .stop(let witness) = origin {
            guard pid != witness.processID, try witness.hasExited() else { throw RuntimeActivationError.unavailable }
        }
    }
    func requireOldExit() throws {
        switch origin {
        case .stop(let witness):
            guard try witness.hasExited() else { throw RuntimeActivationError.unavailable }
        case .startup(let custody): try custody.validateResources()
        }
    }
    func validate() throws {
        guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
        try admission.validateMachineBoundary(directory: directory, expected: cohort.machineIdentity)
        try drain.validateAccountBoundary(directory: directory, accountID: cohort.accountID, expected: cohort.accountIdentity)
        try verifyConfiguration()
        try requireOldExit()
        try admission.validateMachineBoundary(directory: directory, expected: cohort.machineIdentity)
        try drain.validateAccountBoundary(directory: directory, accountID: cohort.accountID, expected: cohort.accountIdentity)
    }
    /// Only the restoration owner reaches this, after the committed healthy pending row. A's local hold still blocks requests.
    func releaseDrain() throws { try validate(); drain.close() }
}
