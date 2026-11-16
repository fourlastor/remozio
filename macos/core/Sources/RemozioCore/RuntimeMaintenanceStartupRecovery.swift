import Darwin
import Foundation

enum RuntimeMaintenanceStartupAttemptError: Error { case beforePending }

struct RuntimeMaintenanceStartupFailure: Error {
    let failure: RuntimeMaintenanceWindowRecord.Failure
    let underlying: Error
    init(_ failure: RuntimeMaintenanceWindowRecord.Failure, _ underlying: Error) {
        self.failure = failure; self.underlying = underlying
    }
}

/// Owns new startup custody. A retained row selects work but never constructs a stop owner or an exit witness.
final class RuntimeMaintenanceStartupRecovery: @unchecked Sendable {
    typealias Record = RuntimeMaintenanceWindowRecord
    typealias Transition = PreparationIntentStore.RuntimeMaintenanceTransition
    typealias Frame = RuntimeMaintenanceStartupFrame
    enum Result {
        case nothing, ownerRecovery(Record), probeRequired
        case cancelAndReopen(Custody)
        case restoration(PreparedRestoration)
    }
    final class Custody: @unchecked Sendable {
        let floor: RuntimeMaintenanceStartupFloor
        let admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken, directory: ReleaseDestinationLease
        let native: Bool
        let verifyConfiguration: @Sendable () throws -> Void
        private let verifyCaller: @Sendable () throws -> Void
        let inspect: @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation
        let observe: @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness
        private let read: @Sendable () throws -> Frame
        private let writeNative: (@Sendable (Record, Record, Frame) throws -> Transition)?
        private let writeOwned: (@Sendable (Record, Record) throws -> Record)?
        fileprivate let release: SignedReleaseEvidence
        private let lock = NSRecursiveLock(), processID = getpid(), ownerUID = getuid()
        private var row: Record, invalidated = false, registrationUsed = false, recoveryUsed = false
        fileprivate init(floor: RuntimeMaintenanceStartupFloor, row: Record, admission: UpdateOrdinaryAdmissionLease,
            drain: UpdateDrainToken, directory: ReleaseDestinationLease, release: SignedReleaseEvidence,
            read: @escaping @Sendable () throws -> Frame,
            writeNative: (@Sendable (Record, Record, Frame) throws -> Transition)?,
            writeOwned: (@Sendable (Record, Record) throws -> Record)?,
            verifyCaller: @escaping @Sendable () throws -> Void,
            verifyConfiguration: @escaping @Sendable () throws -> Void,
            inspect: @escaping @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation,
            observe: @escaping @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness) {
            self.floor = floor; self.row = row; self.admission = admission; self.drain = drain; self.directory = directory
            self.release = release; self.read = read; self.writeNative = writeNative; self.writeOwned = writeOwned
            native = writeNative != nil; self.verifyCaller = verifyCaller; self.verifyConfiguration = verifyConfiguration
            self.inspect = inspect; self.observe = observe
        }
        var current: Record { lock.withLock { row } }
        func validateResources(recovery: Bool = false) throws {
            try lock.withLock {
                guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID, !invalidated else {
                    throw JournalLeaseError.invalidated
                }
                try admission.validateMachineBoundary(directory: directory, expected: floor.cohort.machineIdentity)
                // The committed pending row is the only boundary after which the client may close the drain.
                if row.phase != .reopenPending && row.phase != .restored {
                    try drain.validateAccountBoundary(directory: directory, accountID: floor.cohort.accountID,
                        expected: floor.cohort.accountIdentity)
                }
                if recovery { try verifyCaller() } else { try verifyConfiguration() }
                try admission.validateMachineBoundary(directory: directory, expected: floor.cohort.machineIdentity)
            }
        }
        func withRegistration(_ expected: Record, body: () throws -> Void) throws {
            try lock.withLock {
                guard !registrationUsed else { throw JournalLeaseError.invalidated }; registrationUsed = true
                try requireRestoring(expected); try Task.checkCancellation(); try body(); try requireRestoring(expected)
            }
        }
        fileprivate func requireCurrent(_ expected: Record) throws -> Frame {
            try lock.withLock {
                try validateResources(); guard row == expected else { throw PreparationStoreError.staleRevision }
                let first = try read(); try floor.requireCurrent(first, window: expected, release: release)
                let second = try read(); try floor.requireCurrent(second, window: expected, release: release)
                try second.source.actual.requireSame(as: first.source.actual)
                try validateResources(); return second
            }
        }
        func requireRestoring(_ expected: Record) throws {
            guard expected.phase == .restoring else { throw PreparationStoreError.invalidTransition }
            _ = try requireCurrent(expected)
            try drain.validateAccountBoundary(directory: directory, accountID: floor.cohort.accountID,
                expected: floor.cohort.accountIdentity)
        }
        func persistNative(_ next: Record, previous: Record) throws -> Transition {
            if next.phase == .needsOwnerRecovery { return try persistNativeFailure(next, previous: previous) }
            return try persistNativeChecked(next, previous: previous)
        }
        private func persistNativeChecked(_ next: Record, previous: Record) throws -> Transition {
            try lock.withLock {
                guard native, let writeNative else { throw JournalLeaseError.rootRequired }
                let frame = try requireCurrent(previous); try next.requireReplacing(previous)
                try Task.checkCancellation()
                // Every error after entering the writer is uncertain. No recovery write or RPC follows it.
                let receipt: Transition
                do {
                    receipt = try writeNative(next, previous, frame)
                    try receipt.requireReplacement(next, replacing: previous)
                } catch { invalidated = true; throw AuthorityMaintenanceClientError.needsOwnerRecovery }
                row = next
                do { _ = try requireCurrent(next) }
                catch {
                    // The commit is confirmed. A failed scope check can attempt exactly one recovery write.
                    _ = try? persistRecovery(next, failure: .changedScope)
                    throw RuntimePreparationError.changedScope
                }
                return receipt
            }
        }
        func persistOwned(_ next: Record, previous: Record) throws -> Record {
            try RuntimeMaintenanceOwnedControl.require()
            if next.phase == .needsOwnerRecovery { return try persistOwnedFailure(next, previous: previous) }
            return try persistOwnedChecked(next, previous: previous)
        }
        private func persistOwnedChecked(_ next: Record, previous: Record) throws -> Record {
            try RuntimeMaintenanceOwnedControl.require()
            return try lock.withLock {
                guard !native, let writeOwned else { throw JournalLeaseError.unsafeMetadata }
                _ = try requireCurrent(previous); try next.requireReplacing(previous)
                try Task.checkCancellation()
                do {
                    guard try writeOwned(next, previous) == next else { throw PreparationStoreError.staleRevision }
                } catch { invalidated = true; throw AuthorityMaintenanceClientError.needsOwnerRecovery }
                row = next
                do { _ = try requireCurrent(next) }
                catch {
                    _ = try? persistRecovery(next, failure: .changedScope)
                    throw RuntimePreparationError.changedScope
                }
                return next
            }
        }
        /// A confirmed row can record one failure under fresh caller and lock checks.
        /// Host or job drift must not prevent the failure record. An uncertain write still forbids it.
        private func failureFrame(_ next: Record, previous: Record) throws -> Frame {
            try Task.checkCancellation()
            guard !invalidated, !recoveryUsed, row == previous, previous.phase != .needsOwnerRecovery,
                  previous.phase != .restored, next.phase == .needsOwnerRecovery else { throw JournalLeaseError.invalidated }
            recoveryUsed = true; try next.requireReplacing(previous)
            try validateResources(recovery: true)
            let frame = try read()
            guard frame.window == previous else { throw PreparationStoreError.staleRevision }
            try validateResources(recovery: true)
            return frame
        }
        private func persistNativeFailure(_ next: Record, previous: Record) throws -> Transition {
            try lock.withLock {
                guard native, let writeNative else { throw JournalLeaseError.rootRequired }
                let frame = try failureFrame(next, previous: previous)
                try Task.checkCancellation()
                do {
                    let receipt = try writeNative(next, previous, frame)
                    try receipt.requireReplacement(next, replacing: previous); row = next; return receipt
                } catch { invalidated = true; throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            }
        }
        private func persistOwnedFailure(_ next: Record, previous: Record) throws -> Record {
            try RuntimeMaintenanceOwnedControl.require()
            return try lock.withLock {
                guard !native, let writeOwned else { throw JournalLeaseError.unsafeMetadata }
                _ = try failureFrame(next, previous: previous)
                try Task.checkCancellation()
                do {
                    guard try writeOwned(next, previous) == next else { throw PreparationStoreError.staleRevision }
                    row = next; return next
                } catch { invalidated = true; throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            }
        }
        fileprivate func persistRecovery(_ previous: Record, failure: Record.Failure) throws -> Record {
            let next = try RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                service: previous.service, failure: failure)
            if native { _ = try persistNativeFailure(next, previous: previous) }
            else { _ = try persistOwnedFailure(next, previous: previous) }
            return next
        }
        fileprivate func persistRestartBridge(_ next: Record, previous: Record) throws -> Transition? {
            guard [.draining, .stopping].contains(previous.phase), previous.operation == .notStarted,
                  next.phase == .needsOwnerRecovery, next.failure == .serviceUnavailable else {
                throw PreparationStoreError.invalidTransition
            }
            if native { return try persistNativeChecked(next, previous: previous) }
            _ = try persistOwnedChecked(next, previous: previous); return nil
        }
        fileprivate func requireBeforePendingRetry() throws {
            try lock.withLock {
                guard !invalidated, !recoveryUsed, [.draining, .stopping, .restoring].contains(row.phase) else {
                    throw JournalLeaseError.invalidated
                }
                try validateResources(recovery: true)
            }
        }
        func requireCleanup(_ expected: Record) throws { _ = try requireCurrent(expected) }
        func releaseCleanupDrain(after receipt: Transition, pending: Record, previous: Record) throws {
            guard native else { throw JournalLeaseError.rootRequired }
            try receipt.requireReplacement(pending, replacing: previous); try releaseCleanup(pending)
        }
        func releaseOwnedCleanupDrain(after pending: Record) throws {
            try RuntimeMaintenanceOwnedControl.require()
            guard !native else { throw JournalLeaseError.unsafeMetadata }; try releaseCleanup(pending)
        }
        private func releaseCleanup(_ pending: Record) throws {
            try lock.withLock {
                guard row == pending, pending.phase == .reopenPending, pending.service == .notStopped,
                      pending.operation == .notStarted else { throw PreparationStoreError.invalidTransition }
                try validateResources()
                try drain.validateAccountBoundary(directory: directory, accountID: floor.cohort.accountID,
                    expected: floor.cohort.accountIdentity)
                drain.close()
            }
        }
        fileprivate func persist(_ next: Record, previous: Record) throws -> Transition? {
            if native { return try persistNative(next, previous: previous) }
            _ = try persistOwned(next, previous: previous); return nil
        }
        deinit { drain.close(); admission.close(); directory.close() }
    }
    /// Issued after the exact restoring row and one registration or adoption under fresh custody.
    final class PreparedRestoration: @unchecked Sendable {
        let window: Record, previous: Record
        private let custody: Custody, receipt: Transition?
        private let lock = NSLock(), processID = getpid()
        private var consumed = false
        fileprivate init(custody: Custody, window: Record, previous: Record, receipt: Transition?) {
            self.custody = custody; self.window = window; self.previous = previous; self.receipt = receipt
        }
        func requireReceipt() throws {
            guard getpid() == processID else { throw JournalLeaseError.invalidated }
            if let receipt { try receipt.requireReplacement(window, replacing: previous) }
            // A preexisting restoring row has no new receipt. It requires exact protected readback instead.
            try custody.requireRestoring(window)
        }
        func consume() throws -> Custody {
            try lock.withLock {
                guard !consumed else { throw JournalLeaseError.invalidated }; consumed = true
            }
            try requireReceipt(); return custody
        }
    }
    private final class NativeFiles: @unchecked Sendable {
        let configuration: AdministrativeSetupConfiguration, release: SignedReleaseEvidence
        let directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken
        let accountID: Data
        private let processID = getpid()
        init(configuration: AdministrativeSetupConfiguration, release: SignedReleaseEvidence, accountID: Data,
            directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken) {
            self.configuration = configuration; self.release = release; self.accountID = accountID
            self.directory = directory; self.admission = admission; self.drain = drain
        }
        func read() throws -> Frame {
            try use { try $0.runtimeMaintenanceStartupFrame(accountID: accountID, candidate: release) }
        }
        func write(_ next: Record, _ previous: Record, _ frame: Frame) throws -> Transition {
            try use { machine in
                try machine.validateUpdateAdmissionDirectory(directory)
                return try machine.writeRuntimeMaintenanceTransition(next, replacing: previous,
                    expected: frame.source.actual, candidate: release, directory: directory,
                    admission: admission, accountDrain: drain)
            }
        }
        private func use<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            guard getpid() == processID, getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.invalidated }
            let machine = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
            do { let value = try body(machine); try machine.close(); return value }
            catch { try? machine.close(); throw error }
        }
    }
    private let custody: Custody
    private let observeOperation: @Sendable (Record) -> RuntimeMaintenanceRuntimeObservation.State
    private let register: @Sendable (Custody, Record) throws -> Void
    private let lock = NSRecursiveLock()
    private var prepared = false, probePending = false, runUsed = false
    private let afterProbePolicy: @Sendable (Record, Bool) throws -> RuntimeMaintenanceStartupPolicy.Action
    private let continuationRevision = AccountPreparationIntent.randomID()
    private init(custody: Custody,
        observeOperation: @escaping @Sendable (Record) -> RuntimeMaintenanceRuntimeObservation.State,
        register: @escaping @Sendable (Custody, Record) throws -> Void,
        afterProbePolicy: @escaping @Sendable (Record, Bool) throws -> RuntimeMaintenanceStartupPolicy.Action = {
            try RuntimeMaintenanceStartupPolicy.afterProbe($0, sameIncarnation: $1)
        }) {
        self.custody = custody; self.observeOperation = observeOperation; self.register = register; self.afterProbePolicy = afterProbePolicy
    }
    var window: Record { custody.current }

    /// Fixed installed Setup only. Busy means no row write and no RPC.
    static func open(accountID: Data) throws -> RuntimeMaintenanceStartupRecovery? {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let configuration = try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath)
        guard configuration.machineDirectory == MachineBootstrap.machineDirectory,
              let setup = configuration.codePolicy.entries.first(where: { $0.role == .setupController && $0.active }),
              let app = configuration.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw RuntimePreparationError.changedScope
        }
        let policy = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
            approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
        let processID = getpid()
        let verify: @Sendable () throws -> Void = {
            guard getpid() == processID, getuid() == 0, geteuid() == 0,
                  try DynamicCodeValidation.selfPath() == MachineBootstrap.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath,
                  try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath).canonicalBytes
                    == configuration.canonicalBytes else { throw RuntimePreparationError.changedScope }
            try DynamicCodeValidation.validateSelf(requirement: policy.requirement
                + " and info[\"RemozioSecurityGeneration\"] = \"\(setup.installedGeneration)\"")
        }
        try verify()
        let release = try SignedReleaseInspection.inspect(URL(fileURLWithPath: MachineBootstrap.bundlePath),
            teamID: app.teamID, appIdentifier: app.identifier)
        try configuration.validate(release: release)
        func closedMachine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            let machine = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
            do { let value = try body(machine); try machine.close(); return value }
            catch { try? machine.close(); throw error }
        }
        // This read discovers gate identities only. No pre-custody row is used for recovery.
        let registration = try closedMachine { try $0.stableMachineUpdateSnapshot(candidate: release).admission }
        guard let account = registration.accounts.first(where: { $0.accountID == accountID }) else {
            throw RuntimePreparationError.changedScope
        }
        let directory = try ReleaseDestinationLease.acquire(path: configuration.machineDirectory)
        do {
            let admission = try UpdateOrdinaryAdmissionLease.open(machineDirectory: configuration.machineDirectory, expected: registration.machine)
            do {
                let drain = try UpdateAdmissionBarrier.open(machineDirectory: configuration.machineDirectory,
                    expected: account.identity, scope: .account(accountID)).beginDrain()
                do {
                    let files = NativeFiles(configuration: configuration, release: release, accountID: accountID,
                        directory: directory, admission: admission, drain: drain)
                    let read: @Sendable () throws -> Frame = { try files.read() }
                    let frame = try read()
                    guard let row = frame.window else { drain.close(); admission.close(); directory.close(); return nil }
                    if row.phase == .restored || row.phase == .needsOwnerRecovery {
                        drain.close(); admission.close(); directory.close(); return nil
                    }
                    guard frame.source.actual.admission == registration else { throw RuntimePreparationError.changedScope }
                    try configuration.validate(inventory: frame.source.actual.inventory, release: release)
                    let floor = try RuntimeMaintenanceStartupFloor(frame: frame, release: release)
                    let custody = Custody(floor: floor, row: row, admission: admission, drain: drain, directory: directory,
                        release: release, read: read, writeNative: { try files.write($0, $1, $2) },
                        writeOwned: nil, verifyCaller: verify, verifyConfiguration: {
                            try verify()
                            guard try ProtectedServiceConfiguration.read(path: floor.cohort.job.configurationPath) == floor.host.canonicalBytes else {
                                throw RuntimePreparationError.changedScope
                            }
                            let jobDirectory = try ProtectedSetupDirectory(anchor: "/",
                                relativePath: String(InstalledAccountJobManifest.directory.dropFirst()), owner: 0,
                                visibility: .sharedMetadata, createIfMissing: false)
                            defer { jobDirectory.close() }
                            _ = try MachineUpdateRetainedSetupPromotionSourceValidation.retainedJobBytes(
                                floor.cohort.job, directory: jobDirectory, owner: 0)
                            for account in [row.scope.authority, row.scope.target] {
                                guard let prepared = floor.source.preparations.first(where: { $0.accountID == account.accountID }) else {
                                    throw RuntimePreparationError.changedScope
                                }
                                try LocalAccountDirectory.validateOwnership(LocalAccountDirectory.lookup(uid: account.ownerUID),
                                    uid: account.ownerUID, directoryID: prepared.directoryID)
                            }
                        }, inspect: { job in
                            try RuntimeJobStopSession.classify(BoundedNativeCommand.run(executable: "/bin/launchctl",
                                arguments: ["print", "system/" + job.declaration.label]), job: job)
                        }, observe: { try RuntimeJobProcessObservation.open(job: $0, code: $1, processID: $2) })
                    _ = try custody.requireCurrent(row)
                    return .init(custody: custody, observeOperation: { window in
                        // The synchronous M08 loan opens B only and ends before any async transfer.
                        do {
                            try custody.validateResources()
                            let machine = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
                            let frame: PreparationIntentStore.RetainedImportFrame
                            do {
                                let target = try LocalAccountDirectory.lookup(uid: window.scope.target.ownerUID)
                                let entry = try machine.retainedSetupInitialRuntimeEntry(owner: target, candidate: release)
                                let inputs = try machine.withSharedImportJournal { journal in
                                    if let journal { return try machine.withSharedImportSnapshot(journal: journal) { path, owner in
                                        try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: entry.runtime, journal: journal,
                                            verifyCurrent: { try machine.validateStorageLease() },
                                            readRelay: { try .read($0, directory: path, owner: owner) })
                                    } }
                                    return try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: entry.runtime, journal: nil,
                                        verifyCurrent: { try machine.validateStorageLease() }, readRelay: { _ in throw SharedSetupImportError.wrongScope })
                                }
                                frame = (entry, inputs); try machine.close()
                            } catch { try? machine.close(); throw error }
                            return try MachineUpdateRetainedSetupRuntimeNativeContext.withNativeCustody(
                                machineDirectory: configuration.machineDirectory, expected: frame, candidate: release) { loan in
                                try custody.validateResources()
                                return RuntimeMaintenanceRuntimeObservation.observeNative(window: window, expected: frame,
                                    candidate: release, custody: loan)
                            }
                        } catch { return .unknown }
                    }, register: { custody, restoring in
                        try RuntimeJobRegistration.ensureStartupRestoration(custody, window: restoring)
                    })
                } catch { drain.close(); throw error }
            } catch { admission.close(); throw error }
        } catch { directory.close(); throw error }
    }

    /// Native and record-only constructors are separate. Root cannot inject readers, writes, or native callbacks.
    static func openOwned(frame: Frame, release: SignedReleaseEvidence, admission: UpdateOrdinaryAdmissionLease,
        directory: ReleaseDestinationLease, accountBarrier: UpdateAdmissionBarrier,
        read: @escaping @Sendable () throws -> Frame,
        persist: @escaping @Sendable (Record, Record) throws -> Record,
        verify: @escaping @Sendable () throws -> Void,
        inspect: @escaping @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation,
        observe: @escaping @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness,
        observeOperation: @escaping @Sendable (Record) -> RuntimeMaintenanceRuntimeObservation.State,
        register: @escaping @Sendable () throws -> Void,
        afterProbePolicy: @escaping @Sendable (Record, Bool) throws -> RuntimeMaintenanceStartupPolicy.Action = {
            try RuntimeMaintenanceStartupPolicy.afterProbe($0, sameIncarnation: $1)
        }) throws -> RuntimeMaintenanceStartupRecovery {
        try RuntimeMaintenanceOwnedControl.require()
        guard let row = frame.window else { throw PreparationStoreError.notFound }
        let drain = try accountBarrier.beginDrain()
        do {
            let floor = try RuntimeMaintenanceStartupFloor(frame: frame, release: release)
            let custody = Custody(floor: floor, row: row, admission: admission, drain: drain, directory: directory,
                release: release, read: read, writeNative: nil, writeOwned: persist, verifyCaller: {}, verifyConfiguration: verify,
                inspect: inspect, observe: observe)
            _ = try custody.requireCurrent(row)
            return .init(custody: custody, observeOperation: observeOperation, register: { custody, restoring in
                try custody.withRegistration(restoring) { try register() }
            }, afterProbePolicy: afterProbePolicy)
        } catch { drain.close(); throw error }
    }

    /// A one-shot synchronous dispatcher. A probe is the only branch that continues after this returns.
    fileprivate func prepare() throws -> Result {
        try lock.withLock {
            guard !prepared else { throw JournalLeaseError.invalidated }; prepared = true
            let row = custody.current
            _ = try custody.requireCurrent(row)
            switch try RuntimeMaintenanceStartupPolicy.initial(row) {
            case .nothing: return .nothing
            case .ownerRecovery(let failure): return .ownerRecovery(try recover(row, failure: failure))
            case .probeIncarnation: probePending = true; return .probeRequired
            case .observeOperation:
                let operation = RuntimeMaintenanceStartupPolicy.operation(observeOperation(row))
                _ = try custody.requireCurrent(row)
                let settled = try RuntimeMaintenanceStartupPolicy.row(row, phase: .workSettled, operation: operation, service: .stopped)
                _ = try custody.persist(settled, previous: row)
                return .restoration(try restoring(settled))
            case .restore: return .restoration(try restoring(row))
            case .cancelAndReopen, .restartRestoration: throw PreparationStoreError.invalidTransition
            }
        }
    }
    /// The decision uses only the authenticated proof. The caller closes this client before restart work.
    fileprivate func afterAuthenticatedProbe(_ proof: AuthorityMaintenanceIncarnationProof,
        client: AuthorityMaintenanceXPCClient) throws -> RuntimeMaintenanceStartupPolicy.Action {
        try lock.withLock {
            guard prepared, probePending else { throw JournalLeaseError.invalidated }
            let row = custody.current
            do { try proof.requireObserved(by: client) }
            catch { throw RuntimeMaintenanceStartupAttemptError.beforePending }
            guard let target = row.shutdownBinding, proof.accountID == row.scope.authority.accountID else {
                throw RuntimePreparationError.changedScope
            }
            probePending = false
            return try afterProbePolicy(row, proof.incarnation == target.incarnation)
        }
    }
    private struct OwnedClients: Sendable {
        let makeDriver: @Sendable () throws -> any AuthorityMaintenanceClientDriver
        let capturePeer: @Sendable () throws -> any RuntimeJobExitWitness
        let requirePeerLive: @Sendable (any RuntimeJobExitWitness) throws -> Void
        let beforeHealthyOpen: @Sendable (AuthorityMaintenanceXPCClient) async -> Void
        let afterProbe: @Sendable () -> Void
        let beforeCancel: @Sendable (AuthorityMaintenanceXPCClient) async -> Void
    }
    private enum ClientMode { case native, owned(OwnedClients) }
    func runNative(until deadline: ContinuousClock.Instant) async throws -> Record {
        guard getuid() == 0, geteuid() == 0, custody.native else { throw JournalLeaseError.rootRequired }
        return try await run(mode: .native, until: deadline)
    }
    func runOwned(makeDriver: @escaping @Sendable () throws -> any AuthorityMaintenanceClientDriver,
        capturePeer: @escaping @Sendable () throws -> any RuntimeJobExitWitness,
        requirePeerLive: @escaping @Sendable (any RuntimeJobExitWitness) throws -> Void,
        beforeHealthyOpen: @escaping @Sendable (AuthorityMaintenanceXPCClient) async -> Void = { _ in },
        afterProbe: @escaping @Sendable () -> Void = {},
        beforeCancel: @escaping @Sendable (AuthorityMaintenanceXPCClient) async -> Void = { _ in },
        until deadline: ContinuousClock.Instant) async throws -> Record {
        try RuntimeMaintenanceOwnedControl.require()
        guard !custody.native else { throw JournalLeaseError.unsafeMetadata }
        return try await run(mode: .owned(.init(makeDriver: makeDriver, capturePeer: capturePeer,
            requirePeerLive: requirePeerLive, beforeHealthyOpen: beforeHealthyOpen,
            afterProbe: afterProbe, beforeCancel: beforeCancel)), until: deadline)
    }
    private func makeClient(_ mode: ClientMode, context: AuthorityMaintenanceChannelRequest) throws -> AuthorityMaintenanceXPCClient {
        switch mode {
        case .native:
            guard let setup = custody.floor.host.codePolicy.entries.first(where: { $0.role == .setupController && $0.active }) else {
                throw RuntimePreparationError.changedScope
            }
            return try .init(context: context, authority: custody.floor.code, setup: setup, release: custody.release)
        case .owned(let owned):
            return try .openOwned(context: context, driver: owned.makeDriver())
        }
    }
    private func observe(_ client: AuthorityMaintenanceXPCClient, mode: ClientMode,
        until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceIncarnationProof {
        switch mode {
        case .native: return try await client.observeIncarnationNative(until: deadline)
        case .owned: return try await client.observeIncarnationOwned(until: deadline)
        }
    }
    private func run(mode: ClientMode, until deadline: ContinuousClock.Instant) async throws -> Record {
        // A repeated call cannot reach the fallback writer of the first call.
        try lock.withLock {
            guard !runUsed else { throw JournalLeaseError.invalidated }
            runUsed = true
        }
        do {
            try Task.checkCancellation()
            let owner: RuntimeMaintenanceRestoration
            switch try prepare() {
            case .nothing: return window
            case .ownerRecovery(let row): return row
            case .restoration(let prepared): owner = try .openStartup(prepared)
            case .probeRequired:
                let row = window
                let context = try AuthorityMaintenanceChannelRequest(action: .open,
                    accountID: row.scope.authority.accountID, attemptID: row.id, revision: continuationRevision,
                    installationID: row.scope.installationID, gate: custody.floor.cohort.accountIdentity,
                    binding: nil, challenge: AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID())
                let (client, proof, decision) = try await decisionProbe(mode, context: context, until: deadline)
                do {
                    if decision == .cancelAndReopen {
                        let restored: Record
                        switch mode {
                        case .native:
                            restored = try await client.cancelAndReopenStartupNative(proof, custody: custody, until: deadline)
                        case .owned(let owned):
                            await owned.beforeCancel(client)
                            restored = try await client.cancelAndReopenStartupOwned(proof, custody: custody, until: deadline)
                        }
                        await client.close()
                        return restored
                    }
                } catch {
                    await client.close()
                    throw error
                }
                // No store write, registration or process observation uses the decision connection.
                await client.close()
                switch decision {
                case .ownerRecovery(let failure): return try recover(window, failure: failure)
                case .restartRestoration:
                    let previous = window
                    let bridge = try RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                        service: previous.service, failure: .serviceUnavailable)
                    _ = try custody.persistRestartBridge(bridge, previous: previous)
                    owner = try .openStartup(restoring(bridge))
                default: throw PreparationStoreError.invalidTransition
                }
            case .cancelAndReopen: throw PreparationStoreError.invalidTransition
            }
            return try await restoreHealthy(owner, mode: mode, until: deadline)
        } catch {
            if Task.isCancelled || error is CancellationError { throw CancellationError() }
            let row = window
            _ = try? custody.persistRecovery(row, failure: Self.failure(error, fallback: .healthFailed))
            if let failure = error as? RuntimeMaintenanceStartupFailure { throw failure.underlying }
            throw error
        }
    }
    private func decisionProbe(_ mode: ClientMode, context: AuthorityMaintenanceChannelRequest,
        until deadline: ContinuousClock.Instant) async throws -> (AuthorityMaintenanceXPCClient, AuthorityMaintenanceIncarnationProof, RuntimeMaintenanceStartupPolicy.Action) {
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            _ = try custody.requireCurrent(window)
            let client = try makeClient(mode, context: context)
            do {
                let proof = try await observe(client, mode: mode, until: deadline)
                if case .owned(let owned) = mode { owned.afterProbe() }
                try Task.checkCancellation()
                let decision = try afterAuthenticatedProbe(proof, client: client)
                return (client, proof, decision)
            } catch {
                await client.close(); try Task.checkCancellation()
                guard error is AuthorityMaintenanceClientError || error is RuntimeMaintenanceStartupAttemptError else { throw error }
                _ = try custody.requireCurrent(window)
                try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: .milliseconds(250))))
            }
        }
        throw RuntimeMaintenanceStartupFailure(.serviceUnavailable, AuthorityMaintenanceClientError.needsOwnerRecovery)
    }
    private func restoreHealthy(_ owner: RuntimeMaintenanceRestoration, mode: ClientMode,
        until deadline: ContinuousClock.Instant) async throws -> Record {
        var refreshWitness = false
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            try custody.requireBeforePendingRetry()
            if refreshWitness {
                try owner.discardStartupCandidate()
            }
            try await requireRestoringProcess(until: deadline)
            // Check protected metadata and job liveness before creating the new connection.
            try owner.validateBeforePending()
            let context = try owner.openRequest(challenge: AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID())
            let client = try makeClient(mode, context: context)
            do {
                let proof: AuthorityMaintenanceIncarnationProof
                do { proof = try await observe(client, mode: mode, until: deadline) }
                catch { throw RuntimeMaintenanceStartupAttemptError.beforePending }
                let restored: Record
                switch mode {
                case .native:
                    restored = try await client.restoreStartupHealthyNative(proof, owner: owner, until: deadline,
                        persist: { try self.custody.persistNative($0, previous: $1) })
                case .owned(let owned):
                    await owned.beforeHealthyOpen(client)
                    restored = try await client.restoreStartupHealthyOwned(proof, owner: owner,
                        capturePeer: owned.capturePeer, requirePeerLive: owned.requirePeerLive, afterProbe: owned.afterProbe, until: deadline,
                        persist: { try self.custody.persistOwned($0, previous: $1) })
                }
                await client.close()
                return restored
            } catch {
                await client.close()
                try Task.checkCancellation()
                guard case RuntimeMaintenanceStartupAttemptError.beforePending = error else { throw error }
                // Scope failures and policy refusals end the run instead of entering a hidden retry loop.
                try custody.requireRestoring(owner.window)
                refreshWitness = true
                try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: .milliseconds(250))))
            }
        }
        throw RuntimeMaintenanceStartupFailure(.healthFailed, AuthorityMaintenanceClientError.needsOwnerRecovery)
    }
    static func failure(_ error: Error, fallback: Record.Failure) -> Record.Failure {
        if let failure = error as? RuntimeMaintenanceStartupFailure { return failure.failure }
        if error is AuthorityMaintenanceClientError { return .healthFailed }
        if error is RuntimePreparationError || error is PreparationStoreError || error is JournalLeaseError { return .changedScope }
        if error is RuntimeActivationError { return .serviceUnavailable }
        return fallback
    }
    private func recover(_ row: Record, failure: Record.Failure) throws -> Record {
        try custody.persistRecovery(row, failure: failure)
    }
    private func restoring(_ previous: Record) throws -> PreparedRestoration {
        let restoring: Record, receipt: Transition?
        if previous.phase == .restoring { restoring = previous; receipt = nil }
        else {
            restoring = try RuntimeMaintenanceStartupPolicy.row(previous, phase: .restoring, service: .restartPending,
                revision: continuationRevision)
            receipt = try custody.persist(restoring, previous: previous)
        }
        try custody.requireRestoring(restoring)
        do {
            if try custody.inspect(custody.floor.cohort.job) == .absent { try register(custody, restoring) }
        } catch {
            throw RuntimeMaintenanceStartupFailure(Self.failure(error, fallback: .serviceUnavailable), error)
        }
        try custody.requireRestoring(restoring)
        return .init(custody: custody, window: restoring, previous: previous, receipt: receipt)
    }
    private func requireRestoringProcess(until deadline: ContinuousClock.Instant) async throws {
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            try custody.requireRestoring(window)
            do {
                switch try custody.inspect(custody.floor.cohort.job) {
                case .absent, .matching(nil): break
                case .conflicting: throw RuntimeActivationError.unavailable
                case .matching(let pid?):
                    guard pid > 1 else { throw RuntimeActivationError.unavailable }
                    let observed = try custody.observe(custody.floor.cohort.job, custody.floor.code, pid)
                    guard observed.processID == pid, try !observed.hasExited(),
                          try custody.inspect(custody.floor.cohort.job) == .matching(pid) else {
                        throw RuntimeActivationError.unavailable
                    }
                    return
                }
            } catch {
                throw RuntimeMaintenanceStartupFailure(Self.failure(error, fallback: .serviceUnavailable), error)
            }
            try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: .milliseconds(250))))
        }
        throw RuntimeMaintenanceStartupFailure(.serviceUnavailable, RuntimeActivationError.unavailable)
    }
}
