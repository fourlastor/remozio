import Darwin
import Foundation

/// Concrete library effects. The installed Setup has no facade, listener or selector that calls this factory.
final class SetupOrphanInProcessRestoreEffect: Sendable {
    typealias Row = RuntimeMaintenanceWindowRecord
    typealias Joined = SetupRetainedOrphanClaim.Joined
    typealias Frame = RuntimeMaintenanceStartupFrame
    typealias Transition = PreparationIntentStore.RuntimeMaintenanceTransition
    /// Ordinary-owner resources stay on the original phase executor. Root cannot inject this bundle.
    struct OwnedResources: @unchecked Sendable {
        let release: SignedReleaseEvidence
        let admission: UpdateOrdinaryAdmissionLease, directory: ReleaseDestinationLease, accountBarrier: UpdateAdmissionBarrier
        let read: @Sendable () throws -> Frame
        let persist: @Sendable (Row, Row) throws -> Row
        let writeIntent: @Sendable (Row, Joined, Frame) throws -> Transition
        let writeCompletion: @Sendable (Row, Joined, VerifiedUnboundGateObservation, Frame) throws -> Transition
        let verify: @Sendable () throws -> Void
        let inspect: @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation
        let observe: @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness
        let register: @Sendable () throws -> Void
        let makeDriver: @Sendable (SetupRetainedInvocationReservation.RestorationPhases) throws -> any AuthorityMaintenanceClientDriver
        let capturePeer: @Sendable () throws -> any RuntimeJobExitWitness
        let requirePeerLive: @Sendable (any RuntimeJobExitWitness) throws -> Void
        init(release: SignedReleaseEvidence, admission: UpdateOrdinaryAdmissionLease, directory: ReleaseDestinationLease,
            accountBarrier: UpdateAdmissionBarrier, read: @escaping @Sendable () throws -> Frame,
            persist: @escaping @Sendable (Row, Row) throws -> Row,
            writeIntent: @escaping @Sendable (Row, Joined, Frame) throws -> Transition,
            writeCompletion: @escaping @Sendable (Row, Joined, VerifiedUnboundGateObservation, Frame) throws -> Transition,
            verify: @escaping @Sendable () throws -> Void,
            inspect: @escaping @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation,
            observe: @escaping @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness,
            register: @escaping @Sendable () throws -> Void,
            makeDriver: @escaping @Sendable (SetupRetainedInvocationReservation.RestorationPhases) throws -> any AuthorityMaintenanceClientDriver,
            capturePeer: @escaping @Sendable () throws -> any RuntimeJobExitWitness,
            requirePeerLive: @escaping @Sendable (any RuntimeJobExitWitness) throws -> Void) throws {
            try RuntimeMaintenanceOwnedControl.require()
            self.release = release; self.admission = admission; self.directory = directory; self.accountBarrier = accountBarrier
            self.read = read; self.persist = persist; self.writeIntent = writeIntent; self.writeCompletion = writeCompletion
            self.verify = verify; self.inspect = inspect; self.observe = observe; self.register = register
            self.makeDriver = makeDriver; self.capturePeer = capturePeer; self.requirePeerLive = requirePeerLive
        }
    }
    private struct CapturedFrame: @unchecked Sendable { let frame: Frame }
    private let processLease: SetupProcessLease
    private let read: @Sendable () throws -> Frame
    private let makeResources: @Sendable () throws -> OwnedResources
    private init(processLease: SetupProcessLease, read: @escaping @Sendable () throws -> Frame,
        makeResources: @escaping @Sendable () throws -> OwnedResources) {
        self.processLease = processLease; self.read = read; self.makeResources = makeResources
    }
    static func owned(processLease: SetupProcessLease, read: @escaping @Sendable () throws -> Frame,
        makeResources: @escaping @Sendable () throws -> OwnedResources) throws -> SetupOrphanInProcessRestoreEffect {
        try RuntimeMaintenanceOwnedControl.require(); try processLease.validate()
        return .init(processLease: processLease, read: read, makeResources: makeResources)
    }
    func effects(verifyPeer: @escaping @Sendable () throws -> SetupOrphanRecoveryOperations.Peer,
        routing: @escaping @Sendable () -> AdministrativeSetupLifecycle.State,
        checkHost: @escaping @Sendable () throws -> Void,
        importAuthorization: @escaping @Sendable (Data) throws -> SetupRetainedRecoveryAuthorization)
        throws -> SetupOrphanRecoveryOperations.Effects {
        try RuntimeMaintenanceOwnedControl.require()
        return .init(verifyPeer: verifyPeer, routing: routing, checkHost: checkHost, importAuthorization: importAuthorization,
            restore: { joined, target, deadline in try await self.restore(joined: joined, target: target, until: deadline) },
            adopt: { joined, _ in try await joined.finishRecordedRestorationOwned(processLease: self.processLease) })
    }
    func restore(joined: Joined, target: SetupRetainedOrphanClaim.Target,
        until deadline: ContinuousClock.Instant) async throws -> Row {
        try RuntimeMaintenanceOwnedControl.require()
        let phases = try joined.restorationPhases().forAttempt(until: deadline)
        let captured = try await phases.run {
            try self.processLease.validate(); try joined.requireCurrentAuthorization()
            guard target.window != nil else { throw RuntimePreparationError.changedScope }
            let frame = try self.read()
            guard let row = frame.window else { throw PreparationStoreError.notFound }
            try joined.requireRestorationWindow(row)
            return CapturedFrame(frame: frame)
        }
        guard let row = captured.frame.window else { throw PreparationStoreError.notFound }
        if row.shutdownBinding == nil {
            return try await RuntimeMaintenanceUnboundRestoreRunner.restoreOwned(joined: joined, processLease: processLease,
                expected: row, makeResources: makeResources, until: deadline)
        }
        let resources = try await phases.run { try self.makeResources() }
        // Settlement can release the record before this method returns. Close these actual resources directly.
        defer { resources.admission.close(); resources.directory.close() }
        return try await RuntimeMaintenanceStartupRecovery.restoreExplicitOwned(joined: joined,
            processLease: processLease, frame: captured.frame, release: resources.release,
            admission: resources.admission, directory: resources.directory, accountBarrier: resources.accountBarrier,
            read: resources.read, persist: resources.persist, verify: resources.verify,
            inspect: resources.inspect, observe: resources.observe, register: resources.register,
            makeDriver: { try resources.makeDriver(phases) }, capturePeer: resources.capturePeer,
            requirePeerLive: resources.requirePeerLive, until: deadline)
    }
    /// The native recovery operations call this fixed restoration entry.
    static func restoreNative(joined: Joined, target: SetupRetainedOrphanClaim.Target,
        processLease: SetupProcessLease, until deadline: ContinuousClock.Instant) async throws -> Row {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard let window = target.window else { throw RuntimePreparationError.changedScope }
        let accountID = window.scope.authority.accountID
        let phases = try joined.restorationPhases().forAttempt(until: deadline)
        let metadata = try await phases.run {
            try processLease.validate(); try joined.requireRestorationAccount(accountID)
            let metadata = try RuntimeMaintenanceInProcessNativeFrame.capture(accountID: accountID)
            guard let row = metadata.frame.window else { throw PreparationStoreError.notFound }
            try joined.requireRestorationWindow(row); return metadata
        }
        guard let row = metadata.frame.window else { throw PreparationStoreError.notFound }
        if row.shutdownBinding != nil {
            return try await RuntimeMaintenanceStartupRecovery.restoreExplicitNative(joined: joined,
                processLease: processLease, accountID: accountID, until: deadline)
        }
        return try await RuntimeMaintenanceUnboundRestoreRunner.restoreNative(joined: joined,
            processLease: processLease, expected: row, until: deadline)
    }
}

/// Reads fixed native metadata on the admitted executor. It grants no writer or transport capability.
struct RuntimeMaintenanceInProcessNativeFrame: @unchecked Sendable {
    let frame: RuntimeMaintenanceStartupFrame, release: SignedReleaseEvidence, setup: AuthorityCodeEntry
    private init(frame: RuntimeMaintenanceStartupFrame, release: SignedReleaseEvidence, setup: AuthorityCodeEntry) {
        self.frame = frame; self.release = release; self.setup = setup
    }
    static func capture(accountID: Data) throws -> Self {
        guard getuid() == 0, geteuid() == 0, accountID.count == 16 else { throw JournalLeaseError.rootRequired }
        let configuration = try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath)
        guard configuration.machineDirectory == MachineBootstrap.machineDirectory,
              let setup = configuration.codePolicy.entries.first(where: { $0.role == .setupController && $0.active }),
              let app = configuration.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw RuntimePreparationError.changedScope
        }
        let policy = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
            approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
        func verify() throws {
            guard getuid() == 0, geteuid() == 0,
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
        let machine = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
        let frame: RuntimeMaintenanceStartupFrame
        do { frame = try machine.runtimeMaintenanceStartupFrame(accountID: accountID, candidate: release); try machine.close() }
        catch { try? machine.close(); throw error }
        try verify(); return .init(frame: frame, release: release, setup: setup)
    }
}
