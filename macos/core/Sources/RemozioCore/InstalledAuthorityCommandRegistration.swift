import Darwin
import Foundation
import RemozioMach
import RemozioProtocol

/// Resource transfer only. The registration owner must validate the installation before calling this helper.
enum InstalledCommandMachineHandoff {
    static func take(machine: PreparationIntentStore, checkIn: () throws -> mach_port_t) throws -> mach_port_t {
        let port = try checkIn()
        do { try machine.close() }
        catch {
            _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1)
            throw error
        }
        return port
    }
}

/// Retains protected placement through shutdown and machine metadata through validated check-in.
/// Every operation on the machine store uses this lock. The receive host owns a transferred right.
final class InstalledAuthorityCommandRegistration: @unchecked Sendable {
    let configuration: InstalledAuthorityCommandConfiguration
    let releaseActivity: ReleaseActivityBarrier
    let admissionStartup: AuthorityUpdateAdmissionStartup?
    private var startupActivity: ReleaseActivityToken?
    private let lock = NSLock()
    private let path: String
    private let selfPath: String
    private let bundle: URL
    private let requirement: String
    private let placement: ReleaseDestinationLease
    private let machine: PreparationIntentStore
    private var closed = false
    private var taken = false

    static func open(path: String) throws -> InstalledAuthorityCommandRegistration {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let config = try InstalledAuthorityCommandConfiguration.load(path: path)
        let entry = config.codePolicy.entries.first(where: { $0.role == .authority })!
        let requirement = try XPCPeerPolicy(teamID: entry.teamID, componentIdentifier: entry.identifier,
            approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: 0).requirement
            + " and info[\"RemozioSecurityGeneration\"] = \"\(entry.installedGeneration)\""
        try DynamicCodeValidation.validateSelf(requirement: requirement)
        let selfPath = try DynamicCodeValidation.selfPath(), suffix = "/" + InstalledAuthorityCommandConfiguration.executablePath
        guard selfPath.hasSuffix(suffix) else { throw InstalledAuthorityCommandError.wrongExecutable }
        let bundle = URL(fileURLWithPath: String(selfPath.dropLast(suffix.count)))
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        var store: PreparationIntentStore?
        do {
            _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
            let app = config.codePolicy.entries.first(where: { $0.role == .app })!
            try config.validateRelease(SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier), bundlePath: bundle.path)
            let machine = try PreparationIntentStore.open(directoryPath: config.machineDirectory, macID: config.command.macID)
            store = machine
            let activity = try ReleaseActivityBarrier.open(machineDirectory: config.machineDirectory)
            let startup = try activity.acquireShared()
            let admission = try AuthorityUpdateAdmissionStartup.capture(machine: machine, macID: config.command.macID,
                installationID: config.installationID, accountID: config.command.accountID, activity: activity, readCurrent: {
                    let current = try PreparationIntentStore.open(directoryPath: config.machineDirectory, macID: config.command.macID)
                    do {
                        let state = try current.updateAdmissionState()
                        try current.close()
                        return state
                    } catch { try? current.close(); throw error }
                }, openBarrier: { scope, identity in
                    try UpdateAdmissionBarrier.open(machineDirectory: config.machineDirectory, expected: identity, scope: scope)
                })
            let owner = InstalledAuthorityCommandRegistration(configuration: config, activity: activity, startup: startup,
                admission: admission, path: path, selfPath: selfPath,
                bundle: bundle, requirement: requirement, placement: placement, machine: machine)
            try owner.validate()
            return owner
        } catch { try? store?.close(); placement.close(); throw error }
    }
    private init(configuration: InstalledAuthorityCommandConfiguration, activity: ReleaseActivityBarrier, startup: ReleaseActivityToken,
                 admission: AuthorityUpdateAdmissionStartup?, path: String, selfPath: String,
                 bundle: URL, requirement: String, placement: ReleaseDestinationLease, machine: PreparationIntentStore) {
        self.configuration = configuration; releaseActivity = activity; startupActivity = startup
        admissionStartup = admission
        self.path = path; self.selfPath = selfPath; self.bundle = bundle
        self.requirement = requirement; self.placement = placement; self.machine = machine
    }
    private func validate() throws {
        guard !closed, getuid() == 0, geteuid() == 0 else { throw InstalledAuthorityCommandError.unavailable }
        guard try InstalledAuthorityCommandConfiguration.load(path: path).canonicalBytes == configuration.canonicalBytes else {
            throw InstalledAuthorityCommandError.changedConfiguration
        }
        try DynamicCodeValidation.validateSelf(requirement: requirement)
        guard try DynamicCodeValidation.selfPath() == selfPath else { throw InstalledAuthorityCommandError.wrongExecutable }
        _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
        let app = configuration.codePolicy.entries.first(where: { $0.role == .app })!
        let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
        guard let inventory = try machine.loadInventory() else { throw InstalledAuthorityCommandError.wrongInstallation }
        let declaration = try configuration.validate(inventory: inventory, release: release, bundlePath: bundle.path)
        let service = configuration.command.presence.wake.request.service
        guard let continuityDirectory = service.continuityDirectory,
              let intent = try machine.initialization(accountID: configuration.command.accountID), intent.complete,
              intent.installationID == configuration.installationID,
              intent.journalPath == service.journalDirectory + "/journal.sqlite",
              intent.continuityPath == continuityDirectory + "/continuity.sqlite" else {
            throw InstalledAuthorityCommandError.wrongInstallation
        }
        let component = release.manifest.components.first(where: { $0.role == .authority })!
        switch configuration.jobPlacement {
        case .bundled:
            let manifest = try InstallationServiceManifest(declaration: declaration, component: component, configurationPath: path,
                userName: "root", arguments: [component.relativePath, "--command-configuration", path],
                machServices: [service.serviceName, configuration.command.presence.endpoint.serviceName, configuration.command.serviceName],
                runAtLoad: true, keepAlive: true)
            try manifest.validate(ProtectedServiceConfiguration.readPublic(path: bundle.appendingPathComponent(
                "Contents/Library/LaunchDaemons/" + configuration.plistName).path), inventory: inventory, release: release)
        case .systemAccount:
            let manifest = try InstalledAccountJobManifest(accountID: configuration.command.accountID, role: .authority,
                executionUID: 0, userName: "root", bundlePath: bundle.path,
                gatewaySettingsControlEnabled: configuration.gatewaySettingsControlEnabled)
            guard manifest.declaration == declaration, manifest.configurationPath == path else {
                throw InstalledAuthorityCommandError.changedConfiguration
            }
            try manifest.validate(ProtectedServiceConfiguration.readPublic(path: manifest.path), inventory: inventory, release: release)
        }
        try placement.validate()
        try startupActivity?.validate()
        try admissionStartup?.validate()
    }
    /// The startup writer is closed after check-in. Runtime checks retain the original protected inputs and signed identity.
    func validateRuntime() throws {
        try lock.withLock {
            guard !closed, taken, getuid() == 0, geteuid() == 0 else { throw InstalledAuthorityCommandError.unavailable }
            guard try InstalledAuthorityCommandConfiguration.load(path: path).canonicalBytes == configuration.canonicalBytes else {
                throw InstalledAuthorityCommandError.changedConfiguration
            }
            try DynamicCodeValidation.validateSelf(requirement: requirement)
            guard try DynamicCodeValidation.selfPath() == selfPath else { throw InstalledAuthorityCommandError.wrongExecutable }
            try placement.validate()
            try admissionStartup?.validate()
        }
    }
    /// Read optional scope under the original machine lease, before check-in closes it.
    func captureGatewaySettingsStartup() throws -> AuthorityGatewaySettingsStartupRecovery.Snapshot {
        try lock.withLock {
            guard !taken else { throw InstalledAuthorityCommandError.unavailable }
            try validate()
            return AuthorityGatewaySettingsStartupRecovery.capture(machine: machine, authority: configuration)
        }
    }
    /// Only an initially unreadable snapshot needs another short machine lease. No lease survives an asynchronous call.
    func reloadGatewaySettingsStartup() throws -> AuthorityGatewaySettingsStartupRecovery.Snapshot {
        try validateRuntime()
        let current = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.command.macID)
        do {
            try validateRuntime()
            let snapshot = AuthorityGatewaySettingsStartupRecovery.capture(machine: current, authority: configuration)
            try current.close(); try validateRuntime()
            return snapshot
        } catch { try? current.close(); throw error }
    }
    func takeReceiveRight() throws -> mach_port_t {
        try lock.withLock {
            guard !taken else { throw InstalledAuthorityCommandError.unavailable }
            try validate()
            try admissionStartup?.requireCurrent(machine: machine)
            let port = try InstalledCommandMachineHandoff.take(machine: machine) {
                var port = mach_port_t(MACH_PORT_NULL)
                let status = configuration.command.serviceName.withCString { remozio_authority_check_in_service($0, &port) }
                guard status == KERN_SUCCESS else { throw InstalledAuthorityCommandError.unavailable }
                return port
            }
            taken = true
            startupActivity?.close(); startupActivity = nil
            return port
        }
    }
    /// Build the optional control service only from retained codec 3 metadata and current signed scope.
    func makeGatewaySettingsListener(service: AuthorityWakeService) throws -> GatewaySettingsControlXPCListener? {
        guard configuration.gatewaySettingsControlEnabled else { return nil }
        let activity = try releaseActivity.acquireShared(); defer { activity.close() }
        try validateRuntime(); try activity.validate()
        let app = configuration.codePolicy.entries.first(where: { $0.role == .app && $0.active })!
        let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
        try configuration.validateRelease(release, bundlePath: bundle.path)
        guard let authority = configuration.codePolicy.entries.first(where: { $0.role == .authority && $0.active }),
              let setup = configuration.codePolicy.entries.first(where: { $0.role == .setupController && $0.active }),
              let binding = service.gatewaySettingsBinding,
              binding.accountID == configuration.command.accountID else { throw GatewayPreparationError.changedScope }
        let verify: @Sendable () throws -> Void = { [weak self] in
            guard let self else { throw InstalledAuthorityCommandError.unavailable }
            try self.validateRuntime()
        }
        let access = try AuthorityGatewaySettingsAccess(service: service, binding: binding, verifyCurrent: verify)
        let barrier = releaseActivity
        let listener = try GatewaySettingsControlXPCListener(accountID: configuration.command.accountID,
            authorityCode: authority, setupCode: setup, release: release, access: access,
            acquireActivity: { try barrier.acquireShared() })
        try validateRuntime(); try activity.validate()
        return listener
    }

    /// Reads current protected state with a short writer. The caller cannot carry the writer across an await.
    private func withGatewayRecoveryMachine<T>(_ operation: (PreparationIntentStore, SignedReleaseEvidence) throws -> T) throws -> T {
        let activity = try releaseActivity.acquireShared(); defer { activity.close() }
        try validateRuntime(); try activity.validate()
        let app = configuration.codePolicy.entries.first(where: { $0.role == .app && $0.active })!
        let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
        try configuration.validateRelease(release, bundlePath: bundle.path)
        let current = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.command.macID)
        do {
            try validateRuntime(); try activity.validate()
            let result = try operation(current, release)
            try current.close(); try validateRuntime(); try activity.validate()
            return result
        } catch { try? current.close(); throw error }
    }
    /// Capture eligibility before check-in closes the startup machine writer.
    func captureUpdateSchedulingStartup() -> AuthorityUpdateSchedulingStartupSnapshot {
        lock.withLock {
            .init {
                guard !taken else { throw InstalledAuthorityCommandError.unavailable }
                try validate()
                let app = configuration.codePolicy.entries.first(where: { $0.role == .app && $0.active })!
                let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
                let plan = try machine.runtimeActivation(accountID: configuration.command.accountID).plan
                let selected = try AuthorityUpdateSchedulingStartupSelection.capture(plan: plan,
                    configuration: configuration, release: release, bundlePath: bundle.path)
                if selected != nil, admissionStartup?.boundary.accountID != configuration.command.accountID {
                    throw InstalledAuthorityCommandError.unavailable
                }
                return selected
            }
        }
    }

    /// The phone supplies no candidate path. Its validator remains mandatory inside every account read.
    func withUpdateSchedulingCandidate<Value: Sendable>(journal: AuthorityJournal, binding: AuthorityPeerBinding,
        selection: AuthorityUpdateSchedulingStartupSelection,
        validateTransport: @Sendable (JournalTransaction) throws -> Void,
        _ body: (LiveUpdateSchedulingCandidate) throws -> Value) throws -> Value {
        guard binding.scope.macID == configuration.command.macID,
              binding.scope.accountID == configuration.command.accountID else { throw UpdateSchedulingCandidateLeaseError.wrongScope }
        return try withSelectedUpdateCandidate(journal: journal, selection: selection, validateAccount: { tx in
            try validateTransport(tx); try tx.requireDirectApprovalBinding(binding)
        }, body)
    }

    private func withSelectedUpdateCandidate<Value: Sendable>(journal: AuthorityJournal,
        selection: AuthorityUpdateSchedulingStartupSelection,
        validateAccount: @Sendable (JournalTransaction) throws -> Void,
        _ body: (LiveUpdateSchedulingCandidate) throws -> Value) throws -> Value {
        try withoutActuallyEscaping(validateAccount) { validator in
            try withGatewayRecoveryMachine { store, release in
                try selection.requireCurrent(plan: store.runtimeActivation(accountID: configuration.command.accountID).plan,
                    configuration: configuration, release: release, bundlePath: bundle.path)
                guard let selected = try store.updateCandidate(), selected.selected else { throw UpdateSchedulingJournalError.notOffered }
                let destination = try ReleaseDestinationLease.acquire(path: selected.preparation.parent)
                defer { destination.close() }
                let readPolicy: () throws -> AuthorityCodePolicy = {
                    try journal.read { transaction in
                        try AuthoritySelfValidation.validate(transaction: transaction)
                        try validator(transaction)
                        let trust = try transaction.approvalTrustSnapshot()
                        guard trust.macID == self.configuration.command.macID,
                              trust.accountID == self.configuration.command.accountID,
                              let policy = try transaction.codePolicy()?.policy else { throw AuthorityTransportAccessError.unconfigured }
                        return policy
                    }
                }
                let prepared = try UpdateSchedulingPreparedRelease.capture(attemptID: selected.preparation.id,
                    macID: configuration.command.macID, accountID: configuration.command.accountID, destination: destination,
                    store: store, readPolicy: readPolicy)
                return try prepared.withCurrentCandidateLease(macID: configuration.command.macID, accountID: configuration.command.accountID,
                    expected: selected, destination: destination, store: store, readPolicy: readPolicy, body)
            }
        }
    }

    /// Construction performs no migration. The service starts owned offer work only after check-in.
    func makeUpdateSchedulingStartup(selection: AuthorityUpdateSchedulingStartupSelection, journal: AuthorityJournal,
        signer: EnclaveAuthorityRequestSigner, clock: AuthorityClock) throws -> AuthorityUpdateSchedulingStartup {
        let wall: @Sendable () throws -> UInt64 = {
            let value = Date().timeIntervalSince1970 * 1000
            guard value.isFinite, value >= 0, value < Double(UInt64.max) else { throw AuthorityClockError.overflow }
            return UInt64(value)
        }
        let provider = try makePhoneUpdateSchedulingProvider(selection: selection, signer: signer,
            now: { try clock.now() }, wall: wall)
        let policy = try UpdateSchedulingJournalPolicy(clockEpoch: clock.epoch, challengeLifetimeMillis: 30_000,
            maximumOperations: 1024, payloadLimits: .init(maxBytes: 65_536, maxDepth: 16, maxItems: 4096),
            signingLimits: .init(maxBytes: 131_072, maxDepth: 16, maxItems: 4096))
        let offers = try AuthorityUpdateSchedulingOfferOwner(
            intervalMilliseconds: configuration.command.presence.wake.request.maintenanceIntervalMilliseconds) { [self] in
            do {
                return try withSelectedUpdateCandidate(journal: journal, selection: selection, validateAccount: { _ in }) { candidate in
                    try journal.refreshUpdateSchedulingOffer(candidate: candidate, policy: policy,
                        macID: configuration.command.macID, accountID: configuration.command.accountID).snapshot
                }
            } catch UpdateSchedulingJournalError.notOffered { return nil }
        }
        return .init(provider: provider, offers: offers)
    }

    /// This factory does not select a candidate, migrate storage or advertise a feature.
    func makePhoneUpdateSchedulingProvider(selection: AuthorityUpdateSchedulingStartupSelection, signer: EnclaveAuthorityRequestSigner,
        now: @escaping @Sendable () throws -> AuthorityMoment,
        wall: @escaping @Sendable () throws -> UInt64) throws -> AuthorityPhoneUpdateSchedulingProvider {
        guard signer.macID == configuration.command.macID, signer.accountID == configuration.command.accountID else {
            throw AuthorityRequestSignerError.wrongIdentity
        }
        return { [self] journal, binding, frame, validateTransport in
            try withUpdateSchedulingCandidate(journal: journal, binding: binding, selection: selection, validateTransport: validateTransport) { candidate in
                try journal.exchangeUpdateScheduling(candidate: candidate, frame: frame, binding: binding,
                    signer: signer, validateTransport: validateTransport, now: now, wall: wall)
            }
        }
    }

    func gatewayRecoveryStatus() throws -> AuthorityGatewayRecoverySnapshot.Status {
        try withGatewayRecoveryMachine { machine, _ in
            try AuthorityGatewayRecoverySnapshot.status(machine: machine, authority: configuration)
        }
    }
    private func verifyGatewayRecovery(_ snapshot: AuthorityGatewayRecoverySnapshot) throws {
        try withGatewayRecoveryMachine { machine, release in
            try snapshot.withPublicationScope(machine: machine, authority: configuration) { scope in
                try scope.verifyNative(release, verifyCurrent: validateRuntime)
            }
        }
    }
    /// The shared release token covers the complete authenticated exchange. Every metadata read closes its own writer.
    private func withGatewayRecoveryChannel<T: Sendable>(_ snapshot: AuthorityGatewayRecoverySnapshot,
        role: GatewaySettingsConsumerRole, generation: UUID?,
        operation: @Sendable (GatewaySettingsConsumerChannel) async throws -> T) async throws -> T {
        let activity = try releaseActivity.acquireShared(); defer { activity.close() }
        let verify: @Sendable () throws -> Void = { [self] in
            try activity.validate(); try verifyGatewayRecovery(snapshot); try activity.validate()
        }
        try verify(); try Task.checkCancellation()
        let app = configuration.codePolicy.entries.first(where: { $0.role == .app && $0.active })!
        let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
        try configuration.validateRelease(release, bundlePath: bundle.path)
        let channel = try GatewaySettingsConsumerChannel.recovery(role: role,
            services: snapshot.plan.pair.authority.material.runtime.services, codePolicy: configuration.codePolicy,
            release: release, expectedGeneration: generation, verifyCurrent: verify)
        do {
            let result = try await operation(channel)
            await channel.close(); try verify(); try Task.checkCancellation()
            return result
        } catch { await channel.close(); throw error }
    }
    func makeGatewayRecoveryAccess(service: AuthorityWakeService) throws -> AuthorityGatewayRecoveryAccess {
        guard configuration.gatewaySettingsControlEnabled,
              service.gatewaySettingsBinding?.accountID == configuration.command.accountID else {
            throw GatewayPreparationError.changedScope
        }
        return try .init(service: service, operations: .init(verifyCurrent: { [self] in try validateRuntime() },
            capture: { [self] id in
                try withGatewayRecoveryMachine { machine, release in
                    let snapshot = try AuthorityGatewayRecoverySnapshot.load(machine: machine, authority: configuration, attemptID: id)
                    try snapshot.withPublicationScope(machine: machine, authority: configuration) { scope in
                        try scope.verifyNative(release, verifyCurrent: validateRuntime)
                    }
                    return snapshot
                }
            }, verify: { [self] snapshot in try verifyGatewayRecovery(snapshot) },
            publish: { [self] snapshot, ticket in
                try withGatewayRecoveryMachine { machine, release in
                    try snapshot.withPublicationScope(machine: machine, authority: configuration) { scope in
                        _ = try GatewayRuntimeSettingsRecoveryPublication.prepare(scope, release: release,
                            verifyCurrent: validateRuntime, requireRootPaused: ticket.requireValid)
                    }
                }
            }, control: { [self] snapshot, role, action, generation in
                try await withGatewayRecoveryChannel(snapshot, role: role, generation: generation) { channel in
                    try await channel.execute(snapshot.plan.fence, action: action)
                }
            }, observe: { [self] snapshot, role in
                try await withGatewayRecoveryChannel(snapshot, role: role, generation: nil) { channel in
                    try await channel.observeBinding()
                }
            }, remove: { [self] snapshot, ticket, proof in
                try withGatewayRecoveryMachine { machine, release in
                    try snapshot.withPublicationScope(machine: machine, authority: configuration) { scope in
                        _ = try GatewayRuntimeSettingsRecoveryPublication.removeAccepted(scope, release: release,
                            verifyCurrent: validateRuntime, requireFreshAcceptance: {
                                try ticket.requireValid(); try proof.requireValid(for: snapshot.plan)
                            })
                    }
                }
            }))
    }

    func close() throws {
        try lock.withLock {
            guard !closed else { return }
            try machine.close(); admissionStartup?.recovery.close(); placement.close(); startupActivity?.close(); startupActivity = nil; closed = true
        }
    }
    deinit { try? machine.close(); admissionStartup?.recovery.close(); placement.close() }
}

extension AuthorityRuntimeRunner {
    /// Restores one configured command runtime from current protected installation state on every attempt.
    public init(installedCommandConfigurationPath: String, initialRetryMilliseconds: Int = 1000,
                maximumRetryMilliseconds: Int = 30_000, monitorMilliseconds: Int = 250,
                report: @escaping @Sendable (Status) -> Void) throws {
        try self.init(initialRetryMilliseconds: initialRetryMilliseconds, maximumRetryMilliseconds: maximumRetryMilliseconds,
            monitorMilliseconds: monitorMilliseconds, open: {
                let registration = try InstalledAuthorityCommandRegistration.open(path: installedCommandConfigurationPath)
                do {
                    let optionalStartup: AuthorityGatewaySettingsStartupRecovery.Snapshot
                    if registration.configuration.command.presence.wake.phonePush == nil {
                        optionalStartup = try registration.captureGatewaySettingsStartup()
                    } else { optionalStartup = .absent }
                    let schedulingFactory: AuthorityUpdateSchedulingStartupFactory?
                    switch registration.captureUpdateSchedulingStartup() {
                    case .selected(let selection):
                        schedulingFactory = { journal, signer, clock in
                            try registration.makeUpdateSchedulingStartup(selection: selection, journal: journal, signer: signer, clock: clock)
                        }
                    case .unsupported, .unavailable:
                        schedulingFactory = nil
                    }
                    let service = try AuthorityWakeService.openInstalled(configuration: registration.configuration.command,
                        takingRegisteredReceiveRight: { try registration.takeReceiveRight() },
                        releaseActivity: registration.releaseActivity,
                        updateAdmission: registration.admissionStartup?.boundary, updateSchedulingFactory: schedulingFactory,
                        reconcileExpired: Self.reconcileCoordinatorExpiration)
                    let recovery = AuthorityGatewaySettingsStartupRecovery(snapshot: optionalStartup, service: service,
                        reload: { try registration.reloadGatewaySettingsStartup() })
                    let consumerRecovery = AuthorityGatewayRecoverySupervisor(operations: .init(
                        status: { try registration.gatewayRecoveryStatus() },
                        makeCoordinator: { try registration.makeGatewayRecoveryAccess(service: service).makeCoordinator() }))
                    let monitor: AuthorityGatewayExtensionMonitor?
                    if registration.configuration.command.presence.wake.phonePush == nil {
                        monitor = try AuthorityGatewayExtensionMonitor {
                            do {
                                try Task.checkCancellation()
                                let activity = try registration.releaseActivity.acquireShared()
                                defer { activity.close() }
                                let verify: @Sendable () throws -> Void = {
                                    try registration.validateRuntime(); try activity.validate()
                                }
                                guard try await recovery.prepare(verifyCurrent: verify) else {
                                    await service.suspendPhonePush(); return nil
                                }
                                guard try await consumerRecovery.refresh() else {
                                    await service.suspendPhonePush(); return nil
                                }
                                guard let loaded = try GatewayRuntimeLoader.load(authority: registration.configuration, verifyCurrent: verify) else {
                                    await service.suspendPhonePush(); return nil
                                }
                                try Task.checkCancellation()
                                _ = try await service.installPhonePush(loaded.configuration.material.phonePush,
                                    commitDigest: loaded.commit.observationDigest, verifyCurrent: verify)
                                try verify(); try Task.checkCancellation()
                                return try loaded.commit.observationDigest
                            } catch {
                                await service.suspendPhonePush(); throw error
                            }
                        }
                    } else { monitor = nil }
                    let settings = try AuthorityGatewaySettingsListenerSupervisor {
                        guard registration.configuration.gatewaySettingsControlEnabled else { return nil }
                        return AuthorityGatewaySettingsRuntime {
                            try registration.makeGatewaySettingsListener(service: service)
                        }
                    }
                    return AuthorityRuntimeInstance(start: {
                        let activity = try registration.releaseActivity.acquireShared()
                        do {
                            _ = try await recovery.prepare(verifyCurrent: {
                                try registration.validateRuntime(); try activity.validate()
                            })
                            try activity.validate(); activity.close()
                        } catch { activity.close(); throw error }
                        try await service.start(); try await settings.start(); try await monitor?.start()
                    }, close: {
                        await monitor?.close(); await consumerRecovery.close(); await settings.close()
                        try await service.close(); try registration.close()
                    }, retired: { await service.isRetired })
                } catch { try? registration.close(); throw error }
            }, report: report)
    }
}
