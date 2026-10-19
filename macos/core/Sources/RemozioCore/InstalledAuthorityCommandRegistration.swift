import Darwin
import Foundation
import RemozioMach

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
            let owner = InstalledAuthorityCommandRegistration(configuration: config, activity: activity, startup: startup, path: path, selfPath: selfPath,
                bundle: bundle, requirement: requirement, placement: placement, machine: machine)
            try owner.validate()
            return owner
        } catch { try? store?.close(); placement.close(); throw error }
    }
    private init(configuration: InstalledAuthorityCommandConfiguration, activity: ReleaseActivityBarrier, startup: ReleaseActivityToken,
                 path: String, selfPath: String,
                 bundle: URL, requirement: String, placement: ReleaseDestinationLease, machine: PreparationIntentStore) {
        self.configuration = configuration; releaseActivity = activity; startupActivity = startup
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
                executionUID: 0, userName: "root", bundlePath: bundle.path)
            guard manifest.declaration == declaration, manifest.configurationPath == path else {
                throw InstalledAuthorityCommandError.changedConfiguration
            }
            try manifest.validate(ProtectedServiceConfiguration.readPublic(path: manifest.path), inventory: inventory, release: release)
        }
        try placement.validate()
        try startupActivity?.validate()
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
        }
    }
    func takeReceiveRight() throws -> mach_port_t {
        try lock.withLock {
            guard !taken else { throw InstalledAuthorityCommandError.unavailable }
            try validate()
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
    func close() throws {
        try lock.withLock {
            guard !closed else { return }
            try machine.close(); placement.close(); startupActivity?.close(); startupActivity = nil; closed = true
        }
    }
    deinit { try? machine.close(); placement.close() }
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
                    let service = try AuthorityWakeService.open(configuration: registration.configuration.command,
                        takingRegisteredReceiveRight: { try registration.takeReceiveRight() },
                        releaseActivity: registration.releaseActivity,
                        reconcileExpired: Self.reconcileCoordinatorExpiration)
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
                    return AuthorityRuntimeInstance(start: {
                        try await service.start(); try await monitor?.start()
                    }, close: {
                        await monitor?.close(); try await service.close(); try registration.close()
                    }, retired: { await service.isRetired })
                } catch { try? registration.close(); throw error }
            }, report: report)
    }
}
