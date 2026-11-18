import Darwin
import Foundation
import RemozioProtocol

public enum AdministrativeSetupServiceError: Error, Equatable { case invalidConfiguration, changedConfiguration, wrongRelease, wrongExecutable }

/// Retained Root-private startup inputs. Provisioning must establish current code floors and registration independently.
public struct AdministrativeSetupConfiguration: Sendable, CustomStringConvertible {
    public static let serviceName = "dev.sebastiano.remozio.macos.setup"
    public static let plistName = "dev.sebastiano.remozio.macos.setup.plist"
    public static let startupPath = "/Library/Application Support/Remozio/setup.cbor"
    public static let executablePath = "Contents/Library/LaunchServices/RemozioSetup"
    public let machineDirectory: String
    public let macID: Data
    public let installationID: Data
    public let releaseDigest: Data
    public let codePolicy: AuthorityCodePolicy
    public let maximumConnections: Int
    public let handshakeTimeoutMilliseconds: UInt64
    public let canonicalBytes: Data
    public var description: String { "AdministrativeSetupConfiguration(redacted)" }

    public init(machineDirectory: String, macID: Data, installationID: Data, releaseDigest: Data, codePolicy: AuthorityCodePolicy,
                maximumConnections: Int = 8, handshakeTimeoutMilliseconds: UInt64 = 5000) throws {
        let parts = machineDirectory.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard machineDirectory.hasPrefix("/"), machineDirectory.utf8.count < Int(PATH_MAX), !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              macID.count == 16, installationID.count == 16, releaseDigest.count == 32,
              (1...64).contains(maximumConnections), (1...60_000).contains(handshakeTimeoutMilliseconds),
              let app = codePolicy.entries.first(where: { $0.role == .app && $0.active }),
              let host = codePolicy.entries.first(where: { $0.role == .setupController && $0.active }),
              app.teamID == host.teamID else { throw AdministrativeSetupServiceError.invalidConfiguration }
        self.machineDirectory = machineDirectory; self.macID = macID; self.installationID = installationID
        self.releaseDigest = releaseDigest; self.codePolicy = codePolicy
        self.maximumConnections = maximumConnections; self.handshakeTimeoutMilliseconds = handshakeTimeoutMilliseconds
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(machineDirectory), 2: .bytes(macID),
            3: .bytes(installationID), 4: .bytes(releaseDigest), 5: .bytes(codePolicy.bytes),
            6: .unsigned(UInt64(maximumConnections)), 7: .unsigned(handshakeTimeoutMilliseconds)]), limits: Self.limits)
    }
    public static func load(path: String) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try decode(ProtectedServiceConfiguration.read(path: path))
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...7),
              f[0] == .unsigned(1), case .text(let directory) = f[1], case .bytes(let mac) = f[2],
              case .bytes(let installation) = f[3], case .bytes(let release) = f[4], case .bytes(let policy) = f[5],
              case .unsigned(let maximum) = f[6], let count = Int(exactly: maximum), case .unsigned(let timeout) = f[7] else {
            throw AdministrativeSetupServiceError.invalidConfiguration
        }
        let result = try Self(machineDirectory: directory, macID: mac, installationID: installation, releaseDigest: release,
            codePolicy: .decode(policy), maximumConnections: count, handshakeTimeoutMilliseconds: timeout)
        guard result.canonicalBytes == bytes else { throw AdministrativeSetupServiceError.invalidConfiguration }; return result
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 2, maxItems: 32) } }

    func validate(release: SignedReleaseEvidence) throws {
        guard try InstallationInventory.digest(release) == releaseDigest else { throw AdministrativeSetupServiceError.wrongRelease }
        try ReleaseGenerationPreflight.validate(release, against: codePolicy)
        for entry in codePolicy.entries where entry.active {
            guard let component = release.manifest.components.first(where: { $0.role == entry.role }),
                  component.generation == entry.installedGeneration, release.codeDirectoryHashes[entry.role] == entry.codeDirectoryHash else {
                throw AdministrativeSetupServiceError.wrongRelease
            }
        }
        guard release.manifest.components.first(where: { $0.role == .setupController })?.relativePath == Self.executablePath else {
            throw AdministrativeSetupServiceError.wrongRelease
        }
    }
    func validate(inventory: InstallationInventory, release: SignedReleaseEvidence) throws {
        guard inventory.macID == macID, inventory.installationID == installationID, inventory.releaseDigest == releaseDigest else {
            throw AdministrativeSetupServiceError.wrongRelease
        }
        try inventory.compareRelease(release); try validate(release: release)
        guard inventory.services.contains(where: { $0.role == .setupController && $0.kind == .daemon && $0.domainUID == nil &&
            $0.executionUID == 0 && $0.accountID == nil && $0.label == Self.serviceName && $0.plistName == Self.plistName }) else {
            throw AdministrativeSetupServiceError.wrongRelease
        }
    }
}

/// Owns verified host custody before the store-backed owner exists.
public final class AdministrativeSetupService: @unchecked Sendable {
    private final class Host: @unchecked Sendable {
        let configurationPath: String, configuration: AdministrativeSetupConfiguration
        let requirement: String, path: String, bundle: URL
        let placement: ReleaseDestinationLease, processLease: SetupProcessLease
        let activity: ReleaseActivityBarrier, release: SignedReleaseEvidence
        let nativeMode: GatewaySettingsNativeSupport.Mode
        let shutdown: AdministrativeSetupShutdown
        let executor = SetupAuditUpgradeWorkExecutor(name: "Remozio setup startup")
        private var preparedOwner: SetupAccountOwner?
        init(configurationPath: String, configuration: AdministrativeSetupConfiguration, requirement: String,
            path: String, bundle: URL, placement: ReleaseDestinationLease, processLease: SetupProcessLease,
            activity: ReleaseActivityBarrier, release: SignedReleaseEvidence, nativeMode: GatewaySettingsNativeSupport.Mode) {
            self.configurationPath = configurationPath; self.configuration = configuration; self.requirement = requirement
            self.path = path; self.bundle = bundle; self.placement = placement; self.processLease = processLease
            self.activity = activity; self.release = release; self.nativeMode = nativeMode
            shutdown = .init(placement: placement, processLease: processLease)
        }
        func validateStartup() throws { _ = try checkedStartup() }
        // Before an owner exists these checks and the first store read have no activity token, as on main.
        // A concurrent release change can refuse startup; the lifecycle then retires for a fresh process.
        private func checkedStartup() throws -> SignedReleaseEvidence {
            try processLease.validate()
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            guard try AdministrativeSetupConfiguration.load(path: configurationPath).canonicalBytes == configuration.canonicalBytes else {
                throw AdministrativeSetupServiceError.changedConfiguration
            }
            _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
            let app = configuration.codePolicy.entries.first { $0.role == .app }!
            let current = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try configuration.validate(release: current)
            try DynamicCodeValidation.validateSelf(requirement: requirement)
            guard try DynamicCodeValidation.selfPath() == path else { throw AdministrativeSetupServiceError.wrongExecutable }
            try placement.validate()
            return current
        }
        func verifyHost(_ inventory: InstallationInventory) throws {
            let inspected = try checkedStartup()
            try verifyInventoryHost(inventory, release: inspected)
        }
        func checkHost() throws -> AdministrativeSetupLifecycle.HostCheck {
            let inspected = try checkedStartup()
            return .init(verifyInventory: { inventory in
                do { try self.verifyInventoryHost(inventory, release: inspected) }
                catch { throw AdministrativeSetupServiceError.wrongRelease }
            })
        }
        private func verifyInventoryHost(_ inventory: InstallationInventory, release: SignedReleaseEvidence) throws {
            guard inventory.bundlePath == bundle.path else { throw AdministrativeSetupServiceError.wrongRelease }
            try configuration.validate(inventory: inventory, release: release)
            let declaration = inventory.services.first { $0.role == .setupController && $0.accountID == nil && $0.label == AdministrativeSetupConfiguration.serviceName }!
            let component = release.manifest.components.first { $0.role == .setupController }!
            let manifest = try InstallationServiceManifest(declaration: declaration, component: component,
                configurationPath: configurationPath, userName: "root", arguments: [component.relativePath, "--configuration", configurationPath],
                machServices: [AdministrativeSetupConfiguration.serviceName], runAtLoad: true, keepAlive: true)
            let plist = bundle.appendingPathComponent("Contents/Library/LaunchDaemons/" + AdministrativeSetupConfiguration.plistName)
            try manifest.validate(ProtectedServiceConfiguration.readPublic(path: plist.path), inventory: inventory, release: release)
        }
        private func makeOwner(checkedHost: AdministrativeSetupLifecycle.HostCheck) throws -> SetupAccountOwner {
            let configuration = self.configuration, release = self.release, activity = self.activity
            let nativeMode = self.nativeMode
            let store = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
            do {
                guard let inventory = try store.loadInventory() else { throw PreparationStoreError.notFound }
                try checkedHost.verifyInventory(inventory); try store.close()
            } catch { try? store.close(); throw error }
            let verifyHost: (InstallationInventory) throws -> Void = { try self.verifyHost($0) }
            return try SetupAccountOwner(openMachine: {
                try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
            }, expectedReleaseDigest: configuration.releaseDigest,
                resume: { try AuthorityAccountInitialization.resume(machine: $0, expected: $1) }, verifyHost: verifyHost,
                accountCodePolicy: configuration.codePolicy, prepareRuntime: { machine, account, expected, accepted, verify in
                    let enabled = try GatewaySettingsNativeSupport.serviceActivityEnabled(reference: expected.reference, mode: nativeMode)
                    return try RuntimePublicationController.prepare(machine: machine, account: account, expected: expected,
                        fileCustodyAccepted: accepted, serviceActivityEnabled: enabled, selectAuditDelivery: { reference in
                            try RuntimeAuditDeliverySupport.selectedVersion(reference: reference, release: release, policy: configuration.codePolicy)
                        }, verifyCurrent: verify)
                }, releaseActivity: activity,
                gatewayJournalOperation: .native(machineDirectory: configuration.machineDirectory, macID: configuration.macID),
                gatewayActivationOperation: nativeMode == .native
                    ? .native(machineDirectory: configuration.machineDirectory, macID: configuration.macID) : nil,
                gatewaySettingsOperation: nativeMode == .native
                    ? .native(machineDirectory: configuration.machineDirectory, macID: configuration.macID) : nil,
                importedGatewayOperation: nativeMode == .native
                    ? .native(machineDirectory: configuration.machineDirectory, macID: configuration.macID) : nil)

        }
        func prepare(checkedHost: AdministrativeSetupLifecycle.HostCheck, signal: @escaping @Sendable () -> Void) async throws -> AdministrativeSetupLifecycle.Runtime {
            try await executor.run { _ in
                let owner: SetupAccountOwner
                if let prepared = self.preparedOwner { owner = prepared }
                else {
                    owner = try self.makeOwner(checkedHost: checkedHost)
                    try self.shutdown.bind(owner)
                    self.preparedOwner = owner
                    try owner.installMaintenanceRecoverySignal(signal)
                }
                return try .native(owner: owner, shutdown: self.shutdown, candidate: self.release)
            }
        }
    }
    private final class Signal: @unchecked Sendable {
        private let lock = NSLock()
        private weak var lifecycle: AdministrativeSetupLifecycle?
        func bind(_ lifecycle: AdministrativeSetupLifecycle) { lock.withLock { self.lifecycle = lifecycle } }
        func notify() {
            if let lifecycle = lock.withLock({ lifecycle }) { Task { await lifecycle.requestDiscovery() } }
        }
    }
    private let lock = NSLock()
    private let host: Host
    private let listener: AdministrativeSetupXPCListener
    private let routing: AdministrativeSetupLifecycle.Routing
    private let signal = Signal()
    private var lifecycle: AdministrativeSetupLifecycle?

    /// The startup hold ends before a pending lifecycle can block an existing exclusive cutover.
    private static func startupSequence<Verified, Value>(_ activity: ReleaseActivityBarrier,
        verify: () throws -> Verified, makePending: (Verified) throws -> Value) throws -> Value {
        let startup = try activity.acquireShared()
        defer { startup.close() }
        let verified = try verify()
        return try makePending(verified)
    }
    /// Runs the same startup ownership sequence with ordinary fixtures. It cannot run Root checks or a native listener.
    static func openOwnedStartup<Verified, Value>(_ activity: ReleaseActivityBarrier,
        verify: () throws -> Verified, makePending: (Verified) throws -> Value) throws -> Value {
        try RuntimeMaintenanceOwnedControl.require()
        return try startupSequence(activity, verify: verify, makePending: makePending)
    }
    public static func open(configurationPath: String) throws -> AdministrativeSetupService {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard configurationPath == AdministrativeSetupConfiguration.startupPath else { throw AdministrativeSetupServiceError.invalidConfiguration }
        let configuration = try AdministrativeSetupConfiguration.load(path: configurationPath)
        let app = configuration.codePolicy.entries.first { $0.role == .app }!
        let component = configuration.codePolicy.entries.first { $0.role == .setupController }!
        let requirement = try XPCPeerPolicy(teamID: component.teamID, componentIdentifier: component.identifier,
            approvedCodeDirectoryHashes: [component.codeDirectoryHash], expectedUserID: 0).requirement
            + " and info[\"RemozioSecurityGeneration\"] = \"\(component.installedGeneration)\""
        try DynamicCodeValidation.validateSelf(requirement: requirement)
        let path = try DynamicCodeValidation.selfPath(), suffix = "/" + AdministrativeSetupConfiguration.executablePath
        guard path.hasSuffix(suffix) else { throw AdministrativeSetupServiceError.wrongExecutable }
        let bundle = URL(fileURLWithPath: String(path.dropLast(suffix.count)))
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        var processLease: SetupProcessLease?
        do {
            let activity = try ReleaseActivityBarrier.open(machineDirectory: configuration.machineDirectory)
            return try startupSequence(activity, verify: {
                _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
                let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
                try configuration.validate(release: release)
                // Select once from the fixed verified release, before the listener can start. Failure exits through startup code78.
                let nativeMode = try GatewaySettingsNativeSupport.mode(release: release, policy: configuration.codePolicy)
                let instance = try SetupProcessLease.acquire(); processLease = instance
                let host = Host(configurationPath: configurationPath, configuration: configuration, requirement: requirement,
                    path: path, bundle: bundle, placement: placement, processLease: instance, activity: activity, release: release, nativeMode: nativeMode)
                try host.validateStartup()
                return host
            }, makePending: { host in
                let routing = AdministrativeSetupLifecycle.Routing(validateStartup: { try host.shutdown.validateRecoveryCustody() })
                let listener = try AdministrativeSetupXPCListener(serviceName: AdministrativeSetupConfiguration.serviceName,
                    teamID: app.teamID, appIdentifier: app.identifier, appHashes: [app.codeDirectoryHash], routing: routing,
                    validateStartup: { try host.validateStartup() }, maximumConnections: configuration.maximumConnections,
                    handshakeTimeoutMilliseconds: configuration.handshakeTimeoutMilliseconds)
                return AdministrativeSetupService(host: host, listener: listener, routing: routing)
            })
        } catch { placement.close(); processLease?.close(); throw error }
    }
    private init(host: Host, listener: AdministrativeSetupXPCListener, routing: AdministrativeSetupLifecycle.Routing) {
        self.host = host; self.listener = listener; self.routing = routing
    }
    public func start(terminate: @escaping @Sendable (Int32) -> Void = { exit($0) }) throws {
        try lock.withLock {
            guard lifecycle == nil else { throw AdministrativeSetupError.unavailable }
            let host = self.host, listener = self.listener, signal = self.signal
            let lifecycle = try AdministrativeSetupLifecycle.native(routing: routing,
                validateStartup: { try host.shutdown.validateRecoveryCustody() },
                validateHost: { try await host.executor.run { _ in try host.checkHost() } },
                prepare: { try await host.prepare(checkedHost: $0, signal: { signal.notify() }) },
                closeWithoutRuntime: { try await host.shutdown.close() },
                stopListener: { listener.close() }, terminate: terminate)
            self.lifecycle = lifecycle; signal.bind(lifecycle)
            try listener.start()
            Task { await lifecycle.start() }
        }
    }
    public func requestRetirement() {
        if let lifecycle = lock.withLock({ lifecycle }) { Task { await lifecycle.requestRetirement() } }
    }
    public func waitUntilStopped() async {
        if let lifecycle = lock.withLock({ lifecycle }) { await lifecycle.waitUntilStopped() }
    }
    public func close() async throws {
        if let lifecycle = lock.withLock({ lifecycle }) { await lifecycle.close() }
        else { listener.close(); try await host.shutdown.close() }
    }
    deinit {
        if let lifecycle { Task { await lifecycle.requestRetirement() } }
        else {
            listener.close()
            let shutdown = host.shutdown
            Task { try? await shutdown.close() }
        }
    }
}
