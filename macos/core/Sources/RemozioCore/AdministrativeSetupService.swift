import Darwin
import Foundation
import RemozioProtocol

public enum AdministrativeSetupServiceError: Error, Equatable { case invalidConfiguration, changedConfiguration, wrongRelease, wrongExecutable }

/// Retained Root-private startup inputs. Provisioning must establish current code floors and registration independently.
public struct AdministrativeSetupConfiguration: Sendable, CustomStringConvertible {
    public static let serviceName = "dev.remozio.setup"
    public static let plistName = "dev.remozio.setup.plist"
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

/// Owns the protected release lease, machine store and local listener. It creates no service registration or network socket.
public final class AdministrativeSetupService {
    private let owner: SetupAccountOwner
    private let listener: AdministrativeSetupXPCListener
    private let shutdown: AdministrativeSetupShutdown
    private var closed = false

    public static func open(configurationPath: String) throws -> AdministrativeSetupService {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard configurationPath == AdministrativeSetupConfiguration.startupPath else { throw AdministrativeSetupServiceError.invalidConfiguration }
        let configuration = try AdministrativeSetupConfiguration.load(path: configurationPath)
        let app = configuration.codePolicy.entries.first(where: { $0.role == .app })!
        let host = configuration.codePolicy.entries.first(where: { $0.role == .setupController })!
        let requirement = try XPCPeerPolicy(teamID: host.teamID, componentIdentifier: host.identifier,
            approvedCodeDirectoryHashes: [host.codeDirectoryHash], expectedUserID: 0).requirement
            + " and info[\"RemozioSecurityGeneration\"] = \"\(host.installedGeneration)\""
        try DynamicCodeValidation.validateSelf(requirement: requirement)
        let path = try DynamicCodeValidation.selfPath(), suffix = "/" + AdministrativeSetupConfiguration.executablePath
        guard path.hasSuffix(suffix) else { throw AdministrativeSetupServiceError.wrongExecutable }
        let bundle = URL(fileURLWithPath: String(path.dropLast(suffix.count)))
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        var machine: PreparationIntentStore?
        var owner: SetupAccountOwner?
        do {
            let activity = try ReleaseActivityBarrier.open(machineDirectory: configuration.machineDirectory)
            let startup = try activity.acquireShared()
            defer { startup.close() }
            _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
            let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try configuration.validate(release: release)
            let nativeMode = try GatewaySettingsNativeSupport.mode(release: release, policy: configuration.codePolicy)
            let store = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
            machine = store
            guard let inventory = try store.loadInventory(), inventory.bundlePath == bundle.path else {
                throw AdministrativeSetupServiceError.wrongRelease
            }
            func verifyHost(_ inventory: InstallationInventory) throws {
                guard inventory.bundlePath == bundle.path else { throw AdministrativeSetupServiceError.wrongRelease }
                guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
                guard try AdministrativeSetupConfiguration.load(path: configurationPath).canonicalBytes == configuration.canonicalBytes else {
                    throw AdministrativeSetupServiceError.changedConfiguration
                }
                _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
                let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
                try configuration.validate(inventory: inventory, release: release)
                try DynamicCodeValidation.validateSelf(requirement: requirement)
                guard try DynamicCodeValidation.selfPath() == path else { throw AdministrativeSetupServiceError.wrongExecutable }
                let declaration = inventory.services.first(where: { $0.role == .setupController && $0.accountID == nil && $0.label == AdministrativeSetupConfiguration.serviceName })!
                let component = release.manifest.components.first(where: { $0.role == .setupController })!
                let manifest = try InstallationServiceManifest(declaration: declaration, component: component,
                    configurationPath: configurationPath, userName: "root", arguments: [component.relativePath, "--configuration", configurationPath],
                    machServices: [AdministrativeSetupConfiguration.serviceName], runAtLoad: true, keepAlive: true)
                let plist = bundle.appendingPathComponent("Contents/Library/LaunchDaemons/" + AdministrativeSetupConfiguration.plistName)
                try manifest.validate(ProtectedServiceConfiguration.readPublic(path: plist.path), inventory: inventory, release: release)
                try placement.validate()
            }
            try verifyHost(inventory)
            try store.close(); machine = nil
            let next = try SetupAccountOwner(openMachine: {
                try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
            }, expectedReleaseDigest: configuration.releaseDigest,
                resume: { try AuthorityAccountInitialization.resume(machine: $0, expected: $1) }, verifyHost: verifyHost,
                accountCodePolicy: configuration.codePolicy, prepareRuntime: { machine, account, expected, accepted, verify in
                    let enabled = try GatewaySettingsNativeSupport.serviceActivityEnabled(reference: expected.reference, mode: nativeMode)
                    return try RuntimePublicationController.prepare(machine: machine, account: account, expected: expected,
                        fileCustodyAccepted: accepted, serviceActivityEnabled: enabled, verifyCurrent: verify)
                }, releaseActivity: activity,
                gatewayJournalOperation: .native(machineDirectory: configuration.machineDirectory, macID: configuration.macID),
                gatewayActivationOperation: nativeMode == .native
                    ? .native(machineDirectory: configuration.machineDirectory, macID: configuration.macID) : nil)
            owner = next
            let listener = try AdministrativeSetupXPCListener(serviceName: AdministrativeSetupConfiguration.serviceName,
                teamID: app.teamID, appIdentifier: app.identifier, appHashes: [app.codeDirectoryHash], owner: next,
                maximumConnections: configuration.maximumConnections, handshakeTimeoutMilliseconds: configuration.handshakeTimeoutMilliseconds)
            return .init(owner: next, listener: listener, placement: placement)
        } catch { try? owner?.close(); if owner == nil { try? machine?.close() }; placement.close(); throw error }
    }

    private init(owner: SetupAccountOwner, listener: AdministrativeSetupXPCListener, placement: ReleaseDestinationLease) {
        self.owner = owner; self.listener = listener; shutdown = .init(owner: owner, placement: placement)
    }
    public func start() throws { guard !closed else { throw AdministrativeSetupError.unavailable }; try listener.start() }
    public func close() async throws {
        guard !closed else { return }
        listener.close(); try await shutdown.close(); closed = true
    }
    deinit {
        listener.close()
        let pending = shutdown
        Task { try? await pending.close() }
    }
}
