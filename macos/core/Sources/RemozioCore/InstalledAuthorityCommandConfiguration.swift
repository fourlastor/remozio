import Darwin
import Foundation
import RemozioProtocol

public enum InstalledAuthorityCommandError: Error, Equatable {
    case invalidConfiguration, wrongInstallation, wrongRelease, changedConfiguration, wrongExecutable, unavailable
}

public enum InstalledCommandJobPlacement: UInt64, Sendable { case bundled = 1, systemAccount = 2 }

/// Root-private host inputs. Parsing does not establish installation or execution authority.
public struct InstalledAuthorityCommandConfiguration: Sendable, CustomStringConvertible {
    public static let supportedVersions: Set<UInt64> = [1, 2, 3]
    public static let executablePath = "Contents/Library/LaunchServices/RemozioAuthority"
    public let formatVersion: UInt64
    public let gatewaySettingsControlEnabled: Bool
    public let jobPlacement: InstalledCommandJobPlacement
    public let machineDirectory: String
    public let installationID: Data
    public let releaseDigest: Data
    public let codePolicy: AuthorityCodePolicy
    public let command: AuthorityCommandStartupConfiguration
    public let label: String
    public let plistName: String
    public let canonicalBytes: Data
    public var description: String { "InstalledAuthorityCommandConfiguration(redacted)" }

    public init(machineDirectory: String, installationID: Data, releaseDigest: Data, codePolicy: AuthorityCodePolicy,
                command: AuthorityCommandStartupConfiguration, label: String, plistName: String,
                jobPlacement: InstalledCommandJobPlacement = .bundled, gatewaySettingsControlEnabled: Bool = false) throws {
        let parts = machineDirectory.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard machineDirectory.hasPrefix("/"), machineDirectory.utf8.count < Int(PATH_MAX), !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              installationID.count == 16, releaseDigest.count == 32, command.execution != nil,
              command.presence.wake.request.service.continuityDirectory != nil,
              GatewayWakeEndpointConfiguration.validServiceName(label),
              GatewayWakeEndpointConfiguration.validServiceName(plistName), plistName.hasSuffix(".plist") else {
            throw InstalledAuthorityCommandError.invalidConfiguration
        }
        guard !gatewaySettingsControlEnabled || jobPlacement == .systemAccount else {
            throw InstalledAuthorityCommandError.invalidConfiguration
        }
        let requiredRoles: [AuthorityCodeRole] = [.app, .authority, .commandFrontend, .commandMonitor, .commandChild, .transport, .notificationGateway]
            + (gatewaySettingsControlEnabled ? [.setupController] : [])
        for role in requiredRoles {
            guard codePolicy.entries.contains(where: { $0.role == role && $0.active }) else {
                throw InstalledAuthorityCommandError.invalidConfiguration
            }
        }
        func requirePolicy(_ actual: XPCPeerPolicy, role: AuthorityCodeRole) throws {
            let entry = codePolicy.entries.first(where: { $0.role == role })!
            let expected = try XPCPeerPolicy(teamID: entry.teamID, componentIdentifier: entry.identifier,
                approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: actual.expectedUserID)
            guard actual.requirement == expected.requirement else { throw InstalledAuthorityCommandError.invalidConfiguration }
        }
        try requirePolicy(command.presence.endpoint.appPolicy, role: .app)
        try requirePolicy(command.presence.wake.request.service.transportPolicy, role: .transport)
        try requirePolicy(command.presence.wake.gatewayPolicy, role: .notificationGateway)
        if jobPlacement == .systemAccount {
            let paths = try RuntimePreparationPaths(accountID: command.accountID)
            guard machineDirectory == MachineBootstrap.machineDirectory,
                  label == paths.namespace + ".authority", plistName == label + ".plist",
                  command.serviceName == paths.commandService,
                  command.presence.endpoint.serviceName == paths.presenceService,
                  command.presence.wake.request.service.serviceName == paths.authorityService,
                  command.policyPath == paths.policy,
                  command.presence.wake.request.keyRecordPath == paths.authorityDirectory + "/Key/" + AuthorityKeyProvisioning.recordFileName else {
                throw InstalledAuthorityCommandError.invalidConfiguration
            }
        }
        formatVersion = gatewaySettingsControlEnabled ? 3 : jobPlacement.rawValue
        self.gatewaySettingsControlEnabled = gatewaySettingsControlEnabled
        self.jobPlacement = jobPlacement
        self.machineDirectory = machineDirectory; self.installationID = installationID; self.releaseDigest = releaseDigest
        self.codePolicy = codePolicy; self.command = command; self.label = label; self.plistName = plistName
        var fields: [UInt64: CBORValue] = [0: .unsigned(formatVersion), 1: .text(machineDirectory),
            2: .bytes(installationID), 3: .bytes(releaseDigest), 4: .bytes(try codePolicy.bytes),
            5: .bytes(command.canonicalBytes), 6: .text(label), 7: .text(plistName)]
        if jobPlacement == .systemAccount { fields[8] = .text("protected-system-account-v1") }
        if gatewaySettingsControlEnabled {
            fields[9] = .text(try RuntimePreparationPaths(accountID: command.accountID).gatewaySettingsControlService)
        }
        canonicalBytes = try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    }
    public static func load(path: String) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try decode(ProtectedServiceConfiguration.read(path: path))
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), case .unsigned(let version) = f[0], supportedVersions.contains(version),
              let placement = InstalledCommandJobPlacement(rawValue: version == 3 ? 2 : version),
              Set(f.keys) == (version == 3 ? Set(UInt64(0)...9) : placement == .bundled ? Set(UInt64(0)...7) : Set(UInt64(0)...8)),
              placement == .bundled || f[8] == .text("protected-system-account-v1"), case .text(let directory) = f[1], case .bytes(let installation) = f[2],
              case .bytes(let digest) = f[3], case .bytes(let policy) = f[4], case .bytes(let command) = f[5],
              case .text(let label) = f[6], case .text(let plist) = f[7] else { throw InstalledAuthorityCommandError.invalidConfiguration }
        let value = try Self(machineDirectory: directory, installationID: installation, releaseDigest: digest,
            codePolicy: .decode(policy), command: .decode(command), label: label, plistName: plist, jobPlacement: placement,
            gatewaySettingsControlEnabled: version == 3)
        guard value.canonicalBytes == bytes else { throw InstalledAuthorityCommandError.invalidConfiguration }; return value
    }
    /// Select the optional service only after both retained signed components declare its codecs.
    /// Protected registration and runtime identity checks remain separate prerequisites.
    func enablingGatewaySettingsControl(release: SignedReleaseEvidence) throws -> Self {
        guard jobPlacement == .systemAccount, try InstallationInventory.digest(release) == releaseDigest else {
            throw InstalledAuthorityCommandError.wrongRelease
        }
        try validateGatewaySettingsRelease(release)
        return try .init(machineDirectory: machineDirectory, installationID: installationID, releaseDigest: releaseDigest,
            codePolicy: codePolicy, command: command, label: label, plistName: plistName,
            jobPlacement: jobPlacement, gatewaySettingsControlEnabled: true)
    }
    private func validateGatewaySettingsRelease(_ release: SignedReleaseEvidence) throws {
        guard let authority = codePolicy.entries.first(where: { $0.role == .authority && $0.active }),
              let setup = codePolicy.entries.first(where: { $0.role == .setupController && $0.active }) else {
            throw InstalledAuthorityCommandError.wrongRelease
        }
        try GatewaySettingsControlReleaseValidation.validate(release, authority: authority, setup: setup)
        for role: AuthorityCodeRole in [.authority, .setupController] {
            guard let format = release.manifest.components.first(where: { $0.role == role })?.formats.first(where: {
                $0.name == "authority.command-host-config"
            }), format.readers.contains(3), format.writers.contains(3) else {
                throw InstalledAuthorityCommandError.wrongRelease
            }
        }
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 131072, maxDepth: 2, maxItems: 32) } }

    func validate(inventory: InstallationInventory, release: SignedReleaseEvidence, bundlePath: String) throws -> InstallationService {
        guard inventory.macID == command.macID, inventory.installationID == installationID,
              inventory.releaseDigest == releaseDigest, inventory.bundlePath == bundlePath,
              inventory.accounts.contains(where: { $0.accountID == command.accountID && $0.ownerUID == command.callerUID }),
              let declaration = inventory.services.first(where: { $0.role == .authority && $0.kind == .daemon &&
                $0.domainUID == nil && $0.executionUID == 0 && $0.accountID == command.accountID &&
                $0.label == label && $0.plistName == plistName }) else { throw InstalledAuthorityCommandError.wrongInstallation }
        if jobPlacement == .systemAccount {
            let paths = try RuntimePreparationPaths(accountID: command.accountID)
            guard inventory.services.contains(where: {
                $0.role == .transport && $0.kind == .daemon && $0.domainUID == nil && $0.accountID == command.accountID &&
                $0.executionUID == command.presence.wake.request.service.transportPolicy.expectedUserID &&
                $0.label == paths.namespace + ".transport" && $0.plistName == paths.namespace + ".transport.plist"
            }) else { throw InstalledAuthorityCommandError.wrongInstallation }
        }
        try inventory.compareRelease(release)
        try validateRelease(release, bundlePath: bundlePath)
        return declaration
    }
    func validateRelease(_ release: SignedReleaseEvidence, bundlePath: String) throws {
        guard try InstallationInventory.digest(release) == releaseDigest else { throw InstalledAuthorityCommandError.wrongRelease }
        try ReleaseGenerationPreflight.validate(release, against: codePolicy)
        if gatewaySettingsControlEnabled { try validateGatewaySettingsRelease(release) }
        for entry in codePolicy.entries where entry.active {
            guard let component = release.manifest.components.first(where: { $0.role == entry.role }),
                  component.generation == entry.installedGeneration, release.codeDirectoryHashes[entry.role] == entry.codeDirectoryHash else {
                throw InstalledAuthorityCommandError.wrongRelease
            }
        }
        guard release.manifest.components.first(where: { $0.role == .authority })?.relativePath == Self.executablePath,
              let execution = command.execution,
              let monitor = release.manifest.components.first(where: { $0.role == .commandMonitor }),
              let child = release.manifest.components.first(where: { $0.role == .commandChild }),
              execution.monitorPath == bundlePath + "/" + monitor.relativePath,
              execution.childPath == bundlePath + "/" + child.relativePath else { throw InstalledAuthorityCommandError.wrongRelease }
    }

}
