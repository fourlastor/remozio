import Foundation

/// Retains exact job operands. This value grants no file writer, registration removal, or process exit evidence.
struct MachineUpdateAuthorityReadinessJobTransition {
    let startup: InstalledAccountJobManifest
    let completion: InstalledAccountJobManifest
    init(startup: InstalledAuthorityCommandConfiguration, completion: InstalledAuthorityCommandConfiguration,
        bundlePath: String) throws {
        guard startup.jobPlacement == .systemAccount, completion.jobPlacement == .systemAccount,
              startup.gatewaySettingsControlEnabled, completion.gatewaySettingsControlEnabled,
              !startup.installedReadinessEnabled, completion.installedReadinessEnabled,
              startup.releaseDigest == completion.releaseDigest,
              startup.command.macID == completion.command.macID,
              startup.command.accountID == completion.command.accountID,
              startup.installationID == completion.installationID,
              startup.label == completion.label, startup.plistName == completion.plistName else {
            throw InstalledAuthorityCommandError.changedConfiguration
        }
        func job(_ host: InstalledAuthorityCommandConfiguration) throws -> InstalledAccountJobManifest {
            try .init(accountID: host.command.accountID, role: .authority, executionUID: 0, userName: "root",
                bundlePath: bundlePath, gatewaySettingsControlEnabled: true,
                installedReadinessEnabled: host.installedReadinessEnabled)
        }
        let before = try job(startup), after = try job(completion)
        guard before.declaration == after.declaration, before.path == after.path,
              before.arguments == after.arguments, before.configurationPath == after.configurationPath,
              before.executablePath == after.executablePath,
              after.machServices == before.machServices.union([
                try MachineUpdateAuthorityReadinessDeclaration.serviceName(accountID: completion.command.accountID)]) else {
            throw InstalledAuthorityCommandError.changedConfiguration
        }
        self.startup = before; self.completion = after
    }
    static var formatRequirements: [RetainedReleaseFormat] { get throws {
        var formats = try [RetainedReleaseFormat(role: .authority,
            name: MachineUpdateAuthorityReadinessDeclaration.formatName,
            readVersions: [MachineUpdateAuthorityReadinessDeclaration.version],
            writeVersions: [MachineUpdateAuthorityReadinessDeclaration.version])]
        for role in [AuthorityCodeRole.authority, .setupController] {
            formats.append(try .init(role: role, name: "authority.command-host-config",
                readVersions: [4], writeVersions: [4]))
            formats.append(try .init(role: role, name: MachineUpdateCompletionPublicationRecord.formatName,
                readVersions: MachineUpdateCompletionPublicationRecord.formatVersions,
                writeVersions: MachineUpdateCompletionPublicationRecord.formatVersions))
        }
        return formats
    } }
    static func requireRelease(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        try MachineUpdateAuthorityReadinessDeclaration.validate(release, policy: policy)
        guard release.manifest.components.first(where: { $0.role == .authority })?.relativePath
            == InstalledAuthorityCommandConfiguration.executablePath else {
            throw InstalledAuthorityCommandError.wrongRelease
        }
        let versions = MachineUpdateCompletionPublicationRecord.formatVersions
        for role: AuthorityCodeRole in [.authority, .setupController] {
            guard let format = release.manifest.components.first(where: { $0.role == role })?.formats.first(where: {
                $0.name == MachineUpdateCompletionPublicationRecord.formatName
            }), format.readers.isSuperset(of: versions), format.writers.isSuperset(of: versions) else {
                throw InstalledAuthorityCommandError.wrongRelease
            }
        }
    }
}
