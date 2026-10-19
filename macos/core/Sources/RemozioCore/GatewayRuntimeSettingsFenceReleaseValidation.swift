import Foundation

/// Require signed readers before publishing a record that can pause every optional consumer.
enum GatewayRuntimeSettingsFenceReleaseValidation {
    static let formatName = "runtime.gateway-settings-fence"
    static let version: UInt64 = 1
    static func validate(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        let roles: [AuthorityCodeRole] = [.authority, .transport, .notificationGateway, .setupController]
        let entries = roles.compactMap { role in policy.entries.first { $0.role == role && $0.active } }
        guard entries.count == roles.count, Set(entries.map(\.teamID)).count == 1 else { throw GatewayPreparationError.changedScope }
        for entry in entries {
            guard let component = release.manifest.components.first(where: { $0.role == entry.role }),
                  component.identifier == entry.identifier, component.teamID == entry.teamID,
                  component.generation == entry.installedGeneration, component.codeDirectoryHash == entry.codeDirectoryHash,
                  release.codeDirectoryHashes[entry.role] == entry.codeDirectoryHash,
                  let format = component.formats.first(where: { $0.name == formatName }), format.readers.contains(version),
                  entry.role != .setupController || format.writers.contains(version) else { throw GatewayPreparationError.changedScope }
        }
    }
}
