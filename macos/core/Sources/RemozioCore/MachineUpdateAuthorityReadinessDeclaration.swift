import Foundation
import RemozioProtocol

/// Signed declaration gates only. This value creates no service, connection, or native authority.
enum MachineUpdateAuthorityReadinessDeclaration {
    static let formatName = "authority.installed-readiness"
    static let version: UInt64 = 1
    static func serviceName(accountID: Data) throws -> String {
        let name = try RuntimePreparationPaths(accountID: accountID).authorityService + ".readiness"
        guard GatewayWakeEndpointConfiguration.validServiceName(name) else { throw InstalledAuthorityCommandError.invalidConfiguration }
        return name
    }
    static func validate(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        guard let authority = policy.entries.first(where: { $0.role == .authority && $0.active }),
              let component = release.manifest.components.first(where: { $0.role == .authority }),
              component.identifier == authority.identifier, component.teamID == authority.teamID,
              component.generation == authority.installedGeneration,
              component.codeDirectoryHash == authority.codeDirectoryHash,
              release.codeDirectoryHashes[.authority] == authority.codeDirectoryHash,
              let format = component.formats.first(where: { $0.name == formatName }),
              format.readers.contains(version), format.writers.contains(version) else {
            throw InstalledAuthorityCommandError.wrongRelease
        }
        for role in [AuthorityCodeRole.authority,.setupController] {
            guard let code = policy.entries.first(where: { $0.role == role && $0.active }),
                  let participant = release.manifest.components.first(where: { $0.role == role }),
                  participant.identifier == code.identifier, participant.teamID == code.teamID,
                  participant.generation == code.installedGeneration, participant.codeDirectoryHash == code.codeDirectoryHash,
                  release.codeDirectoryHashes[role] == code.codeDirectoryHash,
                  let host = participant.formats.first(where: { $0.name == "authority.command-host-config" }),
                  host.readers.contains(4), host.writers.contains(4) else {
                throw InstalledAuthorityCommandError.wrongRelease
            }
        }
    }
}
