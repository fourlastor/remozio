import Foundation

/// Future archive declarations required by a live preflight. They grant no archive or startup authority.
enum MachineUpdatePreflightCompatibility {
    static let configurationFormatName = "authority.machine-update-configuration-epoch"
    static let installedFormatName = "authority.installed-release-state"
    static let retainedSetupFormatName = "runtime.retained-setup-release"
    static var configurationProvenanceRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map {
            try .init(role: $0, name: configurationFormatName, readVersions: [1, 2, 3, 4], writeVersions: [3, 4])
        }
    } }
    static var installedProvenanceRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map {
            try .init(role: $0, name: installedFormatName, readVersions: [1, 2], writeVersions: [2])
        }
    } }
    static var retainedSetupRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: retainedSetupFormatName, readVersions: [1], writeVersions: role == .setupController ? [1] : []),
                 RetainedReleaseFormat(role: role, name: GatewaySettingsConsumerHostConfiguration.formatName,
                    readVersions: [3], writeVersions: role == .setupController ? [3] : [])]
        }
    } }
    static var retainedSetupActivationRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map { role in
            try .init(role: role, name: RuntimeActivationPlan.formatName, readVersions: [6], writeVersions: role == .setupController ? [6] : [])
        }
    } }
    static func requireProvenanceFormats(_ candidate: SignedReleaseEvidence) throws {
        try MachineUpdateProvisioningHistory.requireFormats(candidate)
        try require(configurationProvenanceRequirements + installedProvenanceRequirements, candidate)
    }
    static func requireRetainedSetupFormats(_ candidate: SignedReleaseEvidence) throws {
        try require(retainedSetupRequirements + retainedSetupActivationRequirements, candidate)
    }
    private static func require(_ requirements: [RetainedReleaseFormat], _ candidate: SignedReleaseEvidence) throws {
        for requirement in requirements {
            guard let declared = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: declared.readers), requirement.writeVersions.isSubset(of: declared.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
}
