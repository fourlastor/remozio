import Foundation

/// Declares the retained policy table and its reader requirements.
enum MachineUpdateRetainedSetupPolicyStorage {
    static let schemaVersion: Int64 = 25
    static let tableName = "retained_setup_policy_intents_v1"
    static let createSQL = "CREATE TABLE retained_setup_policy_intents_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),id BLOB NOT NULL CHECK(length(id)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 131072)) STRICT"

    static let stableSchemaVersions = Set(24...MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion)
    static let policySchemaVersions: Set<Int64> = [25, 26, 27, 28]
    /// Requirements for a future policy writer. These values do not declare a reachable manifest producer.
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation",
                    readVersions: [24, 25], writeVersions: [25]),
                 RetainedReleaseFormat(role: role, name: MachineUpdateRetainedSetupPolicyIntentRecord.formatName,
                    readVersions: [MachineUpdateRetainedSetupPolicyIntentRecord.currentFormatVersion],
                    writeVersions: [MachineUpdateRetainedSetupPolicyIntentRecord.currentFormatVersion])]
        }
    } }
    static func requireFormats(_ candidate: SignedReleaseEvidence) throws {
        for requirement in try requirements {
            guard let format = candidate.manifest.components.first(where: { $0.role == requirement.role })?
                .formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: format.readers), requirement.writeVersions.isSubset(of: format.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    static func requireMigrationFormats(_ candidate: SignedReleaseEvidence) throws {
        try requireFormats(candidate)
        for role in [AuthorityCodeRole.authority, .setupController] {
            guard candidate.manifest.components.first(where: { $0.role == role })?
                .formats.first(where: { $0.name == "authority.installation-preparation" })?.migrations[24] == 25 else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    /// Rejects unsupported store contracts before a future writer enters its first transaction.
    static func requireSchema(_ version: Int64, candidate: SignedReleaseEvidence) throws {
        guard stableSchemaVersions.contains(version) else { throw PreparationStoreError.incompatibleStore }
        try MachineUpdateStableReleaseRecord.requireFormats(candidate); try requireFormats(candidate)
        if version == 24 { try requireMigrationFormats(candidate) }
        if version >= MachineUpdateRetainedSetupCompletionStorage.schemaVersion {
            try MachineUpdateRetainedSetupCompletionStorage.requireReaderFormats(candidate)
        }
        if version >= MachineUpdateRetainedSetupPromotionStorage.schemaVersion {
            try MachineUpdateRetainedSetupPromotionStorage.requireReaderFormats(candidate)
        }
        if version >= MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion {
            try MachineUpdateRetainedSetupPromotionReadyStorage.requireReaderFormats(candidate)
        }
    }

    static var readerRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [25]),
                 RetainedReleaseFormat(role: role, name: MachineUpdateRetainedSetupPolicyIntentRecord.formatName,
                    readVersions: [MachineUpdateRetainedSetupPolicyIntentRecord.currentFormatVersion])]
        }
    } }

    static func requireReaderFormats(_ candidate: SignedReleaseEvidence) throws {
        for requirement in try readerRequirements {
            guard let component = candidate.manifest.components.first(where: { $0.role == requirement.role }),
                  let format = component.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: format.readers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
}
