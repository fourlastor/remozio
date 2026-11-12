import Foundation

/// Declares isolated promotion data. It creates no table, admits no schema, and grants no writer authority.
enum MachineUpdateRetainedSetupPromotionStorage {
    static let schemaVersion: Int64 = 27
    static let tableName = "retained_setup_promotion_intents_v1"
    static let createSQL = "CREATE TABLE retained_setup_promotion_intents_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),id BLOB NOT NULL CHECK(length(id)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 3149824)) STRICT"

    static var readerRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [27]),
                 RetainedReleaseFormat(role: role, name: MachineUpdateRetainedSetupPromotionIntentRecord.formatName,
                    readVersions: [MachineUpdateRetainedSetupPromotionIntentRecord.currentFormatVersion])]
        }
    } }
    static func requireReaderFormats(_ candidate: SignedReleaseEvidence) throws {
        try MachineUpdateRetainedSetupCompletionStorage.requireReaderFormats(candidate)
        for requirement in try readerRequirements {
            guard let component = candidate.manifest.components.first(where: { $0.role == requirement.role }),
                  let format = component.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: format.readers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    /// Checks prospective producer declarations only. It grants no writer or migration authority.
    static func requireProposalFormats(_ candidate: SignedReleaseEvidence) throws {
        try requireReaderFormats(candidate)
        try RuntimeRetainedSetupCompletionBinding.requireCompletedHostFormats(candidate)
        for role in [AuthorityCodeRole.authority, .setupController] {
            guard let component = candidate.manifest.components.first(where: { $0.role == role }),
                  let installation = component.formats.first(where: { $0.name == "authority.installation-preparation" }),
                  Set([UInt64(24), 25, 26, 27]).isSubset(of: installation.readers),
                  Set([UInt64(25), 26, 27]).isSubset(of: installation.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
            for (name, version) in [
                (MachineUpdateRetainedSetupPolicyIntentRecord.formatName, MachineUpdateRetainedSetupPolicyIntentRecord.currentFormatVersion),
                (MachineUpdateRetainedSetupCompletionIntentRecord.formatName, MachineUpdateRetainedSetupCompletionIntentRecord.currentFormatVersion),
                (MachineUpdateRetainedSetupPromotionIntentRecord.formatName, MachineUpdateRetainedSetupPromotionIntentRecord.currentFormatVersion)
            ] {
                let needsWriter = name != MachineUpdateRetainedSetupPromotionIntentRecord.formatName || role == .setupController
                guard let format = component.formats.first(where: { $0.name == name }), format.readers.contains(version),
                      !needsWriter || format.writers.contains(version) else { throw PreparationStoreError.incompatibleStore }
            }
        }
    }
    enum WriteOperation { case retainPrepared, changePhase }

    /// Checks the full producer contract before the future writer starts a transaction.
    static func requireWriteFormats(_ candidate: SignedReleaseEvidence, sourceSchema: Int64,
        operation: WriteOperation) throws {
        try requireProposalFormats(candidate)
        switch (sourceSchema, operation) {
        case (26, .retainPrepared): try requireMigrationFormats(candidate)
        case (27, _), (28, _): break
        default: throw PreparationStoreError.invalidTransition
        }
    }

    /// Checks declarations only. This check does not perform or authorize a migration.
    static func requireMigrationFormats(_ candidate: SignedReleaseEvidence) throws {
        try requireProposalFormats(candidate)
        for role in [AuthorityCodeRole.authority, .setupController] {
            guard candidate.manifest.components.first(where: { $0.role == role })?
                .formats.first(where: { $0.name == "authority.installation-preparation" })?.migrations[26] == 27 else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
}
