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
}
