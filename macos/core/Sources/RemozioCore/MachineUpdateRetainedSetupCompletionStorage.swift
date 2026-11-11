import Foundation

/// Declares the retained completion table and its reader requirements.
enum MachineUpdateRetainedSetupCompletionStorage {
    static let schemaVersion: Int64 = 26
    static let tableName = "retained_setup_completion_intents_v1"
    static let createSQL = "CREATE TABLE retained_setup_completion_intents_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),id BLOB NOT NULL CHECK(length(id)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 262144)) STRICT"

    static var readerRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [26]),
                 RetainedReleaseFormat(role: role, name: MachineUpdateRetainedSetupCompletionIntentRecord.formatName,
                    readVersions: [MachineUpdateRetainedSetupCompletionIntentRecord.currentFormatVersion])]
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
