import Foundation

/// Declares historical readiness storage. It creates no table and admits no schema or writer.
enum MachineUpdateRetainedSetupPromotionReadyStorage {
    static let schemaVersion: Int64 = 28
    static let tableName = "retained_setup_promotion_ready_v1"
    static let createSQL = "CREATE TABLE retained_setup_promotion_ready_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),id BLOB NOT NULL CHECK(length(id)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 71680)) STRICT"
    static var readerRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [28]),
                 RetainedReleaseFormat(role: role, name: MachineUpdateRetainedSetupPromotionReadyRecord.formatName, readVersions: [1])]
        }
    } }
    static func requireReaderFormats(_ candidate: SignedReleaseEvidence) throws {
        try MachineUpdateRetainedSetupPromotionStorage.requireReaderFormats(candidate)
        for requirement in try readerRequirements {
            guard let declared = candidate.manifest.components.first(where: { $0.role == requirement.role })?
                .formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: declared.readers) else { throw PreparationStoreError.incompatibleStore }
        }
    }
}
