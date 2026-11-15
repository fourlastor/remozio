import Foundation

/// Declares protected window storage. It creates no table, admits no schema and grants no writer authority.
enum RuntimeMaintenanceWindowStorage {
    static let schemaVersion: Int64 = 29
    static let tableName = "runtime_maintenance_windows_v1"
    static let createSQL = "CREATE TABLE runtime_maintenance_windows_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),attempt BLOB NOT NULL UNIQUE CHECK(length(attempt)=16),revision BLOB NOT NULL UNIQUE CHECK(length(revision)=16),phase INTEGER NOT NULL CHECK(phase BETWEEN 1 AND 10),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 4096)) STRICT"
    static var readerRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [UInt64(schemaVersion)]),
                 RetainedReleaseFormat(role: role, name: RuntimeMaintenanceWindowRecord.formatName, readVersions: [1])]
        }
    } }
    static func requireReaderFormats(_ candidate: SignedReleaseEvidence, recordVersions: Set<UInt64> = [1]) throws {
        try MachineUpdateRetainedSetupPromotionReadyStorage.requireReaderFormats(candidate)
        for required in try readerRequirements {
            guard let format = candidate.manifest.components.first(where: { $0.role == required.role })?
                .formats.first(where: { $0.name == required.name }), required.readVersions.isSubset(of: format.readers),
                  required.name != RuntimeMaintenanceWindowRecord.formatName || recordVersions.isSubset(of: format.readers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    /// Only Setup produces windows. Authority declarations cannot replace the Setup producer contract.
    static func requireWriteFormats(_ candidate: SignedReleaseEvidence, sourceSchema: Int64, recordVersion: UInt64 = 1) throws {
        guard [Int64(28), 29].contains(sourceSchema) else { throw PreparationStoreError.invalidTransition }
        try requireReaderFormats(candidate, recordVersions: [1, recordVersion])
        guard let setup = candidate.manifest.components.first(where: { $0.role == .setupController }),
              let installation = setup.formats.first(where: { $0.name == "authority.installation-preparation" }),
              installation.writers.contains(29), setup.formats.first(where: { $0.name == RuntimeMaintenanceWindowRecord.formatName })?.writers.contains(recordVersion) == true,
              sourceSchema != 28 || installation.migrations[28] == 29 else { throw PreparationStoreError.incompatibleStore }
    }
    /// The caller supplies indexed columns and bytes from one protected transaction. No machine query occurs here.
    static func decode(accountID: Data, attemptID: Data, revision: Data, phase: UInt64,
                       bytes: Data) throws -> RuntimeMaintenanceWindowRecord {
        let value: RuntimeMaintenanceWindowRecord
        do { value = try RuntimeMaintenanceWindowRecord.decode(bytes) } catch { throw PreparationStoreError.corruptRecord }
        guard value.scope.authority.accountID == accountID, value.id == attemptID, value.revision == revision,
              value.phase.rawValue == phase else { throw PreparationStoreError.corruptRecord }
        return value
    }
}
