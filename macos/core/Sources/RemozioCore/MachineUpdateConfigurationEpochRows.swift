import Foundation

/// Validates the retained row envelope before the archive decodes its typed payloads.
enum MachineUpdateConfigurationEpochRows {
    struct Row {
        let kind: Int64
        let account: Data
        let epoch: Data
        let revision: Data
        let payload: Data
    }

    static func decodeRecord(_ rows: [Row], macID: Data) throws -> MachineUpdateConfigurationEpochRecord? {
        guard let header = rows.first else { return nil }
        guard rows.count <= 518, header.kind == 0, header.account == MachineUpdateConfigurationEpochRecord.globalAccount else {
            throw PreparationStoreError.corruptRecord
        }
        let record = try MachineUpdateConfigurationEpochRecord.decode(header.payload)
        let epoch = withUnsafeBytes(of: record.id.uuid) { Data($0) }
        let revision = withUnsafeBytes(of: record.revision.uuid) { Data($0) }
        guard record.macID == macID, header.epoch == epoch, header.revision == revision,
              rows.count == record.operands.count + 1 else {
            throw PreparationStoreError.corruptRecord
        }
        for (row, operand) in zip(rows.dropFirst(), record.operands) {
            guard row.kind == operand.kind, row.account == operand.account,
                  row.epoch == epoch, row.revision == revision,
                  !row.payload.isEmpty, row.payload.count <= RuntimeReleaseConfigurationSource.maximumBytes,
                  MachineUpdateActivationRecord.digest(row.payload) == operand.digest else {
                throw PreparationStoreError.corruptRecord
            }
        }
        return record
    }
}
