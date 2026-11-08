import Foundation

/// Retained restart values only. Runtime owners must authenticate subsequent health. This value grants no startup or floor authority.
struct MachineUpdateRestartSnapshot {
    let source: MachineUpdateRestartSource
    let configuration: MachineUpdateConfigurationEpoch.Archive
    let backend: MachineUpdateBackendEpoch.Archive

    func requireSame(as expected: Self) throws {
        guard source == expected.source, configuration.record == expected.configuration.record,
              configuration.artifacts == expected.configuration.artifacts,
              backend.record == expected.backend.record, backend.artifacts == expected.backend.artifacts else {
            throw PreparationStoreError.staleRevision
        }
    }
}

/// Exact retained placement only. This check grants no replacement or startup authority.
enum MachineUpdateRestartPlacement {
    static func require(_ record: MachineUpdateReplacementRecord, installed: ReleaseDestinationLease,
                        prepared: ReleaseDestinationLease) throws {
        try record.requireParents(installed: installed, prepared: prepared)
        guard record.phase == .observed,
              try installed.preparationCopyIdentity(name: record.installedName) == record.preparedIdentity,
              try prepared.preparationCopyIdentity(name: record.preparedName) == record.previousIdentity else {
            throw MachineUpdateReplacementError.changedBinding
        }
    }
}
