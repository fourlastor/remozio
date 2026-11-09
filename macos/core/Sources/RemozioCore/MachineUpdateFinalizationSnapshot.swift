import Foundation

/// Actual installed metadata. Historical operands do not grant startup or admission authority.
struct MachineUpdateFinalizationSnapshot: Sendable {
    let schemaVersion: Int64
    let inventory: InstallationInventory
    let candidate: UpdateSchedulingCandidateRecord
    let activation: MachineUpdateActivationRecord
    let admission: UpdateAdmissionRegistrationRecord
    let installed: MachineUpdateInstalledReleaseEpoch.Archive
    let preparations: [AccountPreparationIntent]
    let initializations: [AuthorityInitializationIntent]

    func requireSame(as other: Self) throws {
        guard schemaVersion == other.schemaVersion, inventory == other.inventory, candidate == other.candidate,
              activation == other.activation, admission == other.admission, preparations == other.preparations, initializations == other.initializations,
              installed.record == other.installed.record, installed.artifacts == other.installed.artifacts else {
            throw PreparationStoreError.staleRevision
        }
    }
}

enum MachineUpdateFinalizationFrame {
    case publication(MachineUpdateCompletionPublicationSnapshot)
    case installed(MachineUpdateFinalizationSnapshot)

    func requireSame(as other: Self) throws {
        switch (self, other) {
        case (.publication(let actual), .publication(let expected)): try actual.requireSame(as: expected)
        case (.installed(let actual), .installed(let expected)): try actual.requireSame(as: expected)
        default: throw PreparationStoreError.staleRevision
        }
    }
}
