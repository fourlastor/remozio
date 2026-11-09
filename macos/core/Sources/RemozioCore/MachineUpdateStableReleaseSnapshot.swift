import Foundation

/// Exact stable metadata. The snapshot carries no live readiness proof or admission authority.
struct MachineUpdateStableReleaseSnapshot: Sendable {
    let inventory: InstallationInventory
    let activation: MachineUpdateActivationRecord
    let admission: UpdateAdmissionRegistrationRecord
    let candidate: UpdateSchedulingCandidateRecord
    let installed: MachineUpdateInstalledReleaseEpoch.Archive
    let seal: MachineUpdateStableReleaseRecord
    let currentRowsDigest: Data

    /// Only the first stable frame can continue the original finishing readiness proof.
    func requireInitialTransition(from expected: MachineUpdateInstalledReadinessPlan, release: SignedReleaseEvidence) throws {
        let before = expected.view.compatibility.source.actual
        let proposed = try MachineUpdateStableReleaseRecord(readiness: expected, completed: activation, candidate: release)
        guard inventory == before.inventory, admission == before.admission, candidate == before.candidate,
              currentRowsDigest == expected.view.compatibility.source.historicalSourceDigest,
              installed.record == before.installed.record, installed.artifacts == before.installed.artifacts,
              try seal.encoded == proposed.encoded else { throw PreparationStoreError.staleRevision }
    }

    func requireSame(as other: Self) throws {
        guard inventory == other.inventory, activation == other.activation, admission == other.admission,
              candidate == other.candidate, currentRowsDigest == other.currentRowsDigest,
              installed.record == other.installed.record, installed.artifacts == other.installed.artifacts,
              try seal.encoded == other.seal.encoded else { throw PreparationStoreError.staleRevision }
    }
}

/// A verified transaction can lend either its actual finishing or its actual terminal metadata.
enum MachineUpdateStableCompletionFrame: Sendable {
    case finishing(MachineUpdateInstalledReadinessPlan)
    case stable(MachineUpdateStableReleaseSnapshot)

    func requireSame(as expected: Self) throws {
        switch (self, expected) {
        case (.finishing(let actual), .finishing(let before)): try actual.requireSame(as: before)
        case (.stable(let actual), .stable(let before)): try actual.requireSame(as: before)
        default: throw PreparationStoreError.staleRevision
        }
    }
}
