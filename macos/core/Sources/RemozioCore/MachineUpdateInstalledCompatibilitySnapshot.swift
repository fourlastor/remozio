import Foundation

/// Describes the installed release under a finishing loan. It grants no startup, write or admission authority.
struct MachineUpdateInstalledCompatibilitySnapshot: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let source: MachineUpdateInstalledSourceSnapshot
    let runtime: RuntimeReleaseCompatibilitySnapshot
    var description: String { "MachineUpdateInstalledCompatibilitySnapshot(redacted)" }
    var debugDescription: String { description }

    func requireSame(as other: Self) throws {
        try source.requireSame(as: other.source)
        guard runtime.inputs == other.runtime.inputs else { throw PreparationStoreError.staleRevision }
    }

    func requireCurrent(scope: PreparationIntentStore.CompletionFinalizationScope) throws {
        try scope.readCompatibility().requireSame(as: self)
    }

    /// Checks format support while the actual finishing frame remains current.
    func validate(_ candidate: SignedReleaseEvidence, policy: AuthorityCodePolicy,
        scope: PreparationIntentStore.CompletionFinalizationScope) throws {
        guard try InstallationInventory.digest(candidate) == source.actual.inventory.releaseDigest else {
            throw PreparationStoreError.staleRevision
        }
        try runtime.validate(candidate, policy: policy, verifyCurrent: { try requireCurrent(scope: scope) })
    }
}
