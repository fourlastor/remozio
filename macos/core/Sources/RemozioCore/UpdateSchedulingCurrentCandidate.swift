import Darwin
import Foundation

enum UpdateSchedulingCandidateLeaseError: Error, Equatable {
    case expired, wrongScope, notDesignatedUpdateOwner
}

/// Enables retained selection storage. It grants no scheduling, drain, replacement, or restart authority.
enum UpdateSchedulingCurrentCandidate {
    static func enableStorage(installedRelease: SignedReleaseEvidence, policy: AuthorityCodePolicy,
        store: PreparationIntentStore) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try enableStorageInLease(installedRelease: installedRelease, policy: policy, store: store)
    }

    static func enableStorageInLease(installedRelease: SignedReleaseEvidence, policy: AuthorityCodePolicy,
        store: PreparationIntentStore) throws {
        try UpdateSchedulingCandidateRecord.validateReaders(installedRelease, policy: policy)
        try RuntimeReleaseCompatibilitySnapshot.capture(machine: store).validate(installedRelease, policy: policy, machine: store)
        try store.upgradeUpdateCandidateStorage(expectedInstalledReleaseDigest: InstallationInventory.digest(installedRelease))
    }
}
