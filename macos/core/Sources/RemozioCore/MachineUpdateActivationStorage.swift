import Darwin
import Foundation

enum MachineUpdateActivationStorage {
    static func enable(installedRelease: SignedReleaseEvidence, policy: AuthorityCodePolicy, store: PreparationIntentStore) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try enableInLease(installedRelease: installedRelease, policy: policy, store: store)
    }
    static func enableInLease(installedRelease: SignedReleaseEvidence, policy: AuthorityCodePolicy, store: PreparationIntentStore) throws {
        try ReleaseCompatibilityPreflight.validate(installedRelease, policy: policy,
            requirements: .init(formats: MachineUpdateActivationRecord.requirements, requests: []))
        try RuntimeReleaseCompatibilitySnapshot.capture(machine: store).validate(installedRelease, policy: policy, machine: store)
        try store.upgradeMachineUpdateActivationStorage(expectedInstalledReleaseDigest: InstallationInventory.digest(installedRelease))
    }
}
