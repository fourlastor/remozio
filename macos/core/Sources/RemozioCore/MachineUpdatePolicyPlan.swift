import Foundation

/// Proposed policy values only. Construction does not publish policy, prove health or commit security floors.
struct MachineUpdatePolicyPlan: CustomStringConvertible, CustomDebugStringConvertible {
    let source: AuthorityCodePolicySnapshot
    let releaseDigest: Data
    let startupPolicy: AuthorityCodePolicy
    let completionPolicy: AuthorityCodePolicy
    var description: String { "MachineUpdatePolicyPlan(redacted)" }
    var debugDescription: String { description }

    init(source: AuthorityCodePolicySnapshot, candidate: SignedReleaseEvidence) throws {
        _ = try source.storedBytes
        try ReleaseGenerationPreflight.validate(candidate, against: source.policy)
        let components = Dictionary(uniqueKeysWithValues: candidate.manifest.components.map { ($0.role, $0) })
        var startup: [AuthorityCodeEntry] = [], completion: [AuthorityCodeEntry] = []
        for retained in source.policy.entries {
            guard let component = components[retained.role], let hash = candidate.codeDirectoryHashes[retained.role] else {
                guard !retained.active else { throw ReleaseGenerationPreflightError.missingActiveRole(retained.role) }
                startup.append(retained); completion.append(retained); continue
            }
            startup.append(try .init(role: retained.role, teamID: retained.teamID, identifier: retained.identifier,
                installedGeneration: component.generation, minimumGeneration: retained.minimumGeneration,
                codeDirectoryHash: hash, active: retained.active))
            completion.append(try .init(role: retained.role, teamID: retained.teamID, identifier: retained.identifier,
                installedGeneration: component.generation, minimumGeneration: component.generation,
                codeDirectoryHash: hash, active: retained.active))
        }
        self.source = source; releaseDigest = try InstallationInventory.digest(candidate)
        startupPolicy = try source.policy.retainingFormat(with: startup)
        completionPolicy = try source.policy.retainingFormat(with: completion)
        try startupPolicy.requireSuccessor(of: source.policy)
        try completionPolicy.requireSuccessor(of: startupPolicy)
    }

    /// Recheck the protected revision and every retained role token before using either proposed value.
    func requireCurrent(_ current: AuthorityCodePolicySnapshot) throws {
        guard current == source else { throw AuthorityCodePolicyError.staleRevision }
    }

    func requireCandidate(_ candidate: SignedReleaseEvidence) throws {
        try ReleaseGenerationPreflight.validate(candidate, against: source.policy)
        guard try InstallationInventory.digest(candidate) == releaseDigest else { throw RuntimePreparationError.changedScope }
    }
}
