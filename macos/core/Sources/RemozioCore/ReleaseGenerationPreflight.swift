import Foundation

public enum ReleaseGenerationPreflightError: Error, Equatable {
    case invalidEvidence, identityChanged(AuthorityCodeRole), rollback(AuthorityCodeRole), missingActiveRole(AuthorityCodeRole)
}

/// Compares candidate signature evidence with retained code policy. This check grants no installation authority.
public enum ReleaseGenerationPreflight {
    /// Read current protected policy and inspect the protected copy again at the installation boundary.
    /// Format compatibility, notarization, quiescence and durable activation remain separate requirements.
    public static func validate(_ evidence: SignedReleaseEvidence, against policy: AuthorityCodePolicy) throws {
        let components = evidence.manifest.components
        guard Set(evidence.codeDirectoryHashes.keys) == Set(components.map(\.role)),
              components.allSatisfy({ component in
                  guard component.teamID != nil,
                        let hash = evidence.codeDirectoryHashes[component.role], hash.count == 20 else { return false }
                  return component.role == .app || component.codeDirectoryHash == hash
              }) else { throw ReleaseGenerationPreflightError.invalidEvidence }
        for retained in policy.entries {
            guard let candidate = components.first(where: { $0.role == retained.role }) else {
                if retained.active { throw ReleaseGenerationPreflightError.missingActiveRole(retained.role) }
                continue
            }
            guard candidate.teamID == retained.teamID, candidate.identifier == retained.identifier else {
                throw ReleaseGenerationPreflightError.identityChanged(retained.role)
            }
            guard candidate.generation >= retained.minimumGeneration,
                  candidate.generation >= retained.installedGeneration else {
                throw ReleaseGenerationPreflightError.rollback(retained.role)
            }
        }
    }
}
