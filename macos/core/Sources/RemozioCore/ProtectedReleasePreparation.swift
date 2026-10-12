import Darwin
import Foundation

public struct InactiveReleaseCopyEvidence: Sendable {
    public let bundle: URL
    public let counts: ReleaseCopyCounts
    public let signature: SignedReleaseEvidence
}

/// Prepares an inactive copy. Compatibility, notarization, recovery and activation remain separate gates.
public enum ProtectedReleasePreparation {
    /// The policy reader must use current protected state. Never derive it from the candidate.
    public static func prepare(source: URL, destination: ReleaseDestinationLease, bundleName: String,
                               limits: ReleaseCopyLimits = try! .init(), readPolicy: () throws -> AuthorityCodePolicy,
                               checkCancellation: @escaping () throws -> Void = {}) throws -> InactiveReleaseCopyEvidence {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try prepareInLease(source: source, destination: destination, bundleName: bundleName,
            limits: limits, readPolicy: readPolicy, checkCancellation: checkCancellation)
    }

    // Internal composition. Production calls the Root-only entry point; fixtures use an ordinary-owner lease.
    static func prepareInLease(source: URL, destination: ReleaseDestinationLease, bundleName: String,
                               limits: ReleaseCopyLimits = try! .init(), readPolicy: () throws -> AuthorityCodePolicy,
                               checkCancellation: @escaping () throws -> Void = {}) throws -> InactiveReleaseCopyEvidence {
        try destination.validate(); try checkCancellation()
        let initialPolicy = try readPolicy()
        guard let identity = initialPolicy.entries.first(where: { $0.role == .app }) else {
            throw AuthorityCodePolicyError.invalidPolicy
        }
        let original = try SignedReleaseInspection.inspect(source, teamID: identity.teamID, appIdentifier: identity.identifier)
        try ReleaseGenerationPreflight.validate(original, against: initialPolicy)
        let bundle = URL(fileURLWithPath: destination.path).appendingPathComponent(bundleName, isDirectory: true)
        var copied: SignedReleaseEvidence?
        let counts = try destination.withDirectory { descriptor in
            try DescriptorTreeCopy.copy(source: source, parent: URL(fileURLWithPath: destination.path), name: bundleName,
                limits: limits, checkCancellation: checkCancellation, borrowedParent: descriptor, validateCopy: { counts in
                    guard try destination.inspectCopiedTree(name: bundleName, limits: limits) == counts else {
                        throw ReleaseCopyError.changedDestination
                    }
                    let value = try SignedReleaseInspection.inspect(bundle, teamID: identity.teamID, appIdentifier: identity.identifier)
                    guard try value.manifest.canonicalBytes == original.manifest.canonicalBytes,
                          value.codeDirectoryHashes == original.codeDirectoryHashes,
                          value.dependencyCodeDirectoryHashes == original.dependencyCodeDirectoryHashes else {
                        throw ReleaseManifestError.identityMismatch
                    }
                    let finalPolicy = try readPolicy()
                    guard finalPolicy.entries.contains(where: { $0.role == .app }) else { throw AuthorityCodePolicyError.invalidPolicy }
                    try ReleaseGenerationPreflight.validate(value, against: finalPolicy)
                    guard try destination.inspectCopiedTree(name: bundleName, limits: limits) == counts else {
                        throw ReleaseCopyError.changedDestination
                    }
                    copied = value
                }, openedFile: { _, _, _ in })
        }
        guard let copied else { throw ReleaseGenerationPreflightError.invalidEvidence }
        return InactiveReleaseCopyEvidence(bundle: bundle, counts: counts, signature: copied)
    }
}
