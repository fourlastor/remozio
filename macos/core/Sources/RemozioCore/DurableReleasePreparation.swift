import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum DurablePreparationError: Error {
    case recordMissing, incompleteRecord, destinationChanged, signingMetadataChanged
    case preparationAndRecordFailure(any Error, any Error)
}
public struct DurableInactiveCopyEvidence {
    public let attemptID: UUID
    public let copy: InactiveReleaseCopyEvidence
}

/// Persists preparation progress. No record or returned inactive copy grants activation authority.
public enum DurableReleasePreparation {
    public static func prepare(source: URL, destination: ReleaseDestinationLease, store: PreparationIntentStore,
                        limits: ReleaseCopyLimits = try! .init(), readPolicy: () throws -> AuthorityCodePolicy,
                        checkCancellation: @escaping () throws -> Void = {}) throws -> DurableInactiveCopyEvidence {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try prepareInLease(source: source, destination: destination, store: store,
            limits: limits, readPolicy: readPolicy, checkCancellation: checkCancellation)
    }
    // Internal ordinary-owner seam. Production cannot select an ownership or signature override.
    static func prepareInLease(source: URL, destination: ReleaseDestinationLease, store: PreparationIntentStore,
                               limits: ReleaseCopyLimits = try! .init(), readPolicy: () throws -> AuthorityCodePolicy,
                               checkCancellation: @escaping () throws -> Void = {}) throws -> DurableInactiveCopyEvidence {
        try reconcileAbandonedInLease(destination: destination, store: store)
        let attempt = try store.begin(parent: destination.path, ancestry: destination.preparationAncestry())
        do {
            let copy = try ProtectedReleasePreparation.prepareInLease(source: source, destination: destination,
                bundleName: attempt.bundleName, limits: limits, readPolicy: readPolicy, checkCancellation: checkCancellation)
            let identity = try destination.preparationCopyIdentity(name: attempt.bundleName)
            _ = try store.recordCopy(id: attempt.id, expectedRevision: attempt.revision, identity: identity,
                                     digest: digest(copy.signature))
            return .init(attemptID: attempt.id, copy: copy)
        } catch {
            let preparationFailure = error
            do { _ = try store.abandon(id: attempt.id, expectedRevision: attempt.revision) }
            catch { throw DurablePreparationError.preparationAndRecordFailure(preparationFailure, error) }
            throw preparationFailure
        }
    }
    /// Reclaims only abandoned bookkeeping whose bound copy is absent. It never removes filesystem objects.
    public static func reconcileAbandoned(destination: ReleaseDestinationLease, store: PreparationIntentStore) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try reconcileAbandonedInLease(destination: destination, store: store)
    }
    static func reconcileAbandonedInLease(destination: ReleaseDestinationLease, store: PreparationIntentStore) throws {
        let ancestry = try destination.preparationAncestry()
        for record in try store.records() where record.phase == .abandoned {
            guard record.parent == destination.path, record.ancestry == ancestry,
                  try !destination.preparationCopyExists(name: record.bundleName) else { continue }
            try store.forgetAbsentAbandoned(id: record.id, expectedRevision: record.revision)
        }
    }
    public static func recover(attemptID: UUID, destination: ReleaseDestinationLease, store: PreparationIntentStore,
                        limits: ReleaseCopyLimits = try! .init(), readPolicy: () throws -> AuthorityCodePolicy) throws -> DurableInactiveCopyEvidence {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try recoverInLease(attemptID: attemptID, destination: destination, store: store,
                                  limits: limits, readPolicy: readPolicy)
    }
    static func recoverInLease(attemptID: UUID, destination: ReleaseDestinationLease, store: PreparationIntentStore,
                               limits: ReleaseCopyLimits = try! .init(), readPolicy: () throws -> AuthorityCodePolicy,
                               inspect: (URL, String, String) throws -> SignedReleaseEvidence = {
                                   try SignedReleaseInspection.inspect($0, teamID: $1, appIdentifier: $2)
                               }) throws -> DurableInactiveCopyEvidence {
        guard let record = try store.records().first(where: { $0.id == attemptID }) else { throw DurablePreparationError.recordMissing }
        guard record.phase == .copyRecorded, let expectedIdentity = record.copyIdentity,
              let expectedDigest = record.copyDigest else { throw DurablePreparationError.incompleteRecord }
        guard destination.path == record.parent, try destination.preparationAncestry() == record.ancestry,
              try destination.preparationCopyIdentity(name: record.bundleName) == expectedIdentity else {
            throw DurablePreparationError.destinationChanged
        }
        let counts = try destination.inspectCopiedTree(name: record.bundleName, limits: limits)
        let policy = try readPolicy()
        guard let identity = policy.entries.first(where: { $0.role == .app }) else { throw AuthorityCodePolicyError.invalidPolicy }
        let bundle = URL(fileURLWithPath: destination.path).appendingPathComponent(record.bundleName, isDirectory: true)
        let signature = try inspect(bundle, identity.teamID, identity.identifier)
        try ReleaseGenerationPreflight.validate(signature, against: policy)
        guard try digest(signature) == expectedDigest else { throw DurablePreparationError.signingMetadataChanged }
        let finalPolicy = try readPolicy()
        guard finalPolicy.entries.contains(where: { $0.role == .app }) else { throw AuthorityCodePolicyError.invalidPolicy }
        try ReleaseGenerationPreflight.validate(signature, against: finalPolicy)
        guard try destination.preparationAncestry() == record.ancestry,
              try destination.preparationCopyIdentity(name: record.bundleName) == expectedIdentity,
              try destination.inspectCopiedTree(name: record.bundleName, limits: limits) == counts else {
            throw DurablePreparationError.destinationChanged
        }
        return .init(attemptID: record.id, copy: .init(bundle: bundle, counts: counts, signature: signature))
    }
    static func digest(_ signature: SignedReleaseEvidence) throws -> Data {
        let hashes = Dictionary(uniqueKeysWithValues: signature.codeDirectoryHashes.map { ($0.key.rawValue, CBORValue.bytes($0.value)) })
        let bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(signature.manifest.canonicalBytes),
                                                     2: .map(hashes)]),
            limits: .init(maxBytes: ReleaseManifest.maximumBytes + 4096, maxDepth: 3, maxItems: 256))
        return Data(SHA256.hash(data: Data("Remozio inactive release record v1\0".utf8) + bytes))
    }
}
