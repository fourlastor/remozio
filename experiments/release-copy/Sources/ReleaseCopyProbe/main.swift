import Darwin
import Foundation
@testable import RemozioCore

var phase = "argument validation"
do {
    let args = CommandLine.arguments
    guard (5...6).contains(args.count), args.count == 5 || ["raise-floor", "inspect-only", "durable-copy"].contains(args[5]),
          getuid() != 0, getuid() == geteuid(), args[4].hasPrefix("dev.remozio.experiment.sparkleboundary.") else { exit(64) }
    let source = URL(fileURLWithPath: args[1]), parent = URL(fileURLWithPath: args[2])
    for root in [source.deletingLastPathComponent().deletingLastPathComponent(), parent.deletingLastPathComponent()] {
        guard root.lastPathComponent.hasPrefix("remozio-sparkle-boundary-") else { exit(64) }
        var info = stat()
        guard lstat(root.path, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFDIR,
              info.st_mode & 0o077 == 0 else { exit(64) }
    }
    let lease = try ReleaseDestinationLease(anchor: parent.deletingLastPathComponent().path, relativeDirectory: parent.lastPathComponent, owner: geteuid())
    defer { lease.close() }
    if args.count == 6 && args[5] == "inspect-only" {
        let counts = try lease.inspectCopiedTree(name: "Fixture.app")
        FileHandle.standardOutput.write(try JSONEncoder().encode(counts) + Data([10]))
        exit(0)
    }
    // This policy is synthetic fixture data. Production reads retained protected state.
    phase = "initial native inspection"
    let initial = try SignedReleaseInspection.inspect(source, teamID: args[3], appIdentifier: args[4])
    let policy = try AuthorityCodePolicy(entries: initial.manifest.components.map { component in
        guard let team = component.teamID, let hash = initial.codeDirectoryHashes[component.role] else { throw ReleaseManifestError.identityMismatch }
        return try .init(role: component.role, teamID: team, identifier: component.identifier,
            installedGeneration: component.generation, minimumGeneration: component.generation, codeDirectoryHash: hash, active: true)
    })
    if args.count == 6 && args[5] == "durable-copy" {
        let state = parent.appendingPathComponent("State")
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: false)
        guard chmod(state.path, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
        for name in ["writer.lock", "installation.sqlite"] {
            let file = state.appendingPathComponent(name)
            try Data().write(to: file)
            guard chmod(file.path, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
        }
        func store(_ initialize: Bool) throws -> PreparationIntentStore {
            try .init(lease: InstallationStorageLease(anchor: parent.path, relativeDirectory: "State", owner: geteuid()),
                      macID: Data(repeating: 1, count: 16), maximumRecords: 4, initialize: initialize)
        }
        let first = try store(true)
        phase = "durable preparation"
        let prepared = try DurableReleasePreparation.prepareInLease(source: source, destination: lease,
            store: first, readPolicy: { policy })
        try first.close()
        phase = "durable store reopen"
        let reopened = try store(false)
        defer { try? reopened.close() }
        let saved = try reopened.records()
        phase = "fresh native recovery"
        let recovered = try DurableReleasePreparation.recoverInLease(attemptID: prepared.attemptID,
            destination: lease, store: reopened, readPolicy: { policy })
        phase = "recovered native evidence comparison"
        let matches: [String: Bool] = [
            "bundleURL": recovered.copy.bundle == prepared.copy.bundle,
            "bundlePath": recovered.copy.bundle.path == prepared.copy.bundle.path,
            "counts": recovered.copy.counts == prepared.copy.counts,
            "manifest": try recovered.copy.signature.manifest.canonicalBytes == prepared.copy.signature.manifest.canonicalBytes,
            "componentHashes": recovered.copy.signature.codeDirectoryHashes == prepared.copy.signature.codeDirectoryHashes,
            "dependencyHashes": recovered.copy.signature.dependencyCodeDirectoryHashes == prepared.copy.signature.dependencyCodeDirectoryHashes]
        guard matches.values.allSatisfy({ $0 }) else {
            FileHandle.standardError.write(try JSONSerialization.data(withJSONObject: matches, options: [.sortedKeys]) + Data([10]))
            throw ReleaseManifestError.identityMismatch
        }
        phase = "advanced recovery floor"
        var reads = 0
        do {
            _ = try DurableReleasePreparation.recoverInLease(attemptID: prepared.attemptID,
                destination: lease, store: reopened, readPolicy: {
                    reads += 1
                    if reads == 1 { return policy }
                    return try AuthorityCodePolicy(entries: policy.entries.map { entry in
                        try .init(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                            installedGeneration: entry.installedGeneration + 1, minimumGeneration: entry.minimumGeneration + 1,
                            codeDirectoryHash: entry.codeDirectoryHash, active: entry.active)
                    })
                })
            throw ReleaseGenerationPreflightError.invalidEvidence
        } catch ReleaseGenerationPreflightError.rollback { }
        guard reads == 2, try reopened.records() == saved else { throw AuthorityCodePolicyError.invalidPolicy }
        phase = "changed copied metadata"
        let resource = recovered.copy.bundle.appendingPathComponent("Contents/Resources/compressed-data")
        let fd = open(resource.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        defer { Darwin.close(fd) }
        let name = "dev.remozio.experiment.recovery"
        let bytes = Data([1])
        guard bytes.withUnsafeBytes({ fsetxattr(fd, name, $0.baseAddress, $0.count, 0, 0) }) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        do {
            _ = try DurableReleasePreparation.recoverInLease(attemptID: prepared.attemptID,
                destination: lease, store: reopened, readPolicy: { policy })
            throw ReleaseGenerationPreflightError.invalidEvidence
        } catch JournalLeaseError.unsafeMetadata { }
        guard fremovexattr(fd, name, 0) == 0 else { throw JournalLeaseError.system(errno) }
        _ = try DurableReleasePreparation.recoverInLease(attemptID: prepared.attemptID,
            destination: lease, store: reopened, readPolicy: { policy })
        guard try reopened.records() == saved else { throw PreparationStoreError.corruptRecord }
        try reopened.close()
        let result: [String: Any] = ["control": "durable-signed-copy-reopen", "realCoreCopierUsed": true,
            "nativeSignatureInspectorUsed": true, "copyCountsMatch": true, "signingMetadataMatch": true,
            "persistedRecordRetained": true, "advancedFloorRejected": true, "changedMetadataRejected": true,
            "metadataCleanupRecovered": true, "RootIsolationTested": false, "activation": false]
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]) + Data([10]))
        exit(0)
    }
    phase = "ordinary inactive copy"
    var policyReads = 0
    let result = try ProtectedReleasePreparation.prepareInLease(source: source, destination: lease, bundleName: "Fixture.app", readPolicy: {
        policyReads += 1
        if args.count == 6 && policyReads == 2 {
            return try AuthorityCodePolicy(entries: policy.entries.map { entry in
                try .init(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                    installedGeneration: entry.installedGeneration + 1, minimumGeneration: entry.minimumGeneration + 1,
                    codeDirectoryHash: entry.codeDirectoryHash, active: entry.active)
            })
        }
        return policy
    })
    guard policyReads == 2 else { throw AuthorityCodePolicyError.invalidPolicy }
    FileHandle.standardOutput.write(try JSONEncoder().encode(result.counts) + Data([10]))
} catch {
    fputs("copy fixture rejected at \(phase): \(error)\n", stderr)
    exit(65)
}
