import Darwin
import Foundation
@testable import RemozioCore

do {
    let args = CommandLine.arguments
    guard (5...6).contains(args.count), args.count == 5 || ["raise-floor", "inspect-only"].contains(args[5]),
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
    let initial = try SignedReleaseInspection.inspect(source, teamID: args[3], appIdentifier: args[4])
    let policy = try AuthorityCodePolicy(entries: initial.manifest.components.map { component in
        guard let team = component.teamID, let hash = initial.codeDirectoryHashes[component.role] else { throw ReleaseManifestError.identityMismatch }
        return try .init(role: component.role, teamID: team, identifier: component.identifier,
            installedGeneration: component.generation, minimumGeneration: component.generation, codeDirectoryHash: hash, active: true)
    })
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
    fputs("copy fixture rejected: \(error)\n", stderr)
    exit(65)
}
