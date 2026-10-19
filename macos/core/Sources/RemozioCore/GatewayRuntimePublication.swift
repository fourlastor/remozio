import Darwin
import Foundation

/// Publishes optional inputs without replacing foreground startup files or stopping their services.
/// The administrator operation must hold its machine/release scope and authorize this transition.
enum GatewayRuntimePublication {
    enum Mode { case publishPending, validateRetained }
    enum Artifact: CaseIterable, Hashable { case authority, transport, commit }
    struct Result { let files: [Artifact: AdministrativeSetupPublicationResult] }

    static func publish(_ pair: GatewayRuntimeExtensions, journal: GatewayJournalPreparationState,
                        foreground: RuntimeActivationPlan, inventory: InstallationInventory, mode: Mode,
                        verifyCurrent: () throws -> Void) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent(); try pair.validate(journal: journal, foreground: foreground, inventory: inventory)
        let paths = try RuntimePreparationPaths(accountID: pair.authority.material.runtime.services.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        return try publish(pair, directory: directory, owner: 0, mode: mode, verifyCurrent: verifyCurrent)
    }

    // Owned fixtures exercise publication ordering. The native entry fixes the owner, path and validated setup scope.
    static func publish(_ pair: GatewayRuntimeExtensions, directory: ProtectedSetupDirectory, owner: uid_t, mode: Mode,
                        verifyCurrent: () throws -> Void, willCommit: () throws -> Void = {},
                        didPublish: (Artifact) throws -> Void = { _ in }) throws -> Result {
        let files: [(Artifact, Data, AdministrativeSetupPublication.File)] = [
            (.authority, try pair.authority.encoded, .authorityGatewayRuntime),
            (.transport, try pair.transport.encoded, .transportGatewayRuntime),
            (.commit, try GatewayRuntimeCommit(pair).encoded, .gatewayRuntimeCommit)
        ]
        func verify() throws { try verifyCurrent(); try directory.validate() }
        func exists(_ file: AdministrativeSetupPublication.File) throws -> Bool {
            try directory.withSharedDirectory { parent in
                var info = stat()
                if fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }; return false
            }
        }
        try verify()
        let retained = try mode == .validateRetained || exists(.gatewayRuntimeCommit)
        // Check every existing sibling before creating any missing one. A published marker forbids repair by creation.
        for (_, bytes, file) in files {
            try verify()
            if try retained || exists(file) {
                try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
            }
        }
        var results: [Artifact: AdministrativeSetupPublicationResult] = [:]
        for (artifact, bytes, file) in files {
            try verify()
            // Recheck both role files immediately before the marker makes either role available to a loader.
            if artifact == .commit {
                for (_, roleBytes, roleFile) in files.prefix(2) {
                    try AdministrativeSetupPublication.validateRetained(roleBytes, file: roleFile, directory: directory, owner: owner, verify: verify)
                }
                try willCommit(); try verify()
            }
            if retained {
                try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
                results[artifact] = .retained
            } else {
                results[artifact] = try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: owner, verify: verify)
            }
            try didPublish(artifact); try verify()
        }
        for (_, bytes, file) in files {
            try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
        }
        try verify(); return .init(files: results)
    }
}
