import Darwin
import Foundation

/// Authorized setup holds the release scope and verifies the retained activation intent before every operation.
/// These files add optional consumers. Foreground startup files and service identities stay unchanged.
enum GatewayRuntimeActivationFiles {
    enum Mode: Equatable { case publishPending, validateRetained }
    enum Artifact: CaseIterable, Hashable { case configuration, job, authority, transport, commit }
    struct Result { let files: [Artifact: AdministrativeSetupPublicationResult] }

    static func prepare(plan: GatewayRuntimeActivationPlan, account: AccountPreparationIntent,
                        initialization: AuthorityInitializationIntent, journal: GatewayJournalPreparationState,
                        foreground: RuntimeActivationPlan, inventory: InstallationInventory, mode: Mode,
                        verifyCurrent: () throws -> Void) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        _ = try plan.proposal(journal: journal, foreground: foreground, inventory: inventory)
        func verify() throws {
            try verifyCurrent()
            try RuntimeActivationFiles.validate(plan: foreground, account: account, initialization: initialization,
                inventory: inventory, verifyCurrent: verifyCurrent)
            _ = try GatewayPrivateArtifactPublication.publish(account: account, expected: plan.extensions.authority.material,
                mode: .validateRetained, verifyCurrent: verifyCurrent)
            try verifyCurrent()
        }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: plan.accountID)
        let shared = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { shared.close() }
        let jobs = try ProtectedSetupDirectory(anchor: "/", relativePath: String(InstalledAccountJobManifest.directory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { jobs.close() }
        return try publish(plan, journal: journal, foreground: foreground, inventory: inventory,
            shared: shared, jobs: jobs, owner: 0, mode: mode, verifyCurrent: verify)
    }

    // Owned fixtures use real file publication. They do not prove Root placement or dedicated service access.
    static func publish(_ plan: GatewayRuntimeActivationPlan, journal: GatewayJournalPreparationState,
                        foreground: RuntimeActivationPlan, inventory: InstallationInventory, shared: ProtectedSetupDirectory,
                        jobs: ProtectedSetupDirectory, owner: uid_t, mode: Mode, verifyCurrent: () throws -> Void,
                        didPublish: (Artifact) throws -> Void = { _ in }) throws -> Result {
        let proposal = try plan.proposal(journal: journal, foreground: foreground, inventory: inventory)
        let files: [(Artifact, Data, AdministrativeSetupPublication.File, ProtectedSetupDirectory)] = [
            (.configuration, proposal.gateway.canonicalBytes, .gatewayConfiguration, shared),
            (.job, try plan.gatewayJob.bytes, .accountJob(accountID: plan.accountID, role: .notificationGateway), jobs),
            (.authority, try plan.extensions.authority.encoded, .authorityGatewayRuntime, shared),
            (.transport, try plan.extensions.transport.encoded, .transportGatewayRuntime, shared),
            (.commit, try GatewayRuntimeCommit(plan.extensions).encoded, .gatewayRuntimeCommit, shared)
        ]
        func verify() throws { try verifyCurrent(); try shared.validate(); try jobs.validate() }
        func exists(_ file: AdministrativeSetupPublication.File, _ directory: ProtectedSetupDirectory) throws -> Bool {
            try directory.withSharedDirectory { parent in
                var info = stat()
                if fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }; return false
            }
        }
        func validate(_ entry: (Artifact, Data, AdministrativeSetupPublication.File, ProtectedSetupDirectory)) throws {
            try verify()
            try AdministrativeSetupPublication.validateRetained(entry.1, file: entry.2, directory: entry.3, owner: owner, verify: verify)
        }
        try verify()
        let retained = try mode == .validateRetained || exists(.gatewayRuntimeCommit, shared)
        // A conflict in any role refuses before creating a sibling. A commit marker forbids creation as repair.
        for entry in files { if try retained || exists(entry.2, entry.3) { try validate(entry) } }
        var results: [Artifact: AdministrativeSetupPublicationResult] = [:]
        for entry in files.prefix(2) {
            try verify()
            if retained { try validate(entry); results[entry.0] = .retained }
            else {
                results[entry.0] = try AdministrativeSetupPublication.publish(entry.1, file: entry.2,
                    directory: entry.3, owner: owner, verify: verify)
            }
            try didPublish(entry.0); try verify()
        }
        let published = try GatewayRuntimePublication.publish(plan.extensions, directory: shared, owner: owner,
            mode: retained ? .validateRetained : .publishPending, verifyCurrent: verify,
            willCommit: { for entry in files.prefix(2) { try validate(entry) } }, didPublish: { artifact in
                let target: Artifact
                switch artifact { case .authority: target = .authority; case .transport: target = .transport; case .commit: target = .commit }
                try didPublish(target)
            })
        for (source, target): (GatewayRuntimePublication.Artifact, Artifact) in [(.authority, .authority), (.transport, .transport), (.commit, .commit)] {
            results[target] = published.files[source]
        }
        for entry in files { try validate(entry) }
        try verify(); return .init(files: results)
    }
}
