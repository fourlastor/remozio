import Darwin
import Foundation

/// The authorized owner holds the machine/release scope and verifies native quiescence before every file change.
enum GatewayRuntimeSettingsPublication {
    struct Result { let files: [String: GatewayRuntimeSettingsFileResult] }
    static func prepare(_ plan: GatewayRuntimeSettingsPublicationPlan, account: AccountPreparationIntent,
                        initialization: AuthorityInitializationIntent, journal: GatewayJournalPreparationState,
                        foreground: RuntimeActivationPlan, inventory: InstallationInventory,
                        verifyCurrent: () throws -> Void, requireQuiesced: () throws -> Void) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        _ = try plan.revision.proposal(activation: plan.activation, journal: journal, foreground: foreground, inventory: inventory)
        func verify() throws {
            try verifyCurrent(); try requireQuiesced()
            try RuntimeActivationFiles.validate(plan: foreground, account: account, initialization: initialization,
                inventory: inventory, verifyCurrent: verifyCurrent)
            _ = try GatewayPrivateArtifactPublication.publish(account: account, expected: plan.pair.authority.material,
                mode: .validateRetained, verifyCurrent: verifyCurrent)
            try verifyCurrent(); try requireQuiesced()
        }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: plan.revision.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        let jobs = try ProtectedSetupDirectory(anchor: "/", relativePath: String(InstalledAccountJobManifest.directory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { jobs.close() }
        func verifyFixed() throws {
            try verify()
            try AdministrativeSetupPublication.validateRetained(plan.activation.gatewayJob.bytes,
                file: .accountJob(accountID: plan.revision.accountID, role: .notificationGateway), directory: jobs, owner: 0, verify: verify)
        }
        return try publish(plan, directory: directory, owner: 0, verifyCurrent: verifyFixed, requireQuiesced: requireQuiesced)
    }
    // Owned fixtures exercise real atomic publication without asserting Root or native consumer admission.
    static func publish(_ plan: GatewayRuntimeSettingsPublicationPlan, directory: ProtectedSetupDirectory, owner: uid_t,
                        verifyCurrent: () throws -> Void, requireQuiesced: () throws -> Void,
                        didPublish: (AdministrativeSetupPublication.File) throws -> Void = { _ in }) throws -> Result {
        func verify() throws { try verifyCurrent(); try requireQuiesced(); try directory.validate() }
        func read(_ artifact: GatewayRuntimeSettingsPublicationPlan.Artifact) throws -> Data? {
            do {
                return try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: artifact.file.name,
                    owner: owner, privateFile: artifact.file.mode == 0o600)
            } catch JournalLeaseError.system(let code) where code == ENOENT {
                guard artifact.previous == nil else { throw JournalLeaseError.system(code) }; return nil
            }
        }
        func validate(_ artifact: GatewayRuntimeSettingsPublicationPlan.Artifact, selectedOnly: Bool) throws {
            try verify(); let bytes = try read(artifact)
            guard bytes == artifact.selected || (!selectedOnly && bytes == artifact.previous) else {
                throw AdministrativeSetupPublicationError.conflictingConfiguration
            }
        }
        try verify()
        let marker = try read(plan.artifacts.last!)
        let selectedMarker = marker == plan.artifacts.last!.selected
        for artifact in plan.artifacts { try validate(artifact, selectedOnly: selectedMarker) }
        var results: [String: GatewayRuntimeSettingsFileResult] = [:]
        for (index, artifact) in plan.artifacts.enumerated() {
            try verify()
            if index == plan.artifacts.count - 1 {
                for sibling in plan.artifacts.dropLast() { try validate(sibling, selectedOnly: true) }
            }
            if selectedMarker {
                try AdministrativeSetupPublication.validateRetained(artifact.selected, file: artifact.file,
                    directory: directory, owner: owner, verify: verify)
                results[artifact.file.name] = .retained
            } else {
                results[artifact.file.name] = try AdministrativeSetupPublication.replaceSettings(artifact.selected,
                    expected: artifact.previous, file: artifact.file, directory: directory, owner: owner, verify: verify)
            }
            try didPublish(artifact.file); try verify()
        }
        for artifact in plan.artifacts { try validate(artifact, selectedOnly: true) }
        return .init(files: results)
    }
}
