import Darwin
import Foundation

/// Publishes retained completion bytes at fixed paths. The caller supplies current machine, paired policy and native identity checks.
enum MachineUpdateCompletionPublicationFiles {
    typealias Plan = MachineUpdateCompletionPublicationPlan
    typealias Record = MachineUpdateCompletionPublicationRecord

    static func requireNative(_ plan: Plan, publication: Record, verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try publication.requirePlan(plan)
        try verifyCurrent()
        for entry in plan.entries {
            try withNativeDirectory(entry) { directory in
                try requireEntry(entry, publication: publication, directory: directory, owner: 0, verifyCurrent: verifyCurrent)
            }
        }
        try verifyCurrent()
    }

    /// The owner retains every directory. This check neither opens a writer nor changes the publication record.
    static func requireInLeases(_ plan: Plan, publication: Record, owner: uid_t,
        directory: (Plan.Entry) throws -> ProtectedSetupDirectory, verifyCurrent: () throws -> Void) throws {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try publication.requirePlan(plan)
        try verifyCurrent()
        for entry in plan.entries {
            try requireEntry(entry, publication: publication, directory: directory(entry), owner: owner, verifyCurrent: verifyCurrent)
        }
        try verifyCurrent()
    }

    static func publishNative(_ plan: Plan, publication: Record, accountID: Data, file: Plan.File,
        verifyCurrent: () throws -> Void, didStage: (AdministrativeSetupPublication.Stage) throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let entry = try selected(plan, publication: publication, accountID: accountID, file: file)
        try verifyCurrent()
        try withNativeDirectory(entry) { directory in
            try publishInLease(plan, publication: publication, accountID: accountID, file: file,
                directory: directory, owner: 0, verifyCurrent: verifyCurrent, didStage: didStage)
        }
    }

    /// Only an acknowledged writing marker permits this exchange. The caller must retain the current protected storage scope.
    static func publishInLease(_ plan: Plan, publication: Record, accountID: Data, file: Plan.File,
        directory: ProtectedSetupDirectory, owner: uid_t, verifyCurrent: () throws -> Void,
        didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        let entry = try selected(plan, publication: publication, accountID: accountID, file: file)
        func verify() throws { try verifyCurrent(); try directory.validate() }
        try requireEntry(entry, publication: publication, directory: directory, owner: owner, verifyCurrent: verify)
        let stage: (AdministrativeSetupPublication.Stage) throws -> Void = { value in
            try verify(); try didStage(value); try verify()
        }
        try AdministrativeSetupPublication.replaceMachineUpdateCompletion(entry, publicationID: publication.id,
            directory: directory, owner: owner, verify: verify, didStage: stage)
        try AdministrativeSetupPublication.validateRetained(entry.completion, file: entry.artifact,
            directory: directory, owner: owner, verify: verify)
        try verify()
    }

    private static func selected(_ plan: Plan, publication: Record, accountID: Data, file: Plan.File) throws -> Plan.Entry {
        try publication.requirePlan(plan)
        guard publication.inventoryState == .pending,
              try publication.state(accountID: accountID, file: file) == .writing,
              let entry = plan.entries.first(where: { $0.accountID == accountID && $0.file == file }) else {
            throw PreparationStoreError.invalidTransition
        }
        return entry
    }

    private static func requireEntry(_ entry: Plan.Entry, publication: Record, directory: ProtectedSetupDirectory,
        owner: uid_t, verifyCurrent: () throws -> Void) throws {
        try verifyCurrent(); try directory.validate()
        let actual = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: entry.artifact.name,
            owner: owner, privateFile: entry.artifact.mode == 0o600)
        try AdministrativeSetupPublication.validateRetained(actual, file: entry.artifact, directory: directory,
            owner: owner, verify: verifyCurrent)
        let state: MachineUpdatePublicationProgress.State
        switch try publication.state(accountID: entry.accountID, file: entry.file) {
        case .pending: state = .pending
        case .writing: state = .writing
        case .published: state = .published
        }
        try entry.requireActual(actual, state: state)
        try directory.validate(); try verifyCurrent()
    }

    /// Requires the original backend revision and an absent settings fence while completion files can contain either bound version.
    static func requireBackendMetadataNative(_ restart: MachineUpdateRestartSnapshot,
        verifyCurrent: () throws -> Void) throws {
        try requireBackendMetadataNative(backend: restart.backend, configuration: restart.configuration, verifyCurrent: verifyCurrent)
    }

    static func requireBackendMetadataNative(backend: MachineUpdateBackendEpoch.Archive,
        configuration: MachineUpdateConfigurationEpoch.Archive, verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try backend.validate(epoch: configuration)
        for account in backend.record.accounts ?? [] where account.sourceDigest != nil {
            try verifyCurrent()
            let paths = try RuntimePreparationPaths(accountID: account.accountID)
            let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
                owner: 0, visibility: .sharedMetadata, createIfMissing: false)
            defer { directory.close() }
            try requireBackendMetadataInLease(backend: backend, configuration: configuration, accountID: account.accountID, directory: directory, owner: 0,
                readFence: { try GatewayRuntimeSettingsFenceReader.load(macID: backend.record.macID,
                    accountID: account.accountID, verifyCurrent: verifyCurrent) }, verifyCurrent: verifyCurrent)
        }
        try verifyCurrent()
    }

    static func requireBackendMetadataInLease(_ restart: MachineUpdateRestartSnapshot, accountID: Data,
        directory: ProtectedSetupDirectory, owner: uid_t, readFence: () throws -> GatewayRuntimeSettingsFence?,
        verifyCurrent: () throws -> Void) throws {
        try requireBackendMetadataInLease(backend: restart.backend, configuration: restart.configuration,
            accountID: accountID, directory: directory, owner: owner, readFence: readFence, verifyCurrent: verifyCurrent)
    }

    /// Owned controls use the same revision and fence checks. The caller retains this directory.
    static func requireBackendMetadataInLease(backend: MachineUpdateBackendEpoch.Archive,
        configuration: MachineUpdateConfigurationEpoch.Archive, accountID: Data, directory: ProtectedSetupDirectory, owner: uid_t, readFence: () throws -> GatewayRuntimeSettingsFence?,
        verifyCurrent: () throws -> Void) throws {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try backend.validate(epoch: configuration)
        guard let source = try backend.capture(accountID: accountID)?.source else { throw PreparationStoreError.notFound }
        let file = AdministrativeSetupPublication.File.gatewaySettingsRevision
        func verify() throws { try verifyCurrent(); try directory.validate() }
        for _ in 0..<2 {
            try verify()
            guard try readFence() == nil else { throw GatewayPreparationError.changedScope }
            if let revision = source.revision {
                let actual = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
                    owner: owner, privateFile: false)
                try AdministrativeSetupPublication.validateRetained(actual, file: file, directory: directory,
                    owner: owner, verify: verify)
                guard try actual == revision.encoded else { throw GatewayPreparationError.changedScope }
            } else {
                guard try ProtectedServiceConfiguration.readOptional(anchor: directory.path, relativePath: file.name,
                    owner: owner) == nil else { throw GatewayPreparationError.changedScope }
            }
            guard try readFence() == nil else { throw GatewayPreparationError.changedScope }
            try verify()
        }
    }

    private static func withNativeDirectory<Value>(_ entry: Plan.Entry,
        _ body: (ProtectedSetupDirectory) throws -> Value) throws -> Value {
        let paths = try RuntimePreparationPaths(accountID: entry.accountID)
        let path: String, visibility: ProtectedSetupDirectory.Visibility
        switch entry.file {
        case .authorityJob: path = InstalledAccountJobManifest.directory; visibility = .sharedMetadata
        case .host: path = paths.privateDirectory; visibility = .privateState
        case .presence, .pairing, .frontend: path = RuntimePreparationPaths.sharedDirectory; visibility = .sharedMetadata
        default: path = paths.serviceDirectory; visibility = .sharedMetadata
        }
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(path.dropFirst()), owner: 0,
            visibility: visibility, createIfMissing: false)
        defer { directory.close() }
        return try body(directory)
    }
}
