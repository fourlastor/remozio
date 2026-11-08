import Darwin
import Foundation

/// Fixed backend paths only. It opens no credential, private key, journal writer or service manager.
enum MachineUpdateBackendPublicationFiles {
    static func publishNative(_ archive: MachineUpdateBackendEpoch.Archive, configuration: MachineUpdateConfigurationEpoch.Archive,
        accountID: Data, file: MachineUpdateBackendPublicationProgress.File, verify: () throws -> Void,
        didStage: (AdministrativeSetupPublication.Stage) throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        try publishInLease(archive, configuration: configuration, accountID: accountID, file: file,
            directory: directory, owner: 0, verify: verify, didStage: didStage)
    }
    static func publishInLease(_ archive: MachineUpdateBackendEpoch.Archive, configuration: MachineUpdateConfigurationEpoch.Archive,
        accountID: Data, file: MachineUpdateBackendPublicationProgress.File, directory: ProtectedSetupDirectory,
        owner: uid_t, verify: () throws -> Void,
        didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws {
        try archive.validate(epoch: configuration)
        guard let progress = archive.record.publication,
              try progress.state(accountID: accountID, file: file) == .writing,
              let capture = try archive.capture(accountID: accountID) else { throw PreparationStoreError.invalidTransition }
        try AdministrativeSetupPublication.replaceMachineUpdateBackend(capture.bytes(file, target: true),
            expected: capture.bytes(file, target: false), file: file.artifact, directory: directory,
            owner: owner, verify: verify, didStage: didStage)
    }
    static func requireNative(_ archive: MachineUpdateBackendEpoch.Archive, configuration: MachineUpdateConfigurationEpoch.Archive,
        accountID: Data, verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent()
        let paths = try RuntimePreparationPaths(accountID: accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        try requireInLease(archive, configuration: configuration, accountID: accountID, directory: directory, owner: 0,
            readFence: { try GatewayRuntimeSettingsFenceReader.load(macID: archive.record.macID,
                accountID: accountID, verifyCurrent: verifyCurrent) }, verifyCurrent: verifyCurrent)
    }
    /// Owned files exercise the same progress checks. The native entry separately requires Root and fixed placement.
    static func requireInLease(_ archive: MachineUpdateBackendEpoch.Archive, configuration: MachineUpdateConfigurationEpoch.Archive,
        accountID: Data, directory: ProtectedSetupDirectory, owner: uid_t,
        readFence: () throws -> GatewayRuntimeSettingsFence?, verifyCurrent: () throws -> Void) throws {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try archive.validate(epoch: configuration)
        guard let capture = try archive.capture(accountID: accountID), let source = capture.source else { throw PreparationStoreError.notFound }
        func verify() throws { try verifyCurrent(); try directory.validate() }
        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            try verify()
            let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
                owner: owner, privateFile: file.mode == 0o600)
            try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
            return bytes
        }
        for _ in 0..<2 {
            try verify(); guard try readFence() == nil else { throw GatewayPreparationError.changedScope }
            for file in MachineUpdateBackendPublicationProgress.File.allCases {
                try capture.requireActual(read(file.artifact), file: file, progress: archive.record.publication)
            }
            if let revision = source.revision {
                guard try read(.gatewaySettingsRevision) == revision.encoded else { throw GatewayPreparationError.changedScope }
            } else {
                guard try ProtectedServiceConfiguration.readOptional(anchor: directory.path,
                    relativePath: AdministrativeSetupPublication.File.gatewaySettingsRevision.name, owner: owner) == nil else {
                    throw GatewayPreparationError.changedScope
                }
            }
            guard try readFence() == nil else { throw GatewayPreparationError.changedScope }; try verify()
        }
    }
}
