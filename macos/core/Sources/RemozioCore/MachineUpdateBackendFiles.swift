import Darwin
import Foundation

/// Fixed Root-owned readers. They open no provider credential, private key or service journal.
enum MachineUpdateBackendFiles {
    static func requireNative(accountID: Data, source: RuntimeReleaseBackendSource,
                              verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let services = source.pair.authority.material.runtime.services
        guard services.accountID == accountID else { throw RuntimePreparationError.changedScope }
        try verifyCurrent()
        let paths = try RuntimePreparationPaths(accountID: accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        try requireInLease(accountID: accountID, source: source, directory: directory, owner: 0,
            readFence: { try GatewayRuntimeSettingsFenceReader.load(macID: services.macID,
                accountID: accountID, verifyCurrent: verifyCurrent) }, verifyCurrent: verifyCurrent)
    }

    /// Owned files exercise the readers without granting native authority.
    static func requireInLease(accountID: Data, source: RuntimeReleaseBackendSource,
        directory: ProtectedSetupDirectory, owner: uid_t, readFence: () throws -> GatewayRuntimeSettingsFence?,
        verifyCurrent: () throws -> Void) throws {
        guard getuid() == owner, geteuid() == owner,
              source.pair.authority.material.runtime.services.accountID == accountID else { throw RuntimePreparationError.changedScope }
        func verify() throws {
            try verifyCurrent(); try directory.validate()
            if source.revision == nil {
                guard try ProtectedServiceConfiguration.readOptional(anchor: directory.path,
                    relativePath: AdministrativeSetupPublication.File.gatewaySettingsRevision.name, owner: owner) == nil else {
                    throw GatewayPreparationError.changedScope
                }
            }
            try directory.validate(); try verifyCurrent()
        }
        try source.requirePublished(read: { file in
            switch file {
            case .authorityGatewayRuntime, .transportGatewayRuntime, .gatewayConfiguration, .gatewayRuntimeCommit, .gatewaySettingsRevision: break
            default: throw RuntimePreparationError.changedScope
            }
            try verify()
            let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
                owner: owner, privateFile: file.mode == 0o600)
            try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory,
                owner: owner, verify: verify)
            return bytes
        }, readFence: readFence, verifyCurrent: verify)
        try verify()
    }
}
