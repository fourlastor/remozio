import Darwin
import Foundation

/// Exact initial public files only. Native admission and protected readers remain the caller's responsibility.
struct GatewaySettingsInitialPublication: Sendable {
    let configuration: GatewayServiceConfiguration
    let commit: GatewayRuntimeCommit
    private let host: GatewaySettingsConsumerHostConfiguration
    private let bytes: [String: Data]
    private static let files: [AdministrativeSetupPublication.File] = [
        .gatewayRuntimeCommit, .transportConfiguration, .transportGatewayRuntime, .gatewayJournalService, .gatewayConfiguration]

    private init(host: GatewaySettingsConsumerHostConfiguration, bytes: [String: Data]) throws {
        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            guard let value = bytes[file.name] else { throw GatewayPreparationError.incomplete }; return value
        }
        let commit = try GatewayRuntimeCommit.decode(read(.gatewayRuntimeCommit))
        guard commit.settingsSequence == nil else { throw GatewayPreparationError.changedScope }
        let transport = try TransportPairingStartupConfiguration.decode(read(.transportConfiguration))
        guard let transportHost = transport.settingsHost, transportHost.role == .transport,
              transportHost.runtime == host.runtime, transportHost.bundlePath == host.bundlePath,
              transportHost.codePolicy == host.codePolicy else { throw GatewayPreparationError.changedScope }
        try transportHost.validate(transport: transport.transport, pairing: transport.control)
        let role = try GatewayRuntimeExtension.decode(read(.transportGatewayRuntime))
        try commit.validate(role); try role.validate(transport: transport)
        let journal = try GatewayJournalSetupServiceConfiguration.decode(read(.gatewayJournalService))
        let configuration = try GatewayServiceConfiguration.decode(read(.gatewayConfiguration))
        guard role.target == .transport, role.material.runtime == host.runtime, role.codePolicy == host.codePolicy,
              journal.bundlePath == host.bundlePath, journal.codePolicy == host.codePolicy,
              journal.intent.id == commit.intentID, try journal.intent.digest == commit.intentDigest,
              journal.intent.material == role.material,
              journal.intent.configuration.canonicalBytes == configuration.canonicalBytes else {
            throw GatewayPreparationError.changedScope
        }
        self.host = host; self.bytes = bytes; self.configuration = configuration; self.commit = commit
    }
    /// Only an absent fence and an initial commit can select this path. No settings receipt can restore it.
    static func load(host: GatewaySettingsConsumerHostConfiguration,
                     readFence: () throws -> GatewayRuntimeSettingsFence?,
                     read: (AdministrativeSetupPublication.File) throws -> Data,
                     verifyCurrent: () throws -> Void) throws -> Self? {
        guard host.role == .gateway else { throw GatewayPreparationError.changedScope }
        try verifyCurrent()
        if try readFence() != nil { try verifyCurrent(); return nil }
        let marker: Data
        do { marker = try read(.gatewayRuntimeCommit) }
        catch JournalLeaseError.system(let code) where code == ENOENT { try verifyCurrent(); return nil }
        let commit = try GatewayRuntimeCommit.decode(marker)
        if commit.settingsSequence != nil { try verifyCurrent(); return nil }
        var bytes = [AdministrativeSetupPublication.File.gatewayRuntimeCommit.name: marker]
        for file in files.dropFirst() { bytes[file.name] = try read(file) }
        let result = try Self(host: host, bytes: bytes)
        try verifyCurrent()
        guard try readFence() == nil else { throw GatewayPreparationError.changedScope }
        for file in files {
            guard try read(file) == bytes[file.name] else { throw GatewayPreparationError.changedScope }
        }
        try verifyCurrent()
        guard try readFence() == nil, try read(.gatewayRuntimeCommit) == marker else { throw GatewayPreparationError.changedScope }
        try verifyCurrent(); return result
    }
    /// A published immutable host requires its control owner. Even a malformed host cannot enable legacy startup.
    static func requireLegacyStartup(readBootstrap: () throws -> Data) throws {
        do { _ = try readBootstrap() }
        catch JournalLeaseError.system(let code) where code == ENOENT { return }
        throw GatewayPreparationError.changedScope
    }
    /// Repeated exact reads detect a changed publication. They do not make the filesystem reads atomic.
    func verifyPublished(readFence: () throws -> GatewayRuntimeSettingsFence?,
                         read: (AdministrativeSetupPublication.File) throws -> Data,
                         verifyCurrent: () throws -> Void) throws {
        guard let current = try Self.load(host: host, readFence: readFence, read: read, verifyCurrent: verifyCurrent),
              current.bytes == bytes else { throw GatewayPreparationError.changedScope }
    }
}
