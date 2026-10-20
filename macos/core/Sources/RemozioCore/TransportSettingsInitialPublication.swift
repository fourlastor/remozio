import Foundation

/// An initial Transport commit binds the exact wake role. This snapshot grants no settings acceptance.
struct TransportSettingsInitialPublication: Sendable {
    let configuration: GatewayRuntimeExtension
    let commit: GatewayRuntimeCommit
    private let bootstrap: TransportSettingsConsumerBootstrap
    private let bytes: [String: Data]
    private static let files: [AdministrativeSetupPublication.File] = [.gatewayRuntimeCommit, .transportConfiguration, .transportGatewayRuntime]
    private init(bootstrap: TransportSettingsConsumerBootstrap, bytes: [String: Data]) throws {
        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            guard let value = bytes[file.name] else { throw GatewayPreparationError.incomplete }; return value
        }
        let commit = try GatewayRuntimeCommit.decode(read(.gatewayRuntimeCommit))
        let configuration = try GatewayRuntimeExtension.decode(read(.transportGatewayRuntime))
        let host = bootstrap.host
        guard commit.settingsSequence == nil, configuration.target == .transport,
              configuration.material.runtime == host.runtime, configuration.codePolicy == host.codePolicy,
              try read(.transportConfiguration) == bootstrap.base.canonicalBytes else { throw GatewayPreparationError.changedScope }
        try commit.validate(configuration); try configuration.validate(transport: bootstrap.base)
        self.configuration = configuration; self.commit = commit; self.bootstrap = bootstrap; self.bytes = bytes
    }
    /// Only a verified missing marker leaf is optional. A settings commit always needs fresh Root coordination.
    static func load(bootstrap: TransportSettingsConsumerBootstrap, readFence: () throws -> GatewayRuntimeSettingsFence?,
                     readCommit: () throws -> Data?, read: (AdministrativeSetupPublication.File) throws -> Data,
                     verifyCurrent: () throws -> Void) throws -> Self? {
        try verifyCurrent()
        if try readFence() != nil { try verifyCurrent(); return nil }
        guard let marker = try readCommit() else { try verifyCurrent(); return nil }
        let commit = try GatewayRuntimeCommit.decode(marker)
        if commit.settingsSequence != nil { try verifyCurrent(); return nil }
        var bytes = [AdministrativeSetupPublication.File.gatewayRuntimeCommit.name: marker]
        for file in files.dropFirst() { bytes[file.name] = try read(file) }
        let result = try Self(bootstrap: bootstrap, bytes: bytes)
        try verifyCurrent()
        guard try readFence() == nil else { throw GatewayPreparationError.changedScope }
        for file in files { guard try read(file) == bytes[file.name] else { throw GatewayPreparationError.changedScope } }
        try verifyCurrent()
        guard try readFence() == nil, try readCommit() == marker else { throw GatewayPreparationError.changedScope }
        try verifyCurrent(); return result
    }
    func verifyPublished(readFence: () throws -> GatewayRuntimeSettingsFence?, readCommit: () throws -> Data?,
                         read: (AdministrativeSetupPublication.File) throws -> Data, verifyCurrent: () throws -> Void) throws {
        guard let current = try Self.load(bootstrap: bootstrap, readFence: readFence, readCommit: readCommit,
            read: read, verifyCurrent: verifyCurrent), current.bytes == bytes else { throw GatewayPreparationError.changedScope }
    }
}
