import Foundation

/// The immutable Transport base carries its control host, but no proof of a running optional backend.
struct TransportSettingsConsumerBootstrap: Sendable {
    let base: TransportPairingStartupConfiguration
    let host: GatewaySettingsConsumerHostConfiguration
    init(base: TransportPairingStartupConfiguration) throws {
        guard let host = base.settingsHost, host.role == .transport else { throw GatewayPreparationError.changedScope }
        try host.validate(transport: base.transport, pairing: base.control)
        self.base = base; self.host = host
    }
    static func decode(_ bytes: Data) throws -> Self { try .init(base: .decode(bytes)) }
    var configurationPath: String { get throws { try RuntimePreparationPaths(accountID: host.runtime.services.accountID).transportConfiguration } }
    func validatePath(_ path: String) throws {
        guard try path == configurationPath else { throw GatewayPreparationError.changedScope }
    }
}
