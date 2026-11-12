import Foundation

/// Per-account metadata only. A declaration grants no listener, native identity or floor authority.
enum MachineUpdateRetainedSetupHealthService {
    static func authority(accountID: Data) throws -> String {
        let value = try RuntimePreparationPaths(accountID: accountID).authorityService + ".retained-setup-health"
        guard GatewayWakeEndpointConfiguration.validServiceName(value) else { throw InstalledAuthorityCommandError.invalidConfiguration }
        return value
    }
}
