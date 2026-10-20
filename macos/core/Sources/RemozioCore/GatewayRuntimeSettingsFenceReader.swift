import Foundation

/// Reads a Root-owned pause record. Only verified leaf absence permits the ordinary optional runtime.
/// A recognized pending record grants no permission to start or resume a provider.
enum GatewayRuntimeSettingsFenceReader {
    static func load(macID: Data, accountID: Data, verifyCurrent: () throws -> Void) throws -> GatewayRuntimeSettingsFence? {
        let paths = try RuntimePreparationPaths(accountID: accountID)
        return try load(macID: macID, accountID: accountID, read: {
            try ProtectedServiceConfiguration.readOptionalPublic(path: paths.serviceDirectory + "/" + AdministrativeSetupPublication.File.gatewaySettingsFence.name)
        }, verifyCurrent: verifyCurrent)
    }
    static func load(macID: Data, accountID: Data, read: () throws -> Data?,
                     verifyCurrent: () throws -> Void) throws -> GatewayRuntimeSettingsFence? {
        guard macID.count == 16, accountID.count == 16 else { throw GatewayPreparationError.invalidRecord }
        try verifyCurrent()
        let bytes = try read()
        let fence = try bytes.map(GatewayRuntimeSettingsFence.decode)
        if let fence {
            guard fence.macID == macID, fence.accountID == accountID else { throw GatewayPreparationError.changedScope }
        }
        try verifyCurrent()
        guard try read() == bytes else { throw GatewayPreparationError.changedScope }
        try verifyCurrent(); return fence
    }
    static func requireAbsent(macID: Data, accountID: Data, verifyCurrent: () throws -> Void) throws {
        guard try load(macID: macID, accountID: accountID, verifyCurrent: verifyCurrent) == nil else {
            throw GatewayPreparationError.incomplete
        }
    }
}
