import Darwin
import Foundation

/// Reads optional protected metadata. A returned value permits a later capability installation, not a Ready claim.
enum GatewayRuntimeLoader {
    struct Loaded: Sendable {
        let configuration: GatewayRuntimeExtension
        let commit: GatewayRuntimeCommit
    }
    static func load(authority base: InstalledAuthorityCommandConfiguration, verifyCurrent: () throws -> Void) throws -> Loaded? {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let paths = try RuntimePreparationPaths(accountID: base.command.accountID)
        return try load(target: .authority, read: { file in
            let path = paths.serviceDirectory + "/" + file.name
            switch file {
            case .authorityGatewayRuntime: return try ProtectedServiceConfiguration.read(path: path)
            default: return try ProtectedServiceConfiguration.readPublic(path: path)
            }
        }, verifyCurrent: verifyCurrent, validate: { try $0.validate(authority: base) })
    }
    static func load(transport base: TransportPairingStartupConfiguration, verifyCurrent: () throws -> Void) throws -> Loaded? {
        guard getuid() == base.transport.serviceUID, geteuid() == base.transport.serviceUID else {
            throw ApprovalTransportStartupError.wrongAccount
        }
        let paths = try RuntimePreparationPaths(accountID: base.transport.accountID)
        return try load(target: .transport, read: { file in
            try ProtectedServiceConfiguration.readPublic(path: paths.serviceDirectory + "/" + file.name)
        }, verifyCurrent: verifyCurrent, validate: { try $0.validate(transport: base) })
    }

    // The only optional absence is the final marker. An incomplete or malformed committed role is an error.
    static func load(target: GatewayRuntimeExtension.Target, read: (AdministrativeSetupPublication.File) throws -> Data,
                     verifyCurrent: () throws -> Void, validate: (GatewayRuntimeExtension) throws -> Void) throws -> Loaded? {
        try verifyCurrent()
        let marker: Data
        do { marker = try read(.gatewayRuntimeCommit) }
        catch JournalLeaseError.system(let code) where code == ENOENT { try verifyCurrent(); return nil }
        let commit = try GatewayRuntimeCommit.decode(marker)
        let role = try GatewayRuntimeExtension.decode(read(target == .authority ? .authorityGatewayRuntime : .transportGatewayRuntime))
        guard role.target == target else { throw GatewayPreparationError.changedScope }
        try commit.validate(role); try validate(role); try verifyCurrent()
        guard try read(.gatewayRuntimeCommit) == marker else { throw GatewayPreparationError.changedScope }
        try verifyCurrent(); return .init(configuration: role, commit: commit)
    }
}
