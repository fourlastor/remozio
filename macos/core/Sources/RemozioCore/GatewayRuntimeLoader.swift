import CryptoKit
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

    private static func validateSettings(_ revision: GatewayRuntimeSettingsRevision,
                                         gateway: GatewayServiceConfiguration, role: GatewayRuntimeExtension) throws {
        let material = role.material, services = material.runtime.services, selection = revision.selection
        let paths = try RuntimePreparationPaths(accountID: services.accountID)
        guard revision.accountID == services.accountID, gateway.registration == material.runtime.gateway,
              gateway.receiptPublicKey == material.phonePush.gatewayReceiptPublicKey,
              gateway.project == material.phonePush.projectID, gateway.packageName == material.phonePush.packageName,
              gateway.ownerUID == services.ownerUID, gateway.serviceName == paths.gatewayService,
              gateway.directoryPath == paths.gatewayDirectory, gateway.providerPath == paths.gatewayProvider,
              gateway.receiptKeyPath == paths.gatewayReceiptKey,
              gateway.serviceUID == services.claims.first(where: { $0.role == .gateway })?.number,
              let endpoint = gateway.wakeEndpoint,
              endpoint.transportUID == services.claims.first(where: { $0.role == .transport })?.number,
              endpoint.serviceName == paths.gatewayWakeService,
              endpoint.maximumConnections == selection.maximumWakeConnections,
              endpoint.maximumOperations == selection.maximumWakeOperations,
              endpoint.challengeLifetimeMillis == selection.wakeChallengeLifetimeMilliseconds,
              try gateway.settings.setupBytes == selection.service.setupBytes,
              let root = role.codePolicy.entries.first(where: { $0.role == .authority && $0.active }),
              let transport = role.codePolicy.entries.first(where: { $0.role == .transport && $0.active }) else {
            throw GatewayPreparationError.changedScope
        }
        let rootPolicy = try XPCPeerPolicy(teamID: root.teamID, componentIdentifier: root.identifier,
            approvedCodeDirectoryHashes: [root.codeDirectoryHash], expectedUserID: 0)
        let transportPolicy = try XPCPeerPolicy(teamID: transport.teamID, componentIdentifier: transport.identifier,
            approvedCodeDirectoryHashes: [transport.codeDirectoryHash], expectedUserID: endpoint.transportUID)
        guard gateway.authorityPolicy.expectedUserID == 0, gateway.authorityPolicy.requirement == rootPolicy.requirement,
              endpoint.policy.expectedUserID == transportPolicy.expectedUserID,
              endpoint.policy.requirement == transportPolicy.requirement else { throw GatewayPreparationError.changedScope }
        if role.target == .transport {
            guard let wake = role.wake, wake.pollMilliseconds == selection.activation.wakePollMilliseconds,
                  wake.wake.timeoutMilliseconds == selection.activation.wakeTimeoutMilliseconds,
                  Data(SHA256.hash(data: wake.canonicalBytes)) == revision.transportWakeDigest else { throw GatewayPreparationError.changedScope }
        }
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
        if commit.settingsSequence != nil {
            let revision = try GatewayRuntimeSettingsRevision.decode(read(.gatewaySettingsRevision))
            let gateway = try GatewayServiceConfiguration.decode(read(.gatewayConfiguration))
            try commit.validate(settings: revision, gateway: gateway)
            try validateSettings(revision, gateway: gateway, role: role)
        }
        guard try read(.gatewayRuntimeCommit) == marker else { throw GatewayPreparationError.changedScope }
        try verifyCurrent(); return .init(configuration: role, commit: commit)
    }
}
