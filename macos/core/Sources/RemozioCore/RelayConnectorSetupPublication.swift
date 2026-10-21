import CryptoKit
import Darwin
import Foundation

extension RelayConnectorStartupPublication {
    /// The setup owner must hold its import lease and verify provider state before calling this native publication path.
    static func publishNative(context: RelayRunCredentialSetupContext, reference: RelayRunCredentialReference,
                              mode: RelayRunCredentialPublication.Mode,
                              verifyCurrent: () throws -> Void) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard context.reference == reference,
              let transport = context.runtime.services.claims.first(where: { $0.role == .transport }) else {
            throw RuntimePreparationError.missingMaterial
        }
        let paths = try RuntimePreparationPaths(accountID: context.account.accountID)
        let accounts = try NativeServiceAccountDirectory(accountID: context.account.accountID, ownerUID: context.account.ownerUID)
        let root = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.privateDirectory.dropFirst()),
            owner: 0, createIfMissing: false)
        defer { root.close() }
        let shared = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { shared.close() }
        func verify() throws {
            try verifyCurrent(); try root.validate(); try shared.validate()
            try accounts.validateGroup(transport); try accounts.validateUser(transport, ownerUID: context.account.ownerUID)
            let retained = try RuntimePreparationMaterial.decode(ProtectedServiceConfiguration.read(anchor: root.path,
                relativePath: AdministrativeSetupPublication.File.runtimeRecord.name, owner: 0))
            guard try retained.reference == context.runtime else { throw RuntimePreparationError.changedScope }
            let material = try RelayRunCredentialMaterial.decode(ProtectedServiceConfiguration.read(anchor: root.path,
                relativePath: AdministrativeSetupPublication.File.relayRunMaterial.name, owner: 0),
                expected: context.expected, plan: context.plan, created: context.created, runtime: context.runtime,
                account: context.account, inventory: context.inventory)
            guard try material.reference == reference else { throw RuntimePreparationError.conflictingMaterial }
            try verifyCurrent()
        }
        let tokenName = AdministrativeSetupPublication.File.transportTunnelToken(ownerUID: transport.number, groupID: transport.number).name
        return try publishPrepared(context: context, reference: reference, directory: shared, owner: 0, mode: mode,
            readBootstrap: { try ProtectedServiceConfiguration.readPublic(path: paths.transportConfiguration) },
            readToken: { try ProtectedServiceConfiguration.readServicePrivateAsRoot(path: paths.serviceDirectory + "/" + tokenName,
                serviceUID: transport.number) }, verifyCurrent: verify)
    }

    // Owned fixtures prove selection and file ordering. They do not prove Root or dedicated-account admission.
    static func publishPrepared(context: RelayRunCredentialSetupContext, reference: RelayRunCredentialReference,
                                directory: ProtectedSetupDirectory, owner: uid_t, mode: RelayRunCredentialPublication.Mode,
                                readBootstrap: () throws -> Data, readToken: () throws -> Data,
                                verifyCurrent: () throws -> Void,
                                didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        try verifyCurrent()
        guard context.reference == reference else { throw RuntimePreparationError.missingMaterial }
        let bytes = try readBootstrap(), token = try readToken()
        let bootstrap = try TransportSettingsConsumerBootstrap.decode(bytes)
        try bootstrap.host.validate(account: context.account, inventory: context.inventory)
        guard bootstrap.host.runtime == context.runtime, bootstrap.base.relayPort == context.plan.port,
              Data(SHA256.hash(data: token)) == reference.credentialDigest else { throw RuntimePreparationError.changedScope }
        _ = try CloudflareTunnelRunCredential.restore(token, tunnel: reference.tunnel)
        func verify() throws {
            try verifyCurrent(); try directory.validate()
            guard try readBootstrap() == bytes, try readToken() == token else { throw RuntimePreparationError.changedScope }
            try verifyCurrent()
        }
        try verify()
        return try publish(context: context, reference: reference, relayPort: context.plan.port, directory: directory,
            owner: owner, mode: mode, verifyCurrent: verify, didStage: didStage)
    }
}
