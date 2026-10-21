import Darwin
import Foundation

/// A protected public reference is optional. It does not prove that the connector or its approval path is ready.
struct RelayConnectorStartupReference: Equatable, Sendable {
    let reference: RelayRunCredentialReference
    private let bytes: Data
    private init(reference: RelayRunCredentialReference, bytes: Data) { self.reference = reference; self.bytes = bytes }

    static func loadNative(scope: GatewaySettingsConsumerNativeScope,
                           bootstrap: TransportSettingsConsumerBootstrap) throws -> Self? {
        guard scope.configuration == bootstrap.host else { throw RuntimePreparationError.changedScope }
        let path = try RuntimePreparationPaths(accountID: bootstrap.host.runtime.services.accountID).serviceDirectory
            + "/" + AdministrativeSetupPublication.File.transportRelayReference.name
        return try load(runtime: bootstrap.host.runtime, relayPort: bootstrap.base.relayPort,
            read: { try ProtectedServiceConfiguration.readOptionalPublic(path: path) }, verifyCurrent: { try scope.validate() })
    }
    func makeNativeSupervisor(scope: GatewaySettingsConsumerNativeScope, bootstrap: TransportSettingsConsumerBootstrap,
                              options: RelayConnectorSupervisor.Options = .standard) throws -> RelayConnectorSupervisor {
        try validateNative(scope: scope, bootstrap: bootstrap)
        return try RelayConnectorSupervisor.native(scope: scope, reference: reference, options: options,
            verifyCurrent: { try self.validateNative(scope: scope, bootstrap: bootstrap) })
    }
    private func validateNative(scope: GatewaySettingsConsumerNativeScope,
                                bootstrap: TransportSettingsConsumerBootstrap) throws {
        guard try Self.loadNative(scope: scope, bootstrap: bootstrap) == self else { throw RuntimePreparationError.changedScope }
    }
    // Same-owner fixtures check metadata and recovery, not Root publication or native service admission.
    static func load(runtime: RuntimeMaterialReference, relayPort: UInt16?, read: () throws -> Data?,
                     verifyCurrent: () throws -> Void) throws -> Self? {
        try verifyCurrent()
        guard let bytes = try read() else {
            try verifyCurrent()
            guard try read() == nil else { throw RuntimePreparationError.changedScope }
            try verifyCurrent(); return nil
        }
        guard let relayPort else { throw RuntimePreparationError.changedScope }
        let reference = try RelayRunCredentialReference.decodeForTransport(bytes, runtime: runtime, relayPort: relayPort)
        try verifyCurrent()
        guard try read() == bytes else { throw RuntimePreparationError.changedScope }
        try verifyCurrent(); return .init(reference: reference, bytes: bytes)
    }
}

/// Publishes metadata only. The setup owner must retain its import lease and verify provider state before activation.
/// Native callers must also validate the published Transport base and the dedicated account's selected token.
enum RelayConnectorStartupPublication {
    static func publish(context: RelayRunCredentialSetupContext, reference: RelayRunCredentialReference,
                        relayPort: UInt16, directory: ProtectedSetupDirectory, owner: uid_t,
                        mode: RelayRunCredentialPublication.Mode,
                        verifyCurrent: () throws -> Void,
                        didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        try verifyCurrent()
        let bytes = try reference.encoded
        guard context.reference == nil || context.reference == reference else { throw RuntimePreparationError.conflictingMaterial }
        if mode == .validateRetained {
            guard context.reference == reference else { throw RuntimePreparationError.missingMaterial }
        }
        guard try RelayRunCredentialReference.decode(bytes, expected: context.expected, plan: context.plan,
            created: context.created, runtime: context.runtime, account: context.account, inventory: context.inventory) == reference,
              relayPort == context.plan.port,
              try RelayRunCredentialReference.decodeForTransport(bytes, runtime: context.runtime, relayPort: relayPort) == reference else {
            throw RuntimePreparationError.changedScope
        }
        if mode == .prepareUnactivated {
            guard [.runtimePublished, .gatewayPrepared].contains(context.expected.phase) else { throw RuntimePreparationError.incomplete }
        }
        let file = AdministrativeSetupPublication.File.transportRelayReference
        func verify() throws { try verifyCurrent(); try directory.validate() }
        try verify()
        if mode == .prepareUnactivated {
            return try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: owner,
                verify: verify, didStage: didStage)
        }
        try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
        try verify(); return .retained
    }
}
