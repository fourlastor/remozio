import Foundation

/// Protected readers for one immutable native host. They grant no permit on their own.
private struct GatewaySettingsGatewayPublication: Sendable {
    let scope: GatewaySettingsConsumerNativeScope
    private var host: GatewaySettingsConsumerHostConfiguration { scope.configuration }
    func fence() throws -> GatewayRuntimeSettingsFence? {
        try GatewayRuntimeSettingsFenceReader.load(macID: host.runtime.services.macID,
            accountID: host.runtime.services.accountID, verifyCurrent: scope.validate)
    }
    func selected(_ binding: GatewaySettingsConsumerBinding, _ fence: GatewayRuntimeSettingsFence) throws -> GatewaySettingsConsumerSelection {
        try scope.validate(); try fence.validate(services: host.runtime.services)
        let paths = try RuntimePreparationPaths(accountID: host.runtime.services.accountID)
        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            try ProtectedServiceConfiguration.readPublic(path: paths.serviceDirectory + "/" + file.name)
        }
        let base = try TransportPairingStartupConfiguration.decode(read(.transportConfiguration))
        guard let transportHost = base.settingsHost, transportHost.role == .transport,
              transportHost.runtime == host.runtime, transportHost.bundlePath == host.bundlePath,
              transportHost.codePolicy == host.codePolicy else { throw GatewayPreparationError.changedScope }
        try transportHost.validate(transport: base.transport, pairing: base.control)
        let configuration = try read(.gatewayConfiguration)
        guard let loaded = try GatewayRuntimeLoader.load(target: .transport, read: read, verifyCurrent: scope.validate, validate: {
            try $0.validate(transport: base)
            guard $0.material.runtime == host.runtime, $0.codePolicy == host.codePolicy else { throw GatewayPreparationError.changedScope }
        }) else { throw GatewayPreparationError.incomplete }
        let selection = try GatewaySettingsConsumerSelection.gateway(binding: binding, fence: fence,
            configuration: .decode(configuration), commit: loaded.commit)
        guard try read(.gatewayConfiguration) == configuration,
              try read(.gatewayRuntimeCommit) == loaded.commit.encoded else { throw GatewayPreparationError.changedScope }
        try scope.validate(); return selection
    }
    func initial(_ binding: GatewaySettingsConsumerBinding) throws -> GatewaySettingsConsumerOwner.InitialRuntime? {
        let services = host.runtime.services
        guard binding.role == .gateway, binding.macID == services.macID, binding.accountID == services.accountID else {
            throw GatewayPreparationError.changedScope
        }
        let paths = try RuntimePreparationPaths(accountID: services.accountID)
        let read: @Sendable (AdministrativeSetupPublication.File) throws -> Data = { file in
            try ProtectedServiceConfiguration.readPublic(path: paths.serviceDirectory + "/" + file.name)
        }
        guard let initial = try GatewaySettingsInitialPublication.load(host: host, readFence: fence,
            read: read, verifyCurrent: scope.validate) else { return nil }
        let verify: @Sendable () throws -> Void = {
            try initial.verifyPublished(readFence: fence, read: read, verifyCurrent: scope.validate)
        }
        return .init(runtime: GatewaySettingsGatewayRuntime(initial: initial, verifyCurrent: verify), verifyCurrent: verify)
    }
    func verifyAccepted(_ selection: GatewaySettingsConsumerSelection) throws {
        try selection.verifyPublished(readFence: fence, readSelected: {
            let current = try selected(selection.binding, selection.fence)
            return (current.configuration, current.commit)
        }, verifyCurrent: scope.validate)
    }
}

/// A distinct immutable bootstrap entry. Opening it never reads provider credentials or opens SQLite.
/// Fresh activation remains disabled until Transport, restart recovery, and Root update coordination also participate.
public final class GatewaySettingsGatewayHost: Sendable {
    private let host: GatewaySettingsConsumerHost
    private init(host: GatewaySettingsConsumerHost) { self.host = host }
    public static func open(path: String) throws -> GatewaySettingsGatewayHost {
        let (scope, release) = try GatewaySettingsConsumerNativeScope.openGateway(path: path)
        do {
            let configuration = scope.configuration, services = configuration.runtime.services
            let publication = GatewaySettingsGatewayPublication(scope: scope)
            let owner = try GatewaySettingsConsumerOwner(role: .gateway, macID: services.macID, accountID: services.accountID,
                operations: .init(verifyScope: scope.validate, readFence: {
                    guard let fence = try publication.fence() else { throw GatewayPreparationError.incomplete }; return fence
                }, loadSelected: publication.selected, makeRuntime: { try GatewaySettingsGatewayRuntime(selection: $0, permit: $1) },
                    verifyAccepted: publication.verifyAccepted, makeInitialRuntime: publication.initial))
            let access = try GatewaySettingsConsumerAccess(owner: owner, services: services, verifyCurrent: scope.validate)
            let listener = try GatewaySettingsConsumerXPCListener(consumerCode: configuration.consumerCode,
                setupCode: configuration.setupCode, release: release, access: access, acquireActivity: scope.acquireActivity)
            let recovery = try GatewaySettingsConsumerXPCListener.recovery(services: services,
                codePolicy: configuration.codePolicy, release: release, access: access, acquireActivity: scope.acquireActivity)
            return try .init(host: .init(owner: owner, listener: listener, activity: scope, recoveryListener: recovery))
        } catch { scope.close(); throw error }
    }
    public func start() async throws { try await host.start() }
    public func poll() async throws { try await host.poll() }
    public func close() async throws { try await host.close() }
}
