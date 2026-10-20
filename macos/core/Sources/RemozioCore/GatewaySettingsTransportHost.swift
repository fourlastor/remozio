import Foundation

/// Fixed protected readers. Only the authenticated owner can turn a selection into a process-local permit.
private struct TransportSettingsPublication: Sendable {
    let scope: GatewaySettingsConsumerNativeScope
    let bootstrap: TransportSettingsConsumerBootstrap
    private var host: GatewaySettingsConsumerHostConfiguration { bootstrap.host }
    private var paths: RuntimePreparationPaths { get throws { try .init(accountID: host.runtime.services.accountID) } }
    func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
        try ProtectedServiceConfiguration.readPublic(path: paths.serviceDirectory + "/" + file.name)
    }
    func marker() throws -> Data? {
        try ProtectedServiceConfiguration.readOptionalPublic(path: paths.serviceDirectory + "/" + AdministrativeSetupPublication.File.gatewayRuntimeCommit.name)
    }
    func fence() throws -> GatewayRuntimeSettingsFence? {
        try GatewayRuntimeSettingsFenceReader.load(macID: host.runtime.services.macID,
            accountID: host.runtime.services.accountID, verifyCurrent: scope.validate)
    }
    func selected(_ binding: GatewaySettingsConsumerBinding, _ fence: GatewayRuntimeSettingsFence) throws -> GatewaySettingsConsumerSelection {
        try scope.validate(); try fence.validate(services: host.runtime.services)
        guard try read(.transportConfiguration) == bootstrap.base.canonicalBytes else { throw GatewayPreparationError.changedScope }
        guard let loaded = try GatewayRuntimeLoader.load(target: .transport, read: read, verifyCurrent: scope.validate, validate: {
            try $0.validate(transport: bootstrap.base)
            guard $0.material.runtime == host.runtime, $0.codePolicy == host.codePolicy else { throw GatewayPreparationError.changedScope }
        }) else { throw GatewayPreparationError.incomplete }
        let selection = try GatewaySettingsConsumerSelection.transport(binding: binding, fence: fence,
            configuration: loaded.configuration, commit: loaded.commit)
        guard try read(.gatewayRuntimeCommit) == loaded.commit.encoded,
              try read(.transportGatewayRuntime) == selection.configuration else { throw GatewayPreparationError.changedScope }
        try scope.validate(); return selection
    }
    func verifyAccepted(_ selection: GatewaySettingsConsumerSelection) throws {
        try selection.verifyPublished(readFence: fence, readSelected: {
            let current = try selected(selection.binding, selection.fence); return (current.configuration, current.commit)
        }, verifyCurrent: scope.validate)
    }
    func initial(_ binding: GatewaySettingsConsumerBinding,
                 report: @escaping @Sendable (TransportWakeRunner.Status) -> Void) throws -> GatewaySettingsConsumerOwner.InitialRuntime? {
        let services = host.runtime.services
        guard binding.role == .transport, binding.macID == services.macID, binding.accountID == services.accountID else {
            throw GatewayPreparationError.changedScope
        }
        guard let initial = try TransportSettingsInitialPublication.load(bootstrap: bootstrap, readFence: fence,
            readCommit: marker, read: read, verifyCurrent: scope.validate) else { return nil }
        let verify: @Sendable () throws -> Void = {
            try initial.verifyPublished(readFence: fence, readCommit: marker, read: read, verifyCurrent: scope.validate)
        }
        return try .init(runtime: GatewaySettingsTransportRuntime(initial: initial, verifyCurrent: verify, report: report), verifyCurrent: verify)
    }
}

/// Starts settings control before direct routes. Optional wake work has a separate owner.
/// Fresh activation waits for Root restart recovery and update coordination.
public final class GatewaySettingsTransportHost: Sendable {
    private let host: TransportSettingsConsumerHost
    private init(host: TransportSettingsConsumerHost) { self.host = host }
    public static func open(path: String, reportDirect: @escaping @Sendable (DirectHostState) -> Void = { _ in },
                            reportRelay: @escaping @Sendable (ApprovalRelayCoordinator.Status) -> Void = { _ in },
                            reportWake: @escaping @Sendable (TransportWakeRunner.Status) -> Void = { _ in }) throws -> GatewaySettingsTransportHost {
        let (scope, release, bootstrap) = try GatewaySettingsConsumerNativeScope.openTransport(path: path)
        var controlActivity: (any OwnedReleaseActivity)?
        do {
            let configuration = bootstrap.host, services = configuration.runtime.services
            let publication = TransportSettingsPublication(scope: scope, bootstrap: bootstrap)
            let owner = try GatewaySettingsConsumerOwner(role: .transport, macID: services.macID, accountID: services.accountID,
                operations: .init(verifyScope: scope.validate, readFence: {
                    guard let fence = try publication.fence() else { throw GatewayPreparationError.incomplete }; return fence
                }, loadSelected: publication.selected,
                makeRuntime: { try GatewaySettingsTransportRuntime(selection: $0, permit: $1, report: reportWake) },
                verifyAccepted: publication.verifyAccepted, makeInitialRuntime: { try publication.initial($0, report: reportWake) }))
            let access = try GatewaySettingsConsumerAccess(owner: owner, services: services, verifyCurrent: scope.validate)
            let listener = try GatewaySettingsConsumerXPCListener(consumerCode: configuration.consumerCode, setupCode: configuration.setupCode,
                release: release, access: access, acquireActivity: scope.acquireActivity)
            let recovery = try GatewaySettingsConsumerXPCListener.recovery(services: services,
                codePolicy: configuration.codePolicy, release: release, access: access, acquireActivity: scope.acquireActivity)
            let activity = try scope.acquireActivity(); controlActivity = activity
            let control = try GatewaySettingsConsumerHost(owner: owner, listener: listener, activity: activity, recoveryListener: recovery)
            let host = try TransportSettingsConsumerHost(control: control, lifetime: scope, makeForeground: {
                try TransportSettingsForegroundRuntime(bootstrap: bootstrap, verifyCurrent: scope.validate,
                    report: reportDirect, reportRelay: reportRelay)
            })
            return .init(host: host)
        } catch { controlActivity?.close(); scope.close(); throw error }
    }
    public func start() async throws { try await host.start() }
    public func poll() async throws { try await host.poll() }
    public func close() async throws { try await host.close() }
}
