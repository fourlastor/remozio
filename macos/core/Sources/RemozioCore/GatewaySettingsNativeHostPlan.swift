import Foundation

/// Immutable host and job selection. Construction and decoding grant no native execution authority.
struct GatewaySettingsNativeHostPlan: Sendable {
    let gateway: GatewaySettingsConsumerHostConfiguration
    let transport: GatewaySettingsConsumerHostConfiguration
    init(reference: RuntimeMaterialReference, bundlePath: String, policy: AuthorityCodePolicy) throws {
        guard reference.serviceActivity != nil else { throw RuntimeActivationError.incomplete }
        gateway = try .init(role: .gateway, runtime: reference, bundlePath: bundlePath, codePolicy: policy)
        transport = try .init(role: .transport, runtime: reference, bundlePath: bundlePath, codePolicy: policy)
    }
    /// Setup must inspect the actual signed release before it retains a new selection.
    func validateRelease(_ release: SignedReleaseEvidence) throws {
        guard try GatewaySettingsNativeSupport.mode(release: release, policy: gateway.codePolicy) == .native else {
            throw GatewayPreparationError.changedScope
        }
        for host in [gateway, transport] {
            try host.validateRelease(release)
            _ = try GatewaySettingsRecoveryNativePolicy(role: host.role, services: host.runtime.services,
                codePolicy: host.codePolicy, release: release)
            guard release.manifest.components.first(where: { $0.role == host.role.codeRole })?.relativePath
                == host.consumerExecutableRelativePath else { throw GatewayPreparationError.changedScope }
        }
        guard release.manifest.components.first(where: { $0.role == .setupController })?.relativePath
            == AdministrativeSetupConfiguration.executablePath else { throw GatewayPreparationError.changedScope }
    }
    /// The native mode requires these readers even before optional Gateway activation or job registration.
    static var releaseRequirements: RetainedReleaseRequirements { get throws {
        var formats: [RetainedReleaseFormat] = []
        func add(_ role: AuthorityCodeRole, _ name: String, _ reads: Set<UInt64>, _ writes: Set<UInt64> = []) throws {
            formats.append(try .init(role: role, name: name, readVersions: reads, writeVersions: writes))
        }
        for role in [AuthorityCodeRole.authority, .setupController] {
            try add(role, RuntimeActivationPlan.formatName, [1, 2], role == .setupController ? [2] : [])
            try add(role, "authority.installation-preparation", [6, 7, 8, 9, 10, 11], [6, 7, 8, 9, 10, 11])
            try add(role, "authority.command-host-config", [3], [3])
            try add(role, GatewaySettingsControlReleaseValidation.formatName, [1], [1])
            try add(role, RuntimePreparationMaterial.formatName, [2], role == .setupController ? [2] : [])
        }
        for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
            try add(role, GatewaySettingsConsumerHostConfiguration.formatName, [1], role == .setupController ? [1] : [])
            try add(role, RuntimeMaterialReference.formatName, [2], role == .setupController ? [2] : [])
            try add(role, ServiceReleaseActivityReference.formatName, [1], role == .setupController ? [1] : [])
            // Gateway and Root also decode Transport's shared bootstrap and selected Gateway configuration.
            try add(role, "transport.pairing-config", [2], role == .setupController ? [2] : [])
            try add(role, "gateway.service-config", [2], role == .setupController ? [2] : [])
            try add(role, GatewayRuntimeSettingsFenceReleaseValidation.formatName, [1, 2],
                role == .authority ? [2] : role == .setupController ? [1] : [])
        }
        for role in GatewaySettingsConsumerRole.allCases {
            try add(.authority, role.formatName, [2], [2])
            try add(.setupController, role.formatName, [1], [1])
            try add(role.codeRole, role.formatName, [1, 2], [1, 2])
        }
        formats.append(contentsOf: try GatewayRuntimeRecordFormats.requirements(
            commitVersions: GatewayRuntimeCommit.supportedVersions, settingsRetained: true))
        return try .init(formats: formats, requests: [])
    } }
    func selecting(_ base: TransportPairingStartupConfiguration) throws -> TransportPairingStartupConfiguration {
        guard base.settingsHost == nil || base.settingsHost == transport else { throw GatewayPreparationError.changedScope }
        return try .init(transport: base.transport, control: base.control, wake: base.wake,
            relayPort: base.relayPort, settingsHost: transport)
    }
    func job(_ role: GatewaySettingsConsumerRole) throws -> InstalledAccountJobManifest {
        let host = role == .gateway ? gateway : transport, services = host.runtime.services
        guard let claim = services.claims.first(where: { $0.role == host.serviceRole }) else { throw RuntimeActivationError.incomplete }
        return try .init(accountID: services.accountID, role: role.codeRole, executionUID: claim.number,
            userName: claim.name, bundlePath: host.bundlePath, settingsConsumerHostEnabled: true)
    }
}
