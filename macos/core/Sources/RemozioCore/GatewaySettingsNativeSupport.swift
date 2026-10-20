import Foundation

/// Selects one complete installed capability family. It performs no provisioning or native admission.
enum GatewaySettingsNativeSupport {
    enum Mode: Sendable, Equatable { case legacy, native }
    static func mode(release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws -> Mode {
        try ReleaseGenerationPreflight.validate(release, against: policy)
        for code in policy.entries where code.active {
            guard let component = release.manifest.components.first(where: { $0.role == code.role }),
                  component.generation == code.installedGeneration,
                  release.codeDirectoryHashes[code.role] == code.codeDirectoryHash else { throw GatewayPreparationError.changedScope }
        }
        let controls = Set(GatewaySettingsConsumerRole.allCases.map(\.formatName))
        let marked = release.manifest.components.contains { component in
            component.formats.contains { format in
                if format.name == GatewaySettingsConsumerHostConfiguration.formatName { return true }
                return (format.name == RuntimeActivationPlan.formatName || format.name == GatewayRuntimeSettingsFenceReleaseValidation.formatName
                    || controls.contains(format.name)) && (format.readers.contains(2) || format.writers.contains(2))
            }
        }
        guard marked else { return .legacy }
        let required: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .setupController]
        let participants = required.compactMap { role in policy.entries.first { $0.role == role && $0.active } }
        guard participants.count == required.count, Set(participants.map(\.teamID)).count == 1,
              Set(participants.map(\.identifier)).count == required.count else { throw GatewayPreparationError.changedScope }
        try ReleaseCompatibilityPreflight.validate(release, policy: policy, requirements: GatewaySettingsNativeHostPlan.releaseRequirements)
        let paths: [(AuthorityCodeRole, String)] = [
            (.authority, InstalledAuthorityCommandConfiguration.executablePath),
            (.transport, "Contents/Library/LaunchServices/RemozioTransport"),
            (.notificationGateway, GatewayJournalSetupServiceConfiguration.executableRelativePath),
            (.setupController, AdministrativeSetupConfiguration.executablePath)]
        for (role, path) in paths {
            guard release.manifest.components.first(where: { $0.role == role })?.relativePath == path else {
                throw GatewayPreparationError.changedScope
            }
        }
        return .native
    }
    /// Established material is immutable. A newer bundle must not replace it to select another mode.
    static func serviceActivityEnabled(reference: RuntimeMaterialReference?, mode: Mode) throws -> Bool {
        if let reference {
            if reference.serviceActivity != nil && mode != .native { throw GatewayPreparationError.changedScope }
            return reference.serviceActivity != nil
        }
        return mode == .native
    }
}
