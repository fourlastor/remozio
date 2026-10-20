import Foundation

/// Access follows original-stack native peer admission. It does not retain the enclosing consumer owner.
struct GatewaySettingsConsumerAccess: Sendable {
    private weak var owner: GatewaySettingsConsumerOwner?
    let binding: GatewaySettingsConsumerBinding
    let serviceUID: UInt32
    let ownerUID: UInt32
    let verifyCurrent: @Sendable () throws -> Void
    init(owner: GatewaySettingsConsumerOwner, services: ServiceAccountPlan,
         verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        let binding = owner.binding
        guard services.macID == binding.macID, services.accountID == binding.accountID,
              let claim = services.claims.first(where: { $0.role == (binding.role == .gateway ? .gateway : .transport) }) else {
            throw GatewayPreparationError.changedScope
        }
        self.owner = owner; self.binding = binding; serviceUID = claim.number; ownerUID = services.ownerUID
        self.verifyCurrent = verifyCurrent
    }
    func requireNativeProcess() throws {
        try DedicatedServiceAccount.requireCurrent(serviceUID: serviceUID, ownerUID: ownerUID)
    }
    func execute(_ request: GatewaySettingsConsumerRequest) async throws -> GatewaySettingsConsumerObservation {
        guard request.binding == binding, let owner else { throw GatewayPreparationError.changedScope }
        try verifyCurrent(); try Task.checkCancellation()
        let result = try await owner.performAuthenticated(request, verifyCaller: verifyCurrent)
        try verifyCurrent(); try Task.checkCancellation()
        return result.observation
    }
}

/// Both exact signed participants must understand this companion role's control format.
enum GatewaySettingsConsumerReleaseValidation {
    static func validate(_ release: SignedReleaseEvidence, role: GatewaySettingsConsumerRole,
                         consumer: AuthorityCodeEntry, setup: AuthorityCodeEntry) throws {
        guard consumer.role == role.codeRole, setup.role == .setupController, consumer.active, setup.active,
              consumer.teamID == setup.teamID else { throw GatewayPreparationError.changedScope }
        for entry in [consumer, setup] {
            guard let component = release.manifest.components.first(where: { $0.role == entry.role }),
                  component.identifier == entry.identifier, component.teamID == entry.teamID,
                  component.generation == entry.installedGeneration, component.codeDirectoryHash == entry.codeDirectoryHash,
                  release.codeDirectoryHashes[entry.role] == entry.codeDirectoryHash,
                  let format = component.formats.first(where: { $0.name == role.formatName }),
                  format.readers.contains(GatewaySettingsConsumerInterface.version),
                  format.writers.contains(GatewaySettingsConsumerInterface.version),
                  let fence = component.formats.first(where: { $0.name == GatewayRuntimeSettingsFence.formatName }),
                  GatewayRuntimeSettingsFence.supportedVersions.isSubset(of: fence.readers),
                  entry.role != .setupController || fence.writers.contains(GatewayRuntimeSettingsFence.settingsVersion) else {
                throw GatewayPreparationError.changedScope
            }
        }
    }
}
