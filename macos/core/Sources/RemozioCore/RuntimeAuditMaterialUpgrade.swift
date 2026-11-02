import Foundation

/// Pure same-release material transformation. This neither publishes files nor changes retained setup or activation state.
/// The protected transition supplies current policy, validates actual activity files, quiesces consumers and commits every dependent reference.
enum RuntimeAuditMaterialUpgrade {
    static func prepare(material: RuntimePreparationMaterial, expected: RuntimeMaterialReference,
                        account: AccountPreparationIntent, activity: ServiceReleaseActivityReference,
                        installedRelease: SignedReleaseEvidence, policy: AuthorityCodePolicy,
                        maximumPayloadBytes: Int = AuthorityServiceConfiguration.defaultMaximumPayloadBytes) throws -> RuntimePreparationMaterial {
        try material.services.validate(account: account)
        try expected.validate(account: account, services: material.services)
        guard try material.reference == expected else { throw RuntimePreparationError.conflictingMaterial }
        guard try InstallationInventory.digest(installedRelease) == account.releaseDigest else { throw RuntimePreparationError.changedScope }
        try activity.validate(services: material.services)
        if let existing = material.serviceActivity {
            guard existing == activity else { throw RuntimePreparationError.conflictingMaterial }
        }
        guard try RuntimeAuditDeliverySupport.selectedVersion(reference: nil, release: installedRelease,
            policy: policy, maximumPayloadBytes: maximumPayloadBytes) == 1 else {
            throw RuntimePreparationError.incomplete
        }
        if material.auditDeliveryVersion == 1 { return material }
        return try .init(materialID: material.materialID, services: material.services,
            transportIdentity: material.transportIdentity, transportPublicKeyInfo: material.transportPublicKeyInfo,
            gateway: material.gateway, serviceActivity: activity, auditDeliveryVersion: 1)
    }
}
