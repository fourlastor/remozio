import Foundation
import RemozioProtocol

/// Selects fresh audit material from a verified release. Existing material never changes its selection here.
enum RuntimeAuditDeliverySupport {
    static func selectedVersion(reference: RuntimeMaterialReference?, release: SignedReleaseEvidence,
                                policy: AuthorityCodePolicy,
                                maximumPayloadBytes: Int = AuthorityServiceConfiguration.defaultMaximumPayloadBytes) throws -> UInt64? {
        let mode = try GatewaySettingsNativeSupport.mode(release: release, policy: policy)
        let native = try GatewaySettingsNativeSupport.serviceActivityEnabled(reference: reference, mode: mode)
        if let reference {
            guard let selected = reference.auditDeliveryVersion else { return nil }
            guard native, maximumPayloadBytes > PhoneAuditFrame.overheadBytes else { throw RuntimePreparationError.changedScope }
            try PhoneAuditReleaseContract.validateDelivery(release, policy: policy)
            return selected
        }
        guard native, maximumPayloadBytes > PhoneAuditFrame.overheadBytes else { return nil }
        let materialNames = Set([RuntimeMaterialReference.formatName, RuntimePreparationMaterial.formatName])
        let freshWriter = release.manifest.components.first { $0.role == .setupController }?.formats.contains {
            materialNames.contains($0.name) && $0.writers.contains(3)
        } == true
        guard freshWriter else { return nil }
        try PhoneAuditReleaseContract.validateDelivery(release, policy: policy)
        return PhoneAuditReleaseContract.version
    }
}
