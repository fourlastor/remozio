import Foundation
import RemozioProtocol

/// Maintenance requires matching client, endpoint and progress codec declarations.
enum SetupAuditUpgradeLocalContract {
    static let version = AdministrativeSetupInterface.auditUpgradeVersion
    static func validate(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(release, policy: policy)
        let formats = try [AuthorityCodeRole.app, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: AdministrativeSetupInterface.formatName, readVersions: [version], writeVersions: [version]),
                 RetainedReleaseFormat(role: role, name: SetupAuditUpgradeProgress.formatName, readVersions: [1], writeVersions: [1])]
        }
        try ReleaseCompatibilityPreflight.validate(release, policy: policy, requirements: .init(formats: formats, requests: []))
    }
}

@objc public protocol AuditUpgradeSetupXPCProtocol {
    func auditUpgradeHello(reply: @escaping @Sendable (UInt64) -> Void)
    func auditUpgradeProgress(reply: @escaping @Sendable (Data?) -> Void)
    func performAuditUpgrade(_ expected: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// Old clients retain their original interface. The daemon exports the combined selector set.
@objc public protocol AdministrativeSetupMaintenanceXPCProtocol: AdministrativeSetupXPCProtocol, AuditUpgradeSetupXPCProtocol {}
