import Foundation
import RemozioProtocol

/// Checks frozen runtime values. The result grants no publication, registration, or startup authority.
enum RuntimeActivationInputValidation {
    static func transportClaim(reference: RuntimeMaterialReference, host: InstalledAuthorityCommandConfiguration,
        transport: TransportPairingStartupConfiguration, hasConsumerHosts: Bool, installedReleaseDigest: Data,
        phoneRoutingVersion: UInt64?, phoneAuditVersion: UInt64?, phoneUpdateSchedulingVersion: UInt64?) throws -> ServiceAccountClaim {
        guard phoneRoutingVersion == nil || (phoneRoutingVersion == PhoneRoutingReleaseContract.version && hasConsumerHosts &&
            host.command.presence.wake.request.service.maximumPayloadBytes >= PhoneRoutingFrame.maximumBytes) else {
            throw RuntimeActivationError.invalidPlan
        }
        guard phoneAuditVersion == nil || (phoneAuditVersion == PhoneAuditReleaseContract.version && hasConsumerHosts &&
            host.command.presence.wake.request.service.maximumPayloadBytes > PhoneAuditFrame.overheadBytes) else {
            throw RuntimeActivationError.invalidPlan
        }
        guard phoneUpdateSchedulingVersion == nil || (phoneUpdateSchedulingVersion == PhoneUpdateSchedulingReleaseContract.version && hasConsumerHosts &&
            host.command.presence.wake.request.service.maximumPayloadBytes >= PhoneUpdateSchedulingFrame.maximumBytes) else {
            throw RuntimeActivationError.invalidPlan
        }
        let admittedAudits = Set(reference.auditDeliveryVersion.map { [$0] } ?? [])
        guard host.command.presence.wake.request.service.auditVersions == admittedAudits,
              reference.auditDeliveryVersion == nil || (reference.auditDeliveryVersion == phoneAuditVersion && hasConsumerHosts) else {
            throw RuntimeActivationError.invalidPlan
        }
        let services = reference.services, paths = try RuntimePreparationPaths(accountID: services.accountID)
        guard let claim = services.claims.first(where: { $0.role == .transport }),
              let gateway = services.claims.first(where: { $0.role == .gateway }),
              host.jobPlacement == .systemAccount, host.installationID == services.installationID, host.releaseDigest == installedReleaseDigest,
              host.command.macID == services.macID, host.command.accountID == services.accountID, host.command.callerUID == services.ownerUID,
              host.command.presence.wake.registration == reference.gateway,
              host.command.presence.wake.request.authorityPublicKey == services.authorityPublicKey,
              host.command.presence.wake.gatewayPolicy.expectedUserID == gateway.number,
              host.command.presence.wake.gatewayServiceName == paths.gatewayService,
              host.command.presence.wake.request.service.transportPolicy.expectedUserID == claim.number,
              try host.command.presence.pairing?.transportPublicKey == reference.transportPublicKeyX963,
              transport.transport.macID == services.macID, transport.transport.accountID == services.accountID,
              transport.transport.ownerUID == services.ownerUID, transport.transport.serviceUID == claim.number,
              transport.transport.authorityServiceName == paths.authorityService,
              transport.transport.identitySource == .protectedFile(path: paths.transportIdentity),
              transport.transport.identityPublicKeyInfo == reference.transportPublicKeyInfo,
              transport.control.serviceName == paths.pairingService,
              host.canonicalBytes.count <= ProtectedServiceConfiguration.maximumBytes,
              transport.canonicalBytes.count <= ProtectedServiceConfiguration.maximumBytes else { throw RuntimeActivationError.invalidPlan }
        func policy(_ role: AuthorityCodeRole, _ uid: UInt32) throws -> XPCPeerPolicy {
            guard let entry = host.codePolicy.entries.first(where: { $0.role == role && $0.active }) else { throw RuntimeActivationError.invalidPlan }
            return try .init(teamID: entry.teamID, componentIdentifier: entry.identifier,
                approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: uid)
        }
        guard try transport.transport.authorityPolicy.requirement == policy(.authority, 0).requirement,
              try transport.control.appPolicy.requirement == policy(.app, services.ownerUID).requirement,
              try transport.control.transportPolicy.requirement == policy(.transport, claim.number).requirement else {
            throw RuntimeActivationError.invalidPlan
        }
        return claim
    }
}
