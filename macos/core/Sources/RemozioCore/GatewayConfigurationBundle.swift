import Foundation
import RemozioProtocol

/// Optional startup proposal only. Protected activation must retain, publish and coordinate these inputs before use.
struct GatewayConfigurationBundle: CustomStringConvertible, CustomDebugStringConvertible {
    let material: GatewayMaterialReference
    let foreground: RuntimeActivationPlan
    let gateway: GatewayServiceConfiguration
    let commandHost: InstalledAuthorityCommandConfiguration
    let transport: TransportPairingStartupConfiguration
    let gatewayJob: InstalledAccountJobManifest
    var description: String { "GatewayConfigurationBundle(redacted)" }
    var debugDescription: String { description }

    init(foreground: RuntimeActivationPlan, material: GatewayMaterialReference, inventory: InstallationInventory,
         settings: GatewayServiceSettings, wakePollMilliseconds: UInt64 = 1000, wakeTimeoutMilliseconds: UInt64 = 5000,
         wakeMaximumConnections: Int = 4, wakeMaximumOperations: Int = 8,
         wakeChallengeLifetimeMilliseconds: UInt64 = 5000) throws {
        let services = foreground.reference.services, account = services.accountID
        let paths = try RuntimePreparationPaths(accountID: account)
        guard foreground.reference == material.runtime,
              inventory.macID == services.macID, inventory.installationID == services.installationID,
              inventory.releaseDigest == services.releaseDigest, inventory.bundlePath == foreground.bundlePath,
              inventory.accounts.contains(where: { $0.accountID == account && $0.ownerUID == services.ownerUID }),
              inventory.services.contains(foreground.authorityJob.declaration), inventory.services.contains(foreground.transportJob.declaration),
              let transportClaim = services.claims.first(where: { $0.role == .transport }),
              let gatewayClaim = services.claims.first(where: { $0.role == .gateway }),
              material.phonePush.maximumControls <= settings.maximumStoredControls,
              material.phonePush.candidateLifetimeMilliseconds <= settings.maximumCandidateLifetimeMillis else {
            throw GatewayPreparationError.changedScope
        }
        func entry(_ role: AuthorityCodeRole) throws -> AuthorityCodeEntry {
            guard let value = foreground.host.codePolicy.entries.first(where: { $0.role == role && $0.active }) else {
                throw GatewayPreparationError.invalidRecord
            }
            return value
        }
        let rootCode = try entry(.authority), gatewayCode = try entry(.notificationGateway)
        let transportCode = try entry(.transport), appCode = try entry(.app)
        guard Set([rootCode.teamID, gatewayCode.teamID, transportCode.teamID, appCode.teamID]).count == 1 else {
            throw GatewayPreparationError.changedScope
        }
        let previous = foreground.host.command, oldPresence = previous.presence, oldWake = oldPresence.wake
        guard oldWake.leaseMilliseconds <= settings.authorityLeaseMillis,
              oldWake.phonePush == nil || oldWake.phonePush?.canonicalBytes == material.phonePush.canonicalBytes else {
            throw GatewayPreparationError.changedScope
        }
        let endpoint = try GatewayWakeEndpointConfiguration(serviceName: paths.gatewayWakeService, transportUID: transportClaim.number,
            teamID: transportCode.teamID, componentIdentifier: transportCode.identifier,
            approvedCodeDirectoryHashes: [transportCode.codeDirectoryHash], maximumConnections: wakeMaximumConnections,
            maximumOperations: wakeMaximumOperations, challengeLifetimeMillis: wakeChallengeLifetimeMilliseconds)
        gateway = try .init(registration: material.runtime.gateway, receiptPublicKey: material.phonePush.gatewayReceiptPublicKey,
            directoryPath: paths.gatewayDirectory, providerPath: paths.gatewayProvider, receiptKeyPath: paths.gatewayReceiptKey,
            serviceUID: gatewayClaim.number, ownerUID: services.ownerUID, serviceName: paths.gatewayService,
            teamID: rootCode.teamID, authorityIdentifier: rootCode.identifier, authorityHashes: [rootCode.codeDirectoryHash],
            project: material.phonePush.projectID, packageName: material.phonePush.packageName, settings: settings, wakeEndpoint: endpoint)
        let wake = try AuthorityWakeStartupConfiguration(request: oldWake.request, registration: oldWake.registration,
            gatewayServiceName: oldWake.gatewayServiceName, gatewayUID: gatewayClaim.number, teamID: gatewayCode.teamID,
            gatewayIdentifier: gatewayCode.identifier, gatewayHashes: [gatewayCode.codeDirectoryHash],
            leaseMilliseconds: oldWake.leaseMilliseconds, pollMilliseconds: oldWake.pollMilliseconds,
            timeoutMilliseconds: oldWake.timeoutMilliseconds, phonePush: material.phonePush)
        let presence = try AuthorityPresenceStartupConfiguration(wake: wake, ownerUID: services.ownerUID,
            appServiceName: oldPresence.endpoint.serviceName, teamID: appCode.teamID, appIdentifier: appCode.identifier,
            appHashes: [appCode.codeDirectoryHash], policy: oldPresence.presence.policy, pairing: oldPresence.pairing)
        let command = try AuthorityCommandStartupConfiguration(presence: presence, serviceName: previous.serviceName,
            policyPath: previous.policyPath, environment: previous.environment, submissionLimits: previous.submissionLimits,
            captureLimits: previous.captureLimits, maximumSessions: previous.maximumSessions,
            receiveWaitMilliseconds: previous.receiveWaitMilliseconds, replyTimeoutMilliseconds: previous.replyTimeoutMilliseconds,
            maximumAncestryEntries: previous.maximumAncestryEntries, approvalLifetimeMilliseconds: previous.approvalLifetimeMilliseconds,
            execution: previous.execution)
        let host = foreground.host
        commandHost = try .init(machineDirectory: host.machineDirectory, installationID: host.installationID,
            releaseDigest: host.releaseDigest, codePolicy: host.codePolicy, command: command, label: host.label,
            plistName: host.plistName, jobPlacement: host.jobPlacement)
        let r = material.runtime.gateway
        let binding = try GatewaySubmissionBinding(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID,
            gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch)
        let signer = try GatewayWakeSignerConfiguration(binding: binding, credentialID: material.wakeCredentialID,
            transportUID: transportClaim.number, ownerUID: services.ownerUID, gatewayUID: gatewayClaim.number,
            serviceName: paths.gatewayWakeService, teamID: gatewayCode.teamID, gatewayIdentifier: gatewayCode.identifier,
            gatewayHashes: [gatewayCode.codeDirectoryHash], custody: .protectedFile, keyRecordPath: paths.transportWakeKey,
            publicKey: material.wakePublicKey, timeoutMilliseconds: wakeTimeoutMilliseconds)
        if let current = foreground.transport.wake {
            guard current.wake.binding == binding, current.wake.credentialID == signer.credentialID,
                  current.wake.publicKey == signer.publicKey, current.wake.custody == signer.custody else {
                throw GatewayPreparationError.changedScope
            }
        }
        let companion = try TransportWakeStartupConfiguration(transport: foreground.transport.transport, wake: signer,
            pollMilliseconds: wakePollMilliseconds)
        transport = try .init(transport: foreground.transport.transport, control: foreground.transport.control,
            wake: companion, relayPort: foreground.transport.relayPort)
        gatewayJob = try .init(accountID: account, role: .notificationGateway, executionUID: gatewayClaim.number,
            userName: gatewayClaim.name, bundlePath: foreground.bundlePath)
        self.material = material; self.foreground = foreground
        _ = try enrolledInventory(inventory)
    }

    /// Add only the declared gateway. Native activation must compare the current inventory before committing this proposal.
    func enrolledInventory(_ inventory: InstallationInventory) throws -> InstallationInventory {
        let services = material.runtime.services
        guard inventory.macID == services.macID, inventory.installationID == services.installationID,
              inventory.releaseDigest == services.releaseDigest, inventory.bundlePath == foreground.bundlePath,
              inventory.accounts.contains(where: { $0.accountID == services.accountID && $0.ownerUID == services.ownerUID }),
              inventory.services.contains(foreground.authorityJob.declaration), inventory.services.contains(foreground.transportJob.declaration) else {
            throw GatewayPreparationError.changedScope
        }
        let declaration = gatewayJob.declaration
        if let existing = inventory.services.first(where: { $0.label == declaration.label ||
            ($0.accountID == services.accountID && $0.role == .notificationGateway && $0.domainUID == nil) }) {
            guard existing == declaration else { throw GatewayPreparationError.conflictingMaterial }
            return inventory
        }
        guard !inventory.services.contains(where: { $0.executionUID == declaration.executionUID && $0.accountID != services.accountID }) else {
            throw GatewayPreparationError.conflictingMaterial
        }
        return try .init(macID: inventory.macID, installationID: inventory.installationID, revision: inventory.revision,
            bundlePath: inventory.bundlePath, releaseDigest: inventory.releaseDigest, accounts: inventory.accounts,
            services: inventory.services + [declaration], formatVersion: inventory.formatVersion)
    }
}
