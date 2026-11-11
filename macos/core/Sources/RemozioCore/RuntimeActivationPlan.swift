import Foundation
import RemozioProtocol

public enum RuntimeActivationError: Error, Equatable {
    case incomplete, invalidPlan, conflictingPlan, changedScope, unavailable, exhausted
}

/// Frozen activation inputs. A plan neither registers jobs nor proves runtime health.
struct RuntimeActivationPlan: CustomStringConvertible, CustomDebugStringConvertible {
    private final class Storage: Sendable {
        let reference: RuntimeMaterialReference
        let bundlePath: String
        let host: InstalledAuthorityCommandConfiguration
        let transport: TransportPairingStartupConfiguration
        let phoneRoutingVersion: UInt64?
        let phoneAuditVersion: UInt64?
        let phoneUpdateSchedulingVersion: UInt64?
        let consumerHosts: GatewaySettingsNativeHostPlan?
        let authorityJob: InstalledAccountJobManifest
        let transportJob: InstalledAccountJobManifest
        @inline(never)
        init(reference: RuntimeMaterialReference, bundlePath: String, host: InstalledAuthorityCommandConfiguration,
             transport: TransportPairingStartupConfiguration, phoneRoutingVersion: UInt64?, phoneAuditVersion: UInt64?,
             phoneUpdateSchedulingVersion: UInt64?, consumerHosts: GatewaySettingsNativeHostPlan?,
             authorityJob: InstalledAccountJobManifest, transportJob: InstalledAccountJobManifest) {
            self.reference = reference; self.bundlePath = bundlePath; self.host = host; self.transport = transport
            self.phoneRoutingVersion = phoneRoutingVersion; self.phoneAuditVersion = phoneAuditVersion
            self.phoneUpdateSchedulingVersion = phoneUpdateSchedulingVersion
            self.consumerHosts = consumerHosts; self.authorityJob = authorityJob; self.transportJob = transportJob
        }
    }
    private let storage: Storage
    static let formatName = "runtime.activation-plan"
    static let supportedVersions: Set<UInt64> = [1, 2, 3, 4, 5]
    var reference: RuntimeMaterialReference { storage.reference }
    var bundlePath: String { storage.bundlePath }
    var host: InstalledAuthorityCommandConfiguration { storage.host }
    var transport: TransportPairingStartupConfiguration { storage.transport }
    var phoneRoutingVersion: UInt64? { storage.phoneRoutingVersion }
    var phoneAuditVersion: UInt64? { storage.phoneAuditVersion }
    var phoneUpdateSchedulingVersion: UInt64? { storage.phoneUpdateSchedulingVersion }
    var formatVersion: UInt64 { phoneUpdateSchedulingVersion != nil ? 5 : phoneAuditVersion != nil ? 4 : phoneRoutingVersion != nil ? 3 : consumerHosts == nil ? 1 : 2 }
    var consumerHosts: GatewaySettingsNativeHostPlan? { storage.consumerHosts }
    var gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration? { consumerHosts?.gateway }
    var authorityJob: InstalledAccountJobManifest { storage.authorityJob }
    var transportJob: InstalledAccountJobManifest { storage.transportJob }
    var description: String { "RuntimeActivationPlan(redacted)" }
    var debugDescription: String { description }
    var accountID: Data { reference.services.accountID }

    init(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
         runtime: RuntimePreparationState, inventory: InstallationInventory,
         gatewaySettingsRelease: SignedReleaseEvidence? = nil, importIntent: SharedSetupImportIntent? = nil,
         relayPlan: SharedSetupImportRelayPlan? = nil) throws {
        guard runtime.configurationPublished, let reference = runtime.reference else { throw RuntimeActivationError.incomplete }
        let bundle = try RuntimeConfigurationBundle.initial(account: account, initialization: initialization, reference: reference,
            inventory: inventory, importIntent: importIntent, relayPlan: relayPlan)
        let label = bundle.paths.namespace + ".authority"
        var host = try InstalledAuthorityCommandConfiguration(machineDirectory: MachineBootstrap.machineDirectory,
            installationID: inventory.installationID, releaseDigest: inventory.releaseDigest, codePolicy: account.initialAuthority.codePolicy,
            command: bundle.command, label: label, plistName: label + ".plist", jobPlacement: .systemAccount)
        if let gatewaySettingsRelease { host = try host.enablingGatewaySettingsControl(release: gatewaySettingsRelease) }
        if reference.serviceActivity != nil {
            guard let gatewaySettingsRelease else { throw RuntimeActivationError.incomplete }
            try GatewaySettingsNativeHostPlan(reference: reference, bundlePath: inventory.bundlePath,
                policy: host.codePolicy).validateRelease(gatewaySettingsRelease)
        }
        let phoneRoutingVersion: UInt64?, phoneAuditVersion: UInt64?, phoneUpdateSchedulingVersion: UInt64?
        if let release = gatewaySettingsRelease {
            phoneRoutingVersion = try PhoneRoutingReleaseContract.selectedVersion(in: release, policy: host.codePolicy,
                nativeHosts: reference.serviceActivity != nil,
                maximumPayloadBytes: host.command.presence.wake.request.service.maximumPayloadBytes)
            phoneAuditVersion = try PhoneAuditReleaseContract.selectedVersion(in: release, policy: host.codePolicy,
                nativeHosts: reference.serviceActivity != nil,
                maximumPayloadBytes: host.command.presence.wake.request.service.maximumPayloadBytes)
            phoneUpdateSchedulingVersion = try PhoneUpdateSchedulingReleaseContract.selectedVersion(in: release, policy: host.codePolicy,
                nativeHosts: reference.serviceActivity != nil,
                maximumPayloadBytes: host.command.presence.wake.request.service.maximumPayloadBytes)
        } else { phoneRoutingVersion = nil; phoneAuditVersion = nil; phoneUpdateSchedulingVersion = nil }
        if reference.auditDeliveryVersion != nil {
            guard let gatewaySettingsRelease else { throw RuntimeActivationError.incomplete }
            try PhoneAuditReleaseContract.validateDelivery(gatewaySettingsRelease, policy: host.codePolicy)
        }
        try self.init(reference: reference, bundlePath: inventory.bundlePath, host: host,
            transport: bundle.transport, gatewaySettingsHost: bundle.gatewaySettingsHost,
            phoneRoutingVersion: phoneRoutingVersion, phoneAuditVersion: phoneAuditVersion,
            phoneUpdateSchedulingVersion: phoneUpdateSchedulingVersion)
        try validate(account: account, reference: reference)
    }
    /// The native file verifier uses the pinned plan policy. The owner independently binds it to the retained import.
    func configurationBundle(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
                             inventory: InstallationInventory) throws -> RuntimeConfigurationBundle {
        try .initial(account: account, initialization: initialization, reference: reference, inventory: inventory,
            presencePolicyOverride: host.command.presence.presence.policy, relayPortOverride: transport.relayPort)
    }
    /// Prepares values only. The owner must verify and coordinate retained dependencies before live replacement.
    func preparingAuditUpgrade(_ intent: RuntimeAuditUpgradeIntent, installedRelease: SignedReleaseEvidence,
                               currentPolicy: AuthorityCodePolicy) throws -> Self {
        try RuntimeAuditUpgradeRecord.validatePreparation(intent, release: installedRelease, policy: currentPolicy)
        guard reference == intent.source, try host.codePolicy.bytes == currentPolicy.bytes,
              try RuntimeAuditDeliverySupport.selectedVersion(reference: intent.target, release: installedRelease,
                policy: currentPolicy, maximumPayloadBytes: host.command.presence.wake.request.service.maximumPayloadBytes) == 1 else {
            throw RuntimeActivationError.changedScope
        }
        let consumers = try GatewaySettingsNativeHostPlan(reference: intent.target, bundlePath: bundlePath, policy: currentPolicy)
        try consumers.validateRelease(installedRelease)
        let nextHost = try InstalledAuthorityCommandConfiguration(machineDirectory: host.machineDirectory,
            installationID: host.installationID, releaseDigest: host.releaseDigest, codePolicy: currentPolicy,
            command: RuntimeAuditUpgradeConfiguration.command(host.command), label: host.label, plistName: host.plistName,
            jobPlacement: host.jobPlacement, gatewaySettingsControlEnabled: true)
        try nextHost.validateRelease(installedRelease, bundlePath: bundlePath)
        let nextTransport = try TransportPairingStartupConfiguration(transport: transport.transport, control: transport.control,
            wake: transport.wake, relayPort: transport.relayPort, settingsHost: consumers.transport)
        return try Self(reference: intent.target, bundlePath: bundlePath, host: nextHost, transport: nextTransport,
            gatewaySettingsHost: consumers.gateway, phoneRoutingVersion: phoneRoutingVersion,
            phoneAuditVersion: PhoneAuditReleaseContract.version, phoneUpdateSchedulingVersion: phoneUpdateSchedulingVersion)
    }
    private init(reference: RuntimeMaterialReference, bundlePath: String, host: InstalledAuthorityCommandConfiguration,
                 transport: TransportPairingStartupConfiguration,
                 gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration? = nil, phoneRoutingVersion: UInt64? = nil,
                 phoneAuditVersion: UInt64? = nil, phoneUpdateSchedulingVersion: UInt64? = nil) throws {
        let selected: GatewaySettingsNativeHostPlan?
        if reference.serviceActivity != nil {
            let plan = try GatewaySettingsNativeHostPlan(reference: reference, bundlePath: bundlePath, policy: host.codePolicy)
            guard host.gatewaySettingsControlEnabled, gatewaySettingsHost == plan.gateway,
                  transport.settingsHost == plan.transport else { throw RuntimeActivationError.invalidPlan }
            selected = plan
        } else {
            guard gatewaySettingsHost == nil, transport.settingsHost == nil else { throw RuntimeActivationError.invalidPlan }
            selected = nil
        }
        let claim = try RuntimeActivationInputValidation.transportClaim(reference: reference, host: host,
            transport: transport, hasConsumerHosts: selected != nil, installedReleaseDigest: reference.services.releaseDigest,
            phoneRoutingVersion: phoneRoutingVersion, phoneAuditVersion: phoneAuditVersion,
            phoneUpdateSchedulingVersion: phoneUpdateSchedulingVersion)
        let services = reference.services
        let authorityJob = try InstalledAccountJobManifest(accountID: services.accountID, role: .authority, executionUID: 0, userName: "root", bundlePath: bundlePath,
            gatewaySettingsControlEnabled: host.gatewaySettingsControlEnabled)
        let transportJob: InstalledAccountJobManifest
        if let selected { transportJob = try selected.job(.transport) }
        else { transportJob = try .init(accountID: services.accountID, role: .transport, executionUID: claim.number, userName: claim.name, bundlePath: bundlePath) }
        storage = .init(reference: reference, bundlePath: bundlePath, host: host, transport: transport,
            phoneRoutingVersion: phoneRoutingVersion, phoneAuditVersion: phoneAuditVersion,
            phoneUpdateSchedulingVersion: phoneUpdateSchedulingVersion, consumerHosts: selected, authorityJob: authorityJob, transportJob: transportJob)
    }
    func validate(account: AccountPreparationIntent, reference: RuntimeMaterialReference) throws {
        try self.reference.validate(account: account, services: reference.services)
        guard self.reference == reference, try host.codePolicy.bytes == account.initialAuthority.codePolicy.bytes else {
            throw RuntimeActivationError.changedScope
        }
    }
    /// Add only this account and its exact jobs. Preserve other accounts and refuse conflicting declarations.
    func enrolledInventory(_ inventory: InstallationInventory) throws -> InstallationInventory {
        let services = reference.services
        guard inventory.macID == services.macID, inventory.installationID == services.installationID,
              inventory.releaseDigest == services.releaseDigest, inventory.bundlePath == bundlePath else { throw RuntimeActivationError.changedScope }
        let account = try InstallationAccount(accountID: services.accountID, ownerUID: services.ownerUID)
        if let existing = inventory.accounts.first(where: { $0.accountID == account.accountID || $0.ownerUID == account.ownerUID }), existing != account {
            throw RuntimeActivationError.conflictingPlan
        }
        var declarations = inventory.services
        for job in [authorityJob, transportJob] {
            if let existing = declarations.first(where: {
                $0.label == job.declaration.label || ($0.accountID == account.accountID && $0.role == job.declaration.role && $0.domainUID == nil)
            }) {
                guard existing == job.declaration else { throw RuntimeActivationError.conflictingPlan }
            } else {
                guard job.declaration.executionUID == 0 || !declarations.contains(where: {
                    $0.executionUID == job.declaration.executionUID && $0.accountID != account.accountID
                }) else { throw RuntimeActivationError.conflictingPlan }
                declarations.append(job.declaration)
            }
        }
        return try .init(macID: inventory.macID, installationID: inventory.installationID, revision: inventory.revision,
            bundlePath: inventory.bundlePath, releaseDigest: inventory.releaseDigest,
            accounts: inventory.accounts.contains(account) ? inventory.accounts : inventory.accounts + [account],
            services: declarations, formatVersion: inventory.formatVersion)
    }
    var encoded: Data { get throws {
        var fields: [UInt64: CBORValue] = [0: .unsigned(formatVersion), 1: .bytes(try reference.encoded),
            2: .text(bundlePath), 3: .bytes(host.canonicalBytes), 4: .bytes(transport.canonicalBytes)]
        if let gatewaySettingsHost { fields[5] = .bytes(try gatewaySettingsHost.encoded) }
        if let phoneUpdateSchedulingVersion {
            fields[6] = phoneRoutingVersion.map(CBORValue.unsigned) ?? .null
            fields[7] = phoneAuditVersion.map(CBORValue.unsigned) ?? .null
            fields[8] = .unsigned(phoneUpdateSchedulingVersion)
        } else if let phoneAuditVersion {
            fields[6] = phoneRoutingVersion.map(CBORValue.unsigned) ?? .null
            fields[7] = .unsigned(phoneAuditVersion)
        } else if let phoneRoutingVersion { fields[6] = .unsigned(phoneRoutingVersion) }
        return try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    } }
    // Decoding depends only on the bytes: its nested decoders and validation read no clock, file, account or
    // process state. A plan can reach 256 KiB, so few are kept.
    private static let decodings = PureResultMemo<Data, RuntimeActivationPlan>(capacity: 8)
    static func decode(_ bytes: Data) throws -> Self {
        try decodings.value(for: bytes) { try decodeUncached(bytes) }
    }
    private static func decodeUncached(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits),
              case .unsigned(let version) = f[0], supportedVersions.contains(version),
              Set(f.keys) == Set(UInt64(0)...(version + 3)),
              case .bytes(let reference) = f[1], case .text(let path) = f[2],
              case .bytes(let host) = f[3], case .bytes(let transport) = f[4] else { throw RuntimeActivationError.invalidPlan }
        let gateway: GatewaySettingsConsumerHostConfiguration?
        if version == 1 { gateway = nil }
        else {
            guard case .bytes(let metadata) = f[5] else { throw RuntimeActivationError.invalidPlan }
            gateway = try .decode(metadata)
        }
        let phoneRoutingVersion: UInt64?, phoneAuditVersion: UInt64?, phoneUpdateSchedulingVersion: UInt64?
        if version >= 3 {
            switch f[6] {
            case .unsigned(let selected) where selected == PhoneRoutingReleaseContract.version: phoneRoutingVersion = selected
            case .null where version >= 4: phoneRoutingVersion = nil
            default: throw RuntimeActivationError.invalidPlan
            }
        } else { phoneRoutingVersion = nil }
        if version >= 4 {
            switch f[7] {
            case .unsigned(let selected) where selected == PhoneAuditReleaseContract.version: phoneAuditVersion = selected
            case .null where version >= 5: phoneAuditVersion = nil
            default: throw RuntimeActivationError.invalidPlan
            }
        } else { phoneAuditVersion = nil }
        if version >= 5 {
            guard case .unsigned(let selected) = f[8], selected == PhoneUpdateSchedulingReleaseContract.version else {
                throw RuntimeActivationError.invalidPlan
            }
            phoneUpdateSchedulingVersion = selected
        } else { phoneUpdateSchedulingVersion = nil }
        let result = try Self(reference: .decode(reference), bundlePath: path, host: .decode(host),
            transport: .decode(transport), gatewaySettingsHost: gateway,
            phoneRoutingVersion: phoneRoutingVersion, phoneAuditVersion: phoneAuditVersion,
            phoneUpdateSchedulingVersion: phoneUpdateSchedulingVersion)
        guard try result.encoded == bytes else { throw RuntimeActivationError.invalidPlan }; return result
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 262144, maxDepth: 1, maxItems: 19) } }

    /// Retains published values after validating their account and release scope.
    static func retainingPublished(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
                                  reference: RuntimeMaterialReference, inventory: InstallationInventory,
                                  installedRelease: SignedReleaseEvidence, command: AuthorityCommandStartupConfiguration,
                                  transport: TransportPairingStartupConfiguration,
                                  host existingHost: InstalledAuthorityCommandConfiguration?,
                                  gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration?,
                                  clients: RuntimeActivationClients) throws -> Self {
        try RuntimeConfigurationBundle.validateScope(account: account, initialization: initialization,
            reference: reference, inventory: inventory)
        try inventory.compareRelease(installedRelease)
        let host: InstalledAuthorityCommandConfiguration
        if let existingHost {
            guard existingHost.command.canonicalBytes == command.canonicalBytes else { throw RuntimeActivationError.conflictingPlan }
            host = existingHost
        } else {
            let label = try RuntimePreparationPaths(accountID: account.accountID).namespace + ".authority"
            let prepared = try InstalledAuthorityCommandConfiguration(machineDirectory: MachineBootstrap.machineDirectory,
                installationID: inventory.installationID, releaseDigest: inventory.releaseDigest,
                codePolicy: account.initialAuthority.codePolicy, command: command, label: label,
                plistName: label + ".plist", jobPlacement: .systemAccount)
            host = try reference.serviceActivity == nil ? prepared : prepared.enablingGatewaySettingsControl(release: installedRelease)
        }
        try host.validateRelease(installedRelease, bundlePath: inventory.bundlePath)
        let maximum = command.presence.wake.request.service.maximumPayloadBytes
        let routing = try PhoneRoutingReleaseContract.selectedVersion(in: installedRelease, policy: host.codePolicy,
            nativeHosts: reference.serviceActivity != nil, maximumPayloadBytes: maximum)
        let audit = try PhoneAuditReleaseContract.selectedVersion(in: installedRelease, policy: host.codePolicy,
            nativeHosts: reference.serviceActivity != nil, maximumPayloadBytes: maximum)
        let update = try PhoneUpdateSchedulingReleaseContract.selectedVersion(in: installedRelease, policy: host.codePolicy,
            nativeHosts: reference.serviceActivity != nil, maximumPayloadBytes: maximum)
        if reference.auditDeliveryVersion != nil {
            try PhoneAuditReleaseContract.validateDelivery(installedRelease, policy: host.codePolicy)
        }
        let plan = try Self(reference: reference, bundlePath: inventory.bundlePath, host: host, transport: transport,
            gatewaySettingsHost: gatewaySettingsHost, phoneRoutingVersion: routing, phoneAuditVersion: audit,
            phoneUpdateSchedulingVersion: update)
        try plan.validate(account: account, reference: reference)
        _ = try plan.configurationBundle(account: account, initialization: initialization, inventory: inventory, clients: clients)
        return plan
    }
    func requireConfigurationScope(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
        inventory: InstallationInventory) throws {
        try validate(account: account, reference: reference)
        guard bundlePath == inventory.bundlePath else { throw RuntimeActivationError.changedScope }
        try RuntimeConfigurationBundle.validateScope(account: account, initialization: initialization,
            reference: reference, inventory: inventory)
    }
    func configurationBundle(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
                             inventory: InstallationInventory, clients: RuntimeActivationClients) throws -> RuntimeConfigurationBundle {
        try .init(retaining: self, account: account, initialization: initialization, inventory: inventory, clients: clients)
    }
}

/// Historical registration progress. It is not a current launchd or process health result.
struct RuntimeActivationState {
    final class Plan: Sendable {
        let value: RuntimeActivationPlan
        var accountID: Data { value.reference.services.accountID }
        var macID: Data { value.reference.services.macID }
        var materialID: Data { value.reference.materialID }
        @inline(never)
        init(_ value: RuntimeActivationPlan) { self.value = value }
        @inline(never)
        init(encoded: Data) throws { value = try RuntimeActivationPlan.decode(encoded) }
    }
    private let retainedPlan: Plan?
    var plan: RuntimeActivationPlan? { retainedPlan?.value }
    let jobsRegistered: Bool
    init(plan: RuntimeActivationPlan?, jobsRegistered: Bool) {
        retainedPlan = plan.map(Plan.init)
        self.jobsRegistered = jobsRegistered
    }
    init(retainedPlan: Plan, jobsRegistered: Bool) {
        self.retainedPlan = retainedPlan
        self.jobsRegistered = jobsRegistered
    }
}
