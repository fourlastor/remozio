import CryptoKit
import Foundation

/// Closed source/target file bindings only. Neither construction nor a file snapshot permits activation.
struct RuntimeAuditUpgradeArtifactPlan: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    enum Directory: UInt64, CaseIterable, Hashable { case runtime, services, clients, jobs, imports }
    struct Variant: Equatable { let source: Data?; let target: Data? }
    struct Entry {
        let directory: Directory
        let file: AdministrativeSetupPublication.File
        let variants: [Variant]
        let expectedIdentity: ProtectedStorageLease.DirectoryIdentity?
        var key: String { "\(directory.rawValue):" + file.name }
    }
    struct GatewayInputs {
        let material: GatewayPreparationMaterial?
        let reference: GatewayMaterialReference?
        let journal: GatewayJournalPreparationState
        let activation: GatewayRuntimeActivationState
        let settings: GatewayRuntimeSettingsState
        let service: GatewayJournalSetupServiceConfiguration?
        let fence: GatewayRuntimeSettingsFence?
        static var empty: Self { .init(material: nil, reference: nil, journal: .init(intent: nil, initialized: false),
            activation: .init(plan: nil, filesPublished: false, jobRegistered: false), settings: .empty, service: nil, fence: nil) }
    }
    struct GatewayTarget {
        let material: GatewayPreparationMaterial?
        let reference: GatewayMaterialReference?
        let journal: GatewayJournalPreparationState
        let activation: GatewayRuntimeActivationState
        let settings: GatewayRuntimeSettingsState
        let service: GatewayJournalSetupServiceConfiguration?
        let fence: GatewayRuntimeSettingsFence?
    }
    let preparation: RuntimeAuditUpgradePreparation
    let sourceAccount: AccountPreparationIntent
    let sourceInitialization: AuthorityInitializationIntent
    let sourceInventory: InstallationInventory
    let sourceJobsRegistered: Bool
    let sourceGateway: GatewayInputs
    let sourceImport: RuntimeAuditUpgradeImportPreparation?
    let entries: [Entry]
    let gateway: GatewayTarget
    var description: String { "RuntimeAuditUpgradeArtifactPlan(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    init(_ preparation: RuntimeAuditUpgradePreparation, material: RuntimePreparationMaterial,
         account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
         inventory: InstallationInventory, clients: RuntimeActivationClients,
         installedRelease: SignedReleaseEvidence, sourceJobsRegistered: Bool = true, gateway input: GatewayInputs = .empty,
         imported: RuntimeAuditUpgradeImportPreparation? = nil,
         transportRelayReference: RelayRunCredentialReference? = nil) throws {
        let old = preparation.source, next = preparation.target, services = preparation.intent.source.services
        guard try material.reference == preparation.intent.source,
              let transport = services.claims.first(where: { $0.role == .transport }),
              let gatewayClaim = services.claims.first(where: { $0.role == .gateway }),
              let activity = preparation.intent.target.serviceActivity else { throw RuntimePreparationError.changedScope }
        let targetMaterial = try RuntimeAuditMaterialUpgrade.prepare(material: material, expected: preparation.intent.source,
            account: account, activity: activity, installedRelease: installedRelease,
            policy: old.host.codePolicy, maximumPayloadBytes: old.host.command.presence.wake.request.service.maximumPayloadBytes)
        guard try targetMaterial.reference == preparation.intent.target else { throw RuntimePreparationError.changedScope }
        let sourceBundle = try old.configurationBundle(account: account, initialization: initialization, inventory: inventory, clients: clients)
        _ = try next.configurationBundle(account: account, initialization: initialization, inventory: inventory, clients: clients)
        var entries: [Entry] = []
        func add(_ directory: Directory, _ file: AdministrativeSetupPublication.File, _ source: Data?, _ target: Data?,
                 optional: Bool = false, alternatives: [Variant] = [],
                 expectedIdentity: ProtectedStorageLease.DirectoryIdentity? = nil) throws {
            try file.validate()
            var values = [Variant(source: source, target: target)] + alternatives
            if optional { values.append(.init(source: nil, target: nil)) }
            var unique: [Variant] = []
            for value in values {
                guard value.source.map({ !$0.isEmpty && $0.count <= ProtectedServiceConfiguration.maximumBytes }) ?? true,
                      value.target.map({ !$0.isEmpty && $0.count <= ProtectedServiceConfiguration.maximumBytes }) ?? true else {
                    throw RuntimePreparationError.invalidRecord
                }
                if let existing = unique.first(where: { $0.source == value.source }) {
                    guard existing.target == value.target else { throw RuntimePreparationError.changedScope }
                } else { unique.append(value) }
            }
            let entry = Entry(directory: directory, file: file, variants: unique, expectedIdentity: expectedIdentity)
            guard !entries.contains(where: { $0.key == entry.key }) else { throw RuntimePreparationError.invalidRecord }
            entries.append(entry)
        }
        try add(.runtime, .runtimeRecord, material.encoded, targetMaterial.encoded)
        try add(.runtime, .auditUpgradeMaterial(intentID: preparation.intent.id), targetMaterial.encoded, targetMaterial.encoded, optional: true)
        try add(.runtime, .commandConfiguration, old.host.command.canonicalBytes, next.host.command.canonicalBytes)
        try add(.runtime, .commandHost, old.host.canonicalBytes, next.host.canonicalBytes, optional: !sourceJobsRegistered)
        try add(.runtime, .elevationPolicy, account.policyBytes, account.policyBytes)
        try add(.services, .transportConfiguration, old.transport.canonicalBytes, next.transport.canonicalBytes)
        try add(.services, .transportIdentity(ownerUID: transport.number, groupID: transport.number),
            material.transportIdentity, material.transportIdentity)
        try add(.services, .gatewaySettingsHost, old.gatewaySettingsHost?.encoded, next.gatewaySettingsHost?.encoded)
        try add(.clients, .presenceClient(ownerUID: account.ownerUID), sourceBundle.presenceClient.canonicalBytes, sourceBundle.presenceClient.canonicalBytes)
        try add(.clients, .pairingClient(ownerUID: account.ownerUID), sourceBundle.pairingClient.canonicalBytes, sourceBundle.pairingClient.canonicalBytes)
        try add(.clients, .frontendClient(ownerUID: account.ownerUID), sourceBundle.frontendClient.canonicalBytes, sourceBundle.frontendClient.canonicalBytes)
        for (before, after) in [(old.authorityJob, next.authorityJob), (old.transportJob, next.transportJob)] {
            try add(.jobs, .accountJob(accountID: account.accountID, role: before.declaration.role), before.bytes, after.bytes, optional: !sourceJobsRegistered)
        }

        if let reference = input.reference {
            guard try input.material?.reference == reference else { throw GatewayPreparationError.missingMaterial }
        }
        let targetGatewayMaterial = try input.material.map { try $0.preparingAuditUpgrade(preparation, expected: $0.reference) }
        let targetReference = try input.reference == nil ? nil : targetGatewayMaterial?.reference
        try add(.runtime, .gatewayMaterial, input.material?.encoded, targetGatewayMaterial?.encoded)
        let privateFilesEstablished = input.journal.intent != nil
        try add(.services, .gatewayProvider(ownerUID: gatewayClaim.number, groupID: gatewayClaim.number),
            input.material?.providerJSON, targetGatewayMaterial?.providerJSON, optional: !privateFilesEstablished)
        try add(.services, .gatewayReceiptKey(ownerUID: gatewayClaim.number, groupID: gatewayClaim.number),
            input.material?.receiptKeyRecord, targetGatewayMaterial?.receiptKeyRecord, optional: !privateFilesEstablished)
        try add(.services, .transportWakeKey(ownerUID: transport.number, groupID: transport.number),
            input.material?.wakeKeyRecord.encode(), targetGatewayMaterial?.wakeKeyRecord.encode(), optional: !privateFilesEstablished)
        let targetJournal: GatewayJournalPreparationState
        if let retained = input.journal.intent {
            guard let reference = input.reference, retained.material == reference,
                  let targetReference else { throw GatewayPreparationError.changedScope }
            try retained.validate(foreground: old, inventory: inventory)
            targetJournal = try .init(intent: .init(id: retained.id, material: targetReference,
                configuration: retained.configuration, files: retained.files), initialized: input.journal.initialized)
        } else {
            guard !input.journal.initialized else { throw GatewayPreparationError.changedScope }
            targetJournal = .init(intent: nil, initialized: false)
        }
        let targetService: GatewayJournalSetupServiceConfiguration?
        if let service = input.service {
            guard service.intent == input.journal.intent, let intent = targetJournal.intent else { throw GatewayPreparationError.changedScope }
            try service.validate(foreground: old, inventory: inventory, release: installedRelease)
            targetService = try .init(intent: intent, bundlePath: service.bundlePath, codePolicy: service.codePolicy,
                maximumLifetimeMilliseconds: service.maximumLifetimeMilliseconds)
        } else { targetService = nil }
        try add(.services, .gatewayJournalService, input.service?.canonicalBytes, targetService?.canonicalBytes)
        try add(.services, .gatewayJournalSetup, nil, nil)
        if let service = input.service, let targetService {
            let job = try GatewayJournalSetupJobManifest(configuration: service)
            let nextJob = try GatewayJournalSetupJobManifest(configuration: targetService)
            try add(.jobs, .gatewayJournalJob(accountID: account.accountID, intentID: service.intent.id), job.bytes, nextJob.bytes, optional: true)
        } else if let intent = input.journal.intent {
            try add(.jobs, .gatewayJournalJob(accountID: account.accountID, intentID: intent.id), nil, nil)
        }
        let targetActivation: GatewayRuntimeActivationState, targetSettings: GatewayRuntimeSettingsState
        let targetFence: GatewayRuntimeSettingsFence?
        if let activation = input.activation.plan {
            guard let material = input.material, let reference = input.reference,
                  !input.activation.jobRegistered || input.activation.filesPublished,
                  input.activation.filesPublished || (input.settings.active == nil && input.settings.pending == nil) else { throw GatewayPreparationError.changedScope }
            let gateway = try preparation.gateway(material: material, expected: reference,
                journal: input.journal, activation: activation, inventory: inventory)
            let settings = try RuntimeAuditUpgradeSettingsPreparation(preparation, state: input.settings,
                journal: input.journal, activation: activation, gateway: gateway, inventory: inventory)
            targetActivation = .init(plan: gateway.activation, filesPublished: input.activation.filesPublished, jobRegistered: input.activation.jobRegistered)
            targetSettings = settings.target
            targetFence = try input.fence.map { try settings.preparingFence($0).target }
            let active = settings.sourceActive, selected = settings.targetActive
            let base: [(AdministrativeSetupPublication.File, Data?, Data?)] = try [
                (.gatewayConfiguration, active.gateway.canonicalBytes, selected.gateway.canonicalBytes),
                (.authorityGatewayRuntime, active.pair.authority.encoded, selected.pair.authority.encoded),
                (.transportGatewayRuntime, active.pair.transport.encoded, selected.pair.transport.encoded),
                (.gatewayRuntimeCommit, active.commit.encoded, selected.commit.encoded),
                (.gatewaySettingsRevision, active.revision?.encoded, selected.revision?.encoded)]
            for (file, before, after) in base {
                var alternatives: [Variant] = []
                if let pending = settings.sourcePending, let nextPending = settings.targetPending {
                    guard let source = pending.artifacts.first(where: { $0.file.name == file.name }),
                          let target = nextPending.artifacts.first(where: { $0.file.name == file.name }) else { throw GatewayPreparationError.changedScope }
                    alternatives.append(.init(source: source.selected, target: target.selected))
                }
                try add(.services, file, before, after, optional: !input.activation.filesPublished, alternatives: alternatives)
            }
            try add(.jobs, .accountJob(accountID: account.accountID, role: .notificationGateway), activation.gatewayJob.bytes,
                gateway.activation.gatewayJob.bytes, optional: !input.activation.filesPublished)
        } else {
            guard !input.activation.filesPublished, !input.activation.jobRegistered,
                  input.settings.active == nil, input.settings.pending == nil, input.settings.phase == nil,
                  input.fence == nil else { throw GatewayPreparationError.changedScope }
            targetActivation = .init(plan: nil, filesPublished: false, jobRegistered: false); targetSettings = .empty; targetFence = nil
            for file: AdministrativeSetupPublication.File in [.gatewayConfiguration, .authorityGatewayRuntime,
                .transportGatewayRuntime, .gatewayRuntimeCommit, .gatewaySettingsRevision] { try add(.services, file, nil, nil) }
            try add(.jobs, .accountJob(accountID: account.accountID, role: .notificationGateway), nil, nil)
        }
        try add(.services, .gatewaySettingsFence, input.fence?.encoded, targetFence?.encoded)
        self.gateway = .init(material: targetGatewayMaterial, reference: targetReference, journal: targetJournal,
            activation: targetActivation, settings: targetSettings, service: targetService, fence: targetFence)

        if let imported {
            let expected = imported.intent, record = imported.source
            guard expected.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)),
                  record.accountID == account.accountID, record.operationID == expected.operationID,
                  record.revision == expected.revision, record.phase == expected.phase.rawValue,
                  record.digest == Data(SHA256.hash(data: try expected.bytes)),
                  record.portableVersion == expected.originalPortableVersion,
                  try record.settingsVersion == expected.recipe.settingsVersion else { throw RuntimePreparationError.changedScope }
            if let source = imported.sourceMaterial {
                let target = try source.preparingAuditUpgrade(preparation, expected: source.reference)
                guard try target.encoded == imported.targetMaterial?.encoded,
                      try record.runCredential?.reference == (record.runCredential == nil ? nil : source.reference),
                      try imported.targetReference == (record.runCredential == nil ? nil : target.reference) else {
                    throw RuntimePreparationError.changedScope
                }
            } else {
                guard imported.targetMaterial == nil, imported.targetReference == nil, record.runCredential == nil else {
                    throw RuntimePreparationError.changedScope
                }
            }
            let preserved: [(AdministrativeSetupPublication.File, SharedSetupImportRelayStorage.Snapshot?)] = [
                (.importRelayPlan(accountID: account.accountID), record.relay),
                (.importRelayProvisioning(accountID: account.accountID), record.relayProvisioning),
                (.importAccessApplication(accountID: account.accountID), record.accessApplication),
                (.importDNSRecord(accountID: account.accountID), record.dnsRecord)]
            for (file, snapshot) in preserved {
                let bytes = imported.preservedFiles.first(where: { $0.file.name == file.name })?.bytes
                guard bytes.map({ Data(SHA256.hash(data: $0)) }) == snapshot?.digest else { throw RuntimePreparationError.changedScope }
                try add(.imports, file, bytes, bytes, expectedIdentity: snapshot?.identity)
            }
            try add(.imports, .importRelayRunReference(accountID: account.accountID), record.runCredential?.reference.encoded, imported.targetReference?.encoded,
                expectedIdentity: record.runCredential?.identity)
            try add(.runtime, .relayRunMaterial, imported.sourceMaterial?.encoded, imported.targetMaterial?.encoded)
            if let published = transportRelayReference {
                guard published == record.runCredential?.reference, let port = old.transport.relayPort else { throw RuntimePreparationError.changedScope }
                _ = try RelayRunCredentialReference.decodeForTransport(published.encoded, runtime: preparation.intent.source,
                    relayPort: port)
            }
            try add(.services, .transportRelayReference, transportRelayReference?.encoded,
                transportRelayReference == nil ? nil : imported.targetReference?.encoded)
            let token = imported.sourceMaterial?.withCredentialBytes { Data($0) }
            try add(.services, .transportTunnelToken(ownerUID: transport.number, groupID: transport.number), token, token,
                optional: transportRelayReference == nil)
        } else {
            guard transportRelayReference == nil else { throw RuntimePreparationError.changedScope }
            for file: AdministrativeSetupPublication.File in [.importRelayPlan(accountID: account.accountID),
                .importRelayProvisioning(accountID: account.accountID), .importAccessApplication(accountID: account.accountID),
                .importDNSRecord(accountID: account.accountID), .importRelayRunReference(accountID: account.accountID)] {
                try add(.imports, file, nil, nil)
            }
            try add(.runtime, .relayRunMaterial, nil, nil)
            try add(.services, .transportRelayReference, nil, nil)
            try add(.services, .transportTunnelToken(ownerUID: transport.number, groupID: transport.number), nil, nil)
        }
        self.preparation = preparation; self.entries = entries
        sourceAccount = account; sourceInitialization = initialization; sourceInventory = inventory
        sourceGateway = input; sourceImport = imported; self.sourceJobsRegistered = sourceJobsRegistered
    }
}
