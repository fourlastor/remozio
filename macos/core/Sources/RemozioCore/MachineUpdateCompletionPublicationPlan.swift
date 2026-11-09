import Foundation
import RemozioProtocol

/// Exact completion operands only. This value grants no file writer, health proof, metadata retirement or admission authority.
struct MachineUpdateCompletionPublicationPlan: CustomStringConvertible, CustomDebugStringConvertible {
    enum File: Int, Codable, CaseIterable, Sendable {
        case host, transport, gateway, presence, pairing, frontend
        case authorityBackend, transportBackend, gatewayBackend, backendCommit
        case authorityJob
        var isBackend: Bool { (Self.authorityBackend.rawValue...Self.backendCommit.rawValue).contains(rawValue) }
        func artifact(ownerUID: UInt32, accountID: Data) -> AdministrativeSetupPublication.File {
            switch self {
            case .host: .commandHost
            case .transport: .transportConfiguration
            case .gateway: .gatewaySettingsHost
            case .presence: .presenceClient(ownerUID: ownerUID)
            case .pairing: .pairingClient(ownerUID: ownerUID)
            case .frontend: .frontendClient(ownerUID: ownerUID)
            case .authorityBackend: .authorityGatewayRuntime
            case .transportBackend: .transportGatewayRuntime
            case .gatewayBackend: .gatewayConfiguration
            case .backendCommit: .gatewayRuntimeCommit
            case .authorityJob: .accountJob(accountID: accountID, role: .authority)
            }
        }
    }
    struct Entry: Equatable, Sendable {
        let accountID: Data
        let ownerUID: UInt32
        let file: File
        let startup: Data
        let completion: Data
        var artifact: AdministrativeSetupPublication.File { file.artifact(ownerUID: ownerUID, accountID: accountID) }
        func requireActual(_ bytes: Data, state: MachineUpdatePublicationProgress.State) throws {
            guard state == .pending && bytes == startup || state == .writing && (bytes == startup || bytes == completion) ||
                  state == .published && bytes == completion else { throw InstalledAuthorityCommandError.changedConfiguration }
        }
    }
    let inventory: InstallationInventory
    let entries: [Entry]
    private let intent: MachineUpdateCompletionIntentArchive
    var description: String { "MachineUpdateCompletionPublicationPlan(redacted)" }
    var debugDescription: String { description }

    /// Checks the caller's fresh source and exact recorded account boundaries before rebuilding file operands.
    init(snapshot: MachineUpdateCompletionSnapshot, candidate: SignedReleaseEvidence,
         currentSourceDigest: Data, boundaries: [AuthorityJournal.MachineUpdatePolicyBoundary]) throws {
        let profile = try MachineUpdateCompletionPolicyProfile(snapshot: snapshot, candidate: candidate,
            currentSourceDigest: currentSourceDigest)
        try profile.requireRecorded(boundaries)
        try self.init(retainedConfiguration: snapshot.restart.configuration, retainedBackend: snapshot.restart.backend,
            intent: snapshot.intent, candidate: candidate)
    }

    /// Rebuilds retained operands only. Native callers must separately verify the actual machine frame and paired policy boundaries.
    init(retainedConfiguration configuration: MachineUpdateConfigurationEpoch.Archive,
        retainedBackend backend: MachineUpdateBackendEpoch.Archive, intent: MachineUpdateCompletionIntentArchive,
        candidate: SignedReleaseEvidence) throws {
        try configuration.validate(); try backend.validate(epoch: configuration); try intent.validate()
        let originalInventory = try InstallationInventory.decode(configuration.artifact(5), expectedMacID: configuration.record.macID)
        let activation = try MachineUpdateActivationRecord.decode(intent.record.activation)
        let originalActivation = try MachineUpdateActivationRecord.decode(configuration.artifact(8))
        try activation.requireScope(candidate: UpdateSchedulingCandidateRecord.decode(configuration.artifact(6)),
            inventory: originalInventory, admission: UpdateAdmissionRegistrationRecord.decode(configuration.artifact(7)))
        guard intent.policyMarkersRecorded, configuration.record.publication?.complete == true,
              backend.record.publication?.complete == true, activation.policyPreflightDigest == originalActivation.policyPreflightDigest,
              activation.attemptID == configuration.record.activationAttempt,
              intent.record.sourceInventoryRevision == originalInventory.revision,
              intent.record.sourceMachineDigest == backend.record.currentSourceDigest,
              try intent.record.epochs == MachineUpdatePolicyIntentRecord.EpochScope(configuration: configuration.record, backend: backend.record),
              try configuration.record.updateID == DurableReleasePreparation.digest(candidate),
              try configuration.record.installedReleaseDigest == InstallationInventory.digest(candidate),
              intent.record.accounts.count == configuration.record.accounts.count else { throw PreparationStoreError.staleRevision }
        for account in intent.record.accounts {
            guard let row = configuration.record.accounts.first(where: { $0.accountID == account.accountID }),
                  account.ownerUID == row.ownerUID, account.sourceDigest == row.sourceDigest,
                  account.inInventory == originalInventory.accounts.contains(where: { $0.accountID == account.accountID }),
                  (account.policyRecordID != nil) == row.configurationPublished else { throw PreparationStoreError.staleRevision }
        }
        let target = try InstallationInventory.decode(intent.record.targetInventory, expectedMacID: originalInventory.macID)
        let expected = try InstallationInventory(macID: originalInventory.macID, installationID: originalInventory.installationID,
            revision: target.revision, bundlePath: originalInventory.bundlePath, releaseDigest: InstallationInventory.digest(candidate),
            accounts: originalInventory.accounts, services: originalInventory.services, formatVersion: originalInventory.formatVersion)
        guard target == expected else { throw PreparationStoreError.staleRevision }
        try target.compareRelease(candidate)
        self.inventory = target; self.intent = intent
        var selected: [Entry] = []
        for row in configuration.record.accounts where row.configurationPublished {
            guard let config = try configuration.configuration(accountID: row.accountID),
                  let policy = intent.policies.first(where: { $0.binding.accountID == row.accountID }),
                  policy.policyRecorded, let committed = policy.committedPolicy,
                  policy.binding == config.completion.binding,
                  try policy.sourcePolicy.snapshot() == configuration.policy(accountID: row.accountID),
                  config.startup.policyStage == .startup, config.completion.policyStage == .completion,
                  try committed.snapshot().policy.bytes == config.completion.host.codePolicy.bytes else {
                throw PreparationStoreError.staleRevision
            }
            try policy.binding.requireCompletionPolicy(committed.snapshot().policy)
            func append(_ file: File, startup: Data, completion: Data) throws {
                guard !startup.isEmpty, !completion.isEmpty,
                      startup.count <= ProtectedServiceConfiguration.maximumBytes,
                      completion.count <= ProtectedServiceConfiguration.maximumBytes else { throw PreparationStoreError.capacity }
                selected.append(.init(accountID: row.accountID, ownerUID: row.ownerUID, file: file,
                    startup: startup, completion: completion))
            }
            for file in MachineUpdatePublicationProgress.File.allCases {
                guard let selectedFile = File(rawValue: file.rawValue) else { throw PreparationStoreError.corruptRecord }
                try append(selectedFile, startup: config.bytes(file, target: true),
                    completion: Self.bytes(config.completion, file: file))
            }
            if let capture = try backend.capture(accountID: row.accountID) {
                guard let startup = capture.startup, let completion = capture.completion,
                      startup.policyStage == .startup, completion.policyStage == .completion,
                      try startup.configuration.encoded == config.startup.encoded,
                      try completion.configuration.encoded == config.completion.encoded else {
                    throw PreparationStoreError.staleRevision
                }
                let pair = try GatewayRuntimeExtensions(release: completion)
                for file in MachineUpdateBackendPublicationProgress.File.allCases {
                    let target: Data
                    switch file {
                    case .authority: target = try pair.authority.encoded
                    case .transport: target = try pair.transport.encoded
                    case .gateway: target = completion.gateway.canonicalBytes
                    case .commit: target = try GatewayRuntimeCommit(release: completion, pair: pair).encoded
                    }
                    guard let selectedFile = File(rawValue: File.authorityBackend.rawValue + file.rawValue) else {
                        throw PreparationStoreError.corruptRecord
                    }
                    try append(selectedFile, startup: capture.bytes(file, target: true), completion: target)
                }
            }
            if config.completion.host.installedReadinessEnabled {
                try MachineUpdateAuthorityReadinessJobTransition.requireRelease(candidate, policy: config.completion.host.codePolicy)
                let job = try MachineUpdateAuthorityReadinessJobTransition(startup: config.startup.host,
                    completion: config.completion.host, bundlePath: target.bundlePath)
                try append(.authorityJob, startup: job.startup.bytes, completion: job.completion.bytes)
            }
        }
        guard selected.count <= 1408,
              Set(selected.map { $0.accountID.base64EncodedString() + ":" + String($0.file.rawValue) }).count == selected.count,
              Set(selected.map(\.accountID)) == Set(intent.policies.map { $0.binding.accountID }) else { throw PreparationStoreError.staleRevision }
        entries = selected
        _ = try fingerprint
    }
    private static func bytes(_ plan: RuntimeReleaseConfigurationPlan, file: MachineUpdatePublicationProgress.File) throws -> Data {
        switch file {
        case .host: plan.host.canonicalBytes
        case .transport: plan.transport.canonicalBytes
        case .gateway: try plan.gateway.encoded
        case .presence: plan.clients.presence.canonicalBytes
        case .pairing: plan.clients.pairing.canonicalBytes
        case .frontend: plan.clients.frontend.canonicalBytes
        }
    }
    var completionIntentDigest: Data { get throws { MachineUpdateActivationRecord.digest(try intent.record.encoded) } }
    var sourceInventoryDigest: Data { get throws { try MachineUpdateActivationRecord.decode(intent.record.activation).inventoryDigest } }
    var fingerprint: Data { get throws {
        let rows = entries.map { entry in
            CBORValue.array([.bytes(entry.accountID), .unsigned(UInt64(entry.ownerUID)), .unsigned(UInt64(entry.file.rawValue)),
                .bytes(MachineUpdateActivationRecord.digest(entry.startup)), .bytes(MachineUpdateActivationRecord.digest(entry.completion))])
        }
        let bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(try intent.record.encoded),
            2: .bytes(MachineUpdateActivationRecord.digest(inventory.canonicalBytes)), 3: .array(rows)]),
            limits: CBORLimits(maxBytes: 524288, maxDepth: 3, maxItems: 16384))
        return MachineUpdateActivationRecord.digest(Data("Remozio/CompletionPublicationPlan/v1\0".utf8) + bytes)
    } }
}
