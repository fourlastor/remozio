import Darwin
import Foundation

enum MachineUpdateConfigurationEpoch {
    // A nonempty global key avoids SQLite's NULL interpretation of a zero-length bound buffer.
    static let global = MachineUpdateConfigurationEpochRecord.globalAccount
    typealias PolicyCapture = MachineUpdatePolicyCapture
    struct Configuration {
        let source: RuntimeReleaseConfigurationSource
        let startup: RuntimeReleaseConfigurationPlan
        let completion: RuntimeReleaseConfigurationPlan
        func requireSource(_ machine: MachineUpdateRestartSource, policy: AuthorityCodePolicySnapshot,
                           candidate: SignedReleaseEvidence) throws {
            guard startup.policyStage == .startup, completion.policyStage == .completion,
                  startup.binding == completion.binding, try startup.sourceDigest == source.digest,
                  completion.sourceDigest == startup.sourceDigest else { throw RuntimePreparationError.changedScope }
            for plan in [startup, completion] {
                try plan.requireSourceForPublication(machine, currentPolicy: policy, candidate: candidate,
                    host: source.host, transport: source.transport, gateway: source.gateway, clients: source.clients)
            }
        }
    }
    struct Artifact: Equatable {
        let kind: Int64
        let account: Data
        let bytes: Data
    }
    private final class ArchiveCache {
        private let lock = NSLock()
        private var validated = false
        private var configurations: [Data: Configuration] = [:]
        private var policies: [Data: AuthorityCodePolicySnapshot] = [:]
        func isValidated() -> Bool { lock.withLock { validated } }
        func markValidated() { lock.withLock { validated = true } }
        func configuration(_ account: Data) -> Configuration? { lock.withLock { configurations[account] } }
        func policy(_ account: Data) -> AuthorityCodePolicySnapshot? { lock.withLock { policies[account] } }
        func retain(_ configuration: Configuration, account: Data) {
            lock.withLock { if configurations.count < 128 { configurations[account] = configuration } }
        }
        func retain(_ policy: AuthorityCodePolicySnapshot, account: Data) {
            lock.withLock { if policies.count < 128 { policies[account] = policy } }
        }
    }
    struct Archive {
        let record: MachineUpdateConfigurationEpochRecord
        let artifacts: [Artifact]
        private let cache: ArchiveCache
        private let decodedValues: PreparationImmutableTupleDecodeCache<Configuration>
        init(record: MachineUpdateConfigurationEpochRecord, artifacts: [Artifact],
            decodedValues: PreparationImmutableTupleDecodeCache<Configuration> = .init()) {
            self.record = record; self.artifacts = artifacts; cache = ArchiveCache(); self.decodedValues = decodedValues
        }
        func artifact(_ kind: Int64, account: Data = global) throws -> Data {
            guard let value = artifacts.first(where: { $0.kind == kind && $0.account == account }) else { throw PreparationStoreError.corruptRecord }
            return value.bytes
        }
        func configuration(accountID: Data) throws -> Configuration? {
            guard let account = record.accounts.first(where: { $0.accountID == accountID }) else { throw PreparationStoreError.notFound }
            guard account.configurationPublished else { return nil }
            if let value = cache.configuration(accountID) { return value }
            let inputs = try [artifact(1, account: accountID), artifact(2, account: accountID), artifact(3, account: accountID)]
            let value = try decodedValues.value(accountID: accountID, inputs: inputs) {
                try Configuration(source: .decode(inputs[0]), startup: .decode(inputs[1]), completion: .decode(inputs[2]))
            }
            cache.retain(value, account: accountID); return value
        }
        func policy(accountID: Data) throws -> AuthorityCodePolicySnapshot? {
            guard let account = record.accounts.first(where: { $0.accountID == accountID }) else { throw PreparationStoreError.notFound }
            guard let revision = account.policyRevision else { return nil }
            if let value = cache.policy(accountID) { return value }
            let bytes: Data
            if record.carriesProvenance {
                guard let policy = try MachineUpdateConfigurationAccountOperand.decode(artifact(4, account: accountID), accountID: accountID).policy else {
                    throw PreparationStoreError.corruptRecord
                }
                bytes = policy
            } else { bytes = try artifact(4, account: accountID) }
            let value = try AuthorityCodePolicySnapshot.decodeStored(bytes, revision: revision)
            if record.carriesProvenance, try value.storedBytes != bytes { throw PreparationStoreError.corruptRecord }
            cache.retain(value, account: accountID); return value
        }
        func provisioningHistory() throws -> MachineUpdateProvisioningHistory? {
            try validate()
            return try decodedProvisioningHistory()
        }
        private func decodedProvisioningHistory() throws -> MachineUpdateProvisioningHistory? {
            guard record.carriesProvenance else { return nil }
            let inventory = try InstallationInventory.decode(artifact(5), expectedMacID: record.macID)
            var parts: [MachineUpdateProvisioningHistory] = []
            for account in record.accounts where account.policyRevision != nil || account.provisioningDigest != nil {
                let operand = try MachineUpdateConfigurationAccountOperand.decode(artifact(4, account: account.accountID), accountID: account.accountID)
                guard (operand.policy != nil) == (account.policyRevision != nil) else { throw PreparationStoreError.corruptRecord }
                if let digest = account.provisioningDigest {
                    guard let history = operand.history, history.accounts.first?.ownerUID == account.ownerUID,
                          try MachineUpdateActivationRecord.digest(history.encoded) == digest else {
                        throw PreparationStoreError.corruptRecord
                    }
                    parts.append(history)
                } else if operand.history != nil { throw PreparationStoreError.corruptRecord }
            }
            return try .combining(parts, current: inventory)
        }
        func validate() throws {
            if cache.isValidated() { return }
            try validateImmutableValue()
            cache.markValidated()
        }
        private func validateImmutableValue() throws {
            _ = try record.encoded
            guard artifacts.count == record.operands.count else { throw PreparationStoreError.corruptRecord }
            for (artifact, operand) in zip(artifacts, record.operands) {
                guard artifact.kind == operand.kind, artifact.account == operand.account,
                      !artifact.bytes.isEmpty, artifact.bytes.count <= RuntimeReleaseConfigurationSource.maximumBytes,
                      MachineUpdateActivationRecord.digest(artifact.bytes) == operand.digest else { throw PreparationStoreError.corruptRecord }
            }
            _ = try decodedProvisioningHistory()
            let inventory = try InstallationInventory.decode(artifact(5), expectedMacID: record.macID), candidate = try UpdateSchedulingCandidateRecord.decode(artifact(6))
            let admission = try UpdateAdmissionRegistrationRecord.decode(artifact(7)), activation = try MachineUpdateActivationRecord.decode(artifact(8))
            let replacement = try MachineUpdateReplacementRecord.decode(artifact(9))
            try activation.requireScope(candidate: candidate, inventory: inventory, admission: admission)
            try replacement.requireScope(activation: activation, inventory: inventory, candidate: candidate)
            guard activation.phase.irreversible, replacement.phase == .observed,
                  activation.attemptID == record.activationAttempt, activation.updateID == record.updateID,
                  activation.candidateDigest == record.candidateDigest, activation.inventoryDigest == record.inventoryDigest,
                  activation.admissionDigest == record.admissionDigest, inventory.macID == record.macID,
                  inventory.installationID == record.installationID else { throw PreparationStoreError.corruptRecord }
            if let retained = activation.policyPreflightDigest {
                let accounts = try record.accounts.map { account in
                    try MachineUpdatePolicyPreflight.PolicyDigestAccount(accountID: account.accountID, ownerUID: account.ownerUID,
                        sourceDigest: account.sourceDigest, policy: policy(accountID: account.accountID))
                }
                guard try MachineUpdatePolicyPreflight.policyDigest(activation: activation, accounts: accounts) == retained else {
                    throw PreparationStoreError.corruptRecord
                }
            }
            for account in record.accounts {
                _ = try policy(accountID: account.accountID)
                if let config = try configuration(accountID: account.accountID) {
                    guard let capturedPolicy = try policy(accountID: account.accountID) else { throw PreparationStoreError.corruptRecord }
                    let policyBytes = try record.carriesProvenance ? capturedPolicy.storedBytes : artifact(4, account: account.accountID)
                    let b = config.startup.binding
                    guard config.startup.policyStage == .startup, config.completion.policyStage == .completion,
                          config.completion.binding == b, try config.source.digest == config.startup.sourceDigest,
                          config.completion.sourceDigest == config.startup.sourceDigest,
                          b.activationAttempt == record.activationAttempt, b.macID == record.macID, b.installationID == record.installationID,
                          b.accountID == account.accountID, b.sourceAccountDigest == account.sourceDigest, b.runtimeReferenceDigest == account.runtimeDigest,
                          b.sourcePolicyRevision == account.policyRevision, b.sourcePolicyDigest == MachineUpdateActivationRecord.digest(policyBytes),
                          b.candidateDigest == record.candidateDigest, b.sourceInventoryDigest == record.inventoryDigest,
                          b.admissionDigest == record.admissionDigest, b.updateID == record.updateID,
                          b.installedReleaseDigest == record.installedReleaseDigest, b.previousInstalledReleaseDigest == inventory.releaseDigest else {
                        throw PreparationStoreError.corruptRecord
                    }
                }
            }
        }
    }
    static func requireArchiveFormats(_ release: SignedReleaseEvidence) throws {
        for requirement in try MachineUpdateConfigurationEpochRecord.requirements {
            guard let component = release.manifest.components.first(where: { $0.role == requirement.role }),
                  let format = component.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: format.readers), requirement.writeVersions.isSubset(of: format.writers) else {
                throw RuntimePreparationError.changedScope
            }
        }
    }
    static func requireProvenanceFormats(_ release: SignedReleaseEvidence) throws {
        try MachineUpdateProvisioningHistory.requireFormats(release)
        for requirement in try MachineUpdateConfigurationEpochRecord.provenanceRequirements {
            guard let declaration = release.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: declaration.readers), requirement.writeVersions.isSubset(of: declaration.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    static func provisioningHistory(source: MachineUpdateRestartSource, candidate: SignedReleaseEvidence) throws -> MachineUpdateProvisioningHistory? {
        guard candidate.manifest.components.contains(where: { $0.formats.contains(where: { $0.name == MachineUpdateProvisioningHistory.formatName }) }) else {
            guard source.provisioningHistory == nil else { throw PreparationStoreError.incompatibleStore }
            return nil
        }
        try requireProvenanceFormats(candidate)
        return try .capture(current: source.replacement.inventory, preparations: source.accounts.compactMap(\.preparation),
            retained: source.provisioningHistory)
    }
    static func requirePublicationFormats(_ release: SignedReleaseEvidence, provenance: Bool = false) throws {
        if provenance { try requireProvenanceFormats(release) }
        try requireArchiveFormats(release)
        for requirement in try MachineUpdateConfigurationEpochRecord.publicationRequirements {
            guard let declaration = release.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: declaration.readers), requirement.writeVersions.isSubset(of: declaration.writers) else {
                throw RuntimePreparationError.changedScope
            }
        }
    }
    static func artifacts(source: MachineUpdateRestartSource, policies: [PolicyCapture], configurations: [Configuration],
        provenance: MachineUpdateProvisioningHistory? = nil) throws -> [Artifact] {
        let c = source.replacement
        guard let replacement = c.replacement else { throw PreparationStoreError.invalidTransition }
        var values = try [Artifact(kind: 5, account: global, bytes: c.inventory.canonicalBytes),
            Artifact(kind: 6, account: global, bytes: c.candidate.encoded), Artifact(kind: 7, account: global, bytes: c.admission.encoded),
            Artifact(kind: 8, account: global, bytes: c.activation.encoded), Artifact(kind: 9, account: global, bytes: replacement.encoded)]
        for capture in policies {
            if let provenance {
                let history = try provenance.accounts.contains(where: { $0.accountID == capture.accountID }) ? provenance.account(capture.accountID) : nil
                if capture.snapshot != nil || history != nil {
                    let operand = try MachineUpdateConfigurationAccountOperand(policy: capture.snapshot, history: history, accountID: capture.accountID)
                    values.append(try .init(kind: 4, account: capture.accountID, bytes: operand.encoded))
                }
            } else if let policy = capture.snapshot { values.append(try .init(kind: 4, account: capture.accountID, bytes: policy.storedBytes)) }
        }
        for config in configurations {
            let id = config.startup.binding.accountID
            values += try [.init(kind: 1, account: id, bytes: config.source.encoded), .init(kind: 2, account: id, bytes: config.startup.encoded),
                           .init(kind: 3, account: id, bytes: config.completion.encoded)]
        }
        return values.sorted { $0.kind == $1.kind ? $0.account.lexicographicallyPrecedes($1.account) : $0.kind < $1.kind }
    }
}

enum MachineUpdateConfigurationEpochStorage {
    static func enable(installedRelease: SignedReleaseEvidence, policy: AuthorityCodePolicy, store: PreparationIntentStore) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try enableInLease(installedRelease: installedRelease, policy: policy, store: store)
    }
    static func enableInLease(installedRelease: SignedReleaseEvidence, policy: AuthorityCodePolicy, store: PreparationIntentStore) throws {
        try ReleaseCompatibilityPreflight.validate(installedRelease, policy: policy,
            requirements: .init(formats: MachineUpdateConfigurationEpochRecord.requirements, requests: []))
        try RuntimeReleaseCompatibilitySnapshot.capture(machine: store).validate(installedRelease, policy: policy, machine: store)
        try store.upgradeMachineUpdateConfigurationEpochStorage(expectedInstalledReleaseDigest: InstallationInventory.digest(installedRelease))
    }
}
