import Foundation

enum MachineUpdateBackendEpoch {
    static let global = Data([0])
    struct Capture {
        let accountID: Data
        let source: RuntimeReleaseBackendSource?
        let startup: RuntimeReleaseBackendPlan?
        let completion: RuntimeReleaseBackendPlan?
    }
    struct Artifact: Equatable { let kind: Int64; let accountID: Data; let bytes: Data }
    private final class ArchiveCache {
        private let lock = NSLock()
        private var captures: [Data: Capture] = [:]
        func capture(_ account: Data) -> Capture? { lock.withLock { captures[account] } }
        func retain(_ capture: Capture) {
            lock.withLock { if captures.count < 128 { captures[capture.accountID] = capture } }
        }
    }
    struct Archive {
        let record: MachineUpdateBackendEpochRecord
        let artifacts: [Artifact]
        private let cache: ArchiveCache
        private let decodedValues: PreparationImmutableTupleDecodeCache<Capture>
        init(record: MachineUpdateBackendEpochRecord, artifacts: [Artifact],
            decodedValues: PreparationImmutableTupleDecodeCache<Capture> = .init()) {
            self.record = record; self.artifacts = artifacts; cache = ArchiveCache(); self.decodedValues = decodedValues
        }
        func capture(accountID: Data) throws -> Capture? {
            guard let accounts = record.accounts else { throw PreparationStoreError.invalidTransition }
            guard let account = accounts.first(where: { $0.accountID == accountID }) else { throw PreparationStoreError.notFound }
            guard let declared = account.sourceDigest else { return nil }
            if let value = cache.capture(accountID) { return value }
            func data(_ kind: Int64) throws -> Data {
                guard let item = artifacts.first(where: { $0.kind == kind && $0.accountID == accountID }) else { throw PreparationStoreError.corruptRecord }
                return item.bytes
            }
            let inputs = try [data(1), data(2), data(3)]
            let value = try decodedValues.value(accountID: accountID, inputs: inputs) {
                try Capture(accountID: accountID, source: RuntimeReleaseBackendSource.decode(inputs[0]),
                    startup: RuntimeReleaseBackendPlan.decode(inputs[1]), completion: RuntimeReleaseBackendPlan.decode(inputs[2]))
            }
            guard try value.source?.digest == declared else { throw PreparationStoreError.corruptRecord }
            cache.retain(value); return value
        }
        func validate(epoch: MachineUpdateConfigurationEpoch.Archive) throws {
            try record.requireScope(epoch)
            guard artifacts.count == record.operands.count else { throw PreparationStoreError.corruptRecord }
            for (artifact, operand) in zip(artifacts, record.operands) {
                guard artifact.kind == operand.kind, artifact.accountID == operand.accountID,
                      MachineUpdateActivationRecord.digest(artifact.bytes) == operand.digest else { throw PreparationStoreError.corruptRecord }
            }
            if let accounts = record.accounts {
                let captures = try accounts.map { account in
                    try capture(accountID: account.accountID) ?? .init(accountID: account.accountID, source: nil, startup: nil, completion: nil)
                }
                guard try MachineUpdateBackendEpoch.artifacts(captures, epoch: epoch) == artifacts else { throw PreparationStoreError.corruptRecord }
            }
        }
    }
    static func artifacts(_ captures: [Capture], epoch: MachineUpdateConfigurationEpoch.Archive) throws -> [Artifact] {
        guard Set(captures.map(\.accountID)) == Set(epoch.record.accounts.filter(\.configurationPublished).map(\.accountID)),
              Set(captures.map(\.accountID)).count == captures.count else { throw PreparationStoreError.corruptRecord }
        var result: [Artifact] = []
        for capture in captures {
            guard let source = capture.source, let startup = capture.startup, let completion = capture.completion else {
                guard capture.source == nil, capture.startup == nil, capture.completion == nil else { throw PreparationStoreError.corruptRecord }; continue
            }
            guard let configuration = try epoch.configuration(accountID: capture.accountID),
                  startup.policyStage == .startup, completion.policyStage == .completion, startup.binding == completion.binding,
                  startup.binding.accountID == capture.accountID, try source.encoded == startup.source.encoded,
                  try source.encoded == completion.source.encoded, try startup.configuration.encoded == configuration.startup.encoded,
                  try completion.configuration.encoded == configuration.completion.encoded,
                  try startup.sourceConfiguration.encoded == configuration.source.encoded,
                  try completion.sourceConfiguration.encoded == configuration.source.encoded,
                  try source.inventory.canonicalBytes == epoch.artifact(5) else { throw PreparationStoreError.corruptRecord }
            result += try [.init(kind: 1, accountID: capture.accountID, bytes: source.encoded),
                           .init(kind: 2, accountID: capture.accountID, bytes: startup.encoded),
                           .init(kind: 3, accountID: capture.accountID, bytes: completion.encoded)]
        }
        return result.sorted { $0.kind == $1.kind ? $0.accountID.lexicographicallyPrecedes($1.accountID) : $0.kind < $1.kind }
    }
    static func requirePublicationFormats(_ candidate: SignedReleaseEvidence, epoch: MachineUpdateConfigurationEpoch.Archive) throws {
        try requireFormats(candidate, epoch: epoch)
        for requirement in try MachineUpdateBackendEpochRecord.publicationRequirements {
            guard let declaration = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: declaration.readers), requirement.writeVersions.isSubset(of: declaration.writers) else {
                throw RuntimePreparationError.changedScope
            }
        }
    }
    static func requireFormats(_ candidate: SignedReleaseEvidence, epoch: MachineUpdateConfigurationEpoch.Archive) throws {
        try MachineUpdateConfigurationEpoch.requirePublicationFormats(candidate, provenance: epoch.record.carriesProvenance)
        guard try InstallationInventory.digest(candidate) == epoch.record.installedReleaseDigest,
              try DurableReleasePreparation.digest(candidate) == epoch.record.updateID else { throw RuntimePreparationError.changedScope }
        for requirement in try MachineUpdateBackendEpochRecord.requirements {
            guard let declaration = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == requirement.name }),
                  requirement.readVersions.isSubset(of: declaration.readers), requirement.writeVersions.isSubset(of: declaration.writers) else {
                throw RuntimePreparationError.changedScope
            }
        }
    }
}
