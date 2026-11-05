import Darwin
import Foundation

enum MachineUpdateReplacementError: Error, Equatable { case wrongPhase, changedBinding, unknownOutcome, system(Int32) }

/// Durable swap operands. This record grants no live lock, signature, restart or floor authority.
struct MachineUpdateReplacementRecord: Codable, Equatable, Sendable, CustomStringConvertible {
    enum Phase: UInt64, Codable, Sendable { case prepared = 1, observed = 2 }
    static let formatName = "authority.machine-update-replacement"
    static let maximumBytes = 16_384
    let formatVersion: UInt64
    let revision: UUID
    let activationAttempt: UUID
    let candidateDigest: Data
    let inventoryDigest: Data
    let admissionDigest: Data
    let policyDigest: Data
    let installedParent: String
    let installedAncestry: [PreparationFileIdentity]
    let installedName: String
    let previousIdentity: PreparationFileIdentity
    let preparedParent: String
    let preparedAncestry: [PreparationFileIdentity]
    let preparedName: String
    let preparedIdentity: PreparationFileIdentity
    let phase: Phase
    var description: String { "MachineUpdateReplacementRecord(redacted)" }

    init(activation: MachineUpdateActivationRecord, inventory: InstallationInventory, candidate: UpdateSchedulingCandidateRecord,
         policy: AuthorityCodePolicy, installed: ReleaseDestinationLease, prepared: ReleaseDestinationLease,
         previousIdentity: PreparationFileIdentity) throws {
        guard activation.phase == .activationStarted, candidate.selected,
              try activation.candidateDigest == MachineUpdateActivationRecord.digest(candidate.encoded),
              activation.inventoryDigest == MachineUpdateActivationRecord.digest(inventory.canonicalBytes),
              let preparedIdentity = candidate.preparation.copyIdentity else {
            throw MachineUpdateReplacementError.wrongPhase
        }
        formatVersion = 1; revision = UUID(); activationAttempt = activation.attemptID
        candidateDigest = activation.candidateDigest; inventoryDigest = activation.inventoryDigest
        admissionDigest = activation.admissionDigest; policyDigest = try MachineUpdateActivationRecord.digest(policy.bytes)
        installedParent = installed.path; installedAncestry = try installed.preparationAncestry()
        installedName = URL(fileURLWithPath: inventory.bundlePath).lastPathComponent
        self.previousIdentity = previousIdentity
        preparedParent = prepared.path; preparedAncestry = try prepared.preparationAncestry()
        preparedName = candidate.preparation.bundleName; self.preparedIdentity = preparedIdentity; phase = .prepared
        try requireScope(activation: activation, inventory: inventory, candidate: candidate)
        try validate()
    }
    private init(_ previous: Self) {
        formatVersion = previous.formatVersion; revision = UUID(); activationAttempt = previous.activationAttempt
        candidateDigest = previous.candidateDigest; inventoryDigest = previous.inventoryDigest
        admissionDigest = previous.admissionDigest; policyDigest = previous.policyDigest
        installedParent = previous.installedParent; installedAncestry = previous.installedAncestry
        installedName = previous.installedName; previousIdentity = previous.previousIdentity
        preparedParent = previous.preparedParent; preparedAncestry = previous.preparedAncestry
        preparedName = previous.preparedName; preparedIdentity = previous.preparedIdentity; phase = .observed
    }
    func observingSwap() throws -> Self {
        guard phase == .prepared else { throw PreparationStoreError.invalidTransition }
        return Self(self)
    }
    func requireScope(activation: MachineUpdateActivationRecord, inventory: InstallationInventory,
                      candidate: UpdateSchedulingCandidateRecord) throws {
        // Hash the supplied operands too: a changed candidate or inventory can keep the same paths and copy identity.
        guard activation.phase.irreversible, activationAttempt == activation.attemptID, candidate.selected,
              candidateDigest == activation.candidateDigest, inventoryDigest == activation.inventoryDigest,
              try candidateDigest == MachineUpdateActivationRecord.digest(candidate.encoded),
              inventoryDigest == MachineUpdateActivationRecord.digest(inventory.canonicalBytes),
              admissionDigest == activation.admissionDigest,
              installedParent + "/" + installedName == inventory.bundlePath,
              preparedParent == candidate.preparation.parent, preparedAncestry == candidate.preparation.ancestry,
              preparedName == candidate.preparation.bundleName, preparedIdentity == candidate.preparation.copyIdentity else {
            throw MachineUpdateReplacementError.changedBinding
        }
    }
    func requireParents(installed: ReleaseDestinationLease, prepared: ReleaseDestinationLease) throws {
        guard installed.path == installedParent, prepared.path == preparedParent,
              try installed.preparationAncestry() == installedAncestry,
              try prepared.preparationAncestry() == preparedAncestry else { throw MachineUpdateReplacementError.changedBinding }
    }
    private func validate() throws {
        func path(_ value: String) -> Bool {
            let parts = value.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
            return value.hasPrefix("/") && value.utf8.count < Int(PATH_MAX) && !parts.isEmpty &&
                parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }
        }
        func name(_ value: String) -> Bool {
            value.hasSuffix(".app") && value.utf8.count <= 255 && !value.contains("/") && !value.utf8.contains(0)
        }
        guard formatVersion == 1, [candidateDigest, inventoryDigest, admissionDigest, policyDigest].allSatisfy({ $0.count == 32 }),
              path(installedParent), path(preparedParent), name(installedName), name(preparedName),
              [installedAncestry, preparedAncestry].allSatisfy({ (1...64).contains($0.count) && $0.allSatisfy { $0.inode > 0 } }),
              previousIdentity.inode > 0, preparedIdentity.inode > 0, previousIdentity != preparedIdentity,
              previousIdentity.device == preparedIdentity.device,
              installedParent != preparedParent || installedName != preparedName else { throw PreparationStoreError.corruptRecord }
    }
    var encoded: Data { get throws {
        try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        guard !data.isEmpty, data.count <= Self.maximumBytes else { throw PreparationStoreError.corruptRecord }
        return data
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw PreparationStoreError.corruptRecord }
            let value = try JSONDecoder().decode(Self.self, from: bytes); try value.validate()
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }; return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [18], writeVersions: [18]),
                 RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: [1])]
        }
    } }
}
