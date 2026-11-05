import CryptoKit
import Foundation

/// A durable phase and scope. Decoding it grants no admission, replacement, restart or floor authority.
struct MachineUpdateActivationRecord: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    enum Phase: UInt64, Codable, Sendable {
        case draining = 1, activationStarted = 2, restartChecking = 3, cancelled = 4, finishing = 5, completed = 6
        var blocksMachineWrites: Bool { self != .cancelled && self != .completed }
        var irreversible: Bool { self == .activationStarted || self == .restartChecking || self == .finishing || self == .completed }
    }
    static let formatName = "authority.machine-update-activation"
    static let maximumBytes = 4096
    let formatVersion: UInt64
    let attemptID: UUID
    let revision: UUID
    let macID: Data
    let installationID: Data
    let updateID: Data
    let generation: UInt64
    let candidateDigest: Data
    let inventoryDigest: Data
    let admissionDigest: Data
    let machineAdmission: PreparationFileIdentity
    let phase: Phase
    let policyPreflightDigest: Data?
    var description: String { "MachineUpdateActivationRecord(redacted)" }
    var debugDescription: String { description }

    init(candidate: UpdateSchedulingCandidateRecord, inventory: InstallationInventory,
         admission: UpdateAdmissionRegistrationRecord, attemptID: UUID = UUID()) throws {
        guard candidate.selected, candidate.macID == inventory.macID, candidate.installationID == inventory.installationID,
              candidate.inventoryRevision == inventory.revision, admission.macID == inventory.macID,
              admission.installationID == inventory.installationID else { throw MachineUpdateActivationError.changedScope }
        formatVersion = 1; self.attemptID = attemptID; revision = UUID(); macID = inventory.macID
        installationID = inventory.installationID; updateID = candidate.updateID; generation = candidate.generation
        candidateDigest = try Self.digest(candidate.encoded); inventoryDigest = Self.digest(inventory.canonicalBytes)
        admissionDigest = try Self.digest(admission.encoded); machineAdmission = admission.machine; phase = .draining; policyPreflightDigest = nil
        try validate()
    }
    private init(_ previous: Self, phase: Phase, policyPreflightDigest: Data? = nil) {
        formatVersion = phase == .completed ? 4 : (phase == .finishing ? 3 : (policyPreflightDigest == nil ? previous.formatVersion : 2))
        attemptID = previous.attemptID; revision = UUID()
        macID = previous.macID; installationID = previous.installationID; updateID = previous.updateID
        generation = previous.generation; candidateDigest = previous.candidateDigest; inventoryDigest = previous.inventoryDigest
        admissionDigest = previous.admissionDigest; machineAdmission = previous.machineAdmission; self.phase = phase
        self.policyPreflightDigest = policyPreflightDigest ?? previous.policyPreflightDigest
    }
    func starting(policyPreflightDigest: Data) throws -> Self {
        guard phase == .draining, policyPreflightDigest.count == 32 else { throw PreparationStoreError.invalidTransition }
        return Self(self, phase: .activationStarted, policyPreflightDigest: policyPreflightDigest)
    }
    func advancing(to next: Phase) throws -> Self {
        switch (phase, next) {
        case (.draining, .activationStarted), (.draining, .cancelled), (.activationStarted, .restartChecking): break
        default:
            if next == .cancelled, phase.irreversible { throw MachineUpdateActivationError.tooLate }
            throw PreparationStoreError.invalidTransition
        }
        return Self(self, phase: next)
    }
    func finalizing() throws -> Self {
        guard phase == .restartChecking, formatVersion == 2 else { throw PreparationStoreError.invalidTransition }
        let value = Self(self, phase: .finishing); try value.validate(); return value
    }
    func requireFinalizationSource(_ previous: Self) throws {
        guard phase == .finishing, formatVersion == 3, previous.phase == .restartChecking, previous.formatVersion == 2,
              attemptID == previous.attemptID, revision != previous.revision, macID == previous.macID,
              installationID == previous.installationID, updateID == previous.updateID, generation == previous.generation,
              candidateDigest == previous.candidateDigest, inventoryDigest == previous.inventoryDigest,
              admissionDigest == previous.admissionDigest, machineAdmission == previous.machineAdmission,
              policyPreflightDigest == previous.policyPreflightDigest else { throw MachineUpdateActivationError.changedScope }
    }
    /// Preserves the finishing scope. Only a verified stable-state transaction can persist this proposal.
    func completing() throws -> Self {
        guard phase == .finishing, formatVersion == 3 else { throw PreparationStoreError.invalidTransition }
        let value = Self(self, phase: .completed); try value.validate(); return value
    }
    func requireCompletionSource(_ previous: Self) throws {
        _ = try encoded; _ = try previous.encoded
        guard phase == .completed, formatVersion == 4, previous.phase == .finishing, previous.formatVersion == 3,
              attemptID == previous.attemptID, revision != previous.revision, macID == previous.macID,
              installationID == previous.installationID, updateID == previous.updateID, generation == previous.generation,
              candidateDigest == previous.candidateDigest, inventoryDigest == previous.inventoryDigest,
              admissionDigest == previous.admissionDigest, machineAdmission == previous.machineAdmission,
              policyPreflightDigest == previous.policyPreflightDigest else { throw MachineUpdateActivationError.changedScope }
    }
    static var completionRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map { role in
            try RetainedReleaseFormat(role: role, name: formatName, readVersions: [1, 2, 3, 4], writeVersions: [4])
        }
    } }
    static func requireCompletionFormats(_ release: SignedReleaseEvidence) throws {
        for requirement in try completionRequirements {
            guard let declaration = release.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == formatName }),
                  requirement.readVersions.isSubset(of: declaration.readers), requirement.writeVersions.isSubset(of: declaration.writers) else {
                throw MachineUpdateActivationError.changedScope
            }
        }
    }
    static var finalizationRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map { role in
            try RetainedReleaseFormat(role: role, name: formatName, readVersions: [1, 2, 3], writeVersions: [3])
        }
    } }
    func requireScope(candidate: UpdateSchedulingCandidateRecord, inventory: InstallationInventory,
                      admission: UpdateAdmissionRegistrationRecord) throws {
        guard candidate.selected, macID == inventory.macID, installationID == inventory.installationID,
              candidate.macID == macID, candidate.installationID == installationID,
              candidate.inventoryRevision == inventory.revision, candidate.updateID == updateID, candidate.generation == generation,
              try candidateDigest == Self.digest(candidate.encoded), inventoryDigest == Self.digest(inventory.canonicalBytes),
              try admissionDigest == Self.digest(admission.encoded), admission.machine == machineAdmission else {
            throw MachineUpdateActivationError.changedScope
        }
    }
    private func validate() throws {
        guard (formatVersion == 1 && policyPreflightDigest == nil && phase != .finishing && phase != .completed ||
               formatVersion == 2 && policyPreflightDigest?.count == 32 && (phase == .activationStarted || phase == .restartChecking) ||
               formatVersion == 3 && policyPreflightDigest?.count == 32 && phase == .finishing ||
               formatVersion == 4 && policyPreflightDigest?.count == 32 && phase == .completed), macID.count == 16, installationID.count == 16, generation > 0,
              [updateID, candidateDigest, inventoryDigest, admissionDigest].allSatisfy({ $0.count == 32 }),
              machineAdmission.inode > 0 else { throw PreparationStoreError.corruptRecord }
    }
    var encoded: Data { get throws {
        try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else { throw PreparationStoreError.corruptRecord }
        return bytes
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw PreparationStoreError.corruptRecord }
            let value = try JSONDecoder().decode(Self.self, from: bytes); try value.validate()
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }; return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
    static func digest(_ bytes: Data) -> Data { Data(SHA256.hash(data: bytes)) }
    static var preflightRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map { role in
            try RetainedReleaseFormat(role: role, name: formatName, readVersions: [1, 2], writeVersions: [2])
        }
    } }
    static func requirePreflightFormats(_ release: SignedReleaseEvidence) throws {
        for requirement in try preflightRequirements {
            guard let declaration = release.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == formatName }),
                  requirement.readVersions.isSubset(of: declaration.readers), requirement.writeVersions.isSubset(of: declaration.writers) else {
                throw MachineUpdateActivationError.changedScope
            }
        }
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [17], writeVersions: [17]),
                 RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: [1])]
        }
    } }
}
