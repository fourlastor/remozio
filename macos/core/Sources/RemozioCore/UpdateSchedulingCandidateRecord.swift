import Foundation

/// Durable selection only. Reading this record grants no scheduling, quiescence or activation authority.
struct UpdateSchedulingCandidateRecord: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "authority.update-scheduling-candidate"
    static let maximumBytes = 32_768
    let formatVersion: UInt64
    let macID: Data
    let installationID: Data
    let inventoryRevision: Data
    let preparation: PreparationIntentRecord
    let generation: UInt64
    let revision: UUID
    let selected: Bool
    var updateID: Data { preparation.copyDigest! }
    var description: String { "UpdateSchedulingCandidateRecord(redacted)" }
    var debugDescription: String { description }

    init(macID: Data, installationID: Data, inventoryRevision: Data, preparation: PreparationIntentRecord,
         generation: UInt64, revision: UUID = UUID(), selected: Bool = true) throws {
        formatVersion = 1; self.macID = macID; self.installationID = installationID
        self.inventoryRevision = inventoryRevision; self.preparation = preparation
        self.generation = generation; self.revision = revision; self.selected = selected
        try validate()
    }
    private func validate() throws {
        try preparation.validate()
        guard formatVersion == 1, macID.count == 16, installationID.count == 16, inventoryRevision.count == 16,
              preparation.phase == .copyRecorded, preparation.copyDigest?.count == 32, generation > 0 else {
            throw PreparationStoreError.corruptRecord
        }
    }
    var encoded: Data {
        get throws {
            try validate()
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let bytes = try encoder.encode(self)
            guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else { throw PreparationStoreError.corruptRecord }
            return bytes
        }
    }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw PreparationStoreError.corruptRecord }
            let value = try JSONDecoder().decode(Self.self, from: bytes)
            try value.validate()
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }
            return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
    static var requirements: [RetainedReleaseFormat] {
        get throws {
            try [AuthorityCodeRole.authority, .setupController].flatMap { role in
                try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [15], writeVersions: [15]),
                     RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: [1])]
            }
        }
    }
    static func validateReaders(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        try ReleaseCompatibilityPreflight.validate(release, policy: policy, requirements: .init(formats: requirements, requests: []))
    }
}
