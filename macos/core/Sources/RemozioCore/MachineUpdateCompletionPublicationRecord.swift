import Foundation
import RemozioProtocol

/// Durable publication intent only. Decoding grants no file writer, metadata retirement or admission authority.
struct MachineUpdateCompletionPublicationRecord: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "authority.machine-update-completion-publication"
    static let maximumBytes = 524288
    static let formatVersions: Set<UInt64> = [1, 2]
    enum State: Int, Codable, Sendable { case pending, writing, published }
    struct Entry: Codable, Equatable, Sendable {
        let accountID: Data
        let ownerUID: UInt32
        let file: MachineUpdateCompletionPublicationPlan.File
        let startupDigest: Data
        let completionDigest: Data
        let state: State
    }
    let formatVersion: UInt64
    let id: UUID
    let revision: UUID
    let intentDigest: Data
    let planFingerprint: Data
    let sourceInventoryDigest: Data
    let targetInventoryDigest: Data
    let entries: [Entry]
    let inventoryState: State
    var filesPublished: Bool { entries.allSatisfy { $0.state == .published } }
    var complete: Bool { filesPublished && inventoryState == .published }
    var description: String { "MachineUpdateCompletionPublicationRecord(redacted)" }
    var debugDescription: String { description }

    init(plan: MachineUpdateCompletionPublicationPlan) throws {
        formatVersion = plan.entries.contains(where: { $0.file == .authorityJob }) ? 2 : 1; id = UUID(); revision = UUID()
        intentDigest = try plan.completionIntentDigest; planFingerprint = try plan.fingerprint
        sourceInventoryDigest = try plan.sourceInventoryDigest
        targetInventoryDigest = MachineUpdateActivationRecord.digest(plan.inventory.canonicalBytes)
        entries = plan.entries.map { .init(accountID: $0.accountID, ownerUID: $0.ownerUID, file: $0.file,
            startupDigest: MachineUpdateActivationRecord.digest($0.startup),
            completionDigest: MachineUpdateActivationRecord.digest($0.completion), state: .pending) }
        inventoryState = .pending; try validate()
    }
    private init(previous: Self, entries: [Entry], inventoryState: State) throws {
        formatVersion = previous.formatVersion; id = previous.id; revision = UUID()
        intentDigest = previous.intentDigest; planFingerprint = previous.planFingerprint
        sourceInventoryDigest = previous.sourceInventoryDigest; targetInventoryDigest = previous.targetInventoryDigest
        self.entries = entries; self.inventoryState = inventoryState; try validate()
    }
    func requirePlan(_ plan: MachineUpdateCompletionPublicationPlan) throws {
        try validate()
        guard formatVersion == (plan.entries.contains(where: { $0.file == .authorityJob }) ? 2 : 1),
              try intentDigest == plan.completionIntentDigest, try planFingerprint == plan.fingerprint,
              try sourceInventoryDigest == plan.sourceInventoryDigest,
              targetInventoryDigest == MachineUpdateActivationRecord.digest(plan.inventory.canonicalBytes),
              entries.count == plan.entries.count else { throw PreparationStoreError.staleRevision }
        for (entry, file) in zip(entries, plan.entries) {
            guard entry.accountID == file.accountID, entry.ownerUID == file.ownerUID, entry.file == file.file,
                  entry.startupDigest == MachineUpdateActivationRecord.digest(file.startup),
                  entry.completionDigest == MachineUpdateActivationRecord.digest(file.completion) else {
                throw PreparationStoreError.staleRevision
            }
        }
    }
    func state(accountID: Data, file: MachineUpdateCompletionPublicationPlan.File) throws -> State {
        guard let entry = entries.first(where: { $0.accountID == accountID && $0.file == file }) else {
            throw PreparationStoreError.notFound
        }
        return entry.state
    }
    func advancing(accountID: Data, file: MachineUpdateCompletionPublicationPlan.File, to next: State) throws -> Self {
        guard let index = entries.firstIndex(where: { $0.accountID == accountID && $0.file == file }) else {
            throw PreparationStoreError.notFound
        }
        return try advancing(index: index, to: next)
    }
    func advancingInventory(to next: State) throws -> Self { try advancing(index: entries.count, to: next) }
    private func advancing(index: Int, to next: State) throws -> Self {
        try validate()
        let states = entries.map(\.state) + [inventoryState]
        guard states.firstIndex(where: { $0 != .published }) == index,
              states[index] == .pending && next == .writing || states[index] == .writing && next == .published else {
            throw PreparationStoreError.invalidTransition
        }
        if index == entries.count { return try Self(previous: self, entries: entries, inventoryState: next) }
        let updated = entries.enumerated().map { offset, entry in
            offset == index ? Entry(accountID: entry.accountID, ownerUID: entry.ownerUID, file: entry.file,
                startupDigest: entry.startupDigest, completionDigest: entry.completionDigest, state: next) : entry
        }
        return try Self(previous: self, entries: updated, inventoryState: inventoryState)
    }
    func requireInventory(_ bytes: Data) throws {
        try validate(); let actual = MachineUpdateActivationRecord.digest(bytes)
        guard inventoryState == .pending && actual == sourceInventoryDigest ||
              inventoryState == .writing && (actual == sourceInventoryDigest || actual == targetInventoryDigest) ||
              inventoryState == .published && actual == targetInventoryDigest else { throw PreparationStoreError.staleRevision }
    }
    private func validate() throws {
        guard (formatVersion == 1 && !entries.contains(where: { $0.file == .authorityJob })) ||
                (formatVersion == 2 && entries.contains(where: { $0.file == .authorityJob })),
              [intentDigest, planFingerprint, sourceInventoryDigest, targetInventoryDigest].allSatisfy({ $0.count == 32 }),
              sourceInventoryDigest != targetInventoryDigest, entries.count <= (formatVersion == 2 ? 1408 : 1280),
              entries.allSatisfy({ $0.accountID.count == 16 && $0.ownerUID > 0 && $0.ownerUID < UInt32.max &&
                  $0.startupDigest.count == 32 && $0.completionDigest.count == 32 }),
              Set(entries.map { $0.accountID.base64EncodedString() + ":" + String($0.file.rawValue) }).count == entries.count,
              entries == entries.sorted(by: { $0.accountID == $1.accountID ? $0.file.rawValue < $1.file.rawValue :
                  $0.accountID.lexicographicallyPrecedes($1.accountID) }) else { throw PreparationStoreError.corruptRecord }
        let states = entries.map(\.state) + [inventoryState]
        if let first = states.firstIndex(where: { $0 != .published }) {
            guard states.dropFirst(first + 1).allSatisfy({ $0 == .pending }) else { throw PreparationStoreError.corruptRecord }
        }
    }
    var encoded: Data { get throws {
        try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else { throw PreparationStoreError.capacity }; return bytes
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw PreparationStoreError.corruptRecord }
            let value = try JSONDecoder().decode(Self.self, from: bytes)
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }; return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [21, 22], writeVersions: [22]),
                RetainedReleaseFormat(role: role, name: formatName, readVersions: formatVersions, writeVersions: formatVersions)]
        }
    } }
}
