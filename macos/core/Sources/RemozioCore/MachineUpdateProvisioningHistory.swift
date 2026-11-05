import Darwin
import Foundation
import RemozioProtocol

/// Exact original inventories for retained preparations. This record grants no storage, enrollment, startup or update authority.
struct MachineUpdateProvisioningHistory: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "authority.machine-update-provisioning-history"
    static let maximumBytes = 64 * 65_536 + 131_072
    struct Account: Equatable, Sendable {
        let accountID: Data
        let ownerUID: UInt32
        let preparationBinding: Data
        let inventoryDigest: Data
    }
    struct Inventory: Equatable, Sendable {
        let digest: Data
        let bytes: Data
    }
    let macID: Data
    let installationID: Data
    let bundlePath: String
    let accounts: [Account]
    let inventories: [Inventory]
    var description: String { "MachineUpdateProvisioningHistory(redacted)" }
    var debugDescription: String { description }

    /// Carries the previous exact operand forward. Missing older provenance cannot be replaced with the current inventory.
    static func capture(current: InstallationInventory, preparations: [AccountPreparationIntent],
        retained: Self? = nil) throws -> Self {
        guard preparations.count <= 64,
              Set(preparations.map(\.accountID)).count == preparations.count,
              Set(preparations.map(\.ownerUID)).count == preparations.count else { throw PreparationStoreError.corruptRecord }
        try retained?.requireScope(current)
        var accounts: [Account] = [], inventories: [Inventory] = []
        for preparation in preparations.sorted(by: { $0.accountID.lexicographicallyPrecedes($1.accountID) }) {
            guard preparation.macID == current.macID, preparation.installationID == current.installationID else {
                throw RuntimePreparationError.changedScope
            }
            let selected: InstallationInventory
            if let retained, retained.accounts.contains(where: { $0.accountID == preparation.accountID }) {
                selected = try retained.inventory(for: preparation, current: current)
            } else {
                guard preparation.releaseDigest == current.releaseDigest else { throw RuntimePreparationError.changedScope }
                selected = current
            }
            let bytes = selected.canonicalBytes, digest = MachineUpdateActivationRecord.digest(bytes)
            accounts.append(try .init(accountID: preparation.accountID, ownerUID: preparation.ownerUID,
                preparationBinding: binding(preparation), inventoryDigest: digest))
            if !inventories.contains(where: { $0.digest == digest }) { inventories.append(.init(digest: digest, bytes: bytes)) }
        }
        return try .init(macID: current.macID, installationID: current.installationID, bundlePath: current.bundlePath,
            accounts: accounts, inventories: inventories.sorted { $0.digest.lexicographicallyPrecedes($1.digest) })
    }
    func requireScope(_ current: InstallationInventory) throws {
        guard macID == current.macID, installationID == current.installationID, bundlePath == current.bundlePath else {
            throw RuntimePreparationError.changedScope
        }
    }
    func inventory(for preparation: AccountPreparationIntent, current: InstallationInventory) throws -> InstallationInventory {
        try requireScope(current)
        guard preparation.macID == macID, preparation.installationID == installationID,
              let account = accounts.first(where: { $0.accountID == preparation.accountID && $0.ownerUID == preparation.ownerUID }),
              try account.preparationBinding == Self.binding(preparation),
              let operand = inventories.first(where: { $0.digest == account.inventoryDigest }) else {
            throw RuntimePreparationError.changedScope
        }
        let inventory = try InstallationInventory.decode(operand.bytes, expectedMacID: macID)
        guard inventory.releaseDigest == preparation.releaseDigest else { throw RuntimePreparationError.changedScope }
        return inventory
    }
    private init(macID: Data, installationID: Data, bundlePath: String, accounts: [Account], inventories: [Inventory]) throws {
        let parts = bundlePath.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard macID.count == 16, installationID.count == 16,
              bundlePath.hasPrefix("/"), bundlePath.utf8.count < Int(PATH_MAX), parts.count <= 64,
              parts.last?.hasSuffix(".app") == true,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              accounts.count <= 64, inventories.count <= 64,
              Set(accounts.map(\.accountID)).count == accounts.count,
              Set(accounts.map(\.ownerUID)).count == accounts.count,
              Set(inventories.map(\.digest)).count == inventories.count,
              accounts.map(\.accountID) == accounts.map(\.accountID).sorted(by: { $0.lexicographicallyPrecedes($1) }),
              inventories.map(\.digest) == inventories.map(\.digest).sorted(by: { $0.lexicographicallyPrecedes($1) }),
              accounts.allSatisfy({ $0.accountID.count == 16 && $0.ownerUID > 0 && $0.ownerUID < UInt32.max &&
                  $0.preparationBinding.count == 32 && $0.inventoryDigest.count == 32 }),
              Set(accounts.map(\.inventoryDigest)) == Set(inventories.map(\.digest)) else { throw PreparationStoreError.corruptRecord }
        for operand in inventories {
            guard !operand.bytes.isEmpty, operand.bytes.count <= 65_536,
                  operand.digest.count == 32, MachineUpdateActivationRecord.digest(operand.bytes) == operand.digest else {
                throw PreparationStoreError.corruptRecord
            }
            let inventory = try InstallationInventory.decode(operand.bytes, expectedMacID: macID)
            guard inventory.installationID == installationID, inventory.bundlePath == bundlePath else {
                throw PreparationStoreError.corruptRecord
            }
        }
        self.macID = macID; self.installationID = installationID; self.bundlePath = bundlePath
        self.accounts = accounts; self.inventories = inventories
        guard try encoded.count <= Self.maximumBytes else { throw PreparationStoreError.capacity }
    }
    /// Setup progress can advance. The account identity, reviewed policy and frozen initial epoch must remain unchanged.
    private static func binding(_ preparation: AccountPreparationIntent) throws -> Data {
        _ = try preparation.bytes
        var directory = preparation.directoryID.uuid
        let bytes = try DeterministicCBOR.encode(.map([
            0: .text("remozio/provisioning-history-account/v1"), 1: .bytes(preparation.setupID),
            2: .bytes(preparation.macID), 3: .bytes(preparation.installationID), 4: .bytes(preparation.releaseDigest),
            5: .bytes(preparation.accountID), 6: .unsigned(UInt64(preparation.ownerUID)),
            7: .bytes(withUnsafeBytes(of: &directory) { Data($0) }),
            8: .bytes(preparation.policyBytes), 9: .bytes(preparation.initializationBytes)
        ]), limits: .init(maxBytes: AccountPreparationIntent.maximumBytes + 512, maxDepth: 1, maxItems: 21))
        return MachineUpdateActivationRecord.digest(bytes)
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .text("remozio/provisioning-history/v1"), 2: .bytes(macID),
            3: .bytes(installationID), 4: .text(bundlePath),
            5: .array(accounts.map { .map([0: .bytes($0.accountID), 1: .unsigned(UInt64($0.ownerUID)),
                2: .bytes($0.preparationBinding), 3: .bytes($0.inventoryDigest)]) }),
            6: .array(inventories.map { .map([0: .bytes($0.digest), 1: .bytes($0.bytes)]) })
        ]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...6), fields[0] == .unsigned(1),
                  fields[1] == .text("remozio/provisioning-history/v1"), case .bytes(let mac) = fields[2],
                  case .bytes(let installation) = fields[3], case .text(let path) = fields[4],
                  case .array(let rows) = fields[5], rows.count <= 64,
                  case .array(let operands) = fields[6], operands.count <= 64 else { throw PreparationStoreError.corruptRecord }
            let accounts = try rows.map { row -> Account in
                guard case .map(let f) = row, Set(f.keys) == Set(UInt64(0)...3), case .bytes(let id) = f[0],
                      case .unsigned(let raw) = f[1], let owner = UInt32(exactly: raw),
                      case .bytes(let binding) = f[2], case .bytes(let inventory) = f[3] else { throw PreparationStoreError.corruptRecord }
                return .init(accountID: id, ownerUID: owner, preparationBinding: binding, inventoryDigest: inventory)
            }
            let inventories = try operands.map { operand -> Inventory in
                guard case .map(let f) = operand, Set(f.keys) == Set(UInt64(0)...1),
                      case .bytes(let digest) = f[0], case .bytes(let bytes) = f[1] else { throw PreparationStoreError.corruptRecord }
                return .init(digest: digest, bytes: bytes)
            }
            let result = try Self(macID: mac, installationID: installation, bundlePath: path, accounts: accounts, inventories: inventories)
            guard try result.encoded == bytes else { throw PreparationStoreError.corruptRecord }
            return result
        } catch { throw PreparationStoreError.corruptRecord }
    }
    func account(_ accountID: Data) throws -> Self {
        guard let account = accounts.first(where: { $0.accountID == accountID }),
              let inventory = inventories.first(where: { $0.digest == account.inventoryDigest }) else {
            throw RuntimePreparationError.changedScope
        }
        return try .init(macID: macID, installationID: installationID, bundlePath: bundlePath,
            accounts: [account], inventories: [inventory])
    }
    static func combining(_ values: [Self], current: InstallationInventory) throws -> Self {
        var accounts: [Account] = [], inventories: [Inventory] = []
        guard values.count <= 64 else { throw PreparationStoreError.capacity }
        for value in values {
            try value.requireScope(current)
            accounts += value.accounts
            for inventory in value.inventories {
                if let existing = inventories.first(where: { $0.digest == inventory.digest }) {
                    guard existing == inventory else { throw PreparationStoreError.corruptRecord }
                } else { inventories.append(inventory) }
            }
        }
        return try .init(macID: current.macID, installationID: current.installationID, bundlePath: current.bundlePath,
            accounts: accounts.sorted { $0.accountID.lexicographicallyPrecedes($1.accountID) },
            inventories: inventories.sorted { $0.digest.lexicographicallyPrecedes($1.digest) })
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].map {
            try .init(role: $0, name: formatName, readVersions: [1], writeVersions: [1])
        }
    } }
    static func requireFormats(_ candidate: SignedReleaseEvidence) throws {
        for requirement in try requirements {
            guard let declared = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: { $0.name == formatName }),
                  requirement.readVersions.isSubset(of: declared.readers), requirement.writeVersions.isSubset(of: declared.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 3, maxItems: 2048) } }
}
