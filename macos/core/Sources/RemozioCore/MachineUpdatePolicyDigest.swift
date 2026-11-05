import Foundation
import RemozioProtocol

/// Binds retained policy inputs. A digest grants no live preflight, replacement, health, or floor authority.
enum MachineUpdatePolicyDigest {
    struct Account {
        let accountID: Data
        let ownerUID: UInt32
        let sourceDigest: Data
        let policy: AuthorityCodePolicySnapshot?
    }
    static func make(activation: MachineUpdateActivationRecord, accounts: [Account]) throws -> Data {
        guard accounts.count <= 128, Set(accounts.map(\.accountID)).count == accounts.count else { throw MachineUpdateActivationError.changedScope }
        func uuid(_ id: UUID) -> Data { var bytes = id.uuid; return withUnsafeBytes(of: &bytes) { Data($0) } }
        let values = try accounts.sorted { $0.accountID.lexicographicallyPrecedes($1.accountID) }.map { account -> CBORValue in
            guard account.accountID.count == 16, account.sourceDigest.count == 32 else { throw MachineUpdateActivationError.changedScope }
            return try .map([0: .bytes(account.accountID), 1: .unsigned(UInt64(account.ownerUID)), 2: .bytes(account.sourceDigest),
                3: account.policy.map { .bytes(uuid($0.revision)) } ?? .null,
                4: account.policy.map { .bytes(MachineUpdateActivationRecord.digest(try $0.storedBytes)) } ?? .null])
        }
        let bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(uuid(activation.attemptID)),
            2: .bytes(activation.macID), 3: .bytes(activation.installationID), 4: .bytes(activation.updateID),
            5: .bytes(activation.candidateDigest), 6: .bytes(activation.inventoryDigest), 7: .bytes(activation.admissionDigest),
            8: .array(values)]), limits: .init(maxBytes: 65536, maxDepth: 3, maxItems: 4096))
        return MachineUpdateActivationRecord.digest(Data("Remozio/MachineUpdatePolicyPreflight/v1\0".utf8) + bytes)
    }
}
