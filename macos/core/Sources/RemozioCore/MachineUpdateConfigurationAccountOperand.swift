import Foundation
import RemozioProtocol

/// Versioned archive operands for one account. These bytes grant no policy write or provisioning authority.
struct MachineUpdateConfigurationAccountOperand: CustomStringConvertible, CustomDebugStringConvertible {
    static let maximumBytes = RuntimeReleaseConfigurationSource.maximumBytes
    let policy: Data?
    let history: MachineUpdateProvisioningHistory?
    var description: String { "MachineUpdateConfigurationAccountOperand(redacted)" }
    var debugDescription: String { description }

    init(policy: AuthorityCodePolicySnapshot?, history: MachineUpdateProvisioningHistory?, accountID: Data) throws {
        try self.init(policy: policy?.storedBytes, history: history, accountID: accountID)
    }
    private init(policy: Data?, history: MachineUpdateProvisioningHistory?, accountID: Data) throws {
        guard accountID.count == 16, policy != nil || history != nil,
              policy == nil || !policy!.isEmpty && policy!.count <= Self.maximumBytes,
              history == nil || history?.accounts.count == 1 && history?.accounts.first?.accountID == accountID else {
            throw PreparationStoreError.corruptRecord
        }
        self.policy = policy; self.history = history
        guard try encoded.count <= Self.maximumBytes else { throw PreparationStoreError.capacity }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio/configuration-account-operands/v1"),
            2: policy.map(CBORValue.bytes) ?? .null,
            3: try history.map { .bytes(try $0.encoded) } ?? .null]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data, accountID: Data) throws -> Self {
        do {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(1),
                  fields[1] == .text("remozio/configuration-account-operands/v1") else { throw PreparationStoreError.corruptRecord }
            let policy: Data?, history: MachineUpdateProvisioningHistory?
            switch fields[2] {
            case .null?: policy = nil
            case .bytes(let bytes)?: policy = bytes
            default: throw PreparationStoreError.corruptRecord
            }
            switch fields[3] {
            case .null?: history = nil
            case .bytes(let bytes)?: history = try .decode(bytes)
            default: throw PreparationStoreError.corruptRecord
            }
            let value = try Self(policy: policy, history: history, accountID: accountID)
            guard try value.encoded == bytes else { throw PreparationStoreError.corruptRecord }; return value
        } catch { throw PreparationStoreError.corruptRecord }
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 1, maxItems: 9) } }
}
