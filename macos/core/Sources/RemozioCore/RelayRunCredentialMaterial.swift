import CryptoKit
import Foundation
import RemozioProtocol

/// Public digests and destination bindings only. This value grants no runtime or provider authority.
struct RelayRunCredentialReference: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "relay.run-credential-reference"
    static let supportedVersions: Set<UInt64> = [1]
    let materialID: Data
    let planBytes: Data
    let tunnelRecordDigest: Data
    let runtime: RuntimeMaterialReference
    let tunnel: CloudflareTunnelObservation
    let credentialDigest: Data
    let materialDigest: Data
    var description: String { "RelayRunCredentialReference(redacted)" }
    var debugDescription: String { description }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-relay-run-reference"),
            2: .bytes(materialID), 3: .bytes(planBytes), 4: .bytes(tunnelRecordDigest), 5: .bytes(try runtime.encoded),
            6: .text(tunnel.accountID), 7: .text(tunnel.tunnelID), 8: .text(tunnel.name),
            9: .bytes(credentialDigest), 10: .bytes(materialDigest)]), limits: Self.limits)
    } }
    fileprivate init(materialID: Data, planBytes: Data, tunnelRecordDigest: Data, runtime: RuntimeMaterialReference,
                     tunnel: CloudflareTunnelObservation, credentialDigest: Data, materialDigest: Data) throws {
        guard materialID.count == 16, tunnelRecordDigest.count == 32,
              credentialDigest.count == 32, materialDigest.count == 32 else { throw RuntimePreparationError.invalidRecord }
        self.materialID = materialID; self.planBytes = planBytes; self.tunnelRecordDigest = tunnelRecordDigest
        self.runtime = runtime; self.tunnel = tunnel; self.credentialDigest = credentialDigest; self.materialDigest = materialDigest
    }
    static func decode(_ bytes: Data, expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                       created: SharedSetupRelayProvisioningRecord, runtime: RuntimeMaterialReference,
                       account: AccountPreparationIntent, inventory: InstallationInventory) throws -> Self {
        let tunnel = try RelayRunCredentialMaterial.validateScope(expected: expected, plan: plan, created: created,
            runtime: runtime, account: account, inventory: inventory)
        guard case let .map(f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...10),
              f[0] == .unsigned(1), f[1] == .text("remozio-relay-run-reference"), case let .bytes(id) = f[2],
              case let .bytes(credentialDigest) = f[9], case let .bytes(materialDigest) = f[10] else {
            throw RuntimePreparationError.invalidRecord
        }
        let value = try Self(materialID: id, planBytes: plan.bytes, tunnelRecordDigest: Data(SHA256.hash(data: created.bytes)),
            runtime: runtime, tunnel: tunnel, credentialDigest: credentialDigest, materialDigest: materialDigest)
        guard try value.encoded == bytes else { throw RuntimePreparationError.conflictingMaterial }
        return value
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 16_384, maxDepth: 1, maxItems: 24) } }
}

/// Private local retention. The operational credential is excluded from progress and portable setup records.
struct RelayRunCredentialMaterial: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    static let formatName = "relay.run-credential-material"
    static let supportedVersions: Set<UInt64> = [1]
    private let materialID: Data
    private let planBytes: Data
    private let tunnelRecordDigest: Data
    private let runtime: RuntimeMaterialReference
    private let credential: CloudflareTunnelRunCredential
    var description: String { "RelayRunCredentialMaterial(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    init(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, created: SharedSetupRelayProvisioningRecord,
         runtime: RuntimeMaterialReference, account: AccountPreparationIntent, inventory: InstallationInventory,
         credential: CloudflareTunnelRunCredential, materialID: Data = AccountPreparationIntent.randomID()) throws {
        let tunnel = try Self.validateScope(expected: expected, plan: plan, created: created, runtime: runtime,
            account: account, inventory: inventory)
        guard materialID.count == 16, credential.tunnel == tunnel else { throw RuntimePreparationError.changedScope }
        self.materialID = materialID; self.planBytes = plan.bytes
        self.tunnelRecordDigest = Data(SHA256.hash(data: created.bytes)); self.runtime = runtime; self.credential = credential
    }
    static func validateScope(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                              created: SharedSetupRelayProvisioningRecord, runtime: RuntimeMaterialReference,
                              account: AccountPreparationIntent, inventory: InstallationInventory) throws -> CloudflareTunnelObservation {
        guard expected.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)) else {
            throw SharedSetupImportError.wrongScope
        }
        try runtime.validate(account: account, services: runtime.services)
        return try created.createdTunnel(expected: expected, plan: plan)
    }
    var encoded: Data { get throws {
        try credential.withFileBytes { token in
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-relay-run-material"),
                2: .bytes(materialID), 3: .bytes(planBytes), 4: .bytes(tunnelRecordDigest),
                5: .bytes(try runtime.encoded), 6: .bytes(token)]), limits: Self.limits)
        }
    } }
    var reference: RelayRunCredentialReference { get throws {
        try credential.withFileBytes { token in
            try .init(materialID: materialID, planBytes: planBytes, tunnelRecordDigest: tunnelRecordDigest,
                runtime: runtime, tunnel: credential.tunnel, credentialDigest: Data(SHA256.hash(data: token)),
                materialDigest: Data(SHA256.hash(data: encoded)))
        }
    } }
    func withCredentialBytes<Value>(_ body: (Data) throws -> Value) rethrows -> Value { try credential.withFileBytes(body) }
    static func decode(_ bytes: Data, expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                       created: SharedSetupRelayProvisioningRecord, runtime: RuntimeMaterialReference,
                       account: AccountPreparationIntent, inventory: InstallationInventory) throws -> Self {
        let tunnel = try validateScope(expected: expected, plan: plan, created: created, runtime: runtime,
            account: account, inventory: inventory)
        guard case let .map(f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...6),
              f[0] == .unsigned(1), f[1] == .text("remozio-relay-run-material"),
              case let .bytes(id) = f[2], case let .bytes(token) = f[6] else { throw RuntimePreparationError.invalidRecord }
        let value = try Self(expected: expected, plan: plan, created: created, runtime: runtime, account: account,
            inventory: inventory, credential: .restore(token, tunnel: tunnel), materialID: id)
        guard try value.encoded == bytes else { throw RuntimePreparationError.conflictingMaterial }
        return value
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 32_768, maxDepth: 1, maxItems: 16) } }
}
