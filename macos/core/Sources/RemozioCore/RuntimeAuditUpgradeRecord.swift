import CryptoKit
import Foundation
import RemozioProtocol

/// Public metadata for a retained audit upgrade. An intent grants no activation authority.
struct RuntimeAuditUpgradeIntent: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let id: Data
    let source: RuntimeMaterialReference
    let target: RuntimeMaterialReference
    let policyDigest: Data
    var description: String { "RuntimeAuditUpgradeIntent(redacted)" }
    var debugDescription: String { description }
    init(id: Data = AccountPreparationIntent.randomID(), source: RuntimeMaterialReference,
         target: RuntimeMaterialReference, policy: AuthorityCodePolicy) throws {
        try self.init(id: id, source: source, target: target, policyDigest: Self.digest(policy))
    }
    private init(id: Data, source: RuntimeMaterialReference, target: RuntimeMaterialReference, policyDigest: Data) throws {
        guard id.count == 16, policyDigest.count == 32, source.auditDeliveryVersion == nil,
              target.auditDeliveryVersion == 1, target.serviceActivity != nil,
              source.services == target.services, source.materialID == target.materialID,
              source.transportPublicKeyInfo == target.transportPublicKeyInfo, source.gateway == target.gateway,
              source.materialDigest != target.materialDigest,
              source.serviceActivity == nil || source.serviceActivity == target.serviceActivity else {
            throw RuntimePreparationError.invalidRecord
        }
        self.id = id; self.source = source; self.target = target; self.policyDigest = policyDigest
    }
    func validate(policy: AuthorityCodePolicy) throws {
        guard try policyDigest == Self.digest(policy) else { throw RuntimePreparationError.changedScope }
    }
    private static func digest(_ policy: AuthorityCodePolicy) throws -> Data {
        Data(SHA256.hash(data: Data("Remozio audit upgrade policy v1\0".utf8) + (try policy.bytes)))
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-runtime-audit-upgrade"), 2: .bytes(id),
            3: .bytes(source.encoded), 4: .bytes(target.encoded), 5: .bytes(policyDigest)]), limits: Self.limits)
    } }
    static func decode(_ data: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(data, limits: limits), Set(f.keys) == Set(UInt64(0)...5),
              f[0] == .unsigned(1), f[1] == .text("remozio-runtime-audit-upgrade"), case .bytes(let id) = f[2],
              case .bytes(let source) = f[3], case .bytes(let target) = f[4], case .bytes(let policy) = f[5] else {
            throw RuntimePreparationError.invalidRecord
        }
        let value = try Self(id: id, source: .decode(source), target: .decode(target), policyDigest: policy)
        guard try value.encoded == data else { throw RuntimePreparationError.invalidRecord }; return value
    }
    static let limits = try! CBORLimits(maxBytes: 20_480, maxDepth: 1, maxItems: 13)
}

/// Historical preparation markers. Each phase records progress without authority to replace a live runtime.
struct RuntimeAuditUpgradeRecord: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.audit-upgrade-record"
    static let supportedVersions: Set<UInt64> = [1]
    enum Phase: UInt64, Sendable { case retained = 1, materialStaged = 2 }
    let intent: RuntimeAuditUpgradeIntent
    let phase: Phase
    let revision: Data
    var description: String { "RuntimeAuditUpgradeRecord(redacted)" }
    var debugDescription: String { description }
    init(intent: RuntimeAuditUpgradeIntent, phase: Phase, revision: Data = AccountPreparationIntent.randomID()) throws {
        guard revision.count == 16 else { throw RuntimePreparationError.invalidRecord }
        self.intent = intent; self.phase = phase; self.revision = revision
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(intent.encoded),
            2: .unsigned(phase.rawValue), 3: .bytes(revision)]), limits: Self.limits)
    } }
    static func decode(_ data: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(data, limits: limits), Set(f.keys) == Set(UInt64(0)...3),
              f[0] == .unsigned(1), case .bytes(let intent) = f[1], case .unsigned(let phase) = f[2],
              let phase = Phase(rawValue: phase), case .bytes(let revision) = f[3] else { throw RuntimePreparationError.invalidRecord }
        let value = try Self(intent: .decode(intent), phase: phase, revision: revision)
        guard try value.encoded == data else { throw RuntimePreparationError.invalidRecord }; return value
    }
    static let limits = try! CBORLimits(maxBytes: 24_576, maxDepth: 1, maxItems: 9)
}
