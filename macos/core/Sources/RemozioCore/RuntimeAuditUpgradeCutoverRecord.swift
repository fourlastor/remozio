import Foundation
import RemozioProtocol

/// Durable progress only. Every live operation still requires fresh owner, barrier and artifact verification.
struct RuntimeAuditUpgradeCutoverRecord: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.audit-upgrade-cutover-record"
    static let supportedVersions: Set<UInt64> = [1]
    enum Phase: UInt64, CaseIterable, Sendable { case selected = 1, filesChanging = 2, filesVerified = 3, metadataCommitted = 4 }
    let graph: RuntimeAuditUpgradeGraphRecord
    let phase: Phase
    let revision: Data
    var description: String { "RuntimeAuditUpgradeCutoverRecord(redacted)" }
    var debugDescription: String { description }
    init(graph: RuntimeAuditUpgradeGraphRecord, phase: Phase = .selected, revision: Data = AccountPreparationIntent.randomID()) throws {
        guard graph.phase == .fileStored, revision.count == 16 else { throw RuntimePreparationError.invalidRecord }
        self.graph = graph; self.phase = phase; self.revision = revision
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-audit-upgrade-cutover"),
            2: .bytes(graph.encoded), 3: .unsigned(phase.rawValue), 4: .bytes(revision)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...4),
              f[0] == .unsigned(1), f[1] == .text("remozio-audit-upgrade-cutover"), case .bytes(let graph) = f[2],
              case .unsigned(let phase) = f[3], let selected = Phase(rawValue: phase), case .bytes(let revision) = f[4] else {
            throw RuntimePreparationError.invalidRecord
        }
        let result = try Self(graph: .decode(graph), phase: selected, revision: revision)
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    static func validateCapabilities(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        try RuntimeAuditUpgradeGraphRecord.validateCapabilities(release, policy: policy)
        try CommandMonitorActivityContract.validate(release, policy: policy)
        try ReleaseCompatibilityPreflight.validate(release, policy: policy, requirements: .init(formats: RuntimeAuditUpgradeStartupFence.requirements, requests: []))
        let formats = try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [14], writeVersions: [14]),
                 RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: role == .setupController ? [1] : [])]
        }
        try ReleaseCompatibilityPreflight.validate(release, policy: policy, requirements: .init(formats: formats, requests: []))
    }
    static let limits = try! CBORLimits(maxBytes: 30720, maxDepth: 1, maxItems: 11)
}
