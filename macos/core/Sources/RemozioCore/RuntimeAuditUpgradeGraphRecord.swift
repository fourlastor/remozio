import Foundation
import RemozioProtocol

/// Public recovery pointer only. Neither phase is an activation, publication or quiescence permit.
struct RuntimeAuditUpgradeGraphRecord: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.audit-upgrade-graph-record"
    static let supportedVersions: Set<UInt64> = [1]
    enum Phase: UInt64, Sendable { case retained = 1, fileStored = 2 }
    let upgrade: RuntimeAuditUpgradeRecord
    let contentDigest: Data
    let graphVersion: UInt64
    let phase: Phase
    let revision: Data
    var description: String { "RuntimeAuditUpgradeGraphRecord(redacted)" }
    var debugDescription: String { description }
    init(upgrade: RuntimeAuditUpgradeRecord, contentDigest: Data, graphVersion: UInt64 = 1,
         phase: Phase = .retained, revision: Data = AccountPreparationIntent.randomID()) throws {
        guard upgrade.phase == .materialStaged, contentDigest.count == 32, graphVersion == 1, revision.count == 16 else {
            throw RuntimePreparationError.invalidRecord
        }
        self.upgrade = upgrade; self.contentDigest = contentDigest; self.graphVersion = graphVersion
        self.phase = phase; self.revision = revision
    }
    func validate(_ graph: RuntimeAuditUpgradeGraph) throws {
        guard upgrade == graph.upgrade, graphVersion == 1, contentDigest == graph.digest else { throw RuntimePreparationError.changedScope }
    }
    static func validateCapabilities(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        try RuntimeAuditUpgradeGraph.validateCapabilities(release, policy: policy)
        let formats = try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [13], writeVersions: [13]),
                 RetainedReleaseFormat(role: role, name: formatName, readVersions: [1], writeVersions: role == .setupController ? [1] : [])]
        }
        try ReleaseCompatibilityPreflight.validate(release, policy: policy, requirements: .init(formats: formats, requests: []))
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-audit-upgrade-graph-record"),
            2: .bytes(upgrade.encoded), 3: .bytes(contentDigest), 4: .unsigned(graphVersion), 5: .unsigned(phase.rawValue),
            6: .bytes(revision)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...6),
              f[0] == .unsigned(1), f[1] == .text("remozio-audit-upgrade-graph-record"), case .bytes(let upgrade) = f[2],
              case .bytes(let digest) = f[3], case .unsigned(let version) = f[4], case .unsigned(let phase) = f[5],
              let selected = Phase(rawValue: phase), case .bytes(let revision) = f[6] else { throw RuntimePreparationError.invalidRecord }
        let result = try Self(upgrade: .decode(upgrade), contentDigest: digest, graphVersion: version, phase: selected, revision: revision)
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    private static let limits = try! CBORLimits(maxBytes: 28672, maxDepth: 1, maxItems: 15)
}
