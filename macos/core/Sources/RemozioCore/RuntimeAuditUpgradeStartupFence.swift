import Foundation
import RemozioProtocol

enum RuntimeAuditUpgradeStartupError: Error, Equatable { case recoveryRequired }

/// Public interruption marker only. Its presence blocks startup; it can never authorize a service or replacement.
struct RuntimeAuditUpgradeStartupFence: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.audit-upgrade-startup-fence"
    static let supportedVersions: Set<UInt64> = [1]
    static let fileName = "audit-upgrade-startup-fence.cbor"
    let macID: Data
    let accountID: Data
    let installationID: Data
    let intentID: Data
    let graphDigest: Data
    let releaseDigest: Data
    var description: String { "RuntimeAuditUpgradeStartupFence(redacted)" }
    var debugDescription: String { description }
    init(_ cutover: RuntimeAuditUpgradeCutoverRecord) throws {
        let services = cutover.graph.upgrade.intent.source.services
        try self.init(macID: services.macID, accountID: services.accountID, installationID: services.installationID,
            intentID: cutover.graph.upgrade.intent.id, graphDigest: cutover.graph.contentDigest, releaseDigest: services.releaseDigest)
    }
    private init(macID: Data, accountID: Data, installationID: Data, intentID: Data, graphDigest: Data, releaseDigest: Data) throws {
        guard [macID, accountID, installationID, intentID].allSatisfy({ $0.count == 16 }), graphDigest.count == 32, releaseDigest.count == 32 else {
            throw RuntimePreparationError.invalidRecord
        }
        self.macID = macID; self.accountID = accountID; self.installationID = installationID
        self.intentID = intentID; self.graphDigest = graphDigest; self.releaseDigest = releaseDigest
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-audit-upgrade-startup-fence"),
            2: .bytes(macID), 3: .bytes(accountID), 4: .bytes(installationID), 5: .bytes(intentID),
            6: .bytes(graphDigest), 7: .bytes(releaseDigest)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...7),
              f[0] == .unsigned(1), f[1] == .text("remozio-audit-upgrade-startup-fence") else { throw RuntimePreparationError.invalidRecord }
        func data(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = f[key] else { throw RuntimePreparationError.invalidRecord }; return value
        }
        let result = try Self(macID: data(2), accountID: data(3), installationID: data(4), intentID: data(5), graphDigest: data(6), releaseDigest: data(7))
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController].map { role in
            try .init(role: role, name: formatName, readVersions: [1], writeVersions: role == .setupController ? [1] : [])
        }
    } }
    /// Native entry points derive the fixed public location. Missing legacy setup directories create no files.
    static func requireOpen(macID: Data, accountID: Data) throws {
        try requireOpen(macID: macID, accountID: accountID, read: { try ProtectedServiceConfiguration.readOptionalAuditFence(accountID: accountID) })
    }
    static func requireOpen(macID: Data, accountID: Data, read: () throws -> Data?) throws {
        guard macID.count == 16, accountID.count == 16 else { throw RuntimePreparationError.invalidRecord }
        guard let bytes = try read() else { return }
        let fence = try decode(bytes)
        guard fence.macID == macID, fence.accountID == accountID else { throw RuntimePreparationError.changedScope }
        throw RuntimeAuditUpgradeStartupError.recoveryRequired
    }
    static let limits = try! CBORLimits(maxBytes: 512, maxDepth: 1, maxItems: 17)
}
