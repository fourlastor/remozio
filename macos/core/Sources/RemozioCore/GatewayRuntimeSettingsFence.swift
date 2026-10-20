import CryptoKit
import Foundation
import RemozioProtocol

/// Public scope for a retained settings change. The native owner must authenticate its Root-owned storage.
/// This record requires a new process to pause; it grants no acceptance, publication or readiness authority.
struct GatewayRuntimeSettingsFence: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.gateway-settings-fence"
    static let settingsVersion: UInt64 = 1
    static let recoveryVersion: UInt64 = 2
    static let supportedVersions: Set<UInt64> = [settingsVersion, recoveryVersion]
    let macID: Data
    let accountID: Data
    let installationID: Data
    let releaseDigest: Data
    let revision: GatewayRuntimeSettingsRevision
    let previous: GatewayRuntimeCommit
    let selected: GatewayRuntimeCommit
    let previousGatewayDigest: Data
    let recoveryAttemptID: Data?
    var version: UInt64 { recoveryAttemptID == nil ? Self.settingsVersion : Self.recoveryVersion }
    var description: String { "GatewayRuntimeSettingsFence(redacted)" }
    var debugDescription: String { description }

    init(_ plan: GatewayRuntimeSettingsPublicationPlan) throws {
        guard let marker = plan.artifacts.last, case .gatewayRuntimeCommit = marker.file,
              let oldMarker = marker.previous, try marker.selected == plan.commit.encoded,
              let gateway = plan.artifacts.first(where: { if case .gatewayConfiguration = $0.file { true } else { false } }),
              let oldGateway = gateway.previous else { throw GatewayPreparationError.incomplete }
        let services = plan.pair.authority.material.runtime.services
        try self.init(macID: services.macID, accountID: services.accountID, installationID: services.installationID,
            releaseDigest: services.releaseDigest, revision: plan.revision, previous: .decode(oldMarker),
            selected: plan.commit, previousGatewayDigest: Data(SHA256.hash(data: oldGateway)))
    }
    /// Revalidating a completed revision keeps the exact commit. The attempt grants no readiness authority.
    init(recovering revision: GatewayRuntimeSettingsRevision, commit: GatewayRuntimeCommit,
         services: ServiceAccountPlan, attemptID: Data) throws {
        try self.init(macID: services.macID, accountID: services.accountID, installationID: services.installationID,
            releaseDigest: services.releaseDigest, revision: revision, previous: commit, selected: commit,
            previousGatewayDigest: revision.gatewayDigest, recoveryAttemptID: attemptID)
    }
    private init(macID: Data, accountID: Data, installationID: Data, releaseDigest: Data,
                 revision: GatewayRuntimeSettingsRevision, previous: GatewayRuntimeCommit,
                 selected: GatewayRuntimeCommit, previousGatewayDigest: Data, recoveryAttemptID: Data? = nil) throws {
        guard [macID, accountID, installationID].allSatisfy({ $0.count == 16 }),
              releaseDigest.count == 32, previousGatewayDigest.count == 32,
              revision.accountID == accountID, revision.sequence <= UInt64(Int64.max),
              selected.settingsSequence == revision.sequence, try selected.settingsRevisionDigest == revision.digest,
              selected.activationDigest == revision.activationDigest, selected.gatewayConfigurationDigest == revision.gatewayDigest,
              previous.intentID == selected.intentID, previous.intentDigest == selected.intentDigest,
              previous.foregroundDigest == selected.foregroundDigest, previous.authorityDigest == selected.authorityDigest else {
            throw GatewayPreparationError.changedScope
        }
        if let recoveryAttemptID {
            guard recoveryAttemptID.count == 16, try previous.encoded == selected.encoded,
                  previousGatewayDigest == revision.gatewayDigest else { throw GatewayPreparationError.changedScope }
        } else if let sequence = previous.settingsSequence {
            guard sequence < UInt64.max, revision.sequence == sequence + 1,
                  previous.settingsRevisionDigest == revision.previousDigest,
                  previous.gatewayConfigurationDigest == previousGatewayDigest,
                  previous.activationDigest == revision.activationDigest else { throw GatewayPreparationError.changedScope }
        } else {
            guard revision.sequence == 1, revision.previousDigest == revision.activationDigest else { throw GatewayPreparationError.changedScope }
        }
        self.macID = macID; self.accountID = accountID; self.installationID = installationID; self.releaseDigest = releaseDigest
        self.revision = revision; self.previous = previous; self.selected = selected; self.previousGatewayDigest = previousGatewayDigest
        self.recoveryAttemptID = recoveryAttemptID
    }
    func validate(services: ServiceAccountPlan) throws {
        guard services.macID == macID, services.accountID == accountID, services.installationID == installationID,
              services.releaseDigest == releaseDigest else { throw GatewayPreparationError.changedScope }
    }
    /// Both exact commits remain paused while the fence exists. Recognition does not authorize resumption.
    func validate(commit: GatewayRuntimeCommit) throws {
        let bytes = try commit.encoded
        guard try bytes == previous.encoded || bytes == selected.encoded else { throw GatewayPreparationError.changedScope }
    }
    func validate(gateway: GatewayServiceConfiguration, commit: GatewayRuntimeCommit) throws {
        try validate(commit: commit)
        let expected = try commit.encoded == previous.encoded ? previousGatewayDigest : revision.gatewayDigest
        guard gateway.registration.macID == macID, gateway.registration.accountID == accountID,
              Data(SHA256.hash(data: gateway.canonicalBytes)) == expected else { throw GatewayPreparationError.changedScope }
    }
    var encoded: Data { get throws {
        var fields: [UInt64: CBORValue] = [0: .unsigned(version), 1: .text(Self.purpose), 2: .bytes(macID), 3: .bytes(accountID),
            4: .bytes(installationID), 5: .bytes(releaseDigest), 6: .bytes(try revision.encoded),
            7: .bytes(try previous.encoded), 8: .bytes(try selected.encoded), 9: .bytes(previousGatewayDigest)]
        if let recoveryAttemptID { fields[10] = .bytes(recoveryAttemptID) }
        return try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              case .unsigned(let version) = fields[0], version == settingsVersion || version == recoveryVersion,
              Set(fields.keys) == Set(UInt64(0)...(version == settingsVersion ? 9 : 10)),
              fields[1] == .text(purpose) else { throw GatewayPreparationError.invalidRecord }
        func data(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = fields[key] else { throw GatewayPreparationError.invalidRecord }; return value
        }
        let result = try Self(macID: data(2), accountID: data(3), installationID: data(4), releaseDigest: data(5),
            revision: .decode(data(6)), previous: .decode(data(7)), selected: .decode(data(8)), previousGatewayDigest: data(9),
            recoveryAttemptID: version == recoveryVersion ? data(10) : nil)
        guard try result.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return result
    }
    private static let purpose = "remozio-gateway-settings-fence"
    private static let limits = try! CBORLimits(maxBytes: 65536, maxDepth: 1, maxItems: 23)
}
