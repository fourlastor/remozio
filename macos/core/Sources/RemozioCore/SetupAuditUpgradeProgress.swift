import CryptoKit
import Foundation
import RemozioProtocol

/// Scoped maintenance observations. No stage grants authority or asserts service health.
public struct SetupAuditUpgradeProgress: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public enum Stage: UInt64, Sendable, CaseIterable {
        case ready = 1, waitingForActivity, waitingForMachine, graphPrepared, waitingForQuiescence
        case filesChanging, filesVerified, metadataCommitted, readyToRestart, registrationObserved, alreadyCurrent
    }
    public static let formatName = "setup.audit-upgrade-progress"
    public static let supportedVersions: Set<UInt64> = [1]
    public static let maximumBytes = 1024
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 2, maxItems: 32)
    public let runtime: SetupRuntimeProgress
    public let installationID: Data
    public let releaseDigest: Data
    public let initializationDigest: Data
    public let stage: Stage
    public let registrationObserved: Set<AuthorityCodeRole>
    public var description: String { "SetupAuditUpgradeProgress(redacted)" }
    public var debugDescription: String { description }

    private init(runtime: SetupRuntimeProgress, installationID: Data, releaseDigest: Data, initializationDigest: Data,
                 stage: Stage, registrationObserved: Set<AuthorityCodeRole> = []) throws {
        let roles: Set<AuthorityCodeRole> = [.authority, .transport, .notificationGateway]
        guard runtime.configurationPublished, runtime.materialID != nil,
              installationID.count == 16, releaseDigest.count == 32, initializationDigest.count == 32,
              registrationObserved.isSubset(of: roles),
              registrationObserved.isEmpty || stage == .registrationObserved,
              registrationObserved.isEmpty || registrationObserved.isSuperset(of: [.authority, .transport]) else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        self.runtime = runtime; self.installationID = installationID; self.releaseDigest = releaseDigest
        self.initializationDigest = initializationDigest; self.stage = stage; self.registrationObserved = registrationObserved
    }
    static func capture(machine: PreparationIntentStore, account: AccountPreparationIntent,
                        inventory: InstallationInventory, initialization: AuthorityInitializationIntent) throws -> Self {
        let runtime = try machine.runtimePreparation(accountID: account.accountID)
        guard let reference = runtime.reference else { throw RuntimePreparationError.incomplete }
        try RuntimeConfigurationBundle.validateScope(account: account, initialization: initialization, reference: reference, inventory: inventory)
        let stage: Stage
        if let cutover = try machine.runtimeAuditCutover(accountID: account.accountID) {
            let intent = cutover.graph.upgrade.intent
            let expected = cutover.phase == .metadataCommitted ? intent.target : intent.source
            guard reference == expected else { throw RuntimePreparationError.changedScope }
            switch cutover.phase {
            case .selected: stage = .graphPrepared
            case .filesChanging: stage = .filesChanging
            case .filesVerified: stage = .filesVerified
            case .metadataCommitted: stage = .metadataCommitted
            }
        } else { stage = reference.auditDeliveryVersion == 1 ? .alreadyCurrent : .ready }
        return try .init(runtime: SetupRuntimeProgress(account: account,
            services: machine.serviceAccountPlan(accountID: account.accountID), state: runtime),
            installationID: inventory.installationID, releaseDigest: inventory.releaseDigest,
            initializationDigest: Data(SHA256.hash(data: initialization.bytes)), stage: stage)
    }
    func validateScope(of expected: Self) throws {
        guard runtime == expected.runtime, installationID == expected.installationID, releaseDigest == expected.releaseDigest,
              initializationDigest == expected.initializationDigest else { throw AdministrativeSetupError.staleProgress }
    }
    func observing(_ progress: RuntimeAuditUpgradeOperation.Progress) throws -> Self {
        let stage: Stage, roles: Set<AuthorityCodeRole>
        switch progress {
        case .waitingForActivity: stage = .waitingForActivity; roles = []
        case .waitingForMachine: stage = .waitingForMachine; roles = []
        case .graphPrepared: stage = .graphPrepared; roles = []
        case .waitingForQuiescence: stage = .waitingForQuiescence; roles = []
        case .filesChanging: stage = .filesChanging; roles = []
        case .filesVerified: stage = .filesVerified; roles = []
        case .metadataCommitted: stage = .metadataCommitted; roles = []
        case .readyToRestart: stage = .readyToRestart; roles = []
        case .registrationObserved(let result):
            guard result.selectedRoles == result.registrationConfirmed else { throw AdministrativeSetupChannelError.invalidMessage }
            stage = .registrationObserved; roles = result.registrationConfirmed
        case .alreadyCurrent: stage = .alreadyCurrent; roles = []
        }
        return try .init(runtime: runtime, installationID: installationID, releaseDigest: releaseDigest,
            initializationDigest: initializationDigest, stage: stage, registrationObserved: roles)
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(runtime.bytes), 2: .bytes(installationID),
            3: .bytes(releaseDigest), 4: .bytes(initializationDigest), 5: .unsigned(stage.rawValue),
            6: .array(registrationObserved.map(\.rawValue).sorted().map(CBORValue.unsigned))]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...6),
              f[0] == .unsigned(1), case .bytes(let runtime) = f[1], case .bytes(let installation) = f[2],
              case .bytes(let release) = f[3], case .bytes(let initialization) = f[4],
              case .unsigned(let rawStage) = f[5], let stage = Stage(rawValue: rawStage),
              case .array(let rawRoles) = f[6], rawRoles.count <= 3 else { throw AdministrativeSetupChannelError.invalidMessage }
        var roles: Set<AuthorityCodeRole> = []
        for raw in rawRoles {
            guard case .unsigned(let n) = raw, let role = AuthorityCodeRole(rawValue: n), roles.insert(role).inserted else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
        }
        let value = try Self(runtime: .decode(runtime), installationID: installation, releaseDigest: release,
            initializationDigest: initialization, stage: stage, registrationObserved: roles)
        guard try value.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return value
    }
}
