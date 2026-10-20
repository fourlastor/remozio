import CryptoKit
import Foundation
import RemozioProtocol

/// Local recovery state only. Imported bytes cannot supply any part of the destination scope.
struct SharedSetupImportIntent: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    struct Scope: Equatable, Sendable {
        let macID: Data
        let installationID: Data
        let releaseDigest: Data
        let accountID: Data
        let ownerUID: UInt32
        let accountBinding: Data

        init(account: AccountPreparationIntent, inventory: InstallationInventory) throws {
            guard account.storagePrepared, inventory.macID == account.macID,
                  inventory.installationID == account.installationID, inventory.releaseDigest == account.releaseDigest else {
                throw SharedSetupImportError.wrongScope
            }
            try self.init(macID: account.macID, installationID: account.installationID, releaseDigest: account.releaseDigest,
                accountID: account.accountID, ownerUID: account.ownerUID, accountBinding: Data(SHA256.hash(data: account.bytes)))
        }
        fileprivate init(macID: Data, installationID: Data, releaseDigest: Data, accountID: Data,
                         ownerUID: UInt32, accountBinding: Data) throws {
            guard [macID, installationID, accountID].allSatisfy({ $0.count == 16 }), releaseDigest.count == 32,
                  accountBinding.count == 32, ownerUID > 0, ownerUID < UInt32.max else { throw SharedSetupImportError.invalidRecord }
            self.macID = macID; self.installationID = installationID; self.releaseDigest = releaseDigest
            self.accountID = accountID; self.ownerUID = ownerUID; self.accountBinding = accountBinding
        }
    }
    /// Recovery retains public choices only. Provider credentials must come from the reopened encrypted bundle.
    struct Recipe: Equatable, Sendable {
        struct CloudflareScope: Equatable, Sendable {
            let accountID: String
            let zoneID: String
            let dnsSuffix: String
        }
        private static let limits = try! CBORLimits(maxBytes: 68_000, maxDepth: 3, maxItems: 32)
        private let settingsBytes: Data
        let firebaseProject: String?
        let pushClient: SetupPushClientConfiguration?
        let cloudflare: CloudflareScope?
        var settings: PortableSetup { get throws { try .init(canonicalBytes: settingsBytes) } }
        var settingsVersion: UInt64 { get throws { try Self.version(settingsBytes) } }
        var originalVersion: UInt64 { get throws {
            let settings = try settings
            return settings.appPreferences != nil ? 4 : pushClient != nil ? 3 : settings.defaults.gateway != nil ? 2 : 1
        } }

        init(proposal: PortableSetup) throws {
            try self.init(settingsBytes: PortableSetup(defaults: proposal.defaults, appPreferences: proposal.appPreferences).canonicalBytes(),
                firebaseProject: proposal.fcm?.project, pushClient: proposal.pushClient,
                cloudflare: proposal.cloudflare.map { .init(accountID: $0.accountID, zoneID: $0.zoneID, dnsSuffix: $0.dnsSuffix) })
        }
        private init(settingsBytes: Data, firebaseProject: String?, pushClient: SetupPushClientConfiguration?,
                     cloudflare: CloudflareScope?) throws {
            let settings = try PortableSetup(canonicalBytes: settingsBytes)
            guard settings.fcm == nil, settings.cloudflare == nil, settings.pushClient == nil,
                  try settings.canonicalBytes() == settingsBytes else { throw SharedSetupImportError.invalidRecord }
            if let firebaseProject { try SetupFCMConfiguration.validateProject(firebaseProject) }
            if let pushClient {
                guard settings.defaults.gateway != nil, firebaseProject == pushClient.projectID else {
                    throw SharedSetupImportError.invalidRecord
                }
            }
            if let cloudflare {
                try SetupCloudflareConfiguration.validateScope(accountID: cloudflare.accountID,
                    zoneID: cloudflare.zoneID, dnsSuffix: cloudflare.dnsSuffix)
            }
            self.settingsBytes = settingsBytes; self.firebaseProject = firebaseProject
            self.pushClient = pushClient; self.cloudflare = cloudflare
        }
        fileprivate static func version(_ bytes: Data) throws -> UInt64 {
            let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 4, maxItems: 128)
            guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  case let .unsigned(version) = fields[0], PortableSetup.supportedVersions.contains(version) else {
                throw SharedSetupImportError.invalidRecord
            }
            return version
        }
        var bytes: Data { get throws {
            try DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(settingsBytes), 2: firebaseProject.map(CBORValue.text) ?? .null,
                3: pushClient.map { .array([$0.projectID, $0.senderID, $0.packageName].map(CBORValue.text)) } ?? .null,
                4: cloudflare.map { .array([$0.accountID, $0.zoneID, $0.dnsSuffix].map(CBORValue.text)) } ?? .null
            ]), limits: Self.limits)
        } }
        static func decode(_ bytes: Data) throws -> Self {
            guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .unsigned(1),
                  case let .bytes(settings) = fields[1] else { throw SharedSetupImportError.invalidRecord }
            let project: String?
            if fields[2] == .null { project = nil }
            else if case let .text(value) = fields[2] { project = value }
            else { throw SharedSetupImportError.invalidRecord }
            func triple(_ key: UInt64) throws -> [String]? {
                if fields[key] == .null { return nil }
                guard case let .array(values) = fields[key], values.count == 3 else { throw SharedSetupImportError.invalidRecord }
                return try values.map { guard case let .text(value) = $0 else { throw SharedSetupImportError.invalidRecord }; return value }
            }
            let push = try triple(3).map { try SetupPushClientConfiguration(projectID: $0[0], senderID: $0[1], packageName: $0[2]) }
            let cloud = try triple(4).map { CloudflareScope(accountID: $0[0], zoneID: $0[1], dnsSuffix: $0[2]) }
            let result = try Self(settingsBytes: settings, firebaseProject: project, pushClient: push, cloudflare: cloud)
            guard try result.bytes == bytes else { throw SharedSetupImportError.invalidRecord }
            return result
        }
    }
    typealias Phase = SetupPortableImportProgress.Phase
    static let maximumBytes = 70_000
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 2, maxItems: 40)
    let scope: Scope
    let operationID: Data
    let revision: Data
    let phase: Phase
    let recipe: Recipe
    let proposalDigest: Data
    let originalPortableVersion: UInt64
    var description: String { "SharedSetupImportIntent(redacted)" }
    var debugDescription: String { description }

    init(scope: Scope, proposal: PortableSetup, operationID: Data = AccountPreparationIntent.randomID()) throws {
        let bytes = try proposal.canonicalBytes()
        try self.init(scope: scope, recipe: Recipe(proposal: proposal), proposalDigest: Data(SHA256.hash(data: bytes)),
            originalPortableVersion: Recipe.version(bytes), operationID: operationID,
            revision: AccountPreparationIntent.randomID(), phase: .retained)
    }
    private init(scope: Scope, recipe: Recipe, proposalDigest: Data, originalPortableVersion: UInt64,
                 operationID: Data, revision: Data, phase: Phase) throws {
        guard operationID.count == 16, revision.count == 16, proposalDigest.count == 32,
              try recipe.originalVersion == originalPortableVersion else { throw SharedSetupImportError.invalidRecord }
        self.scope = scope; self.recipe = recipe; self.proposalDigest = proposalDigest
        self.originalPortableVersion = originalPortableVersion
        self.operationID = operationID; self.revision = revision; self.phase = phase
    }
    /// Reopening the encrypted bundle must match all reviewed bytes before any credential is used.
    func matches(_ proposal: PortableSetup) throws -> Bool {
        let bytes = try proposal.canonicalBytes()
        let reopenedRecipe = try Recipe(proposal: proposal)
        return proposalDigest == Data(SHA256.hash(data: bytes)) && recipe == reopenedRecipe
    }
    /// The caller must verify the native outputs before advancing a marker. A marker alone grants no action authority.
    func advanced(to next: Phase) throws -> Self {
        guard next.rawValue == phase.rawValue + 1 else { throw SharedSetupImportError.invalidTransition }
        return try .init(scope: scope, recipe: recipe, proposalDigest: proposalDigest, originalPortableVersion: originalPortableVersion,
            operationID: operationID, revision: AccountPreparationIntent.randomID(), phase: next)
    }
    var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(2), 1: .text("remozio-shared-setup-import"), 2: .bytes(scope.macID), 3: .bytes(scope.installationID),
            4: .bytes(scope.releaseDigest), 5: .bytes(scope.accountID), 6: .unsigned(UInt64(scope.ownerUID)),
            7: .bytes(scope.accountBinding), 8: .bytes(operationID), 9: .bytes(revision), 10: .unsigned(phase.rawValue),
            11: .bytes(try recipe.bytes), 12: .bytes(proposalDigest), 13: .unsigned(originalPortableVersion)
        ]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...13),
              fields[0] == .unsigned(2), fields[1] == .text("remozio-shared-setup-import"),
              case let .bytes(mac) = fields[2], case let .bytes(installation) = fields[3], case let .bytes(release) = fields[4],
              case let .bytes(account) = fields[5], case let .unsigned(owner) = fields[6], let uid = UInt32(exactly: owner),
              case let .bytes(binding) = fields[7], case let .bytes(operation) = fields[8], case let .bytes(revision) = fields[9],
              case let .unsigned(phaseValue) = fields[10], let phase = Phase(rawValue: phaseValue),
              case let .bytes(recipe) = fields[11], case let .bytes(digest) = fields[12],
              case let .unsigned(portableVersion) = fields[13] else { throw SharedSetupImportError.invalidRecord }
        let scope = try Scope(macID: mac, installationID: installation, releaseDigest: release, accountID: account,
            ownerUID: uid, accountBinding: binding)
        let result = try Self(scope: scope, recipe: Recipe.decode(recipe), proposalDigest: digest, originalPortableVersion: portableVersion,
            operationID: operation, revision: revision, phase: phase)
        guard try result.bytes == bytes else { throw SharedSetupImportError.invalidRecord }
        return result
    }
}

enum SharedSetupImportError: Error, Equatable {
    case invalidRecord, wrongScope, conflict, staleRevision, invalidTransition, capacity, incompatibleStore, corruptRecord
    case closed, unavailable, transactionActive
    case storage(Int32)
}
