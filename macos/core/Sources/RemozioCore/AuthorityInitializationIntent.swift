import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum AuthorityInitializationError: Error, Equatable {
    case invalidIntent, conflictingIntent, staleRevision, missingIntent, invalidBoundary, completed
}

/// Retained setup progress. It grants no enrollment, service registration or command authority.
public struct AuthorityInitializationIntent: Equatable, Sendable, CustomStringConvertible {
    public let setupID: Data
    public let revision: Data
    public let installationID: Data
    public let macID: Data
    public let accountID: Data
    public let releaseDigest: Data
    public let initializationDigest: Data
    let initializationBytes: Data
    /// Restores the exact declaration. The declaration grants no setup authorization.
    public var initialAuthority: AuthorityJournalInitialization { get throws { try .decodeInitialization(initializationBytes) } }
    public let journalPath: String
    public let continuityPath: String
    public let checkpoint: ContinuityCheckpoint?
    public let complete: Bool
    public var description: String { "AuthorityInitializationIntent(redacted)" }

    init(setupID: Data, revision: Data, installationID: Data, macID: Data, accountID: Data,
         releaseDigest: Data, initializationDigest: Data, initializationBytes: Data, journalPath: String, continuityPath: String,
         checkpoint: ContinuityCheckpoint? = nil, complete: Bool = false) throws {
        guard [setupID, revision, installationID, macID, accountID].allSatisfy({ $0.count == 16 }),
              releaseDigest.count == 32, initializationDigest.count == 32,
              Self.path(journalPath, basename: "journal.sqlite"), Self.path(continuityPath, basename: "continuity.sqlite"),
              (journalPath as NSString).deletingLastPathComponent != (continuityPath as NSString).deletingLastPathComponent,
              !(continuityPath as NSString).deletingLastPathComponent.hasPrefix((journalPath as NSString).deletingLastPathComponent + "/"),
              !(journalPath as NSString).deletingLastPathComponent.hasPrefix((continuityPath as NSString).deletingLastPathComponent + "/"),
              !complete || checkpoint != nil else { throw AuthorityInitializationError.invalidIntent }
        let initial = try AuthorityJournalInitialization.decodeInitialization(initializationBytes)
        guard initial.descriptor.macID == macID, initial.descriptor.accountID == accountID,
              try initial.initializationDigest == initializationDigest else { throw AuthorityInitializationError.invalidIntent }
        if let checkpoint {
            guard checkpoint.generation == 1, checkpoint.authorityGeneration == 1, checkpoint.journalHead == 0, checkpoint.journalEpoch == initial.descriptor.epoch else {
                throw AuthorityInitializationError.invalidBoundary
            }
        }
        self.setupID = setupID; self.revision = revision; self.installationID = installationID
        self.macID = macID; self.accountID = accountID; self.releaseDigest = releaseDigest
        self.initializationDigest = initializationDigest; self.initializationBytes = initializationBytes; self.journalPath = journalPath; self.continuityPath = continuityPath
        self.checkpoint = checkpoint; self.complete = complete
    }
    private static func path(_ value: String, basename: String) -> Bool {
        let parts = value.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        return value.hasPrefix("/") && value.utf8.count < Int(PATH_MAX) && parts.last == Substring(basename) &&
            parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }
    }
    func advancing(checkpoint: ContinuityCheckpoint, complete: Bool) throws -> Self {
        var uuid = UUID().uuid
        var next = withUnsafeBytes(of: &uuid) { Data($0) }
        while next == revision { uuid = UUID().uuid; next = withUnsafeBytes(of: &uuid) { Data($0) } }
        return try Self(setupID: setupID, revision: next, installationID: installationID, macID: macID, accountID: accountID,
            releaseDigest: releaseDigest, initializationDigest: initializationDigest, initializationBytes: initializationBytes, journalPath: journalPath,
            continuityPath: continuityPath, checkpoint: checkpoint, complete: complete)
    }
    var bytes: Data {
        get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(setupID), 2: .bytes(revision),
                3: .bytes(installationID), 4: .bytes(macID), 5: .bytes(accountID), 6: .bytes(releaseDigest),
                7: .bytes(initializationDigest), 8: .text(journalPath), 9: .text(continuityPath),
                10: checkpoint.map { .bytes(try $0.bytes) } ?? .null, 11: .unsigned(complete ? 1 : 0), 12: .bytes(initializationBytes)]), limits: Self.limits())
        }
    }
    static let maximumBytes = 147456
    private static func limits() throws -> CBORLimits { try .init(maxBytes: maximumBytes, maxDepth: 3, maxItems: 40) }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits()), Set(f.keys) == Set((0...12).map(UInt64.init)),
              f[0] == .unsigned(1), case .bytes(let setup) = f[1], case .bytes(let revision) = f[2],
              case .bytes(let installation) = f[3], case .bytes(let mac) = f[4], case .bytes(let account) = f[5],
              case .bytes(let release) = f[6], case .bytes(let digest) = f[7], case .text(let journal) = f[8],
              case .text(let continuity) = f[9], case .unsigned(let complete) = f[11], complete <= 1, case .bytes(let inputs) = f[12] else {
            throw AuthorityInitializationError.invalidIntent
        }
        let checkpoint: ContinuityCheckpoint?
        if case .bytes(let data) = f[10] { checkpoint = try .decode(data) }
        else { guard f[10] == .null else { throw AuthorityInitializationError.invalidIntent }; checkpoint = nil }
        let value = try Self(setupID: setup, revision: revision, installationID: installation, macID: mac, accountID: account,
            releaseDigest: release, initializationDigest: digest, initializationBytes: inputs, journalPath: journal, continuityPath: continuity,
            checkpoint: checkpoint, complete: complete == 1)
        guard try value.bytes == bytes else { throw AuthorityInitializationError.invalidIntent }
        return value
    }
}

extension AuthorityJournalInitialization {
    /// Binds all setup inputs. It does not verify the release or authenticate an administrator.
    var initializationDigest: Data { get throws { Data(SHA256.hash(data: try initializationBytes)) } }
    var initializationBytes: Data {
        get throws {
            guard !capabilities.contracts.isEmpty, capabilities.contracts.count <= 64,
                  capabilities.contracts.values.allSatisfy({ $0.count <= 128 }), !allowedContracts.isEmpty,
                  allowedContracts.isSubset(of: Set(capabilities.contracts.keys)) else { throw AuthorityInitializationError.invalidIntent }
            let contracts = capabilities.contracts.sorted {
                ($0.key.requestKind.rawValue, $0.key.wireVersion, $0.key.schemaVersion) <
                    ($1.key.requestKind.rawValue, $1.key.wireVersion, $1.key.schemaVersion)
            }.map { contract, features in
                CBORValue.array([.text(contract.requestKind.rawValue), .unsigned(contract.wireVersion), .unsigned(contract.schemaVersion),
                    .array(features.sorted().map(CBORValue.unsigned)), .unsigned(allowedContracts.contains(contract) ? 1 : 0)])
            }
            let limits = try CBORLimits(maxBytes: 131072, maxDepth: 5, maxItems: 10000)
            let bytes = try DeterministicCBOR.encode(.map([0: .text("remozio/authority-initialization/v1"),
                1: .bytes(descriptor.encode(limits: limits)), 2: .bytes(codePolicy.bytes), 3: .array(contracts),
                4: .unsigned(installCommandReplay ? 1 : 0)]), limits: limits)
            return bytes
        }
    }
    static func decodeInitialization(_ bytes: Data) throws -> Self {
        let limits = try CBORLimits(maxBytes: 131072, maxDepth: 5, maxItems: 10000)
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == [0, 1, 2, 3, 4],
              f[0] == .text("remozio/authority-initialization/v1"), case .bytes(let descriptor) = f[1],
              case .bytes(let policy) = f[2], case .array(let contracts) = f[3], contracts.count <= 64,
              case .unsigned(let replay) = f[4], replay <= 1 else { throw AuthorityInitializationError.invalidIntent }
        var capabilities = [RequestContract: Set<UInt64>](), allowed = Set<RequestContract>()
        for item in contracts {
            guard case .array(let values) = item, values.count == 5, case .text(let kind) = values[0],
                  let requestKind = RequestKind(rawValue: kind), case .unsigned(let wire) = values[1],
                  case .unsigned(let schema) = values[2], case .array(let featureValues) = values[3], featureValues.count <= 128,
                  case .unsigned(let enabled) = values[4], enabled <= 1 else { throw AuthorityInitializationError.invalidIntent }
            let contract = try RequestContract(requestKind: requestKind, wireVersion: wire, schemaVersion: schema)
            var features = Set<UInt64>()
            for value in featureValues {
                guard case .unsigned(let feature) = value, features.insert(feature).inserted else {
                    throw AuthorityInitializationError.invalidIntent
                }
            }
            guard capabilities.updateValue(features, forKey: contract) == nil else { throw AuthorityInitializationError.invalidIntent }
            if enabled == 1 { allowed.insert(contract) }
        }
        let value = Self(descriptor: try .decode(descriptor, limits: limits), codePolicy: try .decode(policy),
            capabilities: .init(contracts: capabilities), allowedContracts: allowed, installCommandReplay: replay == 1)
        guard try value.initializationBytes == bytes else { throw AuthorityInitializationError.invalidIntent }
        return value
    }

}
