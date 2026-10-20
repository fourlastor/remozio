import CryptoKit
import Foundation
import RemozioProtocol

/// Historical import state only. It grants no administrator right and does not assert live service health.
public struct SetupPortableImportProgress: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public enum Phase: UInt64, Sendable { case retained, runtimePublished, gatewayPrepared, relayPrepared, rootComplete }
    public static let formatName = "setup.shared-import-progress"
    public static let supportedVersions: Set<UInt64> = [1]
    public static let maximumByteCount = 1024
    private static let limits = try! CBORLimits(maxBytes: maximumByteCount, maxDepth: 2, maxItems: 24)
    public let runtime: SetupRuntimeProgress
    public let installationID: Data
    public let releaseDigest: Data
    public let operationID: Data?
    public let revision: Data?
    public let proposalDigest: Data?
    public let phase: Phase?
    public let recordDigest: Data?
    public var description: String { "SetupPortableImportProgress(redacted)" }
    public var debugDescription: String { description }

    init(account: AccountPreparationIntent, inventory: InstallationInventory,
         services: ServiceAccountPlanStorage.State, runtime: RuntimePreparationState, retained: SharedSetupImportIntent?) throws {
        let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
        guard retained == nil || retained?.scope == scope else { throw SharedSetupImportError.wrongScope }
        try self.init(runtime: SetupRuntimeProgress(account: account, services: services, state: runtime),
            installationID: inventory.installationID, releaseDigest: inventory.releaseDigest,
            operationID: retained?.operationID, revision: retained?.revision, proposalDigest: retained?.proposalDigest,
            phase: retained?.phase, recordDigest: retained.map { Data(SHA256.hash(data: try $0.bytes)) })
    }
    private init(runtime: SetupRuntimeProgress, installationID: Data, releaseDigest: Data, operationID: Data?,
                 revision: Data?, proposalDigest: Data?, phase: Phase?, recordDigest: Data?) throws {
        guard installationID.count == 16, releaseDigest.count == 32 else { throw SharedSetupImportError.invalidRecord }
        let present = [operationID != nil, revision != nil, proposalDigest != nil, phase != nil, recordDigest != nil]
        guard present.allSatisfy({ $0 }) || present.allSatisfy({ !$0 }),
              operationID == nil || operationID?.count == 16, revision == nil || revision?.count == 16,
              proposalDigest == nil || proposalDigest?.count == 32, recordDigest == nil || recordDigest?.count == 32 else {
            throw SharedSetupImportError.invalidRecord
        }
        if let phase, phase != .retained {
            guard runtime.configurationPublished, runtime.materialID != nil else { throw SharedSetupImportError.invalidRecord }
        }
        self.runtime = runtime; self.installationID = installationID; self.releaseDigest = releaseDigest
        self.operationID = operationID; self.revision = revision; self.proposalDigest = proposalDigest
        self.phase = phase; self.recordDigest = recordDigest
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(try runtime.bytes), 2: .bytes(installationID), 3: .bytes(releaseDigest),
            4: operationID.map(CBORValue.bytes) ?? .null, 5: revision.map(CBORValue.bytes) ?? .null,
            6: proposalDigest.map(CBORValue.bytes) ?? .null, 7: phase.map { .unsigned($0.rawValue) } ?? .null,
            8: recordDigest.map(CBORValue.bytes) ?? .null
        ]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...8), fields[0] == .unsigned(1),
              case let .bytes(runtime) = fields[1], case let .bytes(installation) = fields[2],
              case let .bytes(release) = fields[3] else { throw SharedSetupImportError.invalidRecord }
        func data(_ key: UInt64) throws -> Data? {
            if fields[key] == .null { return nil }
            guard case let .bytes(value) = fields[key] else { throw SharedSetupImportError.invalidRecord }
            return value
        }
        let phase: Phase?
        if fields[7] == .null { phase = nil }
        else if case let .unsigned(value) = fields[7], let selected = Phase(rawValue: value) { phase = selected }
        else { throw SharedSetupImportError.invalidRecord }
        let result = try Self(runtime: SetupRuntimeProgress.decode(runtime), installationID: installation, releaseDigest: release,
            operationID: data(4), revision: data(5), proposalDigest: data(6), phase: phase, recordDigest: data(8))
        guard try result.bytes == bytes else { throw SharedSetupImportError.invalidRecord }; return result
    }
    /// The authenticated reply must retain exactly the reviewed destination and proposal. It is not final import completion.
    func validateRetention(of expected: Self, proposalDigest: Data) throws {
        guard runtime == expected.runtime, installationID == expected.installationID, releaseDigest == expected.releaseDigest,
              proposalDigest.count == 32, self.proposalDigest == proposalDigest, operationID != nil else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        if expected.operationID == nil {
            guard phase == .retained else { throw AdministrativeSetupChannelError.invalidMessage }
        } else {
            guard self == expected else { throw AdministrativeSetupChannelError.invalidMessage }
        }
    }
}
