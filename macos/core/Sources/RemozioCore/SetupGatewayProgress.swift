import CryptoKit
import Foundation
import RemozioProtocol

/// Historical setup progress. This value contains no private credential, path or current service health assertion.
public struct SetupGatewayProgress: Equatable, Sendable {
    public let macID: Data
    public let accountID: Data
    public let setupID: Data
    public let accountRevision: Data
    public let ownerUID: UInt32
    public let runtimeMaterialID: Data
    public let foregroundDigest: Data
    public let gatewayMaterialID: Data?
    public let journalIntentDigest: Data?
    public let journalInitialized: Bool

    init(account: AccountPreparationIntent, runtime: RuntimePreparationState, activation: RuntimeActivationState,
         material: GatewayPreparationState, journal: GatewayJournalPreparationState) throws {
        guard account.storagePrepared, runtime.configurationPublished, let reference = runtime.reference,
              activation.jobsRegistered, let foreground = activation.plan, foreground.reference == reference,
              material.reference == nil || material.reference?.runtime == reference,
              journal.intent != nil || !journal.initialized else { throw GatewayPreparationError.incomplete }
        try reference.validate(account: account, services: reference.services)
        try foreground.validate(account: account, reference: reference)
        if let intent = journal.intent {
            guard intent.material == material.reference else { throw GatewayPreparationError.changedScope }
        }
        macID = account.macID; accountID = account.accountID; setupID = account.setupID
        accountRevision = account.revision; ownerUID = account.ownerUID; runtimeMaterialID = reference.materialID
        foregroundDigest = Data(SHA256.hash(data: try foreground.encoded))
        gatewayMaterialID = material.reference?.materialID; journalIntentDigest = try journal.intent?.digest
        journalInitialized = journal.initialized
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.purpose), 2: .bytes(macID), 3: .bytes(accountID),
            4: .bytes(setupID), 5: .bytes(accountRevision), 6: .unsigned(UInt64(ownerUID)), 7: .bytes(runtimeMaterialID),
            8: .bytes(foregroundDigest), 9: gatewayMaterialID.map(CBORValue.bytes) ?? .null,
            10: journalIntentDigest.map(CBORValue.bytes) ?? .null, 11: .boolean(journalInitialized)]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...11),
              f[0] == .unsigned(1), f[1] == .text(purpose),
              case .unsigned(let owner) = f[6], owner > 0, owner < UInt32.max,
              case .boolean(let initialized) = f[11] else { throw AdministrativeSetupChannelError.invalidMessage }
        func data(_ key: UInt64, _ count: Int) throws -> Data {
            guard case .bytes(let bytes) = f[key], bytes.count == count else { throw AdministrativeSetupChannelError.invalidMessage }; return bytes
        }
        func optional(_ key: UInt64, _ count: Int) throws -> Data? {
            if f[key] == .null { return nil }; return try data(key, count)
        }
        let material = try optional(9, 16), intent = try optional(10, 32)
        guard (intent == nil || material != nil), (intent != nil || !initialized) else { throw AdministrativeSetupChannelError.invalidMessage }
        let result = try Self(macID: data(2, 16), accountID: data(3, 16), setupID: data(4, 16), accountRevision: data(5, 16),
            ownerUID: UInt32(owner), runtimeMaterialID: data(7, 16), foregroundDigest: data(8, 32), gatewayMaterialID: material,
            journalIntentDigest: intent, journalInitialized: initialized)
        guard try result.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return result
    }
    func validatePreparation(of expected: Self) throws {
        guard macID == expected.macID, accountID == expected.accountID, setupID == expected.setupID,
              accountRevision == expected.accountRevision, ownerUID == expected.ownerUID,
              runtimeMaterialID == expected.runtimeMaterialID, foregroundDigest == expected.foregroundDigest,
              gatewayMaterialID != nil, journalIntentDigest != nil,
              expected.gatewayMaterialID == nil || gatewayMaterialID == expected.gatewayMaterialID,
              expected.journalIntentDigest == nil || journalIntentDigest == expected.journalIntentDigest,
              !expected.journalInitialized || journalInitialized else { throw AdministrativeSetupChannelError.invalidMessage }
    }
    func validateJournalCompletion(of expected: Self) throws {
        try validatePreparation(of: expected)
        guard expected.journalIntentDigest != nil, journalInitialized else { throw AdministrativeSetupChannelError.invalidMessage }
    }
    private init(macID: Data, accountID: Data, setupID: Data, accountRevision: Data, ownerUID: UInt32,
                 runtimeMaterialID: Data, foregroundDigest: Data, gatewayMaterialID: Data?, journalIntentDigest: Data?, journalInitialized: Bool) {
        self.macID = macID; self.accountID = accountID; self.setupID = setupID; self.accountRevision = accountRevision
        self.ownerUID = ownerUID; self.runtimeMaterialID = runtimeMaterialID; self.foregroundDigest = foregroundDigest
        self.gatewayMaterialID = gatewayMaterialID; self.journalIntentDigest = journalIntentDigest; self.journalInitialized = journalInitialized
    }
    private static let purpose = "remozio-gateway-setup-progress"
    private static let limits = try! CBORLimits(maxBytes: 640, maxDepth: 1, maxItems: 25)
}

/// Cleanup can remain pending after initialization. Neither field grants normal gateway readiness or push delivery.
public struct SetupGatewayJournalResult: Equatable, Sendable {
    public let progress: SetupGatewayProgress
    public let cleanupComplete: Bool
    init(progress: SetupGatewayProgress, cleanupComplete: Bool) throws {
        guard progress.journalInitialized else { throw GatewayPreparationError.incomplete }
        self.progress = progress; self.cleanupComplete = cleanupComplete
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.purpose), 2: .bytes(progress.bytes),
            3: .boolean(cleanupComplete)]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...3),
              f[0] == .unsigned(1), f[1] == .text(purpose), case .bytes(let progress) = f[2], case .boolean(let cleaned) = f[3] else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        let result = try Self(progress: .decode(progress), cleanupComplete: cleaned)
        guard try result.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return result
    }
    private static let purpose = "remozio-gateway-journal-result"
    private static let limits = try! CBORLimits(maxBytes: 768, maxDepth: 1, maxItems: 9)
}
