import CryptoKit
import Foundation
import RemozioProtocol

/// Historical activation progress only. It contains no path, credential or current runtime health assertion.
public struct SetupActivationProgress: Equatable, Sendable {
    public let macID: Data
    public let accountID: Data
    public let setupID: Data
    public let accountRevision: Data
    public let ownerUID: UInt32
    public let servicePlanID: Data
    public let materialID: Data
    public let planDigest: Data?
    public let jobsRegistered: Bool
    init(account: AccountPreparationIntent, runtime: RuntimePreparationState, state: RuntimeActivationState) throws {
        guard runtime.configurationPublished, let reference = runtime.reference,
              state.plan != nil || !state.jobsRegistered else { throw RuntimeActivationError.incomplete }
        try reference.validate(account: account, services: reference.services)
        try state.plan?.validate(account: account, reference: reference)
        macID = account.macID; accountID = account.accountID; setupID = account.setupID; accountRevision = account.revision
        ownerUID = account.ownerUID; servicePlanID = reference.services.planID; materialID = reference.materialID
        planDigest = try state.plan.map { Data(SHA256.hash(data: try $0.encoded)) }; jobsRegistered = state.jobsRegistered
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(setupID),
            4: .bytes(accountRevision), 5: .unsigned(UInt64(ownerUID)), 6: .bytes(servicePlanID), 7: .bytes(materialID),
            8: planDigest.map(CBORValue.bytes) ?? .null, 9: .boolean(jobsRegistered)]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...9),
              f[0] == .unsigned(1), case .bytes(let mac) = f[1], mac.count == 16, case .bytes(let account) = f[2], account.count == 16,
              case .bytes(let setup) = f[3], setup.count == 16, case .bytes(let revision) = f[4], revision.count == 16,
              case .unsigned(let owner) = f[5], owner > 0, owner < UInt32.max, case .bytes(let services) = f[6], services.count == 16,
              case .bytes(let material) = f[7], material.count == 16, case .boolean(let registered) = f[9] else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        let digest: Data?
        switch f[8] {
        case .null: digest = nil
        case .bytes(let value) where value.count == 32: digest = value
        default: throw AdministrativeSetupChannelError.invalidMessage
        }
        guard digest != nil || !registered else { throw AdministrativeSetupChannelError.invalidMessage }
        let value = Self(macID: mac, accountID: account, setupID: setup, accountRevision: revision, ownerUID: UInt32(owner),
            servicePlanID: services, materialID: material, planDigest: digest, jobsRegistered: registered)
        guard try value.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return value
    }
    func validateCompletion(of expected: Self) throws {
        guard macID == expected.macID, accountID == expected.accountID, setupID == expected.setupID,
              accountRevision == expected.accountRevision, ownerUID == expected.ownerUID, servicePlanID == expected.servicePlanID,
              materialID == expected.materialID, planDigest != nil, jobsRegistered,
              expected.planDigest == nil || planDigest == expected.planDigest else { throw AdministrativeSetupChannelError.invalidMessage }
    }
    private init(macID: Data, accountID: Data, setupID: Data, accountRevision: Data, ownerUID: UInt32,
                 servicePlanID: Data, materialID: Data, planDigest: Data?, jobsRegistered: Bool) {
        self.macID = macID; self.accountID = accountID; self.setupID = setupID; self.accountRevision = accountRevision
        self.ownerUID = ownerUID; self.servicePlanID = servicePlanID; self.materialID = materialID
        self.planDigest = planDigest; self.jobsRegistered = jobsRegistered
    }
    private static let limits = try! CBORLimits(maxBytes: 384, maxDepth: 1, maxItems: 21)
}
