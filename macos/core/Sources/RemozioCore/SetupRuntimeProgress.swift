import Foundation
import RemozioProtocol

/// Historical setup progress. Publication does not assert service health or command readiness.
public struct SetupRuntimeProgress: Equatable, Sendable {
    public let macID: Data
    public let accountID: Data
    public let setupID: Data
    public let accountRevision: Data
    public let ownerUID: UInt32
    public let servicePlanID: Data
    public let materialID: Data?
    public let configurationPublished: Bool

    init(account: AccountPreparationIntent, services: ServiceAccountPlanStorage.State, state: RuntimePreparationState) throws {
        guard account.storagePrepared, services.complete, let plan = services.plan,
              state.reference != nil || !state.configurationPublished else { throw RuntimePreparationError.incomplete }
        try plan.validate(account: account)
        try state.reference?.validate(account: account, services: plan)
        macID = account.macID; accountID = account.accountID; setupID = account.setupID
        accountRevision = account.revision; ownerUID = account.ownerUID; servicePlanID = plan.planID
        materialID = state.reference?.materialID; configurationPublished = state.configurationPublished
    }
    public var bytes: Data {
        get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(setupID),
                4: .bytes(accountRevision), 5: .unsigned(UInt64(ownerUID)), 6: .bytes(servicePlanID),
                7: materialID.map(CBORValue.bytes) ?? .null, 8: .boolean(configurationPublished)]), limits: Self.limits)
        }
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(0...8), f[0] == .unsigned(1),
              case .bytes(let mac) = f[1], mac.count == 16, case .bytes(let account) = f[2], account.count == 16,
              case .bytes(let setup) = f[3], setup.count == 16, case .bytes(let revision) = f[4], revision.count == 16,
              case .unsigned(let owner) = f[5], owner > 0, owner < UInt32.max,
              case .bytes(let plan) = f[6], plan.count == 16, case .boolean(let complete) = f[8] else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        let material: Data?
        switch f[7] {
        case .null: material = nil
        case .bytes(let id) where id.count == 16: material = id
        default: throw AdministrativeSetupChannelError.invalidMessage
        }
        guard material != nil || !complete else { throw AdministrativeSetupChannelError.invalidMessage }
        let value = Self(macID: mac, accountID: account, setupID: setup, accountRevision: revision, ownerUID: UInt32(owner),
            servicePlanID: plan, materialID: material, configurationPublished: complete)
        guard try value.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return value
    }
    func validateCompletion(of expected: Self) throws {
        guard macID == expected.macID, accountID == expected.accountID, setupID == expected.setupID,
              accountRevision == expected.accountRevision, ownerUID == expected.ownerUID, servicePlanID == expected.servicePlanID,
              materialID != nil, configurationPublished, expected.materialID == nil || materialID == expected.materialID else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
    }
    private init(macID: Data, accountID: Data, setupID: Data, accountRevision: Data, ownerUID: UInt32,
                 servicePlanID: Data, materialID: Data?, configurationPublished: Bool) {
        self.macID = macID; self.accountID = accountID; self.setupID = setupID; self.accountRevision = accountRevision
        self.ownerUID = ownerUID; self.servicePlanID = servicePlanID; self.materialID = materialID
        self.configurationPublished = configurationPublished
    }
    private static let limits = try! CBORLimits(maxBytes: 384, maxDepth: 2, maxItems: 28)
}
