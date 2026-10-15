import Foundation
import RemozioProtocol

/// Setup progress only. It does not assert service health, pairing or command execution readiness.
public struct SetupServiceAccountProgress: Equatable, Sendable {
    public let macID: Data
    public let accountID: Data
    public let setupID: Data
    public let accountRevision: Data
    public let ownerUID: UInt32
    public let planID: Data?
    public let complete: Bool
    init(account: AccountPreparationIntent, state: ServiceAccountPlanStorage.State) throws {
        guard account.storagePrepared, state.plan != nil || !state.complete else { throw ServiceAccountProvisioningError.incomplete }
        try state.plan?.validate(account: account)
        macID = account.macID; accountID = account.accountID; setupID = account.setupID; accountRevision = account.revision
        ownerUID = account.ownerUID; planID = state.plan?.planID; complete = state.complete
    }
    public var bytes: Data {
        get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(setupID),
                4: .bytes(accountRevision), 5: .unsigned(UInt64(ownerUID)), 6: planID.map(CBORValue.bytes) ?? .null,
                7: .boolean(complete)]), limits: Self.limits)
        }
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(0...7), f[0] == .unsigned(1),
              case .bytes(let mac) = f[1], mac.count == 16, case .bytes(let account) = f[2], account.count == 16,
              case .bytes(let setup) = f[3], setup.count == 16, case .bytes(let revision) = f[4], revision.count == 16,
              case .unsigned(let owner) = f[5], owner > 0, owner < UInt32.max, case .boolean(let complete) = f[7] else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        let plan: Data?
        switch f[6] {
        case .null: plan = nil
        case .bytes(let value) where value.count == 16: plan = value
        default: throw AdministrativeSetupChannelError.invalidMessage
        }
        guard plan != nil || !complete else { throw AdministrativeSetupChannelError.invalidMessage }
        let value = Self(macID: mac, accountID: account, setupID: setup, accountRevision: revision,
            ownerUID: UInt32(owner), planID: plan, complete: complete)
        guard try value.bytes == bytes else { throw AdministrativeSetupChannelError.invalidMessage }; return value
    }
    func validateCompletion(of expected: Self) throws {
        guard macID == expected.macID, accountID == expected.accountID, setupID == expected.setupID,
              accountRevision == expected.accountRevision, ownerUID == expected.ownerUID, planID != nil, complete,
              expected.planID == nil || planID == expected.planID else { throw AdministrativeSetupChannelError.invalidMessage }
    }
    private init(macID: Data, accountID: Data, setupID: Data, accountRevision: Data, ownerUID: UInt32, planID: Data?, complete: Bool) {
        self.macID = macID; self.accountID = accountID; self.setupID = setupID; self.accountRevision = accountRevision
        self.ownerUID = ownerUID; self.planID = planID; self.complete = complete
    }
    private static let limits = try! CBORLimits(maxBytes: 384, maxDepth: 2, maxItems: 24)
}
