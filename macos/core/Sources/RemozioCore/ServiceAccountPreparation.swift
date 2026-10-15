import Darwin
import Foundation

protocol ServiceAccountDirectoryAccess: AnyObject {
    func lookup(kind: ServiceDirectoryKind, index: ServiceDirectoryIndex) throws -> [ServiceDirectoryRecord]
    func createGroup(_ claim: ServiceAccountClaim) throws
    func createUser(_ claim: ServiceAccountClaim) throws
    func validateGroup(_ claim: ServiceAccountClaim) throws
    func validateUser(_ claim: ServiceAccountClaim, ownerUID: UInt32) throws
}

/// Resumable directory work under the setup owner's serialization and current administrator authorization.
/// Product composition must use the Root directory driver. Fixtures cannot prove native account creation or isolation.
enum ServiceAccountPreparation {
    enum Stage: Equatable {
        case planRetained, groupCreated(ServiceAccountRole), userCreated(ServiceAccountRole), validated(ServiceAccountRole), completed
    }
    static func prepare(machine: PreparationIntentStore, account: AccountPreparationIntent,
                        verifyCurrent: () throws -> Void) throws -> ServiceAccountPlanStorage.State {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent()
        let storage = try ServiceAccountPlanStorage.open(machine: machine, account: account)
        let directory = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
        _ = try resume(account: account, storage: storage, directory: directory,
            makePlan: { try ServiceAccountAllocator.plan(account: account, reserved: machine.reservedServiceAccountNumbers(),
                available: directory.available) }, verifyCurrent: verifyCurrent)
        return try storage.load()
    }
    static func resume(account: AccountPreparationIntent, storage: ServiceAccountPlanStorage,
                       directory: any ServiceAccountDirectoryAccess,
                       makePlan: () throws -> ServiceAccountPlan, verifyCurrent: () throws -> Void,
                       didStage: (Stage) throws -> Void = { _ in }) throws -> ServiceAccountPlan {
        try verifyCurrent()
        let initial = try storage.load()
        var completed = initial.complete
        let plan: ServiceAccountPlan
        if let retained = initial.plan { plan = retained }
        else {
            // An absent plan cannot authorize adopting an existing namespaced record.
            for role in ServiceAccountPlan.roles {
                let name = ServiceAccountClaim.recordName(accountID: account.accountID, role: role)
                for kind in [ServiceDirectoryKind.group, .user] {
                    guard try directory.lookup(kind: kind, index: .name(name)).isEmpty else {
                        throw ServiceAccountProvisioningError.conflictingRecord
                    }
                }
            }
            plan = try makePlan()
        }
        try plan.validate(account: account)
        // Verify a retained plan as well. A committed reservation may precede a lost acknowledgement.
        try storage.retain(plan, verify: verifyCurrent)
        try didStage(.planRetained)
        func verifyScope() throws {
            try verifyCurrent(); try plan.validate(account: account)
            let current = try storage.load()
            guard current.plan == plan else { throw ServiceAccountProvisioningError.changedScope }
            completed = completed || current.complete
        }
        func state(_ claim: ServiceAccountClaim, _ kind: ServiceDirectoryKind) throws -> ServiceDirectoryState {
            try ServiceDirectoryPreflight.evaluate(claim: claim, kind: kind,
                byName: directory.lookup(kind: kind, index: .name(claim.name)),
                byNumber: directory.lookup(kind: kind, index: .number(claim.number)),
                byID: directory.lookup(kind: kind, index: .id(kind == .user ? claim.userID : claim.groupID)))
        }
        func preflight() throws {
            try verifyScope()
            for claim in plan.claims {
                let group = try state(claim, .group), user = try state(claim, .user)
                guard group != .absent || user == .absent else { throw ServiceAccountProvisioningError.conflictingRecord }
                if completed {
                    guard group == .retained, user == .retained else { throw ServiceAccountProvisioningError.missingRecord }
                }
                if group == .retained { try directory.validateGroup(claim) }
                if user == .retained { try directory.validateUser(claim, ownerUID: plan.ownerUID) }
            }
        }
        // Check all roles before the first write, and again before each following write.
        try preflight()
        if !completed {
            for claim in plan.claims {
                if try state(claim, .group) == .absent {
                    try preflight(); try directory.createGroup(claim)
                    try didStage(.groupCreated(claim.role)); try verifyScope()
                }
                guard try state(claim, .group) == .retained else { throw ServiceAccountProvisioningError.missingRecord }
                try directory.validateGroup(claim)
                if try state(claim, .user) == .absent {
                    try preflight(); try directory.createUser(claim)
                    try didStage(.userCreated(claim.role)); try verifyScope()
                }
                guard try state(claim, .user) == .retained else { throw ServiceAccountProvisioningError.missingRecord }
                try directory.validateUser(claim, ownerUID: plan.ownerUID)
                try didStage(.validated(claim.role))
            }
        }
        func verifyComplete() throws {
            try preflight()
            for claim in plan.claims {
                guard try state(claim, .group) == .retained, try state(claim, .user) == .retained else {
                    throw ServiceAccountProvisioningError.missingRecord
                }
            }
        }
        try storage.complete(plan, verify: verifyComplete)
        try didStage(.completed)
        try verifyComplete()
        return plan
    }
}
