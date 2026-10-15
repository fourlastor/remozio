import Darwin
import Foundation

/// Borrows the setup owner's machine connection. Numeric reservations and completion use the same protected transaction store.
final class ServiceAccountPlanStorage {
    struct State: Equatable {
        let plan: ServiceAccountPlan?
        let complete: Bool
    }
    private let machine: PreparationIntentStore
    private let account: AccountPreparationIntent
    static func open(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> ServiceAccountPlanStorage {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try .init(machine: machine, account: account)
    }
    // Ordinary-owner fixtures use actual protected SQLite storage without granting Root or directory mutation authority.
    init(machine: PreparationIntentStore, account: AccountPreparationIntent) throws {
        guard account.storagePrepared else { throw ServiceAccountProvisioningError.incomplete }
        try machine.validateAccountPreparation(account)
        self.machine = machine; self.account = account
    }
    func load() throws -> State {
        try machine.validateAccountPreparation(account)
        let state = try machine.serviceAccountPlan(accountID: account.accountID)
        try state.plan?.validate(account: account)
        return state
    }
    func retain(_ plan: ServiceAccountPlan, verify: () throws -> Void) throws {
        try verify(); try plan.validate(account: account)
        try machine.retainServiceAccountPlan(plan)
        try verify()
        guard try load().plan == plan else { throw ServiceAccountProvisioningError.conflictingRecord }
    }
    func complete(_ plan: ServiceAccountPlan, verify: () throws -> Void) throws {
        // The controller verifies every current directory record before and after this retained transition.
        try verify(); try plan.validate(account: account)
        try machine.completeServiceAccountPlan(plan)
        try verify()
        guard try load() == State(plan: plan, complete: true) else { throw ServiceAccountProvisioningError.conflictingRecord }
    }
}
