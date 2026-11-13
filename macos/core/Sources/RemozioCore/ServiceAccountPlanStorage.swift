import Darwin
import Foundation

/// Borrows the setup owner's machine connection. Reservations and completion use its protected transaction store.
final class ServiceAccountPlanStorage {
    struct State: Equatable {
        let plan: ServiceAccountPlan?
        let complete: Bool
    }
    struct Operations {
        let load: () throws -> State
        let retain: (ServiceAccountPlan, () throws -> Void) throws -> Void
        let complete: (ServiceAccountPlan, () throws -> Void) throws -> Void
    }
    private let account: AccountPreparationIntent
    private let operations: Operations
    static func open(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> ServiceAccountPlanStorage {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try .init(machine: machine, account: account)
    }
    // Ordinary-owner controls use actual protected storage without granting native directory mutation authority.
    init(machine: PreparationIntentStore, account: AccountPreparationIntent) throws {
        guard account.storagePrepared else { throw ServiceAccountProvisioningError.incomplete }
        try machine.validateAccountPreparation(account)
        self.account = account
        operations = .init(load: {
            try machine.validateAccountPreparation(account)
            return try machine.serviceAccountPlan(accountID: account.accountID)
        }, retain: { plan, _ in try machine.retainServiceAccountPlan(plan) },
        complete: { plan, _ in try machine.completeServiceAccountPlan(plan) })
    }
    init(account: AccountPreparationIntent, operations: Operations) throws {
        guard account.storagePrepared else { throw ServiceAccountProvisioningError.incomplete }
        self.account = account; self.operations = operations
        _ = try load()
    }
    func load() throws -> State {
        let state = try operations.load()
        guard state.plan != nil || !state.complete else { throw ServiceAccountProvisioningError.incomplete }
        try state.plan?.validate(account: account)
        return state
    }
    func retain(_ plan: ServiceAccountPlan, verify: () throws -> Void) throws {
        try verify(); try plan.validate(account: account)
        try operations.retain(plan, verify)
        try verify()
        guard try load().plan == plan else { throw ServiceAccountProvisioningError.conflictingRecord }
    }
    func complete(_ plan: ServiceAccountPlan, verify: () throws -> Void) throws {
        // The controller verifies current directory records around the retained transition.
        try verify(); try plan.validate(account: account)
        try operations.complete(plan, verify)
        try verify()
        guard try load() == State(plan: plan, complete: true) else { throw ServiceAccountProvisioningError.conflictingRecord }
    }
}
