import Foundation

/// Joins the machine and import leases. Native publication validates artifacts before advancing the import marker.
enum SharedSetupImportRuntimePreparation {
    static func prepare(machine: PreparationIntentStore, account: AccountPreparationIntent,
                        expected: RuntimePreparationState, journal: SharedSetupImportJournal?,
                        verifyCurrent: @escaping () throws -> Void,
                        publish: (SharedSetupImportIntent?, () throws -> Void) throws -> RuntimePreparationState) throws -> RuntimePreparationState {
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        guard let inventory = try machine.inventory(), try machine.runtimePreparation(accountID: account.accountID) == expected else {
            throw RuntimePreparationError.changedScope
        }
        let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
        var retained = try journal?.current(scope: scope)
        if let retained, retained.phase != .retained {
            guard expected.configurationPublished, expected.reference != nil else { throw RuntimePreparationError.incomplete }
        }
        func verify() throws {
            try verifyCurrent(); try machine.validateAccountPreparation(account)
            guard try machine.inventory() == inventory, try journal?.current(scope: scope) == retained else {
                throw SharedSetupImportError.wrongScope
            }
        }
        try verify()
        let result = try publish(retained, verify)
        try verify()
        guard result.configurationPublished, result.reference != nil,
              try machine.runtimePreparation(accountID: account.accountID) == result else { throw RuntimePreparationError.incomplete }
        if let current = retained, current.phase == .retained {
            guard let journal else { throw SharedSetupImportError.wrongScope }
            retained = try journal.advance(current, to: .runtimePublished)
        }
        try verify(); return result
    }
}
