import Darwin
import Foundation
import RemozioProtocol
@testable import RemozioCore

/// Real owned SQLite, synthetic release/account state. It does not prove native Root preparation or job registration.
final class RuntimeActivationFixture {
    let f: AccountPreparationFixture
    let machine: PreparationIntentStore
    let account: AccountPreparationIntent
    let services: ServiceAccountPlan
    let material: RuntimePreparationMaterial
    let plan: RuntimeActivationPlan
    init(firstServiceUID: UInt32 = 20000) throws {
        let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .commandFrontend, .commandMonitor, .commandChild, .setupController]
        let policy = try AuthorityCodePolicy(entries: roles.map { role in
            try .init(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\(role.rawValue)",
                installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
        })
        f = try .init(policy: policy); machine = try f.open(initialize: true)
        account = try f.resume(machine, f.begin(machine))
        services = try .init(account: account, planID: AccountPreparationIntent.randomID(), claims: [
            .init(accountID: account.accountID, role: .transport, number: firstServiceUID, userID: UUID(), groupID: UUID()),
            .init(accountID: account.accountID, role: .gateway, number: firstServiceUID + 1, userID: UUID(), groupID: UUID())])
        try machine.retainServiceAccountPlan(services); try machine.completeServiceAccountPlan(services)
        let now = Date()
        material = try .create(services: services, notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
        try machine.retainRuntimeMaterial(material.reference); try machine.completeRuntimePublication(material.reference)
        plan = try .init(account: account, initialization: machine.initialization(accountID: account.accountID)!,
            runtime: machine.runtimePreparation(accountID: account.accountID), inventory: machine.inventory()!)
    }
    deinit { try? machine.close() }
}
