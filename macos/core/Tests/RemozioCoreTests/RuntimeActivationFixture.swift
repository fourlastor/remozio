import Darwin
import Foundation
import RemozioProtocol
@testable import RemozioCore

/// Real owned SQLite, synthetic release/account state. It does not prove native Root preparation or job registration.
final class RuntimeActivationFixture {
    private let profile: GatewayRuntimeActivationTestProfile.Scope
    let f: AccountPreparationFixture
    let machine: PreparationIntentStore
    let account: AccountPreparationIntent
    let services: ServiceAccountPlan
    let material: RuntimePreparationMaterial
    let plan: RuntimeActivationPlan
    init(firstServiceUID: UInt32 = 20000, profile: GatewayRuntimeActivationTestProfile.Scope = .disabled) throws {
        self.profile = profile
        let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .commandFrontend, .commandMonitor, .commandChild, .setupController]
        let policy = try AuthorityCodePolicy(entries: roles.map { role in
            try .init(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\(role.rawValue)",
                installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
        })
        let f = try profile.measure("accountFixture") { try AccountPreparationFixture(policy: policy) }; self.f = f
        let machine = try profile.measure("machineInitialize") { try f.open(initialize: true) }; self.machine = machine
        let pending = try profile.measure("accountBegin") { try f.begin(machine) }
        let account = try profile.measure("accountResume") { try f.resume(machine, pending) }; self.account = account
        let services = try ServiceAccountPlan(account: account, planID: AccountPreparationIntent.randomID(), claims: [
            .init(accountID: account.accountID, role: .transport, number: firstServiceUID, userID: UUID(), groupID: UUID()),
            .init(accountID: account.accountID, role: .gateway, number: firstServiceUID + 1, userID: UUID(), groupID: UUID())])
        self.services = services
        try profile.measure("serviceRetain") { try machine.retainServiceAccountPlan(services) }
        try profile.measure("serviceComplete") { try machine.completeServiceAccountPlan(services) }
        let now = Date()
        let material = try profile.measure("materialCreate") {
            try RuntimePreparationMaterial.create(services: services, notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
        }
        self.material = material
        try profile.measure("materialRetain") { try machine.retainRuntimeMaterial(material.reference) }
        try profile.measure("materialCompletePublication") { try machine.completeRuntimePublication(material.reference) }
        plan = try profile.measure("plan") {
            try .init(account: account, initialization: machine.initialization(accountID: account.accountID)!,
                runtime: machine.runtimePreparation(accountID: account.accountID), inventory: machine.inventory()!)
        }
    }
    deinit { try? profile.measure("machineClose") { try machine.close() } }
}
