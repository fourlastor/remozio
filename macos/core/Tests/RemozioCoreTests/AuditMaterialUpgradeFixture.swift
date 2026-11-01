import Darwin
import Foundation
import RemozioProtocol
@testable import RemozioCore

final class AuditMaterialUpgradeFixture {
    let f: AccountPreparationFixture
    let machine: PreparationIntentStore
    let account: AccountPreparationIntent
    let services: ServiceAccountPlan
    let material: RuntimePreparationMaterial
    let policy: AuthorityCodePolicy
    let nativeRelease: SignedReleaseEvidence?

    init(delivery: Bool = true, edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws {
        let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway,
            .commandFrontend, .commandMonitor, .commandChild, .setupController]
        let selectedPolicy = try AuthorityCodePolicy(entries: roles.map { role in
            try .init(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\(role.rawValue)",
                installedGeneration: 1, minimumGeneration: 1,
                codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
        })
        policy = selectedPolicy
        let requirements = try PhoneAuditReleaseContract.requirements
            + (delivery ? PhoneAuditReleaseContract.deliveryRequirements : [])
        let release = try NativeHostReleaseFixture.make(policy: selectedPolicy) { component in
            var formats = component.formats
            for required in requirements where required.role == component.role {
                if let index = formats.firstIndex(where: { $0.name == required.name }) {
                    let old = formats[index]
                    formats[index] = try .init(name: old.name, readers: old.readers.union(required.readVersions),
                        writers: old.writers.union(required.writeVersions))
                } else {
                    formats.append(try .init(name: required.name, readers: required.readVersions,
                        writers: required.writeVersions))
                }
            }
            return try edit(.init(role: component.role, identifier: component.identifier,
                generation: component.generation, relativePath: component.relativePath,
                codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                teamID: component.teamID, formats: formats, requests: component.requests))
        }
        nativeRelease = release
        f = try .init(policy: selectedPolicy, releaseDigest: InstallationInventory.digest(release))
        machine = try f.open(initialize: true)
        account = try f.resume(machine, f.begin(machine))
        services = try .init(account: account, planID: AccountPreparationIntent.randomID(), claims: [
            .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
            .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
        try machine.retainServiceAccountPlan(services)
        try machine.completeServiceAccountPlan(services)
        let activity = try ServiceReleaseActivityReference(services: services,
            identities: [.transport: .init(device: 1, inode: 100), .gateway: .init(device: 1, inode: 101)])
        let now = Date()
        material = try .create(services: services, notValidBefore: now.addingTimeInterval(-60),
            notValidAfter: now.addingTimeInterval(600), serviceActivity: activity,
            auditDeliveryVersion: delivery ? 1 : nil)
    }

    deinit { try? machine.close() }
}
