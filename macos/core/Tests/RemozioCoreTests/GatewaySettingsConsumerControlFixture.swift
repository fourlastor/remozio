import Foundation
import XCTest
@testable import RemozioCore

struct GatewaySettingsConsumerControlFixture {
    let ready: GatewayRuntimeSettingsStoreTests.Ready
    let plan: GatewayRuntimeSettingsPublicationPlan
    let fence: GatewayRuntimeSettingsFence
    init() throws {
        ready = try .init()
        plan = try .init(revision: ready.revision(1), previous: nil, activation: ready.activation,
            journal: ready.fixture.state(), foreground: ready.fixture.runtime.plan,
            inventory: XCTUnwrap(ready.fixture.runtime.machine.inventory()))
        fence = try .init(plan)
    }
    func binding(role: GatewaySettingsConsumerRole = .gateway, generation: UUID = UUID()) throws -> GatewaySettingsConsumerBinding {
        try .init(role: role, macID: fence.macID, accountID: fence.accountID, generation: generation)
    }
    func owner(role: GatewaySettingsConsumerRole = .gateway) throws -> GatewaySettingsConsumerOwner {
        let fence = fence, plan = plan
        return try .init(role: role, macID: fence.macID, accountID: fence.accountID, operations: .init(
            verifyScope: {}, readFence: { fence }, loadSelected: { binding, current in
                if role == .transport { return try .transport(binding: binding, fence: current, configuration: plan.pair.transport, commit: plan.commit) }
                return try .gateway(binding: binding, fence: current, configuration: .decode(XCTUnwrap(plan.artifacts.first {
                    if case .gatewayConfiguration = $0.file { true } else { false }
                }).selected), commit: plan.commit)
            }, makeRuntime: { _, _ in throw GatewayPreparationError.incomplete }))
    }
}
