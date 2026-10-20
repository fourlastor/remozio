import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeReviewedImportBundleTests: XCTestCase {
    private final class Fixture {
        let runtime: RuntimeActivationFixture
        let intent: SharedSetupImportIntent
        init() throws {
            runtime = try .init()
            let proposal = try PortableSetup(defaults: .init(presence: .init(idleMilliseconds: 540_000,
                observationLifetimeMilliseconds: 7000, unavailableGraceMilliseconds: 45_000),
                gateway: GatewaySetupForm().settingsSelection()),
                cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                    dnsSuffix: "remozio.example.invalid", apiToken: "synthetic-token"))
            intent = try .init(scope: .init(account: runtime.account, inventory: XCTUnwrap(runtime.machine.inventory())), proposal: proposal)
        }
        func bundle(_ plan: SharedSetupImportRelayPlan?, presence: PresenceConfiguration? = nil,
                    port: UInt16? = nil) throws -> RuntimeConfigurationBundle {
            try .initial(account: runtime.account,
                initialization: XCTUnwrap(runtime.machine.initialization(accountID: runtime.account.accountID)),
                reference: runtime.material.reference, inventory: XCTUnwrap(runtime.machine.inventory()),
                importIntent: intent, presencePolicyOverride: presence, relayPlan: plan, relayPortOverride: port)
        }
    }
    func testReviewedPresenceAndLocalPortArePreservedWithoutImportingElevationGrants() throws {
        let f = try Fixture(), plan = try SharedSetupImportRelayPlan(expected: f.intent, port: 51001)
        let bundle = try f.bundle(plan)
        XCTAssertEqual(bundle.transport.relayPort, 51001)
        XCTAssertEqual(bundle.command.presence.presence.policy.idleMilliseconds, 540_000)
        XCTAssertEqual(bundle.command.presence.presence.policy.observationLifetimeMilliseconds, 7000)
        XCTAssertEqual(bundle.command.presence.presence.policy.unavailableGraceMilliseconds, 45_000)
        XCTAssertEqual(bundle.elevationPolicy.canonicalBytes, f.runtime.account.policyBytes)
        XCTAssertEqual(try f.bundle(plan, port: 51001).transport.canonicalBytes, bundle.transport.canonicalBytes)
        XCTAssertThrowsError(try f.bundle(plan, port: 51002))
        let other = try PresenceConfiguration(idleMilliseconds: 900_000, observationLifetimeMilliseconds: 7000,
            unavailableGraceMilliseconds: 45_000)
        XCTAssertThrowsError(try f.bundle(plan, presence: other))
    }
    func testMissingOrForeignRelayPlanRefusesBeforeRuntimeMaterialEffects() throws {
        let f = try Fixture()
        let foreign = try SharedSetupImportIntent(scope: f.intent.scope,
            proposal: PortableSetup(defaults: f.intent.recipe.settings.defaults,
                cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                    dnsSuffix: "remozio.example.invalid", apiToken: "synthetic-token")))
        let wrong = try SharedSetupImportRelayPlan(expected: foreign, port: 51001)
        for plan in [SharedSetupImportRelayPlan?.none, wrong] {
            var effects = 0
            XCTAssertThrowsError(try RuntimePublicationController.prepare(machine: f.runtime.machine, account: f.runtime.account,
                expected: f.runtime.machine.runtimePreparation(accountID: f.runtime.account.accountID),
                importIntent: f.intent, relayPlan: plan, verifyCurrent: {},
                verifyServices: { _ in effects += 1 }, verifyAuthority: { _ in effects += 1 },
                restoreMaterial: { _, _, _ in effects += 1; return f.runtime.material },
                publish: { _, _, _ in effects += 1 }))
            XCTAssertEqual(effects, 0)
        }
        XCTAssertThrowsError(try f.bundle(nil))
    }
    func testProviderFreeImportCannotAdoptAnotherImportsRelayPlan() throws {
        let f = try Fixture(), plan = try SharedSetupImportRelayPlan(expected: f.intent, port: 51001)
        let plain = try SharedSetupImportIntent(scope: f.intent.scope,
            proposal: PortableSetup(defaults: f.intent.recipe.settings.defaults))
        XCTAssertThrowsError(try RuntimeConfigurationBundle.initial(account: f.runtime.account,
            initialization: XCTUnwrap(f.runtime.machine.initialization(accountID: f.runtime.account.accountID)),
            reference: f.runtime.material.reference, inventory: XCTUnwrap(f.runtime.machine.inventory()),
            importIntent: plain, relayPlan: plan))
    }
}
