import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned read values prove no native initialization, protected file custody, publication, or startup authority.
final class RuntimeRetainedSetupInitialConfigurationTests: XCTestCase {
    private typealias Configuration = RuntimeRetainedSetupInitialConfiguration
    private typealias Fixture = MachineUpdateReplacementTests


    private func imports(_ snapshot: MachineUpdateRetainedSetupPolicySnapshot, _ presence: PresenceConfiguration?,
        _ port: UInt16?) throws -> (SharedSetupImportIntent?, SharedSetupImportRelayPlan?) {
        guard presence != nil || port != nil else { return (nil, nil) }
        let runtime = snapshot.activation.runtime, account = runtime.preparation
        let inventory = try runtime.setup.source.provisioningInventory(accountID: account.accountID,
            ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
        let cloud = try port.map { _ in try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32),
            zoneID: String(repeating: "b", count: 32), dnsSuffix: "owned.example", apiToken: "synthetic-only") }
        let proposal = PortableSetup(defaults: try .init(presence: presence ?? .init(observationLifetimeMilliseconds: 5000,
            unavailableGraceMilliseconds: 30000), gateway: GatewaySetupForm().settingsSelection()), cloudflare: cloud)
        let intent = try SharedSetupImportIntent(scope: .init(account: account, inventory: inventory), proposal: proposal)
        return (intent, try port.map { try SharedSetupImportRelayPlan(expected: intent, port: $0) })
    }
    private func configuration(snapshot: MachineUpdateRetainedSetupPolicySnapshot, current: AuthorityJournal.MachineUpdatePolicyBoundary,
        candidate: SignedReleaseEvidence, currentCodePolicy: AuthorityCodePolicy,
        presencePolicyOverride: PresenceConfiguration? = nil, relayPortOverride: UInt16? = nil) throws -> Configuration {
        let (intent, relay) = try imports(snapshot, presencePolicyOverride, relayPortOverride)
        return try Configuration(snapshot: snapshot, current: current, candidate: candidate,
            currentCodePolicy: currentCodePolicy, importIntent: intent, relayPlan: relay)
    }
    private func requireSource(_ value: Configuration, snapshot: MachineUpdateRetainedSetupPolicySnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy, presencePolicyOverride: PresenceConfiguration? = nil,
        relayPortOverride: UInt16? = nil) throws {
        let (intent, relay) = try imports(snapshot, presencePolicyOverride, relayPortOverride)
        try value.requireSourceForPublication(snapshot: snapshot, current: current, candidate: candidate,
            currentCodePolicy: currentCodePolicy, importIntent: intent, relayPlan: relay)
    }

    func testInitialConfigurationKeepsTheExactBindingHostsClientsAndRequestedTunables() throws {
        try Fixture.withRetainedInitialConfigurationValueFixture { snapshot, current, candidate, _, verify in
            let presence = try PresenceConfiguration(idleMilliseconds: 123000,
                observationLifetimeMilliseconds: 9000, unavailableGraceMilliseconds: 41000)
            let actual = try configuration(snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy, presencePolicyOverride: presence, relayPortOverride: 45678)
            let selectedImports = try imports(snapshot, presence, 45678)
            let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: candidate, currentCodePolicy: current.policy.policy,
                importIntent: selectedImports.0, relayPlan: selectedImports.1)
            let binding = try RuntimeRetainedSetupReleaseBinding(snapshot: snapshot, current: current, candidate: candidate)
            XCTAssertEqual(actual.binding, binding)
            XCTAssertEqual(actual.host.command.canonicalBytes, bundle.command.canonicalBytes)
            XCTAssertEqual(actual.bundle.transport.canonicalBytes, bundle.transport.canonicalBytes)
            XCTAssertEqual(actual.bundle.presenceClient.canonicalBytes, bundle.presenceClient.canonicalBytes)
            XCTAssertEqual(actual.bundle.pairingClient.canonicalBytes, bundle.pairingClient.canonicalBytes)
            XCTAssertEqual(actual.bundle.frontendClient.canonicalBytes, bundle.frontendClient.canonicalBytes)
            XCTAssertEqual(actual.bundle.elevationPolicy.canonicalBytes, bundle.elevationPolicy.canonicalBytes)
            XCTAssertEqual(actual.bundle.command.presence.presence.policy.idleMilliseconds, presence.idleMilliseconds)
            XCTAssertEqual(actual.bundle.transport.relayPort, 45678)
            XCTAssertEqual(actual.host.installationID, binding.installationID)
            XCTAssertEqual(actual.host.releaseDigest, binding.installedReleaseDigest)
            XCTAssertNotEqual(binding.provisioningReleaseDigest, binding.installedReleaseDigest)
            let transport = try XCTUnwrap(actual.bundle.transport.settingsHost)
            let gateway = try XCTUnwrap(actual.bundle.gatewaySettingsHost)
            XCTAssertEqual(transport.retainedSetupBinding, binding); XCTAssertEqual(gateway.retainedSetupBinding, binding)
            let account = snapshot.activation.runtime.preparation, inventory = snapshot.activation.runtime.setup.source.actual.inventory
            try transport.requireConfigurationScope(account: account, inventory: inventory)
            try gateway.requireConfigurationScope(account: account, inventory: inventory)
            try transport.validateRelease(candidate); try gateway.validateRelease(candidate)
            XCTAssertThrowsError(try transport.validate(account: account, inventory: inventory)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            XCTAssertThrowsError(try gateway.validate(account: account, inventory: inventory)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(transport.encoded))
            XCTAssertThrowsError(try TransportPairingStartupConfiguration.decode(actual.bundle.transport.canonicalBytes))
            try requireSource(actual, snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy, presencePolicyOverride: presence, relayPortOverride: 45678)
            XCTAssertEqual(try actual.digest.count, 32)
            try verify()
        }
    }

    func testSourceFenceKeepsPolicyRevisionPresenceRelayAndCanonicalBytesExact() throws {
        try Fixture.withRetainedInitialConfigurationValueFixture { snapshot, current, candidate, oldPolicy, verify in
            let actual = try configuration(snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy, relayPortOverride: 45678)
            let same = try configuration(snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy, relayPortOverride: 45678)
            XCTAssertEqual(try actual.digest, try same.digest)
            try requireSource(actual, snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy, relayPortOverride: 45678)
            let presence = try PresenceConfiguration(idleMilliseconds: 321000,
                observationLifetimeMilliseconds: 8000, unavailableGraceMilliseconds: 42000)
            let changed = try configuration(snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy, presencePolicyOverride: presence, relayPortOverride: 45678)
            XCTAssertNotEqual(try actual.digest, try changed.digest)
            XCTAssertThrowsError(try requireSource(actual, snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy, presencePolicyOverride: presence, relayPortOverride: 45678)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertThrowsError(try requireSource(actual, snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy, relayPortOverride: 45679)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertThrowsError(try configuration(snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: oldPolicy)) { XCTAssertEqual($0 as? RuntimeActivationError, .changedScope) }
            let imported = try imports(snapshot, presence, 45678)
            let conflictingPresence = try PresenceConfiguration(idleMilliseconds: 654000,
                observationLifetimeMilliseconds: 8000, unavailableGraceMilliseconds: 42000)
            XCTAssertThrowsError(try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot,
                current: current, candidate: candidate, currentCodePolicy: current.policy.policy,
                importIntent: imported.0, presencePolicyOverride: conflictingPresence, relayPlan: imported.1)) {
                XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
            }
            XCTAssertThrowsError(try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot,
                current: current, candidate: candidate, currentCodePolicy: current.policy.policy,
                importIntent: imported.0, relayPlan: imported.1, relayPortOverride: 45679)) {
                XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
            }
            let otherRevision = AuthorityJournal.MachineUpdatePolicyBoundary(macID: current.macID, accountID: current.accountID,
                policy: .init(revision: UUID(), policy: current.policy.policy, roleRevisions: current.policy.roleRevisions),
                checkpoint: current.checkpoint)
            XCTAssertThrowsError(try requireSource(actual, snapshot: snapshot, current: otherRevision,
                candidate: candidate, currentCodePolicy: current.policy.policy, relayPortOverride: 45678)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try verify()
        }
    }

    func testUnrecordedPolicyCannotProduceAnInitialConfiguration() throws {
        try Fixture.withRetainedInitialConfigurationValueFixture(recorded: false) { snapshot, current, candidate, _, verify in
            XCTAssertEqual(snapshot.intent?.phase, .prepared)
            XCTAssertThrowsError(try configuration(snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
            }
            try verify()
        }
    }

    func testAlreadyPublishedRuntimeCannotBeRebuiltAsAnInitialConfiguration() throws {
        try Fixture.withRetainedInitialConfigurationValueFixture { snapshot, current, candidate, _, verify in
            XCTAssertNoThrow(try configuration(snapshot: snapshot, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy))
            let before = snapshot.activation.runtime
            let runtime = try MachineUpdateStableRuntimePreparationSnapshot(setup: before.setup,
                services: .init(plan: before.plan, complete: true),
                state: .init(reference: before.state.reference, configurationPublished: true), reservedNumbers: before.reservedNumbers)
            let activation = try MachineUpdateStableRuntimeActivationSnapshot(runtime: runtime,
                state: snapshot.activation.state, candidate: candidate)
            let published = try MachineUpdateRetainedSetupPolicySnapshot(activation: activation, intent: snapshot.intent, candidate: candidate)
            XCTAssertThrowsError(try configuration(snapshot: published, current: current, candidate: candidate,
                currentCodePolicy: current.policy.policy)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            try verify()
        }
    }
}
