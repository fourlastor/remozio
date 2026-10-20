import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayRuntimeSettingsRecoveryTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private struct Fixture {
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let revision: GatewayRuntimeSettingsRevision
        init() throws {
            ready = try .init(); revision = try ready.revision()
            let store = ready.fixture.runtime.machine
            try store.retainGatewaySettingsTransition(revision)
            for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() { try store.markGatewaySettingsTransition(revision, phase: phase) }
            try store.completeGatewaySettingsTransition(revision)
        }
        var state: GatewayRuntimeSettingsState { get throws {
            try ready.fixture.runtime.machine.gatewaySettingsTransition(accountID: revision.accountID)
        } }
        func plan(_ attempt: UInt8 = 7, state: GatewayRuntimeSettingsState? = nil) throws -> GatewayRuntimeSettingsRecoveryPlan {
            try .init(state: state ?? self.state, activation: ready.activation, journal: ready.fixture.state(),
                foreground: ready.fixture.runtime.plan, inventory: XCTUnwrap(ready.fixture.runtime.machine.inventory()),
                attemptID: Data(repeating: attempt, count: 16))
        }
    }
    private func changed(_ bytes: Data, edit: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        let limits = try CBORLimits(maxBytes: 131072, maxDepth: 2, maxItems: 64)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw Failed() }
        edit(&fields); return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testRecoveryPreservesTheCompletedRevisionCommitPairingAndRetainedState() throws {
        let f = try Fixture(), before = try f.state, plan = try f.plan(), otherAttempt = try f.plan(8)
        let activation = try f.ready.fixture.runtime.machine.gatewayRuntimeActivation(accountID: f.revision.accountID).plan?.encoded
        XCTAssertEqual(try plan.revision.encoded, try f.revision.encoded)
        XCTAssertEqual(plan.commit.settingsSequence, 1)
        XCTAssertEqual(try plan.fence.previous.encoded, try plan.fence.selected.encoded)
        XCTAssertEqual(try plan.commit.encoded, try otherAttempt.commit.encoded)
        XCTAssertNotEqual(try plan.fence.encoded, try otherAttempt.fence.encoded)
        XCTAssertEqual(plan.pair.transport.wake?.wake.credentialID, f.ready.activation.extensions.transport.wake?.wake.credentialID)
        XCTAssertEqual(plan.pair.transport.wake?.wake.publicKey, f.ready.activation.extensions.transport.wake?.wake.publicKey)
        XCTAssertEqual(try f.state.active?.encoded, try before.active?.encoded)
        XCTAssertNil(try f.state.pending); XCTAssertNil(try f.state.phase)
        XCTAssertEqual(try f.ready.fixture.runtime.machine.gatewayRuntimeActivation(accountID: f.revision.accountID).plan?.encoded, activation)
        try plan.validate(state: f.state)
    }
    func testOnlyCompletedCurrentSettingsCanCreateOrRetainARecoveryPlan() throws {
        let f = try Fixture(), plan = try f.plan(), next = try f.ready.revision(2, previous: f.revision)
        for state in [GatewayRuntimeSettingsState.empty,
                      .init(active: f.revision, pending: next, phase: .retained),
                      .init(active: f.revision, pending: nil, phase: .consumersObserved)] {
            XCTAssertThrowsError(try f.plan(state: state)); XCTAssertThrowsError(try plan.validate(state: state))
        }
        try f.ready.fixture.runtime.machine.retainGatewaySettingsTransition(next)
        XCTAssertThrowsError(try plan.validate(state: f.state))
        XCTAssertThrowsError(try f.plan())
        for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() {
            try f.ready.fixture.runtime.machine.markGatewaySettingsTransition(next, phase: phase)
        }
        try f.ready.fixture.runtime.machine.completeGatewaySettingsTransition(next)
        XCTAssertThrowsError(try plan.validate(state: f.state))
        let current = try f.plan(); XCTAssertEqual(current.commit.settingsSequence, 2)
    }
    func testRecoveryFenceHasClosedVersionTwoShapeAndRetainsExactGatewayScope() throws {
        let f = try Fixture(), plan = try f.plan(), fence = try GatewayRuntimeSettingsFence.decode(plan.fence.encoded)
        XCTAssertEqual(fence.version, 2); XCTAssertEqual(fence.recoveryAttemptID, Data(repeating: 7, count: 16))
        XCTAssertEqual(try fence.encoded, try plan.fence.encoded)
        try fence.validate(services: plan.pair.authority.material.runtime.services)
        try fence.validate(gateway: plan.gateway, commit: plan.commit)
        XCTAssertThrowsError(try fence.validate(commit: GatewayRuntimeCommit(f.ready.activation.extensions)))
        let foreign = try Fixture().plan()
        XCTAssertThrowsError(try fence.validate(services: foreign.pair.authority.material.runtime.services))
        XCTAssertThrowsError(try fence.validate(gateway: foreign.gateway, commit: plan.commit))
        XCTAssertEqual(String(describing: plan), "GatewayRuntimeSettingsRecoveryPlan(redacted)")
    }
    func testMalformedRecoveryModesCannotBecomeAnUnchangedSuccessorFence() throws {
        let f = try Fixture(), plan = try f.plan(), bytes = try plan.fence.encoded
        for version: UInt64 in [0, 1, 3, UInt64.max] {
            XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[0] = .unsigned(version) }))
        }
        for size in [0, 15, 17, 32] {
            XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[10] = .bytes(Data(repeating: 1, count: size)) }))
        }
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0.removeValue(forKey: 10) }))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[11] = .null }))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[9] = .bytes(Data(repeating: 1, count: 32)) }))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) {
            $0[7] = .bytes(try! GatewayRuntimeCommit(f.ready.activation.extensions).encoded)
        }))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) {
            $0[0] = .unsigned(1); $0.removeValue(forKey: 10)
        }))
    }
    func testLegacyTransitionAndRequestKeepTheirExactVersionOneBytes() throws {
        let f = try Fixture(), r = f.ready
        let publication = try GatewayRuntimeSettingsPublicationPlan(revision: f.revision, previous: nil,
            activation: r.activation, journal: r.fixture.state(), foreground: r.fixture.runtime.plan,
            inventory: XCTUnwrap(r.fixture.runtime.machine.inventory()))
        let fence = try GatewayRuntimeSettingsFence(publication)
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 1, maxItems: 23)
        let legacy = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-settings-fence"),
            2: .bytes(fence.macID), 3: .bytes(fence.accountID), 4: .bytes(fence.installationID), 5: .bytes(fence.releaseDigest),
            6: .bytes(fence.revision.encoded), 7: .bytes(fence.previous.encoded), 8: .bytes(fence.selected.encoded),
            9: .bytes(fence.previousGatewayDigest)]), limits: limits)
        XCTAssertEqual(try fence.encoded, legacy); XCTAssertNil(fence.recoveryAttemptID)
        let binding = try GatewaySettingsConsumerBinding(role: .gateway, macID: fence.macID, accountID: fence.accountID)
        let request = try GatewaySettingsConsumerRequest(binding: binding, fence: fence, action: .observe, challenge: Data(repeating: 1, count: 32))
        XCTAssertEqual(request.change.version, 1)
        let expected = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-settings-consumer-request"),
            2: .bytes(binding.encoded), 3: .bytes(Data(SHA256.hash(data: legacy))), 4: .bytes(fence.revision.digest),
            5: .bytes(fence.previous.observationDigest), 6: .bytes(fence.selected.observationDigest),
            7: .unsigned(GatewaySettingsControlAction.observe.rawValue), 8: .bytes(request.challenge)]),
            limits: CBORLimits(maxBytes: 768, maxDepth: 1, maxItems: 19))
        XCTAssertEqual(try request.encoded, expected)
    }
    func testRecoveryRequestsUseVersionTwoAndCannotWeakenRootSuccessorMessages() throws {
        let plan = try Fixture().plan(), fence = plan.fence
        let binding = try GatewaySettingsConsumerBinding(role: .transport, macID: fence.macID, accountID: fence.accountID)
        let request = try GatewaySettingsConsumerRequest(binding: binding, fence: fence, action: .quiesce, challenge: Data(repeating: 1, count: 32))
        XCTAssertEqual(request.change.version, 2)
        let decoded = try GatewaySettingsConsumerRequest.decode(request.encoded)
        try decoded.validate(binding: binding, fence: fence)
        XCTAssertEqual(try decoded.encoded, try request.encoded)
        XCTAssertThrowsError(try GatewaySettingsConsumerRequest.decode(changed(request.encoded) { $0[0] = .unsigned(1) }))
        XCTAssertThrowsError(try GatewaySettingsConsumerRequest.decode(changed(request.encoded) { $0[6] = .bytes(Data(repeating: 9, count: 32)) }))
        XCTAssertThrowsError(try AuthorityPhonePushSettingsChange(revisionDigest: fence.revision.digest,
            previousCommitDigest: fence.previous.observationDigest, selectedCommitDigest: fence.selected.observationDigest))
    }
    private final class Runtime: OwnedGatewaySettingsConsumerRuntime, Sendable {
        let starts = Mutex(0)
        func retire() {}
        func start() async throws { starts.withLock { $0 += 1 } }
        func closeAndWait() async throws {}
    }
    func testBothConsumerRolesRequireFreshQuiescenceAndRejectReceiptsAfterRestart() async throws {
        for role in GatewaySettingsConsumerRole.allCases {
            let plan = try Fixture().plan(), fence = plan.fence, runtime = Runtime()
            let operations = GatewaySettingsConsumerOwner.Operations(verifyScope: {}, readFence: { fence }, loadSelected: { binding, fence in
                if role == .gateway { return try .gateway(binding: binding, fence: fence, configuration: plan.gateway, commit: plan.commit) }
                return try .transport(binding: binding, fence: fence, configuration: plan.pair.transport, commit: plan.commit)
            }, makeRuntime: { _, _ in runtime })
            let first = try GatewaySettingsConsumerOwner(role: role, macID: fence.macID, accountID: fence.accountID, operations: operations)
            let second = try GatewaySettingsConsumerOwner(role: role, macID: fence.macID, accountID: fence.accountID, operations: operations)
            func request(_ owner: GatewaySettingsConsumerOwner, _ action: GatewaySettingsControlAction) throws -> GatewaySettingsConsumerRequest {
                try .init(binding: owner.binding, fence: fence, action: action, challenge: Data(repeating: 5, count: 32))
            }
            do { _ = try await first.performAuthenticated(request(first, .accept), verifyCaller: {}); XCTFail() } catch {}
            let paused = try await first.performAuthenticated(request(first, .quiesce), verifyCaller: {})
            XCTAssertEqual(paused.observation, .paused)
            let receipt = try await first.performAuthenticated(request(first, .accept), verifyCaller: {})
            XCTAssertEqual(receipt.observation, .accepted); XCTAssertEqual(runtime.starts.withLock { $0 }, 0)
            try await first.startAcceptedRuntime(); XCTAssertEqual(runtime.starts.withLock { $0 }, 1)
            XCTAssertThrowsError(try GatewaySettingsConsumerResponse.decode(receipt.encoded, expected: request(second, .accept)))
            do { _ = try await second.performAuthenticated(request(second, .accept), verifyCaller: {}); XCTFail() } catch {}
            do { try await second.startAcceptedRuntime(); XCTFail() } catch {}
            try await first.close(); try await second.close()
        }
    }
    func testAnotherRecoveryAttemptInvalidatesRequestsWithoutChangingTheApprovedCommit() throws {
        let f = try Fixture(), first = try f.plan(), second = try f.plan(8)
        let binding = try GatewaySettingsConsumerBinding(role: .gateway, macID: first.fence.macID, accountID: first.fence.accountID)
        let request = try GatewaySettingsConsumerRequest(binding: binding, fence: first.fence, action: .accept, challenge: Data(repeating: 3, count: 32))
        XCTAssertEqual(try first.commit.encoded, try second.commit.encoded)
        XCTAssertThrowsError(try request.validate(binding: binding, fence: second.fence))
        let expected = try GatewaySettingsConsumerRequest(binding: binding, fence: second.fence, action: .accept, challenge: request.challenge)
        let reply = try GatewaySettingsConsumerResponse(request: request, observation: .accepted)
        XCTAssertThrowsError(try GatewaySettingsConsumerResponse.decode(reply.encoded, expected: expected))
    }
}
