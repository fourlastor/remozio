import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsRecoveryCoordinatorTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class Runtime: OwnedGatewaySettingsConsumerRuntime, Sendable {
        func retire() {}
        func start() async throws {}
        func closeAndWait() async throws {}
    }
    private final class State: Sendable {
        struct Values {
            var events: [String] = []
            var plan: GatewayRuntimeSettingsRecoveryPlan?
            var fence: GatewayRuntimeSettingsFence?
            var proof: GatewaySettingsRecoveryAcceptance?
            var attempts: UInt8 = 0
            var available = false, scopeValid = true, replaceTransportBeforeAcceptance = false
            var holdResume = false
            var resumeGate: CheckedContinuation<Void, Never>?
        }
        let value = Mutex(Values())
        func record(_ event: String) { value.withLock { $0.events.append(event) } }
    }
    private final class Fixture: @unchecked Sendable {
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let revision: GatewayRuntimeSettingsRevision
        let state = State()
        let owners = Mutex<[GatewaySettingsConsumerOwner]>([])
        let retired = Mutex<[GatewaySettingsConsumerOwner]>([])
        init() throws {
            ready = try .init(); revision = try ready.revision()
            let initial = try GatewaySettingsConsumerRole.allCases.map(makeOwner)
            owners.withLock { $0 = initial }
        }
        func makeOwner(_ role: GatewaySettingsConsumerRole) throws -> GatewaySettingsConsumerOwner {
            let state = state, services = ready.activation.extensions.authority.material.runtime.services
            return try .init(role: role, macID: services.macID, accountID: services.accountID, operations: .init(
                verifyScope: { if !state.value.withLock({ $0.scopeValid }) { throw Failed() } },
                readFence: { try XCTUnwrap(state.value.withLock { $0.fence }) },
                loadSelected: { binding, fence in
                    let plan = try XCTUnwrap(state.value.withLock { $0.plan })
                    if role == .gateway { return try .gateway(binding: binding, fence: fence, configuration: plan.gateway, commit: plan.commit) }
                    return try .transport(binding: binding, fence: fence, configuration: plan.pair.transport, commit: plan.commit)
                }, makeRuntime: { _, _ in Runtime() }))
        }
        func owner(_ role: GatewaySettingsConsumerRole) -> GatewaySettingsConsumerOwner { owners.withLock { $0[Int(role.rawValue - 1)] } }
        func replaceTransport() throws {
            let next = try makeOwner(.transport), old = owners.withLock { s in let old = s[1]; s[1] = next; return old }
            retired.withLock { $0.append(old) }
        }
        func operations() -> GatewaySettingsRecoveryCoordinator.Operations {
            .init(verifyCurrent: { [self] in if !state.value.withLock({ $0.scopeValid }) { throw Failed() } },
                verifyPlan: { [self] plan in
                    guard state.value.withLock({ $0.scopeValid }), try plan.revision.encoded == revision.encoded else { throw Failed() }
                }, pause: { [self] _ in state.record("pause"); state.value.withLock { $0.available = false } },
                plan: { [self] id in
                    state.record("plan")
                    return try .init(state: .init(active: revision, pending: nil, phase: nil), activation: ready.activation,
                        journal: ready.fixture.state(), foreground: ready.fixture.runtime.plan,
                        inventory: XCTUnwrap(ready.fixture.runtime.machine.inventory()), attemptID: id)
                }, publish: { [self] plan in
                    state.record("publish")
                    state.value.withLock { $0.plan = plan; $0.fence = plan.fence }
                }, control: { [self] plan, role, action, expected in
                    state.record("\(action).\(role)")
                    if action == .accept, role == .gateway,
                       state.value.withLock({ s in let replace = s.replaceTransportBeforeAcceptance; s.replaceTransportBeforeAcceptance = false; return replace }) {
                        try replaceTransport()
                    }
                    let owner = owner(role)
                    guard expected == nil || expected == owner.binding.generation else { throw Failed() }
                    let request = try GatewaySettingsConsumerRequest(binding: owner.binding, fence: plan.fence,
                        action: action, challenge: Data(repeating: 5, count: 32))
                    return try await owner.performAuthenticated(request, verifyCaller: {})
                }, observe: { [self] role in state.record("observe.\(role)"); return owner(role).binding },
                remove: { [self] plan, proof in
                    try proof.requireValid(for: plan); state.record("remove")
                    try state.value.withLock { s in
                        guard try s.fence?.encoded == plan.fence.encoded else { throw Failed() }
                        s.fence = nil; s.proof = proof
                    }
                }, resume: { [self] plan, proof in
                    try proof.requireValid(for: plan); state.record("resume")
                    if state.value.withLock({ $0.holdResume }) {
                        await withCheckedContinuation { gate in state.value.withLock { $0.resumeGate = gate } }
                    }
                    try proof.requireValid(for: plan); state.value.withLock { $0.available = true }
                })
        }
        func coordinator() -> GatewaySettingsRecoveryCoordinator {
            let state = state
            return .init(operations: operations(), attemptID: { state.value.withLock { $0.attempts += 1; return Data(repeating: $0.attempts, count: 16) } })
        }
        func releaseResume() { state.value.withLock { s in let gate = s.resumeGate; s.resumeGate = nil; return gate }?.resume() }
        func closeOwners() async throws {
            for owner in owners.withLock({ $0 }) + retired.withLock({ $0 }) { try await owner.close() }
        }
    }
    private func waitUntil(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !predicate() { guard ContinuousClock.now < deadline else { throw Failed() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testFreshBarrierUsesBothRealOwnersBeforeRemovalAndHealthyPollingNeedsOnlyHello() async throws {
        let f = try Fixture(), coordinator = f.coordinator()
        let result = try await coordinator.refresh(); XCTAssertTrue(result)
        XCTAssertTrue(f.state.value.withLock { $0.available })
        let events = f.state.value.withLock { $0.events }
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "quiesce.transport")), try XCTUnwrap(events.firstIndex(of: "accept.gateway")))
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "accept.transport")), try XCTUnwrap(events.firstIndex(of: "remove")))
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "remove")), try XCTUnwrap(events.firstIndex(of: "resume")))
        let before = events.count, healthy = try await coordinator.refresh(); XCTAssertTrue(healthy)
        XCTAssertEqual(f.state.value.withLock { $0.attempts }, 1)
        XCTAssertEqual(Array(f.state.value.withLock { $0.events }.dropFirst(before)), ["observe.gateway", "observe.transport"])
        await coordinator.close(); XCTAssertFalse(f.state.value.withLock { $0.available }); try await f.closeOwners()
    }
    func testCompanionOnlyRestartMakesANewAttemptAndRevokesOldAcceptanceWithoutChangingSettings() async throws {
        let f = try Fixture(), coordinator = f.coordinator()
        let first = try await coordinator.refresh(); XCTAssertTrue(first)
        let oldProof = try XCTUnwrap(f.state.value.withLock { $0.proof }), oldPlan = try XCTUnwrap(f.state.value.withLock { $0.plan })
        try f.replaceTransport()
        let second = try await coordinator.refresh(); XCTAssertTrue(second)
        let current = try XCTUnwrap(f.state.value.withLock { $0.plan }), proof = try XCTUnwrap(f.state.value.withLock { $0.proof })
        XCTAssertEqual(f.state.value.withLock { $0.attempts }, 2)
        XCTAssertEqual(try current.commit.encoded, try oldPlan.commit.encoded)
        XCTAssertNotEqual(try current.fence.encoded, try oldPlan.fence.encoded)
        XCTAssertThrowsError(try oldProof.requireValid(for: oldPlan))
        XCTAssertEqual(oldProof.bindings[0], proof.bindings[0]); XCTAssertNotEqual(oldProof.bindings[1], proof.bindings[1])
        await coordinator.close(); try await f.closeOwners()
    }
    func testPartialAcceptanceFromAChangedGenerationKeepsRootPausedAndRetryQuiescesBothAgain() async throws {
        let f = try Fixture(), coordinator = f.coordinator()
        f.state.value.withLock { $0.replaceTransportBeforeAcceptance = true }
        let failed = try await coordinator.refresh(); XCTAssertFalse(failed)
        XCTAssertFalse(f.state.value.withLock { $0.available }); XCTAssertNotNil(f.state.value.withLock { $0.fence })
        XCTAssertFalse(f.state.value.withLock { $0.events }.contains("remove")); XCTAssertNil(f.state.value.withLock { $0.proof })
        let result = try await coordinator.refresh(); XCTAssertTrue(result)
        let events = f.state.value.withLock { $0.events }
        XCTAssertEqual(events.filter { $0 == "quiesce.gateway" }.count, 2)
        XCTAssertEqual(events.filter { $0 == "quiesce.transport" }.count, 2)
        XCTAssertEqual(f.state.value.withLock { $0.attempts }, 2)
        await coordinator.close(); try await f.closeOwners()
    }
    func testAChangedProtectedScopeRevokesAcceptanceAndLeavesOptionalWorkUnavailable() async throws {
        let f = try Fixture(), coordinator = f.coordinator()
        let first = try await coordinator.refresh(); XCTAssertTrue(first)
        let proof = try XCTUnwrap(f.state.value.withLock { $0.proof }), plan = try XCTUnwrap(f.state.value.withLock { $0.plan })
        f.state.value.withLock { $0.scopeValid = false }
        let result = try await coordinator.refresh(); XCTAssertFalse(result)
        XCTAssertFalse(f.state.value.withLock { $0.available }); XCTAssertThrowsError(try proof.requireValid(for: plan))
        f.state.value.withLock { $0.scopeValid = true }
        let restored = try await coordinator.refresh(); XCTAssertTrue(restored)
        await coordinator.close(); try await f.closeOwners()
    }
    func testCloseRevokesAcceptanceAndJoinsALateResumeBeforeItsFinalPause() async throws {
        let f = try Fixture(), coordinator = f.coordinator(), closed = Mutex(false)
        f.state.value.withLock { $0.holdResume = true }
        let refresh = Task { try await coordinator.refresh() }
        defer { f.releaseResume() }
        try await waitUntil { f.state.value.withLock { $0.resumeGate != nil } }
        let proof = try XCTUnwrap(f.state.value.withLock { $0.proof }), plan = try XCTUnwrap(f.state.value.withLock { $0.plan })
        let close = Task { await coordinator.close(); closed.withLock { $0 = true } }
        try await waitUntil { (try? proof.requireValid(for: plan)) == nil }
        XCTAssertFalse(closed.withLock { $0 }); XCTAssertFalse(f.state.value.withLock { $0.available })
        f.releaseResume(); await close.value
        do { _ = try await refresh.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertTrue(closed.withLock { $0 }); XCTAssertFalse(f.state.value.withLock { $0.available })
        XCTAssertEqual(f.state.value.withLock { $0.events.last }, "pause")
        try await f.closeOwners()
    }
    func testUnusedOrUncapturedScopeCannotPauseUnrelatedRootWork() async throws {
        let f = try Fixture(), base = f.operations()
        let failing = GatewaySettingsRecoveryCoordinator.Operations(verifyCurrent: base.verifyCurrent, verifyPlan: base.verifyPlan,
            pause: base.pause, plan: { _ in throw Failed() }, publish: base.publish, control: base.control,
            observe: base.observe, remove: base.remove, resume: base.resume)
        let coordinator = GatewaySettingsRecoveryCoordinator(operations: failing)
        let result = try await coordinator.refresh(); XCTAssertFalse(result)
        await coordinator.close()
        XCTAssertFalse(f.state.value.withLock { $0.events }.contains("pause"))
        let unused = f.coordinator(); await unused.close()
        XCTAssertFalse(f.state.value.withLock { $0.events }.contains("pause"))
        try await f.closeOwners()
    }
    func testOldCoordinatorCleanupCannotPauseTheRealRootServiceAfterASettingsSuccessorCommits() async throws {
        let f = try Fixture(), base = f.operations(), root = try AuthorityWakeSettingsTests.Fixture(install: false)
        let baseline = try base.plan(Data(repeating: 1, count: 16)), oldDigest = try baseline.commit.observationDigest
        try root.capability.install(root.options, commitDigest: oldDigest, verifyCurrent: {})
        let service = try root.service([AuthorityWakeSettingsTests.Driver(), AuthorityWakeSettingsTests.Driver(), AuthorityWakeSettingsTests.Driver()])
        try await service.start()
        let ticket = Mutex<AuthorityPhonePushRecoveryTicket?>(nil), pausedDigests = Mutex<[Data]>([])
        let operations = GatewaySettingsRecoveryCoordinator.Operations(verifyCurrent: base.verifyCurrent, verifyPlan: base.verifyPlan,
            pause: { plan in
                let digest = try plan.commit.observationDigest
                pausedDigests.withLock { $0.append(digest) }
                let current = try await service.quiescePhonePushRecovery(commitDigest: digest, verifyCurrent: {})
                ticket.withLock { $0 = current }; try await base.pause(plan)
            }, plan: base.plan, publish: base.publish, control: base.control, observe: base.observe, remove: base.remove,
            resume: { plan, proof in
                let current = try XCTUnwrap(ticket.withLock { $0 })
                try await service.resumePhonePushRecovery(current, verifyCurrent: { try proof.requireValid(for: plan) })
                try await service.installPhonePush(root.options, commitDigest: plan.commit.observationDigest, verifyCurrent: {})
                try await base.resume(plan, proof)
            })
        let coordinator = GatewaySettingsRecoveryCoordinator(operations: operations)
        let recovered = try await coordinator.refresh(); XCTAssertTrue(recovered)
        let next = try f.ready.revision(2, previous: f.revision)
        let successor = try GatewayRuntimeSettingsRecoveryPlan(state: .init(active: next, pending: nil, phase: nil),
            activation: f.ready.activation, journal: f.ready.fixture.state(), foreground: f.ready.fixture.runtime.plan,
            inventory: XCTUnwrap(f.ready.fixture.runtime.machine.inventory()), attemptID: Data(repeating: 9, count: 16))
        let selected = try successor.commit.observationDigest
        let change = try AuthorityPhonePushSettingsChange(revisionDigest: next.digest, previousCommitDigest: oldDigest, selectedCommitDigest: selected)
        try await service.quiescePhonePushSettings(change, verifyCurrent: {})
        try await service.acceptPhonePushSettings(change, verifyCurrent: {})
        try await service.installPhonePush(root.options, commitDigest: selected, verifyCurrent: {})
        await coordinator.close()
        XCTAssertEqual(pausedDigests.withLock { $0.last }, oldDigest)
        XCTAssertEqual(root.capability.installedCommitDigest, selected); XCTAssertNotNil(root.capability.publication)
        XCTAssertTrue(f.state.value.withLock { $0.available })
        XCTAssertEqual(root.starts.withLock { $0 }, 1)
        try await service.close(); try await f.closeOwners()
    }

}
