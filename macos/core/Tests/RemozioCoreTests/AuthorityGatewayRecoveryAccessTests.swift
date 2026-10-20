import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityGatewayRecoveryAccessTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private final class Runtime: OwnedGatewaySettingsConsumerRuntime, Sendable {
        func retire() {}
        func start() async throws {}
        func closeAndWait() async throws {}
    }
    final class Fixture: @unchecked Sendable {
        struct State {
            var snapshot: AuthorityGatewayRecoverySnapshot?
            var nativeValid = true, failTransportAcceptance = false, advanceDuringRemoval = false
            var holdGatewayAcceptance = false
            var held: CheckedContinuation<Void, Never>?
            var publications = 0
        }
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let revision: GatewayRuntimeSettingsRevision
        let root: AuthorityWakeSettingsTests.Fixture
        let service: AuthorityWakeService
        let directory: ProtectedSetupDirectory
        let path: URL
        let owners = Mutex<[GatewaySettingsConsumerOwner]>([])
        let retired = Mutex<[GatewaySettingsConsumerOwner]>([])
        let state = Mutex(State())
        var machine: PreparationIntentStore { ready.fixture.runtime.machine }
        var authority: InstalledAuthorityCommandConfiguration { ready.fixture.runtime.plan.host }
        init(nativeConsumerHosts: Bool = false) throws {
            ready = try .init(nativeConsumerHosts: nativeConsumerHosts); revision = try ready.revision(); root = try .init(install: false,
                macID: ready.fixture.runtime.plan.host.command.macID, accountID: ready.fixture.runtime.plan.host.command.accountID)
            let machine = ready.fixture.runtime.machine, foreground = ready.fixture.runtime.plan
            let transition = try GatewayRuntimeSettingsPublicationPlan(revision: revision, previous: nil, activation: ready.activation,
                journal: ready.fixture.state(), foreground: foreground, inventory: XCTUnwrap(machine.inventory()))
            try machine.retainGatewaySettingsTransition(revision)
            for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() { try machine.markGatewaySettingsTransition(revision, phase: phase) }
            try machine.completeGatewaySettingsTransition(revision)
            let snapshot = try AuthorityGatewayRecoverySnapshot.load(machine: machine, authority: foreground.host, attemptID: Data(repeating: 1, count: 16))
            try root.capability.install(root.options, commitDigest: snapshot.plan.commit.observationDigest, verifyCurrent: {})
            service = try root.service((0..<8).map { _ in AuthorityWakeSettingsTests.Driver() },
                binding: .init(accountID: snapshot.account.accountID, rootEpoch: UUID()))
            path = URL(fileURLWithPath: "/private/tmp/remozio-recovery-access-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false)
            guard chmod(path.path, 0o755) == 0 else { throw Refused() }
            directory = try .init(anchor: path.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
            for artifact in transition.artifacts {
                _ = try AdministrativeSetupPublication.publish(artifact.selected, file: artifact.file, directory: directory, owner: getuid())
            }
            let initial = try GatewaySettingsConsumerRole.allCases.map(makeOwner)
            owners.withLock { $0 = initial }
        }
        deinit { directory.close(); try? FileManager.default.removeItem(at: path) }
        var fencePath: String { directory.path + "/gateway-settings-fence.cbor" }
        func makeOwner(_ role: GatewaySettingsConsumerRole) throws -> GatewaySettingsConsumerOwner {
            let services = ready.activation.extensions.authority.material.runtime.services
            return try .init(role: role, macID: services.macID, accountID: services.accountID, operations: .init(
                verifyScope: { [self] in try verifyNative() }, readFence: { [self] in
                    try .decode(Data(contentsOf: URL(fileURLWithPath: fencePath)))
                }, loadSelected: { [self] binding, fence in
                    let snapshot = try XCTUnwrap(state.withLock { $0.snapshot }), plan = snapshot.plan
                    try snapshot.validate(machine: machine, authority: authority)
                    if role == .gateway { return try .gateway(binding: binding, fence: fence, configuration: plan.gateway, commit: plan.commit) }
                    return try .transport(binding: binding, fence: fence, configuration: plan.pair.transport, commit: plan.commit)
                }, makeRuntime: { _, _ in Runtime() }))
        }
        func owner(_ role: GatewaySettingsConsumerRole) -> GatewaySettingsConsumerOwner { owners.withLock { $0[Int(role.rawValue - 1)] } }
        func replaceTransport() throws {
            let next = try makeOwner(.transport), old = owners.withLock { s in let old = s[1]; s[1] = next; return old }
            retired.withLock { $0.append(old) }
        }
        func verifyNative() throws { guard state.withLock({ $0.nativeValid }) else { throw Refused() } }
        func operations() -> AuthorityGatewayRecoveryAccess.Operations {
            .init(verifyCurrent: { [self] in try verifyNative() }, capture: { [self] id in
                let snapshot = try AuthorityGatewayRecoverySnapshot.load(machine: machine, authority: authority, attemptID: id)
                state.withLock { $0.snapshot = snapshot }; return snapshot
            }, verify: { [self] snapshot in try snapshot.validate(machine: machine, authority: authority) },
            publish: { [self] snapshot, ticket in
                try snapshot.withPublicationScope(machine: machine, authority: authority) { scope in
                    _ = try GatewayRuntimeSettingsRecoveryPublication.publish(scope, directory: directory, owner: getuid(),
                        verifyCurrent: verifyNative, requireRootPaused: ticket.requireValid)
                }
                state.withLock { $0.publications += 1 }
            }, control: { [self] snapshot, role, action, expected in
                if role == .transport && action == .accept && state.withLock({ $0.failTransportAcceptance }) { throw Refused() }
                let owner = owner(role)
                guard expected == nil || expected == owner.binding.generation else { throw Refused() }
                let request = try GatewaySettingsConsumerRequest(binding: owner.binding, fence: snapshot.plan.fence,
                    action: action, challenge: Data(repeating: 3, count: 32))
                let response = try await owner.performAuthenticated(request, verifyCaller: verifyNative)
                if role == .gateway && action == .accept && state.withLock({ $0.holdGatewayAcceptance }) {
                    await withCheckedContinuation { gate in state.withLock { $0.held = gate } }
                }
                return response
            }, observe: { [self] _, role in owner(role).binding }, remove: { [self] snapshot, ticket, proof in
                if state.withLock({ $0.advanceDuringRemoval }) {
                    try machine.retainGatewaySettingsTransition(ready.revision(2, previous: revision))
                }
                try snapshot.withPublicationScope(machine: machine, authority: authority) { scope in
                    _ = try GatewayRuntimeSettingsRecoveryPublication.remove(scope, directory: directory, owner: getuid(),
                        verifyCurrent: verifyNative, requireFreshAcceptance: {
                            try ticket.requireValid(); try proof.requireValid(for: snapshot.plan)
                        })
                }
            })
        }
        func access() throws -> AuthorityGatewayRecoveryAccess { try .init(service: service, operations: operations()) }
        func release() { state.withLock { s in let held = s.held; s.held = nil; return held }?.resume() }
        func closeOwners() async throws {
            for owner in owners.withLock({ $0 }) + retired.withLock({ $0 }) { try await owner.close() }
            try await service.close()
        }
    }
    private func waitUntil(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while !predicate() { guard ContinuousClock.now < deadline else { throw Refused() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testRealServiceAndProtectedFilesRecoverWithoutReplacingTheForegroundOrInstallingTheProvider() async throws {
        let f = try Fixture(), access = try f.access(), coordinator = try access.makeCoordinator(), original = try f.root.state()
        XCTAssertThrowsError(try access.makeCoordinator())
        try await f.service.start()
        let recovered = try await coordinator.refresh(); XCTAssertTrue(recovered)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.fencePath)); XCTAssertNil(f.root.capability.publication)
        XCTAssertEqual(try f.root.state(), original); XCTAssertEqual(f.root.starts.withLock { $0 }, 1); XCTAssertEqual(f.root.closes.withLock { $0 }, 0)
        let plan = try XCTUnwrap(f.state.withLock { $0.snapshot?.plan })
        try await f.service.installPhonePush(f.root.options, commitDigest: plan.commit.observationDigest, verifyCurrent: f.verifyNative)
        XCTAssertNotNil(f.root.capability.publication)
        let healthy = try await coordinator.refresh(); XCTAssertTrue(healthy)
        XCTAssertEqual(f.state.withLock { $0.publications }, 1); XCTAssertNotNil(f.root.capability.publication)
        await coordinator.close(); XCTAssertNil(f.root.capability.publication)
        try await f.closeOwners()
    }
    func testCompanionRestartRepeatsBothBarriersWithAFreshFenceAndPreservesSettingsAndPairing() async throws {
        let f = try Fixture(), coordinator = try f.access().makeCoordinator(), before = try f.root.state()
        try await f.service.start()
        let first = try await coordinator.refresh(); XCTAssertTrue(first)
        let original = try XCTUnwrap(f.state.withLock { $0.snapshot })
        try await f.service.installPhonePush(f.root.options, commitDigest: original.plan.commit.observationDigest, verifyCurrent: {})
        try f.replaceTransport()
        let next = try await coordinator.refresh(); XCTAssertTrue(next)
        let current = try XCTUnwrap(f.state.withLock { $0.snapshot })
        XCTAssertNotEqual(try original.plan.fence.encoded, try current.plan.fence.encoded)
        XCTAssertEqual(try original.plan.commit.encoded, try current.plan.commit.encoded)
        XCTAssertEqual(f.state.withLock { $0.publications }, 2); XCTAssertNil(f.root.capability.publication)
        XCTAssertEqual(try f.root.state(), before)
        XCTAssertEqual(try f.machine.gatewaySettingsTransition(accountID: f.revision.accountID).active?.encoded, try f.revision.encoded)
        await coordinator.close(); try await f.closeOwners()
    }
    func testPartialConsumerAcceptanceRetainsTheFenceAndRealRootHoldUntilAFreshAttemptSucceeds() async throws {
        let f = try Fixture(), coordinator = try f.access().makeCoordinator()
        f.state.withLock { $0.failTransportAcceptance = true }
        try await f.service.start()
        let failed = try await coordinator.refresh(); XCTAssertFalse(failed)
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.fencePath)); XCTAssertNil(f.root.capability.publication)
        let status = await f.service.wakeStatus; XCTAssertEqual(status, .suspendedForRecovery)
        let original = try XCTUnwrap(f.state.withLock { $0.snapshot })
        f.state.withLock { $0.failTransportAcceptance = false }
        let recovered = try await coordinator.refresh(); XCTAssertTrue(recovered)
        XCTAssertNotEqual(try original.plan.fence.encoded, try XCTUnwrap(f.state.withLock { $0.snapshot }).plan.fence.encoded)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.fencePath)); XCTAssertNil(f.root.capability.publication)
        await coordinator.close(); try await f.closeOwners()
    }
    func testNewPrivateSettingsDuringRemovalKeepTheFenceAndCannotResumeTheOldRootFloor() async throws {
        let f = try Fixture(), coordinator = try f.access().makeCoordinator()
        f.state.withLock { $0.advanceDuringRemoval = true }
        try await f.service.start()
        let result = try await coordinator.refresh(); XCTAssertFalse(result)
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.fencePath)); XCTAssertNil(f.root.capability.publication)
        let status = await f.service.wakeStatus; XCTAssertEqual(status, .suspendedForRecovery)
        let old = try XCTUnwrap(f.state.withLock { $0.snapshot })
        let pending = try XCTUnwrap(f.machine.gatewaySettingsTransition(accountID: f.revision.accountID).pending)
        let successor = try GatewayRuntimeSettingsRecoveryPlan(state: .init(active: pending, pending: nil, phase: nil),
            activation: f.ready.activation, journal: f.ready.fixture.state(), foreground: f.ready.fixture.runtime.plan,
            inventory: XCTUnwrap(f.machine.inventory()), attemptID: Data(repeating: 9, count: 16))
        let change = try AuthorityPhonePushSettingsChange(revisionDigest: pending.digest,
            previousCommitDigest: old.plan.commit.observationDigest, selectedCommitDigest: successor.commit.observationDigest)
        try await f.service.quiescePhonePushSettings(change, verifyCurrent: {})
        try await f.service.acceptPhonePushSettings(change, verifyCurrent: {})
        try await f.service.installPhonePush(f.root.options, commitDigest: successor.commit.observationDigest, verifyCurrent: {})
        await coordinator.close()
        XCTAssertEqual(f.root.capability.installedCommitDigest, try successor.commit.observationDigest)
        XCTAssertNotNil(f.root.capability.publication); try await f.closeOwners()
    }
    func testCloseJoinsALateConsumerReplyAndKeepsTheRealRootPaused() async throws {
        let f = try Fixture(), coordinator = try f.access().makeCoordinator(), closed = Mutex(false)
        f.state.withLock { $0.holdGatewayAcceptance = true }
        try await f.service.start()
        let refresh = Task { try await coordinator.refresh() }
        defer { f.release() }
        try await waitUntil { f.state.withLock { $0.held != nil } }
        let close = Task { await coordinator.close(); closed.withLock { $0 = true } }
        try await Task.sleep(for: .milliseconds(10))
        XCTAssertFalse(closed.withLock { $0 }); XCTAssertNil(f.root.capability.publication)
        f.release(); await close.value
        do { _ = try await refresh.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertTrue(closed.withLock { $0 }); XCTAssertTrue(FileManager.default.fileExists(atPath: f.fencePath))
        let status = await f.service.wakeStatus; XCTAssertEqual(status, .suspendedForRecovery)
        try await f.closeOwners()
    }
    func testMissingRootBindingAndForeignProtectedAccountRefuseBeforePausing() async throws {
        let f = try Fixture(), root = try AuthorityWakeSettingsTests.Fixture(), unbound = try root.service([])
        XCTAssertThrowsError(try AuthorityGatewayRecoveryAccess(service: unbound, operations: f.operations()))
        let foreign = try Fixture(), base = f.operations()
        let operations = AuthorityGatewayRecoveryAccess.Operations(verifyCurrent: base.verifyCurrent,
            capture: foreign.operations().capture, verify: foreign.operations().verify,
            publish: base.publish, control: base.control, observe: base.observe, remove: base.remove)
        let coordinator = try AuthorityGatewayRecoveryAccess(service: f.service, operations: operations).makeCoordinator()
        let result = try await coordinator.refresh(); XCTAssertFalse(result)
        XCTAssertEqual(f.state.withLock { $0.publications }, 0); XCTAssertNotNil(f.root.capability.publication)
        await coordinator.close(); try await f.closeOwners(); try await foreign.closeOwners(); try await unbound.close()
    }
}
