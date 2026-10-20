import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsTransitionOperationTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    private final class Runtime: OwnedGatewaySettingsConsumerRuntime, Sendable {
        func retire() {}
        func start() async throws {}
        func closeAndWait() async throws {}
    }
    private final class State: Sendable {
        struct Values {
            var events: [String] = []
            var fail: String?
            var replaceTransport = false, replaceRoot = false, holdAccept = false
            var gate: CheckedContinuation<Void, Never>?
            var quiescence: GatewaySettingsTransitionBarrier?
            var acceptance: GatewaySettingsTransitionBarrier?
        }
        let values = Mutex(Values())
        func event(_ name: String) throws {
            try values.withLock { s in s.events.append(name); if s.fail == name { throw Interrupted() } }
        }
    }
    private final class Fixture: @unchecked Sendable {
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let scope: GatewayRuntimeSettingsFencePublication.Scope
        let root: URL
        let directory: ProtectedSetupDirectory
        let authority: AuthorityWakeSettingsTests.Fixture
        let service: AuthorityWakeService
        let state = State()
        let owners = Mutex<[GatewaySettingsConsumerOwner]>([])
        let oldOwners = Mutex<[GatewaySettingsConsumerOwner]>([])
        var plan: GatewayRuntimeSettingsPublicationPlan { scope.plan }
        init(native: Bool = false) throws {
            ready = try .init(nativeConsumerHosts: native)
            let f = ready.fixture, revision = try ready.revision()
            let plan = try GatewayRuntimeSettingsPublicationPlan(revision: revision, previous: nil,
                activation: ready.activation, journal: f.state(), foreground: f.runtime.plan,
                inventory: XCTUnwrap(f.runtime.machine.inventory()))
            scope = .init(plan: plan, machine: f.runtime.machine, account: f.runtime.account,
                foreground: f.runtime.plan, inventory: try XCTUnwrap(f.runtime.machine.inventory()))
            try f.runtime.machine.retainGatewaySettingsTransition(revision)
            root = URL(fileURLWithPath: "/private/tmp/remozio-settings-transition-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw Interrupted() }
            directory = try .init(anchor: root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
            for artifact in plan.artifacts {
                if let old = artifact.previous {
                    _ = try AdministrativeSetupPublication.publish(old, file: artifact.file, directory: directory, owner: getuid())
                }
            }
            let services = plan.pair.authority.material.runtime.services
            authority = try .init(install: false, macID: services.macID, accountID: services.accountID)
            try authority.capability.install(authority.options, commitDigest: AuthorityPhonePushSettingsChange(plan).previousCommitDigest, verifyCurrent: {})
            service = try authority.service([.init(), .init(), .init()], binding: .init(accountID: services.accountID, rootEpoch: UUID()))
            owners.withLock { $0 = [] }
            let values = try GatewaySettingsConsumerRole.allCases.map(makeOwner)
            owners.withLock { $0 = values }
        }
        deinit { directory.close(); try? FileManager.default.removeItem(at: root) }
        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
                owner: getuid(), privateFile: file.mode == 0o600)
        }
        func fence() throws -> GatewayRuntimeSettingsFence {
            try .decode(read(.gatewaySettingsFence))
        }
        func makeOwner(_ role: GatewaySettingsConsumerRole) throws -> GatewaySettingsConsumerOwner {
            let plan = plan, directoryPath = directory.path
            let services = plan.pair.authority.material.runtime.services
            let read: @Sendable (AdministrativeSetupPublication.File) throws -> Data = { file in
                try ProtectedServiceConfiguration.read(anchor: directoryPath, relativePath: file.name,
                    owner: getuid(), privateFile: file.mode == 0o600)
            }
            return try .init(role: role, macID: services.macID, accountID: services.accountID,
                operations: .init(verifyScope: {}, readFence: { try .decode(read(.gatewaySettingsFence)) },
                    loadSelected: { binding, fence in
                        guard try read(.gatewayRuntimeCommit) == plan.commit.encoded else { throw Interrupted() }
                        if role == .gateway {
                            return try .gateway(binding: binding, fence: fence,
                                configuration: .decode(read(.gatewayConfiguration)), commit: plan.commit)
                        }
                        return try .transport(binding: binding, fence: fence,
                            configuration: .decode(read(.transportGatewayRuntime)), commit: plan.commit)
                    }, makeRuntime: { _, _ in Runtime() }))
        }
        func owner(_ role: GatewaySettingsConsumerRole) -> GatewaySettingsConsumerOwner {
            owners.withLock { $0[Int(role.rawValue - 1)] }
        }
        func operations() -> GatewaySettingsTransitionOperation.Operations {
            .init(verifyPending: { [self] incoming in
                guard try incoming.revision.encoded == plan.revision.encoded else { throw Interrupted() }
                try scope.validatePending()
            }, verifyComplete: { [self] _ in try scope.validateComplete() },
            root: { [self] plan, action, expected in
                try state.event("root.\(action)")
                let binding = try XCTUnwrap(service.gatewaySettingsBinding)
                guard expected == nil || expected == binding.rootEpoch else { throw Interrupted() }
                let returned: GatewaySettingsControlBinding
                if action == .observe, state.values.withLock({ $0.replaceRoot }) {
                    returned = try .init(accountID: binding.accountID, rootEpoch: UUID())
                } else { returned = binding }
                let request = try GatewaySettingsControlRequest(binding: returned, change: .init(plan), action: action,
                    challenge: Data(repeating: 7, count: 32))
                let access = try AuthorityGatewaySettingsAccess(service: service, binding: binding, verifyCurrent: {})
                if returned != binding { return try .init(request: request, observation: .suspended) }
                return try await .init(request: request, observation: access.execute(request))
            }, publishFence: { [self] _ in
                try state.event("fence")
                _ = try GatewayRuntimeSettingsFencePublication.publish(scope, directory: directory, owner: getuid(), verifyCurrent: {})
            }, consumer: { [self] _, role, action, expected in
                try state.event("\(action).\(role)")
                if action == .accept, role == .transport {
                    if state.values.withLock({ $0.replaceTransport }) {
                        let replacement = try makeOwner(role)
                        let old = owners.withLock { s in let old = s[1]; s[1] = replacement; return old }
                        oldOwners.withLock { $0.append(old) }
                    }
                    if state.values.withLock({ $0.holdAccept }) {
                        await withCheckedContinuation { gate in state.values.withLock { $0.gate = gate } }
                    }
                }
                let owner = owner(role)
                guard expected == nil || expected == owner.binding.generation else { throw Interrupted() }
                let request = try GatewaySettingsConsumerRequest(binding: owner.binding, fence: fence(), action: action,
                    challenge: Data(repeating: 8, count: 32))
                return try await owner.performAuthenticated(request, verifyCaller: {})
            }, observe: { [self] role in try state.event("observe.\(role)"); return owner(role).binding },
            mark: { [self] _, phase in
                try state.event("mark.\(phase)"); try scope.machine.markGatewaySettingsTransition(plan.revision, phase: phase)
            }, publish: { [self] plan, proof in
                try proof.requireValid(for: plan, phase: .quiesced); state.values.withLock { $0.quiescence = proof }
                try state.event("publish")
                _ = try GatewayRuntimeSettingsPublication.publish(plan, directory: directory, owner: getuid(),
                    verifyCurrent: scope.validatePending, requireQuiesced: { try proof.requireValid(for: plan, phase: .quiesced) },
                    didPublish: { file in try self.state.event("published.\(file.name)") })
            }, complete: { [self] plan, proof in
                try proof.requireValid(for: plan, phase: .accepted); state.values.withLock { $0.acceptance = proof }
                try state.event("complete"); try scope.machine.completeGatewaySettingsTransition(plan.revision)
                try state.event("completed")
            }, removeFence: { [self] plan, proof in
                try proof.requireValid(for: plan, phase: .accepted); try state.event("remove")
                _ = try GatewayRuntimeSettingsFencePublication.remove(scope, directory: directory, owner: getuid(), verifyCurrent: {})
            })
        }
        func release() { state.values.withLock { s in let old = s.gate; s.gate = nil; return old }?.resume() }
        func close() async throws {
            release()
            for owner in owners.withLock({ $0 }) + oldOwners.withLock({ $0 }) { try await owner.close() }
            try await service.close()
        }
        func run() async throws -> GatewaySettingsTransitionOperation.Result {
            try await GatewaySettingsTransitionOperation.resume(plan, operations: operations())
        }
    }
    func testRealOwnersAndProtectedFilesFinishBeforeRootAcceptsWithoutChangingTheRequest() async throws {
        let f = try Fixture(native: true); try await f.service.start()
        let request = try f.authority.state(), foreground = try f.ready.fixture.runtime.plan.encoded
        let result = try await f.run()
        XCTAssertEqual(result.observation, .accepted)
        try f.scope.validateComplete()
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.directory.path + "/gateway-settings-fence.cbor"))
        XCTAssertEqual(try f.read(.gatewayRuntimeCommit), try f.plan.commit.encoded)
        XCTAssertEqual(try f.authority.state(), request)
        XCTAssertEqual(try f.ready.fixture.runtime.plan.encoded, foreground)
        XCTAssertEqual(f.authority.starts.withLock { $0 }, 1); XCTAssertEqual(f.authority.closes.withLock { $0 }, 0)
        XCTAssertEqual(f.authority.capability.retainedCommitDigest, try f.plan.commit.observationDigest)
        XCTAssertNil(f.authority.capability.installedCommitDigest)
        XCTAssertNil(f.authority.capability.publication)
        try await f.service.installPhonePush(f.authority.options, commitDigest: f.plan.commit.observationDigest, verifyCurrent: { try f.scope.validateComplete() })
        XCTAssertNotNil(f.authority.capability.publication)
        XCTAssertEqual(f.authority.capability.installedCommitDigest, try f.plan.commit.observationDigest)
        let events = f.state.values.withLock { $0.events }
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "quiesce.transport")), try XCTUnwrap(events.firstIndex(of: "publish")))
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "accept.transport")), try XCTUnwrap(events.firstIndex(of: "complete")))
        XCTAssertLessThan(try XCTUnwrap(events.firstIndex(of: "remove")), try XCTUnwrap(events.firstIndex(of: "root.accept")))
        for phase in [GatewaySettingsTransitionBarrier.Phase.quiesced, .accepted] {
            let proof = try XCTUnwrap(f.state.values.withLock { phase == .quiesced ? $0.quiescence : $0.acceptance })
            XCTAssertThrowsError(try proof.requireValid(for: f.plan, phase: phase))
        }
        try await f.close()
    }
    func testSavedObservationMarkersCannotSkipTheFreshThreeProcessBarrier() async throws {
        let f = try Fixture(); try await f.service.start()
        for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() { try f.scope.machine.markGatewaySettingsTransition(f.plan.revision, phase: phase) }
        _ = try await f.run()
        let events = f.state.values.withLock { $0.events }
        for event in ["root.quiesce", "quiesce.gateway", "quiesce.transport", "publish", "accept.gateway", "accept.transport"] {
            XCTAssertTrue(events.contains(event), event)
        }
        try await f.close()
    }
    func testPartialPublicationAndEveryLaterFailureLeaveRootPausedAndPreserveThePendingRevision() async throws {
        for event in ["fence", "quiesce.transport", "published.transport-gateway-runtime.cbor", "accept.transport", "complete"] {
            let f = try Fixture(); try await f.service.start(); let request = try f.authority.state()
            f.state.values.withLock { $0.fail = event }
            do { _ = try await f.run(); XCTFail(event) } catch {}
            let stored = try f.scope.machine.gatewaySettingsTransition(accountID: f.plan.revision.accountID)
            XCTAssertEqual(try stored.pending?.encoded, try f.plan.revision.encoded)
            XCTAssertNil(stored.active)
            XCTAssertNil(f.authority.capability.publication)
            XCTAssertEqual(try f.authority.state(), request)
            XCTAssertFalse(f.state.values.withLock { $0.events }.contains("root.accept"))
            f.state.values.withLock { $0.fail = nil }
            _ = try await f.run()
            try f.scope.validateComplete(); try await f.close()
        }
    }
    func testChangedCompanionGenerationOrRootEpochCannotCompleteTheRevision() async throws {
        for changeRoot in [false, true] {
            let f = try Fixture(); try await f.service.start()
            f.state.values.withLock { if changeRoot { $0.replaceRoot = true } else { $0.replaceTransport = true } }
            do { _ = try await f.run(); XCTFail() } catch {}
            try f.scope.validatePending()
            XCTAssertFalse(f.state.values.withLock { $0.events }.contains("complete"))
            XCTAssertNil(f.authority.capability.publication)
            try await f.close()
        }
    }
    func testLostCompletionReplyNeedsCompletedRecoveryAndCannotRepeatThePendingOperation() async throws {
        let f = try Fixture(); try await f.service.start()
        f.state.values.withLock { $0.fail = "completed" }
        do { _ = try await f.run(); XCTFail() } catch {}
        try f.scope.validateComplete()
        XCTAssertNotNil(try f.fence()); XCTAssertNil(f.authority.capability.publication)
        let count = f.state.values.withLock { $0.events.count }
        f.state.values.withLock { $0.fail = nil }
        do { _ = try await f.run(); XCTFail() } catch {}
        XCTAssertEqual(f.state.values.withLock { $0.events.count }, count)
        try await f.close()
    }
    func testCancellationDuringCompanionAcceptanceCannotCommitOrResumeRoot() async throws {
        let f = try Fixture(); try await f.service.start()
        f.state.values.withLock { $0.holdAccept = true }
        let task = Task { try await f.run() }; defer { f.release() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(10))
        while !f.state.values.withLock({ $0.gate != nil }) {
            guard ContinuousClock.now < deadline else { throw Interrupted() }
            try await Task.sleep(for: .milliseconds(2))
        }
        task.cancel(); f.release()
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        try f.scope.validatePending()
        XCTAssertFalse(f.state.values.withLock { $0.events }.contains("complete"))
        XCTAssertNil(f.authority.capability.publication); try await f.close()
    }
}
