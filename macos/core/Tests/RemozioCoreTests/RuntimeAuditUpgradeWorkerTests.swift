import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Swift-task callers dispatch ordinary-owner work to a managed worker. Native custody and platform service calls remain separate gates.
final class RuntimeAuditUpgradeWorkerTests: XCTestCase {
    private final class Owned<Value>: @unchecked Sendable {
        let value: Value
        init(_ value: Value) { self.value = value }
    }
    private final class ResultBox: @unchecked Sendable {
        private let lock = NSLock()
        private var result: Result<Void, any Error>?
        func set(_ result: Result<Void, any Error>) { lock.withLock { self.result = result } }
        func check() throws { try lock.withLock { try XCTUnwrap(result).get() } }
    }
    private final class Latch: @unchecked Sendable {
        private let lock = NSLock()
        private var fired = false, settled: Bool?
        func claim() -> Bool { lock.withLock { if fired { return false }; fired = true; return true } }
        func settle(_ value: Bool) { lock.withLock { settled = value } }
        var settlement: Bool? { lock.withLock { settled } }
    }
    private func worker(_ name: String, owner: SetupAccountOwner? = nil,
                        authorization: SetupAuditUpgradeAuthorization? = nil, body: @escaping @Sendable (SetupAuditUpgradeCancellation, SetupAccountOwner.ExecutorAdmission?) throws -> Void) throws {
        let completed = expectation(description: name), result = ResultBox()
        Task.detached { [completed, result] in
            let probe: @Sendable (SetupAuditUpgradeCancellation, SetupAccountOwner.ExecutorAdmission?) throws -> Void = { cancellation, admission in
                let stack = pthread_get_stacksize_np(pthread_self())
                FileHandle.standardOutput.write(Data("AUDIT_WORKER start \(name) main=\(pthread_main_np() != 0) stackBytes=\(stack)\n".utf8))
                XCTAssertEqual(pthread_main_np(), 0)
                XCTAssertGreaterThanOrEqual(stack, SetupAuditUpgradeWorkExecutor.stackBytes)
                try body(cancellation, admission)
            }
            do {
                if let owner, let authorization { try await owner.performAuditUpgradeWork(authorization: authorization) { c, admission in try probe(c, admission) } }
                else { try await SetupAuditUpgradeWorkExecutor().run { c in try probe(c, nil) } }
                result.set(.success(()))
            } catch { result.set(.failure(error)) }
            FileHandle.standardOutput.write(Data("AUDIT_WORKER settled \(name)\n".utf8))
            completed.fulfill()
        }
        wait(for: [completed], timeout: 90)
        try result.check()
    }
    func testSwiftCallerPreparesSourceAndGraphOnManagedWorker() throws {
        let files = try RuntimeAuditUpgradeArtifactTests.Fixture(), sourceArtifacts = try files.plan()
        try files.install(sourceArtifacts)
        for entry in sourceArtifacts.entries where entry.file.name == "command-host.cbor" || entry.directory == .jobs {
            let path = try XCTUnwrap(files.directories[entry.directory]).path + "/" + entry.file.name
            if FileManager.default.fileExists(atPath: path) { XCTAssertEqual(unlink(path), 0) }
        }
        let owned = Owned(files)
        try worker("source-preparation") { cancellation, _ in
            let files = owned.value, f = files.f, release = try XCTUnwrap(f.nativeRelease)
            let plan = try RuntimeAuditUpgradeSourcePlan.retainOwned(machine: f.machine, account: f.account,
                installedRelease: release, owner: getuid(), runtime: XCTUnwrap(files.directories[.runtime]),
                services: XCTUnwrap(files.directories[.services]), clientsDirectory: XCTUnwrap(files.directories[.clients]), verifyOwner: cancellation.check)
            XCTAssertEqual(try plan.encoded, try files.preparation.source.encoded)
            let record = try f.machine.retainRuntimeAuditUpgrade(files.preparation.intent,
                currentPolicy: plan.host.codePolicy, installedRelease: release)
            let staged = try RuntimeAuditUpgradeStaging.stageOwned(machine: f.machine, account: f.account, expected: record,
                currentPolicy: plan.host.codePolicy, installedRelease: release, directory: XCTUnwrap(files.directories[.runtime]),
                owner: getuid(), verifyCurrent: cancellation.check, verifyActivity: { _ in try cancellation.check() })
            let scope = try RuntimeAuditUpgradeCaptureScope.captureOwned(machine: f.machine, expected: staged,
                installedRelease: release, currentPolicy: plan.host.codePolicy, owner: getuid(), verifyOwner: cancellation.check)
            defer { scope.close() }
            let observation = try RuntimeAuditUpgradeCollector.captureOwned(scope: scope, directories: files.directories,
                owner: getuid(), observeJournal: { nil })
            let graph = try RuntimeAuditUpgradeGraph(observation: observation, upgrade: staged,
                installedRelease: release, currentPolicy: plan.host.codePolicy)
            let retained = try f.machine.retainRuntimeAuditGraph(graph, installedRelease: release, currentPolicy: plan.host.codePolicy)
            let stored = try RuntimeAuditUpgradeGraphStorage.restoreOwned(machine: f.machine, expected: retained,
                installedRelease: release, currentPolicy: plan.host.codePolicy, directory: XCTUnwrap(files.directories[.runtime]),
                owner: getuid(), verifyOwner: cancellation.check)
            XCTAssertEqual(stored.phase, .fileStored)
            XCTAssertFalse(try f.machine.runtimeActivation(accountID: f.account.accountID).jobsRegistered)
            XCTAssertEqual(graph.snapshot.plan.sourceInventory, try f.machine.inventory())
        }
    }
    func testSwiftCallerCompletesOwnedInvocationOnManagedWorker() throws {
        let h = try RuntimeAuditUpgradeOperationTests.Harness(gateway: true), owner = try h.owner()
        defer { try? owner.close() }
        let expected = try XCTUnwrap(owner.auditUpgradeProgress(callerUID: getuid())), harness = Owned(h)
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
        try worker("complete-cutover", owner: owner, authorization: grant) { cancellation, admission in
            XCTAssertTrue(cancellation === grant.cancellationToken)
            let invocation: SetupAuditUpgradeInvocation
            do {
                invocation = try .openOwned(owner: owner, expected: expected, authorization: grant, admission: admission,
                    openOperation: harness.value.operation(scope:))
            } catch { grant.close(); throw error }
            defer { XCTAssertTrue(owner.settleAuditUpgradeInvocation(invocation)) }
            try invocation.run { bytes in
                let result = try SetupAuditUpgradeProgress.decode(bytes)
                try result.validateScope(of: expected)
                XCTAssertEqual(result.stage, .registrationObserved)
                XCTAssertEqual(result.registrationObserved, [.authority, .transport, .notificationGateway])
                XCTAssertThrowsError(try owner.verifyCurrent())
            }
        }
        try owner.verifyCurrent()
        XCTAssertTrue(h.bootstraps.values.allSatisfy { $0 == 1 })
        XCTAssertEqual(h.preparations, 1); XCTAssertEqual(h.restarts, 1)
    }
    /// Task cancellation during the cutover leaves the failed cleanup with the setup owner. Only a later cleanup releases admission.
    func testCancelledWorkerRetainsFailedCleanupInTheSetupOwnerUntilRetry() throws {
        let h = try RuntimeAuditUpgradeOperationTests.Harness(), owner = try h.owner()
        defer { try? owner.close() }
        h.quiescenceCloseFails = true
        let expected = try XCTUnwrap(owner.auditUpgradeProgress(callerUID: getuid())), harness = Owned(h), latch = Latch()
        let reached = expectation(description: "Cutover holds quiescence"), resume = DispatchSemaphore(value: 0)
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {
            guard harness.value.q != nil, latch.claim() else { return }
            reached.fulfill()
            _ = resume.wait(timeout: .now() + 15)
        })
        let done = expectation(description: "Cancelled worker settled"), result = ResultBox()
        let task = Task.detached { [done, result] in
            do {
                try await owner.performAuditUpgradeWork(authorization: grant) { _, admission in
                    let invocation = try SetupAuditUpgradeInvocation.openOwned(owner: owner, expected: expected, authorization: grant, admission: admission,
                        openOperation: harness.value.operation(scope:))
                    defer { latch.settle(owner.settleAuditUpgradeInvocation(invocation)) }
                    try invocation.run { _ in XCTFail("Cancelled reply") }
                }
                result.set(.success(()))
            } catch { result.set(.failure(error)) }
            done.fulfill()
        }
        wait(for: [reached], timeout: 30); task.cancel()
        XCTAssertNil(latch.settlement)
        XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
        resume.signal(); wait(for: [done], timeout: 30)
        XCTAssertThrowsError(try result.check()); XCTAssertEqual(latch.settlement, false)
        XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try h.installer.acquireShared())
        XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
        let process = try SetupProcessLease.openOwned(directory: .init(anchor: h.activity.root.path, relativeDirectory: "Machine", owner: getuid()))
        defer { process.close() }
        let checks = Mutex(0), identity = h.base.runtime.f.identity, accountID = h.base.runtime.account.accountID
        let rights = try SetupRetainedRecoveryAuthorization.openOwned(
            peer: .init(processID: getpid(), userID: identity.uid, auditSessionID: 1), currentOwner: identity,
            incarnation: UUID(), verifyRights: { checks.withLock { $0 += 1 } })
        let baseline = checks.withLock { $0 }, started = ContinuousClock.now
        let refused = expectation(description: "Failed cleanup refuses another claim")
        Task.detached {
            do {
                _ = try await SetupRestartRecovery.Claim.openOwned(owner: owner, authorization: rights,
                    processLease: process, accountID: accountID, until: .now.advanced(by: .seconds(5)))
                XCTFail("A failed audit cleanup lost its admission")
            } catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
            refused.fulfill()
        }
        wait(for: [refused], timeout: 3)
        XCTAssertLessThan(started.duration(to: .now), .milliseconds(100)); XCTAssertEqual(checks.withLock { $0 }, baseline)
        XCTAssertFalse(owner.retryAuditUpgradeCleanup())
        try XCTUnwrap(h.q).closeFails = false
        XCTAssertTrue(owner.retryAuditUpgradeCleanup()); try owner.verifyCurrent(); try h.machine { _ in () }
    }
}
