import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsTransitionContextTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private final class Fixture: @unchecked Sendable {
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let revision: GatewayRuntimeSettingsRevision
        let expected: SetupGatewayActivationProgress
        let snapshot: GatewaySettingsTransitionSnapshot
        init() throws {
            ready = try .init(nativeConsumerHosts: true)
            let machine = ready.fixture.runtime.machine
            revision = try ready.revision()
            let owner = ready.fixture.runtime.plan.host.command.callerUID
            let account = try XCTUnwrap(machine.accountPreparation(ownerUID: owner))
            let setup = try SetupGatewayProgress(account: account,
                runtime: machine.runtimePreparation(accountID: account.accountID),
                activation: machine.runtimeActivation(accountID: account.accountID),
                material: machine.gatewayPreparation(accountID: account.accountID),
                journal: machine.gatewayJournalPreparation(accountID: account.accountID))
            expected = try .init(setup: setup, state: machine.gatewayRuntimeActivation(accountID: account.accountID))
            try machine.retainGatewaySettingsTransition(revision)
            snapshot = try .load(machine: machine, ownerUID: owner, expected: expected, revision: revision)
            try machine.close()
        }
        func open() throws -> PreparationIntentStore { try ready.fixture.runtime.f.open() }
        func context(verify: @escaping @Sendable (AccountPreparationIntent) throws -> Void = { _ in }) throws -> GatewaySettingsTransitionContext {
            try .init(snapshot: snapshot, openMachine: open, verifyHost: { _ in }, verifyAccount: verify)
        }
    }
    func testEveryReadClosesItsWriterAndTheCapturedPhaseCannotFollowCompletion() throws {
        let f = try Fixture(), context = try f.context()
        XCTAssertEqual(try context.observePhase(), .pending)
        try context.verify(.pending)
        let machine = try f.open()
        for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() {
            try machine.markGatewaySettingsTransition(f.revision, phase: phase)
        }
        try machine.completeGatewaySettingsTransition(f.revision)
        try machine.close()
        XCTAssertThrowsError(try context.verify(.pending))
        XCTAssertEqual(try context.observePhase(), .complete)
        try context.verify(.complete)
        let reopened = try f.open(); try reopened.close()
    }
    func testFailedAccountVerificationClosesTheBorrowAndCannotReturnAPhase() throws {
        let f = try Fixture(), allowed = Mutex(true)
        let context = try f.context { _ in guard allowed.withLock({ $0 }) else { throw Refused() } }
        try context.verify(.pending)
        allowed.withLock { $0 = false }
        XCTAssertThrowsError(try context.observePhase())
        let machine = try f.open(); defer { try? machine.close() }
        XCTAssertEqual(try machine.gatewaySettingsTransition(accountID: f.revision.accountID).pending?.encoded, try f.revision.encoded)
    }
    func testInvalidControlTimeoutRefusesBeforeOpeningAnyMachineStore() throws {
        let f = try Fixture(), opens = Mutex(0)
        for timeout: UInt64 in [0, 60_001, .max] {
            XCTAssertThrowsError(try GatewaySettingsTransitionContext(snapshot: f.snapshot,
                openMachine: { opens.withLock { $0 += 1 }; return try f.open() },
                verifyHost: { _ in }, verifyAccount: { _ in }, timeoutMilliseconds: timeout))
        }
        XCTAssertEqual(opens.withLock { $0 }, 0)
    }
    func testNativeEntryRefusesAnOrdinaryProcessBeforeHostVerificationOrProtectedReads() async throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("This control requires an ordinary account") }
        let f = try Fixture(), verified = Mutex(0)
        do {
            _ = try await GatewaySettingsTransitionRootOperation.resumeNative(machineDirectory: "/unused-protected-store",
                macID: f.snapshot.inventory.macID, ownerUID: f.expected.setup.ownerUID,
                expected: f.expected, revision: f.revision, verifyHost: { _ in verified.withLock { $0 += 1 } })
            XCTFail("An ordinary process cannot enter native settings mutation")
        } catch { XCTAssertEqual(error as? JournalLeaseError, .rootRequired) }
        XCTAssertEqual(verified.withLock { $0 }, 0)
    }
}
