import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class MachineUpdateRestartHealthCoordinatorTests: XCTestCase {
    private final class Account: OwnedMachineUpdateRestartAccount {
        let accountID: Data
        let replies: [MachineUpdateAuthenticatedRoleReply]
        let hotJournal: Bool
        let valid = Mutex(true), busy = Mutex(false)
        let closes = Mutex(0)
        init(accountID: Data, replies: [MachineUpdateAuthenticatedRoleReply] = [], hotJournal: Bool = false) {
            self.accountID = accountID; self.replies = replies; self.hotJournal = hotJournal
        }
        func check() async throws -> [MachineUpdateAuthenticatedRoleReply] {
            if hotJournal { throw MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired }
            return replies
        }
        func validate() throws {
            if busy.withLock({ $0 }) { throw MachineUpdateHealthSourceError.busy }
            guard valid.withLock({ $0 }) else { throw JournalLeaseError.invalidated }
        }
        func close() async throws { closes.withLock { $0 += 1 } }
    }

    private final class InstalledAccount: OwnedMachineUpdateInstalledReadinessAccount {
        let health: Account
        let ordinary = Mutex(true)
        let beforeProof: @Sendable () async throws -> Void
        var accountID: Data { health.accountID }

        init(_ health: Account, beforeProof: @escaping @Sendable () async throws -> Void = {}) {
            self.health = health
            self.beforeProof = beforeProof
        }
        func check() async throws -> [MachineUpdateAuthenticatedRoleReply] {
            try await beforeProof()
            return try await health.check()
        }
        func validate() throws { try health.validate() }
        func validateOrdinaryReadiness() throws {
            guard ordinary.withLock({ $0 }) else { throw JournalLeaseError.invalidated }
        }
        func close() async throws { try await health.close() }
    }

    private final class RecoveryCount: Sendable { let calls = Mutex(0) }

    private func reply(_ requirement: MachineUpdateRestartHealthPlan.Requirement,
        signedBy fixture: MachineUpdateRoleChallengeTests.Fixture) throws -> MachineUpdateAuthenticatedRoleReply {
        let challenge = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let bytes = try fixture.answer(challenge.request, expected: requirement)
        return try challenge.accept(bytes, authenticatePeer: { _ in })
    }

    private final class Activity: OwnedReleaseActivity {
        let closed = Mutex(false)
        func validate() throws {
            guard !closed.withLock({ $0 }) else { throw JournalLeaseError.invalidated }
        }
        func close() { closed.withLock { $0 = true } }
    }

    func testInstalledReadinessChecksBothAccountsConcurrentlyAndLendsTheProofOnce() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let started = Mutex(0)
        let activity = Activity()
        let rendezvous: @Sendable () async throws -> Void = {
            try activity.validate()
            started.withLock { $0 += 1 }
            let clock = ContinuousClock(), deadline = ContinuousClock().now + .seconds(2)
            while started.withLock({ $0 }) < 2 {
                guard clock.now < deadline else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
                try await Task.sleep(for: .milliseconds(10))
            }
        }
        var requirements: [MachineUpdateHealthInventory.Requirement] = []
        var accounts: [InstalledAccount] = []
        for account in [UInt8(3), 4] {
            let authority = try fixture.requirement(account: account)
            let transport = try fixture.requirement(role: .transport, uid: 20000 + UInt32(account), account: account)
            requirements += [authority, transport]
            accounts.append(InstalledAccount(Account(accountID: authority.binding.accountID,
                replies: try [reply(authority, signedBy: fixture), reply(transport, signedBy: fixture)]), beforeProof: rendezvous))
        }
        let owners = accounts
        let inventory = try MachineUpdateHealthInventory(requirements: requirements, preservedAccounts: [])
        let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {},
            installedActivity: activity, makeAccount: { accountID, _ in
                guard let owner = owners.first(where: { $0.accountID == accountID }) else {
                    throw MachineUpdateHealthCoordinatorError.invalidInventory
                }
                return owner
            }, recoverOrdinary: { _ in XCTFail("Installed readiness reached a restart writer") })
        let expired = try await coordinator.withVerifiedInstalledReadiness { scope in
            XCTAssertEqual(scope.inventory.accountIDs, inventory.accountIDs)
            try scope.validate()
            try activity.validate()
            XCTAssertEqual(owners.map { $0.health.closes.withLock { $0 } }, [0, 0])
            return scope
        }
        XCTAssertThrowsError(try expired.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertEqual(owners.map { $0.health.closes.withLock { $0 } }, [1, 1])
        XCTAssertTrue(activity.closed.withLock { $0 })
        do {
            try await coordinator.withVerifiedInstalledReadiness { _ in XCTFail("Readiness scope was reused") }
        } catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .busy) }
    }

    func testInstalledReadinessRevalidatesOrdinaryOwnersBeforeReturning() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let authority = try fixture.requirement(), transport = try fixture.requirement(role: .transport, uid: 20000)
        let inventory = try MachineUpdateHealthInventory(requirements: [authority, transport], preservedAccounts: [])
        let health = Account(accountID: authority.binding.accountID,
            replies: try [reply(authority, signedBy: fixture), reply(transport, signedBy: fixture)])
        let owner = InstalledAccount(health), activity = Activity()
        let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {},
            installedActivity: activity, makeAccount: { _, _ in owner },
            recoverOrdinary: { _ in XCTFail("Installed readiness reached a restart writer") })
        do {
            try await coordinator.withVerifiedInstalledReadiness { scope in
                try scope.validate()
                owner.ordinary.withLock { $0 = false }
            }
            XCTFail("Unavailable ordinary runtime verified")
        } catch { XCTAssertEqual(error as? JournalLeaseError, .invalidated) }
        XCTAssertEqual(health.closes.withLock { $0 }, 1)
        XCTAssertTrue(activity.closed.withLock { $0 })
    }

    func testInstalledReadinessCannotRecoverAGatewayJournal() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let authority = try fixture.requirement()
        let transport = try fixture.requirement(role: .transport, uid: 20000)
        let gateway = try fixture.requirement(role: .notificationGateway, uid: 20001)
        let inventory = try MachineUpdateHealthInventory(requirements: [authority, transport, gateway], preservedAccounts: [])
        let health = Account(accountID: authority.binding.accountID, hotJournal: true)
        let owner = InstalledAccount(health), activity = Activity()
        let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {},
            installedActivity: activity, makeAccount: { _, _ in owner },
            recoverOrdinary: { _ in XCTFail("Installed readiness reached a restart writer") })
        do {
            try await coordinator.withVerifiedInstalledReadiness { _ in XCTFail("Unready Gateway verified") }
            XCTFail("Unready Gateway returned")
        } catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .installedGatewayRecoveryRequired) }
        XCTAssertEqual(health.closes.withLock { $0 }, 1)
        XCTAssertTrue(activity.closed.withLock { $0 })
        try await coordinator.close()
        XCTAssertEqual(health.closes.withLock { $0 }, 1)
    }

    func testMissingSelectedRoleKeepsTheMachineUnverifiedAndRetainsItsOwnerUntilClose() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let authority = try fixture.requirement(), transport = try fixture.requirement(role: .transport, uid: 20000)
        let inventory = try MachineUpdateHealthInventory(requirements: [authority, transport], preservedAccounts: [])
        let owner = Account(accountID: authority.binding.accountID, replies: [try reply(authority, signedBy: fixture)])
        let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {},
            makeAccount: { _, _ in owner }, recoverOrdinary: { _ in XCTFail("Missing evidence reached recovery") })
        do { try await coordinator.check(); XCTFail("Missing role verified the machine") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .incompleteHealth) }
        do { try await coordinator.requireVerified(); XCTFail("Unverified machine advanced") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .incompleteHealth) }
        XCTAssertEqual(owner.closes.withLock { $0 }, 0)
        try await coordinator.close()
        XCTAssertEqual(owner.closes.withLock { $0 }, 1)
    }

    func testCompleteCohortIsRevalidatedBeforeRestartMayAdvance() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let authority = try fixture.requirement(), transport = try fixture.requirement(role: .transport, uid: 20000)
        let inventory = try MachineUpdateHealthInventory(requirements: [authority, transport], preservedAccounts: [])
        let owner = Account(accountID: authority.binding.accountID,
            replies: try [reply(authority, signedBy: fixture), reply(transport, signedBy: fixture)])
        let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {},
            makeAccount: { _, _ in owner }, recoverOrdinary: { _ in XCTFail("Verified cohort reached recovery") })
        try await coordinator.check()
        try await coordinator.requireVerified()
        owner.busy.withLock { $0 = true }
        do { try await coordinator.requireVerified(); XCTFail("Busy cohort advanced") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthSourceError, .busy) }
        XCTAssertEqual(owner.closes.withLock { $0 }, 0)
        owner.busy.withLock { $0 = false }
        try await coordinator.requireVerified()
        owner.valid.withLock { $0 = false }
        do { try await coordinator.requireVerified(); XCTFail("Expired owner advanced the restart") }
        catch { XCTAssertEqual(error as? JournalLeaseError, .invalidated) }
        try await coordinator.close()
        XCTAssertEqual(owner.closes.withLock { $0 }, 1)
    }

    func testBusyInitialCollectionClosesPartialOwnersAndAllowsAFreshAttempt() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let gateway = try fixture.requirement(role: .notificationGateway, uid: 20001)
        let inventory = try MachineUpdateHealthInventory(requirements: [gateway], preservedAccounts: [])
        let partial = Account(accountID: gateway.binding.accountID, replies: [try reply(gateway, signedBy: fixture)])
        let current = Account(accountID: gateway.binding.accountID, replies: [try reply(gateway, signedBy: fixture)])
        let attempts = Mutex(0)
        partial.busy.withLock { $0 = true }
        let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {},
            makeAccount: { _, _ in
                attempts.withLock { $0 += 1; return $0 == 1 ? partial : current }
            }, recoverOrdinary: { _ in XCTFail("Busy reached recovery") })
        do { try await coordinator.check(); XCTFail("Partial collection passed") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthSourceError, .busy) }
        XCTAssertEqual(partial.closes.withLock { $0 }, 1)
        try await coordinator.check()
        try await coordinator.requireVerified()
        try await coordinator.close()
        XCTAssertEqual(current.closes.withLock { $0 }, 1)
    }

    func testSecondAccountFailurePreventsTheCohortFromAdvancing() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let first = try fixture.requirement(role: .notificationGateway, uid: 20001, account: 3)
        let second = try fixture.requirement(role: .notificationGateway, uid: 20002, account: 4)
        let inventory = try MachineUpdateHealthInventory(requirements: [first, second], preservedAccounts: [])
        let ready = Account(accountID: first.binding.accountID, replies: [try reply(first, signedBy: fixture)])
        let missing = Account(accountID: second.binding.accountID)
        let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {},
            makeAccount: { account, _ in account == ready.accountID ? ready : missing },
            recoverOrdinary: { _ in XCTFail("Missing proof reached recovery") })
        do { try await coordinator.check(); XCTFail("Incomplete cohort passed") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .incompleteHealth) }
        do { try await coordinator.requireVerified(); XCTFail("Incomplete cohort advanced") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .incompleteHealth) }
        XCTAssertEqual(ready.closes.withLock { $0 }, 0)
        try await coordinator.close()
        XCTAssertEqual(ready.closes.withLock { $0 }, 1)
        XCTAssertEqual(missing.closes.withLock { $0 }, 1)
    }

    func testCompletedRecoveryRequiresFreshOwnersForTheWholeCohort() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let first = try fixture.requirement(role: .notificationGateway, uid: 20001, account: 3)
        let second = try fixture.requirement(role: .notificationGateway, uid: 20002, account: 4)
        let inventory = try MachineUpdateHealthInventory(requirements: [first, second], preservedAccounts: [])
        let previous = Account(accountID: first.binding.accountID, replies: [try reply(first, signedBy: fixture)])
        let hot = Account(accountID: second.binding.accountID, hotJournal: true)
        let fresh = Account(accountID: first.binding.accountID, replies: [try reply(first, signedBy: fixture)])
        let recovered = Account(accountID: second.binding.accountID, replies: [try reply(second, signedBy: fixture)])
        let recovery = RecoveryCount()
        let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {},
            makeAccount: { account, _ in
                let afterRecovery = recovery.calls.withLock { $0 > 0 }
                if account == previous.accountID { return afterRecovery ? fresh : previous }
                return afterRecovery ? recovered : hot
            }, recoverOrdinary: { account in
                XCTAssertEqual(account, hot.accountID)
                XCTAssertEqual(previous.closes.withLock { $0 }, 1)
                XCTAssertEqual(hot.closes.withLock { $0 }, 1)
                recovery.calls.withLock { $0 += 1 }
            })
        do { try await coordinator.check(); XCTFail("Recovery produced machine health") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .recoveryCompletedNeedsFreshCheck) }
        do { try await coordinator.requireVerified(); XCTFail("Recovery advanced the restart") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .incompleteHealth) }
        try await coordinator.check()
        try await coordinator.requireVerified()
        try await coordinator.close()
        XCTAssertEqual(recovery.calls.withLock { $0 }, 1)
        XCTAssertEqual(previous.closes.withLock { $0 }, 1)
        XCTAssertEqual(fresh.closes.withLock { $0 }, 1)
        XCTAssertEqual(recovered.closes.withLock { $0 }, 1)
    }

    func testRecoveryFailureOrSourceInvalidationCannotRearmTheCoordinator() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let gateway = try fixture.requirement(role: .notificationGateway, uid: 20001)
        let inventory = try MachineUpdateHealthInventory(requirements: [gateway], preservedAccounts: [])
        for writerFails in [true, false] {
            let owner = Account(accountID: gateway.binding.accountID, hotJournal: true)
            let factories = Mutex(0), calls = Mutex(0)
            let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {
                if calls.withLock({ $0 > 0 }) { throw JournalLeaseError.invalidated }
            }, makeAccount: { _, _ in
                factories.withLock { $0 += 1 }
                return owner
            }, recoverOrdinary: { account in
                XCTAssertEqual(account, owner.accountID)
                XCTAssertEqual(owner.closes.withLock { $0 }, 1)
                calls.withLock { $0 += 1 }
                if writerFails { throw JournalLeaseError.invalidated }
            })
            do { try await coordinator.check(); XCTFail("Invalid recovery passed") }
            catch { XCTAssertEqual(error as? JournalLeaseError, .invalidated) }
            do { try await coordinator.check(); XCTFail("Invalid recovery allowed another check") }
            catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .busy) }
            try await coordinator.close()
            XCTAssertEqual(factories.withLock { $0 }, 1)
            XCTAssertEqual(calls.withLock { $0 }, 1)
            XCTAssertEqual(owner.closes.withLock { $0 }, 1)
        }
    }

    func testWriterFailuresAndPostWriterContentionNeverRearmTheCoordinator() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let gateway = try fixture.requirement(role: .notificationGateway, uid: 20001)
        let inventory = try MachineUpdateHealthInventory(requirements: [gateway], preservedAccounts: [])
        for scenario in 0..<3 {
            let owner = Account(accountID: gateway.binding.accountID, hotJournal: true)
            let factories = Mutex(0), calls = Mutex(0)
            let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {
                if scenario == 2, calls.withLock({ $0 > 0 }) { throw MachineUpdateHealthSourceError.busy }
            }, makeAccount: { _, _ in
                factories.withLock { $0 += 1 }
                return owner
            }, recoverOrdinary: { _ in
                calls.withLock { $0 += 1 }
                if scenario == 0 { throw MachineUpdateHealthSourceError.busy }
                if scenario == 1 { throw MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired }
            })
            do { try await coordinator.check(); XCTFail("Recovery failure passed") }
            catch {
                if scenario == 1 {
                    XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .gatewayRecoveryRequired)
                } else {
                    XCTAssertEqual(error as? MachineUpdateHealthSourceError, .busy)
                }
            }
            do { try await coordinator.check(); XCTFail("Recovery failure allowed a fresh check") }
            catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .busy) }
            try await coordinator.close()
            XCTAssertEqual(factories.withLock { $0 }, 1)
            XCTAssertEqual(calls.withLock { $0 }, 1)
            XCTAssertEqual(owner.closes.withLock { $0 }, 1)
        }
    }

    func testHotJournalClosesTheAccountBeforeRecoveryAndKeepsTheMachineUnverified() async throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        let gateway = try fixture.requirement(role: .notificationGateway, uid: 20001)
        let inventory = try MachineUpdateHealthInventory(requirements: [gateway], preservedAccounts: [])
        let owner = Account(accountID: gateway.binding.accountID, hotJournal: true)
        let recovered = RecoveryCount()
        let coordinator = MachineUpdateRestartHealthCoordinator(inventory: inventory, verifyCurrent: {},
            makeAccount: { _, _ in owner }, recoverOrdinary: { accountID in
                XCTAssertEqual(accountID, owner.accountID)
                XCTAssertEqual(owner.closes.withLock { $0 }, 1)
                recovered.calls.withLock { $0 += 1 }
            })
        do { try await coordinator.check(); XCTFail("Recovery produced machine health") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .recoveryCompletedNeedsFreshCheck) }
        XCTAssertEqual(recovered.calls.withLock { $0 }, 1)
        do { try await coordinator.check(); XCTFail("A second hot journal passed") }
        catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .gatewayRecoveryRequired) }
        XCTAssertEqual(recovered.calls.withLock { $0 }, 1)
        do { try await coordinator.requireVerified(); XCTFail("Recovery advanced the restart") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .incompleteHealth) }
        try await coordinator.close()
        XCTAssertEqual(owner.closes.withLock { $0 }, 2)
    }
}
