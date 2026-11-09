import Darwin
import Foundation

/// One account owns its Authority, consumer channels, and any paired Gateway reader until joined close.
protocol OwnedMachineUpdateRestartAccount: AnyObject, Sendable {
    var accountID: Data { get }
    func check() async throws -> [MachineUpdateAuthenticatedRoleReply]
    func validate() throws
    func close() async throws
}

/// A synchronous loan of the live installed readiness cohort.
final class MachineUpdateVerifiedInstalledReadinessScope: @unchecked Sendable {
    let inventory: MachineUpdateHealthInventory
    private let processID = getpid()
    private let thread = pthread_self()
    private let lock = NSRecursiveLock()
    private var verify: (@Sendable () throws -> Void)?

    fileprivate init(inventory: MachineUpdateHealthInventory, verify: @escaping @Sendable () throws -> Void) {
        self.inventory = inventory
        self.verify = verify
    }

    func validate() throws {
        guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard let verify else { throw JournalLeaseError.invalidated }
            do { try verify() }
            catch { self.verify = nil; throw error }
        }
    }

    var isExpired: Bool { lock.withLock { verify == nil } }

    fileprivate func expire() {
        lock.withLock { verify = nil }
    }
}

/// Checks the exact retained cohort while the restart owner keeps the original admission drain closed.
actor MachineUpdateRestartHealthCoordinator {
    private enum Phase { case new, checking, verified, failed, closing, closed }
    private let inventory: MachineUpdateHealthInventory
    private let verifyCurrent: @Sendable () throws -> Void
    private let makeAccount: @Sendable (Data, [MachineUpdateHealthInventory.Requirement]) async throws -> any OwnedMachineUpdateRestartAccount
    private let recoverOrdinary: @Sendable (Data) async throws -> Void
    private let installedActivity: (any OwnedReleaseActivity)?
    private var activityReleased = false
    private var installedScopeClaimed = false
    private var phase = Phase.new
    private var accounts: [any OwnedMachineUpdateRestartAccount] = []
    private var attemptedRecovery: Set<Data> = []
    private var recoveryCompleted = false
    private var operation: Task<Void, Error>?
    private var settlement: Task<Void, Error>?

    init(inventory: MachineUpdateHealthInventory, verifyCurrent: @escaping @Sendable () throws -> Void,
        makeAccount: @escaping @Sendable (Data, [MachineUpdateHealthInventory.Requirement]) async throws -> any OwnedMachineUpdateRestartAccount,
        recoverOrdinary: @escaping @Sendable (Data) async throws -> Void) {
        self.inventory = inventory
        self.installedActivity = nil
        self.verifyCurrent = verifyCurrent
        self.makeAccount = makeAccount
        self.recoverOrdinary = recoverOrdinary
    }

    init(plan: MachineUpdateInstalledReadinessPlan, candidate: SignedReleaseEvidence,
        terminal: MachineUpdateInstalledTerminalReadBridge, activity: any OwnedReleaseActivity,
        makeAccount: @escaping @Sendable (Data, [MachineUpdateHealthInventory.Requirement]) async throws -> any OwnedMachineUpdateInstalledReadinessAccount) throws {
        try terminal.requirePlan(plan, candidate: candidate)
        inventory = plan.inventory
        installedActivity = activity
        verifyCurrent = {
            try activity.validate()
            try terminal.requireCurrent()
            try activity.validate()
        }
        self.makeAccount = { try await makeAccount($0, $1) }
        recoverOrdinary = { _ in throw MachineUpdateHealthCoordinatorError.installedGatewayRecoveryRequired }
    }

    func check() async throws {
        guard phase == .new else { throw MachineUpdateHealthCoordinatorError.busy }
        phase = .checking
        recoveryCompleted = false
        let recoveryCount = attemptedRecovery.count
        let task = Task { try await checkAttempt() }
        operation = task
        defer { operation = nil }
        do {
            try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
            try Task.checkCancellation()
            guard phase == .checking else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
            phase = .verified
        } catch MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired {
            if phase == .checking, recoveryCompleted {
                phase = .new
                throw MachineUpdateHealthCoordinatorError.recoveryCompletedNeedsFreshCheck
            }
            if phase == .checking { phase = .failed }
            throw MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired
        } catch MachineUpdateHealthSourceError.busy {
            if phase == .checking {
                phase = accounts.isEmpty && attemptedRecovery.count == recoveryCount ? .new : .failed
            }
            throw MachineUpdateHealthSourceError.busy
        } catch {
            if phase == .checking { phase = .failed }
            throw error
        }
    }

    private func checkAttempt() async throws {
        do {
            if installedActivity != nil {
                try await performInstalledChecks()
            } else {
                try await performChecks()
            }
            try requireChecking()
            try validateAccounts()
        } catch MachineUpdateHealthSourceError.busy {
            // A partial collection has one-use challenges. Close it before a fresh attempt.
            try await settleAccounts()
            throw MachineUpdateHealthSourceError.busy
        }
    }

    private func requireChecking() throws {
        try Task.checkCancellation()
        guard phase == .checking else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
        try verifyCurrent()
    }

    private func performChecks() async throws {
        for accountID in inventory.accountIDs {
            try requireChecking()
            let required = inventory.requirements(accountID: accountID)
            let owner = try await makeAccount(accountID, required)
            // Keep even a mismatched or cancelled factory result until it has actually closed.
            accounts.append(owner)
            try requireChecking()
            guard owner.accountID == accountID else { throw MachineUpdateHealthCoordinatorError.invalidInventory }
            let replies: [MachineUpdateAuthenticatedRoleReply]
            if required.contains(where: { $0.role == .notificationGateway }) {
                replies = try await MachineUpdateGatewayHealthRecovery.check(health: { try await owner.check() },
                    verifyRecovery: verifyCurrent, recoverOrdinary: { try await self.recoverGateway(accountID) })
            } else {
                replies = try await owner.check()
            }
            try requireChecking()
            try inventory.requireReplies(replies, accountID: accountID)
            try owner.validate()
        }
    }

    private func performInstalledChecks() async throws {
        try requireChecking()
        guard inventory.accountIDs.count + inventory.preservedAccounts.count <= 64 else {
            throw MachineUpdateHealthCoordinatorError.invalidInventory
        }
        try await withThrowingTaskGroup(of: Void.self) { group in
            for accountID in inventory.accountIDs {
                group.addTask { try await self.checkInstalledAccount(accountID) }
            }
            for try await _ in group {}
        }
    }

    private func checkInstalledAccount(_ accountID: Data) async throws {
        try requireChecking()
        let requirements = inventory.requirements(accountID: accountID)
        let owner = try await makeAccount(accountID, requirements)
        guard !accounts.contains(where: { $0 === owner }) else { throw MachineUpdateHealthCoordinatorError.duplicateOwner }
        // Keep a late or invalid owner until the task group joins and settlement closes it.
        accounts.append(owner)
        try requireChecking()
        guard let installed = owner as? any OwnedMachineUpdateInstalledReadinessAccount,
              installed.accountID == accountID else { throw MachineUpdateHealthCoordinatorError.invalidInventory }
        try installed.validateOrdinaryReadiness()
        let replies: [MachineUpdateAuthenticatedRoleReply]
        do { replies = try await installed.check() }
        catch MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired {
            throw MachineUpdateHealthCoordinatorError.installedGatewayRecoveryRequired
        }
        try requireChecking()
        try inventory.requireReplies(replies, accountID: accountID)
        try Self.validateInstalled(installed)
    }

    private static func validateInstalled(_ owner: any OwnedMachineUpdateRestartAccount) throws {
        guard let installed = owner as? any OwnedMachineUpdateInstalledReadinessAccount else {
            throw MachineUpdateHealthCoordinatorError.invalidInventory
        }
        try installed.validateOrdinaryReadiness()
        try installed.validate()
        try installed.validateOrdinaryReadiness()
    }

    /// The installed cohort can lend its proof once. The scope expires before cleanup begins.
    func withVerifiedInstalledReadiness<Value: Sendable>(joinCleanup: Bool = true,
        _ body: @Sendable (MachineUpdateVerifiedInstalledReadinessScope) throws -> Value
    ) async throws -> Value {
        guard installedActivity != nil, phase == .new, !installedScopeClaimed else {
            throw MachineUpdateHealthCoordinatorError.busy
        }
        installedScopeClaimed = true
        let result: Result<Value, Error>
        do {
            try await check()
            guard phase == .verified else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
            let owners = accounts, verify = verifyCurrent
            let scope = MachineUpdateVerifiedInstalledReadinessScope(inventory: inventory, verify: {
                try Task.checkCancellation()
                try verify()
                for owner in owners { try Self.validateInstalled(owner) }
                try verify()
                try Task.checkCancellation()
            })
            defer { scope.expire() }
            try scope.validate()
            let value = try body(scope)
            try scope.validate()
            result = .success(value)
        } catch { result = .failure(error) }
        if joinCleanup { try await close() }
        return try result.get()
    }

    /// Revalidate the live owners before the machine advances its restart phase.
    func requireVerified() throws {
        guard installedActivity == nil, phase == .verified else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
        do { try validateAccounts() }
        catch MachineUpdateHealthSourceError.busy { throw MachineUpdateHealthSourceError.busy }
        catch { phase = .failed; throw error }
    }

    private func validateAccounts() throws {
        try Task.checkCancellation(); try verifyCurrent()
        let accountIDs = accounts.map(\.accountID)
        if installedActivity != nil {
            guard accountIDs.count == inventory.accountIDs.count, Set(accountIDs) == Set(inventory.accountIDs) else {
                throw MachineUpdateHealthCoordinatorError.incompleteHealth
            }
            for account in accounts { try Self.validateInstalled(account) }
        } else {
            guard accountIDs == inventory.accountIDs else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
            for account in accounts { try account.validate() }
        }
        try verifyCurrent(); try Task.checkCancellation()
    }

    private func recoverGateway(_ accountID: Data) async throws {
        try requireChecking()
        guard !attemptedRecovery.contains(accountID) else {
            throw MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired
        }
        try await settleAccounts()
        try requireChecking()
        attemptedRecovery.insert(accountID)
        do {
            try await recoverOrdinary(accountID)
        } catch {
            // A failed writer may have changed durable state. This coordinator cannot replay it.
            if phase == .checking { phase = .failed }
            throw error
        }
        try requireChecking()
        recoveryCompleted = true
    }

    private func settleAccounts() async throws {
        while let account = accounts.last {
            try await account.close()
            accounts.removeLast()
        }
    }

    func close() async throws {
        if phase == .closed { return }
        let task: Task<Void, Error>
        if let settlement { task = settlement }
        else {
            phase = .closing
            let running = operation; running?.cancel()
            task = Task { _ = try? await running?.value; try await settleAccounts() }
            settlement = task
        }
        do {
            try await task.value
            if settlement == task {
                phase = .closed; settlement = nil
                if !activityReleased {
                    activityReleased = true
                    installedActivity?.close()
                }
            }
        } catch {
            if settlement == task { settlement = nil }
            throw error
        }
    }

    deinit {
        guard let installedActivity, !activityReleased else { return }
        let retained = accounts
        Task {
            for owner in retained.reversed() {
                while (try? await owner.close()) == nil {
                    try? await Task.sleep(for: .milliseconds(100))
                }
            }
            installedActivity.close()
        }
    }
}
