import Foundation

/// One account owns its Authority, consumer channels, and any paired Gateway reader until joined close.
protocol OwnedMachineUpdateRestartAccount: AnyObject, Sendable {
    var accountID: Data { get }
    func check() async throws -> [MachineUpdateAuthenticatedRoleReply]
    func validate() throws
    func close() async throws
}

/// Checks the exact retained cohort while the restart owner keeps the original admission drain closed.
actor MachineUpdateRestartHealthCoordinator {
    private enum Phase { case new, checking, verified, failed, closing, closed }
    private let inventory: MachineUpdateHealthInventory
    private let verifyCurrent: @Sendable () throws -> Void
    private let makeAccount: @Sendable (Data, [MachineUpdateHealthInventory.Requirement]) async throws -> any OwnedMachineUpdateRestartAccount
    private let recoverOrdinary: @Sendable (Data) async throws -> Void
    private var phase = Phase.new
    private var accounts: [any OwnedMachineUpdateRestartAccount] = []
    private var operation: Task<Void, Error>?
    private var settlement: Task<Void, Error>?

    /// The native caller supplies the original drain, protected account owners, and the ordinary recovery operation.
    init(snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        activity: MachineUpdateRestartSharedActivity,
        verifyCurrent: @escaping @Sendable () throws -> Void,
        makeAccount: @escaping @Sendable (Data, [MachineUpdateHealthInventory.Requirement]) async throws -> any OwnedMachineUpdateRestartAccount,
        recoverOrdinary: @escaping @Sendable (Data) async throws -> Void) throws {
        let context = snapshot.source.replacement
        let macID = context.inventory.macID
        let installationID = context.inventory.installationID
        let attempt = context.activation.attemptID
        let verifyScope: @Sendable () throws -> Void = {
            try activity.requireScope(macID: macID, installationID: installationID, activationAttempt: attempt)
            try verifyCurrent()
            try activity.requireScope(macID: macID, installationID: installationID, activationAttempt: attempt)
        }
        try verifyScope()
        try self.init(inventory: .init(plan: MachineUpdateRestartHealthPlan(snapshot: snapshot, candidate: candidate)),
            verifyCurrent: verifyScope, makeAccount: makeAccount, recoverOrdinary: recoverOrdinary)
    }

    init(inventory: MachineUpdateHealthInventory, verifyCurrent: @escaping @Sendable () throws -> Void,
        makeAccount: @escaping @Sendable (Data, [MachineUpdateHealthInventory.Requirement]) async throws -> any OwnedMachineUpdateRestartAccount,
        recoverOrdinary: @escaping @Sendable (Data) async throws -> Void) {
        self.inventory = inventory; self.verifyCurrent = verifyCurrent
        self.makeAccount = makeAccount; self.recoverOrdinary = recoverOrdinary
    }

    func check() async throws {
        guard phase == .new else { throw MachineUpdateHealthCoordinatorError.busy }
        phase = .checking
        let task = Task { try await checkAttempt() }
        operation = task
        defer { operation = nil }
        do {
            try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
            try Task.checkCancellation()
            guard phase == .checking else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
            phase = .verified
        } catch MachineUpdateHealthSourceError.busy {
            if phase == .checking { phase = accounts.isEmpty ? .new : .failed }
            throw MachineUpdateHealthSourceError.busy
        } catch {
            if phase == .checking { phase = .failed }
            throw error
        }
    }

    private func checkAttempt() async throws {
        do {
            try await performChecks()
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
                let verify = verifyCurrent, recover = recoverOrdinary
                replies = try await MachineUpdateGatewayHealthRecovery.check(health: { try await owner.check() },
                    verifyRecovery: verify, recoverOrdinary: {
                        try await self.settleBeforeRecovery()
                        try Task.checkCancellation(); try verify()
                        try await recover(accountID)
                    })
            } else {
                replies = try await owner.check()
            }
            try requireChecking()
            try inventory.requireReplies(replies, accountID: accountID)
            try owner.validate()
        }
    }

    /// Revalidate the live owners before the machine advances its restart phase.
    func requireVerified() throws {
        guard phase == .verified else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
        do { try validateAccounts() }
        catch MachineUpdateHealthSourceError.busy { throw MachineUpdateHealthSourceError.busy }
        catch { phase = .failed; throw error }
    }

    private func validateAccounts() throws {
        try Task.checkCancellation(); try verifyCurrent()
        guard accounts.map(\.accountID) == inventory.accountIDs else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
        for account in accounts { try account.validate() }
        try verifyCurrent(); try Task.checkCancellation()
    }

    private func settleBeforeRecovery() async throws {
        try requireChecking()
        try await settleAccounts()
        try requireChecking()
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
            if settlement == task { phase = .closed; settlement = nil }
        } catch {
            if settlement == task { settlement = nil }
            throw error
        }
    }
}
