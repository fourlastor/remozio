import Darwin
import Foundation

/// Composes native restart health under the machine owner's existing admission drain.
final class MachineUpdateNativeRestartHealth: @unchecked Sendable {
    // These retained values are immutable. The machine owner serializes reads from its store.
    private let snapshot: MachineUpdateRestartSnapshot
    private let candidate: SignedReleaseEvidence
    private let plan: MachineUpdateRestartHealthPlan
    private let activity: MachineUpdateRestartSharedActivity
    private let sourceAccess: MachineUpdateHealthSourceAccess
    private let readCurrent: @Sendable (MachineUpdateRestartReadinessLoan) throws -> MachineUpdateRestartSnapshot
    private let verifyCurrent: @Sendable () throws -> Void

    static func coordinator(snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        activity: MachineUpdateRestartSharedActivity, sourceAccess: MachineUpdateHealthSourceAccess,
        readCurrent: @escaping @Sendable (MachineUpdateRestartReadinessLoan) throws -> MachineUpdateRestartSnapshot,
        verifyCurrent: @escaping @Sendable () throws -> Void,
        recoverOrdinary: @escaping @Sendable (Data) async throws -> Void) throws -> MachineUpdateRestartHealthCoordinator {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let factory = try Self(snapshot: snapshot, candidate: candidate, activity: activity, sourceAccess: sourceAccess,
            readCurrent: readCurrent, verifyCurrent: verifyCurrent)
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
        return try MachineUpdateRestartHealthCoordinator(inventory: .init(plan: factory.plan),
            verifyCurrent: verifyScope, makeAccount: { accountID, requirements in
                try factory.makeAccount(accountID, requirements: requirements)
            }, recoverOrdinary: recoverOrdinary)
    }

    private init(snapshot: MachineUpdateRestartSnapshot, candidate: SignedReleaseEvidence,
        activity: MachineUpdateRestartSharedActivity, sourceAccess: MachineUpdateHealthSourceAccess,
        readCurrent: @escaping @Sendable (MachineUpdateRestartReadinessLoan) throws -> MachineUpdateRestartSnapshot,
        verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        self.snapshot = snapshot; self.candidate = candidate; self.activity = activity; self.sourceAccess = sourceAccess
        self.readCurrent = readCurrent; self.verifyCurrent = verifyCurrent
        plan = try .init(snapshot: snapshot, candidate: candidate)
    }

    private func makeAccount(_ accountID: Data, requirements: [MachineUpdateRestartHealthPlan.Requirement]) throws
        -> MachineUpdateNativeHealthAccount {
        try verifyCurrent()
        guard let account = plan.accounts.first(where: { $0.accountID == accountID }),
              account.requirements == requirements else { throw MachineUpdateHealthCoordinatorError.invalidInventory }
        return try .init(accountID: accountID, requirements: requirements, operations: .init(
            verifyCurrent: verifyCurrent, makeAuthority: { [self] in
                try MachineUpdateAuthorityHealthOwner.openForRestart(snapshot: snapshot, candidate: candidate, accountID: accountID,
                    activity: activity, sourceAccess: sourceAccess, readCurrent: readCurrent)
            }, makeGatewayReader: { [self] in
                try MachineUpdateGatewayPairedHealthReader.openForRestart(snapshot: snapshot, candidate: candidate, accountID: accountID,
                    activity: activity, sourceAccess: sourceAccess, readCurrent: readCurrent)
            }, makeConnection: { [self] requirement, authorityChallenge in
                try await openConsumer(accountID: accountID, requirement: requirement, authorityChallenge: authorityChallenge)
            }))
    }

    private func openConsumer(accountID: Data, requirement: MachineUpdateRestartHealthPlan.Requirement,
        authorityChallenge: Data?) async throws -> MachineUpdateConsumerHealthConnectionScope {
        try Task.checkCancellation(); try verifyCurrent()
        let (account, selected) = try plan.select(accountID: accountID, role: requirement.role)
        guard selected == requirement else { throw MachineUpdateHealthCoordinatorError.changedScope }
        let input = try Self.consumerInputs(account: account, requirement: requirement)
        let verifier = MachineUpdateNativeRestartVerifier(snapshot: snapshot, host: account.configuration.host,
            sourceAccess: sourceAccess, readCurrent: readCurrent)
        let loan = try activity.acquireShared()
        let channel = try MachineUpdateConsumerHealthChannel.nativeConsumer(host: input.host, requirement: selected,
            registration: input.registration, release: candidate, purpose: .startup,
            authorityReadinessRequest: authorityChallenge,
            verifyCurrent: { [self] in try verifyCurrent(); try verifier.validate(loan) }, releaseScope: { loan.close() })
        return try await channel.openScope()
    }

    /// Value selection only. The channel still verifies the release, Root identity and consumer peer.
    static func consumerInputs(account: MachineUpdateRestartHealthPlan.Account,
        requirement: MachineUpdateRestartHealthPlan.Requirement
    ) throws -> (host: GatewaySettingsConsumerHostConfiguration, registration: GatewayRegistrationIdentity?) {
        guard account.requirements.contains(requirement) else { throw MachineUpdateHealthCoordinatorError.changedScope }
        switch requirement.role {
        case .transport:
            guard let host = account.configuration.transport.settingsHost else { throw RuntimePreparationError.incomplete }
            return (host, nil)
        case .notificationGateway:
            guard let backend = account.backend else { throw RuntimePreparationError.incomplete }
            return (account.configuration.gateway, backend.gateway.registration)
        default:
            throw MachineUpdateHealthCoordinatorError.invalidInventory
        }
    }
}
