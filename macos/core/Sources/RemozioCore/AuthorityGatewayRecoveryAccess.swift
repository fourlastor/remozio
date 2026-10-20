import Foundation
import Synchronization

/// Binds one recovery coordinator to the existing Root service and short protected reads.
/// Native operations own their release activity. No machine writer survives an asynchronous operation here.
final class AuthorityGatewayRecoveryAccess: Sendable {
    struct Operations: Sendable {
        let verifyCurrent: @Sendable () throws -> Void
        let capture: @Sendable (Data) throws -> AuthorityGatewayRecoverySnapshot
        let verify: @Sendable (AuthorityGatewayRecoverySnapshot) throws -> Void
        let publish: @Sendable (AuthorityGatewayRecoverySnapshot, AuthorityPhonePushRecoveryTicket) throws -> Void
        let control: @Sendable (AuthorityGatewayRecoverySnapshot, GatewaySettingsConsumerRole,
                                GatewaySettingsControlAction, UUID?) async throws -> GatewaySettingsConsumerResponse
        let observe: @Sendable (AuthorityGatewayRecoverySnapshot, GatewaySettingsConsumerRole) async throws -> GatewaySettingsConsumerBinding
        let remove: @Sendable (AuthorityGatewayRecoverySnapshot, AuthorityPhonePushRecoveryTicket,
                               GatewaySettingsRecoveryAcceptance) throws -> Void
    }
    private struct State {
        var snapshot: AuthorityGatewayRecoverySnapshot?
        var ticket: AuthorityPhonePushRecoveryTicket?
        var coordinatorCreated = false
    }
    private let service: AuthorityWakeService
    private let binding: GatewaySettingsControlBinding
    private let operations: Operations
    private let state = Mutex(State())

    init(service: AuthorityWakeService, operations: Operations) throws {
        guard let binding = service.gatewaySettingsBinding else { throw GatewayPreparationError.incomplete }
        self.service = service; self.binding = binding; self.operations = operations
    }
    func makeCoordinator() throws -> GatewaySettingsRecoveryCoordinator {
        try state.withLock {
            guard !$0.coordinatorCreated else { throw GatewayPreparationError.changedScope }
            $0.coordinatorCreated = true
        }
        return .init(operations: .init(verifyCurrent: { [self] in try verifyIdentity() },
            verifyPlan: { [self] plan in _ = try snapshot(for: plan) },
            pause: { [self] plan in try await pause(plan) },
            plan: { [self] id in
                try verifyIdentity()
                let captured = try operations.capture(id)
                guard captured.plan.fence.recoveryAttemptID == id else { throw GatewayPreparationError.changedScope }
                try verify(captured)
                state.withLock { $0.snapshot = captured; $0.ticket = nil }
                return captured.plan
            }, publish: { [self] plan in
                let (snapshot, ticket) = try paused(plan)
                try operations.publish(snapshot, ticket)
                _ = try paused(plan)
            }, control: { [self] plan, role, action, generation in
                let current = try snapshot(for: plan)
                let response = try await operations.control(current, role, action, generation)
                _ = try snapshot(for: plan)
                return response
            }, observe: { [self] role in
                guard let current = state.withLock({ $0.snapshot }) else { throw GatewayPreparationError.incomplete }
                try verify(current)
                let binding = try await operations.observe(current, role)
                _ = try snapshot(for: current.plan)
                return binding
            }, remove: { [self] plan, proof in
                let (snapshot, ticket) = try paused(plan)
                try proof.requireValid(for: plan)
                try operations.remove(snapshot, ticket, proof)
                try proof.requireValid(for: plan); _ = try paused(plan)
            }, resume: { [self] plan, proof in
                let (_, ticket) = try paused(plan)
                try await service.resumePhonePushRecovery(ticket, verifyCurrent: { [self] in
                    try proof.requireValid(for: plan)
                    let (_, current) = try paused(plan)
                    guard current === ticket else { throw GatewayPreparationError.changedScope }
                })
                try proof.requireValid(for: plan); _ = try snapshot(for: plan)
            }))
    }
    private func verifyIdentity() throws {
        guard service.gatewaySettingsBinding == binding else { throw GatewayPreparationError.changedScope }
        try operations.verifyCurrent()
    }
    private func verify(_ snapshot: AuthorityGatewayRecoverySnapshot) throws {
        try verifyIdentity()
        guard snapshot.account.accountID == binding.accountID,
              snapshot.plan.fence.accountID == binding.accountID else { throw GatewayPreparationError.changedScope }
        try operations.verify(snapshot); try verifyIdentity()
    }
    private func snapshot(for plan: GatewayRuntimeSettingsRecoveryPlan) throws -> AuthorityGatewayRecoverySnapshot {
        guard let current = state.withLock({ $0.snapshot }),
              try current.plan.fence.encoded == plan.fence.encoded else { throw GatewayPreparationError.changedScope }
        try verify(current)
        return current
    }
    private func paused(_ plan: GatewayRuntimeSettingsRecoveryPlan) throws -> (AuthorityGatewayRecoverySnapshot, AuthorityPhonePushRecoveryTicket) {
        let snapshot = try snapshot(for: plan)
        guard let ticket = state.withLock({ $0.ticket }),
              try ticket.commitDigest == plan.commit.observationDigest else { throw GatewayPreparationError.changedScope }
        try ticket.requireValid()
        return (snapshot, ticket)
    }
    private func pause(_ plan: GatewayRuntimeSettingsRecoveryPlan) async throws {
        try verifyIdentity()
        // Cleanup must stop only its captured floor, even when the private settings scope has advanced.
        let ticket = try await service.quiescePhonePushRecovery(commitDigest: plan.commit.observationDigest,
            verifyCurrent: { [self] in try verifyIdentity() })
        try ticket.requireValid(); try verifyIdentity()
        let digest = try plan.fence.encoded
        try state.withLock {
            if let snapshot = $0.snapshot, try snapshot.plan.fence.encoded == digest { $0.ticket = ticket }
        }
    }
}
