import CryptoKit
import Darwin
import Foundation
import Security
import Synchronization

/// Process-local evidence from a fresh two-consumer barrier. It is neither serializable nor delivery readiness.
final class GatewaySettingsRecoveryAcceptance: Sendable {
    private let valid = Mutex(true)
    private let processID = getpid()
    private let fenceDigest: Data
    let bindings: [GatewaySettingsConsumerBinding]
    fileprivate init(plan: GatewayRuntimeSettingsRecoveryPlan, bindings: [GatewaySettingsConsumerBinding]) throws {
        guard bindings.count == 2, bindings.map(\.role) == GatewaySettingsConsumerRole.allCases,
              bindings.allSatisfy({ $0.macID == plan.fence.macID && $0.accountID == plan.fence.accountID }) else {
            throw GatewayPreparationError.changedScope
        }
        self.bindings = bindings; fenceDigest = Data(SHA256.hash(data: try plan.fence.encoded))
    }
    fileprivate func revoke() { valid.withLock { $0 = false } }
    func requireValid(for plan: GatewayRuntimeSettingsRecoveryPlan) throws {
        guard processID == getpid(), valid.withLock({ $0 }),
              fenceDigest == Data(SHA256.hash(data: try plan.fence.encoded)) else { throw GatewayPreparationError.changedScope }
    }
}

/// Recover the same completed commit after Root or either companion restarts. Foreground service ownership stays separate.
actor GatewaySettingsRecoveryCoordinator {
    struct Operations: Sendable {
        let verifyCurrent: @Sendable () throws -> Void
        let verifyPlan: @Sendable (GatewayRuntimeSettingsRecoveryPlan) throws -> Void
        let pause: @Sendable (GatewayRuntimeSettingsRecoveryPlan) async throws -> Void
        let plan: @Sendable (Data) throws -> GatewayRuntimeSettingsRecoveryPlan
        let publish: @Sendable (GatewayRuntimeSettingsRecoveryPlan) throws -> Void
        let control: @Sendable (GatewayRuntimeSettingsRecoveryPlan, GatewaySettingsConsumerRole,
                                GatewaySettingsControlAction, UUID?) async throws -> GatewaySettingsConsumerResponse
        let observe: @Sendable (GatewaySettingsConsumerRole) async throws -> GatewaySettingsConsumerBinding
        let remove: @Sendable (GatewayRuntimeSettingsRecoveryPlan, GatewaySettingsRecoveryAcceptance) throws -> Void
        let resume: @Sendable (GatewayRuntimeSettingsRecoveryPlan, GatewaySettingsRecoveryAcceptance) async throws -> Void
    }
    private let operations: Operations
    private let attemptID: @Sendable () throws -> Data
    private var acceptedPlan: GatewayRuntimeSettingsRecoveryPlan?
    private var admittedPlan: GatewayRuntimeSettingsRecoveryPlan?
    private var acceptance: GatewaySettingsRecoveryAcceptance?
    private var work: (id: UUID, task: Task<Bool, any Error>)?
    private var closing: Task<Void, Never>?
    private var closed = false

    init(operations: Operations, attemptID: @escaping @Sendable () throws -> Data = randomAttemptID) {
        self.operations = operations; self.attemptID = attemptID
    }
    deinit {
        acceptance?.revoke()
        let pending = work?.task, operations = operations, admitted = admittedPlan, accepted = acceptedPlan
        let plan = admitted ?? accepted
        pending?.cancel()
        Task { _ = try? await pending?.value; if let plan { try? await operations.pause(plan) } }
    }
    /// True means the scope has fresh consumer acceptance. It makes no claim about provider delivery.
    func refresh() async throws -> Bool {
        guard !closed else { throw GatewayPreparationError.changedScope }
        guard work == nil else { return false }
        let pending = (id: UUID(), task: Task { try await self.refreshOwned() })
        work = pending
        do {
            let result = try await withTaskCancellationHandler { try await pending.task.value } onCancel: { pending.task.cancel() }
            if work?.id == pending.id { work = nil }
            return result
        } catch {
            if work?.id == pending.id { work = nil }
            throw error
        }
    }
    func close() async {
        if let closing { await closing.value; return }
        let plan = admittedPlan ?? acceptedPlan
        closed = true; revoke()
        let pending = work?.task, operations = operations
        pending?.cancel()
        let cleanup = Task { _ = try? await pending?.value; if let plan { try? await operations.pause(plan) } }
        closing = cleanup; await cleanup.value
    }
    private func revoke() { acceptance?.revoke(); acceptance = nil; acceptedPlan = nil }
    private func verify(_ plan: GatewayRuntimeSettingsRecoveryPlan? = nil) throws {
        guard !closed else { throw GatewayPreparationError.changedScope }
        try Task.checkCancellation(); try operations.verifyCurrent()
        if let plan { try operations.verifyPlan(plan) }
    }
    private func observed(_ plan: GatewayRuntimeSettingsRecoveryPlan) async throws -> [GatewaySettingsConsumerBinding] {
        var result: [GatewaySettingsConsumerBinding] = []
        for role in GatewaySettingsConsumerRole.allCases {
            try verify(plan)
            let value = try await operations.observe(role)
            try verify(plan)
            guard value.role == role, value.macID == plan.fence.macID, value.accountID == plan.fence.accountID else {
                throw GatewayPreparationError.changedScope
            }
            result.append(value)
        }
        return result
    }
    private func control(_ plan: GatewayRuntimeSettingsRecoveryPlan, role: GatewaySettingsConsumerRole,
                         action: GatewaySettingsControlAction, expected: GatewaySettingsConsumerBinding?) async throws -> GatewaySettingsConsumerBinding {
        try verify(plan)
        let response = try await operations.control(plan, role, action, expected?.generation)
        try verify(plan)
        let request = response.request, binding = request.binding
        guard request.action == action, binding.role == role, expected == nil || binding == expected else {
            throw GatewayPreparationError.changedScope
        }
        try request.validate(binding: binding, fence: plan.fence)
        guard action == .quiesce ? response.observation == .paused :
            response.observation == .accepted || response.observation == .runtimeStarted else { throw GatewayPreparationError.changedScope }
        return binding
    }
    private func refreshOwned() async throws -> Bool {
        admittedPlan = acceptedPlan
        do {
            try verify()
            if let plan = acceptedPlan, let acceptance {
                do {
                    try acceptance.requireValid(for: plan)
                    guard try await observed(plan) == acceptance.bindings else { throw GatewayPreparationError.changedScope }
                    admittedPlan = nil; return true
                } catch { try Task.checkCancellation(); revoke() }
            }
            let id = try attemptID()
            guard id.count == 16 else { throw GatewayPreparationError.invalidRecord }
            let plan = try operations.plan(id)
            guard plan.fence.recoveryAttemptID == id else { throw GatewayPreparationError.changedScope }
            try verify(plan); admittedPlan = plan
            try await operations.pause(plan); try verify(plan)
            try operations.publish(plan); try verify(plan)
            var bindings: [GatewaySettingsConsumerBinding] = []
            for role in GatewaySettingsConsumerRole.allCases {
                bindings.append(try await control(plan, role: role, action: .quiesce, expected: nil))
            }
            for binding in bindings { _ = try await control(plan, role: binding.role, action: .accept, expected: binding) }
            guard try await observed(plan) == bindings else { throw GatewayPreparationError.changedScope }
            let proof = try GatewaySettingsRecoveryAcceptance(plan: plan, bindings: bindings)
            acceptance = proof
            try verify(plan); try proof.requireValid(for: plan); try operations.remove(plan, proof); try verify(plan)
            try await operations.resume(plan, proof); try verify(plan)
            guard try await observed(plan) == bindings else { throw GatewayPreparationError.changedScope }
            try proof.requireValid(for: plan); acceptedPlan = plan; admittedPlan = nil
            return true
        } catch {
            let plan = admittedPlan ?? acceptedPlan
            revoke(); admittedPlan = nil
            // Cleanup cannot substitute a newer scope after an authorized settings takeover.
            let operations = operations
            if let plan {
                let pause = Task { try? await operations.pause(plan) }
                await pause.value
            }
            try Task.checkCancellation()
            return false
        }
    }
    private static func randomAttemptID() throws -> Data {
        var bytes = Data(count: 16)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else {
            throw GatewayPreparationError.invalidRecord
        }
        return bytes
    }
}
