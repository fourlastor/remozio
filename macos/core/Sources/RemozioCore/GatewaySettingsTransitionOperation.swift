import CryptoKit
import Darwin
import Foundation
import Synchronization

/// Fresh process evidence for one exact transition. Storage records cannot reconstruct this value.
final class GatewaySettingsTransitionBarrier: Sendable {
    enum Phase { case quiesced, accepted }
    let root: GatewaySettingsControlBinding
    let consumers: [GatewaySettingsConsumerBinding]
    private let phase: Phase
    private let digest: Data
    private let processID = getpid()
    private let valid = Mutex(true)
    fileprivate init(plan: GatewayRuntimeSettingsPublicationPlan, root: GatewaySettingsControlBinding,
                     consumers: [GatewaySettingsConsumerBinding], phase: Phase) throws {
        let fence = try GatewayRuntimeSettingsFence(plan)
        guard root.accountID == fence.accountID, consumers.map(\.role) == GatewaySettingsConsumerRole.allCases,
              consumers.allSatisfy({ $0.macID == fence.macID && $0.accountID == fence.accountID }) else {
            throw GatewayPreparationError.changedScope
        }
        self.root = root; self.consumers = consumers; self.phase = phase
        digest = Data(SHA256.hash(data: try fence.encoded))
    }
    fileprivate func revoke() { valid.withLock { $0 = false } }
    func requireValid(for plan: GatewayRuntimeSettingsPublicationPlan, phase: Phase) throws {
        guard getpid() == processID, valid.withLock({ $0 }), self.phase == phase,
              digest == Data(SHA256.hash(data: try GatewayRuntimeSettingsFence(plan).encoded)) else {
            throw GatewayPreparationError.changedScope
        }
    }
}

/// The authorized setup owner serializes admission and closes each machine scope before native exchanges.
/// An uncertain result requires a fresh protected read. This operation never retries or rolls back implicitly.
enum GatewaySettingsTransitionOperation {
    struct Operations: Sendable {
        let verifyPending: @Sendable (GatewayRuntimeSettingsPublicationPlan) throws -> Void
        let verifyComplete: @Sendable (GatewayRuntimeSettingsPublicationPlan) throws -> Void
        let root: @Sendable (GatewayRuntimeSettingsPublicationPlan, GatewaySettingsControlAction, UUID?) async throws -> GatewaySettingsControlResponse
        let publishFence: @Sendable (GatewayRuntimeSettingsPublicationPlan) throws -> Void
        let consumer: @Sendable (GatewayRuntimeSettingsPublicationPlan, GatewaySettingsConsumerRole,
                                 GatewaySettingsControlAction, UUID?) async throws -> GatewaySettingsConsumerResponse
        let observe: @Sendable (GatewaySettingsConsumerRole) async throws -> GatewaySettingsConsumerBinding
        let mark: @Sendable (GatewayRuntimeSettingsPublicationPlan, GatewayRuntimeSettingsPhase) throws -> Void
        let publish: @Sendable (GatewayRuntimeSettingsPublicationPlan, GatewaySettingsTransitionBarrier) throws -> Void
        let complete: @Sendable (GatewayRuntimeSettingsPublicationPlan, GatewaySettingsTransitionBarrier) throws -> Void
        let removeFence: @Sendable (GatewayRuntimeSettingsPublicationPlan, GatewaySettingsTransitionBarrier) throws -> Void
    }
    struct Result: Sendable {
        let root: GatewaySettingsControlBinding
        let consumers: [GatewaySettingsConsumerBinding]
        let observation: GatewaySettingsControlObservation
    }
    /// Saved phases never skip fresh barriers. Completed revisions use the separate restart recovery path.
    static func resume(_ plan: GatewayRuntimeSettingsPublicationPlan, operations: Operations) async throws -> Result {
        let fence = try GatewayRuntimeSettingsFence(plan), change = try AuthorityPhonePushSettingsChange(plan)
        func verify(completed: Bool = false) throws {
            try Task.checkCancellation()
            if completed { try operations.verifyComplete(plan) } else { try operations.verifyPending(plan) }
        }
        func root(_ action: GatewaySettingsControlAction, expected: GatewaySettingsControlBinding?,
                  completed: Bool = false) async throws -> GatewaySettingsControlResponse {
            try verify(completed: completed)
            let result = try await operations.root(plan, action, expected?.rootEpoch)
            try verify(completed: completed)
            guard result.request.action == action, result.request.change == change,
                  result.request.binding.accountID == fence.accountID,
                  expected == nil || result.request.binding == expected else { throw GatewayPreparationError.changedScope }
            if action == .accept {
                guard result.observation == .accepted || result.observation == .providerInstalled else {
                    throw GatewayPreparationError.changedScope
                }
            } else if result.observation != .suspended { throw GatewayPreparationError.changedScope }
            return result
        }
        func consumer(_ role: GatewaySettingsConsumerRole, _ action: GatewaySettingsControlAction,
                      expected: GatewaySettingsConsumerBinding?) async throws -> GatewaySettingsConsumerBinding {
            try verify()
            let result = try await operations.consumer(plan, role, action, expected?.generation)
            try verify()
            let request = result.request, binding = request.binding
            guard request.action == action, binding.role == role, expected == nil || binding == expected else {
                throw GatewayPreparationError.changedScope
            }
            try request.validate(binding: binding, fence: fence)
            guard action == .quiesce ? result.observation == .paused :
                result.observation == .accepted || result.observation == .runtimeStarted else { throw GatewayPreparationError.changedScope }
            return binding
        }
        func observe(_ expected: [GatewaySettingsConsumerBinding], completed: Bool = false) async throws {
            for binding in expected {
                try verify(completed: completed)
                let current = try await operations.observe(binding.role)
                try verify(completed: completed)
                guard current == binding else { throw GatewayPreparationError.changedScope }
            }
        }
        try verify()
        let paused = try await root(.quiesce, expected: nil).request.binding
        try operations.publishFence(plan); try verify()
        var bindings: [GatewaySettingsConsumerBinding] = []
        for role in GatewaySettingsConsumerRole.allCases {
            bindings.append(try await consumer(role, .quiesce, expected: nil))
        }
        _ = try await root(.observe, expected: paused); try await observe(bindings)
        let quiescence = try GatewaySettingsTransitionBarrier(plan: plan, root: paused, consumers: bindings, phase: .quiesced)
        defer { quiescence.revoke() }
        try verify(); try quiescence.requireValid(for: plan, phase: .quiesced)
        try operations.mark(plan, .quiesced); try verify()
        try operations.publish(plan, quiescence); try verify()
        try operations.mark(plan, .filesPublished); try verify()
        for binding in bindings { _ = try await consumer(binding.role, .accept, expected: binding) }
        try await observe(bindings); _ = try await root(.observe, expected: paused)
        let acceptance = try GatewaySettingsTransitionBarrier(plan: plan, root: paused, consumers: bindings, phase: .accepted)
        defer { acceptance.revoke() }
        try verify(); try acceptance.requireValid(for: plan, phase: .accepted)
        try operations.mark(plan, .consumersObserved); try verify()
        try operations.complete(plan, acceptance); try verify(completed: true)
        try await observe(bindings, completed: true); _ = try await root(.observe, expected: paused, completed: true)
        try acceptance.requireValid(for: plan, phase: .accepted)
        try operations.removeFence(plan, acceptance); try verify(completed: true)
        let result = try await root(.accept, expected: paused, completed: true)
        return .init(root: paused, consumers: bindings, observation: result.observation)
    }
}
