import Foundation

/// Owns recovery across protected settings observations. Foreground requests remain owned by AuthorityWakeService.
actor AuthorityGatewayRecoverySupervisor {
    struct Operations: Sendable {
        let status: @Sendable () throws -> AuthorityGatewayRecoverySnapshot.Status
        let makeCoordinator: @Sendable () throws -> GatewaySettingsRecoveryCoordinator
    }
    private let operations: Operations
    private var coordinator: GatewaySettingsRecoveryCoordinator?
    private var completedObserved = false
    private var work: (id: UUID, task: Task<Bool, any Error>)?
    private var closing: Task<Void, Never>?
    private var closed = false

    init(operations: Operations) { self.operations = operations }
    deinit {
        let pending = work?.task, coordinator = coordinator
        pending?.cancel()
        Task { _ = try? await pending?.value; await coordinator?.close() }
    }
    /// Initial activation uses its existing path. Completed settings require fresh acceptance from both consumers.
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
        closed = true
        let pending = work?.task, current = coordinator
        pending?.cancel()
        let cleanup = Task { _ = try? await pending?.value; await current?.close() }
        closing = cleanup; await cleanup.value
        coordinator = nil
    }
    private func refreshOwned() async throws -> Bool {
        do {
            try Task.checkCancellation()
            guard !closed else { throw GatewayPreparationError.changedScope }
            switch try operations.status() {
            case .initial:
                guard !completedObserved else { throw GatewayPreparationError.changedScope }
                return true
            case .pending:
                let current = coordinator; coordinator = nil
                await current?.close()
                try Task.checkCancellation()
                return false
            case .completed:
                completedObserved = true
                if coordinator == nil { coordinator = try operations.makeCoordinator() }
                guard let current = coordinator else { throw GatewayPreparationError.incomplete }
                let accepted = try await current.refresh()
                try Task.checkCancellation()
                guard !closed else { throw GatewayPreparationError.changedScope }
                return accepted
            }
        } catch {
            let current = coordinator; coordinator = nil
            // Joined cleanup runs outside the cancelled refresh and can only pause its captured Root floor.
            let cleanup = Task { await current?.close() }; await cleanup.value
            try Task.checkCancellation()
            throw error
        }
    }
}
