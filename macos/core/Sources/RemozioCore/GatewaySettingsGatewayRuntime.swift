import Foundation
import Synchronization

protocol GatewaySettingsGatewayBackend: AnyObject, Sendable {
    func start() throws
    func retire()
    func close() async throws
}
extension GatewayService: GatewaySettingsGatewayBackend {}

/// Retains the real Gateway before startup and until its provider and database drain finishes.
actor GatewaySettingsGatewayRuntime: OwnedGatewaySettingsConsumerRuntime {
    private final class State: Sendable {
        struct Value { var retired = false; var backend: (any GatewaySettingsGatewayBackend)? }
        let value = Mutex(Value())
    }
    private nonisolated let state = State()
    private let verifyCurrent: @Sendable () throws -> Void
    private let open: @Sendable () async throws -> any GatewaySettingsGatewayBackend
    private var opening: Task<any GatewaySettingsGatewayBackend, Error>?
    private var closing: (id: UUID, task: Task<Void, Error>)?
    private var started = false

    init(selection: GatewaySettingsConsumerSelection, permit: GatewaySettingsConsumerPermit) throws {
        guard selection.binding.role == .gateway else { throw GatewayPreparationError.changedScope }
        verifyCurrent = {
            try permit.requireValid(binding: selection.binding, fence: selection.fence,
                configuration: selection.configuration, commit: selection.commit)
        }
        open = { try await GatewayService.openAccepted(selection: selection, permit: permit) }
    }
    init(initial: GatewaySettingsInitialPublication, verifyCurrent: @escaping @Sendable () throws -> Void) {
        self.verifyCurrent = verifyCurrent
        open = { try await GatewayService.openInitial(publication: initial, verifyCurrent: verifyCurrent) }
    }
    // Owned backends test lifetime races without native process admission or provider credentials.
    init(verifyCurrent: @escaping @Sendable () throws -> Void,
         open: @escaping @Sendable () async throws -> any GatewaySettingsGatewayBackend) {
        self.verifyCurrent = verifyCurrent; self.open = open
    }
    nonisolated func retire() {
        let backend = state.value.withLock { value in value.retired = true; return value.backend }
        backend?.retire()
    }
    func start() async throws {
        guard !started, !state.value.withLock({ $0.retired }) else { throw GatewayServiceError.unavailable }
        started = true
        let state = state, open = open, verify = verifyCurrent
        let attempt = Task<any GatewaySettingsGatewayBackend, Error> {
            try verify(); try Task.checkCancellation()
            let backend = try await open()
            let retired = state.value.withLock { value in value.backend = backend; return value.retired }
            if retired { backend.retire() }
            return backend
        }
        opening = attempt
        do {
            let backend = try await attempt.value
            try verify()
            guard !state.value.withLock({ $0.retired }) else { throw GatewayServiceError.unavailable }
            try backend.start(); try verify()
            guard !state.value.withLock({ $0.retired }) else { throw GatewayServiceError.unavailable }
        } catch { retire(); throw error }
    }
    /// A cancelled closer still joins the owned open and close tasks. Failed cleanup keeps the backend for retry.
    func closeAndWait() async throws {
        retire()
        let pending: (id: UUID, task: Task<Void, Error>)
        if let closing { pending = closing }
        else {
            let opening = opening, state = state
            pending = (UUID(), Task {
                _ = await opening?.result
                if let backend = state.value.withLock({ $0.backend }) { try await backend.close() }
            })
            closing = pending
        }
        do {
            try await pending.task.value
            if closing?.id == pending.id {
                state.value.withLock { $0.backend = nil }; opening = nil; closing = nil
            }
        } catch {
            if closing?.id == pending.id { closing = nil }
            throw error
        }
    }
    deinit {
        let state = state, opening = opening, pending = closing?.task
        let backend = state.value.withLock { value in value.retired = true; return value.backend }
        backend?.retire()
        Task {
            if let pending, (try? await pending.value) != nil { return }
            _ = await opening?.result
            while let backend = state.value.withLock({ $0.backend }) {
                do { try await backend.close(); state.value.withLock { $0.backend = nil }; return }
                catch { try? await Task.sleep(for: .milliseconds(100)) }
            }
        }
    }
}
