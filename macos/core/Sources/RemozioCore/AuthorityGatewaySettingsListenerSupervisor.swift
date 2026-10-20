import Foundation

/// Retries an optional settings listener without replacing the foreground service or its clock.
/// A failed attempt must settle all owned listener work before another attempt can start.
actor AuthorityGatewaySettingsListenerSupervisor {
    enum Status: Equatable, Sendable { case idle, starting, listening, waiting, absent, closing, closed }
    private let makeRuntime: @Sendable () -> AuthorityGatewaySettingsRuntime?
    private let retryMilliseconds: Int
    private var current: AuthorityGatewaySettingsRuntime?
    private var worker: Task<Void, Never>?
    private var closing: Task<Void, Never>?
    private var started = false
    private var closed = false
    private(set) var status = Status.idle

    init(retryMilliseconds: Int = 1000, makeRuntime: @escaping @Sendable () -> AuthorityGatewaySettingsRuntime?) throws {
        guard (100...60_000).contains(retryMilliseconds) else { throw AuthorityWakePublisherError.invalidConfiguration }
        self.retryMilliseconds = retryMilliseconds; self.makeRuntime = makeRuntime
    }
    deinit {
        let worker = worker, previous = current, pending = closing
        worker?.cancel()
        Task {
            if let pending { await pending.value }
            else { await previous?.close(); await worker?.value }
        }
    }
    func start() throws {
        guard !started, !closed else { throw GatewayPreparationError.changedScope }
        started = true
        let makeRuntime = makeRuntime, delay = retryMilliseconds
        worker = Task { [weak self] in
            while !Task.isCancelled {
                guard await self?.beginAttempt() == true else { return }
                guard let runtime = makeRuntime() else { await self?.markAbsent(); return }
                guard await self?.retain(runtime) == true else { await runtime.close(); return }
                do {
                    try Task.checkCancellation(); try await runtime.start(); try Task.checkCancellation()
                    if await self?.didStart(runtime) == true { return }
                    await runtime.close(); return
                } catch {
                    await runtime.close()
                    guard await self?.didFail(runtime) == true else { return }
                    do { try await Task.sleep(for: .milliseconds(delay)) } catch { return }
                }
            }
        }
    }
    private func beginAttempt() -> Bool {
        guard !closed, current == nil else { return false }; status = .starting; return true
    }
    private func retain(_ runtime: AuthorityGatewaySettingsRuntime) -> Bool {
        guard !closed, current == nil else { return false }; current = runtime; return true
    }
    private func markAbsent() { if !closed { status = .absent } }
    private func didStart(_ runtime: AuthorityGatewaySettingsRuntime) -> Bool {
        guard !closed, current === runtime else { return false }; status = .listening; return true
    }
    private func didFail(_ runtime: AuthorityGatewaySettingsRuntime) -> Bool {
        guard !closed, current === runtime else { return false }; current = nil; status = .waiting; return true
    }
    /// Concurrent and cancelled closers join the same cleanup, including any failed startup attempt.
    func close() async {
        if let closing { await closing.value; return }
        guard !closed else { return }
        closed = true; status = .closing; worker?.cancel()
        let previous = current, worker = worker
        let cleanup = Task<Void, Never> { await previous?.close(); await worker?.value }
        closing = cleanup; await cleanup.value
        current = nil; self.worker = nil; closing = nil; status = .closed
    }
}
