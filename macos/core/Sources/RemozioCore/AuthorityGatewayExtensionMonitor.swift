import Foundation

/// Observes optional provider installation. No state here asserts service health, provider delivery or phone readiness.
actor AuthorityGatewayExtensionMonitor {
    enum Status: Equatable, Sendable { case idle, absent, providerInstalled(Data), unavailable, closing, closed }
    private let refresh: @Sendable () async throws -> Data?
    private let interval: Int
    private var worker: Task<Void, Never>?
    private var started = false
    private var closed = false
    private(set) var status = Status.idle

    init(intervalMilliseconds: Int = 1000, refresh: @escaping @Sendable () async throws -> Data?) throws {
        guard (100...60_000).contains(intervalMilliseconds) else { throw AuthorityWakePublisherError.invalidConfiguration }
        interval = intervalMilliseconds; self.refresh = refresh
    }
    deinit { worker?.cancel() }
    func start() throws {
        guard !started, !closed else { throw AuthorityWakePublisherError.closed }
        started = true
        worker = Task { [weak self, refresh, interval] in
            while !Task.isCancelled {
                do {
                    let digest = try await refresh()
                    try Task.checkCancellation()
                    guard digest == nil || digest?.count == 32 else { throw GatewayPreparationError.invalidRecord }
                    guard await self?.update(digest.map(Status.providerInstalled) ?? .absent) == true else { return }
                } catch {
                    if Task.isCancelled { return }
                    guard await self?.update(.unavailable) == true else { return }
                }
                do { try await Task.sleep(for: .milliseconds(interval)) } catch { return }
            }
        }
    }
    private func update(_ status: Status) -> Bool {
        guard !closed else { return false }; self.status = status; return true
    }
    /// Every concurrent closer waits for the same admitted refresh. Cancellation does not release resources early.
    func close() async {
        closed = true; status = .closing; worker?.cancel()
        let current = worker
        await current?.value
        worker = nil; status = .closed
    }
}
