import Foundation
import RemozioProtocol

/// Refreshes verified offers independently of the account maintenance lock. It never changes admission.
actor AuthorityUpdateSchedulingOfferOwner {
    enum Status: Equatable, Sendable { case idle, absent, offered(UpdateSchedulingSnapshot), unavailable, closing, closed }
    private let refresh: @Sendable () async throws -> UpdateSchedulingSnapshot?
    private let interval: Int
    private var worker: Task<Void, Never>?
    private var started = false
    private var closed = false
    private(set) var status = Status.idle

    init(intervalMilliseconds: Int, refresh: @escaping @Sendable () async throws -> UpdateSchedulingSnapshot?) throws {
        guard (100...60_000).contains(intervalMilliseconds) else { throw AuthorityWakePublisherError.invalidConfiguration }
        interval = intervalMilliseconds; self.refresh = refresh
    }
    deinit { worker?.cancel() }
    func start() throws {
        guard !started, !closed else { throw AuthorityWakePublisherError.closed }
        started = true
        worker = Task.detached { [weak self, refresh, interval] in
            while !Task.isCancelled {
                do {
                    let value = try await refresh()
                    try Task.checkCancellation()
                    guard await self?.update(value.map(Status.offered) ?? .absent) == true else { return }
                } catch {
                    if Task.isCancelled { return }
                    guard await self?.update(.unavailable) == true else { return }
                }
                do { try await Task.sleep(for: .milliseconds(interval)) } catch { return }
            }
        }
    }
    private func update(_ value: Status) -> Bool {
        guard !closed else { return false }; status = value; return true
    }
    /// Cancellation does not release an admitted machine or account operation before its owner returns.
    func close() async {
        closed = true; status = .closing; worker?.cancel()
        let current = worker
        await current?.value
        worker = nil; status = .closed
    }
}
