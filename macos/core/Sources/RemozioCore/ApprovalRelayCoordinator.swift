import Foundation

/// Keeps the relay bound to the current direct listener. Optional relay failure leaves direct transport running.
public actor ApprovalRelayCoordinator {
    public enum Status: Sendable, Equatable { case idle, starting, ready, failed, closed }
    typealias Factory = @Sendable (UInt16, @escaping @Sendable (DirectListenerEvent) -> Void) throws -> any OwnedApprovalRelay
    private let factory: Factory
    private let retryMilliseconds: UInt64
    private let report: @Sendable (Status) -> Void
    private var current: (id: UUID, port: UInt16, relay: any OwnedApprovalRelay)?
    private var retryAfter: ContinuousClock.Instant?
    private var updating = false
    private var closed = false
    public private(set) var status = Status.idle

    public init(listenPort: UInt16, maximumConnections: Int = 8, timeoutMilliseconds: UInt64 = 15_000,
                retryMilliseconds: UInt64 = 1000, report: @escaping @Sendable (Status) -> Void) throws {
        guard listenPort > 0, (1...64).contains(maximumConnections),
              (1...60_000).contains(timeoutMilliseconds) else { throw ApprovalRelayError.invalidConfiguration }
        try self.init(retryMilliseconds: retryMilliseconds, factory: { port, event in
            try ApprovalWebSocketRelay(listenPort: listenPort, targetPort: port, maximumConnections: maximumConnections,
                timeoutMilliseconds: timeoutMilliseconds, event: event)
        }, report: report)
    }
    init(retryMilliseconds: UInt64 = 1000, factory: @escaping Factory,
         report: @escaping @Sendable (Status) -> Void = { _ in }) throws {
        guard (100...60_000).contains(retryMilliseconds) else { throw ApprovalRelayError.invalidConfiguration }
        self.retryMilliseconds = retryMilliseconds; self.factory = factory; self.report = report
    }
    deinit {
        if let current { Task { await current.relay.closeAndWait() } }
    }

    /// The transport owner calls this serially with measured listener state, including loss of authority.
    public func update(_ state: DirectHostState) async throws {
        try Task.checkCancellation()
        guard !closed else { throw ApprovalRelayError.stopped }
        guard !updating else { throw ApprovalRelayError.busy }
        updating = true
        defer { updating = false }
        let port: UInt16?
        if case .ready(let value) = state { port = value } else { port = nil }
        if current?.port == port, status != .failed { return }
        let changedPort = (current?.port ?? failedPort) != port
        if !changedPort, status == .failed, let retryAfter, ContinuousClock.now < retryAfter { return }
        if let previous = current {
            await previous.relay.closeAndWait()
            if current?.id == previous.id { current = nil }
        }
        guard !closed else { return }
        guard let port else { failedPort = nil; retryAfter = nil; set(.idle); return }
        let id = UUID()
        do {
            let relay = try factory(port) { [weak self] event in
                Task { await self?.received(event, id: id) }
            }
            current = (id, port, relay)
            set(.starting)
            try relay.start()
            retryAfter = nil
        } catch {
            if let current { await current.relay.closeAndWait(); self.current = nil }
            guard !closed else { return }
            retryAfter = ContinuousClock.now.advanced(by: .milliseconds(Int64(retryMilliseconds)))
            failedPort = port
            set(.failed)
        }
    }
    private var failedPort: UInt16?
    private func received(_ event: DirectListenerEvent, id: UUID) {
        guard !closed, current?.id == id else { return }
        switch event {
        case .ready:
            guard status == .starting else { return }
            failedPort = nil; retryAfter = nil; set(.ready)
        case .failed, .stopped:
            failedPort = current?.port
            retryAfter = ContinuousClock.now.advanced(by: .milliseconds(Int64(retryMilliseconds)))
            set(.failed)
        }
    }
    public func close() async {
        closed = true
        if let current { await current.relay.closeAndWait(); self.current = nil }
        set(.closed)
    }
    private func set(_ value: Status) {
        guard (!closed || value == .closed), value != status else { return }
        status = value
        report(value)
    }
}
