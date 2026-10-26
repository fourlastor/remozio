import Darwin
import Foundation

/// Supervises an optional connector. Edge status does not prove Access policy or approval delivery.
/// Each replacement waits for the previous child and its readiness work to settle.
actor RelayConnectorSupervisor {
    enum Status: Equatable, Sendable {
        case idle, starting, discovering, checking, connected, disconnected, unavailable
        case stopping, waiting, refused, closing, closed, unsettled
    }
    struct Options: Sendable {
        let retryMilliseconds: Int
        let maximumRetryMilliseconds: Int
        let probeMilliseconds: Int
        init(retryMilliseconds: Int = 1000, maximumRetryMilliseconds: Int = 30_000,
             probeMilliseconds: Int = 1000) throws {
            guard (100...60_000).contains(retryMilliseconds),
                  (retryMilliseconds...60_000).contains(maximumRetryMilliseconds),
                  (100...60_000).contains(probeMilliseconds) else {
                throw RelayConnectorProcess.Failure.invalidConfiguration
            }
            self.retryMilliseconds = retryMilliseconds; self.maximumRetryMilliseconds = maximumRetryMilliseconds
            self.probeMilliseconds = probeMilliseconds
        }
        static let standard = try! Self()
    }
    struct Operations: Sendable {
        let start: @Sendable (@escaping @Sendable (RelayConnectorProcess.Event) -> Void) throws -> RelayConnectorProcess
        let probe: @Sendable (RelayConnectorDiscovery) async throws -> RelayConnectorReadiness.State
        let validateCurrent: @Sendable () throws -> Void
        init(start: @escaping @Sendable (@escaping @Sendable (RelayConnectorProcess.Event) -> Void) throws -> RelayConnectorProcess,
             probe: @escaping @Sendable (RelayConnectorDiscovery) async throws -> RelayConnectorReadiness.State,
             validateCurrent: @escaping @Sendable () throws -> Void = {}) {
            self.start = start; self.probe = probe; self.validateCurrent = validateCurrent
        }
    }
    private let operations: Operations
    private let options: Options
    private var nextRetryMilliseconds: Int
    private var incarnation: UUID?
    private var current: RelayConnectorProcess?
    private var probe: Task<Void, Never>?
    private var retry: Task<Void, Never>?
    private var cleanup: Task<Bool, Never>?
    private var closing: Task<Bool, Never>?
    private var started = false
    private var closed = false
    private(set) var status = Status.idle

    init(options: Options = .standard, operations: Operations) {
        self.options = options; self.operations = operations; nextRetryMilliseconds = options.retryMilliseconds
    }
    static func native(scope: GatewaySettingsConsumerNativeScope, reference: RelayRunCredentialReference,
                       options: Options = .standard,
                       verifyCurrent: @escaping @Sendable () throws -> Void = {}) throws -> RelayConnectorSupervisor {
        let readiness = try RelayConnectorReadiness()
        return RelayConnectorSupervisor(options: options, operations: .init(start: { event in
            try RelayConnectorProcess.startNative(scope: scope, reference: reference, verifyCurrent: verifyCurrent, event: event)
        }, probe: { try await readiness.probe($0) }, validateCurrent: { try scope.validate(); try verifyCurrent() }))
    }
    deinit {
        let probe = probe, retry = retry, pending = cleanup, process = current
        probe?.cancel(); retry?.cancel()
        Task {
            if let pending { _ = await pending.value }
            else { _ = await process?.stopAndWait(); await probe?.value }
            await retry?.value
        }
    }
    func start() throws {
        try Task.checkCancellation()
        guard !started, !closed else { throw RelayConnectorProcess.Failure.invalidConfiguration }
        started = true; launch()
    }
    private func launch() {
        guard !closed, current == nil, cleanup == nil else { return }
        let id = UUID(); incarnation = id; status = .starting
        do {
            // This actor retains the child before queued event callbacks can run.
            current = try operations.start { [weak self] event in
                Task { [weak self] in await self?.receive(event, incarnation: id) }
            }
            status = .discovering
        } catch {
            incarnation = nil
            if Self.isTemporary(error) { scheduleRetry() } else { status = .refused }
        }
    }
    private func receive(_ event: RelayConnectorProcess.Event, incarnation id: UUID) async {
        guard !closed, incarnation == id, current != nil, cleanup == nil else { return }
        switch event {
        case .discovered(let discovery):
            guard probe == nil, status == .discovering else { return }
            status = .checking
            let check = operations.probe, verify = operations.validateCurrent, interval = options.probeMilliseconds
            let invalidated: @Sendable (Bool) -> Void = { [weak self] mayRetry in
                Task { [weak self] in await self?.retireCurrent(incarnation: id, mayRetry: mayRetry) }
            }
            probe = Task { [weak self] in
                while !Task.isCancelled {
                    do { try verify() } catch { if !Task.isCancelled { invalidated(Self.isTemporary(error)) }; return }
                    let observed: Status
                    do { observed = try await check(discovery) == .connected ? .connected : .disconnected }
                    catch { if Task.isCancelled { return }; observed = .unavailable }
                    guard !Task.isCancelled else { return }
                    do { try verify() } catch { invalidated(Self.isTemporary(error)); return }
                    guard await self?.record(observed, incarnation: id) == true else { return }
                    do { try await Task.sleep(for: .milliseconds(interval)) } catch { return }
                }
            }
        case .completed:
            status = .stopping
            let pending = beginCleanup()
            let settled = await pending.value
            guard !closed, incarnation == id else { return }
            guard settled else { status = .unsettled; return }
            current = nil; probe = nil; cleanup = nil; incarnation = nil
            scheduleRetry()
        }
    }
    private func retireCurrent(incarnation id: UUID, mayRetry: Bool) async {
        guard !closed, incarnation == id, current != nil, cleanup == nil else { return }
        status = .stopping
        let pending = beginCleanup(), settled = await pending.value
        guard !closed, incarnation == id else { return }
        guard settled else { status = .unsettled; return }
        current = nil; probe = nil; cleanup = nil; incarnation = nil
        if mayRetry { scheduleRetry() } else { status = .refused }
    }
    static func isTemporary(_ error: any Error) -> Bool {
        let code: Int32
        if let failure = error as? RelayConnectorProcess.Failure, case .system(let value) = failure { code = value }
        else if let failure = error as? JournalLeaseError, case .system(let value) = failure { code = value }
        else { return false }
        return [EAGAIN, ENOMEM, EMFILE, ENFILE, EINTR, ETXTBSY, EIO, EBUSY, ENOSPC, ETIMEDOUT].contains(code)
    }
    private func record(_ observed: Status, incarnation id: UUID) -> Bool {
        guard !closed, incarnation == id, current != nil, cleanup == nil else { return false }
        status = observed
        if observed == .connected { nextRetryMilliseconds = options.retryMilliseconds }
        return true
    }
    private func scheduleRetry() {
        guard !closed, current == nil, cleanup == nil else { return }
        status = .waiting
        let id = UUID(), delay = nextRetryMilliseconds
        incarnation = id
        nextRetryMilliseconds = min(options.maximumRetryMilliseconds, delay * 2)
        retry = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(delay)) } catch { return }
            guard !Task.isCancelled else { return }
            await self?.retry(incarnation: id)
        }
    }
    private func retry(incarnation id: UUID) {
        guard !closed, incarnation == id, status == .waiting else { return }
        retry = nil; launch()
    }
    private func beginCleanup() -> Task<Bool, Never> {
        if let cleanup { return cleanup }
        let process = current, probe = probe
        probe?.cancel()
        let pending = Task {
            let completion = await process?.stopAndWait()
            await probe?.value
            return completion?.termination.settled ?? true
        }
        cleanup = pending; return pending
    }
    /// Cancelled and concurrent callers join the same cleanup. False never permits a replacement child.
    @discardableResult
    func close() async -> Bool {
        if let closing {
            let settled = await closing.value
            finishClose(settled: settled); return settled
        }
        closed = true; status = .closing
        let retry = retry; retry?.cancel()
        let pending = beginCleanup()
        let result = Task { let settled = await pending.value; await retry?.value; return settled }
        closing = result
        let settled = await result.value
        finishClose(settled: settled); return settled
    }
    private func finishClose(settled: Bool) {
        status = settled ? .closed : .unsettled
        if settled { current = nil; probe = nil; cleanup = nil; retry = nil; incarnation = nil }
    }
}
