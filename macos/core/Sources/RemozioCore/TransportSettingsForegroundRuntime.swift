import Foundation
import Synchronization

/// Owns direct approvals, pairing and relay. Optional wake has a separate controller and lifetime.
actor TransportSettingsForegroundRuntime: OwnedTransportSettingsForeground {
    struct Operations: Sendable {
        let startDirect: @Sendable () async throws -> Void
        let startPairing: @Sendable () throws -> Void
        let directState: @Sendable () async -> DirectHostState
        let updateRelay: @Sendable (DirectHostState) async throws -> Void
        let retirePairing: @Sendable () -> Void
        let closePairing: @Sendable () async -> Void
        let closeRelay: @Sendable () async -> Void
        let closeDirect: @Sendable () async -> Void
    }
    private final class State: Sendable {
        struct Value { var retired = false; var cleanup: Task<Void, Never>? }
        let value = Mutex(Value())
        let operations: Operations
        init(_ operations: Operations) { self.operations = operations }
        func retire() -> Task<Void, Never> {
            let operations = operations
            let task = value.withLock { value in
                value.retired = true
                if let cleanup = value.cleanup { return cleanup }
                let cleanup = Task {
                    let pairing = Task { await operations.closePairing() }
                    let relay = Task { await operations.closeRelay() }
                    let direct = Task { await operations.closeDirect() }
                    await pairing.value; await relay.value; await direct.value
                }
                value.cleanup = cleanup; return cleanup
            }
            operations.retirePairing(); return task
        }
    }
    private nonisolated let state: State
    private let operations: Operations
    private let verifyCurrent: @Sendable () throws -> Void
    private let report: @Sendable (DirectHostState) -> Void
    private var started = false
    private var previous: DirectHostState?

    init(bootstrap: TransportSettingsConsumerBootstrap, verifyCurrent: @escaping @Sendable () throws -> Void,
         report: @escaping @Sendable (DirectHostState) -> Void,
         reportRelay: @escaping @Sendable (ApprovalRelayCoordinator.Status) -> Void) throws {
        let configuration = bootstrap.base.transport
        try configuration.requireNativeProcess(); try verifyCurrent()
        let identity = try ApprovalTransportIdentity.load(configuration: configuration)
        try verifyCurrent()
        let pairing = try TransportPairingXPCListener(configuration: bootstrap.base.control, identity: identity)
        let relay = try bootstrap.base.relayPort.map { port in
            try ApprovalRelayCoordinator(listenPort: port, maximumConnections: configuration.maximumConnections,
                timeoutMilliseconds: configuration.timeoutMilliseconds, report: reportRelay)
        }
        let service = try DirectApprovalTransportService(macID: configuration.macID, accountID: configuration.accountID,
            identity: identity, authorityServiceName: configuration.authorityServiceName, authorityPolicy: configuration.authorityPolicy,
            maximumConnections: configuration.maximumConnections, timeoutMilliseconds: configuration.timeoutMilliseconds,
            refreshMilliseconds: configuration.refreshMilliseconds, requestDeliveryTimeoutMilliseconds: configuration.timeoutMilliseconds,
            requestRefreshMilliseconds: configuration.refreshMilliseconds)
        try verifyCurrent()
        self.init(operations: .init(startDirect: { try await service.start() }, startPairing: { try pairing.start() },
            directState: { await service.state }, updateRelay: { try await relay?.update($0) },
            retirePairing: { pairing.close() }, closePairing: { await pairing.closeAndWait() },
            closeRelay: { await relay?.close() }, closeDirect: { await service.closeAndWait() }),
            verifyCurrent: verifyCurrent, report: report)
    }
    /// Owned operations preserve the native lifecycle without simulating dedicated-account admission.
    init(operations: Operations, verifyCurrent: @escaping @Sendable () throws -> Void,
         report: @escaping @Sendable (DirectHostState) -> Void = { _ in }) {
        self.operations = operations; state = State(operations); self.verifyCurrent = verifyCurrent; self.report = report
    }
    private func requireCurrent() throws {
        try Task.checkCancellation()
        guard !state.value.withLock({ $0.retired }) else { throw DirectHostError.stopped }
        try verifyCurrent()
        guard !state.value.withLock({ $0.retired }) else { throw DirectHostError.stopped }
    }
    func start() async throws {
        guard !started else { throw DirectHostError.stopped }
        try requireCurrent(); started = true
        do {
            try await operations.startDirect(); try requireCurrent()
            try operations.startPairing(); try requireCurrent()
        } catch { retire(); throw error }
    }
    func poll() async throws {
        guard started else { throw DirectHostError.stopped }
        try requireCurrent()
        let current = await operations.directState(); try requireCurrent()
        if previous != current { report(current); previous = current }
        try await operations.updateRelay(current); try requireCurrent()
        switch current {
        case .stopped, .authorityUnavailable, .failed: throw DirectHostError.authorityUnavailable
        case .noEligiblePhones, .starting, .ready: break
        }
    }
    nonisolated func retire() { _ = state.retire() }
    func closeAndWait() async throws { await state.retire().value }
    deinit { _ = state.retire() }
}
