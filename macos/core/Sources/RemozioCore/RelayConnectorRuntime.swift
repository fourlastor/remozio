import Foundation

/// Loads optional protected connector metadata without owning the foreground routes or their lifetime baseline.
actor RelayConnectorRuntime: OwnedTransportRelayConnector {
    enum Status: Equatable, Sendable {
        case idle, absent, waiting, starting, active(RelayConnectorSupervisor.Status), refused, closing, closed, unsettled
    }
    private let load: @Sendable () throws -> RelayConnectorStartupReference?
    private let make: @Sendable (RelayConnectorStartupReference) throws -> RelayConnectorSupervisor
    private let retryDelay: Duration
    private var retryAt = ContinuousClock.now
    private var current: RelayConnectorSupervisor?
    private var closing: Task<Void, any Error>?
    private var polling = false
    private var closed = false
    private(set) var status = Status.idle

    init(retryMilliseconds: Int = 1000, load: @escaping @Sendable () throws -> RelayConnectorStartupReference?,
         make: @escaping @Sendable (RelayConnectorStartupReference) throws -> RelayConnectorSupervisor) throws {
        guard (100...60_000).contains(retryMilliseconds) else { throw RelayConnectorProcess.Failure.invalidConfiguration }
        self.load = load; self.make = make; retryDelay = .milliseconds(retryMilliseconds)
    }
    static func native(scope: GatewaySettingsConsumerNativeScope, bootstrap: TransportSettingsConsumerBootstrap,
                       release: SignedReleaseEvidence, retryMilliseconds: Int = 1000,
                       options: RelayConnectorSupervisor.Options = .standard) throws -> RelayConnectorRuntime {
        guard scope.configuration == bootstrap.host else { throw RuntimePreparationError.changedScope }
        return try .init(retryMilliseconds: retryMilliseconds, load: {
            guard let reference = try RelayConnectorStartupReference.loadNative(scope: scope, bootstrap: bootstrap) else { return nil }
            try RelayConnectorStartupReference.validateReleaseFormats(release.manifest.components)
            return reference
        }, make: { try $0.makeNativeSupervisor(scope: scope, bootstrap: bootstrap, options: options) })
    }
    func poll() async throws {
        try Task.checkCancellation()
        guard !closed else { throw GatewayServiceError.unavailable }
        guard !polling else { return }
        polling = true; defer { polling = false }
        if let current {
            let observed = await current.status
            if !closed { status = .active(observed) }
            return
        }
        guard status != .refused, ContinuousClock.now >= retryAt else { return }
        do {
            guard let reference = try load() else {
                status = .absent; retryAt = ContinuousClock.now.advanced(by: retryDelay); return
            }
            let supervisor = try make(reference)
            current = supervisor; status = .starting
            try await supervisor.start()
            let observed = await supervisor.status
            if !closed { status = .active(observed) }
        } catch {
            if let current {
                let settled = await current.close()
                guard !closed else { return }
                guard settled else { status = .unsettled; return }
                self.current = nil
            }
            guard !closed else { return }
            try Task.checkCancellation()
            if RelayConnectorSupervisor.isTemporary(error) {
                status = .waiting; retryAt = ContinuousClock.now.advanced(by: retryDelay)
            } else { status = .refused }
        }
    }
    /// Success means the supervisor joined its child and readiness work. Unsettled work remains a shutdown error.
    func close() async throws {
        let pending: Task<Void, any Error>
        if let closing { pending = closing }
        else {
            closed = true; status = .closing
            let current = current
            pending = Task {
                if let current, !(await current.close()) { throw GatewayServiceError.unavailable }
            }
            closing = pending
        }
        do { try await pending.value; current = nil; status = .closed }
        catch { status = .unsettled; throw error }
    }
    deinit {
        let pending = closing, current = current
        Task {
            if let pending { _ = await pending.result }
            else { _ = await current?.close() }
        }
    }
}
