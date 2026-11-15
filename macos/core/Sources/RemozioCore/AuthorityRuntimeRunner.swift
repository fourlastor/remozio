import Foundation
import Synchronization

public enum AuthorityRuntimeError: Error, Equatable { case unmanagedExpiration }

/// One owned runtime. Factory failure must release its resources before throwing.
struct AuthorityRuntimeInstance: Sendable {
    let id = UUID()
    let start: @Sendable () async throws -> Void
    let close: @Sendable () async throws -> Void
    let retired: @Sendable () async -> Bool
    var prepareCloseMarker: (@Sendable () async throws -> (@Sendable () throws -> Void)?)? = nil
}

private final class AuthorityRuntimeOwnership: Sendable {
    private struct State {
        var stopping = false
        var instance: AuthorityRuntimeInstance?
        var status = AuthorityRuntimeRunner.Status.idle
    }
    private let state = Mutex(State())
    private let report: @Sendable (AuthorityRuntimeRunner.Status) -> Void
    init(report: @escaping @Sendable (AuthorityRuntimeRunner.Status) -> Void) { self.report = report }
    var stopping: Bool { state.withLock { $0.stopping } }
    var status: AuthorityRuntimeRunner.Status { state.withLock { $0.status } }
    var instance: AuthorityRuntimeInstance? { state.withLock { $0.instance } }
    func stop() { state.withLock { $0.stopping = true } }
    func retain(_ instance: AuthorityRuntimeInstance) throws -> Bool {
        try state.withLock {
            guard $0.instance == nil else { throw AuthorityXPCEndpointError.unavailable }
            $0.instance = instance
            return !$0.stopping
        }
    }
    func clear(_ instance: AuthorityRuntimeInstance) {
        state.withLock { if $0.instance?.id == instance.id { $0.instance = nil } }
    }
    func update(_ status: AuthorityRuntimeRunner.Status) {
        let changed = state.withLock {
            guard (!$0.stopping || status == .closed || status == .shutdownFailed), $0.status != status else { return false }
            $0.status = status; return true
        }
        if changed { report(status) }
    }
    func closeCurrent() async throws {
        if let instance { try await instance.close(); clear(instance) }
    }
}

/// Owns protected startup retries and asynchronous shutdown. Diagnostics never grant action authority.
/// Report callbacks must return promptly and must not reenter the runner.
public actor AuthorityRuntimeRunner {
    public enum Status: Equatable, Sendable {
        case idle, starting, waiting(retryMilliseconds: Int), running, retired
        case failed(AuthorityStartupFailure), shutdownFailed, closed
    }
    private let ownership: AuthorityRuntimeOwnership
    private let open: @Sendable () async throws -> AuthorityRuntimeInstance
    private let initialRetry: Int
    private let maximumRetry: Int
    private let monitorMilliseconds: Int
    private var worker: Task<Void, Never>?
    private var closing: Task<Void, any Error>?
    private var started = false
    private var cleanupComplete = false
    public nonisolated var status: Status { ownership.status }

    /// Reload protected metadata and restore the hardware signer on every startup attempt. No trust-only fallback is used.
    public init(presenceConfigurationPath: String, initialRetryMilliseconds: Int = 1000,
                maximumRetryMilliseconds: Int = 30_000, monitorMilliseconds: Int = 250,
                report: @escaping @Sendable (Status) -> Void) throws {
        try self.init(initialRetryMilliseconds: initialRetryMilliseconds, maximumRetryMilliseconds: maximumRetryMilliseconds,
            monitorMilliseconds: monitorMilliseconds, open: {
                let configuration = try AuthorityPresenceStartupConfiguration.load(path: presenceConfigurationPath)
                let service = try AuthorityWakeService.open(configuration: configuration, reconcileExpired: Self.reconcileCoordinatorExpiration)
                return AuthorityRuntimeInstance(start: { try await service.start() }, close: { try await service.close() },
                    retired: { await service.isRetired })
            }, report: report)
    }
    init(initialRetryMilliseconds: Int = 1000, maximumRetryMilliseconds: Int = 30_000, monitorMilliseconds: Int = 250,
         open: @escaping @Sendable () async throws -> AuthorityRuntimeInstance,
         report: @escaping @Sendable (Status) -> Void) throws {
        guard (100...60_000).contains(initialRetryMilliseconds),
              (initialRetryMilliseconds...300_000).contains(maximumRetryMilliseconds),
              (10...60_000).contains(monitorMilliseconds) else { throw AuthorityServiceConfigurationError.invalidConfiguration }
        ownership = AuthorityRuntimeOwnership(report: report); self.open = open
        initialRetry = initialRetryMilliseconds; maximumRetry = maximumRetryMilliseconds; self.monitorMilliseconds = monitorMilliseconds
    }
    deinit {
        ownership.stop(); worker?.cancel()
        let worker = worker, pending = closing, ownership = ownership
        if !cleanupComplete {
            Task {
                if let pending {
                    do { try await pending.value } catch { try? await ownership.closeCurrent() }
                } else { await worker?.value; try? await ownership.closeCurrent() }
            }
        }
    }
    public func start() throws {
        guard !started, !ownership.stopping else { throw AuthorityXPCEndpointError.unavailable }
        started = true
        worker = Task { [ownership, open, initialRetry, maximumRetry, monitorMilliseconds] in
            await Self.run(ownership: ownership, open: open, initialRetry: initialRetry,
                maximumRetry: maximumRetry, monitorMilliseconds: monitorMilliseconds)
        }
    }
    /// Stops future attempts, awaits the active attempt, and retains failed cleanup for a later close.
    public func close() async throws {
        ownership.stop(); worker?.cancel()
        guard !cleanupComplete else { return }
        if let closing { try await closing.value; return }
        let previous = worker; worker = nil
        let ownership = ownership
        let cleanup = Task { await previous?.value; try await ownership.closeCurrent() }
        closing = cleanup
        do {
            try await cleanup.value
            cleanupComplete = true; closing = nil; ownership.update(.closed)
        } catch { closing = nil; ownership.update(.shutdownFailed); throw error }
    }
    /// The installed main loop uses this path. Cancellation remains a thrown CancellationError.
    public func runUntilExit() async throws -> Status {
        try start()
        while true {
            try Task.checkCancellation()
            let current = ownership.status
            switch current {
            case .failed, .retired, .shutdownFailed, .closed: return current
            default: try await Task.sleep(for: .milliseconds(250))
            }
        }
    }
    /// Only signal termination of the current running instance can publish its already bound close marker.
    // Armed marker errors report shutdown failure; unarmed termination keeps ordinary cleanup.
    public func closeForTermination() async throws {
        let current = ownership.instance
        var publish: (@Sendable () throws -> Void)?
        do { if !ownership.stopping, ownership.status == .running { publish = try await current?.prepareCloseMarker?() } }
        catch { try await close(); throw error }
        guard !ownership.stopping, ownership.instance?.id == current?.id, ownership.status == .running else { try await close(); return }
        try await close(); try publish?()
    }
    /// Command expiry already closes original resources under the request lock. External adapters need their own registered cleanup.
    static func reconcileCoordinatorExpiration(_ states: [ApprovalRequestState]) throws {
        guard states.allSatisfy({ $0.requestKind == .command && $0.phase == .expired }) else {
            throw AuthorityRuntimeError.unmanagedExpiration
        }
    }
    private static func retire(_ instance: AuthorityRuntimeInstance, ownership: AuthorityRuntimeOwnership) async {
        ownership.update(.retired)
        do {
            try await instance.close()
            ownership.clear(instance)
        } catch {
            ownership.update(.shutdownFailed)
        }
    }
    private static func run(ownership: AuthorityRuntimeOwnership, open: @Sendable () async throws -> AuthorityRuntimeInstance,
                            initialRetry: Int, maximumRetry: Int, monitorMilliseconds: Int) async {
        var retry = initialRetry
        while !ownership.stopping, !Task.isCancelled {
            ownership.update(.starting)
            do {
                let instance = try await open()
                guard try ownership.retain(instance) else { return }
                try Task.checkCancellation()
                try await instance.start()
                guard !ownership.stopping, !Task.isCancelled else { return }
                if await instance.retired() {
                    await retire(instance, ownership: ownership)
                    return
                }
                guard !ownership.stopping, !Task.isCancelled else { return }
                ownership.update(.running)
                while !ownership.stopping, !Task.isCancelled {
                    if await instance.retired() {
                        await retire(instance, ownership: ownership)
                        return
                    }
                    try await Task.sleep(for: .milliseconds(monitorMilliseconds))
                }
                return
            } catch {
                if ownership.stopping || Task.isCancelled { return }
                do { try await ownership.closeCurrent() }
                catch { ownership.update(.shutdownFailed); return }
                let failure = AuthorityStartupFailure(error: error)
                guard failure == .temporaryStorageFailure else { ownership.update(.failed(failure)); return }
                ownership.update(.waiting(retryMilliseconds: retry))
                do { try await Task.sleep(for: .milliseconds(retry)) } catch { return }
                retry = min(retry * 2, maximumRetry)
            }
        }
    }
}
