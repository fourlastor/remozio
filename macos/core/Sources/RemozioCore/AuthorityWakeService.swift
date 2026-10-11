import Darwin
import Foundation
import RemozioProtocol
import Synchronization

private final class AuthorityRequestRetirementSignal: Sendable { let value = Mutex(false) }

/// Owns the request service and its asynchronous publisher. Presence remains a required live runtime input.
public actor AuthorityWakeService {
    public nonisolated let presence: AuthorityPresenceRuntime?
    public enum WakeStatus: Equatable, Sendable { case idle, connecting, running, waiting(retryMilliseconds: UInt64), closed }
    private let commandReceiver: AuthorityCommandReceiveWorker?
    private let makePublisher: @Sendable () throws -> AuthorityWakePublisher
    private let hints: AuthorityWakeHintSource
    private let requestsRetired: @Sendable () -> Bool
    private let startRequests: @Sendable () throws -> Void
    private let closeRequests: @Sendable () throws -> Void
    private let interval: UInt64
    private let initialRetry: UInt64
    private let maximumRetry: UInt64
    private var task: Task<Void, Never>?
    private var receiverObserver: Task<Void, Never>?
    private var publisher: AuthorityWakePublisher?
    private var closing: Task<Void, any Error>?
    private var cleanupComplete = false
    private var started = false
    private var closed = false
    private var retired = false
    public private(set) var wakeStatus = WakeStatus.idle
    public var isRetired: Bool { retired || commandReceiver?.isRetired == true }
    init(makePublisher: @escaping @Sendable () throws -> AuthorityWakePublisher, hints: AuthorityWakeHintSource,
         interval: UInt64, initialRetryMilliseconds: UInt64 = 1000, maximumRetryMilliseconds: UInt64 = 30_000,
         startRequests: @escaping @Sendable () throws -> Void, closeRequests: @escaping @Sendable () throws -> Void,
         requestsRetired: @escaping @Sendable () -> Bool = { false }, presence: AuthorityPresenceRuntime? = nil,
         commandReceiver: AuthorityCommandReceiveWorker? = nil) throws {
        guard (1...30_000).contains(interval), (100...60_000).contains(initialRetryMilliseconds),
              (initialRetryMilliseconds...300_000).contains(maximumRetryMilliseconds) else { throw AuthorityWakePublisherError.invalidConfiguration }
        self.presence = presence; self.makePublisher = makePublisher; self.hints = hints; self.interval = interval
        self.initialRetry = initialRetryMilliseconds; self.maximumRetry = maximumRetryMilliseconds
        self.startRequests = startRequests; self.closeRequests = closeRequests; self.commandReceiver = commandReceiver
        self.requestsRetired = { requestsRetired() || commandReceiver?.isRetired == true }
    }
    deinit {
        task?.cancel(); receiverObserver?.cancel(); commandReceiver?.requestStop(); presence?.close(); hints.close()
        let worker = task, observer = receiverObserver, publisher = publisher, pending = closing, closeRequests = closeRequests, commandReceiver = commandReceiver
        if !cleanupComplete {
            Task {
                await commandReceiver?.close()
                await observer?.value
                if let pending {
                    do { try await pending.value } catch { try? closeRequests() }
                } else {
                    await publisher?.close(); await worker?.value; try? closeRequests()
                }
            }
        }
    }
    /// Restore the hardware Root signer and both protected stores before any listener starts.
    public static func open(configuration: AuthorityWakeStartupConfiguration,
                            routing: @escaping @Sendable () throws -> PresenceRouting,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            commandReceiverFactory: AuthorityCommandReceiveFactory? = nil,
                            onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws -> AuthorityWakeService {
        guard getuid() == 0, geteuid() == 0 else { throw GatewayServiceError.wrongAccount }
        let clock = try AuthorityClock()
        let journal = try AuthorityService.openJournal(configuration: configuration.request.service)
        return try compose(configuration: configuration, journal: journal, clock: clock, presence: nil, appEndpoint: nil,
            routing: routing, reconcileExpired: reconcileExpired, commandReceiverFactory: commandReceiverFactory, onCommandAuthorized: onCommandAuthorized)
    }
    public static func open(configuration: AuthorityPresenceStartupConfiguration,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            commandReceiverFactory: AuthorityCommandReceiveFactory? = nil,
                            onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws -> AuthorityWakeService {
        try open(configuration: configuration.wake, accountPresence: configuration.presence,
            appEndpoint: configuration.endpoint, reconcileExpired: reconcileExpired, commandReceiverFactory: commandReceiverFactory, onCommandAuthorized: onCommandAuthorized)
    }
    /// Enable the durable mode ledger and share one Root epoch with observations, signing and wake publication.
    /// The owning authenticated GUI endpoint supplies observations; unavailable observations keep their explicit unknown state.
    public static func open(configuration: AuthorityWakeStartupConfiguration, accountPresence: AuthorityAccountPresenceConfiguration,
                            appEndpoint: AuthorityPresenceEndpointConfiguration,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            commandReceiverFactory: AuthorityCommandReceiveFactory? = nil,
                            onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws -> AuthorityWakeService {
        guard getuid() == 0, geteuid() == 0 else { throw GatewayServiceError.wrongAccount }
        guard accountPresence.macID == configuration.request.service.macID,
              accountPresence.accountID == configuration.request.service.accountID,
              accountPresence.ownerUID != configuration.request.service.transportPolicy.expectedUserID,
              accountPresence.ownerUID != configuration.gatewayPolicy.expectedUserID,
              appEndpoint.appPolicy.expectedUserID == accountPresence.ownerUID,
              appEndpoint.serviceName != configuration.request.service.serviceName,
              appEndpoint.serviceName != configuration.gatewayServiceName else { throw AuthorityPresenceError.wrongScope }
        let clock = try AuthorityClock()
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 16, maxItems: 4096)
        let policy = try RoutingJournalPolicy(clockEpoch: clock.epoch, challengeLifetimeMillis: 30_000, maximumOperations: 1024,
            payloadLimits: limits, signingLimits: CBORLimits(maxBytes: 131_072, maxDepth: 16, maxItems: 4096))
        let journal = try AuthorityService.openJournal(configuration: configuration.request.service, routingPolicy: policy)
        let presence = AuthorityPresenceRuntime(configuration: accountPresence, clockEpoch: clock.epoch)
        return try compose(configuration: configuration, journal: journal, clock: clock, presence: presence, appEndpoint: appEndpoint,
            routing: { throw AuthorityPresenceError.unavailable }, reconcileExpired: reconcileExpired, commandReceiverFactory: commandReceiverFactory, onCommandAuthorized: onCommandAuthorized)
    }
    private static func compose(configuration: AuthorityWakeStartupConfiguration, journal: AuthorityJournal, clock: AuthorityClock,
                                presence: AuthorityPresenceRuntime?, appEndpoint: AuthorityPresenceEndpointConfiguration?, routing: @escaping @Sendable () throws -> PresenceRouting,
                                reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                                commandReceiverFactory: AuthorityCommandReceiveFactory?,
                                onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void) throws -> AuthorityWakeService {
        do {
            let signer = try EnclaveAuthorityRequestSigner.load(path: configuration.request.keyRecordPath,
                configuration: configuration.request.service, expectedPublicKey: configuration.request.authorityPublicKey, journal: journal)
            let providers: AuthorityRequestProviders
            if let presence { providers = try AuthorityRequestProviders(configuration: configuration.request.service, signer: signer, presence: presence) }
            else { providers = try AuthorityRequestProviders(configuration: configuration.request.service, signer: signer, routing: routing) }
            let ownerRouting: (@Sendable (ApprovalRequestCoordinator, AuthorityMoment) throws -> PresenceRouting)?
            if let presence { ownerRouting = { owner, moment in try presence.routing(owner: owner, now: moment) } }
            else { ownerRouting = nil }
            let hints = try AuthorityWakeHintSource(registration: configuration.registration)
            let retired = AuthorityRequestRetirementSignal()
            let makePublisher: @Sendable () throws -> AuthorityWakePublisher = {
                let channel = try GatewayRootChannel(serviceName: configuration.gatewayServiceName, gatewayPolicy: configuration.gatewayPolicy,
                    timeoutMilliseconds: configuration.timeoutMilliseconds)
                return try AuthorityWakePublisher(journal: journal, channel: channel, registration: configuration.registration,
                    leaseMilliseconds: configuration.leaseMilliseconds, clock: { try clock.now() }, routing: routing,
                    ownerRouting: ownerRouting)
            }
            let service = try AuthorityService(configuration: configuration.request.service, journal: journal,
                maintenanceIntervalMilliseconds: configuration.request.maintenanceIntervalMilliseconds,
                validateSelf: AuthoritySelfValidation.validate, requestClock: { try clock.now() }, requestProviders: providers,
                wakeHints: { try hints.current() }, reconcileExpired: reconcileExpired,
                onMaintenanceFailure: { retired.value.withLock { $0 = true } }, onCommandAuthorized: onCommandAuthorized)
            let presenceListener: AuthorityPresenceXPCListener?
            if let presence, let appEndpoint {
                presenceListener = try AuthorityPresenceXPCListener(configuration: appEndpoint, journal: journal, presence: presence, clock: clock)
            } else { presenceListener = nil }
            let commandReceiver = try commandReceiverFactory?(journal, clock)
            return try AuthorityWakeService(makePublisher: makePublisher, hints: hints, interval: configuration.pollMilliseconds,
                startRequests: { try service.start(); try presenceListener?.start() },
                closeRequests: { presenceListener?.close(); try service.close() },
                requestsRetired: { retired.value.withLock { $0 } }, presence: presence, commandReceiver: commandReceiver)
        } catch { presence?.close(); try? journal.close(); throw error }
    }
    /// Start direct request listeners before attempting the optional gateway connection.
    public func start() async throws {
        guard !started, !closed else { throw AuthorityWakePublisherError.closed }
        started = true
        do {
            try Task.checkCancellation()
            try startRequests()
            if let commandReceiver {
                receiverObserver = Task { [weak self, commandReceiver] in
                    for await _ in commandReceiver.retirement {
                        guard !Task.isCancelled else { return }
                        await self?.commandReceiverDidRetire()
                        return
                    }
                }
            }
            try await commandReceiver?.start()
            try Task.checkCancellation()
            guard !closed else { throw AuthorityWakePublisherError.closed }
        }
        catch { try? await close(); throw error }
        task = Task { [weak self, makePublisher, hints, requestsRetired, interval, initialRetry, maximumRetry] in
            await Self.publish(makePublisher: makePublisher, hints: hints, requestsRetired: requestsRetired,
                interval: interval, initialRetry: initialRetry, maximumRetry: maximumRetry,
                update: { [weak self] publisher, status in await self?.update(publisher: publisher, status: status) ?? false },
                failed: { [weak self] in await self?.publisherDidStop() })
        }
    }
    /// Failed request cleanup remains owned and can be retried. Concurrent callers share one cleanup attempt.
    public func close() async throws {
        closed = true; wakeStatus = .closed
        guard !cleanupComplete else { return }
        if let closing { try await closing.value; return }
        let previous = task; task = nil; previous?.cancel(); commandReceiver?.requestStop()
        let observer = receiverObserver; receiverObserver = nil; observer?.cancel()
        hints.close(); presence?.close()
        let publisher = publisher, closeRequests = closeRequests, commandReceiver = commandReceiver
        let work = Task {
            await commandReceiver?.close()
            await publisher?.close()
            await previous?.value
            await observer?.value
            try closeRequests()
        }
        closing = work
        do { try await work.value; cleanupComplete = true; closing = nil; self.publisher = nil }
        catch { closing = nil; throw error }
    }
    private func update(publisher: AuthorityWakePublisher?, status: WakeStatus) -> Bool {
        guard !closed, !retired else { return false }
        self.publisher = publisher; wakeStatus = status
        return true
    }
    private func commandReceiverDidRetire() async {
        guard !closed else { return }
        retired = true
        receiverObserver = nil // This callback belongs to the observer that is now terminating.
        try? await close()
    }
    private func publisherDidStop() async {
        guard !closed else { return }
        retired = true
        task = nil // This callback runs on the terminating worker. Its publisher has already closed.
        try? await close()
    }
    private static func publish(makePublisher: @Sendable () throws -> AuthorityWakePublisher, hints: AuthorityWakeHintSource,
                                requestsRetired: @Sendable () -> Bool, interval: UInt64, initialRetry: UInt64, maximumRetry: UInt64,
                                update: @Sendable (AuthorityWakePublisher?, WakeStatus) async -> Bool,
                                failed: @Sendable () async -> Void) async {
        var retry = initialRetry
        while !Task.isCancelled {
            var publisher: AuthorityWakePublisher?
            do {
                guard !requestsRetired() else { throw AuthorityXPCEndpointError.unavailable }
                let next = try makePublisher(); publisher = next
                guard await update(next, .connecting) else { throw CancellationError() }
                try await next.start()
                try Task.checkCancellation()
                guard !requestsRetired() else { throw AuthorityXPCEndpointError.unavailable }
                try await next.reconcile()
                try hints.install(next.hintFeed)
                guard await update(next, .running) else { throw CancellationError() }
                retry = initialRetry
                try await next.run(intervalMilliseconds: interval, checkAuthority: {
                    guard !requestsRetired() else { throw AuthorityXPCEndpointError.unavailable }
                })
            } catch {
                if let publisher { hints.clear(publisher.hintFeed); await publisher.close() }
                if Task.isCancelled { return }
                guard retryWake(error), !requestsRetired() else { await failed(); return }
                guard await update(nil, .waiting(retryMilliseconds: retry)) else { return }
                do { try await Task.sleep(for: .milliseconds(retry)) } catch { return }
                retry = min(retry * 2, maximumRetry)
            }
        }
    }
    private static func retryWake(_ error: any Error) -> Bool {
        switch error {
        case GatewayRootChannelError.closed, GatewayRootChannelError.timedOut, GatewayRootChannelError.rejected,
             GatewayRootChannelError.invalidMessage, GatewayRootChannelError.unsupportedVersion,
             AuthorityWakePublisherError.expiredLease: return true
        default: return false
        }
    }
}
