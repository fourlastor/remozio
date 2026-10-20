import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Synchronization

private final class AuthorityRequestRetirementSignal: Sendable { let value = Mutex(false) }

/// A live Root pause for one exact commit. Only its service can create or revoke this ticket.
final class AuthorityPhonePushRecoveryTicket: Sendable {
    let commitDigest: Data
    private let active = Mutex(true)
    fileprivate init(commitDigest: Data) { self.commitDigest = commitDigest }
    fileprivate func revoke() { active.withLock { $0 = false } }
    func requireValid() throws {
        guard active.withLock({ $0 }) else { throw GatewayPreparationError.changedScope }
    }
}

/// Owns the request service and its asynchronous publisher. Presence remains a required live runtime input.
public actor AuthorityWakeService {
    public nonisolated let presence: AuthorityPresenceRuntime?
    nonisolated let gatewaySettingsBinding: GatewaySettingsControlBinding?
    public enum WakeStatus: Equatable, Sendable { case idle, connecting, running, waiting(retryMilliseconds: UInt64), quiescingForSettings, suspendedForSettings, quiescingForRecovery, suspendedForRecovery, closed }
    private let commandReceiver: AuthorityCommandReceiveWorker?
    private let commandExecutionWorker: AuthorityCommandExecutionWorker?
    private let makePublisher: @Sendable () throws -> AuthorityWakePublisher
    private let phonePushCapability: AuthorityPhonePushCapability?
    private let hints: AuthorityWakeHintSource
    private let requestsRetired: @Sendable () -> Bool
    private let startRequests: @Sendable () throws -> Void
    private let closeRequests: @Sendable () throws -> Void
    private let stopRequestProducers: @Sendable () async -> Void
    private let interval: UInt64
    private let initialRetry: UInt64
    private let maximumRetry: UInt64
    private var task: Task<Void, Never>?
    private var receiverObserver: Task<Void, Never>?
    private var executionObserver: Task<Void, Never>?
    private var publisher: AuthorityWakePublisher?
    private var settingsChange: AuthorityPhonePushSettingsChange?
    private var acceptedSettings: AuthorityPhonePushSettingsChange?
    private var settingsDrain: Task<Void, Never>?
    private var settingsDrained = false
    private var recoveryTicket: AuthorityPhonePushRecoveryTicket?
    private var acceptedRecoveryTicket: AuthorityPhonePushRecoveryTicket?
    private var recoveryDrain: Task<Void, Never>?
    private var recoveryDrained = false
    private var recoveryStartupHold = false
    private var startupRestorePending = false
    private var startupScope: (options: Data, commitDigest: Data, pendingChange: AuthorityPhonePushSettingsChange?, requiresConsumerRecovery: Bool)?
    private var closing: Task<Void, any Error>?
    private var cleanupComplete = false
    private var started = false
    private var closed = false
    private var retired = false
    public private(set) var wakeStatus = WakeStatus.idle
    public var isRetired: Bool { retired || requestsRetired() }
    init(makePublisher: @escaping @Sendable () throws -> AuthorityWakePublisher, hints: AuthorityWakeHintSource,
         interval: UInt64, initialRetryMilliseconds: UInt64 = 1000, maximumRetryMilliseconds: UInt64 = 30_000,
         startRequests: @escaping @Sendable () throws -> Void, closeRequests: @escaping @Sendable () throws -> Void,
         requestsRetired: @escaping @Sendable () -> Bool = { false }, presence: AuthorityPresenceRuntime? = nil,
         commandReceiver: AuthorityCommandReceiveWorker? = nil,
         commandExecutionWorker: AuthorityCommandExecutionWorker? = nil,
         stopRequestProducers: @escaping @Sendable () async -> Void = {},
         phonePushCapability: AuthorityPhonePushCapability? = nil,
         gatewaySettingsBinding: GatewaySettingsControlBinding? = nil) throws {
        guard (1...30_000).contains(interval), (100...60_000).contains(initialRetryMilliseconds),
              (initialRetryMilliseconds...300_000).contains(maximumRetryMilliseconds) else { throw AuthorityWakePublisherError.invalidConfiguration }
        guard gatewaySettingsBinding == nil || gatewaySettingsBinding?.accountID == hints.binding.accountID else { throw GatewayPreparationError.changedScope }
        self.gatewaySettingsBinding = gatewaySettingsBinding
        self.phonePushCapability = phonePushCapability
        self.presence = presence; self.makePublisher = makePublisher; self.hints = hints; self.interval = interval
        self.initialRetry = initialRetryMilliseconds; self.maximumRetry = maximumRetryMilliseconds
        self.stopRequestProducers = stopRequestProducers
        self.startRequests = startRequests; self.closeRequests = closeRequests; self.commandReceiver = commandReceiver; self.commandExecutionWorker = commandExecutionWorker
        self.requestsRetired = { requestsRetired() || commandReceiver?.isRetired == true || commandExecutionWorker?.isRetired == true }
    }
    deinit {
        recoveryTicket?.revoke(); acceptedRecoveryTicket?.revoke()
        phonePushCapability?.close()
        task?.cancel(); receiverObserver?.cancel(); executionObserver?.cancel(); commandReceiver?.requestStop(); commandExecutionWorker?.requestStop(); presence?.close(); hints.close()
        let worker = task, drain = settingsDrain, recovery = recoveryDrain, observer = receiverObserver, executionObserver = executionObserver, publisher = publisher, pending = closing, closeRequests = closeRequests, stopRequestProducers = stopRequestProducers, commandReceiver = commandReceiver, commandExecutionWorker = commandExecutionWorker
        if !cleanupComplete {
            Task {
                await commandReceiver?.close()
                await stopRequestProducers()
                await commandExecutionWorker?.close()
                await observer?.value
                await executionObserver?.value
                if let pending {
                    do { try await pending.value } catch { try? closeRequests() }
                } else {
                    await publisher?.close(); await worker?.value; await drain?.value; await recovery?.value; try? closeRequests()
                }
            }
        }
    }
    /// Restore the hardware Root signer and both protected stores before any listener starts.
    public static func open(configuration: AuthorityWakeStartupConfiguration,
                            routing: @escaping @Sendable () throws -> PresenceRouting,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            commandReceiverFactory: AuthorityCommandReceiveFactory? = nil,
                            commandExecutionFactory: AuthorityCommandExecutionFactory? = nil,
                            onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws -> AuthorityWakeService {
        guard getuid() == 0, geteuid() == 0 else { throw GatewayServiceError.wrongAccount }
        let clock = try AuthorityClock()
        let journal = try AuthorityService.openJournal(configuration: configuration.request.service,
            gatewayPolicy: configuration.phonePush?.journalPolicy(clockEpoch: clock.epoch))
        return try compose(configuration: configuration, journal: journal, clock: clock, presence: nil, appEndpoint: nil, pairingConfiguration: nil,
            routing: routing, reconcileExpired: reconcileExpired, commandReceiverFactory: commandReceiverFactory, commandExecutionFactory: commandExecutionFactory, onCommandAuthorized: onCommandAuthorized)
    }
    public static func open(configuration: AuthorityPresenceStartupConfiguration,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            commandReceiverFactory: AuthorityCommandReceiveFactory? = nil,
                            commandExecutionFactory: AuthorityCommandExecutionFactory? = nil,
                            onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws -> AuthorityWakeService {
        try open(configuration: configuration.wake, accountPresence: configuration.presence,
            appEndpoint: configuration.endpoint, pairingConfiguration: configuration.pairing, reconcileExpired: reconcileExpired, commandReceiverFactory: commandReceiverFactory, commandExecutionFactory: commandExecutionFactory, onCommandAuthorized: onCommandAuthorized)
    }
    /// Enable the durable mode ledger and share one Root epoch with observations, signing and wake publication.
    /// The owning authenticated GUI endpoint supplies observations; unavailable observations keep their explicit unknown state.
    public static func open(configuration: AuthorityWakeStartupConfiguration, accountPresence: AuthorityAccountPresenceConfiguration,
                            appEndpoint: AuthorityPresenceEndpointConfiguration, pairingConfiguration: AuthorityPairingSetupConfiguration? = nil,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            commandReceiverFactory: AuthorityCommandReceiveFactory? = nil,
                            commandExecutionFactory: AuthorityCommandExecutionFactory? = nil,
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
        let journal = try AuthorityService.openJournal(configuration: configuration.request.service, routingPolicy: policy,
            gatewayPolicy: configuration.phonePush?.journalPolicy(clockEpoch: clock.epoch))
        let presence = AuthorityPresenceRuntime(configuration: accountPresence, clockEpoch: clock.epoch)
        return try compose(configuration: configuration, journal: journal, clock: clock, presence: presence, appEndpoint: appEndpoint, pairingConfiguration: pairingConfiguration,
            routing: { throw AuthorityPresenceError.unavailable }, reconcileExpired: reconcileExpired, commandReceiverFactory: commandReceiverFactory, commandExecutionFactory: commandExecutionFactory, onCommandAuthorized: onCommandAuthorized)
    }
    private static func compose(configuration: AuthorityWakeStartupConfiguration, journal: AuthorityJournal, clock: AuthorityClock,
                                presence: AuthorityPresenceRuntime?, appEndpoint: AuthorityPresenceEndpointConfiguration?,
                                pairingConfiguration: AuthorityPairingSetupConfiguration?, routing: @escaping @Sendable () throws -> PresenceRouting,
                                reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                                commandReceiverFactory: AuthorityCommandReceiveFactory?,
                                commandExecutionFactory: AuthorityCommandExecutionFactory?,
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
            let phonePushWall: @Sendable () throws -> UInt64 = {
                let value = Date().timeIntervalSince1970 * 1000
                guard value.isFinite, value >= 0, value < Double(UInt64.max) else { throw AuthorityClockError.overflow }
                return UInt64(value)
            }
            let phoneCapability = AuthorityPhonePushCapability(journal: journal, registration: configuration.registration,
                clock: { try clock.now() }, wall: phonePushWall, makeProvider: {
                    try AuthorityPhonePushRegistration(policy: $0.registrationPolicy(configuration.registration), signer: signer)
                })
            let hints = try AuthorityWakeHintSource(registration: configuration.registration)
            let retired = AuthorityRequestRetirementSignal()
            let makePublisher: @Sendable () throws -> AuthorityWakePublisher = {
                let channel = try GatewayRootChannel(serviceName: configuration.gatewayServiceName, gatewayPolicy: configuration.gatewayPolicy,
                    timeoutMilliseconds: configuration.timeoutMilliseconds)
                return try AuthorityWakePublisher(journal: journal, channel: channel, registration: configuration.registration,
                    leaseMilliseconds: configuration.leaseMilliseconds, clock: { try clock.now() }, routing: routing,
                    ownerRouting: ownerRouting, phonePush: phoneCapability.publication, phonePushSource: { phoneCapability.publication })
            }
            let executionWorker = try commandExecutionFactory?(journal, clock)
            let service = try AuthorityService(configuration: configuration.request.service, journal: journal,
                maintenanceIntervalMilliseconds: configuration.request.maintenanceIntervalMilliseconds,
                validateSelf: AuthoritySelfValidation.validate, requestClock: { try clock.now() }, requestProviders: providers,
                phonePushRegistration: phoneCapability.registrationProvider(),
                phonePushRecovery: phoneCapability.recoveryProvider(), wakeHints: { try hints.current() }, reconcileExpired: reconcileExpired,
                onMaintenanceFailure: { retired.value.withLock { $0 = true } }, onCommandAuthorized: { notice in
                    _ = executionWorker?.enqueue(notice)
                    onCommandAuthorized(notice)
                })
            if let options = configuration.phonePush {
                try phoneCapability.installInitialConfiguration(options, configurationDigest: Data(SHA256.hash(data: options.canonicalBytes)))
            }
            let presenceListener: AuthorityPresenceXPCListener?
            if let presence, let appEndpoint {
                presenceListener = try AuthorityPresenceXPCListener(configuration: appEndpoint, journal: journal, presence: presence, clock: clock,
                    pairingConfiguration: pairingConfiguration, signer: pairingConfiguration == nil ? nil : signer,
                    minimumEnvelopeVersion: configuration.request.service.minimumEnvelopeVersion, auditVersions: configuration.request.service.auditVersions)
            } else { presenceListener = nil }
            let commandReceiver = try commandReceiverFactory?(journal, clock)
            return try AuthorityWakeService(makePublisher: makePublisher, hints: hints, interval: configuration.pollMilliseconds,
                startRequests: { try service.start(); try presenceListener?.start() },
                closeRequests: { presenceListener?.close(); try service.close() },
                requestsRetired: { retired.value.withLock { $0 } }, presence: presence, commandReceiver: commandReceiver, commandExecutionWorker: executionWorker,
                stopRequestProducers: { await journal.stopCommandExchanges() }, phonePushCapability: phoneCapability,
                gatewaySettingsBinding: .init(accountID: configuration.registration.accountID, rootEpoch: clock.epoch))
        } catch { presence?.close(); try? journal.close(); throw error }
    }
    /// Unreadable optional state must not be treated as absence. Foreground listeners can still start.
    func pauseUnknownPhonePushStartup() throws {
        guard !closed, !isRetired, !started, startupScope == nil, settingsChange == nil else { throw AuthorityWakePublisherError.busy }
        startupRestorePending = true; phonePushCapability?.suspend()
    }
    /// The native owner has freshly verified absence. This cannot erase a previously retained commit floor.
    func allowAbsentPhonePushStartup() throws {
        guard !closed, !isRetired, startupRestorePending, startupScope == nil, settingsChange == nil else {
            throw AuthorityWakePublisherError.busy
        }
        startupRestorePending = false
        if started { startPublisherLoop() }
    }
    /// Apply authenticated retained scope before the first publisher starts. Optional failure keeps foreground startup available.
    /// After failure, the native owner can retry the same restoration while foreground listeners remain active.
    @discardableResult
    func restorePhonePushStartup(_ options: AuthorityPhonePushStartupConfiguration, commitDigest: Data,
                                 pendingChange: AuthorityPhonePushSettingsChange?, requiresConsumerRecovery: Bool = false,
                                 verifyCurrent: @Sendable () throws -> Void) throws -> Bool {
        guard !closed, !isRetired, let phonePushCapability else { throw AuthorityWakePublisherError.closed }
        guard !started || startupRestorePending else { throw AuthorityWakePublisherError.busy }
        guard settingsChange == nil || settingsChange == pendingChange else { throw GatewayPreparationError.changedScope }
        if let scope = startupScope {
            guard scope.options == options.canonicalBytes, scope.commitDigest == commitDigest, scope.pendingChange == pendingChange,
                  scope.requiresConsumerRecovery == requiresConsumerRecovery else {
                throw GatewayPreparationError.changedScope
            }
        } else {
            guard commitDigest.count == 32, pendingChange == nil || pendingChange?.previousCommitDigest == commitDigest,
                  !requiresConsumerRecovery || pendingChange == nil else {
                throw GatewayPreparationError.invalidRecord
            }
            startupScope = (options.canonicalBytes, commitDigest, pendingChange, requiresConsumerRecovery)
        }
        startupRestorePending = true
        settingsChange = pendingChange
        recoveryStartupHold = requiresConsumerRecovery
        if pendingChange != nil { wakeStatus = .quiescingForSettings }
        else if requiresConsumerRecovery { wakeStatus = .suspendedForRecovery }
        let installed = try phonePushCapability.restoreStartup(options, commitDigest: commitDigest,
            pendingChange: pendingChange, requiresConsumerRecovery: requiresConsumerRecovery, verifyCurrent: verifyCurrent)
        startupRestorePending = false
        if started { startPublisherLoop() }
        return installed
    }
    /// The native loader supplies current protected inputs. This result confirms provider installation, not delivery readiness.
    @discardableResult
    func installPhonePush(_ options: AuthorityPhonePushStartupConfiguration, commitDigest: Data,
                          verifyCurrent: @Sendable () throws -> Void) throws -> Bool {
        guard started, !closed, !isRetired, let phonePushCapability else { throw AuthorityWakePublisherError.closed }
        guard !startupRestorePending, !recoveryStartupHold, recoveryTicket == nil else { throw AuthorityWakePublisherError.busy }
        return try phonePushCapability.install(options, commitDigest: commitDigest, verifyCurrent: verifyCurrent)
    }
    func suspendPhonePush() { phonePushCapability?.suspend() }

    /// Pause optional work on its exact retained floor. Every waiter joins the same owned publisher drain.
    func quiescePhonePushRecovery(commitDigest: Data, verifyCurrent: @Sendable () throws -> Void) async throws -> AuthorityPhonePushRecoveryTicket {
        guard started, !closed, !isRetired, let phonePushCapability else { throw AuthorityWakePublisherError.closed }
        guard !startupRestorePending, settingsChange == nil else { throw AuthorityWakePublisherError.busy }
        guard commitDigest.count == 32, phonePushCapability.retainedCommitDigest == commitDigest,
              recoveryTicket == nil || recoveryTicket?.commitDigest == commitDigest else { throw GatewayPreparationError.changedScope }
        try verifyCurrent(); try Task.checkCancellation()
        phonePushCapability.suspend()
        if recoveryTicket == nil {
            acceptedRecoveryTicket?.revoke(); acceptedRecoveryTicket = nil
            recoveryTicket = AuthorityPhonePushRecoveryTicket(commitDigest: commitDigest)
            recoveryDrained = false; wakeStatus = .quiescingForRecovery
            let previous = task; task = nil; previous?.cancel()
            let old = publisher; publisher = nil
            if let old { hints.clear(old.hintFeed) }
            recoveryDrain = Task { await old?.close(); await previous?.value }
        }
        let ticket = recoveryTicket!, drain = recoveryDrain
        try phonePushCapability.quiesceRecovery(commitDigest: commitDigest, verifyCurrent: verifyCurrent)
        await drain?.value
        guard !closed, !isRetired, recoveryTicket === ticket, settingsChange == nil else { throw GatewayPreparationError.changedScope }
        try ticket.requireValid(); try verifyCurrent(); try Task.checkCancellation()
        recoveryDrained = true; wakeStatus = .suspendedForRecovery
        return ticket
    }
    /// The native owner verifies fresh consumer acceptance before releasing this exact live pause.
    @discardableResult
    func resumePhonePushRecovery(_ ticket: AuthorityPhonePushRecoveryTicket, verifyCurrent: @Sendable () throws -> Void) throws -> Bool {
        guard started, !closed, !isRetired, let phonePushCapability else { throw AuthorityWakePublisherError.closed }
        try ticket.requireValid()
        guard !startupRestorePending, settingsChange == nil, phonePushCapability.retainedCommitDigest == ticket.commitDigest else {
            throw GatewayPreparationError.changedScope
        }
        if recoveryTicket == nil, acceptedRecoveryTicket === ticket {
            try verifyCurrent(); try Task.checkCancellation(); return false
        }
        guard recoveryTicket === ticket, recoveryDrained else { throw GatewayPreparationError.incomplete }
        try verifyCurrent()
        try phonePushCapability.releaseRecovery(commitDigest: ticket.commitDigest, verifyCurrent: verifyCurrent)
        try ticket.requireValid(); try verifyCurrent(); try Task.checkCancellation()
        recoveryTicket = nil; recoveryDrain = nil; recoveryDrained = false; recoveryStartupHold = false
        acceptedRecoveryTicket = ticket; wakeStatus = .idle; startPublisherLoop()
        return true
    }

    /// Stop and join optional wake publication without closing the foreground service or replacing its clock.
    /// The native owner must authenticate the change and verify its durable scope on each call.
    func quiescePhonePushSettings(_ change: AuthorityPhonePushSettingsChange,
                                  verifyCurrent: @Sendable () throws -> Void) async throws {
        guard started, !closed, !isRetired, let phonePushCapability else { throw AuthorityWakePublisherError.closed }
        guard !startupRestorePending else { throw AuthorityWakePublisherError.busy }
        guard settingsChange == nil || settingsChange == change else { throw GatewayPreparationError.changedScope }
        try phonePushCapability.quiesceSettings(change, verifyCurrent: verifyCurrent)
        if settingsChange == nil {
            let inherited = recoveryDrain
            recoveryTicket?.revoke(); acceptedRecoveryTicket?.revoke()
            recoveryTicket = nil; acceptedRecoveryTicket = nil; recoveryDrain = nil; recoveryDrained = false; recoveryStartupHold = false
            settingsChange = change; settingsDrained = false; wakeStatus = .quiescingForSettings
            let previous = task; task = nil; previous?.cancel()
            let old = publisher; publisher = nil
            if let old { hints.clear(old.hintFeed) }
            settingsDrain = Task {
                await inherited?.value
                await old?.close()
                await previous?.value
            }
        }
        let drain = settingsDrain
        await drain?.value
        guard !closed, !isRetired, settingsChange == change else { throw AuthorityWakePublisherError.closed }
        try verifyCurrent(); try Task.checkCancellation()
        settingsDrained = true; wakeStatus = .suspendedForSettings
    }
    /// Restart optional publication only after the exact selected change has been admitted.
    /// This result does not prove a gateway connection, provider delivery or phone readiness.
    @discardableResult
    func acceptPhonePushSettings(_ change: AuthorityPhonePushSettingsChange,
                                 verifyCurrent: @Sendable () throws -> Void) throws -> Bool {
        guard started, !closed, !isRetired, let phonePushCapability else { throw AuthorityWakePublisherError.closed }
        guard !startupRestorePending else { throw AuthorityWakePublisherError.busy }
        if settingsChange == nil, acceptedSettings == change {
            _ = try phonePushCapability.acceptSettings(change, verifyCurrent: verifyCurrent); return false
        }
        guard settingsChange == change, settingsDrained else { throw GatewayPreparationError.changedScope }
        try phonePushCapability.acceptSettings(change, verifyCurrent: verifyCurrent)
        settingsChange = nil; settingsDrain = nil; settingsDrained = false; acceptedSettings = change
        wakeStatus = .idle; startPublisherLoop()
        return true
    }

    /// A local observation for one exact change. It does not establish gateway delivery or phone readiness.
    func gatewaySettingsObservation(_ change: AuthorityPhonePushSettingsChange) throws -> GatewaySettingsControlObservation {
        guard started, !closed, !isRetired else { throw AuthorityWakePublisherError.closed }
        if settingsChange == change { return settingsDrained ? .suspended : .quiescing }
        if settingsChange == nil, acceptedSettings == change {
            return phonePushCapability?.installedCommitDigest == change.selectedCommitDigest ? .providerInstalled : .accepted
        }
        return .unknown
    }

    /// Start direct request listeners before attempting the optional gateway connection.
    public func start() async throws {
        guard !started, !closed else { throw AuthorityWakePublisherError.closed }
        started = true
        do {
            try Task.checkCancellation()
            try commandExecutionWorker?.start()
            if let commandExecutionWorker {
                executionObserver = Task { [weak self, commandExecutionWorker] in
                    for await _ in commandExecutionWorker.retirement {
                        guard !Task.isCancelled else { return }
                        await self?.commandExecutionDidRetire()
                        return
                    }
                }
            }
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
        startPublisherLoop()
    }
    private func startPublisherLoop() {
        guard !closed, !retired, !startupRestorePending, !recoveryStartupHold, recoveryTicket == nil, settingsChange == nil, task == nil else { return }
        task = Task { [weak self, makePublisher, hints, requestsRetired, interval, initialRetry, maximumRetry] in
            await Self.publish(makePublisher: makePublisher, hints: hints, requestsRetired: requestsRetired,
                interval: interval, initialRetry: initialRetry, maximumRetry: maximumRetry,
                update: { [weak self] publisher, status in await self?.update(publisher: publisher, status: status) ?? false },
                failed: { [weak self] in await self?.publisherDidStop() })
        }
    }
    /// Failed request cleanup remains owned and can be retried. Concurrent callers share one cleanup attempt.
    public func close() async throws {
        closed = true; wakeStatus = .closed; recoveryTicket?.revoke(); acceptedRecoveryTicket?.revoke(); phonePushCapability?.close()
        guard !cleanupComplete else { return }
        if let closing { try await closing.value; return }
        let previous = task; task = nil; previous?.cancel(); commandReceiver?.requestStop(); commandExecutionWorker?.requestStop()
        let observer = receiverObserver; receiverObserver = nil; observer?.cancel()
        let executionObserver = executionObserver; self.executionObserver = nil; executionObserver?.cancel()
        hints.close(); presence?.close()
        let publisher = publisher, drain = settingsDrain, recovery = recoveryDrain, closeRequests = closeRequests, stopRequestProducers = stopRequestProducers, commandReceiver = commandReceiver, commandExecutionWorker = commandExecutionWorker
        let work = Task {
            await commandReceiver?.close()
            await stopRequestProducers()
            await commandExecutionWorker?.close()
            await publisher?.close()
            await previous?.value
            await drain?.value
            await recovery?.value
            await observer?.value
            await executionObserver?.value
            try closeRequests()
        }
        closing = work
        do { try await work.value; cleanupComplete = true; closing = nil; self.publisher = nil }
        catch { closing = nil; throw error }
    }
    private func update(publisher: AuthorityWakePublisher?, status: WakeStatus) -> Bool {
        guard !closed, !retired, !recoveryStartupHold, recoveryTicket == nil, settingsChange == nil else { return false }
        self.publisher = publisher; wakeStatus = status
        return true
    }
    private func commandReceiverDidRetire() async {
        guard !closed else { return }
        retired = true
        receiverObserver = nil // This callback belongs to the observer that is now terminating.
        try? await close()
    }
    private func commandExecutionDidRetire() async {
        guard !closed else { return }
        retired = true
        executionObserver = nil // This callback belongs to the observer that is now terminating.
        try? await close()
    }
    private func publisherDidStop() async {
        guard !closed, !recoveryStartupHold, recoveryTicket == nil, settingsChange == nil else { return }
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
