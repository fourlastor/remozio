import Foundation
import RemozioProtocol

/// Trusted root provider. Use the supplied clock for request checks, including a fresh sample after signing.
public typealias AuthorityRequestFrameProvider = @Sendable (
    ApprovalRequestCoordinator, AuthorityPeerBinding, Data, @Sendable () throws -> AuthorityMoment
) throws -> Data?

/// Trusted discovery provider. Use the authority clock and current local presence when scanning requests.
public typealias AuthorityPendingRequestsProvider = @Sendable (
    ApprovalRequestCoordinator, AuthorityPeerBinding, @Sendable () throws -> AuthorityMoment
) throws -> [Data]

/// Trusted state/decision provider. Use the supplied authority clock and the configured body budget.
public typealias AuthorityRequestExchangeProvider = @Sendable (
    ApprovalRequestCoordinator, AuthorityPeerBinding, Data, Data?, @Sendable () throws -> AuthorityMoment
) throws -> Data?

/// Owns one authority listener and its journal for a single service lifetime.
/// Protected installation and configuration loading must precede construction.
public final class AuthorityService: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let journal: AuthorityJournal
    private let listener: AuthorityXPCListener
    private var maintenance: AuthorityMaintenanceLoop?
    private let requestClock: @Sendable () throws -> AuthorityMoment
    private let onMaintenanceFailure: @Sendable () -> Void
    private var started = false
    private var closed = false

    /// Opens the provisioned launch stores. Version 2 retains independent continuity ownership until shutdown.
    public convenience init(configuration: AuthorityServiceConfiguration) throws {
        try self.init(configuration: configuration, journal: Self.openJournal(configuration: configuration))
    }

    /// Opens existing paired stores, restores the pinned enclave signer, and prepares the complete request service.
    /// Callbacks are required, synchronous, and must not reenter the service or journal. No listener starts here.
    public convenience init(requestStartup: AuthorityRequestStartupConfiguration,
                            routing: @escaping @Sendable () throws -> PresenceRouting,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            onMaintenanceFailure: @escaping @Sendable () -> Void = {},
                            onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws {
        try self.init(requestStartup: requestStartup,
            openJournal: { try Self.openJournal(configuration: requestStartup.service) },
            loadSigner: { journal in
                try EnclaveAuthorityRequestSigner.load(path: requestStartup.keyRecordPath,
                    configuration: requestStartup.service, expectedPublicKey: requestStartup.authorityPublicKey, journal: journal)
            }, routing: routing, reconcileExpired: reconcileExpired, onMaintenanceFailure: onMaintenanceFailure, onCommandAuthorized: onCommandAuthorized)
    }

    /// Fixture storage/key-loading seam. It preserves hardware-only signing and production service self-validation.
    convenience init(requestStartup: AuthorityRequestStartupConfiguration,
                     openJournal: () throws -> AuthorityJournal,
                     loadSigner: (AuthorityJournal) throws -> EnclaveAuthorityRequestSigner,
                     routing: @escaping @Sendable () throws -> PresenceRouting,
                     reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                     onMaintenanceFailure: @escaping @Sendable () -> Void = {},
                     onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws {
        let journal = try openJournal()
        do {
            let signer = try loadSigner(journal)
            let providers = try AuthorityRequestProviders(configuration: requestStartup.service, signer: signer, routing: routing)
            try self.init(configuration: requestStartup.service, journal: journal, requestProviders: providers,
                maintenanceIntervalMilliseconds: requestStartup.maintenanceIntervalMilliseconds, reconcileExpired: reconcileExpired,
                onMaintenanceFailure: onMaintenanceFailure, onCommandAuthorized: onCommandAuthorized)
        } catch {
            try? journal.close()
            throw error
        }
    }

    static func openJournal(configuration: AuthorityServiceConfiguration, routingPolicy: RoutingJournalPolicy? = nil, gatewayPolicy: GatewayAuthorityPolicy? = nil) throws -> AuthorityJournal {
        let journal: AuthorityJournal
        if configuration.continuityDirectory != nil {
            journal = try AuthorityJournal(recovering: AuthorityStorage.open(configuration: configuration, routingPolicy: routingPolicy, gatewayPolicy: gatewayPolicy),
                macID: configuration.macID, accountID: configuration.accountID)
        } else {
            let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
            journal = try AuthorityJournal(database: JournalDatabase.open(directoryPath: configuration.journalDirectory,
                macID: configuration.macID, accountID: configuration.accountID,
                recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 1_000_000, busyMilliseconds: 5000, gatewayPolicy: gatewayPolicy, routingPolicy: routingPolicy))
        }
        return journal
    }

    /// Transfers the database to this service. Construction failure releases its writer lease.
    public convenience init(configuration: AuthorityServiceConfiguration, database: sending JournalDatabase) throws {
        try self.init(configuration: configuration, journal: AuthorityJournal(database: database))
    }

    /// Shares the prepared request owner with the service. Service closure retires that owner too.
    public convenience init(configuration: AuthorityServiceConfiguration, journal: AuthorityJournal,
                            maintenanceIntervalMilliseconds: Int = 1000,
                            maintain: (@Sendable () throws -> Void)? = nil,
                            requestFrame: AuthorityRequestFrameProvider? = nil,
                            pendingRequestIDs: AuthorityPendingRequestsProvider? = nil,
                            exchangeRequest: AuthorityRequestExchangeProvider? = nil,
                            onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws {
        try self.init(configuration: configuration, journal: journal, maintenanceIntervalMilliseconds: maintenanceIntervalMilliseconds,
            maintain: maintain, validateSelf: AuthoritySelfValidation.validate, requestFrame: requestFrame, pendingRequestIDs: pendingRequestIDs, exchangeRequest: exchangeRequest,
            onCommandAuthorized: onCommandAuthorized)
    }

    /// Installs discovery, signed request delivery, decision/status exchange, and periodic expiry with the same service clock.
    /// Protected signer loading and provisioning must precede construction. Closure retires the shared request owner.
    public convenience init(configuration: AuthorityServiceConfiguration, journal: AuthorityJournal,
                            requestProviders: AuthorityRequestProviders, maintenanceIntervalMilliseconds: Int = 1000,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            onMaintenanceFailure: @escaping @Sendable () -> Void = {},
                            onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws {
        try self.init(configuration: configuration, journal: journal, maintenanceIntervalMilliseconds: maintenanceIntervalMilliseconds,
            validateSelf: AuthoritySelfValidation.validate, requestProviders: requestProviders, reconcileExpired: reconcileExpired,
            onMaintenanceFailure: onMaintenanceFailure, onCommandAuthorized: onCommandAuthorized)
    }

    /// Internal lifecycle fixture. Public constructors always validate the running authority against retained policy.
    init(configuration: AuthorityServiceConfiguration, journal: AuthorityJournal,
         maintenanceIntervalMilliseconds: Int = 1000, maintain: (@Sendable () throws -> Void)? = nil,
         validateSelf: @Sendable (AuthorityJournal) throws -> Void,
         requestClock: (@Sendable () throws -> AuthorityMoment)? = nil,
         requestFrame: AuthorityRequestFrameProvider? = nil,
         pendingRequestIDs: AuthorityPendingRequestsProvider? = nil,
         exchangeRequest: AuthorityRequestExchangeProvider? = nil,
         requestProviders: AuthorityRequestProviders? = nil,
         phonePushRegistration: AuthorityPhonePushRegistrationProvider? = nil,
         phonePushRecovery: AuthorityPhonePushRecoveryProvider? = nil,
         wakeHintFeed: AuthorityWakeHintFeed? = nil,
         wakeHints: (@Sendable () throws -> AuthorityWakeHints)? = nil,
         reconcileExpired: (@Sendable ([ApprovalRequestState]) throws -> Void)? = nil,
         onMaintenanceFailure: @escaping @Sendable () -> Void = {},
         onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws {
        self.journal = journal
        self.onMaintenanceFailure = onMaintenanceFailure
        do {
            if let requestClock { self.requestClock = requestClock }
            else {
                let clock = try AuthorityClock()
                self.requestClock = { try clock.now() }
            }
        } catch { try? journal.close(); throw error }
        do {
            try validateSelf(journal)
            try requestProviders?.requireConfiguration(configuration)
            guard requestProviders == nil || (requestFrame == nil && pendingRequestIDs == nil && exchangeRequest == nil && maintain == nil) else {
                throw AuthorityServiceConfigurationError.invalidConfiguration
            }
            let selectedFrame = requestProviders?.requestFrame ?? requestFrame
            let selectedPending = requestProviders?.pendingRequestIDs ?? pendingRequestIDs
            let selectedExchange = requestProviders?.exchangeRequest ?? exchangeRequest
            let frameClock = self.requestClock
            let frameHandler: (@Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding, Data) throws -> Data?)?
            if let selectedFrame {
                frameHandler = { owner, binding, requestID in try selectedFrame(owner, binding, requestID, frameClock) }
            } else { frameHandler = nil }
            let pendingHandler: (@Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding) throws -> [Data])?
            if let selectedPending {
                pendingHandler = { owner, binding in try selectedPending(owner, binding, frameClock) }
            } else { pendingHandler = nil }
            let exchangeHandler: (@Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding, Data, Data?) throws -> Data?)?
            if let selectedExchange {
                exchangeHandler = { owner, binding, id, decision in try selectedExchange(owner, binding, id, decision, frameClock) }
            } else { exchangeHandler = nil }
            let hintHandler: (@Sendable () throws -> AuthorityWakeHints)?
            guard wakeHintFeed == nil || wakeHints == nil else { throw AuthorityServiceConfigurationError.invalidConfiguration }
            if let wakeHints { hintHandler = wakeHints }
            else if let wakeHintFeed { hintHandler = { try wakeHintFeed.current() } }
            else { hintHandler = nil }
            listener = try AuthorityXPCListener(serviceName: configuration.serviceName,
                peerPolicy: configuration.transportPolicy, macID: configuration.macID,
                accountID: configuration.accountID, journal: journal,
                maximumPayloadBytes: configuration.maximumPayloadBytes,
                minimumEnvelopeVersion: configuration.minimumEnvelopeVersion,
                auditVersions: configuration.auditVersions,
                maximumConnections: configuration.maximumConnections,
                handshakeTimeoutMilliseconds: configuration.handshakeTimeoutMilliseconds,
                maximumOperations: configuration.maximumOperations, requestFrame: frameHandler, pendingRequestIDs: pendingHandler,
                exchangeRequest: exchangeHandler, pairingReceipt: requestProviders?.pairingReceipt,
                phonePushRegistration: phonePushRegistration, phonePushRecovery: phonePushRecovery,
                wakeHints: hintHandler, onCommandAuthorized: onCommandAuthorized)
            let requestEpoch = try self.requestClock().epoch
            try journal.prepareRequests(clockEpoch: requestEpoch, maximumPayloadBytes: configuration.maximumPayloadBytes)
            if let requestProviders, let reconcileExpired {
                let clock = self.requestClock
                maintenance = try AuthorityMaintenanceLoop(intervalMilliseconds: maintenanceIntervalMilliseconds, work: {
                    try journal.withRequests { owner in
                        let states = try requestProviders.expirePending(owner, clock: clock)
                        try reconcileExpired(states)
                    }
                }, failed: { [weak self] in self?.maintenanceDidFail() })
            } else if let maintain {
                maintenance = try AuthorityMaintenanceLoop(intervalMilliseconds: maintenanceIntervalMilliseconds,
                    work: maintain, failed: { [weak self] in self?.maintenanceDidFail() })
            }
        } catch {
            try? journal.close()
            throw error
        }
    }

    /// Samples authority time under the request lock and reconciles committed expiry before releasing it.
    /// Clock and reconciliation callbacks must be synchronous and must not reenter this service or journal.
    public convenience init(configuration: AuthorityServiceConfiguration, journal: AuthorityJournal,
                            maintenanceIntervalMilliseconds: Int = 1000,
                            expiryClock: @escaping @Sendable () throws -> AuthorityMoment,
                            receiptTime: @escaping @Sendable () -> UInt64? = { nil },
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            requestFrame: AuthorityRequestFrameProvider? = nil,
                            pendingRequestIDs: AuthorityPendingRequestsProvider? = nil,
                            exchangeRequest: AuthorityRequestExchangeProvider? = nil,
                            onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws {
        try self.init(configuration: configuration, journal: journal,
            maintenanceIntervalMilliseconds: maintenanceIntervalMilliseconds, expiryClock: expiryClock,
            receiptTime: receiptTime, reconcileExpired: reconcileExpired, validateSelf: AuthoritySelfValidation.validate, requestFrame: requestFrame, pendingRequestIDs: pendingRequestIDs, exchangeRequest: exchangeRequest,
            onCommandAuthorized: onCommandAuthorized)
    }

    /// Fixture seam for the same expiry path used by public construction.
    convenience init(configuration: AuthorityServiceConfiguration, journal: AuthorityJournal,
                     maintenanceIntervalMilliseconds: Int = 1000,
                     expiryClock: @escaping @Sendable () throws -> AuthorityMoment,
                     receiptTime: @escaping @Sendable () -> UInt64? = { nil },
                     reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                     validateSelf: @Sendable (AuthorityJournal) throws -> Void,
                     requestFrame: AuthorityRequestFrameProvider? = nil,
         pendingRequestIDs: AuthorityPendingRequestsProvider? = nil,
         exchangeRequest: AuthorityRequestExchangeProvider? = nil,
         onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws {
        try self.init(configuration: configuration, journal: journal,
            maintenanceIntervalMilliseconds: maintenanceIntervalMilliseconds, maintain: {
                try journal.withRequests { requests in
                    let states = try requests.expirePending(now: expiryClock(), receiptTimeMs: receiptTime())
                    try reconcileExpired(states)
                }
            }, validateSelf: validateSelf, requestClock: expiryClock, requestFrame: requestFrame, pendingRequestIDs: pendingRequestIDs, exchangeRequest: exchangeRequest,
            onCommandAuthorized: onCommandAuthorized)
    }

    deinit { maintenance?.close(); listener.close(); try? journal.close() }

    /// A failed start retires this instance. Recovery requires a new protected startup.
    public func start() throws {
        try lock.withLock {
            guard !started, !closed else { throw AuthorityXPCEndpointError.unavailable }
            do {
                try listener.start()
                try maintenance?.start()
                started = true
            } catch {
                closed = true
                maintenance?.close()
                listener.close()
                try? journal.close()
                throw error
            }
        }
    }

    /// Maintenance calls this after releasing its work lock. Report retirement once after attempting service closure.
    /// The observer must return promptly and must not reenter this service or journal.
    func maintenanceDidFail() {
        let notify = lock.withLock {
            guard !closed else { return false }
            try? close()
            return true
        }
        if notify { onMaintenanceFailure() }
    }

    /// Stops admissions before waiting for any journal transaction and releasing storage.
    public func close() throws {
        try lock.withLock {
            closed = true
            maintenance?.close()
            listener.close()
            try journal.close()
        }
    }
}
