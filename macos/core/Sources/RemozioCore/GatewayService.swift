import Darwin
import Foundation
import RemozioProtocol
import Synchronization

actor GatewayRootDispatcher {
    let coordinator: GatewayDeliveryCoordinator
    let lease: GatewayAuthorityLease
    let receipts: GatewayReceiptSigner
    let retryInterval: UInt64
    private var scheduling = false
    init(coordinator: GatewayDeliveryCoordinator, lease: GatewayAuthorityLease, receipts: GatewayReceiptSigner, retryInterval: UInt64) {
        self.coordinator = coordinator; self.lease = lease; self.receipts = receipts; self.retryInterval = retryInterval
    }
    func synchronize(_ snapshot: GatewayHostSnapshot) async throws {
        try Task.checkCancellation()
        try await coordinator.synchronizeHost(snapshot, lease: lease)
        if !scheduling {
            try await coordinator.startWakeScheduling(retryIntervalMillis: retryInterval)
            scheduling = true
        }
    }
    func execute(_ command: GatewayRootCommand) async throws -> Data {
        try Task.checkCancellation()
        switch command {
        case .head(let query):
            let result = try await coordinator.recoveryHeadReply(canonicalQuery: query, sign: receipts.sign)
            return try GatewayRootCommand.reply([.bytes(result.canonicalPayload), .bytes(result.signature)])
        case .history(let query):
            let result = try await coordinator.recoveryHistoryReply(canonicalQuery: query, sign: receipts.sign)
            return try GatewayRootCommand.reply([.bytes(result.canonicalPayload), .bytes(result.signature)])
        case .candidate(let payload, let signature, let version, let phone, let token):
            let result = try await coordinator.admitCandidate(canonicalPayload: payload, signature: signature,
                wireVersion: version, registrationToken: token, phoneID: phone)
            return try GatewayRootCommand.reply([.bytes(result.receipt.canonicalPayload), .bytes(result.receipt.signature), .boolean(result.inserted)])
        case .recipient(let payload, let signature, let version, let phone, let kind):
            let result = try await coordinator.applyRecipient(canonicalPayload: payload, signature: signature,
                wireVersion: version, kind: kind, phoneID: phone)
            return try GatewayRootCommand.reply([.bytes(result.receipt.canonicalPayload), .bytes(result.receipt.signature), .boolean(result.inserted)])
        case .submission(let payload, let signature, let version):
            let result = try await coordinator.applySubmission(canonicalPayload: payload, signature: signature, wireVersion: version)
            return try GatewayRootCommand.reply([.bytes(result.receipt.canonicalPayload), .bytes(result.receipt.signature), .boolean(result.inserted)], version: 2)
        case .probe(let operation, let phone):
            try await coordinator.startProbe(operationID: operation, phoneID: phone)
            return try GatewayRootCommand.reply([.boolean(true)])
        case .wake(let delivery):
            _ = try await coordinator.enqueueWake(lease.normalize(delivery))
            return try GatewayRootCommand.reply([.boolean(true)])
        case .registerWake(let delivery):
            _ = try await coordinator.registerWake(lease.normalize(delivery))
            return try GatewayRootCommand.reply([.boolean(true)], version: 3)
        case .withdraw(let id):
            try lease.validate()
            try await coordinator.cancelWake(deliveryID: id)
            return try GatewayRootCommand.reply([.boolean(true)])
        }
    }
}

private final class GatewayRetirementSignal: Sendable { let value = Mutex(false) }

/// Native push service ownership. Protected installation must provision its private files and existing journal first.
public final class GatewayService: Sendable {
    private let coordinator: GatewayDeliveryCoordinator
    private let lease: GatewayAuthorityLease
    private let listener: GatewayXPCListener
    private let wakeListener: GatewayWakeXPCListener?
    private let retired: GatewayRetirementSignal
    private init(coordinator: GatewayDeliveryCoordinator, lease: GatewayAuthorityLease,
                 listener: GatewayXPCListener, wakeListener: GatewayWakeXPCListener?, retired: GatewayRetirementSignal) {
        self.coordinator = coordinator; self.lease = lease; self.listener = listener; self.wakeListener = wakeListener; self.retired = retired
    }
    public var isRetired: Bool { retired.value.withLock { $0 } }

    public static func open(configuration: GatewayServiceConfiguration) async throws -> GatewayService {
        try configuration.requireNativeProcess()
        try Task.checkCancellation()
        let credentials = try GatewayServiceCredentials.load(configuration: configuration), clock = try AuthorityClock()
        let lease = try GatewayAuthorityLease(clock: clock, maximumLifetime: configuration.settings.authorityLeaseMillis)
        let settings = configuration.settings
        let oauth = try FCMOAuthClient(account: credentials.account, timeoutSeconds: Double(settings.providerTimeoutSeconds))
        let tokens = try FCMTokenSource(client: oauth, maximumWaiters: settings.maximumOperations)
        let sender = try FCMWakeSender(project: configuration.project, packageName: configuration.packageName,
            timeoutSeconds: Double(settings.providerTimeoutSeconds))
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 8, maxItems: 256)
        let database = try GatewayDatabase.open(directoryPath: configuration.directoryPath, serviceUID: configuration.serviceUID,
            identity: configuration.registration, payloadLimits: limits, signingLimits: limits,
            maximumOperations: settings.maximumStoredControls, maximumPendingPerEnrollment: settings.maximumPendingPerEnrollment,
            maximumLifetimeMillis: settings.maximumCandidateLifetimeMillis, clockEpoch: clock.epoch,
            busyMilliseconds: settings.databaseBusyMillis, initialize: false, migrateLegacyStore: false, probePolicy: settings.probe)
        let coordinator: GatewayDeliveryCoordinator
        do {
            coordinator = try GatewayDeliveryCoordinator(database: database, identity: configuration.registration,
                tokens: tokens, sender: sender, policy: settings.delivery, clockEpoch: clock.epoch,
                wakePolicy: settings.wake, validateAuthority: { try lease.validate() })
        } catch { await tokens.shutdown(); throw error }
        let dispatcher = GatewayRootDispatcher(coordinator: coordinator, lease: lease, receipts: credentials.receipts,
            retryInterval: settings.schedulerRetryMillis)
        let retired = GatewayRetirementSignal()
        do {
            let listener = try GatewayXPCListener(configuration: configuration, lost: {
                lease.retire(); retired.value.withLock { $0 = true }
                Task { await coordinator.authorityUnavailable() }
            }, synchronize: { try await dispatcher.synchronize($0) }, execute: { try await dispatcher.execute($0) })
            let wakeListener = try configuration.wakeEndpoint.map { endpoint in
                try GatewayWakeXPCListener(configuration: endpoint, serviceUID: configuration.serviceUID, clock: clock,
                    handshakeTimeoutMillis: settings.handshakeTimeoutMillis, execute: { submission, signature, challenge in
                        _ = try await coordinator.submitWake(submission, signature: signature, challenge: challenge)
                    })
            }
            return GatewayService(coordinator: coordinator, lease: lease, listener: listener, wakeListener: wakeListener, retired: retired)
        } catch { lease.retire(); try await coordinator.shutdown(); throw error }
    }
    public func start() throws {
        guard !isRetired else { throw GatewayServiceError.unavailable }
        do { try listener.start(); try wakeListener?.start() }
        catch { lease.retire(); retired.value.withLock { $0 = true }; listener.close(); wakeListener?.close(); throw error }
    }
    public func close() async throws {
        lease.retire(); retired.value.withLock { $0 = true }; listener.close(); wakeListener?.close()
        try await coordinator.shutdown()
    }
}
