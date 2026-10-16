import CryptoKit
import Foundation
import RemozioProtocol

/// The transaction validator binds both receipt reads to the current transport policy.
public typealias AuthorityPairingReceiptProvider = @Sendable (
    ApprovalRequestCoordinator, AuthorityPeerBinding, Data, @Sendable (JournalTransaction) throws -> Void
) throws -> Data?

/// A single configured signer, clock contract, and payload budget for all root request operations.
public struct AuthorityRequestProviders: Sendable {
    let configurationBytes: Data
    let requestFrame: AuthorityRequestFrameProvider
    let pendingRequestIDs: AuthorityPendingRequestsProvider
    let exchangeRequest: AuthorityRequestExchangeProvider
    let pairingReceipt: AuthorityPairingReceiptProvider
    let receiptTime: @Sendable () -> UInt64?

    /// Production requires a restored device-bound key. Callbacks must not reenter the service, journal, or request owner.
    public init(configuration: AuthorityServiceConfiguration, signer: EnclaveAuthorityRequestSigner,
                routing: @escaping @Sendable () throws -> PresenceRouting,
                receiptTime: @escaping @Sendable () -> UInt64? = { nil }) throws {
        guard signer.macID == configuration.macID, signer.accountID == configuration.accountID else {
            throw AuthorityRequestSignerError.wrongIdentity
        }
        try self.init(configuration: configuration, publicKey: signer.publicKey,
            signing: { try signer.sign($0) }, routing: routing, receiptTime: receiptTime,
            receiptValidation: AuthoritySelfValidation.validate)
    }

    /// The presence runtime reads the durable mode through each serialized request operation.
    public init(configuration: AuthorityServiceConfiguration, signer: EnclaveAuthorityRequestSigner,
                presence: AuthorityPresenceRuntime, receiptTime: @escaping @Sendable () -> UInt64? = { nil }) throws {
        guard signer.macID == configuration.macID, signer.accountID == configuration.accountID,
              presence.configuration.macID == configuration.macID, presence.configuration.accountID == configuration.accountID else {
            throw AuthorityRequestSignerError.wrongIdentity
        }
        try self.init(configuration: configuration, publicKey: signer.publicKey, signing: { try signer.sign($0) },
            routing: { throw AuthorityPresenceError.unavailable }, receiptTime: receiptTime,
            presence: presence, receiptValidation: AuthoritySelfValidation.validate)
    }

    /// Software signing exists only in internal component fixtures, never as a public custody fallback.
    init(configuration: AuthorityServiceConfiguration, publicKey: Data,
         signing: @escaping @Sendable (Data) throws -> Data,
         routing: @escaping @Sendable () throws -> PresenceRouting,
         receiptTime: @escaping @Sendable () -> UInt64? = { nil },
         presence: AuthorityPresenceRuntime? = nil,
         receiptValidation: @escaping @Sendable (JournalTransaction) throws -> Void = { _ in }) throws {
        guard publicKey.count == 65, publicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil,
              configuration.maximumPayloadBytes > ApprovalMessage.overheadBytes else {
            throw AuthorityServiceConfigurationError.invalidConfiguration
        }
        if let presence {
            guard presence.configuration.macID == configuration.macID, presence.configuration.accountID == configuration.accountID else {
                throw AuthorityPresenceError.wrongScope
            }
        }
        configurationBytes = configuration.canonicalBytes
        self.receiptTime = receiptTime
        let bodyBudget = configuration.maximumRequestBodyBytes
        let statusBudget = min(bodyBudget, AuthorityRequestExchange.maximumFrameBytes - ApprovalMessage.overheadBytes)
        requestFrame = { owner, binding, id, clock in
            try Self.requireScope(binding, configuration: configuration)
            let frameRouting = try presence?.deliveryRouting(owner: owner)
            return try owner.retainedDeliveryFrame(binding: binding, requestID: id, authorityPublicKey: publicKey,
                maximumBodyBytes: bodyBudget, now: clock, routing: { try frameRouting?(clock()) ?? routing() }, receiptTimeMs: receiptTime(), signer: signing)
        }
        pendingRequestIDs = { owner, binding, clock in
            try Self.requireScope(binding, configuration: configuration)
            let moment = try clock()
            return try owner.pendingDeliveryRequestIDs(binding: binding, routing: presence?.routing(owner: owner, now: moment) ?? routing(), now: moment)
        }
        exchangeRequest = { owner, binding, id, decision, clock in
            try Self.requireScope(binding, configuration: configuration)
            return try owner.exchangeRequest(binding: binding, requestID: id, decisionFrame: decision, authorityPublicKey: publicKey,
                maximumBodyBytes: statusBudget, now: clock, receiptTimeMs: receiptTime(), signer: signing)
        }
        pairingReceipt = { owner, binding, setupID, validateTransport in
            try Self.requireScope(binding, configuration: configuration)
            guard setupID.count == 16 else { throw AuthorityXPCError.invalidMessage }
            return try owner.pairingReceipt(setupID: setupID, binding: binding, authorityPublicKey: publicKey,
                verifyHost: { transaction in
                    try receiptValidation(transaction)
                    try validateTransport(transaction)
                }, sign: signing)
        }
    }
    func expirePending(_ owner: ApprovalRequestCoordinator, clock: @Sendable () throws -> AuthorityMoment) throws -> [ApprovalRequestState] {
        try owner.expirePending(now: clock(), receiptTimeMs: receiptTime())
    }
    func requireConfiguration(_ configuration: AuthorityServiceConfiguration) throws {
        guard configuration.canonicalBytes == configurationBytes else { throw AuthorityServiceConfigurationError.invalidConfiguration }
    }
    private static func requireScope(_ binding: AuthorityPeerBinding, configuration: AuthorityServiceConfiguration) throws {
        guard binding.scope.macID == configuration.macID, binding.scope.accountID == configuration.accountID else {
            throw AuthorityRequestSignerError.wrongIdentity
        }
    }
}
