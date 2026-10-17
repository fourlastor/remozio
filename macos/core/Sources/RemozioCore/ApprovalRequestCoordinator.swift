import CryptoKit
import Foundation
import RemozioProtocol
import Security

public enum ApprovalCoordinatorError: Error, Equatable {
    case invalidConfiguration, invalidDraft, capacityExceeded, unavailable, invalidClock, unknownRequest, notPending, wrongPhone, expired
}

public enum PendingRequestRetirement: Sendable {
    case cancelled, deadlineElapsed, targetTimedOut, targetDisappeared, authorityRestart
}

/// Trusted adapter input after capture validation. The coordinator supplies scope, request ID, and fresh challenge.
public struct ApprovalRequestDraft: Sendable {
    public let contract: RequestContract
    public let requiredFeatures: Set<UInt64>
    public let capture: Data
    public let actions: [CapturedAction]
    public let firstObservedAt: AuthorityMoment
    public let deadlineMilliseconds: UInt64
    public let createdUnixMilliseconds: UInt64
    public let expiresUnixMilliseconds: UInt64
    public let observationID: Data?
    public let estimatedLifetimeMilliseconds: UInt64?
    public let lateObservation: Bool
    public init(contract: RequestContract, requiredFeatures: Set<UInt64>, capture: Data, actions: [CapturedAction],
                firstObservedAt: AuthorityMoment, deadlineMilliseconds: UInt64,
                createdUnixMilliseconds: UInt64, expiresUnixMilliseconds: UInt64, observationID: Data? = nil,
                estimatedLifetimeMilliseconds: UInt64? = nil, lateObservation: Bool = false) {
        self.contract = contract; self.requiredFeatures = requiredFeatures; self.capture = capture; self.actions = actions
        self.firstObservedAt = firstObservedAt; self.deadlineMilliseconds = deadlineMilliseconds
        self.createdUnixMilliseconds = createdUnixMilliseconds; self.expiresUnixMilliseconds = expiresUnixMilliseconds
        self.observationID = observationID; self.estimatedLifetimeMilliseconds = estimatedLifetimeMilliseconds
        self.lateObservation = lateObservation
    }
}

/// Local state observation. It is not a signed status response or an execution permit.
public struct ApprovalRequestState: Equatable, Sendable {
    public let requestKind: RequestKind
    public let macID: Data
    public let accountID: Data
    public let requestDigest: Data
    public let challenge: Data
    public let reason: RequestStatusReason
    public let terminalAt: AuthorityMoment?
    public let decisionPhoneID: Data?
    public let requestID: Data
    public let phase: RequestPhase
    public let revision: UInt64
    public let firstObservedAt: AuthorityMoment
    public let deadlineMilliseconds: UInt64

    /// V1 status projection. The host supplies a fresh observation revision and authenticates the response separately.
    public func statusPayload(observationID: Data, observationRevision: UInt64, now: AuthorityMoment,
                              estimatedLifetimeMs: UInt64?, lateObservation: Bool) throws -> RequestStatusPayload {
        guard now.epoch == firstObservedAt.epoch, now.milliseconds >= firstObservedAt.milliseconds,
              terminalAt == nil || (terminalAt!.epoch == now.epoch && terminalAt!.milliseconds <= now.milliseconds) else {
            throw ApprovalCoordinatorError.invalidClock
        }
        let pending = phase == .queued || phase == .presented
        let wirePhase: RequestPhase = phase == .unknown && reason == .targetDisappeared ? .cancelled : phase
        return try RequestStatusPayload(macID: macID, accountID: accountID, requestID: requestID,
            requestDigest: requestDigest, challenge: challenge, revision: observationRevision, phase: wirePhase, reason: reason,
            observationID: observationID, observedAgeMs: now.milliseconds - firstObservedAt.milliseconds,
            authorizationRemainingMs: pending ? (now.milliseconds < deadlineMilliseconds ? deadlineMilliseconds - now.milliseconds : 0) : nil,
            estimatedLifetimeMs: estimatedLifetimeMs, lateObservation: lateObservation,
            terminalAgeMs: terminalAt.map { $0.milliseconds - firstObservedAt.milliseconds }, decisionPhoneID: decisionPhoneID)
    }
}

/// The service serializes this non-Sendable owner with all other journal users and adapter observations.
/// Construct only after authority continuity and admission-storage gates pass. This owner never dispatches target actions.
public final class ApprovalRequestCoordinator {
    let database: JournalDatabase
    private let writer: AuditEpochWriter
    private let mac: Data
    private let account: Data
    private let clockEpoch: UUID
    private let maximumRequests: Int
    private let maximumRetainedBytes: Int
    private let requestLimits: CBORLimits
    private let captureLimits: CBORLimits
    private let decisionLimits: CBORLimits
    private let signingLimits: CBORLimits
    private let auditLimits: CBORLimits
    private var lastTime: UInt64?
    private var stopped = false
    private var releaseActivity: ReleaseActivityBarrier?
    var retired: Bool { stopped || database.retired || checkpointed?.retired == true }
    private var checkpointed: CheckpointedJournal?
    private var retainedBytes = 0
    private var deliveryBytes = 0
    private let wakePublication: RetainedWakePublication
    private struct Entry {
        var state: ApprovalRequestState
        let contract: RequestContract
        let permittedActions: Set<CapturedAction>
        let observationID: Data
        let estimatedLifetimeMilliseconds: UInt64?
        let lateObservation: Bool
        var statusRevision: UInt64 = 0
        var retained: RetainedApprovalRequest?
        var command: RetainedCommandCapture?
        var activity: ReleaseActivityToken?
        let category: AuditCategory
        var byteCount: Int
        var delivery: PendingRequestDelivery?
        var frame: Data?
        var frameKey: Data?
        var commandApprovalEnrollment: CommandApprovalEnrollment?
    }
    private var entries: [Data: Entry] = [:]
    private var expiryNotifications: [Data: ApprovalRequestState] = [:]

    public init(database: JournalDatabase, writer: AuditEpochWriter, clockEpoch: UUID,
                maximumRequests: Int, maximumRetainedBytes: Int, requestLimits: CBORLimits, captureLimits: CBORLimits,
                decisionLimits: CBORLimits, signingLimits: CBORLimits, auditLimits: CBORLimits,
                maximumWakeDeliveries: Int = 1024) throws {
        guard (1...4096).contains(maximumRequests), (1...67_108_864).contains(maximumRetainedBytes),
              (1...AuthorityWakeHints.maximumDeliveries).contains(maximumWakeDeliveries),
              requestLimits.maxBytes <= maximumRetainedBytes else { throw ApprovalCoordinatorError.invalidConfiguration }
        let scope = try database.read { tx -> ApprovalTrustSnapshot in
            let trust = try tx.approvalTrustSnapshot()
            guard let epoch = try tx.epoch(writer.epoch), epoch.descriptor.macID == trust.macID,
                  epoch.descriptor.accountID == trust.accountID else { throw AuditJournalError.unavailableEpoch }
            return trust
        }
        self.database = database; self.writer = writer; self.clockEpoch = clockEpoch
        mac = scope.macID; account = scope.accountID
        self.maximumRequests = maximumRequests; self.maximumRetainedBytes = maximumRetainedBytes
        wakePublication = RetainedWakePublication(maximumDeliveries: maximumWakeDeliveries)
        self.requestLimits = requestLimits; self.captureLimits = captureLimits; self.decisionLimits = decisionLimits
        self.signingLimits = signingLimits; self.auditLimits = auditLimits
    }

    /// The host retains both store leases and completes startup recovery before supplying the writer.
    convenience init(database: JournalDatabase, continuity: ContinuityStore, writer: AuditEpochWriter, clockEpoch: UUID,
                     maximumRequests: Int, maximumRetainedBytes: Int, requestLimits: CBORLimits, captureLimits: CBORLimits,
                     decisionLimits: CBORLimits, signingLimits: CBORLimits, auditLimits: CBORLimits) throws {
        try self.init(database: database, writer: writer, clockEpoch: clockEpoch, maximumRequests: maximumRequests,
            maximumRetainedBytes: maximumRetainedBytes, requestLimits: requestLimits, captureLimits: captureLimits,
            decisionLimits: decisionLimits, signingLimits: signingLimits, auditLimits: auditLimits)
        let commits = CheckpointedJournal(journal: database, continuity: continuity)
        try commits.read { _ in () }
        checkpointed = commits
    }

    func attachReleaseActivityBarrier(_ barrier: ReleaseActivityBarrier) throws {
        try running()
        guard entries.isEmpty, releaseActivity == nil else { throw ApprovalCoordinatorError.invalidConfiguration }
        try barrier.validate()
        releaseActivity = barrier
    }

    /// Product pairing requires the independent store. Unpaired owners remain internal component fixtures only.
    func requirePairingCheckpoint() throws {
        try running()
        guard checkpointed != nil else { throw ApprovalCoordinatorError.unavailable }
    }

    /// Local setup only. The host rechecks administrator consent inside the checkpointed commit.
    /// A signing failure after commit is ambiguous; recover the retained receipt instead of enrolling again.
    func commitPairing(_ attempt: PairingEnrollmentAttempt, biometricProof: Data, authorityPublicKey: Data,
                       addEventID: Data, removalEventID: Data?, receiptTimeMs: UInt64?, gateway: EnrollmentGatewayRemoval?,
                       verifyHost: (JournalTransaction) throws -> Void, recheckAdministrator: () throws -> Void,
                       now: () throws -> AuthorityMoment, sign: (Data) throws -> Data)
        throws -> (revision: UUID, receipt: Data, gatewayControl: GatewayAuthorityEnvelope?) {
        let transcript = attempt.transcript
        guard transcript.phone.scope.macID == mac, transcript.phone.scope.accountID == account,
              transcript.macAuthorityKey == authorityPublicKey else { throw PairingEnrollmentError.wrongContext }
        let committed = try write { tx in
            try verifyHost(tx)
            try recheckAdministrator()
            return try attempt.commit(transaction: tx, biometricProof: biometricProof, writer: writer,
                expectedAuditHead: head(tx), addEventID: addEventID, removalEventID: removalEventID,
                receiptTimeMs: receiptTimeMs, gateway: gateway, now: {
                    let moment = try now(); try checkClock(moment); return moment
                })
        }
        let receipt = try retainedPairingReceipt(setupID: transcript.setupID, phoneID: transcript.phone.scope.phoneID,
            epoch: transcript.phone.scope.enrollmentEpoch, authorityPublicKey: authorityPublicKey,
            verifyHost: verifyHost, sign: sign)
        guard let receipt else { throw EnrollmentJournalError.unavailableEnrollment }
        return (committed.revision, receipt, committed.gatewayControl)
    }

    /// The transport supplies the authenticated binding. Expiry does not undo an already durable enrollment.
    func pairingReceipt(setupID: Data, binding: AuthorityPeerBinding, authorityPublicKey: Data,
                        verifyHost: (JournalTransaction) throws -> Void, sign: (Data) throws -> Data) throws -> Data? {
        guard binding.scope.macID == mac, binding.scope.accountID == account else { throw PairingEnrollmentError.wrongContext }
        return try retainedPairingReceipt(setupID: setupID, phoneID: binding.scope.phoneID,
            epoch: binding.scope.enrollmentEpoch, authorityPublicKey: authorityPublicKey,
            verifyHost: { tx in try verifyHost(tx); try tx.requireDirectApprovalBinding(binding) }, sign: sign)
    }

    private func retainedPairingReceipt(setupID: Data, phoneID: Data, epoch: Data, authorityPublicKey: Data,
                                       verifyHost: (JournalTransaction) throws -> Void, sign: (Data) throws -> Data) throws -> Data? {
        func retained(_ tx: JournalTransaction) throws -> PairingTranscript? {
            try verifyHost(tx)
            guard let transcript = try tx.committedPairing(setupID: setupID, authenticatedPhoneID: phoneID,
                authenticatedEnrollmentEpoch: epoch) else { return nil }
            guard transcript.phone.scope.macID == mac, transcript.phone.scope.accountID == account,
                  transcript.macAuthorityKey == authorityPublicKey else { throw PairingEnrollmentError.wrongContext }
            return transcript
        }
        guard let transcript = try read(retained) else { return nil }
        let receipt = try sign(transcript.signingInput(purpose: .macCommit))
        guard try transcript.verify(signature: receipt, publicKey: authorityPublicKey, purpose: .macCommit) else {
            throw PairingEnrollmentError.invalidProof
        }
        guard let current = try read(retained), try current.encode() == transcript.encode() else {
            throw EnrollmentJournalError.unavailableEnrollment
        }
        return receipt
    }

    deinit { close() }

    /// Retires live requests and their OS resources. The journal owner closes storage separately.
    /// This does not overwrite durable decisions or claim an execution outcome.
    public func close() {
        stopped = true
        for entry in entries.values {
            notifyCommandTerminal(entry, outcome: .unknown)
            entry.command?.close()
            entry.activity?.close()
        }
        entries.removeAll(); expiryNotifications.removeAll(); retainedBytes = 0; deliveryBytes = 0
        wakePublication.close()
    }

    /// Transfers the command once. Callers cannot reuse the command or its aliases after this call.
    /// The draft must contain its exact capture and the command action set.
    /// A first transfer owns resources on success or failure. A repeated transfer leaves the existing owner intact.
    /// The host must complete current elevation-policy validation and admission storage gates first.
    /// This owner reserves the submission ID and nonce in the request creation transaction.
    /// The clock callback runs after the OS recheck. It must not reenter this owner or the journal.
    public func admitCommand(_ command: sending RetainedCommandCapture, draft: ApprovalRequestDraft, currentPolicy: XPCPeerPolicy,
                             now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                             checkCancellation: () throws -> Void = {}) throws -> IssuedRequestPayload {
        try admitCommand(command, draft: draft, now: now, receiptTimeMs: receiptTimeMs) {
            try command.recheck(currentPolicy: currentPolicy, checkCancellation: checkCancellation)
        }
    }

    /// Internal fixture policy seam. Tests retain aliases only to inspect OS cleanup under serialized access.
    /// Production always uses the exclusive transfer and protected release policy above.
    func admitCommand(_ command: RetainedCommandCapture, draft: ApprovalRequestDraft, expression: String,
                      userID: uid_t, auditSessionID: au_asid_t?, now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                      checkCancellation: () throws -> Void = {}) throws -> IssuedRequestPayload {
        try admitCommand(command, draft: draft, now: now, receiptTimeMs: receiptTimeMs) {
            try command.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID,
                checkCancellation: checkCancellation)
        }
    }

    private func admitCommand(_ command: RetainedCommandCapture, draft: ApprovalRequestDraft,
                              now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?, recheck: () throws -> Void) throws -> IssuedRequestPayload {
        try command.claimForRequestOwner()
        let reply = try command.takeAdmissionReply()
        defer { reply?.close() }
        let payload: IssuedRequestPayload
        var rejection: CommandAdmissionRejectionReason?
        do {
            if let profile = command.admissionProfile, profile.supportsAdmissionResults {
                guard profile.macID == mac, profile.accountID == account else { throw ApprovalCoordinatorError.invalidDraft }
            }
            let actions: Set<CapturedAction> = [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)]
            guard draft.contract.requestKind == .command, draft.contract.schemaVersion == command.capture.schemaVersion,
                  draft.capture == command.capture.canonicalBytes, draft.actions.count == actions.count,
                  Set(draft.actions) == actions else {
                rejection = .invalidRequest
                throw ApprovalCoordinatorError.invalidDraft
            }
            try recheck()
            let moment = try now()
            // Only errors from this owner's admission path can classify a refusal. Callback errors remain uncertain.
            do { payload = try admit(draft, command: command, now: moment, receiptTimeMs: receiptTimeMs) }
            catch { rejection = Self.admissionRejection(error); throw error }
        } catch {
            let outcome = rejectionOutcome(command, rejection: rejection, error: error)
            try? sendAdmissionOutcome(outcome, command: command, reply: reply)
            command.close(); throw error
        }
        // Admission is complete. Reply loss must not enter rejection cleanup or close the retained command.
        if command.admissionProfile?.supportsAdmissionResults == true, let state = entries[payload.requestID]?.state {
            let identity = CommandAdmittedRequest(requestID: state.requestID, requestDigest: state.requestDigest, challenge: state.challenge)
            do { try sendAdmissionOutcome(.admitted(identity), command: command, reply: reply) }
            catch { /* The client observes uncertainty. The admitted request keeps its normal lifetime. */ }
        }
        return payload
    }

    private static func admissionRejection(_ error: Error) -> CommandAdmissionRejectionReason? {
        switch error {
        case ReleaseActivityError.busy: .updateInstalling
        case ApprovalCoordinatorError.invalidDraft, IssuedRequestError.invalidTimes: .invalidRequest
        case ApprovalCoordinatorError.capacityExceeded, CommandSubmissionReplayError.capacityExceeded: .capacityExceeded
        case DecisionVerificationError.unsupportedContract, IssuedRequestError.unsupportedContract: .unsupported
        case JournalDatabaseError.storage, AuditJournalError.storage, ContinuityStoreError.storage: .storageUnavailable
        default: nil
        }
    }

    var commandAdmissionEpoch: Data { writer.epoch }
    func retainsCommandSubmission(_ submission: CapturedSubmission) -> Bool {
        entries.values.contains { entry in
            guard let prior = entry.command?.capture.submission else { return false }
            return prior.id == submission.id || prior.nonce == submission.nonce
        }
    }

    private func rejectionOutcome(_ command: RetainedCommandCapture, rejection: CommandAdmissionRejectionReason?,
                                  error: Error) -> CommandAdmissionOutcome {
        if error as? CommandSubmissionReplayError == .alreadyReserved { return .uncertain(.duplicateSubmission) }
        guard let rejection, command.admissionProfile?.supportsAdmissionResults == true else {
            return .uncertain(.admissionRejected)
        }
        let submission = command.capture.submission
        // Check retained requests as well as historical reservations. A refusal cannot contradict either owner.
        guard !retainsCommandSubmission(submission) else { return .uncertain(.duplicateSubmission) }
        do {
            let reserved = try read { tx in
                let trust = try tx.approvalTrustSnapshot()
                guard trust.macID == mac, trust.accountID == account else { throw JournalDatabaseError.wrongScope }
                _ = try head(tx)
                return try tx.commandSubmissionReserved(submission)
            }
            guard !reserved else { return .uncertain(.duplicateSubmission) }
            let retry: CommandAdmissionRetryClass
            switch rejection {
            case .updateInstalling: retry = .updateInstalling
            case .storageUnavailable: retry = .storageUnavailable
            default: retry = .never
            }
            return .notAdmitted(rejection, retry)
        } catch { return .uncertain(.storageFailure) }
    }

    private func sendAdmissionOutcome(_ outcome: CommandAdmissionOutcome, command: RetainedCommandCapture,
                                      reply: MachCommandReplyRight?) throws {
        guard let profile = command.admissionProfile, profile.supportsAdmissionResults, let reply else { return }
        guard profile.macID == mac, profile.accountID == account else { throw CommandAdmissionResultError.wrongBinding }
        let payload = CommandAdmissionResultPayload(profile: profile, submission: command.capture.submission,
            submissionDigest: command.submissionDigest, outcome: outcome)
        try reply.send(payload.canonicalBytes, timeoutMilliseconds: 5000)
    }

    /// Admits a non-command adapter draft. Commands require the retained-object transfer in `admitCommand`.
    public func admit(_ draft: ApprovalRequestDraft, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> IssuedRequestPayload {
        guard draft.contract.requestKind != .command else { throw ApprovalCoordinatorError.invalidDraft }
        return try admit(draft, command: nil, now: now, receiptTimeMs: receiptTimeMs)
    }

    /// Synthetic lifecycle fixture only. This method does not authenticate or retain command OS objects.
    func admitFixture(_ draft: ApprovalRequestDraft, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> IssuedRequestPayload {
        try admit(draft, command: nil, now: now, receiptTimeMs: receiptTimeMs)
    }

    private func admit(_ draft: ApprovalRequestDraft, command: RetainedCommandCapture?, now: AuthorityMoment,
                       receiptTimeMs: UInt64?) throws -> IssuedRequestPayload {
        try checkClock(now)
        guard draft.firstObservedAt.epoch == clockEpoch, draft.firstObservedAt.milliseconds <= now.milliseconds,
              now.milliseconds < draft.deadlineMilliseconds,
              draft.observationID == nil || draft.observationID?.count == 16,
              draft.estimatedLifetimeMilliseconds == nil || draft.estimatedLifetimeMilliseconds! > 0 else {
            throw ApprovalCoordinatorError.invalidDraft
        }
        let orphanedExpiries = expiryNotifications.keys.lazy.filter { self.entries[$0] == nil }.count
        guard entries.count + orphanedExpiries < maximumRequests else { throw ApprovalCoordinatorError.capacityExceeded }
        let payload = try IssuedRequestPayload(contract: draft.contract, macID: mac, accountID: account,
            requestID: random(16), challenge: random(32), requiredFeatures: draft.requiredFeatures,
            createdUnixMilliseconds: draft.createdUnixMilliseconds, expiresUnixMilliseconds: draft.expiresUnixMilliseconds,
            canonicalCapture: draft.capture, permittedActions: draft.actions, bodyLimits: requestLimits, captureLimits: captureLimits)
        let digest = try payload.requestDigest(bodyLimits: requestLimits, signingLimits: signingLimits)
        let bytes = try payload.encode(limits: requestLimits).count
        guard bytes <= maximumRetainedBytes - retainedBytes, entries[payload.requestID] == nil,
              expiryNotifications[payload.requestID] == nil else {
            throw ApprovalCoordinatorError.capacityExceeded
        }
        let retained = try RetainedApprovalRequest(payload: payload, phase: .queued, admittedAt: draft.firstObservedAt,
            deadlineMilliseconds: draft.deadlineMilliseconds)
        let category = category(payload.contract.requestKind)
        let observationID = try draft.observationID ?? random(16)
        let activity = try releaseActivity?.acquireShared()
        var transferred = false
        defer { if !transferred { activity?.close() } }
        try write { tx in
            let trust = try tx.approvalTrustSnapshot()
            guard trust.allowedContracts.contains(payload.contract), let features = trust.authorityCapabilities.contracts[payload.contract],
                  payload.requiredFeatures.isSubset(of: features) else { throw DecisionVerificationError.unsupportedContract }
            guard try tx.consumption(requestID: payload.requestID) == nil else { throw ApprovalCoordinatorError.invalidDraft }
            if let command {
                let reservation = try CommandSubmissionReservation(macID: mac, accountID: account, submission: command.capture.submission,
                    captureDigest: Data(SHA256.hash(data: command.capture.canonicalBytes)))
                _ = try tx.reserveCommandSubmission(reservation)
            }
            try append(tx, requestID: payload.requestID, category: category, kind: .requestCreated, outcome: .pending,
                reason: .none, receiptTimeMs: receiptTimeMs)
        }
        entries[payload.requestID] = Entry(state: ApprovalRequestState(requestKind: payload.contract.requestKind, macID: mac, accountID: account, requestDigest: digest, challenge: payload.challenge,
            reason: .none, terminalAt: nil, decisionPhoneID: nil, requestID: payload.requestID, phase: .queued,
            revision: 1, firstObservedAt: draft.firstObservedAt, deadlineMilliseconds: draft.deadlineMilliseconds),
            contract: payload.contract, permittedActions: Set(payload.permittedActions), observationID: observationID,
            estimatedLifetimeMilliseconds: draft.estimatedLifetimeMilliseconds, lateObservation: draft.lateObservation,
            retained: retained, command: command, activity: activity, category: category, byteCount: bytes)
        transferred = true
        retainedBytes += bytes
        return payload
    }

    public func state(requestID: Data) throws -> ApprovalRequestState {
        try running()
        _ = try read { try head($0) }
        guard let entry = entries[requestID] else { throw ApprovalCoordinatorError.unknownRequest }
        return entry.state
    }

    /// A snapshot for signing or delivery. Refresh under the same service serialization before dispatching any transport work.
    public func pendingRequest(requestID: Data, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> RetainedApprovalRequest {
        try pending(requestID, now: now, receiptTimeMs: receiptTimeMs)
    }

    public func markPresented(requestID: Data, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> ApprovalRequestState {
        let retained = try pending(requestID, now: now, receiptTimeMs: receiptTimeMs)
        if retained.phase == .presented { return try state(requestID: requestID) }
        return try replace(requestID, phase: RequestLifecycle.transition(from: retained.phase, event: .present), reason: .none, now: now)
    }

    /// Expires elapsed requests and returns unreported committed expiries from every path once.
    /// Reconcile this batch under the same service serialization. Audit commits before live state changes.
    public func expirePending(now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> [ApprovalRequestState] {
        try checkClock(now)
        let expired = entries.keys.filter { id in
            guard let retained = entries[id]?.retained else { return false }
            return (retained.phase == .queued || retained.phase == .presented) && now.milliseconds >= retained.deadlineMilliseconds
        }.sorted { $0.lexicographicallyPrecedes($1) }
        try write { tx in
            _ = try head(tx)
            for id in expired {
                guard let entry = entries[id] else { throw ApprovalCoordinatorError.unknownRequest }
                try append(tx, requestID: id, category: entry.category, kind: .expired, outcome: .expired,
                    reason: .authorizationExpired, receiptTimeMs: receiptTimeMs)
            }
        }
        for id in expired { _ = try replace(id, phase: .expired, reason: .authorizationExpired, now: now) }
        let notifications = expiryNotifications.keys.sorted { $0.lexicographicallyPrecedes($1) }.map { expiryNotifications[$0]! }
        expiryNotifications.removeAll(keepingCapacity: true)
        return notifications
    }

    /// A Mac-observed pending lifecycle change. A phone decline must use its signed decision instead.
    public func retirePending(requestID: Data, reason: PendingRequestRetirement, now: AuthorityMoment,
                              receiptTimeMs: UInt64?) throws -> ApprovalRequestState {
        try checkClock(now)
        guard let entry = entries[requestID], let retained = entry.retained,
              retained.phase == .queued || retained.phase == .presented else { throw ApprovalCoordinatorError.notPending }
        let event: RequestEvent, auditReason: AuditReason, statusReason: RequestStatusReason
        switch reason {
        case .cancelled: event = .cancel; auditReason = .userCancelled; statusReason = .userCancelled
        case .deadlineElapsed:
            guard now.milliseconds >= retained.deadlineMilliseconds else { throw ApprovalCoordinatorError.invalidDraft }
            event = .expire; auditReason = .authorizationExpired; statusReason = .authorizationExpired
        case .targetTimedOut: event = .expire; auditReason = .targetTimedOut; statusReason = .targetTimedOut
        case .targetDisappeared: event = .loseTarget; auditReason = .targetDisappeared; statusReason = .targetDisappeared
        case .authorityRestart: event = .restartAuthority; auditReason = .authorityRestarted; statusReason = .authorityRestarted
        }
        let phase = try RequestLifecycle.transition(from: retained.phase, event: event)
        let kind: AuditEventKind = phase == .expired ? .expired : phase == .unknown ? .unknownOutcome : .cancelled
        let outcome: AuditOutcome = phase == .expired ? .expired : phase == .unknown ? .unresolved : .noDispatch
        try write { try append($0, requestID: requestID, category: entry.category, kind: kind,
            outcome: outcome, reason: auditReason, receiptTimeMs: receiptTimeMs) }
        return try replace(requestID, phase: phase, reason: statusReason, now: now)
    }

    /// The authenticated channel supplies phone and epoch. Incoming decision bytes never supply trusted enrollment or retained state.
    public func consume(canonicalDecision: Data, signature: Data, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data,
                        now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> ConsumptionReceipt {
        try checkClock(now)
        let decision = try DecisionPayload.decode(canonicalDecision, limits: decisionLimits)
        guard decision.phoneID == authenticatedPhoneID else { throw ApprovalCoordinatorError.wrongPhone }
        let retained = try pending(decision.requestID, now: now, receiptTimeMs: receiptTimeMs)
        let (receipt, enrollment) = try write { tx in
            let trust = try tx.requestDeliveryTrust()
            guard let enrollment = trust.enrollments.first(where: {
                $0.approval.phoneID == authenticatedPhoneID && $0.epoch == authenticatedEnrollmentEpoch && $0.approval.active
            }) else { throw EnrollmentJournalError.unavailableEnrollment }
            let receipt = try tx.consume(canonicalDecision: canonicalDecision, signature: signature, retained: retained,
                expectedTrustRevision: trust.approval.revision, now: now, eventID: random(16), receiptTimeMs: receiptTimeMs,
                writer: writer, expectedHead: head(tx), requestLimits: requestLimits, signingLimits: signingLimits)
            guard let key = enrollment.approval.keys.first(where: { $0.id == decision.keyID }) else {
                throw DecisionVerificationError.wrongKey
            }
            return (receipt, CommandApprovalEnrollment(epoch: enrollment.epoch, key: key))
        }
        if retained.payload.contract.requestKind == .command, receipt.event.outcome == .accepted {
            entries[decision.requestID]?.commandApprovalEnrollment = enrollment
        }
        _ = try replace(decision.requestID, phase: receipt.event.outcome == .noDispatch ? .declined : .authorized,
            reason: receipt.event.outcome == .noDispatch ? .declined : .none, now: now, decisionPhoneID: receipt.decision.phoneID)
        return receipt
    }

    var routingScope: (macID: Data, accountID: Data) { (mac, account) }
    /// Read the current persisted mode under the same continuity boundary as request delivery.
    public func localRoutingState() throws -> RoutingState {
        try running()
        return try read { tx in _ = try head(tx); return try tx.routingState() }
    }
    /// The host authenticates the local Mac control surface. Phone and transport endpoints must never call this method.
    public func setLocalRoutingMode(_ mode: RoutingMode, expectedRevision: UInt64, now: AuthorityMoment,
                                    receiptTimeMs: UInt64?) throws -> RoutingState {
        try checkClock(now)
        let event = try random(16)
        return try write { tx in
            try tx.setLocalRoutingMode(mode, expectedRevision: expectedRevision, eventID: event, receiptTimeMs: receiptTimeMs,
                writer: writer, expectedAuditHead: head(tx))
        }
    }

    /// Prepare bounded wake registrations and withdrawals from current retained requests and journal trust.
    /// The host serializes this operation with authority changes. No asynchronous work or gateway call belongs in this method.
    public func reconcileWakePublications(routing: PresenceRouting, now: AuthorityMoment,
                                          receiptTimeMs: UInt64?) throws -> RetainedWakePublicationSnapshot {
        try checkClock(now)
        let trust = try wakeDeliveryTrust()
        return try reconcileWakePublications(routing: routing, now: now, receiptTimeMs: receiptTimeMs, trust: trust)
    }
    func wakeDeliveryTrust() throws -> RequestDeliveryTrust {
        try running()
        return try read { try $0.requestDeliveryTrust() }
    }
    func reconcileWakePublications(routing: PresenceRouting, now: AuthorityMoment, receiptTimeMs: UInt64?,
                                   trust: RequestDeliveryTrust) throws -> RetainedWakePublicationSnapshot {
        try checkClock(now)
        var limited = 0
        for id in entries.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            let state = try deliveryState(requestID: id, now: now, receiptTimeMs: receiptTimeMs)
            guard state.phase == .queued || state.phase == .presented, let retained = entries[id]?.retained else { continue }
            limited += try wakePublication.reconcile(retained, trust: trust, routing: routing, now: now)
        }
        return try wakePublication.snapshot(routing: routing, capacityLimitedRecipients: limited)
    }

    /// A gateway acknowledgment may arrive after the request changes. Recheck before exposing an opaque transport hint.
    public func acknowledgeWakeRegistration(_ delivery: PhoneRequestDelivery, routing: PresenceRouting,
                                            now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> Bool {
        _ = try reconcileWakePublications(routing: routing, now: now, receiptTimeMs: receiptTimeMs)
        return wakePublication.acknowledgeRegistration(delivery)
    }
    /// Clear only the exact retained withdrawal accepted by the gateway. Terminal entry removal does not clear this queue.
    public func acknowledgeWakeWithdrawal(_ delivery: PhoneRequestDelivery) throws -> Bool {
        try running()
        _ = try read { try head($0) }
        return wakePublication.acknowledgeWithdrawal(delivery)
    }
    /// Only the active publisher can acknowledge work. Replacement preserves original grant IDs and deadlines.
    func beginWakePublicationSession(_ id: UUID) throws { try running(); try wakePublication.beginSession(id) }
    func requireWakePublicationSession(_ id: UUID) throws { try running(); try wakePublication.requireSession(id) }
    func endWakePublicationSession(_ id: UUID) { wakePublication.endSession(id) }

    /// Reconcile queue ownership from current owner state, including terminal states whose capture was released.
    public func reconcileDelivery(requestID: Data, delivery: PendingRequestDelivery, routing: PresenceRouting,
                                  now: AuthorityMoment, receiptTimeMs: UInt64?,
                                  enqueue: (PhoneRequestDelivery) -> Bool) throws -> RequestDeliveryUpdate {
        let current = try deliveryState(requestID: requestID, now: now, receiptTimeMs: receiptTimeMs)
        guard current.phase == .queued || current.phase == .presented else {
            return delivery.close(current: current, routing: routing, now: now)
        }
        guard let retained = entries[requestID]?.retained else { throw ApprovalCoordinatorError.notPending }
        let trust = try read { try $0.requestDeliveryTrust() }
        return delivery.reconcile(current: retained, routing: routing, trust: trust, now: now, enqueue: enqueue)
    }

    /// Recheck current request and journal trust immediately before the first transport handoff.
    /// Prepare asynchronous resources first. The callback must not await, reenter, or mutate authority state.
    /// Return false only if no bytes or work were accepted. Always apply the returned withdrawals, even without a delivery.
    public func handoffDelivery(requestID: Data, delivery: PendingRequestDelivery, deliveryID: UUID,
                                routing: PresenceRouting, now: AuthorityMoment, receiptTimeMs: UInt64?,
                                accept: (PhoneRequestDelivery) -> Bool) throws -> RequestDeliveryDispatch {
        let current = try deliveryState(requestID: requestID, now: now, receiptTimeMs: receiptTimeMs)
        guard current.phase == .queued || current.phase == .presented else {
            return RequestDeliveryDispatch(delivery: nil, update: delivery.close(current: current, routing: routing, now: now))
        }
        guard let retained = entries[requestID]?.retained else { throw ApprovalCoordinatorError.notPending }
        let trust = try read { try $0.requestDeliveryTrust() }
        return delivery.handoff(id: deliveryID, current: retained, routing: routing, trust: trust, now: now, accept: accept)
    }

    /// Builds the signed frame from retained authority state, never from caller-supplied request bytes.
    /// Production supplies its non-exportable authority signer and public key from current local trust.
    /// Keep this call serialized with authority changes. Callbacks must not reenter or mutate this owner.
    /// Sample the clock and presence again after signing; transport acceptance has the same contract as handoffDelivery.
    public func handoffSignedDelivery(requestID: Data, delivery: PendingRequestDelivery, deliveryID: UUID,
                                      authorityPublicKey: Data, maximumBodyBytes: Int,
                                      now: () throws -> AuthorityMoment, routing: () throws -> PresenceRouting,
                                      receiptTimeMs: UInt64?, signer: (Data) throws -> Data,
                                      accept: (PhoneRequestDelivery, Data) -> Bool) throws -> RequestDeliveryDispatch {
        let initialTime = try now()
        let current = try deliveryState(requestID: requestID, now: initialTime, receiptTimeMs: receiptTimeMs)
        guard current.phase == .queued || current.phase == .presented else {
            return RequestDeliveryDispatch(delivery: nil, update: delivery.close(current: current, routing: try routing(), now: initialTime))
        }
        guard let retained = entries[requestID]?.retained else { throw ApprovalCoordinatorError.notPending }
        guard authorityPublicKey.count == 65, authorityPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: authorityPublicKey)) != nil else {
            throw DecisionVerificationError.invalidTrustedState
        }
        let body = try retained.payload.encode(limits: requestLimits)
        guard (1...(16_777_216 - ApprovalMessage.overheadBytes)).contains(maximumBodyBytes),
              body.count <= maximumBodyBytes else { throw ApprovalCoordinatorError.capacityExceeded }
        let input = try SigningInput.make(wireVersion: retained.payload.contract.wireVersion,
            messageType: .request, purpose: .issuedRequest, canonicalPayload: body,
            payloadLimits: requestLimits, inputLimits: signingLimits)
        let signature = try signer(input)
        guard try ApprovalSignature.verify(signature: signature, publicKey: authorityPublicKey,
            wireVersion: retained.payload.contract.wireVersion, messageType: .request, purpose: .issuedRequest,
            canonicalPayload: body, payloadLimits: requestLimits, inputLimits: signingLimits) else {
            throw DecisionVerificationError.invalidSignature
        }
        let frame = try ApprovalMessage(wireVersion: retained.payload.contract.wireVersion,
            type: .request, purpose: .issuedRequest, body: body, signature: signature).encode(maximumBodyBytes: maximumBodyBytes)
        let finalRouting = try routing()
        return try handoffDelivery(requestID: requestID, delivery: delivery, deliveryID: deliveryID,
            routing: finalRouting, now: now(), receiptTimeMs: receiptTimeMs) { accept($0, frame) }
    }

    /// Bounded discovery hints for one current enrollment, never approval or delivery acknowledgments.
    /// The host serializes this call with authority changes. Fetch each frame through retainedDeliveryFrame.
    public func pendingDeliveryRequestIDs(binding: AuthorityPeerBinding, routing: PresenceRouting,
                                          now: AuthorityMoment) throws -> [Data] {
        try checkClock(now)
        let trust = try read { transaction in
            try transaction.requireDirectApprovalBinding(binding)
            return try transaction.requestDeliveryTrust()
        }
        guard let stored = trust.enrollments.first(where: {
            $0.approval.phoneID == binding.scope.phoneID && $0.epoch == binding.scope.enrollmentEpoch
        }), stored.approval.active,
              let enrollment = trust.approval.enrollments.first(where: { $0.phoneID == binding.scope.phoneID }),
              enrollment.active else { return [] }
        let recipient = DeliveryRecipient(stored)
        var result: [Data] = []
        for id in entries.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            guard let retained = entries[id]?.retained,
                  retained.phase == .queued || retained.phase == .presented else { continue }
            let delivery = try deliveryController(requestID: id, retained: retained)
            if delivery.canDiscover(current: retained, routing: routing, authority: trust.approval,
                recipient: recipient, enrollment: enrollment, now: now) { result.append(id) }
        }
        return result
    }

    private func deliveryController(requestID: Data, retained: RetainedApprovalRequest) throws -> PendingRequestDelivery {
        if let existing = entries[requestID]?.delivery { return existing }
        let delivery = try PendingRequestDelivery(request: retained)
        entries[requestID]?.delivery = delivery
        return delivery
    }

    /// Root-owned retry storage for the request-frame provider. Serialize with all authority state.
    /// A returned frame is a possible handoff, not phone receipt or consent. Never persist this cache.
    /// Callbacks must be synchronous and must not reenter or mutate authority state.
    public func retainedDeliveryFrame(binding: AuthorityPeerBinding, requestID: Data, authorityPublicKey: Data,
                                      maximumBodyBytes: Int, now: () throws -> AuthorityMoment,
                                      routing: () throws -> PresenceRouting, receiptTimeMs: UInt64?,
                                      signer: (Data) throws -> Data) throws -> Data? {
        guard (1...(16_777_216 - ApprovalMessage.overheadBytes)).contains(maximumBodyBytes) else {
            throw ApprovalCoordinatorError.invalidConfiguration
        }
        try read { try $0.requireDirectApprovalBinding(binding) }
        let time = try now()
        let state: ApprovalRequestState
        do { state = try deliveryState(requestID: requestID, now: time, receiptTimeMs: receiptTimeMs) }
        catch ApprovalCoordinatorError.unknownRequest { return nil }
        guard state.phase == .queued || state.phase == .presented else { return nil }
        guard let entry = entries[requestID], let retained = entry.retained else { throw ApprovalCoordinatorError.notPending }
        let delivery = try deliveryController(requestID: requestID, retained: retained)
        let currentRouting = try routing()
        let update = try reconcileDelivery(requestID: requestID, delivery: delivery, routing: currentRouting, now: now(),
            receiptTimeMs: receiptTimeMs) { _ in true }
        guard let queued = update.active.first(where: {
            $0.recipient.phoneID == binding.scope.phoneID && $0.recipient.enrollmentEpoch == binding.scope.enrollmentEpoch
        }) else { return nil }
        let cached = entries[requestID]?.frame
        if cached != nil && entries[requestID]?.frameKey != authorityPublicKey { throw DecisionVerificationError.invalidTrustedState }
        if update.dispatched.contains(where: { $0.id == queued.id }) {
            guard let cached else { throw ApprovalCoordinatorError.unavailable }
            guard cached.count <= maximumBodyBytes + ApprovalMessage.overheadBytes else { throw ApprovalCoordinatorError.capacityExceeded }
            return cached
        }
        let cachedSignature = try cached.map {
            try ApprovalMessage.decode($0, maximumBodyBytes: maximumBodyBytes).signature
        }
        var result: Data?
        _ = try handoffSignedDelivery(requestID: requestID, delivery: delivery, deliveryID: queued.id,
            authorityPublicKey: authorityPublicKey, maximumBodyBytes: maximumBodyBytes, now: now, routing: routing,
            receiptTimeMs: receiptTimeMs, signer: { try cachedSignature ?? signer($0) }) { _, frame in
                let previous = entries[requestID]?.frame?.count ?? 0
                let maximum = maximumRetainedBytes + maximumRequests * ApprovalMessage.overheadBytes
                guard frame.count <= maximum - deliveryBytes + previous else { return false }
                entries[requestID]?.frame = frame
                entries[requestID]?.frameKey = authorityPublicKey
                deliveryBytes += frame.count - previous
                result = frame
                return true
            }
        return result
    }

    /// Returns fresh signed state and optionally consumes one authenticated phone decision. It never dispatches a target.
    /// Serialize this call with all authority state. Supply a trusted non-exportable signer; callbacks must not reenter.
    /// A lost reply can follow committed consumption. Reconcile status rather than retrying target execution.
    public func exchangeRequest(binding: AuthorityPeerBinding, requestID: Data, decisionFrame: Data? = nil,
                                authorityPublicKey: Data, maximumBodyBytes: Int,
                                now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                                signer: (Data) throws -> Data) throws -> Data? {
        guard requestID.count == 16, (1...(16_777_216 - ApprovalMessage.overheadBytes)).contains(maximumBodyBytes) else {
            throw ApprovalCoordinatorError.invalidConfiguration
        }
        guard authorityPublicKey.count == 65, authorityPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: authorityPublicKey)) != nil else {
            throw DecisionVerificationError.invalidTrustedState
        }
        let enrollment = try read { transaction in
            try transaction.requireDirectApprovalBinding(binding)
            guard let enrollment = try transaction.requestDeliveryTrust().enrollments.first(where: {
                $0.approval.phoneID == binding.scope.phoneID && $0.epoch == binding.scope.enrollmentEpoch
            }) else { throw EnrollmentJournalError.unavailableEnrollment }
            return enrollment.approval
        }
        let initialTime = try now()
        let current: ApprovalRequestState
        do { current = try deliveryState(requestID: requestID, now: initialTime, receiptTimeMs: receiptTimeMs) }
        catch ApprovalCoordinatorError.unknownRequest { return nil }
        if let decisionFrame {
            guard let entry = entries[requestID] else { throw ApprovalCoordinatorError.unknownRequest }
            let message = try ApprovalMessage.decode(decisionFrame, maximumBodyBytes: maximumBodyBytes)
            let decision = try DecisionPayload.decode(message.body, limits: decisionLimits)
            guard message.type == .decision, decision.macID == mac, decision.accountID == account,
                  decision.requestID == requestID, decision.requestDigest == current.requestDigest,
                  decision.challenge == current.challenge, decision.phoneID == binding.scope.phoneID else {
                throw DecisionVerificationError.wrongRequest
            }
            let requirement = try ActionPolicy.requirement(for: decision.action, requestKind: entry.contract.requestKind,
                retainedPermittedActions: entry.permittedActions)
            let purpose: SigningPurpose
            switch requirement.purpose {
            case .cancellation: purpose = .cancellation
            case .oneTimeUI: purpose = .oneTimeUI
            case .biometricAuthorization: purpose = .biometricAuthorization
            }
            guard let key = enrollment.keys.first(where: { $0.id == decision.keyID }),
                  key.keyClass == requirement.keyClass, message.purpose == purpose else {
                throw DecisionVerificationError.wrongKeyClass
            }
            guard try ApprovalSignature.verify(signature: message.signature, publicKey: key.publicKey,
                wireVersion: message.wireVersion, messageType: .decision, purpose: purpose,
                canonicalPayload: message.body, payloadLimits: decisionLimits, inputLimits: signingLimits) else {
                throw DecisionVerificationError.invalidSignature
            }
            if current.phase == .queued || current.phase == .presented {
                do {
                    _ = try consume(canonicalDecision: message.body, signature: message.signature,
                        authenticatedPhoneID: binding.scope.phoneID, authenticatedEnrollmentEpoch: binding.scope.enrollmentEpoch,
                        now: now(), receiptTimeMs: receiptTimeMs)
                } catch ApprovalCoordinatorError.expired {
                    // Expiry committed before consumption. Return that state through the same signed response path.
                }
            }
        }
        // A pending request can cross its deadline during signing. Discard that snapshot and sign its committed expiry.
        for _ in 0..<2 {
            let time = try now()
            let state = try deliveryState(requestID: requestID, now: time, receiptTimeMs: receiptTimeMs)
            guard let entry = entries[requestID], entry.statusRevision < UInt64.max else {
                throw ApprovalCoordinatorError.unavailable
            }
            let revision = entry.statusRevision + 1
            entries[requestID]?.statusRevision = revision
            let status = try state.statusPayload(observationID: entry.observationID, observationRevision: revision, now: time,
                estimatedLifetimeMs: entry.estimatedLifetimeMilliseconds, lateObservation: entry.lateObservation)
            let limits = try CBORLimits(maxBytes: maximumBodyBytes, maxDepth: 4, maxItems: 64)
            let body = try status.encode(limits: limits)
            let input = try SigningInput.make(wireVersion: 1, messageType: .status, purpose: .status,
                canonicalPayload: body, payloadLimits: limits, inputLimits: signingLimits)
            let signature = try signer(input)
            guard try ApprovalSignature.verify(signature: signature, publicKey: authorityPublicKey,
                wireVersion: 1, messageType: .status, purpose: .status,
                canonicalPayload: body, payloadLimits: limits, inputLimits: signingLimits) else {
                throw DecisionVerificationError.invalidSignature
            }
            let final = try deliveryState(requestID: requestID, now: now(), receiptTimeMs: receiptTimeMs)
            guard final == state else { continue }
            return try ApprovalMessage(wireVersion: 1, type: .status, purpose: .status, body: body,
                signature: signature).encode(maximumBodyBytes: maximumBodyBytes)
        }
        throw ApprovalCoordinatorError.unavailable
    }

    private func deliveryState(requestID: Data, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> ApprovalRequestState {
        try checkClock(now)
        var current = try state(requestID: requestID)
        if (current.phase == .queued || current.phase == .presented) && now.milliseconds >= current.deadlineMilliseconds {
            current = try retirePending(requestID: requestID, reason: .deadlineElapsed, now: now, receiptTimeMs: receiptTimeMs)
        }
        return current
    }

    /// Original binding for the root executor's separate checkpoint and target checks. This snapshot grants no dispatch permission.
    public func consumedRequest(requestID: Data, now: AuthorityMoment) throws -> RetainedApprovalRequest {
        try checkClock(now)
        _ = try read { try head($0) }
        guard let entry = entries[requestID], let retained = entry.retained,
              retained.phase == .authorized || retained.phase == .executing else { throw ApprovalCoordinatorError.notPending }
        return retained
    }

    /// Current original approval metadata for the internal controller. This snapshot grants no dispatch permission.
    func authorizedCommandApproval(requestID: Data, now: AuthorityMoment) throws -> CommandExecutionApproval {
        try checkClock(now)
        guard let entry = entries[requestID], entry.state.phase == .authorized,
              let retained = entry.retained, retained.payload.contract.requestKind == .command,
              entry.command != nil, let enrollment = entry.commandApprovalEnrollment, let outcome = try read({ try $0.consumptionOutcome(requestID: requestID) }),
              outcome.phase == .authorized, outcome.revision == 0,
              outcome.receipt.decision.action.choice == .execute,
              outcome.receipt.decision.requestDigest == entry.state.requestDigest,
              outcome.receipt.decision.challenge == entry.state.challenge else { throw ApprovalCoordinatorError.notPending }
        return CommandExecutionApproval(retained: retained, receipt: outcome.receipt, enrollment: enrollment)
    }

    /// Internal transfer to the same serialized Root execution owner. The result is non-Sendable and grants no release permission.
    func takeAuthorizedCommandExecution(requestID: Data, now: AuthorityMoment) throws -> RetainedCommandExecutionResources {
        try checkClock(now)
        guard var entry = entries[requestID], entry.state.phase == .authorized,
              let retained = entry.retained, retained.payload.contract.requestKind == .command,
              let command = entry.command else { throw ApprovalCoordinatorError.notPending }
        let outcome = try read { try $0.consumptionOutcome(requestID: requestID) }
        guard let outcome, outcome.phase == .authorized, outcome.revision == 0,
              outcome.receipt.event.category == .command, outcome.receipt.decision.action.choice == .execute,
              outcome.receipt.decision.requestDigest == entry.state.requestDigest,
              outcome.receipt.decision.challenge == entry.state.challenge else { throw ApprovalCoordinatorError.notPending }
        let identity = CommandAdmittedRequest(requestID: entry.state.requestID,
            requestDigest: entry.state.requestDigest, challenge: entry.state.challenge)
        let resources = try command.takeExecutionResources(request: identity)
        entry.command = nil
        entries[requestID] = entry
        return resources
    }

    /// Retained winner and result for Already handled responses. It cannot recreate a live request after restart.
    public func historicalOutcome(requestID: Data) throws -> ConsumptionOutcome? {
        try running()
        return try read { try $0.consumptionOutcome(requestID: requestID) }
    }

    /// Only controller-verified outcomes belong here. This records an observation and grants no permission to execute.
    public func recordOutcome(requestID: Data, expectedRevision: UInt64, event: RequestEvent,
                              now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> ConsumptionOutcome {
        try checkClock(now)
        guard let entry = entries[requestID], entry.state.phase == .authorized || entry.state.phase == .executing else {
            throw ApprovalCoordinatorError.notPending
        }
        let outcome = try write { tx in
            try tx.transitionConsumption(requestID: requestID, expectedRevision: expectedRevision, event: event,
                eventID: random(16), receiptTimeMs: receiptTimeMs, writer: writer, expectedHead: head(tx))
        }
        let reason: RequestStatusReason
        switch outcome.phase {
        case .executing: reason = .none
        case .succeeded, .failed: reason = .verifiedResult
        case .unknown: reason = outcome.event.reason == .authorityRestarted ? .authorityRestarted : .outcomeUnavailable
        case .cancelled: reason = .noDispatchProved
        default: throw ConsumptionOutcomeError.corruptData
        }
        _ = try replace(requestID, phase: outcome.phase, reason: reason, now: now)
        return outcome
    }

    /// Terminal metadata remains in the journal. Forgetting never clears durable consumption or pending expiry cleanup.
    /// An unreported expiry still occupies one bounded request slot until expirePending returns it.
    public func forgetTerminal(requestID: Data) throws {
        try running()
        guard let entry = entries[requestID], entry.state.phase.isTerminal else { throw ApprovalCoordinatorError.notPending }
        entries.removeValue(forKey: requestID)
    }

    private func pending(_ id: Data, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> RetainedApprovalRequest {
        try checkClock(now)
        guard let entry = entries[id], let retained = entry.retained,
              retained.phase == .queued || retained.phase == .presented else { throw ApprovalCoordinatorError.notPending }
        _ = try read { try head($0) }
        if now.milliseconds >= retained.deadlineMilliseconds {
            _ = try retirePending(requestID: id, reason: .deadlineElapsed, now: now, receiptTimeMs: receiptTimeMs)
            throw ApprovalCoordinatorError.expired
        }
        return retained
    }

    private func replace(_ id: Data, phase: RequestPhase, reason: RequestStatusReason, now: AuthorityMoment,
                         decisionPhoneID: Data? = nil) throws -> ApprovalRequestState {
        guard var entry = entries[id] else { throw ApprovalCoordinatorError.unknownRequest }
        entry.state = ApprovalRequestState(requestKind: entry.state.requestKind, macID: entry.state.macID, accountID: entry.state.accountID,
            requestDigest: entry.state.requestDigest, challenge: entry.state.challenge, reason: reason,
            terminalAt: phase.isTerminal ? now : nil, decisionPhoneID: decisionPhoneID ?? entry.state.decisionPhoneID,
            requestID: id, phase: phase, revision: entry.state.revision + 1,
            firstObservedAt: entry.state.firstObservedAt, deadlineMilliseconds: entry.state.deadlineMilliseconds)
        if phase != .queued && phase != .presented {
            wakePublication.retire(entry.state, now: now)
            deliveryBytes -= entry.frame?.count ?? 0
            entry.frame = nil; entry.frameKey = nil; entry.delivery = nil
        }
        if !phase.isTerminal {
            guard let old = entry.retained else { throw ApprovalCoordinatorError.notPending }
            entry.retained = try .init(payload: old.payload, phase: phase, admittedAt: old.admittedAt, deadlineMilliseconds: old.deadlineMilliseconds)
        } else {
            let terminal: CommandTerminalOutcome
            switch phase {
            case .declined: terminal = .denied
            case .expired: terminal = .expired
            case .cancelled: terminal = .cancelledBeforeStart
            // Generic lifecycle state does not establish a child's exit status or signal.
            default: terminal = .unknown
            }
            notifyCommandTerminal(entry, outcome: terminal)
            entry.command?.close(); entry.command = nil
            entry.activity?.close(); entry.activity = nil
            entry.retained = nil
            retainedBytes -= entry.byteCount
            entry.byteCount = 0
        }
        entries[id] = entry
        if phase == .expired { expiryNotifications[id] = entry.state }
        return entry.state
    }

    /// A lost private reply cannot undo the committed transition or authorize another invocation.
    private func notifyCommandTerminal(_ entry: Entry, outcome: CommandTerminalOutcome) {
        guard let command = entry.command else { return }
        let identity = CommandAdmittedRequest(requestID: entry.state.requestID,
            requestDigest: entry.state.requestDigest, challenge: entry.state.challenge)
        try? command.sendTerminalOutcome(outcome, request: identity)
    }

    /// Root publisher state only. Private provider data cannot be projected onto an ordinary phone response.
    func currentPhonePushRegistration(_ provider: AuthorityPhonePushRegistration, phoneID: Data, enrollmentEpoch: Data,
                                      now: AuthorityMoment, wall: UInt64) throws -> GatewayCurrentTokenState? {
        try running()
        guard provider.policy.registration.macID == mac, provider.policy.registration.accountID == account else {
            throw GatewayAuthorityError.wrongScope
        }
        try checkClock(now)
        return try read { try provider.current(phoneID: phoneID, enrollmentEpoch: enrollmentEpoch, transaction: $0, now: now, wall: wall) }
    }
    /// Automatic expiry/restart recovery retains pairing. A new candidate still requires provider possession proof.
    func renewExpiredPhonePushRegistration(_ provider: AuthorityPhonePushRegistration, phoneID: Data, enrollmentEpoch: Data,
                                          now: AuthorityMoment, wall: UInt64) throws -> GatewayCurrentTokenState? {
        let current = try currentPhonePushRegistration(provider, phoneID: phoneID, enrollmentEpoch: enrollmentEpoch, now: now, wall: wall)
        guard current?.needsRenewal == true else { return current }
        return try write { try provider.renewExpired(phoneID: phoneID, enrollmentEpoch: enrollmentEpoch, transaction: $0, now: now, wall: wall) }
    }

    /// Protected startup only. The hardware-bound provider validates Root before initializing its fixed identity.
    func preparePhonePushRegistration(_ provider: AuthorityPhonePushRegistration, now: AuthorityMoment) throws {
        try running()
        guard provider.policy.registration.macID == mac, provider.policy.registration.accountID == account else {
            throw GatewayAuthorityError.wrongScope
        }
        try checkClock(now)
        try write { try provider.configure(transaction: $0) }
    }

    /// Fixed token registration operations share this owner's current binding and continuity writer.
    /// No candidate result leaves the owner before durable commit. Callbacks cannot await or reenter it.
    func phonePushRegistration(_ request: PhonePushRegistrationFrame, binding: AuthorityPeerBinding,
                               provider: AuthorityPhonePushRegistration, now: AuthorityMoment, wall: UInt64,
                               validateTransport: (JournalTransaction) throws -> Void) throws -> PhonePushRegistrationFrame {
        try running()
        guard binding.scope.macID == mac, binding.scope.accountID == account else { throw GatewayAuthorityError.wrongScope }
        switch request {
        case .offer, .proof: break
        default: throw AuthorityXPCError.invalidMessage
        }
        _ = try request.encode()
        try checkClock(now)
        return try write { tx in
            try validateTransport(tx)
            return try provider.process(request, binding: binding, transaction: tx, now: now, wall: wall)
        }
    }

    private func append(_ tx: JournalTransaction, requestID: Data, category: AuditCategory, kind: AuditEventKind,
                        outcome: AuditOutcome, reason: AuditReason, receiptTimeMs: UInt64?) throws {
        let current = try head(tx)
        guard current < UInt64.max else { throw AuditJournalError.headMismatch }
        let event = try AuditEventMetadata(eventID: random(16), macID: mac, accountID: account, journalEpoch: writer.epoch,
            sequence: current + 1, requestID: requestID, eventTimeMs: nil, authorityReceiptTimeMs: receiptTimeMs,
            kind: kind, category: category, action: nil, decisionPhoneID: nil, authentication: .system, outcome: outcome,
            reason: reason, droppedEventCount: nil, peerDeviceID: nil)
        try tx.append(event.encode(limits: auditLimits), writer: writer, expectedHead: current)
    }
    private func head(_ tx: JournalTransaction) throws -> UInt64 {
        guard let epoch = try tx.epoch(writer.epoch) else { throw AuditJournalError.unavailableEpoch }
        return epoch.head
    }
    private func read<Value>(_ body: (JournalTransaction) throws -> Value) throws -> Value {
        try running()
        do {
            if let checkpointed { return try checkpointed.read(body) }
            return try database.read(body)
        } catch { retireAfterStorageFailure(); throw error }
    }

    private func write<Value>(_ body: (JournalTransaction) throws -> Value) throws -> Value {
        try running()
        do {
            if let checkpointed { return try checkpointed.write(epoch: writer.epoch, recoverRejectedBody: true, body) }
            return try database.write(body)
        } catch { retireAfterStorageFailure(); throw error }
    }

    private func retireAfterStorageFailure() {
        if database.retired || checkpointed?.retired == true { close() }
    }

    private func running() throws {
        if checkpointed?.retired == true { close() }
        if stopped { throw ApprovalCoordinatorError.unavailable }
        do { try releaseActivity?.validate() }
        catch { close(); throw error }
    }
    private func checkClock(_ now: AuthorityMoment) throws {
        try running()
        guard now.epoch == clockEpoch, lastTime == nil || now.milliseconds >= lastTime! else {
            close()
            throw ApprovalCoordinatorError.invalidClock
        }
        lastTime = now.milliseconds
    }
    private func random(_ count: Int) throws -> Data {
        var value = Data(count: count)
        guard value.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }) == errSecSuccess else {
            throw ApprovalCoordinatorError.unavailable
        }
        return value
    }
    private func category(_ kind: RequestKind) -> AuditCategory {
        switch kind {
        case .command: .command
        case .onePasswordAccess: .onePasswordAccess
        case .onePasswordUnlock: .onePasswordUnlock
        case .littleSnitch: .littleSnitch
        }
    }
}
