import CryptoKit
import Darwin
import Foundation
import Security
import SQLite3
import RemozioProtocol

/// Owns the authority's sole journal connection. Only Sendable results can leave a serialized transaction.
public final class AuthorityJournal: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let database: JournalDatabase
    private var storage: AuthorityStorage?
    private var requests: ApprovalRequestCoordinator?
    private var requestOperationActive = false
    private var requestStartupAttempted = false
    private let commandExchanges = AuthorityCommandExchangeOwnership()
    private var commandExecutions: [Data: CommandExecution] = [:]
    private var releaseActivity: ReleaseActivityBarrier?
    private var commandActivity: [Data: ReleaseActivityToken] = [:]
    private var commandCleanupTimer: DispatchSourceTimer?
    private var commandPollIntervalMilliseconds: Int?
    private var commandRuntimeChecks: [Data: () throws -> Void] = [:]
    private var commandStreamChecks: [Data: () throws -> Void] = [:]

    /// Transfer exclusive ownership. The caller must not keep another user of this connection.
    public init(database: sending JournalDatabase) { self.database = database }

    /// Validates running code before recovering paired stores. Request admission remains closed.
    /// Both stores must already have been opened with the same configured Mac and account scope.
    init(recovering storage: sending AuthorityStorage, macID: Data, accountID: Data,
         validateSelf: (JournalTransaction) throws -> Void = AuthoritySelfValidation.validate) throws {
        do {
            try storage.journal.read { try validateSelf($0) }
            _ = try JournalHistoryRecovery.recover(journal: storage.journal, continuity: storage.continuity,
                macID: macID, accountID: accountID)
            database = storage.journal
            self.storage = storage
        } catch {
            try? storage.close()
            throw error
        }
    }

    /// Owns the configured stores for trust-only service work. Action recovery remains a separate gate.
    init(storage: sending AuthorityStorage) throws {
        do {
            switch try JournalCheckpointRecovery.reconcile(journal: storage.journal, continuity: storage.continuity) {
            case .unchanged, .finalized, .discarded: break
            case .historyDiscontinuity: throw AuthorityStorageStartupError.historyRecoveryRequired
            case .repairRequired: throw AuthorityStorageStartupError.repairRequired
            }
            database = storage.journal
            self.storage = storage
        } catch {
            try? storage.close()
            throw error
        }
    }

    /// Runs once after host identity validation, before activating a listener or admitting request work.
    /// An incomplete attempt retires both stores. The next attempt must reopen and reconcile them.
    func prepareRequests(clockEpoch: UUID, maximumPayloadBytes: Int) throws {
        try lock.withLock {
            try requireNoRequestOperation()
            guard let storage else { return }
            try withStorageFailureCleanup { try database.read { _ in () } }
            guard !requestStartupAttempted, requests == nil else { throw JournalStartupRecovery.Failure.alreadyStarted }
            requestStartupAttempted = true
            do {
                guard (1...16_777_216).contains(maximumPayloadBytes) else { throw ApprovalCoordinatorError.invalidConfiguration }
                let bodyBytes = AuthorityServiceConfiguration.requestBodyLimit(maximumPayloadBytes)
                let limits = try CBORLimits(maxBytes: bodyBytes, maxDepth: 32, maxItems: 262_144)
                let auditLimits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
                let retainedBytes = 67_108_864
                guard maximumPayloadBytes <= retainedBytes else { throw ApprovalCoordinatorError.invalidConfiguration }
                let checkpoint = try storage.continuity.read().committed
                var fresh = Data(count: 16)
                guard fresh.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }) == errSecSuccess else {
                    throw ApprovalCoordinatorError.unavailable
                }
                let epoch = fresh
                let descriptor = try read { transaction in
                    guard let previous = try transaction.epoch(checkpoint.journalEpoch),
                          try transaction.epoch(epoch) == nil else { throw JournalStartupRecovery.Failure.invalidEpoch }
                    var previousID: CBORValue = .null, previousHead: CBORValue = .null, previousDigest: CBORValue = .null
                    if previous.head == 0 {
                        previousID = .bytes(previous.descriptor.epoch); previousHead = .unsigned(0)
                    } else if previous.retainedAfter < previous.head {
                        let page = try transaction.page(epoch: previous.descriptor.epoch, after: previous.head - 1,
                            maximumRecords: 1, maximumBytes: auditLimits.maxBytes)
                        guard let last = page.canonicalRecords.first else { throw AuditJournalError.corruptData }
                        previousID = .bytes(previous.descriptor.epoch); previousHead = .unsigned(previous.head)
                        previousDigest = .bytes(Data(SHA256.hash(data: last)))
                    }
                    // Fully pruned predecessors have no retained event digest. Do not invent a verified link.
                    return try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                        0: .unsigned(1), 1: .bytes(previous.descriptor.macID), 2: .bytes(previous.descriptor.accountID),
                        3: .bytes(epoch), 4: .unsigned(checkpoint.currentAuthorityGeneration), 5: .unsigned(AuditEpochCause.restart.rawValue),
                        6: previousID, 7: previousHead, 8: previousDigest,
                    ]), limits: auditLimits), limits: auditLimits)
                }
                let recovery = try JournalStartupRecovery(journal: database, continuity: storage.continuity,
                    maximumRecords: 128, maximumBytes: 16_777_216)
                var progress = try recovery.start(descriptor: descriptor)
                while true {
                    switch progress {
                    case .recovering: progress = try recovery.advance()
                    case .historyDiscontinuity: throw AuthorityStorageStartupError.historyRecoveryRequired
                    case .repairRequired: throw AuthorityStorageStartupError.repairRequired
                    case .complete:
                        requests = try ApprovalRequestCoordinator(database: database, continuity: storage.continuity,
                            writer: recovery.completedWriter(), clockEpoch: clockEpoch, maximumRequests: 1024,
                            maximumRetainedBytes: retainedBytes, requestLimits: limits, captureLimits: limits,
                            decisionLimits: limits, signingLimits: auditLimits, auditLimits: auditLimits)
                        return
                    }
                }
            } catch {
                try? close()
                throw error
            }
        }
    }

    /// Transfers the database and epoch writer into one serialization boundary.
    /// Recovery and admission-storage gates must pass before construction.
    public init(requests: sending ApprovalRequestCoordinator) {
        database = requests.database
        self.requests = requests
    }

    /// Attach before listeners start. Existing requests cannot be retroactively covered by this barrier.
    func attachReleaseActivityBarrier(_ barrier: ReleaseActivityBarrier) throws {
        try lock.withLock {
            try requireNoRequestOperation()
            guard releaseActivity == nil, commandExecutions.isEmpty, let requests else {
                throw ApprovalCoordinatorError.invalidConfiguration
            }
            try requests.attachReleaseActivityBarrier(barrier)
            releaseActivity = barrier
        }
    }

    /// Pairing and management work use the installed authority's existing machine barrier.
    /// The optional result belongs only to raw component fixtures without an installed registration.
    func acquireReleaseActivity() throws -> ReleaseActivityToken? {
        try lock.withLock {
            try requireNoRequestOperation()
            return try releaseActivity?.acquireShared()
        }
    }

    /// Authorized local setup uses the existing request owner, audit writer and independent checkpoint.
    /// The host authenticates the human transcript first and rechecks native administrator consent in the callback.
    /// Callbacks must not await or reenter this owner. A lost receipt requires reconciliation, not another enrollment.
    public func commitPairing(_ attempt: PairingEnrollmentAttempt, biometricProof: Data,
                          signer: EnclaveAuthorityRequestSigner, addEventID: Data, removalEventID: Data? = nil,
                          receiptTimeMs: UInt64?, gateway: EnrollmentGatewayRemoval? = nil,
                          recheckAdministrator: () throws -> Void, now: () throws -> AuthorityMoment,
                          validateSetupCode: (JournalTransaction) throws -> Void = { _ in })
        throws -> (revision: UUID, receipt: Data, gatewayControl: GatewayAuthorityEnvelope?) {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard signer.macID == attempt.transcript.phone.scope.macID,
              signer.accountID == attempt.transcript.phone.scope.accountID else { throw AuthorityRequestSignerError.wrongIdentity }
        return try withPairingRequestOwner { requests in
            try requests.commitPairing(attempt, biometricProof: biometricProof, authorityPublicKey: signer.publicKey,
                addEventID: addEventID, removalEventID: removalEventID, receiptTimeMs: receiptTimeMs, gateway: gateway,
                verifyHost: { tx in try AuthoritySelfValidation.validate(transaction: tx); try validateSetupCode(tx) },
                recheckAdministrator: recheckAdministrator,
                now: now, sign: signer.sign)
        }
    }

    /// Receipt recovery requires a current authenticated phone binding. It cannot grant or restore enrollment.
    public func pairingReceipt(setupID: Data, binding: AuthorityPeerBinding, signer: EnclaveAuthorityRequestSigner) throws -> Data? {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard signer.macID == binding.scope.macID, signer.accountID == binding.scope.accountID else {
            throw AuthorityRequestSignerError.wrongIdentity
        }
        return try withPairingRequestOwner { requests in
            try requests.pairingReceipt(setupID: setupID, binding: binding, authorityPublicKey: signer.publicKey,
                verifyHost: AuthoritySelfValidation.validate, sign: signer.sign)
        }
    }

    // Same-owner component fixture. Public pairing always validates Root code and uses the enclave signer.
    func commitPairingFixture(_ attempt: PairingEnrollmentAttempt, biometricProof: Data, authorityPublicKey: Data,
                              addEventID: Data, recheckAdministrator: () throws -> Void,
                              now: () throws -> AuthorityMoment, validate: (JournalTransaction) throws -> Void,
                              sign: (Data) throws -> Data) throws -> Data {
        try withPairingRequestOwner { requests in
            try requests.commitPairing(attempt, biometricProof: biometricProof, authorityPublicKey: authorityPublicKey,
                addEventID: addEventID, removalEventID: nil, receiptTimeMs: nil, gateway: nil, verifyHost: validate,
                recheckAdministrator: recheckAdministrator, now: now, sign: sign).receipt
        }
    }
    /// Pairing stays on the exported invocation stack. Native authorization callbacks do not cross executors.
    private func withPairingRequestOwner<Value>(_ body: (ApprovalRequestCoordinator) throws -> Value) throws -> Value {
        try lock.withLock {
            try requireNoRequestOperation()
            guard let requests else { throw ApprovalCoordinatorError.unavailable }
            try requests.requirePairingCheckpoint()
            requestOperationActive = true; defer { requestOperationActive = false }
            return try withStorageFailureCleanup { try body(requests) }
        }
    }

    /// Runs synchronous request work under the journal lock. The coordinator cannot escape in the result.
    /// The callback must not await or reenter this owner.
    public func withRequests<Value: Sendable>(_ body: @Sendable (ApprovalRequestCoordinator) throws -> Value) throws -> Value {
        try lock.withLock {
            try requireNoRequestOperation()
            return try withStorageFailureCleanup {
                try database.read { _ in () } // Reject closed storage or entry from a transaction callback.
                guard let requests else { throw ApprovalCoordinatorError.unavailable }
                requestOperationActive = true
                defer { requestOperationActive = false }
                return try body(requests)
            }
        }
    }

    /// Transfers a command into the serialized request owner, without a Sendable capture wrapper.
    /// A failed first transfer closes its objects. Rejected reentry leaves previously owned objects intact.
    /// The host completes negotiation and current elevation-policy validation before this call.
    /// The request owner commits the submission replay reservation with request creation.
    /// The synchronous callbacks must not await or reenter this journal.
    public func admitCommand(_ command: sending RetainedCommandCapture, draft: ApprovalRequestDraft, currentPolicy: XPCPeerPolicy,
                             now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                             checkCancellation: () throws -> Void = {}) throws -> IssuedRequestPayload {
        lock.lock()
        defer { lock.unlock() }
        let requests: ApprovalRequestCoordinator
        do { requests = try commandAdmissionOwner() }
        catch { command.closeIfUnclaimed(); throw error }
        requestOperationActive = true
        defer { requestOperationActive = false }
        do {
            return try requests.admitCommand(command, draft: draft, currentPolicy: currentPolicy,
                now: now, receiptTimeMs: receiptTimeMs, checkCancellation: checkCancellation)
        } catch {
            if database.retired { retireRequests() }
            throw error
        }
    }

    /// Serialized fixture seam. Aliases only observe resource cleanup; production uses the exclusive transfer above.
    func admitCommand(_ command: RetainedCommandCapture, draft: ApprovalRequestDraft, expression: String,
                      userID: uid_t, auditSessionID: au_asid_t?, now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                      checkCancellation: () throws -> Void = {}) throws -> IssuedRequestPayload {
        try lock.withLock {
            let requests: ApprovalRequestCoordinator
            do { requests = try commandAdmissionOwner() }
            catch { command.closeIfUnclaimed(); throw error }
            requestOperationActive = true
            defer { requestOperationActive = false }
            return try withStorageFailureCleanup {
                try requests.admitCommand(command, draft: draft, expression: expression, userID: userID,
                    auditSessionID: auditSessionID, now: now, receiptTimeMs: receiptTimeMs, checkCancellation: checkCancellation)
            }
        }
    }

    private func commandAdmissionOwner() throws -> ApprovalRequestCoordinator {
        try requireNoRequestOperation()
        try withStorageFailureCleanup { try database.read { _ in () } }
        guard let requests else { throw ApprovalCoordinatorError.unavailable }
        return requests
    }

    /// Handles the original authenticated packet under the journal lock, before any filesystem capture.
    /// Both callbacks are trusted host code. Resolve current elevation policy and lifecycle state without external actions or reentry.
    /// The draft callback receives immutable capture values. Incoming claims cannot select an elevation policy.
    public func admitCommandAttempt(_ attempt: sending RetainedCommandAdmissionAttempt,
                                    resolve: (CommandSubmission) throws -> CommandAdmissionResolution,
                                    draft: (CommandCapture) throws -> ApprovalRequestDraft,
                                    now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                                    checkCancellation: @escaping @Sendable () throws -> Void = {}) throws -> IssuedRequestPayload {
        try handleCommandAttempt(attempt, resolve: resolve, draft: draft, now: now, receiptTimeMs: receiptTimeMs,
            checkCancellation: checkCancellation, validateSelf: { tx in
                guard geteuid() == 0 else { throw JournalLeaseError.rootRequired }
                try AuthoritySelfValidation.validate(transaction: tx)
            }) { snapshot, userID, auditSessionID in
                guard let entry = snapshot.policy.entries.first(where: { $0.role == .commandFrontend }), entry.active,
                      entry.installedGeneration >= entry.minimumGeneration else { throw CommandSessionRegistryError.invalidCodePolicy }
                let policy = try XPCPeerPolicy(teamID: entry.teamID, componentIdentifier: entry.identifier,
                    approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: userID, expectedAuditSessionID: auditSessionID)
                return policy.requirement
            }
    }

    /// Internal fixture identity seam. Production validates the actual Root role and current release frontend policy.
    func admitCommandAttempt(_ attempt: RetainedCommandAdmissionAttempt, expression: String,
                             resolve: (CommandSubmission) throws -> CommandAdmissionResolution,
                             draft: (CommandCapture) throws -> ApprovalRequestDraft,
                             now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                             checkCancellation: @escaping @Sendable () throws -> Void = {}) throws -> IssuedRequestPayload {
        try handleCommandAttempt(attempt, resolve: resolve, draft: draft, now: now, receiptTimeMs: receiptTimeMs,
            checkCancellation: checkCancellation, validateSelf: { _ in }) { _, _, _ in expression }
    }

    private func handleCommandAttempt(_ attempt: RetainedCommandAdmissionAttempt,
                                      resolve: (CommandSubmission) throws -> CommandAdmissionResolution,
                                      draft: (CommandCapture) throws -> ApprovalRequestDraft,
                                      now: () throws -> AuthorityMoment, receiptTimeMs: UInt64?,
                                      checkCancellation: @escaping @Sendable () throws -> Void,
                                      validateSelf: @Sendable (JournalTransaction) throws -> Void,
                                      expression: (AuthorityCodePolicySnapshot, uid_t, au_asid_t?) throws -> String) throws -> IssuedRequestPayload {
        lock.lock(); defer { lock.unlock() }
        do { try requireNoRequestOperation() }
        catch { attempt.closeIfUnclaimed(); throw error }
        try attempt.claimForOwner()
        let profile = attempt.profile, submission = attempt.submission.binding
        let userID = attempt.userID, auditSessionID = attempt.auditSessionID
        let peerExpression: String
        do {
            let policy = try validatedRead { tx in
                try validateSelf(tx)
                let trust = try tx.approvalTrustSnapshot()
                guard trust.macID == profile.macID, trust.accountID == profile.accountID else { throw JournalDatabaseError.wrongScope }
                guard let policy = try tx.codePolicy() else { throw CommandSessionRegistryError.invalidCodePolicy }
                return policy
            }
            peerExpression = try expression(policy, userID, auditSessionID)
            try attempt.recheck(expression: peerExpression)
        } catch {
            try? attempt.send(.uncertain(.storageFailure)); attempt.close(); throw error
        }
        requestOperationActive = true
        defer { requestOperationActive = false }
        do { try checkCancellation() }
        catch { try? attempt.send(.uncertain(.admissionRejected)); attempt.close(); throw error }
        guard requests != nil else {
            try? attempt.send(commandRefusal(profile: profile, submission: submission, reason: .authorityStarting))
            attempt.close(); throw CommandAdmissionControllerError.refused(.authorityStarting)
        }
        let resolution: CommandAdmissionResolution
        do { resolution = try resolve(attempt.submission) }
        catch { try? attempt.send(.uncertain(.admissionRejected)); attempt.close(); throw error }
        let context: CommandAdmissionCaptureContext
        switch resolution {
        case .capture(let value): context = value
        case .refuse(let reason):
            try? attempt.send(commandRefusal(profile: profile, submission: submission, reason: reason))
            attempt.close(); throw CommandAdmissionControllerError.refused(reason)
        }
        let command: RetainedCommandCapture
        do {
            command = try attempt.assemble(context: context, expression: peerExpression, userID: userID,
                auditSessionID: auditSessionID, checkCancellation: {
                    do { try checkCancellation() }
                    catch { throw CommandAdmissionCallbackFailure(underlying: error) }
                })
        } catch {
            let callback = error as? CommandAdmissionCallbackFailure
            let rejection = callback == nil ? Self.commandCaptureRefusal(error) : nil
            let outcome = commandRefusal(profile: profile, submission: submission, reason: rejection)
            try? attempt.send(outcome); attempt.close()
            throw callback?.underlying ?? error
        }
        attempt.close()
        let requestDraft: ApprovalRequestDraft
        do { requestDraft = try draft(command.capture) }
        catch {
            let payload = CommandAdmissionResultPayload(profile: profile, submission: submission,
                submissionDigest: command.submissionDigest, outcome: .uncertain(.admissionRejected))
            try? command.sendAdmissionReply(payload.canonicalBytes); command.close(); throw error
        }
        guard let requests else { command.close(); throw ApprovalCoordinatorError.unavailable }
        do {
            return try requests.admitCommand(command, draft: requestDraft, expression: peerExpression,
                userID: userID, auditSessionID: auditSessionID, now: now,
                receiptTimeMs: receiptTimeMs, checkCancellation: checkCancellation)
        } catch {
            if database.retired { retireRequests() }
            throw error
        }
    }

    /// Apply only to actual capture failures. Callback failures never enter this classifier.
    static func commandCaptureRefusal(_ error: Error) -> CommandAdmissionRejectionReason? {
        switch error {
        case CommandFilesystemCaptureError.invalidPath, CommandFilesystemCaptureError.invalidExecutable,
             CommandFilesystemCaptureError.invalidDirectory: return .invalidRequest
        case CommandFilesystemCaptureError.system(let code) where [ENOENT, ENOTDIR, ELOOP, ENAMETOOLONG].contains(code):
            return .invalidRequest
        default: return nil
        }
    }

    private func commandRefusal(profile: CommandHandshakeProfile, submission: CapturedSubmission,
                                reason: CommandAdmissionRejectionReason?) -> CommandAdmissionOutcome {
        guard let reason else { return .uncertain(.admissionRejected) }
        guard requests?.retainsCommandSubmission(submission) != true else { return .uncertain(.duplicateSubmission) }
        let requestEpoch = requests?.commandAdmissionEpoch
        do {
            let reserved = try validatedRead { tx in
                let trust = try tx.approvalTrustSnapshot()
                guard trust.macID == profile.macID, trust.accountID == profile.accountID else { throw JournalDatabaseError.wrongScope }
                if let requestEpoch, try tx.epoch(requestEpoch) == nil { throw AuditJournalError.unavailableEpoch }
                return try tx.commandSubmissionReserved(submission)
            }
            guard !reserved else { return .uncertain(.duplicateSubmission) }
            let retry: CommandAdmissionRetryClass
            switch reason {
            case .updateInstalling: retry = .updateInstalling
            case .authorityStarting: retry = .authorityStarting
            case .updateWaiting: retry = .updateWaiting
            case .storageUnavailable: retry = .storageUnavailable
            default: retry = .never
            }
            return .notAdmitted(reason, retry)
        } catch { return .uncertain(.storageFailure) }
    }

    /// Keeps policy and recipient validation under the same lock as request work.
    func withValidatedRequests<Value: Sendable>(validate: @Sendable (JournalTransaction) throws -> Void,
                                               body: @Sendable (ApprovalRequestCoordinator) throws -> Value) throws -> Value {
        try lock.withLock {
            try read(validate)
            return try withRequests(body)
        }
    }

    private func requireNoRequestOperation() throws {
        guard !requestOperationActive else { throw JournalDatabaseError.transactionActive }
    }

    public func read<Value: Sendable>(_ body: @Sendable (JournalTransaction) throws -> Value) throws -> Value {
        try lock.withLock {
            try requireNoRequestOperation()
            return try validatedRead(body)
        }
    }

    /// Internal reads remain under the journal lock. They do not clear the request reentry guard.
    private func validatedRead<Value: Sendable>(_ body: @Sendable (JournalTransaction) throws -> Value) throws -> Value {
        return try withStorageFailureCleanup {
            if let storage {
                let checkpoint: ContinuityState
                do {
                    checkpoint = try storage.continuity.read()
                    guard !checkpoint.recoveryRequired, checkpoint.pending == nil else { throw JournalDatabaseError.unavailable }
                } catch {
                    retireAfterValidationFailure(error, continuity: storage.continuity)
                    throw error
                }
                return try database.read { transaction in
                    do {
                        let actual = try CheckpointedJournal.checkpoint(transaction: transaction,
                            epoch: checkpoint.committed.journalEpoch, generation: checkpoint.committed.generation,
                            authorityGeneration: checkpoint.committed.authorityGeneration)
                        guard actual == checkpoint.committed else { throw JournalDatabaseError.unavailable }
                    } catch {
                        retireAfterValidationFailure(error, continuity: storage.continuity)
                        throw error
                    }
                    return try body(transaction)
                }
            }
            return try database.read(body)
        }
    }

    public func write<Value: Sendable>(_ body: @Sendable (JournalTransaction) throws -> Value) throws -> Value {
        try lock.withLock {
            try requireNoRequestOperation()
            guard storage == nil else { throw JournalDatabaseError.readOnly }
            return try withStorageFailureCleanup { try database.write(body) }
        }
    }
    /// Stop the authorization producer and await its post-lock callbacks before draining execution.
    func stopCommandExchanges() async { await commandExchanges.stopAndDrain() }
    func beginCommandExchange() throws { try lock.withLock { try commandExchanges.begin() } }
    func endCommandExchange() { commandExchanges.end() }

    public func close() throws {
        try lock.withLock {
            try requireNoRequestOperation()
            guard !commandExchanges.hasActive else { throw JournalDatabaseError.transactionActive }
            commandExchanges.stop()
            try database.close()
            storage?.continuity.close()
            retireRequests()
            for execution in commandExecutions.values { execution.cancelBeforeRelease() }
        }
    }

    private func withStorageFailureCleanup<Value>(_ body: () throws -> Value) throws -> Value {
        do { return try body() }
        catch {
            if database.retired { retireRequests() }
            throw error
        }
    }

    private func retireAfterValidationFailure(_ error: Error, continuity: ContinuityStore) {
        if database.retired || continuity.retired || !isStorageContention(error) { retireRequests() }
    }

    private func isStorageContention(_ error: Error) -> Bool {
        let code: Int32
        switch error {
        case ContinuityStoreError.storage(let value): code = value
        case JournalDatabaseError.storage(let value): code = value
        case AuditJournalError.storage(let value): code = value
        default: return false
        }
        return code & 0xff == SQLITE_BUSY || code & 0xff == SQLITE_LOCKED
    }

    private func retireRequests() {
        requests?.close()
        requests = nil
    }

    public func trustSnapshot(maximumPayloadBytes: Int, minimumEnvelopeVersion: UInt64 = 1,
                              auditVersions: Set<UInt64> = []) throws -> DirectApprovalTrust {
        try read { try $0.directApprovalTrust(maximumPayloadBytes: maximumPayloadBytes,
            minimumEnvelopeVersion: minimumEnvelopeVersion, auditVersions: auditVersions) }
    }
    /// A current enrollment check, not permission to approve or execute a request.
    public func validatePeer(_ binding: AuthorityPeerBinding) throws -> Bool {
        do {
            try read { try $0.requireDirectApprovalBinding(binding) }
            return true
        } catch EnrollmentJournalError.staleRevision { return false }
          catch EnrollmentJournalError.unavailableEnrollment { return false }
    }
}

public enum CommandAdmissionControllerError: Error, Equatable { case refused(CommandAdmissionRejectionReason) }
private struct CommandAdmissionCallbackFailure: Error { let underlying: Error }


extension AuthorityJournal {
    /// Counts retained command owners, including unreaped children and pending result commits.
    public var activeCommandCount: Int { lock.withLock { commandExecutions.count } }

    /// Reject only the exact original approval that has no native execution owner.
    /// A failed start can already own resources, so its thrown error alone cannot prove no dispatch.
    func cancelUnownedCommandExecution(_ notice: AuthorityCommandAuthorizationNotice, now: AuthorityMoment,
                                       receiptTimeMs: UInt64?) throws -> Bool {
        try lock.withLock {
            try requireNoRequestOperation()
            guard commandExecutions[notice.requestID] == nil else { return false }
            return try withRequests { owner in
                let state: ApprovalRequestState
                do { state = try owner.state(requestID: notice.requestID) }
                catch ApprovalCoordinatorError.unknownRequest { return false }
                guard state.requestKind == .command, state.phase == .authorized,
                      state.requestDigest == notice.requestDigest, state.challenge == notice.challenge else { return false }
                _ = try owner.authorizedCommandApproval(requestID: notice.requestID, now: now)
                _ = try owner.recordOutcome(requestID: notice.requestID, expectedRevision: 0, event: .proveNoDispatch,
                    now: now, receiptTimeMs: receiptTimeMs)
                return true
            }
        }
    }

    /// Check original notice bindings before a start attempt. Existing execution gates remain mandatory.
    func validateCommandAuthorizationNotice(_ notice: AuthorityCommandAuthorizationNotice, now: AuthorityMoment) throws {
        try withRequests { owner in
            let approval = try owner.authorizedCommandApproval(requestID: notice.requestID, now: now)
            guard approval.receipt.decision.requestDigest == notice.requestDigest,
                  approval.retained.payload.challenge == notice.challenge else { throw CommandExecutionError.policyChanged }
        }
    }

    /// Protected host integration. The elevation callback must enforce the selected administrator policy without reentry.
    /// Pipe and PTY execution stay inactive until the host installs the protected command endpoint.
    public func beginCommandExecution(requestID: Data, monitorPath: String, childPath: String, preparationMilliseconds: UInt32,
                                      fileCreationMask: UInt32, maximumActiveCommands: Int = 32, pollIntervalMilliseconds: Int = 20,
                                      validateElevation: @escaping @Sendable (CommandCapture) throws -> Void,
                                      clock: @escaping @Sendable () throws -> AuthorityMoment, receiptTime: @escaping @Sendable () -> UInt64? = { nil }) throws {
        try beginCommandExecution(requestID: requestID, monitorPath: monitorPath, childPath: childPath,
            preparationMilliseconds: preparationMilliseconds, fileCreationMask: fileCreationMask,
            maximumActiveCommands: maximumActiveCommands, pollIntervalMilliseconds: pollIntervalMilliseconds, validateElevation: validateElevation, clock: clock, receiptTime: receiptTime,
            runtime: { tx, approval, capture in
                guard geteuid() == 0 else { throw JournalLeaseError.rootRequired }
                try AuthoritySelfValidation.validate(transaction: tx)
                try approval.requireCurrent(tx.requestDeliveryTrust())
                guard let snapshot = try tx.codePolicy(),
                      let child = snapshot.policy.entries.first(where: { $0.role == .commandChild }), child.active,
                      let monitor = snapshot.policy.entries.first(where: { $0.role == .commandMonitor }), monitor.active,
                      let frontend = snapshot.policy.entries.first(where: { $0.role == .commandFrontend }), frontend.active,
                      let childRevision = snapshot.roleRevisions[.commandChild],
                      let monitorRevision = snapshot.roleRevisions[.commandMonitor],
                      let frontendRevision = snapshot.roleRevisions[.commandFrontend] else { throw CommandExecutionError.policyChanged }
                let policy = try XPCPeerPolicy(teamID: frontend.teamID, componentIdentifier: frontend.identifier,
                    approvedCodeDirectoryHashes: [frontend.codeDirectoryHash], expectedUserID: capture.requester.effectiveUID)
                return CommandExecutionRuntime(child: child, childRevision: childRevision, monitor: monitor, monitorRevision: monitorRevision,
                    frontendRevision: frontendRevision, callerExpression: policy.requirement,
                    userID: capture.requester.effectiveUID, sessionID: nil)
            }, launcher: { context in
                let path = try ProtectedExecutablePath.acquire(path: childPath)
                let monitorPath = try ProtectedExecutablePath.acquire(path: monitorPath)
                return {
                    let policy = try XPCPeerPolicy(teamID: context.child.teamID, componentIdentifier: context.child.identifier,
                        approvedCodeDirectoryHashes: [context.child.codeDirectoryHash], expectedUserID: 0)
                    let evidence = try SignedExecutableValidation.validate(path, policy: policy,
                        committedFloor: context.child.minimumGeneration, installedGeneration: context.child.installedGeneration)
                    guard evidence.generation == context.child.installedGeneration else { throw CommandExecutionError.policyChanged }
                    let monitorPolicy = try XPCPeerPolicy(teamID: context.monitor.teamID, componentIdentifier: context.monitor.identifier,
                        approvedCodeDirectoryHashes: [context.monitor.codeDirectoryHash], expectedUserID: 0)
                    let monitorEvidence = try SignedExecutableValidation.validate(monitorPath, policy: monitorPolicy,
                        committedFloor: context.monitor.minimumGeneration, installedGeneration: context.monitor.installedGeneration)
                    guard monitorEvidence.generation == context.monitor.installedGeneration else { throw CommandExecutionError.policyChanged }
                }
            })
    }

    /// Fixture identity seam. Native spawning, durable transitions and original resources follow the production path.
    func beginCommandExecution(requestID: Data, monitorPath: String, childPath: String, preparationMilliseconds: UInt32,
                               fileCreationMask: UInt32, maximumActiveCommands: Int = 32, pollIntervalMilliseconds: Int = 20,
                               validateElevation: @escaping (CommandCapture) throws -> Void,
                               clock: @escaping () throws -> AuthorityMoment, receiptTime: @escaping () -> UInt64? = { nil },
                               runtime: @escaping @Sendable (JournalTransaction, CommandExecutionApproval, CommandCapture) throws -> CommandExecutionRuntime,
                               launcher: (CommandExecutionRuntime) throws -> () throws -> Void) throws {
        try lock.withLock {
            try requireNoRequestOperation()
            guard (100...60_000).contains(preparationMilliseconds), fileCreationMask <= 0o777,
                  (1...1024).contains(maximumActiveCommands), (10...1000).contains(pollIntervalMilliseconds) else {
                throw CommandExecutionError.invalidConfiguration
            }
            guard commandExecutions.count < maximumActiveCommands,
                  commandExecutions.isEmpty || commandPollIntervalMilliseconds == pollIntervalMilliseconds, commandExecutions[requestID] == nil, let requests else {
                throw CommandExecutionError.unavailable
            }
            requestOperationActive = true
            defer { requestOperationActive = false }
            let approval = try requests.authorizedCommandApproval(requestID: requestID, now: clock())
            let activity = try releaseActivity?.acquireShared()
            var transferredActivity = false
            defer { if !transferredActivity { activity?.close() } }
            let resources = try requests.takeAuthorizedCommandExecution(requestID: requestID, now: clock())
            let capture = resources.capture
            let context: CommandExecutionRuntime
            let checkLauncher: () throws -> Void
            do {
                context = try validatedRead { try runtime($0, approval, capture) }
                checkLauncher = try launcher(context)
            } catch {
                let execution = CommandExecution(resources: resources, approval: approval, clock: clock, receiptTime: receiptTime)
                commandExecutions[requestID] = execution
                commandActivity[requestID] = activity; transferredActivity = true
                startCommandCleanup(intervalMilliseconds: pollIntervalMilliseconds)
                finishCommandExecution(requestID, execution: execution, observedOutcome: .failedBeforeStart)
                throw error
            }
            let execution = CommandExecution(resources: resources, approval: approval, clock: clock, receiptTime: receiptTime,
                callerExpression: context.callerExpression, callerUserID: context.userID, callerSessionID: context.sessionID,
                validateLauncher: checkLauncher, validateElevation: validateElevation)
            commandExecutions[requestID] = execution
            commandActivity[requestID] = activity; transferredActivity = true
            startCommandCleanup(intervalMilliseconds: pollIntervalMilliseconds)
            do { try execution.prepare(monitorPath: monitorPath, childPath: childPath, preparationMilliseconds: preparationMilliseconds, fileCreationMask: fileCreationMask) }
            catch { execution.cancelBeforeRelease(); throw error }
            // The closure stays under this journal's lock and can only verify the same original controller.
            commandStreamChecks[requestID] = {
                try self.validatedRead { tx in
                    guard let snapshot = try tx.codePolicy(),
                          snapshot.roleRevisions[.commandFrontend] == context.frontendRevision,
                          snapshot.policy.entries.contains(where: { $0.role == .commandFrontend && $0.active }) else {
                        throw CommandExecutionError.policyChanged
                    }
                }
            }
            commandRuntimeChecks[requestID] = {
                try self.commandActivity[requestID]?.validate()
                let current = try self.validatedRead { try runtime($0, approval, capture) }
                guard current == context else { throw CommandExecutionError.policyChanged }
                try execution.validateLauncher(); try execution.validateElevation(resources.capture)
            }
        }
    }

    /// Native cleanup does not require available storage or a live request coordinator.
    func pollCommandExecutions() {
        lock.withLock {
            guard !requestOperationActive else { return }
            requestOperationActive = true
            defer { requestOperationActive = false }
            for (id, execution) in commandExecutions {
                switch execution.poll(checkStreamPolicy: {
                    guard let check = self.commandStreamChecks[id] else { throw CommandExecutionError.unavailable }
                    try check()
                }) {
                case .preparing, .running: continue
                case .prepared:
                    do {
                        guard let requests, let validate = commandRuntimeChecks[id] else { throw CommandExecutionError.unavailable }
                        try validate(); try execution.recheck()
                        _ = try requests.recordOutcome(requestID: id, expectedRevision: 0, event: .beginDispatch,
                            now: execution.clock(), receiptTimeMs: execution.receiptTime())
                        execution.dispatchRevision = 1
                        try execution.validateLauncher(); try execution.validateElevation(execution.resources.capture)
                        try execution.recheck()
                        try commandActivity[id]?.validate()
                        try execution.release()
                    } catch { execution.cancelBeforeRelease() }
                case .terminal(let nativeOutcome):
                    finishCommandExecution(id, execution: execution, observedOutcome: nativeOutcome)
                }
            }
            if commandExecutions.isEmpty { commandCleanupTimer?.cancel(); commandCleanupTimer = nil; commandPollIntervalMilliseconds = nil }
        }
    }

    /// Runs only under the journal lock and request-operation guard, including failed pre-spawn validation.
    private func finishCommandExecution(_ id: Data, execution: CommandExecution, observedOutcome: CommandTerminalOutcome) {
        let commitOutcome: CommandTerminalOutcome = execution.terminalCommitFailed ? .unknown : observedOutcome
        var delivered: CommandTerminalOutcome = execution.committedOutcome ?? .unknown
        if execution.committedOutcome == nil, let requests, !requests.retired {
            do {
                let event: RequestEvent
                switch commitOutcome {
                case .exited(0): event = .verifySuccess
                case .exited, .signalled: event = .verifyFailure
                case .failedBeforeStart: event = execution.dispatchRevision == 0 ? .proveNoDispatch : .verifyFailure
                case .requesterExitedBeforeStart: event = execution.dispatchRevision == 0 ? .proveNoDispatch : .loseOutcome
                default: event = .loseOutcome
                }
                _ = try requests.recordOutcome(requestID: id, expectedRevision: execution.dispatchRevision,
                    event: event, now: execution.clock(), receiptTimeMs: execution.receiptTime())
                delivered = commitOutcome
                execution.committedOutcome = commitOutcome
            } catch {
                execution.terminalCommitFailed = true
                execution.deliverTerminal(.unknown)
                if !requests.retired { return }
                retireRequests()
            }
        }
        execution.deliverTerminal(delivered)
        if execution.dispose() {
            commandExecutions.removeValue(forKey: id); commandRuntimeChecks.removeValue(forKey: id); commandStreamChecks.removeValue(forKey: id)
            commandActivity.removeValue(forKey: id)?.close()
        }
        if commandExecutions.isEmpty { commandCleanupTimer?.cancel(); commandCleanupTimer = nil; commandPollIntervalMilliseconds = nil }
    }

    private func startCommandCleanup(intervalMilliseconds: Int) {
        guard commandCleanupTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "dev.remozio.authority.commands"))
        timer.schedule(deadline: .now(), repeating: .milliseconds(intervalMilliseconds), leeway: .milliseconds(2))
        // This lease retains the journal until every owned child is reaped or proven lost, including after close().
        timer.setEventHandler { self.pollCommandExecutions() }
        commandPollIntervalMilliseconds = intervalMilliseconds
        commandCleanupTimer = timer; timer.resume()
    }
}

struct CommandExecutionRuntime: Equatable, Sendable {
    let child: AuthorityCodeEntry
    let childRevision: UUID
    let monitor: AuthorityCodeEntry
    let monitorRevision: UUID
    let frontendRevision: UUID
    let callerExpression: String
    let userID: uid_t
    let sessionID: au_asid_t?
}
