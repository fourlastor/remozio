import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum GatewayDeliveryError: Error, Equatable {
    case invalidConfiguration, stopped, capacityExceeded, alreadyRunning, unknownEnrollment, invalidClock
}

/// Local limits for one gateway process. Waiting for OAuth or a retry occupies a flight slot.
public struct GatewayDeliveryPolicy: Sendable {
    public let maximumFlights: Int
    public let minimumSendIntervalMillis: UInt64
    public let retryBaseDelayMillis: UInt64
    public let maximumRetryBackoffMillis: UInt64
    public init(maximumFlights: Int, minimumSendIntervalMillis: UInt64, retryBaseDelayMillis: UInt64 = 1000,
                maximumRetryBackoffMillis: UInt64 = 60_000) throws {
        guard (1...64).contains(maximumFlights), (1...3_600_000).contains(minimumSendIntervalMillis),
              (1...3_600_000).contains(retryBaseDelayMillis),
              (retryBaseDelayMillis...3_600_000).contains(maximumRetryBackoffMillis) else {
            throw GatewayDeliveryError.invalidConfiguration
        }
        self.maximumFlights = maximumFlights; self.minimumSendIntervalMillis = minimumSendIntervalMillis
        self.retryBaseDelayMillis = retryBaseDelayMillis; self.maximumRetryBackoffMillis = maximumRetryBackoffMillis
    }
}

/// Owns the database, probe tasks, and approval wake tasks. Trusted setup methods are local APIs, never submission endpoints.
public actor GatewayDeliveryCoordinator {
    private let database: GatewayDatabase
    private let identity: GatewayRegistrationIdentity
    private let tokens: FCMTokenSource
    private let policy: GatewayDeliveryPolicy
    private let validateAuthority: @Sendable () throws -> Void
    private let sample: @Sendable () throws -> Sample
    private let sleep: @Sendable (UInt64) async throws -> Void
    private let send: @Sendable (FCMTokenProbe, FCMAccessToken) async throws -> FCMDeliveryResult
    private let wakePolicy: GatewayWakePolicy?
    private let sendWake: (@Sendable (FCMWake, FCMAccessToken) async throws -> FCMDeliveryResult)?
    private var phoneRouting = false
    private let schedulerSleep: @Sendable (UInt64) async throws -> Void
    private var schedulerTask: Task<Void, Never>?
    private var scheduledWakes: [WakeScope: Task<Void, Never>] = [:]
    private var schedulingRetryAt: [WakeScope: UInt64] = [:]
    private var presenceCancelledSchedules: Set<WakeScope> = []
    private var schedulerInterval: UInt64 = 0
    private var lastScheduledScope: WakeScope?
    private var synchronizingHost = false

    private struct WakeScope: Hashable { let phone: Data; let epoch: Data }
    private enum WakeOrigin: Equatable { case root, transport(Data?) }
    private struct WakeEntry {
        let delivery: PhoneRequestDelivery
        var origin: WakeOrigin = .root
        var status: GatewayWakeStatus = .queued
        var attempts = 0
        var providerResult: FCMDeliveryResult?
        var progress: GatewayWakeProgress {
            GatewayWakeProgress(deliveryID: delivery.id, status: status, attempts: attempts, lastProviderResult: providerResult)
        }
    }
    private struct WakeBatch {
        let id: UUID
        let identifier: Data
        let members: [UUID]
        var attempts = 0
        var retryAt: UInt64 = 0
    }
    private struct WakeFlight {
        let id: UUID
        let task: Task<[GatewayWakeProgress], any Error>
    }
    private var wakes: [UUID: WakeEntry] = [:]
    private var wakeBatches: [WakeScope: WakeBatch] = [:]
    private var parkedWakeBatches: [WakeScope: [WakeBatch]] = [:]
    private var wakeFlights: [WakeScope: WakeFlight] = [:]
    private var nextEnrollmentSend: [WakeScope: UInt64] = [:]
    private var enrollments: [Data: GatewayPhoneEnrollment] = [:]
    private var trustRevision = UUID()
    private var active = true
    private var stopped = false
    private var shutdownTask: Task<Void, any Error>?
    private var nextSend: UInt64
    private var lastMoment: AuthorityMoment
    private var flights: [Data: Flight] = [:]

    struct Sample: Sendable { let wall: UInt64; let moment: AuthorityMoment }
    private struct Flight {
        let id: UUID
        let phone: Data
        let enrollmentEpoch: Data
        let task: Task<GatewayProbeProgress?, any Error>
    }

    public init(database: sending GatewayDatabase, identity: GatewayRegistrationIdentity, tokens: FCMTokenSource,
                sender: FCMWakeSender, policy: GatewayDeliveryPolicy, clockEpoch: UUID, wakePolicy: GatewayWakePolicy? = nil,
                validateAuthority: @escaping @Sendable () throws -> Void = {}) throws {
        let wakeSender: (@Sendable (FCMWake, FCMAccessToken) async throws -> FCMDeliveryResult)?
        if wakePolicy != nil { wakeSender = { try validateAuthority(); return try await sender.send($0, accessToken: $1) } }
        else { wakeSender = nil }
        let clock = try AuthorityClock(epoch: clockEpoch)
        try self.init(database: database, identity: identity, tokens: tokens, policy: policy, sample: {
            let wall = Date().timeIntervalSince1970 * 1000
            guard wall.isFinite, wall >= 0, wall < Double(UInt64.max) else { throw GatewayDeliveryError.invalidClock }
            let moment: AuthorityMoment
            do { moment = try clock.now() } catch { throw GatewayDeliveryError.invalidClock }
            return Sample(wall: UInt64(wall), moment: moment)
        }, sleep: { try await Task.sleep(for: .milliseconds($0)) }, send: {
            try validateAuthority(); return try await sender.send($0, accessToken: $1)
        }, wakePolicy: wakePolicy, sendWake: wakeSender, validateAuthority: validateAuthority)
    }

    init(database: sending GatewayDatabase, identity: GatewayRegistrationIdentity, tokens: FCMTokenSource,
         policy: GatewayDeliveryPolicy, sample: @escaping @Sendable () throws -> Sample,
         sleep: @escaping @Sendable (UInt64) async throws -> Void,
         send: @escaping @Sendable (FCMTokenProbe, FCMAccessToken) async throws -> FCMDeliveryResult,
         wakePolicy: GatewayWakePolicy? = nil,
         sendWake: (@Sendable (FCMWake, FCMAccessToken) async throws -> FCMDeliveryResult)? = nil,
         validateAuthority: @escaping @Sendable () throws -> Void = {},
         schedulerSleep: @escaping @Sendable (UInt64) async throws -> Void = { try await Task.sleep(for: .milliseconds($0)) }) throws {
        guard (wakePolicy == nil) == (sendWake == nil) else { throw GatewayDeliveryError.invalidConfiguration }
        self.wakePolicy = wakePolicy; self.sendWake = sendWake; self.schedulerSleep = schedulerSleep
        let first = try sample()
        let (next, overflow) = first.moment.milliseconds.addingReportingOverflow(policy.minimumSendIntervalMillis)
        guard !overflow else { throw GatewayDeliveryError.invalidClock }
        self.database = database; self.identity = identity; self.tokens = tokens; self.policy = policy
        self.validateAuthority = validateAuthority
        self.sample = sample; self.sleep = sleep; self.send = send; lastMoment = first.moment; nextSend = next
    }

    /// The host supplies retained, authenticated enrollment state after protected setup or reconciliation.
    /// Changes cancel affected work. It cannot clear database revocation tombstones.
    public func replaceTrustedEnrollments(_ values: [GatewayPhoneEnrollment], active: Bool) throws {
        try running()
        guard values.count <= 1024, Set(values.map(\.phoneID)).count == values.count else {
            throw GatewayDeliveryError.invalidConfiguration
        }
        let next = Dictionary(uniqueKeysWithValues: values.map { ($0.phoneID, $0) })
        for flight in flights.values {
            let before = enrollments[flight.phone], after = next[flight.phone]
            if self.active != active || before?.epoch != after?.epoch || before?.tag != after?.tag || before?.active != after?.active {
                flight.task.cancel()
            }
        }
        for (id, entry) in wakes {
            let before = enrollments[entry.delivery.recipient.phoneID], after = next[entry.delivery.recipient.phoneID]
            if !active || before?.epoch != after?.epoch || before?.tag != after?.tag || after?.active != true {
                withdrawWake(id)
            }
        }
        nextEnrollmentSend = nextEnrollmentSend.filter { next[$0.key.phone]?.epoch == $0.key.epoch }
        enrollments = next; self.active = active; trustRevision = UUID()
        schedulingRetryAt = schedulingRetryAt.filter { next[$0.key.phone]?.epoch == $0.key.epoch }
        pumpWakeScheduling()
    }

    /// The native host seals the old lease before replacing state. Activation and routing share one actor turn.
    func synchronizeHost(_ snapshot: GatewayHostSnapshot, lease: GatewayAuthorityLease) throws {
        try running()
        guard snapshot.registration == identity else { throw GatewayServiceError.invalidMessage }
        synchronizingHost = true
        defer { synchronizingHost = false; pumpWakeScheduling() }
        try lease.renew(rootEpoch: snapshot.rootEpoch, sequence: snapshot.sequence,
            observedAt: snapshot.observedAtMilliseconds, deadline: snapshot.leaseDeadlineMilliseconds) {
            try replaceTrustedEnrollments(snapshot.enrollments, active: snapshot.active)
            try setPhoneRouting(snapshot.phoneRouting)
        }
    }

    func authorityUnavailable() {
        for task in scheduledWakes.values { task.cancel() }
        for flight in flights.values { flight.task.cancel() }
        for flight in wakeFlights.values { flight.task.cancel() }
    }

    public func admitCandidate(canonicalPayload: Data, signature: Data, wireVersion: UInt64,
                               registrationToken: String, phoneID: Data) throws -> GatewayCandidateAdmission {
        try running()
        let time = try current()
        return try database.admitCandidate(canonicalPayload: canonicalPayload, signature: signature, wireVersion: wireVersion,
            registrationToken: registrationToken, trust: trust(phoneID), nowUnixMillis: time.wall, now: time.moment)
    }

    /// Root-only control plane. The current host lease and registration remain authoritative; no phone enrollment is required.
    public func applySubmission(canonicalPayload: Data, signature: Data, wireVersion: UInt64) throws -> GatewaySubmissionApplication {
        try running()
        let time = try current()
        let result = try database.applySubmission(canonicalPayload: canonicalPayload, signature: signature, wireVersion: wireVersion,
            trust: GatewaySubmissionTrust(registration: identity, active: active, revision: trustRevision, appliedControlRevision: database.head()),
            nowUnixMillis: time.wall, now: time.moment)
        if result.inserted {
            // A fresh proof may resume retained work, but cannot reset its deadline or attempt count.
            let credential = try currentWakeCredential()?.credentialID
            for (scope, flight) in wakeFlights {
                if let batch = wakeBatches[scope], wakeMembers(batch).contains(where: {
                    $0.origin != .root && !wakeAuthorized($0, credential: credential)
                }) {
                    flight.task.cancel()
                }
            }
            pumpWakeScheduling()
        }
        return result
    }

    public func applyRecipient(canonicalPayload: Data, signature: Data, wireVersion: UInt64,
                               kind: GatewayRecipientKind, phoneID: Data) throws -> GatewayRecipientApplication {
        try running()
        let time = try current()
        let result = try database.applyRecipient(canonicalPayload: canonicalPayload, signature: signature, wireVersion: wireVersion,
            kind: kind, trust: trust(phoneID), nowUnixMillis: time.wall, now: time.moment)
        if result.inserted && kind == .phoneRevocation {
            for flight in flights.values where flight.phone == result.receipt.phoneID && flight.enrollmentEpoch == result.receipt.enrollmentEpoch {
                flight.task.cancel()
            }
            for (id, entry) in wakes where entry.delivery.recipient.phoneID == result.receipt.phoneID &&
                entry.delivery.recipient.enrollmentEpoch == result.receipt.enrollmentEpoch { withdrawWake(id) }
        }
        if result.inserted && kind == .activation {
            schedulingRetryAt.removeValue(forKey: WakeScope(phone: result.receipt.phoneID, epoch: result.receipt.enrollmentEpoch))
        }
        pumpWakeScheduling()
        return result
    }

    /// Registered root callers only; the service host must authenticate the channel before calling.
    /// The signer belongs to the host's pinned gateway key and must never come from message fields.
    /// Historical reads remain available while delivery is inactive. They grant no delivery or approval authority.
    public func recoveryHeadReply(canonicalQuery: Data, sign: @Sendable (Data) throws -> Data) throws -> GatewayHeadReply {
        try recoveryScope()
        return try database.headReply(canonicalQuery: canonicalQuery, sign: sign)
    }

    /// A fresh optional query shares the existing Root control connection and does not change enrollment or provider state.
    func mappingStateReply(canonicalQuery: Data, sign: @Sendable (Data) throws -> Data) throws -> GatewayMappingStateReply {
        try recoveryScope(); _ = try current()
        let (scope, _) = try GatewayMappingStateWire.query(canonicalQuery)
        return try database.mappingStateReply(query: canonicalQuery, trust: trust(scope.phoneID), sign: sign)
    }

    /// Reads one bounded page on the same actor that applies controls. No token or provider call is involved.
    public func recoveryHistoryReply(canonicalQuery: Data, sign: @Sendable (Data) throws -> Data) throws -> GatewayControlHistoryReply {
        try recoveryScope()
        return try database.controlHistoryReply(canonicalQuery: canonicalQuery, sign: sign)
    }

    private func recoveryScope() throws {
        try running()
        guard try database.headEvidence().registration == identity else { throw GatewayDatabaseError.wrongScope }
    }

    public func progress(operationID: Data) throws -> GatewayProbeProgress? {
        try running(); return try database.probeProgress(candidateOperationID: operationID)
    }

    /// Runs bounded retries for an admitted candidate. Acceptance still requires a separate phone proof and root control.
    public func deliverProbe(operationID: Data, phoneID: Data) async throws -> GatewayProbeProgress? {
        let task = try beginProbe(operationID: operationID, phoneID: phoneID)
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }

    /// Accept bounded service-owned work without occupying the Root control connection during provider I/O.
    public func startProbe(operationID: Data, phoneID: Data) throws {
        _ = try beginProbe(operationID: operationID, phoneID: phoneID)
    }
    private func beginProbe(operationID: Data, phoneID: Data) throws -> Task<GatewayProbeProgress?, any Error> {
        try running(); try Task.checkCancellation()
        _ = try current()
        guard operationID.count == 16 else { throw GatewayDatabaseError.wrongScope }
        guard flights[operationID] == nil else { throw GatewayDeliveryError.alreadyRunning }
        guard flights.count + wakeFlights.count < policy.maximumFlights else { throw GatewayDeliveryError.capacityExceeded }
        let enrollment = try trust(phoneID).enrollment
        guard let receipt = try database.receipt(operationID: operationID), receipt.candidate.binding.phoneID == phoneID,
              receipt.candidate.binding.enrollmentEpoch == enrollment.epoch else { throw GatewayDatabaseError.wrongScope }
        let id = UUID()
        let task = Task {
            defer {
                if flights[operationID]?.id == id { flights.removeValue(forKey: operationID) }
                pumpWakeScheduling()
            }
            return try await self.run(operationID: operationID, phoneID: phoneID)
        }
        flights[operationID] = Flight(id: id, phone: phoneID, enrollmentEpoch: enrollment.epoch, task: task)
        return task
    }

    public func cancel(operationID: Data) { flights[operationID]?.task.cancel() }

    public func shutdown() async throws {
        if let shutdownTask { try await shutdownTask.value; return }
        stopped = true
        let scheduler = schedulerTask, scheduled = Array(scheduledWakes.values)
        scheduler?.cancel()
        for task in scheduled { task.cancel() }
        let tasks = flights.values.map(\.task), wakeTasks = wakeFlights.values.map(\.task)
        for task in tasks { task.cancel() }
        for task in wakeTasks { task.cancel() }
        let task = Task {
            await scheduler?.value
            for task in scheduled { await task.value }
            for task in tasks { _ = await task.result }
            for task in wakeTasks { _ = await task.result }
            await tokens.shutdown()
            try database.close()
        }
        shutdownTask = task
        try await task.value
    }

    /// Authenticated root-host state only. Presence changes delivery, never approval authority.
    /// Queued work pauses with its original batch identifier, attempt budget, and request deadlines.
    public func setPhoneRouting(_ enabled: Bool) throws {
        try running(); phoneRouting = enabled
        if !enabled {
            presenceCancelledSchedules.formUnion(scheduledWakes.keys)
            for flight in wakeFlights.values { flight.task.cancel() }
        }
        pumpWakeScheduling()
    }

    /// Start the service-owned drain loop after protected setup. The interval bounds retries of preparation failures.
    /// New work and completed flights also trigger a drain without waiting for the timer. Shutdown owns every task.
    public func startWakeScheduling(retryIntervalMillis: UInt64) throws {
        try running()
        guard wakePolicy != nil else { throw GatewayWakeError.unavailable }
        guard (1...60_000).contains(retryIntervalMillis) else { throw GatewayDeliveryError.invalidConfiguration }
        guard schedulerTask == nil else { throw GatewayDeliveryError.alreadyRunning }
        _ = try current()
        schedulerInterval = retryIntervalMillis
        schedulerTask = Task { [weak self] in
            guard let self else { return }
            await self.runWakeScheduling()
        }
        pumpWakeScheduling()
    }

    private func runWakeScheduling() async {
        while !Task.isCancelled && !stopped {
            do { try await schedulerSleep(schedulerInterval) }
            catch { return }
            guard !Task.isCancelled else { return }
            pumpWakeScheduling()
        }
    }

    private func pumpWakeScheduling() {
        guard !synchronizingHost else { return }
        guard schedulerTask != nil, !stopped else { return }
        let now: UInt64
        do { now = try current().moment.milliseconds }
        catch { return }
        expireWakes(now)
        for (scope, flight) in wakeFlights {
            if let batch = wakeBatches[scope], wakeMembers(batch).isEmpty { flight.task.cancel() }
        }
        guard phoneRouting else { return }
        let credential = try? currentWakeCredential()?.credentialID
        let scopes = Set(wakes.values.filter { $0.status == .queued && wakeAuthorized($0, credential: credential) }
            .map(wakeScope)).sorted(by: scopePrecedes)
        let ordered: [WakeScope]
        if let lastScheduledScope {
            ordered = scopes.filter { scopePrecedes(lastScheduledScope, $0) } + scopes.filter { !scopePrecedes(lastScheduledScope, $0) }
        } else { ordered = scopes }
        for scope in ordered where scheduledWakes[scope] == nil && wakeFlights[scope] == nil && (schedulingRetryAt[scope] ?? 0) <= now {
            let reserved = scheduledWakes.keys.filter { wakeFlights[$0] == nil }.count
            guard flights.count + wakeFlights.count + reserved < policy.maximumFlights else { break }
            lastScheduledScope = scope
            scheduledWakes[scope] = Task { await self.runScheduledWake(scope) }
        }
    }

    private func scopePrecedes(_ a: WakeScope, _ b: WakeScope) -> Bool {
        a.phone == b.phone ? a.epoch.lexicographicallyPrecedes(b.epoch) : a.phone.lexicographicallyPrecedes(b.phone)
    }

    private func runScheduledWake(_ scope: WakeScope) async {
        do {
            _ = try await deliverWakeBatch(phoneID: scope.phone, enrollmentEpoch: scope.epoch)
            schedulingRetryAt.removeValue(forKey: scope)
        } catch {
            // An expected presence pause may resume immediately. Unexpected cancellation still needs preparation backoff.
            if presenceCancelledSchedules.contains(scope) || !phoneRouting || wakeBatches[scope] == nil {
                schedulingRetryAt.removeValue(forKey: scope)
            } else if !stopped, let now = try? current().moment.milliseconds {
                let (retry, overflow) = now.addingReportingOverflow(schedulerInterval)
                schedulingRetryAt[scope] = overflow ? UInt64.max : retry
            }
        }
        presenceCancelledSchedules.remove(scope)
        scheduledWakes.removeValue(forKey: scope)
        pumpWakeScheduling()
    }

    /// The root host submits only its current, authorized pending deliveries. This is not a wire endpoint.
    /// Repeating an unchanged identity returns its current state. A conflicting reuse cannot renew its deadline.
    @discardableResult
    public func enqueueWake(_ delivery: PhoneRequestDelivery) throws -> GatewayWakeProgress {
        try retainWake(delivery, origin: .root)
    }

    /// Root registers a retained delivery over its authenticated channel. Registration alone schedules nothing.
    @discardableResult
    public func registerWake(_ delivery: PhoneRequestDelivery) throws -> GatewayWakeProgress {
        try retainWake(delivery, origin: .transport(nil))
    }

    /// The restricted endpoint consumes its fresh challenge before calling this method.
    /// All recipient and deadline fields come from the Root-owned registry, never the submission.
    @discardableResult
    func submitWake(_ submission: GatewayWakeSubmission, signature: Data, challenge: GatewayWakeChallenge) throws -> GatewayWakeProgress {
        try running(); try Task.checkCancellation()
        let now = try current().moment
        expireWakes(now.milliseconds)
        guard challenge.issuedAt <= now.milliseconds, now.milliseconds < challenge.deadline,
              challenge.deadline > challenge.issuedAt, challenge.deadline - challenge.issuedAt <= 60_000 else {
            throw GatewayWakeSubmissionError.invalidMessage
        }
        guard let credential = try currentWakeCredential() else { throw GatewayWakeSubmissionError.unavailableCredential }
        try submission.authenticate(signature: signature, expectedChallenge: challenge.bytes, registration: identity, credential: credential)
        let id = try GatewayHostSnapshot.uuid(submission.deliveryID)
        guard var entry = wakes[id], case .transport = entry.origin,
              entry.status != .withdrawn, entry.status != .expired,
              now.milliseconds < entry.delivery.deadlineMilliseconds else { throw GatewayWakeSubmissionError.unknownDelivery }
        guard phoneRouting else { throw GatewayWakeError.localRouting }
        _ = try wakeMapping(wakeScope(entry))
        entry.origin = .transport(credential.credentialID)
        wakes[id] = entry
        pumpWakeScheduling()
        return entry.progress
    }

    private func retainWake(_ delivery: PhoneRequestDelivery, origin: WakeOrigin) throws -> GatewayWakeProgress {
        try running()
        guard let wakePolicy else { throw GatewayWakeError.unavailable }
        let now = try current().moment
        expireWakes(now.milliseconds)
        if let entry = wakes[delivery.id] {
            guard entry.delivery == delivery,
                  (entry.origin == .root) == (origin == .root) else { throw GatewayWakeError.conflictingDelivery }
            return entry.progress
        }
        guard delivery.recipient.phoneID.count == 16, delivery.recipient.enrollmentEpoch.count == 16,
              delivery.requestID.count == 16, delivery.admittedAt.epoch == now.epoch,
              delivery.admittedAt.milliseconds <= now.milliseconds, now.milliseconds < delivery.deadlineMilliseconds,
              delivery.deadlineMilliseconds - delivery.admittedAt.milliseconds <= wakePolicy.maximumLifetimeMillis else {
            throw GatewayWakeError.invalidDelivery
        }
        _ = try wakeMapping(WakeScope(phone: delivery.recipient.phoneID, epoch: delivery.recipient.enrollmentEpoch))
        // Expired identities cannot be retried with their original deadlines. Live identities retain deduplication state.
        discardFinishedWakeBatches()
        let retained = Set(wakeBatches.values.flatMap(\.members) + parkedWakeBatches.values.flatMap { $0.flatMap(\.members) })
        wakes = wakes.filter { $0.value.delivery.deadlineMilliseconds > now.milliseconds || retained.contains($0.key) }
        guard wakes.count < wakePolicy.maximumEntries else { throw GatewayDeliveryError.capacityExceeded }
        let entry = WakeEntry(delivery: delivery, origin: origin)
        wakes[delivery.id] = entry
        pumpWakeScheduling()
        return entry.progress
    }

    public func wakeProgress(deliveryID: UUID) throws -> GatewayWakeProgress? {
        try running(); expireWakes(try current().moment.milliseconds)
        return wakes[deliveryID]?.progress
    }

    /// Resolution, expiry from the root, or enrollment withdrawal retires only this delivery.
    public func cancelWake(deliveryID: UUID) throws { try running(); withdrawWake(deliveryID) }

    /// Freeze one enrollment's queued members before dispatch, then use the same opaque wake for every retry.
    /// Later arrivals remain queued for the next batch. The host drains queued work and retries capacity or preparation failures.
    public func deliverWakeBatch(phoneID: Data, enrollmentEpoch: Data) async throws -> [GatewayWakeProgress] {
        try running(); try Task.checkCancellation()
        guard wakePolicy != nil else { throw GatewayWakeError.unavailable }
        guard phoneRouting else { throw GatewayWakeError.localRouting }
        let scope = WakeScope(phone: phoneID, epoch: enrollmentEpoch)
        guard wakeFlights[scope] == nil else { throw GatewayDeliveryError.alreadyRunning }
        guard flights.count + wakeFlights.count < policy.maximumFlights else { throw GatewayDeliveryError.capacityExceeded }
        expireWakes(try current().moment.milliseconds)
        discardFinishedWakeBatches()
        let credential = try currentWakeCredential()?.credentialID
        if let batch = wakeBatches[scope], authorizedWakeMembers(batch, credential: credential).isEmpty {
            parkedWakeBatches[scope, default: []].append(batch)
            wakeBatches.removeValue(forKey: scope)
        }
        if wakeBatches[scope] == nil,
           let index = parkedWakeBatches[scope]?.firstIndex(where: { !authorizedWakeMembers($0, credential: credential).isEmpty }) {
            wakeBatches[scope] = parkedWakeBatches[scope]?.remove(at: index)
        }
        if wakeBatches[scope] == nil {
            let retained = Set(parkedWakeBatches[scope, default: []].flatMap(\.members))
            let members = wakes.values.filter { $0.status == .queued && wakeScope($0) == scope &&
                wakeAuthorized($0, credential: credential) && !retained.contains($0.delivery.id) }
                .map { $0.delivery.id }.sorted { $0.uuidString < $1.uuidString }
            guard !members.isEmpty else { return [] }
            wakeBatches[scope] = WakeBatch(id: UUID(), identifier: SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }, members: members)
        }
        let id = UUID()
        let task = Task { try await self.runWake(scope) }
        wakeFlights[scope] = WakeFlight(id: id, task: task)
        defer {
            if wakeFlights[scope]?.id == id { wakeFlights.removeValue(forKey: scope) }
            discardFinishedWakeBatches()
            pumpWakeScheduling()
        }
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }

    private func runWake(_ scope: WakeScope) async throws -> [GatewayWakeProgress] {
        guard let initial = wakeBatches[scope], let wakePolicy, let sendWake else { throw GatewayWakeError.unavailable }
        do {
            while true {
                try running(); try Task.checkCancellation()
                guard phoneRouting else { throw GatewayWakeError.localRouting }
                let now = try current().moment
                expireWakes(now.milliseconds)
                guard var batch = wakeBatches[scope], batch.id == initial.id else { throw GatewayWakeError.invalidDelivery }
                for entry in wakeMembers(batch) where entry.attempts >= wakePolicy.maximumAttempts {
                    wakes[entry.delivery.id]?.status = .exhausted
                }
                if wakeMembers(batch).isEmpty { break }
                let live = authorizedWakeMembers(batch, credential: try currentWakeCredential()?.credentialID)
                guard !live.isEmpty else { throw GatewayWakeSubmissionError.unavailableCredential }
                _ = try wakeMapping(scope)
                let earliestDeadline = live.map { $0.delivery.deadlineMilliseconds }.min()!
                let due = max(batch.retryAt, max(nextSend, nextEnrollmentSend[scope] ?? 0))
                if now.milliseconds < due { try await wait(until: min(due, earliestDeadline)); continue }
                let grant = try await tokens.token()
                let bearer: FCMAccessToken
                do { bearer = try await tokens.accessToken(for: grant) }
                catch FCMError.tokenExpired { continue }
                catch FCMTokenSourceError.invalidated { continue }
                try running(); try Task.checkCancellation()
                guard phoneRouting else { throw GatewayWakeError.localRouting }
                let time = try current().moment
                expireWakes(time.milliseconds)
                if wakeMembers(batch).isEmpty { break }
                let ready = authorizedWakeMembers(batch, credential: try currentWakeCredential()?.credentialID)
                guard !ready.isEmpty else { throw GatewayWakeSubmissionError.unavailableCredential }
                let currentDue = max(batch.retryAt, max(nextSend, nextEnrollmentSend[scope] ?? 0))
                if time.milliseconds < currentDue { continue }
                let mapping = try wakeMapping(scope)
                let remaining = ready.map { $0.delivery.deadlineMilliseconds - time.milliseconds }.min()!
                let ttl = UInt32(min(UInt64(wakePolicy.maximumTTLSeconds), remaining / 1000))
                let wake = try FCMWake(registrationToken: mapping.registrationToken, identifier: batch.identifier,
                    enrollmentTag: mapping.activation.binding.enrollmentTag, ttlSeconds: ttl, priority: .high)
                let (globalNext, globalOverflow) = time.milliseconds.addingReportingOverflow(policy.minimumSendIntervalMillis)
                let (enrollmentNext, enrollmentOverflow) = time.milliseconds.addingReportingOverflow(wakePolicy.minimumEnrollmentIntervalMillis)
                guard !globalOverflow, !enrollmentOverflow else { throw GatewayDeliveryError.invalidClock }
                batch.attempts += 1; wakeBatches[scope] = batch
                for entry in ready {
                    wakes[entry.delivery.id]?.status = .dispatching
                    wakes[entry.delivery.id]?.attempts += 1
                }
                nextSend = globalNext; nextEnrollmentSend[scope] = enrollmentNext
                let dispatched = WakeBatch(id: batch.id, identifier: batch.identifier, members: ready.map { $0.delivery.id },
                    attempts: batch.attempts, retryAt: batch.retryAt)
                let result: FCMDeliveryResult
                do { result = try await sendWake(wake, bearer) }
                catch {
                    try Task.checkCancellation()
                    guard (error as? FCMError) == .network else { finishWakeMembers(dispatched, status: .failed); throw error }
                    markWakeRetry(dispatched, result: nil)
                    try scheduleWakeRetry(scope, batch: batch, minimum: 0)
                    continue
                }
                try running(); try Task.checkCancellation()
                expireWakes(try current().moment.milliseconds)
                for entry in wakeMembers(dispatched) { wakes[entry.delivery.id]?.providerResult = result }
                switch result {
                case .accepted: finishWakeMembers(dispatched, status: .accepted)
                case .authenticationRequired:
                    markWakeRetry(dispatched, result: result)
                    await tokens.invalidate(grant)
                    try Task.checkCancellation()
                    try scheduleWakeRetry(scope, batch: batch, minimum: 0)
                    continue
                case .retryable(let seconds):
                    let delay = (seconds * 1000).rounded(.up)
                    guard seconds.isFinite, seconds >= 0, delay.isFinite, delay < Double(UInt64.max) else {
                        finishWakeMembers(dispatched, status: .rejected); break
                    }
                    markWakeRetry(dispatched, result: result)
                    try scheduleWakeRetry(scope, batch: batch, minimum: UInt64(delay))
                    continue
                case .registrationInvalid:
                    _ = try database.invalidateMapping(mapping, trust: trust(scope.phone))
                    finishWakeMembers(dispatched, status: .rejected)
                case .validated, .senderMismatch, .rejected: finishWakeMembers(dispatched, status: .rejected)
                }
                if wakeMembers(batch).isEmpty { break }
            }
        } catch {
            // Cancellation or preparation failure keeps the frozen batch for an explicit host retry, without extending any deadline.
            if let batch = wakeBatches[scope], batch.id == initial.id { markWakeRetry(batch, result: nil) }
            throw error
        }
        let result = initial.members.compactMap { wakes[$0]?.progress }
        wakeBatches.removeValue(forKey: scope)
        return result
    }

    private func discardFinishedWakeBatches() {
        for (scope, batch) in wakeBatches where wakeFlights[scope] == nil && wakeMembers(batch).isEmpty {
            wakeBatches.removeValue(forKey: scope)
        }
        for (scope, batches) in parkedWakeBatches {
            let retained = batches.filter { !wakeMembers($0).isEmpty }
            if retained.isEmpty { parkedWakeBatches.removeValue(forKey: scope) }
            else { parkedWakeBatches[scope] = retained }
        }
    }

    private func currentWakeCredential() throws -> GatewayActiveSubmissionCredential? {
        guard active else { return nil }
        return try database.activeSubmissionCredential(trust: GatewaySubmissionTrust(registration: identity,
            active: active, revision: trustRevision, appliedControlRevision: database.head()))
    }
    private func wakeAuthorized(_ entry: WakeEntry, credential: Data?) -> Bool {
        switch entry.origin {
        case .root: return true
        case .transport(let submitted): return submitted != nil && submitted == credential
        }
    }
    private func authorizedWakeMembers(_ batch: WakeBatch, credential: Data?) -> [WakeEntry] {
        wakeMembers(batch).filter { wakeAuthorized($0, credential: credential) }
    }

    private func scheduleWakeRetry(_ scope: WakeScope, batch: WakeBatch, minimum: UInt64) throws {
        let now = try current().moment.milliseconds
        let delay = max(minimum, backoff(batch.attempts))
        let (next, overflow) = now.addingReportingOverflow(delay)
        if overflow { finishWakeMembers(batch, status: .rejected); return }
        wakeBatches[scope]?.retryAt = next
    }
    private func markWakeRetry(_ batch: WakeBatch, result: FCMDeliveryResult?) {
        for entry in wakeMembers(batch) {
            wakes[entry.delivery.id]?.status = .queued
            if let result { wakes[entry.delivery.id]?.providerResult = result }
        }
    }
    private func finishWakeMembers(_ batch: WakeBatch, status: GatewayWakeStatus) {
        for entry in wakeMembers(batch) { wakes[entry.delivery.id]?.status = status }
    }
    private func wakeMembers(_ batch: WakeBatch) -> [WakeEntry] {
        batch.members.compactMap { wakes[$0] }.filter { $0.status == .queued || $0.status == .dispatching }
    }
    private func wakeScope(_ entry: WakeEntry) -> WakeScope {
        WakeScope(phone: entry.delivery.recipient.phoneID, epoch: entry.delivery.recipient.enrollmentEpoch)
    }
    private func wakeMapping(_ scope: WakeScope) throws -> GatewayActiveMapping {
        let trusted = try trust(scope.phone)
        guard trusted.enrollment.epoch == scope.epoch,
              let mapping = try database.activeMapping(trust: trusted) else { throw GatewayWakeError.unavailableMapping }
        return mapping
    }
    private func expireWakes(_ now: UInt64) {
        for (id, entry) in wakes where entry.delivery.deadlineMilliseconds <= now && (entry.status == .queued || entry.status == .dispatching) {
            wakes[id]?.status = .expired
        }
    }
    private func withdrawWake(_ id: UUID) {
        guard let entry = wakes[id] else { return }
        if entry.status == .queued || entry.status == .dispatching { wakes[id]?.status = .withdrawn }
        let scope = wakeScope(entry)
        if let batch = wakeBatches[scope], wakeMembers(batch).isEmpty { wakeFlights[scope]?.task.cancel() }
    }

    private func run(operationID: Data, phoneID: Data) async throws -> GatewayProbeProgress? {
        while true {
            try running(); try Task.checkCancellation()
            if let progress = try database.probeProgress(candidateOperationID: operationID) {
                switch progress.status {
                case .accepted, .terminal: return progress
                case .retryable:
                    if let retry = progress.retryAtMilliseconds { try await wait(until: retry) }
                case .reserved, .dispatched: throw GatewayProbeError.attemptInFlight
                }
            }
            let beforeOAuth = try current()
            try database.checkProbeCandidate(candidateOperationID: operationID, trust: trust(phoneID),
                nowUnixMillis: beforeOAuth.wall, now: beforeOAuth.moment)
            let grant = try await tokens.token()
            // Reentrancy during OAuth or pacing must not preserve stale enrollment state or a stale deadline.
            while true {
                try running(); try Task.checkCancellation()
                let time = try current()
                if time.moment.milliseconds < nextSend { try await wait(until: nextSend); continue }
                break
            }
            // Refresh the bearer after pacing, then repeat pacing if another flight took the next slot.
            let freshBearer: FCMAccessToken
            do { freshBearer = try await tokens.accessToken(for: grant) }
            catch FCMError.tokenExpired { continue }
            catch FCMTokenSourceError.invalidated { continue }
            try running(); try Task.checkCancellation()
            let time = try current()
            if time.moment.milliseconds < nextSend { continue }
            let (next, overflow) = time.moment.milliseconds.addingReportingOverflow(policy.minimumSendIntervalMillis)
            guard !overflow else { throw GatewayDeliveryError.invalidClock }
            let snapshot = try trust(phoneID)
            let reservation = try database.reserveProbe(candidateOperationID: operationID, trust: snapshot,
                nowUnixMillis: time.wall, now: time.moment)
            do {
                let probe = try database.takeProbe(reservation, trust: snapshot, nowUnixMillis: time.wall, now: time.moment)
                nextSend = next
                let result = try await send(probe, freshBearer)
                try Task.checkCancellation()
                let outcome: GatewayProbeOutcome
                switch result {
                case .accepted: outcome = .accepted
                case .authenticationRequired:
                    await tokens.invalidate(grant)
                    try Task.checkCancellation()
                    outcome = .retry(minimumDelayMillis: backoff(reservation.number))
                case .retryable(let seconds): outcome = retry(seconds, attempt: reservation.number)
                case .validated, .registrationInvalid, .senderMismatch, .rejected: outcome = .terminal
                }
                try database.finishProbe(reservation, outcome: outcome, now: current().moment)
            } catch {
                // A lost response does not establish receipt. The original candidate remains the only retry scope.
                let retry = !Task.isCancelled && !stopped && (error as? FCMError) == .network
                try database.finishProbe(reservation, outcome: retry ? .retry(minimumDelayMillis: backoff(reservation.number)) : .terminal,
                    now: clockSample().moment)
                if !retry { throw error }
            }
        }
    }

    private func backoff(_ attempt: Int) -> UInt64 {
        let base = min(policy.maximumRetryBackoffMillis, policy.retryBaseDelayMillis * (UInt64(1) << min(max(attempt - 1, 0), 31)))
        return min(policy.maximumRetryBackoffMillis, base + UInt64.random(in: 0...(base / 4)))
    }
    private func retry(_ seconds: TimeInterval, attempt: Int) -> GatewayProbeOutcome {
        let millis = (seconds * 1000).rounded(.up)
        guard seconds.isFinite, seconds >= 0, millis.isFinite, millis < Double(UInt64.max) else { return .terminal }
        return .retry(minimumDelayMillis: max(UInt64(millis), backoff(attempt)))
    }
    private func wait(until deadline: UInt64) async throws {
        let now = try current().moment.milliseconds
        if deadline > now { try await sleep(deadline - now) }
        try Task.checkCancellation()
    }
    var activeProbeCount: Int { flights.count }
    var scheduledWakeCount: Int { scheduledWakes.count }

    private func running() throws { guard !stopped else { throw GatewayDeliveryError.stopped } }
    private func current() throws -> Sample {
        do { try validateAuthority() }
        catch { authorityUnavailable(); throw error }
        return try clockSample()
    }
    /// Finish an existing reservation after authority loss while retaining clock epoch and regression checks.
    private func clockSample() throws -> Sample {
        let result = try sample()
        guard result.moment.epoch == lastMoment.epoch, result.moment.milliseconds >= lastMoment.milliseconds else {
            stopped = true
            schedulerTask?.cancel()
            for task in scheduledWakes.values { task.cancel() }
            for flight in flights.values { flight.task.cancel() }
            for flight in wakeFlights.values { flight.task.cancel() }
            throw GatewayDeliveryError.invalidClock
        }
        lastMoment = result.moment
        return result
    }
    private func trust(_ phone: Data) throws -> GatewayCandidateTrust {
        guard let enrollment = enrollments[phone] else { throw GatewayDeliveryError.unknownEnrollment }
        return try GatewayCandidateTrust(ownerID: identity.ownerID, macID: identity.macID, accountID: identity.accountID,
            gatewayID: identity.gatewayID, lifecycleEpoch: identity.lifecycleEpoch, rootPublicKey: identity.rootPublicKey,
            active: active, revision: trustRevision, appliedControlRevision: database.head(), enrollment: enrollment)
    }
}
