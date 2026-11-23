import Foundation
import RemozioProtocol

public enum AuthorityWakePublisherError: Error, Equatable {
    case invalidConfiguration, closed, busy, invalidClock, expiredLease, wrongAuthority
}

private struct WakePublicationSample: Sendable {
    let now: AuthorityMoment
    let routing: PresenceRouting
    let trust: RequestDeliveryTrust
    let work: RetainedWakePublicationSnapshot
}

private struct PhonePushPublicationWork: Sendable {
    let enrollment: StoredApprovalEnrollment
    let state: GatewayCurrentTokenState
    func nextRevision(after head: UInt64) -> UInt64 {
        state.candidate.revision > head ? state.candidate.revision : (state.activation?.revision ?? state.candidate.revision)
    }
}

/// Owns one Root control channel and one transient wake incarnation. No network await holds the journal lock.
/// Presence and clock callbacks are trusted, synchronous, and must not reenter the journal or publisher.
public actor AuthorityWakePublisher {
    private enum State { case new, opening, open, closed }
    private let journal: AuthorityJournal
    private let channel: GatewayRootChannel
    private let registration: GatewayRegistrationIdentity
    private let leaseMilliseconds: UInt64
    private let clock: @Sendable () throws -> AuthorityMoment
    private let routing: @Sendable (ApprovalRequestCoordinator, AuthorityMoment) throws -> PresenceRouting
    private let receiptTime: @Sendable () -> UInt64?
    private var phonePush: AuthorityPhonePushPublication?
    private let phonePushSource: (@Sendable () -> AuthorityPhonePushPublication?)?
    private var phonePushConfigurationDigest: Data?
    public private(set) var phonePushDiagnostic: AuthorityPhonePushPublicationDiagnostic
    private let gatewayRevocations: AuthorityGatewayRevocationState?
    private var revocationRecoverySupported: Bool?
    private var grantTombstonesSupported: Bool?
    private var grantTombstoneRetryAt: UInt64 = 0
    private var revocationCapabilityRetryAt: UInt64 = 0
    private var phoneCursor = 0
    private var revocationCursor = 0
    private var probeOperations: [Data: Data] = [:]
    public nonisolated let hintFeed: AuthorityWakeHintFeed
    private var state = State.new
    private var busy = false
    private var loopRunning = false
    private var epoch: UUID?
    private var sequence: UInt64 = 0
    private let session = UUID()
    private var lease: (deadline: UInt64, trustRevision: UUID, phoneRouting: Bool)?

    /// The owner-aware callback may read the durable mode. It must not mutate the owner or reenter the journal.
    public init(journal: AuthorityJournal, channel: GatewayRootChannel, registration: GatewayRegistrationIdentity,
                leaseMilliseconds: UInt64, clock: @escaping @Sendable () throws -> AuthorityMoment,
                routing: @escaping @Sendable () throws -> PresenceRouting,
                receiptTime: @escaping @Sendable () -> UInt64? = { nil },
                ownerRouting: (@Sendable (ApprovalRequestCoordinator, AuthorityMoment) throws -> PresenceRouting)? = nil,
                phonePush: AuthorityPhonePushPublication? = nil,
                phonePushSource: (@Sendable () -> AuthorityPhonePushPublication?)? = nil,
                gatewayRevocations: AuthorityGatewayRevocationState? = nil) throws {
        guard (1...60_000).contains(leaseMilliseconds) else { throw AuthorityWakePublisherError.invalidConfiguration }
        guard phonePush == nil || phonePush?.provider.policy.registration == registration else { throw AuthorityWakePublisherError.wrongAuthority }
        guard gatewayRevocations == nil || gatewayRevocations?.registration == registration else {
            throw AuthorityWakePublisherError.wrongAuthority
        }
        self.phonePush = phonePush; self.phonePushSource = phonePushSource
        self.gatewayRevocations = gatewayRevocations
        phonePushDiagnostic = phonePush == nil ? .disabled : .notStarted
        self.journal = journal; self.channel = channel; self.registration = registration
        self.leaseMilliseconds = leaseMilliseconds; self.clock = clock; self.routing = ownerRouting ?? { _, _ in try routing() }; self.receiptTime = receiptTime
        hintFeed = try AuthorityWakeHintFeed(journal: journal, registration: registration, clock: clock, routing: self.routing, receiptTime: receiptTime)
    }

    /// Add the optional provider between publication turns. Keep the current gateway session, lease and probe history.
    @discardableResult
    func installPhonePush(_ publication: AuthorityPhonePushPublication, configurationDigest: Data) throws -> Bool {
        guard state != .closed else { throw AuthorityWakePublisherError.closed }
        guard state != .opening, !busy else { throw AuthorityWakePublisherError.busy }
        guard configurationDigest.count == 32, publication.provider.policy.registration == registration else {
            throw AuthorityWakePublisherError.wrongAuthority
        }
        if let current = phonePush {
            let left = current.provider.policy, right = publication.provider.policy
            guard current.gatewayPublicKey == publication.gatewayPublicKey, current.maximumPhonesPerTurn == publication.maximumPhonesPerTurn,
                  left.registration == right.registration, left.projectID == right.projectID,
                  left.senderID == right.senderID, left.packageName == right.packageName,
                  phonePushConfigurationDigest == nil || phonePushConfigurationDigest == configurationDigest else {
                throw GatewayPreparationError.changedScope
            }
            phonePushConfigurationDigest = configurationDigest; return false
        }
        phonePush = publication; phonePushConfigurationDigest = configurationDigest; phonePushDiagnostic = .notStarted
        gatewayRevocations?.setPushEnabled(true, owner: session)
        return true
    }

    public func start() async throws {
        guard state == .new else { throw AuthorityWakePublisherError.closed }
        state = .opening
        do {
            try journal.withRequests { try $0.beginWakePublicationSession(session) }
            gatewayRevocations?.begin(session, pushEnabled: phonePush != nil)
            _ = try sample()
            try await channel.start()
            guard state == .opening else { throw AuthorityWakePublisherError.closed }
            state = .open
        } catch { await close(); throw error }
    }

    /// One bounded drain. Rejected registrations retain their exact IDs and deadlines for the next drain.
    /// Hints are available only after a successful registration and a fresh synchronized lease.
    public func reconcile() async throws {
        guard state == .open else { throw AuthorityWakePublisherError.closed }
        guard !busy else { throw AuthorityWakePublisherError.busy }
        if let phonePushSource {
            let next = phonePushSource()
            guard next == nil || next?.provider.policy.registration == registration else { throw AuthorityWakePublisherError.wrongAuthority }
            if next == nil { phonePushDiagnostic = .disabled }
            else if phonePush == nil { phonePushDiagnostic = .notStarted }
            phonePush = next
            gatewayRevocations?.setPushEnabled(next != nil, owner: session)
        }
        busy = true
        hintFeed.pause()
        defer { busy = false }
        do {
            try await synchronize(sample())
            if phonePush != nil {
                do {
                    phonePushDiagnostic = try await reconcilePhonePush() ? .turnCompleted : .retryPending
                } catch {
                    phonePushDiagnostic = .retryPending
                    // A registration failure must not stop healthy foreground approval or ordinary wake publication.
                    _ = try liveSample()
                }
            }
            try await withdrawPending()
            let registrations = try liveSample().work.registrations
            for delivery in registrations {
                let current = try liveSample()
                guard current.routing.destination == .phones, current.work.registrations.contains(delivery) else { continue }
                do { try await channel.registerWake(delivery) }
                catch GatewayRootChannelError.rejected { continue }
                // The asynchronous acknowledgment is data until the serialized owner rechecks the original request.
                try requireOpen()
                let expectedEpoch = epoch, deadline = lease?.deadline
                try journal.withRequests { [clock, routing, receiptTime, session] owner in
                    try owner.requireWakePublicationSession(session)
                    let now = try clock()
                    guard now.epoch == expectedEpoch else { throw AuthorityWakePublisherError.invalidClock }
                    guard let deadline, now.milliseconds < deadline else { throw AuthorityWakePublisherError.expiredLease }
                    _ = try owner.acknowledgeWakeRegistration(delivery, routing: routing(owner, now), now: now, receiptTimeMs: receiptTime())
                }
                try requireOpen()
            }
            // Include withdrawals created while a registration acknowledgment was in flight.
            try await withdrawPending()
            try await synchronize(liveSample())
            let current = try liveSample()
            if let lease {
                hintFeed.publish(epoch: current.now.epoch, deadline: lease.deadline, revision: lease.trustRevision, phoneRouting: lease.phoneRouting)
            }
        } catch { await close(); throw error }
    }

    /// The caller negotiates the hint extension independently of ordinary request-frame delivery.
    /// Every read checks current storage, request phase, enrollment, presence, clock, and the last gateway lease.
    public func readyDeliveryIDs() throws -> [UUID] {
        try requireOpen()
        return try hintFeed.current().deliveryIDs
    }

    /// The runtime retains and cancels this task with its service lifetime. A failed channel cannot be reused.
    public func run(intervalMilliseconds: UInt64) async throws {
        try await run(intervalMilliseconds: intervalMilliseconds, checkAuthority: {})
    }
    /// The shared runtime rechecks retirement before each publication turn.
    func run(intervalMilliseconds: UInt64, checkAuthority: @Sendable () throws -> Void) async throws {
        guard intervalMilliseconds > 0, intervalMilliseconds <= leaseMilliseconds / 2, !loopRunning else {
            throw AuthorityWakePublisherError.invalidConfiguration
        }
        loopRunning = true
        defer { loopRunning = false }
        do {
            if state == .new { try await start() }
            else { try requireOpen() }
            while true {
                try Task.checkCancellation()
                try checkAuthority()
                try await reconcile()
                try await Task.sleep(for: .milliseconds(intervalMilliseconds))
            }
        } catch { await close(); throw error }
    }

    public func close() async {
        guard state != .closed else { return }
        state = .closed; lease = nil; phonePushDiagnostic = .closed
        gatewayRevocations?.close(session)
        hintFeed.close()
        // The gateway's connection lease owns cleanup if withdrawal cannot complete during shutdown.
        try? journal.withRequests { $0.endWakePublicationSession(session) }
        await channel.close()
    }

    private func sample() throws -> WakePublicationSample {
        try Task.checkCancellation()
        let current = try journal.withRequests { [clock, routing, receiptTime, session] owner in
            try owner.requireWakePublicationSession(session)
            let now = try clock(), route = try routing(owner, now), trust = try owner.wakeDeliveryTrust()
            let work = try owner.reconcileWakePublications(routing: route, now: now, receiptTimeMs: receiptTime(), trust: trust)
            return WakePublicationSample(now: now, routing: route, trust: trust, work: work)
        }
        guard current.trust.approval.macID == registration.macID, current.trust.approval.accountID == registration.accountID else {
            throw AuthorityWakePublisherError.wrongAuthority
        }
        if let epoch { guard current.now.epoch == epoch else { throw AuthorityWakePublisherError.invalidClock } }
        else { epoch = current.now.epoch }
        return current
    }
    private func liveSample() throws -> WakePublicationSample {
        try requireOpen()
        let current = try sample()
        guard let lease, current.now.milliseconds < lease.deadline else { throw AuthorityWakePublisherError.expiredLease }
        return current
    }
    private func requireOpen() throws {
        try Task.checkCancellation()
        guard state == .open else { throw AuthorityWakePublisherError.closed }
    }
    private func synchronize(_ current: WakePublicationSample) async throws {
        try requireOpen()
        let (next, sequenceOverflow) = sequence.addingReportingOverflow(1)
        let (deadline, clockOverflow) = current.now.milliseconds.addingReportingOverflow(leaseMilliseconds)
        guard !sequenceOverflow, !clockOverflow else { throw AuthorityWakePublisherError.invalidClock }
        let enrollments = try Self.gatewaySnapshotEnrollments(current.trust.enrollments)
        let snapshot = try GatewayHostSnapshot(registration: registration, rootEpoch: current.now.epoch,
            sequence: next, observedAtMilliseconds: current.now.milliseconds, leaseDeadlineMilliseconds: deadline,
            enrollments: enrollments, active: true, phoneRouting: current.routing.destination == .phones)
        sequence = next
        try await channel.synchronize(snapshot)
        try requireOpen()
        lease = (deadline, current.trust.approval.revision, snapshot.phoneRouting)
        let afterSync = try liveSample()
        if let gatewayRevocations, phonePush != nil {
            if revocationRecoverySupported != true, afterSync.now.milliseconds >= revocationCapabilityRetryAt {
                let supported = try await channel.supportsPhoneRevocationRecovery(registration: registration)
                revocationRecoverySupported = supported
                if !supported {
                    let (retryAt, overflow) = afterSync.now.milliseconds.addingReportingOverflow(30_000)
                    revocationCapabilityRetryAt = overflow ? UInt64.max : retryAt
                }
            }
            let live = try liveSample()
            if let supported = revocationRecoverySupported, live.trust.approval.revision == current.trust.approval.revision {
                gatewayRevocations.publishCapability(supported, now: live.now, deadline: deadline, owner: session)
            }
            if grantTombstonesSupported != true, live.now.milliseconds >= grantTombstoneRetryAt {
                let supported = try await channel.supportsGrantTombstones(registration: registration)
                grantTombstonesSupported = supported
                if !supported {
                    let (retryAt, overflow) = live.now.milliseconds.addingReportingOverflow(30_000)
                    grantTombstoneRetryAt = overflow ? UInt64.max : retryAt
                }
            }
        }
    }

    static func gatewaySnapshotEnrollments(_ retained: [StoredApprovalEnrollment]) throws -> [GatewayPhoneEnrollment] {
        var byPhone: [Data: GatewayPhoneEnrollment] = [:]
        for enrollment in retained {
            let phoneID = enrollment.approval.phoneID
            if let prior = byPhone[phoneID] {
                guard !(prior.active && enrollment.approval.active) else { throw GatewayServiceError.invalidMessage }
                guard enrollment.approval.active else { continue }
            }
            byPhone[phoneID] = try GatewayPhoneEnrollment(phoneID: phoneID, epoch: enrollment.epoch,
                tag: enrollment.notificationTag, active: enrollment.approval.active)
        }
        return Array(byPhone.values)
    }

    private func withPhoneOwner<Value: Sendable>(_ expectedRevision: UUID, _ body: @Sendable (ApprovalRequestCoordinator, AuthorityMoment) throws -> Value) throws -> Value {
        try requireOpen()
        let expectedEpoch = epoch, deadline = lease?.deadline
        return try journal.withRequests { [clock, session] owner in
            try owner.requireWakePublicationSession(session)
            let now = try clock()
            guard now.epoch == expectedEpoch else { throw AuthorityWakePublisherError.invalidClock }
            guard let deadline, now.milliseconds < deadline else { throw AuthorityWakePublisherError.expiredLease }
            guard try owner.wakeDeliveryTrust().approval.revision == expectedRevision else { throw EnrollmentJournalError.staleRevision }
            return try body(owner, now)
        }
    }
    private func phoneState(_ enrollment: StoredApprovalEnrollment, revision: UUID) throws -> GatewayCurrentTokenState? {
        guard let push = phonePush else { return nil }
        return try withPhoneOwner(revision) { owner, now in
            return try owner.currentPhonePushRegistration(push.provider, phoneID: enrollment.approval.phoneID,
                enrollmentEpoch: enrollment.epoch, now: now, wall: push.wallTime())
        }
    }
    private func samePhoneState(_ expected: GatewayCurrentTokenState, enrollment: StoredApprovalEnrollment, revision: UUID) throws -> Bool {
        guard let current = try phoneState(enrollment, revision: revision) else { return false }
        return current.candidate.operationID == expected.candidate.operationID && current.activation?.operationID == expected.activation?.operationID
    }
    private func mappingState(_ state: GatewayCurrentTokenState, revision: UUID) async throws -> VerifiedGatewayMappingState {
        guard let push = phonePush else { throw AuthorityWakePublisherError.invalidConfiguration }
        let now = try liveSample().now, limits = try CBORLimits(maxBytes: 4096, maxDepth: 8, maxItems: 128)
        let candidate = try GatewayTokenCandidate.decode(state.candidate.canonicalPayload, limits: limits)
        let scope = try GatewayMappingScope(registration: registration, binding: candidate.binding)
        let owner = try GatewayMappingQueryOwner(scope: scope, gatewayPublicKey: push.gatewayPublicKey,
            clockEpoch: now.epoch, lifetimeMilliseconds: min(5000, leaseMilliseconds))
        let reply = try await channel.mappingState(query: owner.query(now: now))
        let current = try liveSample()
        guard current.trust.approval.revision == revision else { throw EnrollmentJournalError.staleRevision }
        let observation = try owner.accept(reply, now: current.now)
        guard let deadline = lease?.deadline else { throw AuthorityWakePublisherError.expiredLease }
        try withPhoneOwner(revision) { owner, now in
            try owner.recordPhonePushMapping(push.provider, observation: observation, session: session,
                expectedTrustRevision: revision, validUntilMilliseconds: deadline, now: now, wall: push.wallTime())
        }
        return observation
    }
    private func repairMissing(_ observation: VerifiedGatewayMappingState, state: GatewayCurrentTokenState,
                               enrollment: StoredApprovalEnrollment, revision: UUID) throws {
        guard let push = phonePush, try samePhoneState(state, enrollment: enrollment, revision: revision) else { return }
        _ = try withPhoneOwner(revision) { owner, now in
            try owner.renewMissingPhonePushRegistration(push.provider, observation: observation,
                expectedTrustRevision: revision, now: now, wall: push.wallTime())
        }
    }
    private func reconcilePhonePush() async throws -> Bool {
        guard let push = phonePush else { return true }
        let first = try liveSample(), revision = first.trust.approval.revision
        guard !first.trust.enrollments.isEmpty else {
            gatewayRevocations?.recordGrantHealth(.clear, owner: session)
            phoneCursor = 0; probeOperations = [:]; return true
        }
        let headOwner = try GatewayHeadQueryOwner(registration: registration, gatewayPublicKey: push.gatewayPublicKey,
            clockEpoch: first.now.epoch, lifetimeMillis: min(5000, leaseMilliseconds))
        let reply = try await channel.head(query: headOwner.makeQuery(now: first.now))
        let current = try liveSample(), head = try headOwner.accept(reply, now: current.now)
        if gatewayRevocations != nil {
            try await observeRevocation(head: head, headOwner: headOwner, current: current, revision: revision)
        }
        let acknowledgment = try withPhoneOwner(revision) { owner, now in
            try owner.acknowledgePhonePushHead(push.provider, head: head, expectedTrustRevision: revision, now: now)
        }
        guard acknowledgment.disposition == .recorded || acknowledgment.disposition == .alreadyRecorded else {
            if acknowledgment.disposition == .conflictingLocalHistory {
                gatewayRevocations?.recordGrantHealth(.blocked, owner: session)
            }
            return false
        }
        if try withPhoneOwner(revision, { owner, now in
            try owner.prepareManagedPhoneRevocation(push.provider, now: now, wall: push.wallTime())
        }) { return false }
        let retirement = try withPhoneOwner(revision) { owner, now in
            try owner.phonePushGrantRetirement(push.provider, after: head.evidence.revision, now: now, wall: push.wallTime())
        }
        switch retirement {
        case .none:
            gatewayRevocations?.recordGrantHealth(.clear, owner: session)
        case .expiresBeforeRetirement:
            gatewayRevocations?.recordGrantHealth(.waitingForGrantExpiry, owner: session)
            return false
        case .eligible(let control):
            guard grantTombstonesSupported == true else {
                let health: GatewayRevocationHealth = grantTombstonesSupported == false ? .gatewayUpdateNeeded : .pending
                gatewayRevocations?.recordGrantHealth(health, owner: session)
                return false
            }
            let signature = try withPhoneOwner(revision) { owner, now in
                try owner.abandonPhonePushGrant(control, provider: push.provider, now: now, wall: push.wallTime())
            }
            do {
                _ = try await channel.abandonGrant(control, signature: signature)
                gatewayRevocations?.recordGrantHealth(.pending, owner: session)
            } catch GatewayRootChannelError.rejected {
                // The gateway can commit before losing its reply. A nil reply is not a refusal.
                gatewayRevocations?.recordGrantHealth(.grantAbandonmentInconclusive, owner: session)
            }
            // Another signed head is required before moving on to the next control.
            return false
        }
        let enrollments = current.trust.enrollments.filter { $0.approval.active }
        let phones = Set(enrollments.map { $0.approval.phoneID })
        probeOperations = probeOperations.filter { phones.contains($0.key) }
        let count = min(push.maximumPhonesPerTurn, enrollments.count)
        let start = enrollments.isEmpty ? 0 : phoneCursor % enrollments.count
        defer { phoneCursor = enrollments.isEmpty ? 0 : (start + count) % enrollments.count }
        let retained = try withPhoneOwner(revision) { owner, now in
            let wall = try push.wallTime()
            return try enrollments.compactMap { enrollment -> PhonePushPublicationWork? in
                guard let state = try owner.currentPhonePushRegistration(push.provider, phoneID: enrollment.approval.phoneID,
                    enrollmentEpoch: enrollment.epoch, now: now, wall: wall) else { return nil }
                return PhonePushPublicationWork(enrollment: enrollment, state: state)
            }
        }
        let otherControl = try withPhoneOwner(revision) { owner, now in
            try owner.phonePushPublicationBarrier(push.provider, after: head.evidence.revision, now: now)
        }
        let work = Dictionary(uniqueKeysWithValues: retained.map { ($0.enrollment.approval.phoneID, $0) })
        let signedHead = head.evidence.revision
        let pendingControls = retained.filter { !$0.state.needsRenewal && $0.nextRevision(after: signedHead) > signedHead }
            .sorted { $0.nextRevision(after: signedHead) < $1.nextRevision(after: signedHead) }
        var selected = pendingControls.prefix(count).map(\.enrollment)
        // New controls follow the shared revision order. Remaining slots poll existing mappings in cursor order.
        for index in 0..<count where selected.count < count {
            let enrollment = enrollments[(start + index) % enrollments.count]
            if !selected.contains(where: { $0.approval.phoneID == enrollment.approval.phoneID }) { selected.append(enrollment) }
        }
        selected.sort {
            (work[$0.approval.phoneID]?.nextRevision(after: signedHead) ?? UInt64.max)
                < (work[$1.approval.phoneID]?.nextRevision(after: signedHead) ?? UInt64.max)
        }
        var confirmedHead = head.evidence.revision, completed = true
        for enrollment in selected {
            guard let item = work[enrollment.approval.phoneID] else { continue }
            // Expired probes still wait for a fresh authenticated phone exchange.
            if item.state.needsRenewal {
                guard item.state.activationAbandonmentConfirmed else { continue }
                do {
                    let observation = try await mappingState(item.state, revision: revision)
                    if observation.activation == nil {
                        try repairMissing(observation, state: item.state, enrollment: enrollment, revision: revision)
                    }
                } catch GatewayRootChannelError.rejected { completed = false }
                continue
            }
            let next = item.nextRevision(after: confirmedHead)
            if let otherControl, next > otherControl {
                completed = false; continue
            }
            if next > confirmedHead, next - confirmedHead != 1 {
                completed = false; continue
            }
            do {
                if let appliedRevision = try await publishPhoneState(item.state, enrollment: enrollment, revision: revision, head: confirmedHead) {
                    confirmedHead = max(confirmedHead, appliedRevision)
                }
            } catch GatewayRootChannelError.rejected { completed = false }
        }
        if let otherControl, let envelope = try withPhoneOwner(revision, { owner, now in
            try owner.localPhonePushRevocation(push.provider, revision: otherControl, now: now)
        }) {
            let earlier = pendingControls.contains { item in
                let pending = item.nextRevision(after: signedHead)
                return pending > signedHead && pending < otherControl
            }
            try await recoverRevocation(envelope, signedHead: head.evidence.revision, earlier: earlier, revision: revision)
            return false
        }
        return completed
    }

    private func recoverRevocation(_ envelope: GatewayAuthorityEnvelope, signedHead: UInt64, earlier: Bool,
                                   revision: UUID) async throws {
        let operation = envelope.operationID
        let target = try revocationRecipient(envelope)
        guard let gatewayRevocations else { return }
        if earlier {
            gatewayRevocations.record(.gatewayPending, for: operation, owner: session)
            return
        }
        guard revocationRecoverySupported == true, signedHead == envelope.revision - 1 else {
            if revocationRecoverySupported == true {
                try withPhoneOwner(revision) { [registration] owner, _ in
                    try owner.recordManagedPhoneRevocation(target, registration: registration, progress: .blocked)
                }
            }
            gatewayRevocations.record(.gatewayBlocked, for: operation, owner: session)
            return
        }
        gatewayRevocations.record(.gatewayPending, for: operation, owner: session)
        do {
            _ = try await channel.recoverPhoneRevocation(envelope, registration: registration, expectedHead: signedHead)
            try withPhoneOwner(revision) { _, _ in }
            // The next turn verifies an independent gateway signature before reporting delivery.
        } catch GatewayRootChannelError.rejected {
            // The gateway may have committed before the reply was lost. Recheck its signed head on the next turn.
        }
    }

    private func revocationRecipient(_ envelope: GatewayAuthorityEnvelope) throws -> DeliveryRecipient {
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 8, maxItems: 128)
        let control = try GatewayPhoneRevocation.decode(envelope.canonicalPayload, limits: limits)
        return DeliveryRecipient(phoneID: control.binding.phoneID, enrollmentEpoch: control.binding.enrollmentEpoch)
    }

    private func observeRevocation(head: VerifiedGatewayHead, headOwner: GatewayHeadQueryOwner,
                                   current: WakePublicationSample, revision: UUID) async throws {
        guard let push = phonePush, let gatewayRevocations, head.evidence.revision > 0 else { return }
        let headRevision = head.evidence.revision
        let inactive = current.trust.enrollments.filter { !$0.approval.active }
        guard !inactive.isEmpty else { return }
        let index = revocationCursor % inactive.count
        revocationCursor = (index + 1) % inactive.count
        let phone = DeliveryRecipient(inactive[index])
        let envelope: GatewayAuthorityEnvelope? = try withPhoneOwner(revision) { owner, now in
            if let exact = try owner.localPhonePushRevocation(push.provider, revision: headRevision, now: now),
               gatewayRevocations.deliveryStatus(exact.operationID) != .gatewayApplied {
                return exact
            }
            return try owner.localPhonePushRevocation(push.provider, phone: phone, now: now)
        }
        guard let envelope, envelope.revision <= headRevision,
              gatewayRevocations.deliveryStatus(envelope.operationID) != .gatewayApplied else { return }
        let receipt: GatewayControlReceipt?
        if envelope.revision == headRevision {
            receipt = head.evidence.receipt
        } else {
            let query = try headOwner.makeHistoryQuery(afterRevision: envelope.revision - 1,
                throughRevision: envelope.revision, maximumRecords: 1, now: current.now)
            do {
                let reply = try await channel.history(query: query)
                receipt = try headOwner.acceptHistory(reply, now: liveSample().now).page.records.first
            } catch GatewayRootChannelError.rejected { return }
        }
        // An empty page may reflect incomplete retained history. Only a conflicting receipt proves a mismatch.
        guard let receipt else {
            gatewayRevocations.record(.gatewayInconclusive, for: envelope.operationID, owner: session)
            return
        }
        let matches = receipt.kind == envelope.kind && receipt.operationID == envelope.operationID
            && receipt.canonicalPayload == envelope.canonicalPayload && receipt.signature == envelope.signature
        let target = try revocationRecipient(envelope)
        try withPhoneOwner(revision) { [registration] owner, _ in
            try owner.recordManagedPhoneRevocation(target, registration: registration, progress: matches ? .applied : .blocked)
        }
        gatewayRevocations.record(matches ? .gatewayApplied : .gatewayBlocked, for: envelope.operationID, owner: session)
    }
    private func confirmsMapping(_ observation: VerifiedGatewayMappingState, activation: GatewayAuthorityEnvelope) throws -> Bool {
        guard let mapped = observation.activation else { return false }
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 8, maxItems: 128)
        guard try mapped.encode(limits: limits) == activation.canonicalPayload else { throw GatewayAuthorityError.wrongScope }
        return true
    }
    private func publishPhoneState(_ state: GatewayCurrentTokenState, enrollment: StoredApprovalEnrollment,
                                   revision: UUID, head: UInt64) async throws -> UInt64? {
        if let activation = state.activation {
            if state.candidate.revision > head {
                _ = try await channel.applyTokenCandidate(state.candidate, registration: registration)
                return state.candidate.revision
            }
            let observed = try await mappingState(state, revision: revision)
            guard try samePhoneState(state, enrollment: enrollment, revision: revision) else { return nil }
            if try confirmsMapping(observed, activation: activation) { return activation.revision }
            do {
                _ = try await channel.applyTokenCandidate(state.candidate, registration: registration)
                guard try samePhoneState(state, enrollment: enrollment, revision: revision) else { return nil }
                _ = try await channel.applyTokenActivation(activation, registration: registration)
            } catch GatewayRootChannelError.rejected {
                // A rejection is ambiguous. Only local expiry and another fresh absence can justify replacement.
                guard let push = phonePush else { throw AuthorityWakePublisherError.invalidConfiguration }
                let limits = try CBORLimits(maxBytes: 4096, maxDepth: 8, maxItems: 128)
                let expires = try GatewayMappingActivation.decode(activation.canonicalPayload, limits: limits).expiresAtUnixMillis
                let expired = try withPhoneOwner(revision) { _, _ in try push.wallTime() >= expires }
                guard expired else { throw GatewayRootChannelError.rejected }
                let fresh = try await mappingState(state, revision: revision)
                guard try samePhoneState(state, enrollment: enrollment, revision: revision) else { return nil }
                if try confirmsMapping(fresh, activation: activation) { return activation.revision }
                try repairMissing(fresh, state: state, enrollment: enrollment, revision: revision)
                return nil
            }
            guard try samePhoneState(state, enrollment: enrollment, revision: revision) else { return nil }
            let fresh = try await mappingState(state, revision: revision)
            guard try samePhoneState(state, enrollment: enrollment, revision: revision) else { return nil }
            if try !confirmsMapping(fresh, activation: activation) {
                try repairMissing(fresh, state: state, enrollment: enrollment, revision: revision)
            }
            return activation.revision
        } else if probeOperations[enrollment.approval.phoneID] != state.candidate.operationID {
            _ = try await channel.applyTokenCandidate(state.candidate, registration: registration)
            guard try samePhoneState(state, enrollment: enrollment, revision: revision) else { return nil }
            try await channel.probeCandidate(operationID: state.candidate.operationID, phoneID: enrollment.approval.phoneID)
            guard try samePhoneState(state, enrollment: enrollment, revision: revision) else { return nil }
            probeOperations[enrollment.approval.phoneID] = state.candidate.operationID
            return state.candidate.revision
        }
        return nil
    }

    private func withdrawPending() async throws {
        for delivery in try liveSample().work.withdrawals {
            guard try liveSample().work.withdrawals.contains(delivery) else { continue }
            do { try await channel.withdrawWake(delivery.id) }
            catch GatewayRootChannelError.rejected { continue }
            _ = try liveSample()
            _ = try journal.withRequests { owner in
                try owner.requireWakePublicationSession(session)
                return try owner.acknowledgeWakeWithdrawal(delivery)
            }
            try requireOpen()
        }
    }
}
