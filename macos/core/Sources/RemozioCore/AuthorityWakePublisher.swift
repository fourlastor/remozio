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
    var revision: UInt64 { state.activation?.revision ?? state.candidate.revision }
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
    private let phonePush: AuthorityPhonePushPublication?
    public private(set) var phonePushDiagnostic: AuthorityPhonePushPublicationDiagnostic
    private var phoneCursor = 0
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
                phonePush: AuthorityPhonePushPublication? = nil) throws {
        guard (1...60_000).contains(leaseMilliseconds) else { throw AuthorityWakePublisherError.invalidConfiguration }
        guard phonePush == nil || phonePush?.provider.policy.registration == registration else { throw AuthorityWakePublisherError.wrongAuthority }
        self.phonePush = phonePush
        phonePushDiagnostic = phonePush == nil ? .disabled : .notStarted
        self.journal = journal; self.channel = channel; self.registration = registration
        self.leaseMilliseconds = leaseMilliseconds; self.clock = clock; self.routing = ownerRouting ?? { _, _ in try routing() }; self.receiptTime = receiptTime
        hintFeed = try AuthorityWakeHintFeed(journal: journal, registration: registration, clock: clock, routing: self.routing, receiptTime: receiptTime)
    }

    public func start() async throws {
        guard state == .new else { throw AuthorityWakePublisherError.closed }
        state = .opening
        do {
            try journal.withRequests { try $0.beginWakePublicationSession(session) }
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
        let enrollments = try current.trust.enrollments.map {
            try GatewayPhoneEnrollment(phoneID: $0.approval.phoneID, epoch: $0.epoch, tag: $0.notificationTag, active: $0.approval.active)
        }
        let snapshot = try GatewayHostSnapshot(registration: registration, rootEpoch: current.now.epoch,
            sequence: next, observedAtMilliseconds: current.now.milliseconds, leaseDeadlineMilliseconds: deadline,
            enrollments: enrollments, active: true, phoneRouting: current.routing.destination == .phones)
        sequence = next
        try await channel.synchronize(snapshot)
        try requireOpen()
        lease = (deadline, current.trust.approval.revision, snapshot.phoneRouting)
        _ = try liveSample()
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
        guard first.trust.enrollments.contains(where: { $0.approval.active }) else {
            phoneCursor = 0; probeOperations = [:]; return true
        }
        let headOwner = try GatewayHeadQueryOwner(registration: registration, gatewayPublicKey: push.gatewayPublicKey,
            clockEpoch: first.now.epoch, lifetimeMillis: min(5000, leaseMilliseconds))
        let reply = try await channel.head(query: headOwner.makeQuery(now: first.now))
        let current = try liveSample(), head = try headOwner.accept(reply, now: current.now)
        let acknowledgment = try withPhoneOwner(revision) { owner, now in
            try owner.acknowledgePhonePushHead(push.provider, head: head, expectedTrustRevision: revision, now: now)
        }
        guard acknowledgment.disposition == .recorded || acknowledgment.disposition == .alreadyRecorded else { return false }
        let enrollments = current.trust.enrollments.filter { $0.approval.active }
        let phones = Set(enrollments.map { $0.approval.phoneID })
        probeOperations = probeOperations.filter { phones.contains($0.key) }
        guard !enrollments.isEmpty else { phoneCursor = 0; return true }
        let count = min(push.maximumPhonesPerTurn, enrollments.count), start = phoneCursor % enrollments.count
        defer { phoneCursor = (start + count) % enrollments.count }
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
        let pendingControls = retained.filter { !$0.state.needsRenewal && $0.revision > head.evidence.revision }.sorted { $0.revision < $1.revision }
        var selected = pendingControls.prefix(count).map(\.enrollment)
        // New controls follow the shared revision order. Remaining slots poll existing mappings in cursor order.
        for index in 0..<count where selected.count < count {
            let enrollment = enrollments[(start + index) % enrollments.count]
            if !selected.contains(where: { $0.approval.phoneID == enrollment.approval.phoneID }) { selected.append(enrollment) }
        }
        selected.sort { (work[$0.approval.phoneID]?.revision ?? UInt64.max) < (work[$1.approval.phoneID]?.revision ?? UInt64.max) }
        var confirmedHead = head.evidence.revision, completed = true
        for enrollment in selected {
            // Expired probes wait for a fresh authenticated phone exchange. A timer must not fill retained history with renewals.
            guard let item = work[enrollment.approval.phoneID], !item.state.needsRenewal else { continue }
            if let otherControl, item.revision > otherControl {
                completed = false; continue
            }
            if let barrier = pendingControls.first(where: { $0.revision > confirmedHead }), item.revision > barrier.revision {
                completed = false; continue
            }
            do {
                if let appliedRevision = try await publishPhoneState(item.state, enrollment: enrollment, revision: revision) {
                    confirmedHead = max(confirmedHead, appliedRevision)
                }
            } catch GatewayRootChannelError.rejected { completed = false }
        }
        return completed
    }
    private func confirmsMapping(_ observation: VerifiedGatewayMappingState, activation: GatewayAuthorityEnvelope) throws -> Bool {
        guard let mapped = observation.activation else { return false }
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 8, maxItems: 128)
        guard try mapped.encode(limits: limits) == activation.canonicalPayload else { throw GatewayAuthorityError.wrongScope }
        return true
    }
    private func publishPhoneState(_ state: GatewayCurrentTokenState, enrollment: StoredApprovalEnrollment,
                                   revision: UUID) async throws -> UInt64? {
        if let activation = state.activation {
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
