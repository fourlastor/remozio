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
                ownerRouting: (@Sendable (ApprovalRequestCoordinator, AuthorityMoment) throws -> PresenceRouting)? = nil) throws {
        guard (1...60_000).contains(leaseMilliseconds) else { throw AuthorityWakePublisherError.invalidConfiguration }
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
        state = .closed; lease = nil
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
