import Foundation
import RemozioProtocol
import Synchronization

/// Optional providers for one running journal and clock. No lock is held across a journal operation.
/// The runtime must authenticate and revalidate protected metadata before installation.
final class AuthorityPhonePushCapability: Sendable {
    private struct Installed: Sendable {
        let options: AuthorityPhonePushStartupConfiguration
        let publication: AuthorityPhonePushPublication
        let commitDigest: Data
    }
    private struct State {
        var installed: Installed?
        var installing = false
        var closed = false
    }
    private let state = Mutex(State())
    private let journal: AuthorityJournal
    private let registration: GatewayRegistrationIdentity
    private let clock: @Sendable () throws -> AuthorityMoment
    private let wall: @Sendable () throws -> UInt64
    private let makeProvider: @Sendable (AuthorityPhonePushStartupConfiguration) throws -> AuthorityPhonePushRegistration

    init(journal: AuthorityJournal, registration: GatewayRegistrationIdentity,
         clock: @escaping @Sendable () throws -> AuthorityMoment, wall: @escaping @Sendable () throws -> UInt64,
         makeProvider: @escaping @Sendable (AuthorityPhonePushStartupConfiguration) throws -> AuthorityPhonePushRegistration) {
        self.journal = journal; self.registration = registration; self.clock = clock; self.wall = wall; self.makeProvider = makeProvider
    }
    var publication: AuthorityPhonePushPublication? { state.withLock { $0.closed ? nil : $0.installed?.publication } }
    var installedCommitDigest: Data? { state.withLock { $0.closed ? nil : $0.installed?.commitDigest } }

    /// Install once without changing request deadlines, pairing, listener ownership or the running clock.
    /// Matching retries keep the existing provider. Settings changes need a separate explicit transition.
    @discardableResult
    func install(_ options: AuthorityPhonePushStartupConfiguration, commitDigest: Data,
                 verifyCurrent: () throws -> Void) throws -> Bool {
        guard commitDigest.count == 32 else { throw GatewayPreparationError.invalidRecord }
        let previous = try state.withLock { state in
            guard !state.closed else { throw AuthorityWakePublisherError.closed }
            guard !state.installing else { throw AuthorityWakePublisherError.busy }
            if let installed = state.installed {
                guard installed.options.canonicalBytes == options.canonicalBytes, installed.commitDigest == commitDigest else {
                    throw GatewayPreparationError.changedScope
                }
            }
            state.installing = true; return state.installed
        }
        defer { state.withLock { $0.installing = false } }
        try verifyCurrent()
        if previous != nil {
            try state.withLock { guard !$0.closed else { throw AuthorityWakePublisherError.closed } }
            return false
        }
        let provider = try makeProvider(options), expected = try options.registrationPolicy(registration)
        guard provider.policy.registration == expected.registration, provider.policy.projectID == expected.projectID,
              provider.policy.senderID == expected.senderID, provider.policy.packageName == expected.packageName else {
            throw GatewayPreparationError.changedScope
        }
        let publication = try AuthorityPhonePushPublication(provider: provider, gatewayPublicKey: options.gatewayReceiptPublicKey, wallTime: wall)
        let moment = try clock()
        try state.withLock { guard !$0.closed else { throw AuthorityWakePublisherError.closed } }
        _ = try journal.enableGatewayPolicy(options.journalPolicy(clockEpoch: moment.epoch), macID: registration.macID,
            accountID: registration.accountID, verifyCurrent: verifyCurrent)
        try journal.withRequests { [clock] owner in try owner.preparePhonePushRegistration(provider, now: clock()) }
        try verifyCurrent()
        try state.withLock {
            guard !$0.closed else { throw AuthorityWakePublisherError.closed }
            $0.installed = Installed(options: options, publication: publication, commitDigest: commitDigest)
        }
        return true
    }
    func registrationProvider() -> AuthorityPhonePushRegistrationProvider {
        { [self] owner, binding, frame, validate in
            try AuthorityPhonePushExchange.request(frame, binding: binding)
            guard let provider = publication?.provider else {
                return .outcome(correlationID: frame.correlationID, outcome: .unavailable)
            }
            return try provider.provider(clock: clock, wall: wall)(owner, binding, frame, validate)
        }
    }
    func recoveryProvider() -> AuthorityPhonePushRecoveryProvider {
        { [self] owner, binding, frame, validate in
            try AuthorityPhonePushRecoveryExchange.request(frame, binding: binding)
            guard let provider = publication?.provider else {
                return .outcome(correlationID: frame.correlationID, failure: .unavailable)
            }
            return try provider.recoveryProvider(clock: clock, wall: wall)(owner, binding, frame, validate)
        }
    }
    /// Stop future optional admissions. The service still owns any admitted journal work until it settles.
    func close() { state.withLock { $0.closed = true; $0.installed = nil } }
}
