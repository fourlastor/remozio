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
        var available = false
        var installing = false
        var closed = false
        var pendingSettings: AuthorityPhonePushSettingsChange?
        var acceptedSettings: AuthorityPhonePushSettingsChange?
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
    var publication: AuthorityPhonePushPublication? { state.withLock { ($0.closed || !$0.available) ? nil : $0.installed?.publication } }
    var installedCommitDigest: Data? { state.withLock { ($0.closed || !$0.available) ? nil : $0.installed?.commitDigest } }

    /// Install once without changing request deadlines, pairing, listener ownership or the running clock.
    /// Matching retries keep the existing provider. Settings changes need a separate explicit transition.
    @discardableResult
    func install(_ options: AuthorityPhonePushStartupConfiguration, commitDigest: Data,
                 verifyCurrent: () throws -> Void) throws -> Bool {
        try install(options, commitDigest: commitDigest, configureLedger: true, verifyCurrent: verifyCurrent)
    }
    /// Startup already opened the configured ledger. Preserve its existing request-owner and legacy startup behavior.
    @discardableResult
    func installInitialConfiguration(_ options: AuthorityPhonePushStartupConfiguration, configurationDigest: Data) throws -> Bool {
        try install(options, commitDigest: configurationDigest, configureLedger: false, verifyCurrent: {})
    }
    private func install(_ options: AuthorityPhonePushStartupConfiguration, commitDigest: Data, configureLedger: Bool,
                         verifyCurrent: () throws -> Void) throws -> Bool {
        guard commitDigest.count == 32 else { throw GatewayPreparationError.invalidRecord }
        try Task.checkCancellation()
        let previous = try state.withLock { state in
            guard !state.closed else { throw AuthorityWakePublisherError.closed }
            guard !state.installing, state.pendingSettings == nil else { throw AuthorityWakePublisherError.busy }
            if let installed = state.installed {
                guard installed.options.canonicalBytes == options.canonicalBytes, installed.commitDigest == commitDigest else {
                    throw GatewayPreparationError.changedScope
                }
            }
            state.installing = true; return (installed: state.installed, available: state.available)
        }
        defer { state.withLock { $0.installing = false } }
        try verifyCurrent()
        if previous.installed != nil, previous.available {
            try state.withLock { guard !$0.closed else { throw AuthorityWakePublisherError.closed } }
            return false
        }
        let provider = try previous.installed?.publication.provider ?? makeProvider(options)
        let expected = try options.registrationPolicy(registration)
        guard provider.policy.registration == expected.registration, provider.policy.projectID == expected.projectID,
              provider.policy.senderID == expected.senderID, provider.policy.packageName == expected.packageName else {
            throw GatewayPreparationError.changedScope
        }
        let publication = try AuthorityPhonePushPublication(provider: provider, gatewayPublicKey: options.gatewayReceiptPublicKey, wallTime: wall)
        let moment = try clock()
        try state.withLock { guard !$0.closed else { throw AuthorityWakePublisherError.closed } }
        if configureLedger {
            _ = try journal.enableGatewayPolicy(options.journalPolicy(clockEpoch: moment.epoch), macID: registration.macID,
                accountID: registration.accountID, verifyCurrent: verifyCurrent)
        }
        try journal.withRequests { [clock] owner in try owner.preparePhonePushRegistration(provider, now: clock()) }
        try verifyCurrent(); try Task.checkCancellation()
        try state.withLock {
            guard !$0.closed else { throw AuthorityWakePublisherError.closed }
            $0.installed = Installed(options: options, publication: publication, commitDigest: commitDigest)
            $0.available = true
        }
        return true
    }
    /// Fence new phone registration work, then drain the existing serialized owner.
    /// The native owner must verify the retained, authorized change. This does not stop the wake publisher.
    @discardableResult
    func quiesceSettings(_ change: AuthorityPhonePushSettingsChange, verifyCurrent: () throws -> Void) throws -> Bool {
        try Task.checkCancellation()
        try state.withLock { state in
            guard !state.closed else { throw AuthorityWakePublisherError.closed }
            guard !state.installing else { throw AuthorityWakePublisherError.busy }
            guard let installed = state.installed, installed.commitDigest == change.previousCommitDigest,
                  state.pendingSettings == nil || state.pendingSettings == change else { throw GatewayPreparationError.changedScope }
            state.installing = true
        }
        defer { state.withLock { $0.installing = false } }
        try verifyCurrent()
        let first = try state.withLock { state in
            guard !state.closed else { throw AuthorityWakePublisherError.closed }
            let first = state.pendingSettings == nil
            state.pendingSettings = change; state.acceptedSettings = nil; state.available = false
            return first
        }
        // Earlier handlers hold this journal lock. Later handlers observe the fence before choosing a provider.
        try journal.withRequests { [clock] owner in
            try owner.requireLiveGatewaySetup(clockEpoch: clock().epoch)
        }
        try verifyCurrent(); try Task.checkCancellation()
        try state.withLock { guard !$0.closed else { throw AuthorityWakePublisherError.closed } }
        return first
    }

    /// Admit an exact successor while keeping optional admissions suspended.
    /// A later ordinary monitor pass must validate the selected protected files before restoring the same provider.
    @discardableResult
    func acceptSettings(_ change: AuthorityPhonePushSettingsChange, verifyCurrent: () throws -> Void) throws -> Bool {
        try Task.checkCancellation()
        let alreadyAccepted = try state.withLock { state in
            guard !state.closed else { throw AuthorityWakePublisherError.closed }
            guard !state.installing else { throw AuthorityWakePublisherError.busy }
            guard let installed = state.installed else { throw GatewayPreparationError.changedScope }
            let already = state.pendingSettings == nil && state.acceptedSettings == change &&
                installed.commitDigest == change.selectedCommitDigest
            guard already || (state.pendingSettings == change && installed.commitDigest == change.previousCommitDigest) else {
                throw GatewayPreparationError.changedScope
            }
            state.installing = true; return already
        }
        defer { state.withLock { $0.installing = false } }
        try verifyCurrent()
        try journal.withRequests { [clock] owner in
            try owner.requireLiveGatewaySetup(clockEpoch: clock().epoch)
        }
        try verifyCurrent(); try Task.checkCancellation()
        return try state.withLock { state in
            guard !state.closed, let previous = state.installed else { throw AuthorityWakePublisherError.closed }
            if alreadyAccepted { return false }
            state.installed = Installed(options: previous.options, publication: previous.publication,
                commitDigest: change.selectedCommitDigest)
            state.pendingSettings = nil; state.acceptedSettings = change; state.available = false
            return true
        }
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
    func close() { state.withLock { $0.closed = true; $0.available = false; $0.installed = nil } }
    /// A missing or invalid optional record stops future admissions. Matching verified metadata can restore the same provider.
    func suspend() { state.withLock { $0.available = false } }
}
