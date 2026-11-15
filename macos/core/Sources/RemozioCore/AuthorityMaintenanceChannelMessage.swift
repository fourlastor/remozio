import Foundation
import RemozioProtocol

/// Bounded correlation metadata. Native peer checks and the protected record read remain separate requirements.
struct AuthorityMaintenanceChannelRequest: Equatable, Sendable {
    enum Action: UInt64, CaseIterable, Sendable { case open = 1, observe = 2, arm = 3, cancel = 4, reopen = 5 }
    let action: Action
    let accountID: Data, attemptID: Data, revision: Data, installationID: Data, challenge: Data
    let gate: PreparationFileIdentity
    let binding: AuthorityMaintenanceBinding?
    init(action: Action, accountID: Data, attemptID: Data, revision: Data, installationID: Data,
         gate: PreparationFileIdentity, binding: AuthorityMaintenanceBinding?, challenge: Data) throws {
        guard [accountID, attemptID, revision, installationID].allSatisfy({ $0.count == 16 }),
              challenge.count == 32, gate.inode > 0, (action == .open) == (binding == nil),
              binding == nil || (binding?.accountID == accountID && binding?.attemptID == attemptID && (action == .reopen || binding?.revision == revision)) else {
            throw RuntimePreparationError.invalidRecord
        }
        self.action = action; self.accountID = accountID; self.attemptID = attemptID; self.revision = revision
        self.installationID = installationID; self.gate = gate; self.binding = binding; self.challenge = challenge
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("authority.maintenance-request"),
            2: .unsigned(action.rawValue), 3: .bytes(accountID), 4: .bytes(attemptID), 5: .bytes(revision),
            6: try binding.map { .bytes(try $0.encoded) } ?? .null, 7: .bytes(challenge),
            8: .bytes(installationID), 9: .unsigned(UInt64(gate.device)), 10: .unsigned(gate.inode)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...10),
              f[0] == .unsigned(1), f[1] == .text("authority.maintenance-request"),
              let action = Action(rawValue: try channelUInt(f[2])), case .bytes(let account) = f[3],
              case .bytes(let attempt) = f[4], case .bytes(let revision) = f[5], case .bytes(let challenge) = f[7],
              case .bytes(let installation) = f[8] else { throw RuntimePreparationError.invalidRecord }
        let device = try channelUInt(f[9]); guard device <= UInt64(UInt32.max) else { throw RuntimePreparationError.invalidRecord }
        let binding: AuthorityMaintenanceBinding?
        if f[6] == .null { binding = nil }
        else { guard case .bytes(let value) = f[6] else { throw RuntimePreparationError.invalidRecord }; binding = try .decode(value) }
        let result = try Self(action: action, accountID: account, attemptID: attempt, revision: revision, installationID: installation,
            gate: .init(device: UInt32(device), inode: channelUInt(f[10])), binding: binding, challenge: challenge)
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    private static let limits = try! CBORLimits(maxBytes: 512, maxDepth: 1, maxItems: 23)
}

/// These separately captured owners are not an atomic idle proof. Unavailable owners must fail before encoding.
struct AuthorityMaintenanceChannelWork: Equatable, Sendable {
    let journal: AuthorityMaintenanceJournalWork
    let execution: AuthorityMaintenanceExecutionWork
    let pairing: AuthorityMaintenancePairingWork
    init(journal: AuthorityMaintenanceJournalWork, execution: AuthorityMaintenanceExecutionWork,
         pairing: AuthorityMaintenancePairingWork) throws {
        let counts = [journal.requests.liveRequests, journal.requests.commandCaptures, journal.requests.activityOwners,
            journal.exchanges.active, journal.nativeExecutions, journal.executionActivityOwners,
            execution.queuedTurns, execution.rejectedTurns, pairing.stagedAttempts, pairing.activityOwners]
        guard counts.allSatisfy({ $0 >= 0 && UInt64($0) <= UInt64(UInt32.max) }) else { throw RuntimePreparationError.invalidRecord }
        self.journal = journal; self.execution = execution; self.pairing = pairing
    }
    fileprivate var value: CBORValue {
        .array([.unsigned(UInt64(journal.requests.liveRequests)), .unsigned(UInt64(journal.requests.commandCaptures)),
            .unsigned(UInt64(journal.requests.activityOwners)), .unsigned(UInt64(journal.exchanges.active)), .boolean(journal.exchanges.stopped),
            .unsigned(UInt64(journal.nativeExecutions)), .unsigned(UInt64(journal.executionActivityOwners)),
            .boolean(execution.started), .boolean(execution.stopping), .boolean(execution.failed),
            .unsigned(UInt64(execution.queuedTurns)), .unsigned(UInt64(execution.rejectedTurns)), .boolean(pairing.ready),
            .unsigned(UInt64(pairing.stagedAttempts)), .unsigned(UInt64(pairing.activityOwners)), .boolean(pairing.operationActive)])
    }
    fileprivate static func decode(_ value: CBORValue) throws -> Self {
        guard case .array(let a) = value, a.count == 16 else { throw RuntimePreparationError.invalidRecord }
        func count(_ index: Int) throws -> Int {
            let n = try channelUInt(a[index]); guard n <= UInt64(UInt32.max) else { throw RuntimePreparationError.invalidRecord }; return Int(n)
        }
        func flag(_ index: Int) throws -> Bool {
            guard case .boolean(let b) = a[index] else { throw RuntimePreparationError.invalidRecord }; return b
        }
        return try .init(journal: .init(requests: .init(liveRequests: count(0), commandCaptures: count(1), activityOwners: count(2)),
            exchanges: .init(active: count(3), stopped: flag(4)), nativeExecutions: count(5), executionActivityOwners: count(6)),
            execution: .init(started: flag(7), stopping: flag(8), failed: flag(9), queuedTurns: count(10), rejectedTurns: count(11)),
            pairing: .init(ready: flag(12), stagedAttempts: count(13), activityOwners: count(14), operationActive: flag(15)))
    }
}

/// Replies echo the exact request. Applied arm reports actual transfer; stagesPending permits only bounded waiting.
/// Refused carries no work and requires cancellation without retry. Bytes grant no native authority.
struct AuthorityMaintenanceChannelResponse: Equatable, Sendable {
    enum Outcome: UInt64, CaseIterable, Sendable { case applied = 1, stagesPending = 2, refused = 3 }
    let request: AuthorityMaintenanceChannelRequest
    let binding: AuthorityMaintenanceBinding
    let work: AuthorityMaintenanceChannelWork?
    let outcome: Outcome
    init(request: AuthorityMaintenanceChannelRequest, binding: AuthorityMaintenanceBinding, work: AuthorityMaintenanceChannelWork?,
         outcome: Outcome) throws {
        let observes = [AuthorityMaintenanceChannelRequest.Action.open, .observe, .arm].contains(request.action)
        let valid: Bool
        switch outcome {
        case .applied: valid = observes == (work != nil)
        case .stagesPending: valid = request.action == .arm && work != nil
        case .refused: valid = work == nil
        }
        guard request.accountID == binding.accountID, request.attemptID == binding.attemptID, (request.action == .reopen || request.revision == binding.revision),
              request.binding == nil || request.binding == binding, valid else {
            throw RuntimePreparationError.changedScope
        }
        self.request = request; self.binding = binding; self.work = work; self.outcome = outcome
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("authority.maintenance-response"),
            2: .bytes(request.encoded), 3: .bytes(binding.encoded), 4: work?.value ?? .null, 5: .unsigned(outcome.rawValue)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data, expected: AuthorityMaintenanceChannelRequest) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...5),
              f[0] == .unsigned(1), f[1] == .text("authority.maintenance-response"), f[2] == .bytes(try expected.encoded),
              case .bytes(let binding) = f[3], let outcome = Outcome(rawValue: try channelUInt(f[5])) else { throw RuntimePreparationError.invalidRecord }
        let result = try Self(request: expected, binding: .decode(binding), work: f[4] == .null ? nil : .decode(f[4]!), outcome: outcome)
        guard try result.encoded == bytes else { throw RuntimePreparationError.invalidRecord }; return result
    }
    private static let limits = try! CBORLimits(maxBytes: 1024, maxDepth: 2, maxItems: 32)
}

private func channelUInt(_ value: CBORValue?) throws -> UInt64 {
    guard case .unsigned(let n) = value else { throw RuntimePreparationError.invalidRecord }; return n
}
