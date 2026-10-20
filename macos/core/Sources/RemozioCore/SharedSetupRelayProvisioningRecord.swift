import CryptoKit
import Foundation
import RemozioProtocol

enum RelayProvisioningError: Error, Equatable { case invalidRecord, wrongScope, invalidTransition, staleRecord, requiresReconciliation }

/// Historical public resource state only. An unresolved dispatch never authorizes an automatic creation retry.
struct SharedSetupRelayProvisioningRecord: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "setup.shared-import-relay-provisioning"
    static let supportedVersions: Set<UInt64> = [1]
    private static let limits = try! CBORLimits(maxBytes: 8192, maxDepth: 1, maxItems: 32)
    enum Phase: UInt64, Sendable { case prepared = 1, dispatched, created, rejected, unknown }
    enum Refusal: UInt64, Sendable { case unauthorized = 1, rateLimited, providerRejected }
    let planBytes: Data
    let recordID: Data
    let revision: Data
    let attemptID: Data
    let attemptNumber: UInt64
    let phase: Phase
    let tunnelID: String?
    let refusal: Refusal?
    let initialImportRevision: Data
    let requestDigest: Data
    let bytes: Data
    var description: String { "SharedSetupRelayProvisioningRecord(redacted)" }
    var debugDescription: String { description }
    static func requestBody(plan: SharedSetupImportRelayPlan) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["name": plan.tunnelName, "config_src": "cloudflare"], options: [.sortedKeys])
    }
    init(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan) throws {
        try plan.validate(expected: expected)
        try self.init(planBytes: plan.bytes, recordID: AccountPreparationIntent.randomID(), revision: AccountPreparationIntent.randomID(),
            attemptID: AccountPreparationIntent.randomID(), attemptNumber: 1, phase: .prepared, tunnelID: nil, refusal: nil,
            initialImportRevision: expected.revision, requestDigest: Data(SHA256.hash(data: Self.requestBody(plan: plan))))
    }
    private init(planBytes: Data, recordID: Data, revision: Data, attemptID: Data, attemptNumber: UInt64, phase: Phase,
                 tunnelID: String?, refusal: Refusal?, initialImportRevision: Data, requestDigest: Data) throws {
        guard [recordID, revision, attemptID, initialImportRevision].allSatisfy({ $0.count == 16 }), attemptNumber > 0,
              requestDigest.count == 32, (phase == .created) == (tunnelID != nil), (phase == .rejected) == (refusal != nil) else {
            throw RelayProvisioningError.invalidRecord
        }
        if let tunnelID {
            guard tunnelID.utf8.count == 36, let uuid = UUID(uuidString: tunnelID), uuid.uuidString.lowercased() == tunnelID else {
                throw RelayProvisioningError.invalidRecord
            }
        }
        self.planBytes = planBytes; self.recordID = recordID; self.revision = revision; self.attemptID = attemptID
        self.attemptNumber = attemptNumber; self.phase = phase; self.tunnelID = tunnelID; self.refusal = refusal
        self.initialImportRevision = initialImportRevision; self.requestDigest = requestDigest
        bytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .text("remozio-import-tunnel-creation"), 2: .bytes(planBytes), 3: .bytes(recordID),
            4: .bytes(revision), 5: .bytes(attemptID), 6: .unsigned(attemptNumber), 7: .unsigned(phase.rawValue),
            8: tunnelID.map(CBORValue.text) ?? .null, 9: refusal.map { .unsigned($0.rawValue) } ?? .null,
            10: .bytes(initialImportRevision), 11: .bytes(requestDigest)
        ]), limits: Self.limits)
    }
    func validate(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan) throws {
        try plan.validate(expected: expected)
        guard planBytes == plan.bytes, requestDigest == Data(SHA256.hash(data: try Self.requestBody(plan: plan))) else {
            throw RelayProvisioningError.wrongScope
        }
    }
    func createdTunnel(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan) throws -> CloudflareTunnelObservation {
        try validate(expected: expected, plan: plan)
        guard phase == .created, let tunnelID, let selected = expected.recipe.cloudflare else { throw RelayProvisioningError.requiresReconciliation }
        return .init(accountID: selected.accountID, tunnelID: tunnelID, name: plan.tunnelName)
    }
    func transition(to next: Phase, tunnelID: String? = nil, refusal: Refusal? = nil) throws -> Self {
        let value = try Self(planBytes: planBytes, recordID: recordID, revision: AccountPreparationIntent.randomID(),
            attemptID: attemptID, attemptNumber: attemptNumber, phase: next, tunnelID: tunnelID, refusal: refusal,
            initialImportRevision: initialImportRevision, requestDigest: requestDigest)
        try value.validateTransition(from: self); return value
    }
    /// A future explicit repair must verify current provider absence and obtain fresh administrator authorization first.
    func retryAfterRefusal() throws -> Self {
        guard phase == .rejected, attemptNumber < UInt64.max else { throw RelayProvisioningError.invalidTransition }
        let value = try Self(planBytes: planBytes, recordID: recordID, revision: AccountPreparationIntent.randomID(),
            attemptID: AccountPreparationIntent.randomID(), attemptNumber: attemptNumber + 1, phase: .prepared, tunnelID: nil, refusal: nil,
            initialImportRevision: initialImportRevision, requestDigest: requestDigest)
        try value.validateTransition(from: self); return value
    }
    func validateTransition(from previous: Self?) throws {
        guard let previous else {
            guard phase == .prepared, attemptNumber == 1 else { throw RelayProvisioningError.invalidTransition }; return
        }
        if self == previous { return }
        guard planBytes == previous.planBytes, recordID == previous.recordID,
              initialImportRevision == previous.initialImportRevision, requestDigest == previous.requestDigest,
              revision != previous.revision else { throw RelayProvisioningError.invalidTransition }
        if previous.phase == .rejected, phase == .prepared {
            guard previous.attemptNumber < UInt64.max, attemptNumber == previous.attemptNumber + 1,
                  attemptID != previous.attemptID else { throw RelayProvisioningError.invalidTransition }; return
        }
        guard attemptID == previous.attemptID, attemptNumber == previous.attemptNumber,
              (previous.phase == .prepared && phase == .dispatched) ||
              (previous.phase == .dispatched && [.created, .rejected, .unknown].contains(phase)) else {
            throw RelayProvisioningError.invalidTransition
        }
    }
    static func decode(_ bytes: Data, expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan) throws -> Self {
        guard case let .map(f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...11),
              f[0] == .unsigned(1), f[1] == .text("remozio-import-tunnel-creation"),
              case let .bytes(planBytes) = f[2], case let .bytes(record) = f[3], case let .bytes(revision) = f[4],
              case let .bytes(attempt) = f[5], case let .unsigned(number) = f[6], case let .unsigned(raw) = f[7], let phase = Phase(rawValue: raw),
              case let .bytes(initial) = f[10], case let .bytes(digest) = f[11] else { throw RelayProvisioningError.invalidRecord }
        let tunnel: String?, refusal: Refusal?
        switch f[8] { case .null?: tunnel = nil; case .text(let value)?: tunnel = value; default: throw RelayProvisioningError.invalidRecord }
        switch f[9] { case .null?: refusal = nil; case .unsigned(let value)?:
            guard let decoded = Refusal(rawValue: value) else { throw RelayProvisioningError.invalidRecord }; refusal = decoded
        default: throw RelayProvisioningError.invalidRecord }
        let result = try Self(planBytes: planBytes, recordID: record, revision: revision, attemptID: attempt, attemptNumber: number,
            phase: phase, tunnelID: tunnel, refusal: refusal, initialImportRevision: initial, requestDigest: digest)
        try result.validate(expected: expected, plan: plan)
        guard result.bytes == bytes else { throw RelayProvisioningError.invalidRecord }; return result
    }
}
