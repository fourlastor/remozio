import CryptoKit
import Foundation
import RemozioProtocol

/// Historical public resource state only. An unresolved dispatch never authorizes an automatic creation retry.
struct SharedSetupAccessApplicationRecord: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "setup.shared-import-access-application"
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
    let applicationID: String?
    let tunnelID: String
    let audience: String?
    let refusal: Refusal?
    let initialImportRevision: Data
    let requestDigest: Data
    let bytes: Data
    var description: String { "SharedSetupAccessApplicationRecord(redacted)" }
    var debugDescription: String { description }
    static func requestBody(plan: SharedSetupImportRelayPlan) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["name": plan.accessApplicationName, "type": "self_hosted", "domain": plan.hostname,
            "destinations": [["type": "public", "uri": plan.hostname]], "policies": [], "service_auth_401_redirect": true,
            "auto_redirect_to_identity": false, "app_launcher_visible": false, "allow_authenticate_via_warp": false], options: [.sortedKeys])
    }
    init(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord) throws {
        let tunnel = try createdTunnel.createdTunnel(expected: expected, plan: plan)
        try self.init(planBytes: plan.bytes, recordID: AccountPreparationIntent.randomID(), revision: AccountPreparationIntent.randomID(),
            attemptID: AccountPreparationIntent.randomID(), attemptNumber: 1, phase: .prepared, applicationID: nil, tunnelID: tunnel.tunnelID,
            audience: nil, refusal: nil, initialImportRevision: expected.revision,
            requestDigest: Data(SHA256.hash(data: Self.requestBody(plan: plan))))
    }
    private init(planBytes: Data, recordID: Data, revision: Data, attemptID: Data, attemptNumber: UInt64, phase: Phase,
                 applicationID: String?, tunnelID: String, audience: String?, refusal: Refusal?, initialImportRevision: Data, requestDigest: Data) throws {
        guard [recordID, revision, attemptID, initialImportRevision].allSatisfy({ $0.count == 16 }), attemptNumber > 0,
              requestDigest.count == 32, (phase == .created) == (applicationID != nil), (phase == .created) == (audience != nil), (phase == .rejected) == (refusal != nil) else {
            throw RelayProvisioningError.invalidRecord
        }
        for value in [tunnelID] + (applicationID.map { [$0] } ?? []) {
            guard value.utf8.count == 36, let uuid = UUID(uuidString: value), uuid.uuidString.lowercased() == value else {
                throw RelayProvisioningError.invalidRecord
            }
        }
        if let audience {
            guard !audience.isEmpty, audience.utf8.count <= 256,
                  audience.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 }) else {
                throw RelayProvisioningError.invalidRecord
            }
        }
        self.planBytes = planBytes; self.recordID = recordID; self.revision = revision; self.attemptID = attemptID
        self.attemptNumber = attemptNumber; self.phase = phase; self.applicationID = applicationID; self.tunnelID = tunnelID; self.audience = audience; self.refusal = refusal
        self.initialImportRevision = initialImportRevision; self.requestDigest = requestDigest
        bytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .text("remozio-import-access-application-creation"), 2: .bytes(planBytes), 3: .bytes(recordID),
            4: .bytes(revision), 5: .bytes(attemptID), 6: .unsigned(attemptNumber), 7: .unsigned(phase.rawValue),
            8: applicationID.map(CBORValue.text) ?? .null, 9: refusal.map { .unsigned($0.rawValue) } ?? .null,
            10: .bytes(initialImportRevision), 11: .bytes(requestDigest), 12: .text(tunnelID), 13: audience.map(CBORValue.text) ?? .null
        ]), limits: Self.limits)
    }
    func validate(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord) throws {
        try plan.validate(expected: expected)
        guard tunnelID == (try createdTunnel.createdTunnel(expected: expected, plan: plan)).tunnelID, planBytes == plan.bytes, requestDigest == Data(SHA256.hash(data: try Self.requestBody(plan: plan))) else {
            throw RelayProvisioningError.wrongScope
        }
    }
    func createdApplication(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                            createdTunnel: SharedSetupRelayProvisioningRecord) throws -> CloudflareAccessApplicationIdentity {
        try validate(expected: expected, plan: plan, createdTunnel: createdTunnel)
        guard phase == .created, let applicationID, let audience, let selected = expected.recipe.cloudflare else { throw RelayProvisioningError.requiresReconciliation }
        return .init(accountID: selected.accountID, applicationID: applicationID, name: plan.accessApplicationName, hostname: plan.hostname, audience: audience)
    }
    func transition(to next: Phase, applicationID: String? = nil, audience: String? = nil, refusal: Refusal? = nil) throws -> Self {
        let value = try Self(planBytes: planBytes, recordID: recordID, revision: AccountPreparationIntent.randomID(),
            attemptID: attemptID, attemptNumber: attemptNumber, phase: next, applicationID: applicationID, tunnelID: tunnelID, audience: audience, refusal: refusal,
            initialImportRevision: initialImportRevision, requestDigest: requestDigest)
        try value.validateTransition(from: self); return value
    }
    /// A future explicit repair must verify current provider absence and obtain fresh administrator authorization first.
    func retryAfterRefusal() throws -> Self {
        guard phase == .rejected, attemptNumber < UInt64.max else { throw RelayProvisioningError.invalidTransition }
        let value = try Self(planBytes: planBytes, recordID: recordID, revision: AccountPreparationIntent.randomID(),
            attemptID: AccountPreparationIntent.randomID(), attemptNumber: attemptNumber + 1, phase: .prepared, applicationID: nil, tunnelID: tunnelID, audience: nil, refusal: nil,
            initialImportRevision: initialImportRevision, requestDigest: requestDigest)
        try value.validateTransition(from: self); return value
    }
    func validateTransition(from previous: Self?) throws {
        guard let previous else {
            guard phase == .prepared, attemptNumber == 1 else { throw RelayProvisioningError.invalidTransition }; return
        }
        if self == previous { return }
        guard tunnelID == previous.tunnelID, planBytes == previous.planBytes, recordID == previous.recordID,
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
    static func decode(_ bytes: Data, expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord) throws -> Self {
        guard case let .map(f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...13),
              f[0] == .unsigned(1), f[1] == .text("remozio-import-access-application-creation"),
              case let .bytes(planBytes) = f[2], case let .bytes(record) = f[3], case let .bytes(revision) = f[4],
              case let .bytes(attempt) = f[5], case let .unsigned(number) = f[6], case let .unsigned(raw) = f[7], let phase = Phase(rawValue: raw),
              case let .bytes(initial) = f[10], case let .bytes(digest) = f[11], case let .text(tunnelID) = f[12] else { throw RelayProvisioningError.invalidRecord }
        let application: String?, refusal: Refusal?, audience: String?
        switch f[8] { case .null?: application = nil; case .text(let value)?: application = value; default: throw RelayProvisioningError.invalidRecord }
        switch f[13] { case .null?: audience = nil; case .text(let value)?: audience = value; default: throw RelayProvisioningError.invalidRecord }
        switch f[9] { case .null?: refusal = nil; case .unsigned(let value)?:
            guard let decoded = Refusal(rawValue: value) else { throw RelayProvisioningError.invalidRecord }; refusal = decoded
        default: throw RelayProvisioningError.invalidRecord }
        let result = try Self(planBytes: planBytes, recordID: record, revision: revision, attemptID: attempt, attemptNumber: number,
            phase: phase, applicationID: application, tunnelID: tunnelID, audience: audience, refusal: refusal, initialImportRevision: initial, requestDigest: digest)
        try result.validate(expected: expected, plan: plan, createdTunnel: createdTunnel)
        guard result.bytes == bytes else { throw RelayProvisioningError.invalidRecord }; return result
    }
}
