import CryptoKit
import Foundation
import RemozioProtocol

/// Historical creation state. The owner must separately verify current ingress and Access coverage before dispatch.
struct SharedSetupDNSRecord: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "setup.shared-import-dns"
    static let supportedVersions: Set<UInt64> = [1]
    private static let limits = try! CBORLimits(maxBytes: 8192, maxDepth: 1, maxItems: 40)
    enum Phase: UInt64, Sendable { case prepared = 1, dispatched, created, rejected, unknown }
    enum Refusal: UInt64, Sendable { case unauthorized = 1, rateLimited, providerRejected }
    let planBytes: Data
    let recordID: Data
    let revision: Data
    let attemptID: Data
    let attemptNumber: UInt64
    let phase: Phase
    let dnsRecordID: String?
    let tunnelID: String
    let accessApplicationID: String
    let accessRecordDigest: Data
    let refusal: Refusal?
    let initialImportRevision: Data
    let requestDigest: Data
    let bytes: Data
    var description: String { "SharedSetupDNSRecord(redacted)" }
    var debugDescription: String { description }
    static func requestBody(plan: SharedSetupImportRelayPlan, tunnelID: String) throws -> Data {
        guard let uuid = UUID(uuidString: tunnelID), uuid.uuidString.lowercased() == tunnelID else { throw RelayProvisioningError.wrongScope }
        return try JSONSerialization.data(withJSONObject: ["name": plan.hostname, "type": "CNAME", "content": tunnelID + ".cfargotunnel.com",
            "proxied": true, "ttl": 1], options: [.sortedKeys])
    }
    static func validProviderID(_ value: String) -> Bool {
        value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    init(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
         application: SharedSetupAccessApplicationRecord) throws {
        let tunnel = try createdTunnel.createdTunnel(expected: expected, plan: plan)
        let access = try application.createdApplication(expected: expected, plan: plan, createdTunnel: createdTunnel)
        try self.init(planBytes: plan.bytes, recordID: AccountPreparationIntent.randomID(), revision: AccountPreparationIntent.randomID(),
            attemptID: AccountPreparationIntent.randomID(), attemptNumber: 1, phase: .prepared, dnsRecordID: nil, tunnelID: tunnel.tunnelID,
            accessApplicationID: access.applicationID, accessRecordDigest: Data(SHA256.hash(data: application.bytes)), refusal: nil,
            initialImportRevision: expected.revision, requestDigest: Data(SHA256.hash(data: Self.requestBody(plan: plan, tunnelID: tunnel.tunnelID))))
    }
    private init(planBytes: Data, recordID: Data, revision: Data, attemptID: Data, attemptNumber: UInt64, phase: Phase,
                 dnsRecordID: String?, tunnelID: String, accessApplicationID: String, accessRecordDigest: Data,
                 refusal: Refusal?, initialImportRevision: Data, requestDigest: Data) throws {
        guard [recordID, revision, attemptID, initialImportRevision].allSatisfy({ $0.count == 16 }), attemptNumber > 0,
              requestDigest.count == 32, accessRecordDigest.count == 32, (phase == .created) == (dnsRecordID != nil),
              (phase == .rejected) == (refusal != nil) else { throw RelayProvisioningError.invalidRecord }
        for value in [tunnelID, accessApplicationID] {
            guard value.utf8.count == 36, let uuid = UUID(uuidString: value), uuid.uuidString.lowercased() == value else {
                throw RelayProvisioningError.invalidRecord
            }
        }
        if let dnsRecordID { guard Self.validProviderID(dnsRecordID) else { throw RelayProvisioningError.invalidRecord } }
        self.planBytes = planBytes; self.recordID = recordID; self.revision = revision; self.attemptID = attemptID
        self.attemptNumber = attemptNumber; self.phase = phase; self.dnsRecordID = dnsRecordID; self.tunnelID = tunnelID
        self.accessApplicationID = accessApplicationID; self.accessRecordDigest = accessRecordDigest; self.refusal = refusal
        self.initialImportRevision = initialImportRevision; self.requestDigest = requestDigest
        bytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .text("remozio-import-dns-creation"), 2: .bytes(planBytes), 3: .bytes(recordID),
            4: .bytes(revision), 5: .bytes(attemptID), 6: .unsigned(attemptNumber), 7: .unsigned(phase.rawValue),
            8: dnsRecordID.map(CBORValue.text) ?? .null, 9: refusal.map { .unsigned($0.rawValue) } ?? .null,
            10: .bytes(initialImportRevision), 11: .bytes(requestDigest), 12: .text(tunnelID), 13: .bytes(accessRecordDigest), 14: .text(accessApplicationID)
        ]), limits: Self.limits)
    }
    func validate(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                  application: SharedSetupAccessApplicationRecord) throws {
        try plan.validate(expected: expected)
        let access = try application.createdApplication(expected: expected, plan: plan, createdTunnel: createdTunnel)
        guard tunnelID == (try createdTunnel.createdTunnel(expected: expected, plan: plan)).tunnelID, planBytes == plan.bytes,
              accessApplicationID == access.applicationID, accessRecordDigest == Data(SHA256.hash(data: application.bytes)),
              requestDigest == Data(SHA256.hash(data: try Self.requestBody(plan: plan, tunnelID: tunnelID))) else { throw RelayProvisioningError.wrongScope }
    }
    func createdRecord(expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan, createdTunnel: SharedSetupRelayProvisioningRecord,
                       application: SharedSetupAccessApplicationRecord) throws -> CloudflareDNSRecordIdentity {
        try validate(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application)
        guard phase == .created, let dnsRecordID, let selected = expected.recipe.cloudflare else { throw RelayProvisioningError.requiresReconciliation }
        return .init(zoneID: selected.zoneID, recordID: dnsRecordID, hostname: plan.hostname, target: tunnelID + ".cfargotunnel.com")
    }
    func transition(to next: Phase, dnsRecordID: String? = nil, refusal: Refusal? = nil) throws -> Self {
        let value = try Self(planBytes: planBytes, recordID: recordID, revision: AccountPreparationIntent.randomID(), attemptID: attemptID,
            attemptNumber: attemptNumber, phase: next, dnsRecordID: dnsRecordID, tunnelID: tunnelID, accessApplicationID: accessApplicationID,
            accessRecordDigest: accessRecordDigest, refusal: refusal, initialImportRevision: initialImportRevision, requestDigest: requestDigest)
        try value.validateTransition(from: self); return value
    }
    /// An explicit repair needs fresh authorization and new provider absence checks before it can dispatch.
    func retryAfterRefusal() throws -> Self {
        guard phase == .rejected, attemptNumber < UInt64.max else { throw RelayProvisioningError.invalidTransition }
        let value = try Self(planBytes: planBytes, recordID: recordID, revision: AccountPreparationIntent.randomID(),
            attemptID: AccountPreparationIntent.randomID(), attemptNumber: attemptNumber + 1, phase: .prepared, dnsRecordID: nil,
            tunnelID: tunnelID, accessApplicationID: accessApplicationID, accessRecordDigest: accessRecordDigest, refusal: nil,
            initialImportRevision: initialImportRevision, requestDigest: requestDigest)
        try value.validateTransition(from: self); return value
    }
    func validateTransition(from previous: Self?) throws {
        guard let previous else {
            guard phase == .prepared, attemptNumber == 1 else { throw RelayProvisioningError.invalidTransition }; return
        }
        if self == previous { return }
        guard tunnelID == previous.tunnelID, accessApplicationID == previous.accessApplicationID, accessRecordDigest == previous.accessRecordDigest,
              planBytes == previous.planBytes, recordID == previous.recordID, initialImportRevision == previous.initialImportRevision,
              requestDigest == previous.requestDigest, revision != previous.revision else { throw RelayProvisioningError.invalidTransition }
        if previous.phase == .rejected, phase == .prepared {
            guard previous.attemptNumber < UInt64.max, attemptNumber == previous.attemptNumber + 1,
                  attemptID != previous.attemptID else { throw RelayProvisioningError.invalidTransition }; return
        }
        guard attemptID == previous.attemptID, attemptNumber == previous.attemptNumber,
              (previous.phase == .prepared && phase == .dispatched) ||
              (previous.phase == .dispatched && [.created, .rejected, .unknown].contains(phase)) else { throw RelayProvisioningError.invalidTransition }
    }
    static func decode(_ bytes: Data, expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                       createdTunnel: SharedSetupRelayProvisioningRecord, application: SharedSetupAccessApplicationRecord) throws -> Self {
        guard case let .map(f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...14),
              f[0] == .unsigned(1), f[1] == .text("remozio-import-dns-creation"),
              case let .bytes(planBytes) = f[2], case let .bytes(record) = f[3], case let .bytes(revision) = f[4],
              case let .bytes(attempt) = f[5], case let .unsigned(number) = f[6], case let .unsigned(raw) = f[7], let phase = Phase(rawValue: raw),
              case let .bytes(initial) = f[10], case let .bytes(digest) = f[11], case let .text(tunnelID) = f[12],
              case let .bytes(accessDigest) = f[13], case let .text(accessID) = f[14] else { throw RelayProvisioningError.invalidRecord }
        let remote: String?, refusal: Refusal?
        switch f[8] { case .null?: remote = nil; case .text(let value)?: remote = value; default: throw RelayProvisioningError.invalidRecord }
        switch f[9] { case .null?: refusal = nil; case .unsigned(let value)?:
            guard let decoded = Refusal(rawValue: value) else { throw RelayProvisioningError.invalidRecord }; refusal = decoded
        default: throw RelayProvisioningError.invalidRecord }
        let result = try Self(planBytes: planBytes, recordID: record, revision: revision, attemptID: attempt, attemptNumber: number,
            phase: phase, dnsRecordID: remote, tunnelID: tunnelID, accessApplicationID: accessID, accessRecordDigest: accessDigest,
            refusal: refusal, initialImportRevision: initial, requestDigest: digest)
        try result.validate(expected: expected, plan: plan, createdTunnel: createdTunnel, application: application)
        guard result.bytes == bytes else { throw RelayProvisioningError.invalidRecord }; return result
    }
}
