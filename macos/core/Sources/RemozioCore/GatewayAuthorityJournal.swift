import CryptoKit
import Foundation
import RemozioProtocol
import SQLite3

public enum GatewayAuthorityError: Error, Equatable {
    case disabled, invalidConfiguration, unconfigured, wrongScope, unavailableEnrollment, unavailableRegistration, invalidToken
    case headMismatch, capacityExceeded, corruptData, invalidSignature, invalidClock, expired, superseded, alreadyConsumed
    case unsupportedSubmissionControl
}

/// Protected host state. Neither candidate nor proof fields establish this trust.
public struct GatewayAuthorityTrust: Sendable {
    public let registration: GatewayRegistrationIdentity
    public let enrollment: GatewayPhoneEnrollment
    public let active: Bool
    public init(registration: GatewayRegistrationIdentity, enrollment: GatewayPhoneEnrollment, active: Bool) {
        self.registration = registration; self.enrollment = enrollment; self.active = active
    }
}

public struct GatewayAuthorityPolicy: Sendable {
    public let payloadLimits: CBORLimits
    public let signingLimits: CBORLimits
    public let maximumControls: Int
    public let candidateLifetimeMillis: UInt64
    public let clockEpoch: UUID
    public init(payloadLimits: CBORLimits, signingLimits: CBORLimits, maximumControls: Int,
                candidateLifetimeMillis: UInt64, clockEpoch: UUID) throws {
        guard (2...100_000).contains(maximumControls), (1...86_400_000).contains(candidateLifetimeMillis),
              payloadLimits.maxBytes <= 65_536, signingLimits.maxBytes <= 131_072 else {
            throw GatewayAuthorityError.invalidConfiguration
        }
        self.payloadLimits = payloadLimits; self.signingLimits = signingLimits; self.maximumControls = maximumControls
        self.candidateLifetimeMillis = candidateLifetimeMillis; self.clockEpoch = clockEpoch
    }
}

/// A retained signed control, not permission to publish. Recheck current trust and outbox eligibility before sending.
public struct GatewayAuthorityEnvelope: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let kind: UInt64
    public let operationID: Data
    public let revision: UInt64
    public let canonicalPayload: Data
    public let signature: Data
    // Protected operational data. It must never appear in audit history or phone fetch metadata.
    let registrationToken: String?
    public var description: String { "GatewayAuthorityEnvelope(redacted)" }
    public var debugDescription: String { description }
}

/// Highest known control that an authenticated gateway reply reported. This is historical, not live status.
public struct GatewayAcknowledgment: Equatable, Sendable {
    public let revision: UInt64
    public let operationID: Data?
    public let abandonedGrant: Bool
}

enum GatewayGrantRetirement: Sendable, Equatable {
    case none
    case expiresBeforeRetirement
    case eligible(GatewayControlTombstone)
}

public enum GatewayAcknowledgmentDisposition: Sendable, Equatable {
    case recorded, alreadyRecorded, olderThanRecorded
    case missingLocalHistory, conflictingLocalHistory
}

public struct GatewayAcknowledgmentResult: Sendable {
    public let disposition: GatewayAcknowledgmentDisposition
    public let acknowledged: GatewayAcknowledgment?
    public let localRevision: UInt64
    public let reportedRevision: UInt64
}

public enum GatewayHistoryRecoveryDisposition: Sendable, Equatable {
    case reconciled, localHeadChanged, requiresTrustRecovery, conflictingLocalHistory
}

/// Historical recovery only. A non-reconciled result cannot authorize publication or restore phone authority.
public struct GatewayHistoryRecoveryResult: Sendable {
    public let disposition: GatewayHistoryRecoveryDisposition
    public let localRevision: UInt64
    public let reportedRevision: UInt64
}

public enum GatewayTrustEvidenceKind: UInt64, Sendable { case candidate = 1, activation = 2 }
public enum GatewayTrustRestrictionDisposition: Sendable, Equatable { case knownHistory, restricted, alreadyRestricted }
public struct GatewayTrustRestrictionResult: Sendable {
    public let phoneID: Data
    public let disposition: GatewayTrustRestrictionDisposition
    public let trustRevision: UUID
}

/// Committed local recovery state, not permission to reopen admission before continuity checkpointing.
public struct GatewayTrustEvidenceRecovery: Sendable {
    public let trustRevision: UUID
    public let auditHead: UInt64
    /// Changes in this call, not the complete set of phones without authority.
    public let changedPhoneIDs: Set<Data>
    /// Phones awaiting administrator repair. Ordinary revoked epochs are reflected in the trust snapshot instead.
    public let restrictedPhoneIDs: Set<Data>
}

/// Current desired state for a protected Root owner. It contains private provider material and is never phone-fetchable.
struct GatewayCurrentTokenState: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let candidate: GatewayAuthorityEnvelope
    let activation: GatewayAuthorityEnvelope?
    let candidateExpired: Bool
    let activationAbandonmentConfirmed: Bool
    var needsRenewal: Bool { activation == nil && candidateExpired }
    var description: String { "GatewayCurrentTokenState(redacted)" }
    var debugDescription: String { description }
}

/// Private table owner. Every call runs within the journal owner's transaction and protected writer lease.
final class GatewayAuthorityJournal {
    private let db: OpaquePointer
    private let mac: Data
    private let account: Data
    private let policy: GatewayAuthorityPolicy
    private let run = UUID()
    private var lastMoment: UInt64?

    init(connection: OpaquePointer, macID: Data, accountID: Data, policy: GatewayAuthorityPolicy) {
        db = connection; mac = macID; account = accountID; self.policy = policy
    }

    static func createSchema(_ db: OpaquePointer) throws {
        let sql = """
            CREATE TABLE main.gateway_authority_v1(id INTEGER PRIMARY KEY CHECK(id=1), identity BLOB NOT NULL, head BLOB NOT NULL CHECK(length(head)=8)) STRICT;
            CREATE TABLE main.gateway_outbox_v1(
                operation BLOB PRIMARY KEY CHECK(length(operation)=16), revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8),
                kind INTEGER NOT NULL CHECK(kind IN (1,2)), candidate BLOB NOT NULL CHECK(length(candidate)=16),
                payload BLOB NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64), token BLOB
            ) STRICT, WITHOUT ROWID;
            CREATE UNIQUE INDEX main.gateway_single_activation_v1 ON gateway_outbox_v1(candidate) WHERE kind=2;
            CREATE TABLE main.gateway_root_candidates_v1(
                candidate BLOB PRIMARY KEY CHECK(length(candidate)=16), phone BLOB NOT NULL CHECK(length(phone)=16),
                enrollment BLOB NOT NULL CHECK(length(enrollment)=16), operation BLOB NOT NULL UNIQUE REFERENCES gateway_outbox_v1(operation),
                run BLOB NOT NULL CHECK(length(run)=16), started BLOB NOT NULL CHECK(length(started)=8),
                deadline BLOB NOT NULL CHECK(length(deadline)=8), consumed BLOB REFERENCES gateway_outbox_v1(operation)
            ) STRICT, WITHOUT ROWID;
            CREATE TABLE main.gateway_desired_tokens_v1(
                phone BLOB PRIMARY KEY CHECK(length(phone)=16), candidate BLOB NOT NULL UNIQUE REFERENCES gateway_root_candidates_v1(candidate)
            ) STRICT, WITHOUT ROWID;
            """
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    static func createRevocationSchema(_ db: OpaquePointer) throws {
        let sql = """
            CREATE TABLE main.gateway_revocations_v1(
                operation BLOB PRIMARY KEY CHECK(length(operation)=16), revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8),
                phone BLOB NOT NULL CHECK(length(phone)=16), enrollment BLOB NOT NULL CHECK(length(enrollment)=16),
                payload BLOB NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64),
                run BLOB NOT NULL CHECK(length(run)=16), started BLOB NOT NULL CHECK(length(started)=8),
                deadline BLOB NOT NULL CHECK(length(deadline)=8)
            ) STRICT, WITHOUT ROWID;
            CREATE INDEX main.gateway_revoked_epoch_v1 ON gateway_revocations_v1(phone,enrollment,revision DESC);
            """
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    static func createAcknowledgmentSchema(_ db: OpaquePointer) throws {
        let result = sqlite3_exec(db, """
            CREATE TABLE main.gateway_acknowledgment_v1(
                id INTEGER PRIMARY KEY CHECK(id=1), revision BLOB NOT NULL CHECK(length(revision)=8),
                operation BLOB CHECK(operation IS NULL OR length(operation)=16)
            ) STRICT;
            """, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    static func createReconciledSchema(_ db: OpaquePointer) throws {
        let result = sqlite3_exec(db, """
            CREATE TABLE main.gateway_reconciled_controls_v1(
                operation BLOB PRIMARY KEY CHECK(length(operation)=16), revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8),
                kind INTEGER NOT NULL CHECK(kind IN (1,2)), candidate BLOB NOT NULL CHECK(length(candidate)=16),
                payload BLOB NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64)
            ) STRICT, WITHOUT ROWID;
            """, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    func reconcile(_ history: VerifiedGatewayHistory, expectedLocalRevision: UInt64, enrollments: [StoredApprovalEnrollment],
                   now: AuthorityMoment) throws -> GatewayHistoryRecoveryResult {
        let identity = history.head.evidence.registration, local = try head(identity)
        func result(_ disposition: GatewayHistoryRecoveryDisposition) -> GatewayHistoryRecoveryResult {
            GatewayHistoryRecoveryResult(disposition: disposition, localRevision: local,
                reportedRevision: history.head.evidence.revision)
        }
        try clock(now)
        guard history.receivedAt.epoch == now.epoch, history.receivedAt.milliseconds <= now.milliseconds else {
            throw GatewayAuthorityError.invalidClock
        }
        guard local == expectedLocalRevision else { return result(.localHeadChanged) }
        guard history.afterRevision == (local == 0 ? 0 : local - 1), history.head.evidence.revision > local else {
            return result(.conflictingLocalHistory)
        }
        var missing = history.records[...]
        var retainedBoundary: GatewayControlReceipt?
        if local > 0 {
            guard let boundary = missing.first, boundary.revision == local,
                  let retained = try envelope(boundary.operationID, identity: identity) else { return result(.conflictingLocalHistory) }
            guard retained.revision == local, try matchesRetainedControl(boundary, retained: retained, identity: identity) else {
                return result(.conflictingLocalHistory)
            }
            retainedBoundary = boundary
            missing = missing.dropFirst()
        }
        var submissionCredentials = Set<Data>()
        if missing.contains(where: { if case .submission = $0 { true } else { false } }) {
            guard try submissionHistoryInstalled() else { return result(.requiresTrustRecovery) }
            submissionCredentials = Set(try submissionEntries(identity).map { $0.receipt.control.credentialID })
        }
        var candidates: [Data?] = []
        var firstRevocations = Set<RevokedEpoch>()
        var retainedHistoryCount = 0
        for record in missing {
            if let recovered = try recoveredRevocation(operation: record.operationID, identity: identity) {
                guard case .recipient(let receipt) = record, case .revocation(let value) = receipt.control,
                      recovered == value else { return result(.conflictingLocalHistory) }
            }
            let binding: GatewayTokenBinding
            switch record {
            case .tombstone:
                // An unknown tombstone never reconstructs a missing grant or grants local authority.
                return result(.requiresTrustRecovery)
            case .submission(let receipt):
                guard try envelope(record.operationID, identity: identity) == nil else { return result(.conflictingLocalHistory) }
                let value = receipt.control
                let freshCredential = submissionCredentials.insert(value.credentialID).inserted
                if value.kind == .rotation, !freshCredential {
                    return result(.conflictingLocalHistory)
                }
                guard record.canonicalPayload.count <= policy.payloadLimits.maxBytes else { throw GatewayAuthorityError.capacityExceeded }
                candidates.append(nil)
                continue
            case .candidate(let value): binding = value.candidate.binding
            case .recipient(let value):
                switch value.control {
                case .activation(let activation): binding = activation.binding
                case .revocation(let revocation):
                    let phone = revocation.binding.phoneID, epoch = revocation.binding.enrollmentEpoch
                    let enrollment = enrollments.first { $0.approval.phoneID == phone && $0.epoch == epoch }
                    guard enrollment?.approval.active != true else { return result(.requiresTrustRecovery) }
                    let signed = try latestRevocation(phone: phone, epoch: epoch, identity: identity)
                    guard try signed != nil || recoveredRevocation(phone: phone, epoch: epoch, identity: identity) != nil else {
                        return result(.requiresTrustRecovery)
                    }
                    guard try envelope(record.operationID, identity: identity) == nil else { return result(.conflictingLocalHistory) }
                    guard record.canonicalPayload.count <= policy.payloadLimits.maxBytes else { throw GatewayAuthorityError.capacityExceeded }
                    let pair = RevokedEpoch(phone: phone, epoch: epoch)
                    if enrollment == nil || signed != nil || !firstRevocations.insert(pair).inserted {
                        retainedHistoryCount += 1
                    }
                    candidates.append(nil)
                    continue
                }
            }
            guard try !trustRestricted(phone: binding.phoneID, identity: identity) else { return result(.requiresTrustRecovery) }
            guard enrollments.contains(where: {
                $0.approval.phoneID == binding.phoneID && $0.epoch == binding.enrollmentEpoch && $0.notificationTag == binding.enrollmentTag
            }) else { return result(.requiresTrustRecovery) }
            guard try envelope(record.operationID, identity: identity) == nil else { return result(.conflictingLocalHistory) }
            guard record.canonicalPayload.count <= policy.payloadLimits.maxBytes else { throw GatewayAuthorityError.capacityExceeded }
            candidates.append(binding.candidateID)
        }
        let deliveryCount = missing.count - firstRevocations.count - retainedHistoryCount
        if deliveryCount > 0 { try requireCapacity(.delivery, additional: deliveryCount) }
        if !firstRevocations.isEmpty { try requireCapacity(.firstRevocation, additional: firstRevocations.count) }
        if retainedHistoryCount > 0 { try requireCapacity(.revocationHistory, additional: retainedHistoryCount) }
        for (record, candidate) in zip(missing, candidates) {
            if let candidate {
                let kind: UInt64
                switch record { case .candidate: kind = 1; case .recipient: kind = 2; case .submission, .tombstone: throw GatewayAuthorityError.corruptData }
                try statement("INSERT INTO main.gateway_reconciled_controls_v1 VALUES(?,?,\(kind),?,?,?)",
                    [record.operationID, uint(record.revision), candidate, record.canonicalPayload, record.signature]) { try done($0) }
            } else {
                // The zero run cannot belong to a live owner. Recovery retains history, not a renewed publication deadline.
                switch record {
                case .submission(let receipt):
                    let value = receipt.control
                    try statement("INSERT INTO main.gateway_submission_outbox_v1 VALUES(?,?,\(value.kind.rawValue),?,?,?,?,?,?)",
                        [record.operationID, uint(record.revision), value.credentialID, record.canonicalPayload, record.signature,
                         Data(repeating: 0, count: 16), uint(0), uint(value.expiresAtUnixMillis - value.issuedAtUnixMillis)]) { try done($0) }
                case .recipient(let receipt):
                    guard case .revocation(let value) = receipt.control else { throw GatewayAuthorityError.corruptData }
                    try statement("INSERT INTO main.gateway_revocations_v1 VALUES(?,?,?,?,?,?,?,?,?)",
                        [record.operationID, uint(record.revision), value.binding.phoneID, value.binding.enrollmentEpoch,
                         record.canonicalPayload, record.signature, Data(repeating: 0, count: 16), uint(0),
                         uint(value.expiresAtUnixMillis - value.issuedAtUnixMillis)]) { try done($0) }
                case .candidate, .tombstone: throw GatewayAuthorityError.corruptData
                }
            }
        }
        // Retain desired token material, but retire every old candidate and proof in the same transaction.
        try statement("UPDATE main.gateway_root_candidates_v1 SET run=zeroblob(16)", []) { try done($0) }
        if let retainedBoundary { try resolveGrantAbandonment(retainedBoundary, registration: identity) }
        try advance(from: local, to: history.head.evidence.revision)
        guard try acknowledge(history.head).disposition == .recorded else { throw GatewayAuthorityError.corruptData }
        return result(.reconciled)
    }

    static func createTrustRestrictionsSchema(_ db: OpaquePointer) throws {
        let result = sqlite3_exec(db, """
            CREATE TABLE main.gateway_trust_restrictions_v1(
                phone BLOB PRIMARY KEY CHECK(length(phone)=16), kind INTEGER NOT NULL CHECK(kind IN (1,2)),
                operation BLOB NOT NULL UNIQUE CHECK(length(operation)=16), payload BLOB NOT NULL,
                signature BLOB NOT NULL CHECK(length(signature)=64)
            ) STRICT, WITHOUT ROWID;
            """, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    private func trustEvidence(kind: GatewayTrustEvidenceKind, payload: Data, signature: Data,
                               identity: GatewayRegistrationIdentity) throws -> (GatewayTokenBinding, Data) {
        let binding: GatewayTokenBinding, operation: Data, valid: Bool
        switch kind {
        case .candidate:
            let value = try GatewayTokenCandidate.decode(payload, limits: policy.payloadLimits)
            binding = value.binding; operation = value.operationID
            valid = try GatewayTokenCandidateSignature.verify(signature: signature, publicKey: identity.rootPublicKey, wireVersion: 1,
                canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits)
        case .activation:
            let value = try GatewayMappingActivation.decode(payload, limits: policy.payloadLimits)
            binding = value.binding; operation = value.operationID
            valid = try GatewayRecipientSignature.verify(signature: signature, publicKey: identity.rootPublicKey, wireVersion: 1,
                kind: .activation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits)
        }
        guard valid else { throw GatewayAuthorityError.invalidSignature }
        guard identity.matches(binding) else { throw GatewayAuthorityError.wrongScope }
        return (binding, operation)
    }

    func trustRestricted(phone: Data, identity: GatewayRegistrationIdentity) throws -> Bool {
        try statement("SELECT kind,operation,payload,signature FROM main.gateway_trust_restrictions_v1 WHERE phone=?", [phone]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return false }
            guard result == SQLITE_ROW, let raw = UInt64(exactly: sqlite3_column_int64($0, 0)),
                  let kind = GatewayTrustEvidenceKind(rawValue: raw) else { throw GatewayAuthorityError.corruptData }
            do {
                let (binding, operation) = try trustEvidence(kind: kind, payload: blob($0, 2, maximum: policy.payloadLimits.maxBytes),
                    signature: blob($0, 3, maximum: 64), identity: identity)
                guard binding.phoneID == phone, try blob($0, 1, maximum: 16) == operation else { throw GatewayAuthorityError.corruptData }
            } catch { throw GatewayAuthorityError.corruptData }
            return true
        }
    }

    func restrictUnknownTrust(kind: GatewayTrustEvidenceKind, payload: Data, signature: Data,
                              identity: GatewayRegistrationIdentity, enrollments: [StoredApprovalEnrollment]) throws -> (Data, GatewayTrustRestrictionDisposition) {
        _ = try head(identity)
        let (binding, operation) = try trustEvidence(kind: kind, payload: payload, signature: signature, identity: identity)
        let phone = binding.phoneID
        if try trustRestricted(phone: phone, identity: identity) { return (phone, .alreadyRestricted) }
        if enrollments.contains(where: { $0.approval.phoneID == phone && $0.epoch == binding.enrollmentEpoch && $0.notificationTag == binding.enrollmentTag }) {
            return (phone, .knownHistory)
        }
        try requireCapacity(.trustRestriction)
        try statement("INSERT INTO main.gateway_trust_restrictions_v1 VALUES(?,\(kind.rawValue),?,?,?)",
            [phone, operation, payload, signature]) { try done($0) }
        try statement("UPDATE main.gateway_root_candidates_v1 SET run=zeroblob(16) WHERE phone=?", [phone]) { try done($0) }
        return (phone, .restricted)
    }

    static func createRecoveredRevocationsSchema(_ db: OpaquePointer) throws {
        let result = sqlite3_exec(db, """
            CREATE TABLE main.gateway_recovered_revocations_v1(
                phone BLOB NOT NULL CHECK(length(phone)=16), enrollment BLOB NOT NULL CHECK(length(enrollment)=16),
                operation BLOB NOT NULL UNIQUE CHECK(length(operation)=16), payload BLOB NOT NULL,
                signature BLOB NOT NULL CHECK(length(signature)=64), PRIMARY KEY(phone,enrollment)
            ) STRICT, WITHOUT ROWID;
            """, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    /// Restrictive evidence is permanent. Its delivery expiry cannot restore a revoked enrollment.
    func recoverRevocation(payload: Data, signature: Data, identity: GatewayRegistrationIdentity) throws -> (GatewayPhoneRevocation, Bool) {
        _ = try head(identity)
        let value = try GatewayPhoneRevocation.decode(payload, limits: policy.payloadLimits)
        guard try GatewayRecipientSignature.verify(signature: signature, publicKey: identity.rootPublicKey, wireVersion: 1,
            kind: .phoneRevocation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits) else {
            throw GatewayAuthorityError.invalidSignature
        }
        guard GatewayStoredRecipient.revocation(value).matches(identity) else { throw GatewayAuthorityError.wrongScope }
        let phone = value.binding.phoneID, epoch = value.binding.enrollmentEpoch
        var changed = false
        if try latestRevocation(phone: phone, epoch: epoch, identity: identity) == nil,
           try recoveredRevocation(phone: phone, epoch: epoch, identity: identity) == nil {
            let retained = try hasRetainedEnrollment(phone: phone, epoch: epoch)
            try requireCapacity(retained ? .firstRecoveredRevocation : .otherRecoveredRevocation)
            try statement("INSERT INTO main.gateway_recovered_revocations_v1 VALUES(?,?,?,?,?)",
                [phone, epoch, value.operationID, payload, signature]) { try done($0) }
            changed = true
        }
        try statement("""
            DELETE FROM main.gateway_desired_tokens_v1 WHERE candidate IN
            (SELECT candidate FROM main.gateway_root_candidates_v1 WHERE phone=? AND enrollment=?)
            """, [phone, epoch]) { try done($0); changed = changed || sqlite3_changes(db) != 0 }
        if changed {
            try statement("UPDATE main.gateway_root_candidates_v1 SET run=zeroblob(16) WHERE phone=? AND enrollment=? AND run<>zeroblob(16)",
                [phone, epoch]) { try done($0) }
        }
        return (value, changed)
    }

    private func recoveredRevocation(operation: Data, identity: GatewayRegistrationIdentity) throws -> GatewayPhoneRevocation? {
        try statement("SELECT phone,enrollment FROM main.gateway_recovered_revocations_v1 WHERE operation=?", [operation]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW,
                  let value = try recoveredRevocation(phone: blob($0, 0, maximum: 16), epoch: blob($0, 1, maximum: 16), identity: identity),
                  value.operationID == operation else { throw GatewayAuthorityError.corruptData }
            return value
        }
    }

    private func recoveredRevocation(phone: Data, epoch: Data, identity: GatewayRegistrationIdentity) throws -> GatewayPhoneRevocation? {
        try statement("SELECT operation,payload,signature FROM main.gateway_recovered_revocations_v1 WHERE phone=? AND enrollment=?", [phone, epoch]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let payload = try blob($0, 1, maximum: policy.payloadLimits.maxBytes), signature = try blob($0, 2, maximum: 64)
            guard let value = try? GatewayPhoneRevocation.decode(payload, limits: policy.payloadLimits),
                  try GatewayRecipientSignature.verify(signature: signature, publicKey: identity.rootPublicKey, wireVersion: 1,
                    kind: .phoneRevocation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits),
                  GatewayStoredRecipient.revocation(value).matches(identity), value.binding.phoneID == phone, value.binding.enrollmentEpoch == epoch,
                  try blob($0, 0, maximum: 16) == value.operationID else { throw GatewayAuthorityError.corruptData }
            return value
        }
    }

    func acknowledgment(_ identity: GatewayRegistrationIdentity) throws -> GatewayAcknowledgment? {
        let local = try head(identity)
        return try statement("SELECT revision,operation FROM main.gateway_acknowledgment_v1 WHERE id=1", []) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let revision = try unsigned(blob($0, 0, maximum: 8))
            let operation = sqlite3_column_type($0, 1) == SQLITE_NULL ? nil : try blob($0, 1, maximum: 16)
            guard revision <= local, (revision == 0) == (operation == nil) else { throw GatewayAuthorityError.corruptData }
            var abandoned = false
            if let operation {
                guard let retained = try envelope(operation, identity: identity), retained.revision == revision else {
                    throw GatewayAuthorityError.corruptData
                }
                abandoned = try abandonedGrant(operation, registration: identity)?.resolution == .confirmed
            }
            return GatewayAcknowledgment(revision: revision, operationID: operation, abandonedGrant: abandoned)
        }
    }

    /// Record only controls already present in protected local history. Never fill a history gap from this reply.
    func acknowledge(_ verified: VerifiedGatewayHead, record: Bool = true) throws -> GatewayAcknowledgmentResult {
        let evidence = verified.evidence, identity = evidence.registration
        let local = try head(identity), previous = try acknowledgment(identity)
        func result(_ disposition: GatewayAcknowledgmentDisposition, _ value: GatewayAcknowledgment?) -> GatewayAcknowledgmentResult {
            GatewayAcknowledgmentResult(disposition: disposition, acknowledged: value,
                localRevision: local, reportedRevision: evidence.revision)
        }
        var abandoned = false
        if let receipt = evidence.receipt {
            guard let retained = try envelope(receipt.operationID, identity: identity) else {
                return result(.missingLocalHistory, previous)
            }
            guard retained.revision == evidence.revision, try matchesRetainedControl(receipt, retained: retained, identity: identity) else {
                return result(.conflictingLocalHistory, previous)
            }
            if case .tombstone = receipt { abandoned = true }
        } else if evidence.revision != 0 { throw GatewayAuthorityError.corruptData }
        // Check receipt consistency before treating an old response as harmless reordering.
        if let previous {
            if evidence.revision < previous.revision { return result(.olderThanRecorded, previous) }
            if evidence.revision == previous.revision {
                return result(.alreadyRecorded, GatewayAcknowledgment(revision: previous.revision,
                    operationID: previous.operationID, abandonedGrant: abandoned))
            }
        }
        guard evidence.revision <= local else { return result(.missingLocalHistory, previous) }
        let value = GatewayAcknowledgment(revision: evidence.revision, operationID: evidence.receipt?.operationID,
            abandonedGrant: abandoned)
        if !record { return result(.recorded, value) }
        if let receipt = evidence.receipt { try resolveGrantAbandonment(receipt, registration: identity) }
        try statement("""
            INSERT INTO main.gateway_acknowledgment_v1 VALUES(1,?,?)
            ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,operation=excluded.operation
            """, [uint(value.revision), value.operationID]) { try done($0) }
        return result(.recorded, value)
    }

    private func matchesRetainedControl(_ receipt: GatewayControlReceipt, retained: GatewayAuthorityEnvelope,
                                        identity: GatewayRegistrationIdentity) throws -> Bool {
        guard receipt.operationID == retained.operationID, receipt.revision == retained.revision else { return false }
        let retirement = try abandonedGrant(retained.operationID, registration: identity)
        if case .tombstone(let evidence) = receipt {
            return retirement?.isRetired == true && retirement?.control == evidence.tombstone
                && retirement?.signature == evidence.signature && evidence.tombstone.originalKind.rawValue == retained.kind
                && evidence.tombstone.originalDigest == GatewayControlTombstone.digest(
                    payload: retained.canonicalPayload, signature: retained.signature)
        }
        guard retirement?.resolution != .confirmed, receipt.kind == retained.kind,
              receipt.canonicalPayload == retained.canonicalPayload else { return false }
        return retirement == nil || receipt.signature == retained.signature
    }

    // Call only after the signed receipt has matched the exact retained control.
    private func resolveGrantAbandonment(_ receipt: GatewayControlReceipt, registration: GatewayRegistrationIdentity) throws {
        guard let retirement = try abandonedGrant(receipt.operationID, registration: registration),
              retirement.resolution == .pending else { return }
        let resolution: AbandonmentResolution
        if case .tombstone = receipt { resolution = .confirmed }
        else { resolution = .superseded }
        try statement("UPDATE main.gateway_abandoned_grants_v1 SET resolution=\(resolution.rawValue) WHERE operation=? AND resolution=0",
            [receipt.operationID]) { row in
            try done(row)
            guard sqlite3_changes(db) == 1 else { throw GatewayAuthorityError.corruptData }
        }
    }

    func configure(_ identity: GatewayRegistrationIdentity) throws {
        try scope(identity)
        let encoded = try identity.encode()
        if let previous = try statement("SELECT identity FROM main.gateway_authority_v1 WHERE id=1", [], { stmt -> Data? in
            let result = sqlite3_step(stmt)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            return try blob(stmt, 0, maximum: 512)
        }) {
            guard previous == encoded else { throw GatewayAuthorityError.wrongScope }
            return
        }
        let extra = try submissionCountSQL()
        try statement("SELECT (SELECT count(*) FROM main.gateway_outbox_v1)+(SELECT count(*) FROM main.gateway_root_candidates_v1)+(SELECT count(*) FROM main.gateway_desired_tokens_v1)+(SELECT count(*) FROM main.gateway_revocations_v1)+(SELECT count(*) FROM main.gateway_acknowledgment_v1)+(SELECT count(*) FROM main.gateway_reconciled_controls_v1)+(SELECT count(*) FROM main.gateway_recovered_revocations_v1)+(SELECT count(*) FROM main.gateway_trust_restrictions_v1)" + extra, []) {
            guard sqlite3_step($0) == SQLITE_ROW, sqlite3_column_int64($0, 0) == 0 else { throw GatewayAuthorityError.corruptData }
        }
        try statement("INSERT INTO main.gateway_authority_v1 VALUES(1,?,?)", [encoded, uint(0)]) { try done($0) }
    }

    func head(_ identity: GatewayRegistrationIdentity) throws -> UInt64 {
        try scope(identity)
        return try statement("SELECT identity,head FROM main.gateway_authority_v1 WHERE id=1", []) {
            guard sqlite3_step($0) == SQLITE_ROW else { throw GatewayAuthorityError.unconfigured }
            guard try blob($0, 0, maximum: 512) == identity.encode() else { throw GatewayAuthorityError.wrongScope }
            let value = try unsigned(blob($0, 1, maximum: 8))
            let extra = try submissionCountSQL()
            let count = try statement("SELECT (SELECT count(*) FROM main.gateway_outbox_v1)+(SELECT count(*) FROM main.gateway_revocations_v1)+(SELECT count(*) FROM main.gateway_reconciled_controls_v1)" + extra, []) { stmt -> UInt64 in
                guard sqlite3_step(stmt) == SQLITE_ROW, let count = UInt64(exactly: sqlite3_column_int64(stmt, 0)) else { throw GatewayAuthorityError.corruptData }
                return count
            }
            guard value == count else { throw GatewayAuthorityError.corruptData }
            if value > 0 {
                let submission = try AuthorityJournalSchema.featureTier(on: db) >= 16 ? " UNION ALL SELECT operation,revision FROM main.gateway_submission_outbox_v1" : ""
                try statement("SELECT operation,revision FROM main.gateway_outbox_v1 UNION ALL SELECT operation,revision FROM main.gateway_revocations_v1 UNION ALL SELECT operation,revision FROM main.gateway_reconciled_controls_v1" + submission + " ORDER BY revision DESC LIMIT 1", []) { stmt in
                    guard sqlite3_step(stmt) == SQLITE_ROW, let latest = try envelope(blob(stmt, 0, maximum: 16), identity: identity),
                          latest.revision == value else { throw GatewayAuthorityError.corruptData }
                }
            }
            return value
        }
    }

    static let abandonmentTable = "gateway_abandoned_grants_v1"

    func abandonmentHistoryInstalled() throws -> Bool {
        try AuthorityJournalSchema.featureTier(on: db) == 18
    }

    private enum AbandonmentResolution: Int32 { case pending, confirmed, superseded }

    private struct AbandonedGrant {
        let control: GatewayControlTombstone
        let signature: Data?
        let resolution: AbandonmentResolution
        var isRetired: Bool { resolution != .superseded }
    }

    private func abandonedGrant(_ operation: Data, registration: GatewayRegistrationIdentity) throws -> AbandonedGrant? {
        guard try abandonmentHistoryInstalled() else { return nil }
        return try statement("SELECT revision,kind,digest,signature,resolution FROM main.gateway_abandoned_grants_v1 WHERE operation=?", [operation]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW, let kind = GatewayControlTombstone.GrantKind(rawValue: try unsigned(blob($0, 1, maximum: 8))) else {
                throw GatewayAuthorityError.corruptData
            }
            let control = try GatewayControlTombstone(registration: registration, revision: unsigned(blob($0, 0, maximum: 8)),
                originalKind: kind, operationID: operation, originalDigest: blob($0, 2, maximum: 32))
            let signature = sqlite3_column_type($0, 3) == SQLITE_NULL ? nil : try blob($0, 3, maximum: 64)
            if let signature {
                do { _ = try GatewayControlTombstone.authenticate(control.encode(), signature: signature, registration: registration) }
                catch { throw GatewayAuthorityError.corruptData }
            }
            guard let resolution = AbandonmentResolution(rawValue: sqlite3_column_int($0, 4)),
                  resolution != .confirmed || signature != nil else { throw GatewayAuthorityError.corruptData }
            return AbandonedGrant(control: control, signature: signature, resolution: resolution)
        }
    }

    private func grant(at revision: UInt64, registration: GatewayRegistrationIdentity) throws -> GatewayAuthorityEnvelope? {
        let operation = try statement("SELECT operation FROM main.gateway_outbox_v1 WHERE revision=?", [uint(revision)]) { row -> Data? in
            let result = sqlite3_step(row)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            return try blob(row, 0, maximum: 16)
        }
        guard let operation else { return nil }
        guard let value = try envelope(operation, identity: registration), value.revision == revision,
              GatewayControlTombstone.GrantKind(rawValue: value.kind) != nil else { throw GatewayAuthorityError.corruptData }
        return value
    }

    func grantRetirement(at revision: UInt64, registration: GatewayRegistrationIdentity,
                         enrollments: [StoredApprovalEnrollment], wall: UInt64) throws -> GatewayGrantRetirement {
        guard revision <= (try head(registration)), revision > (try acknowledgment(registration)?.revision ?? 0),
              let original = try grant(at: revision, registration: registration),
              let kind = GatewayControlTombstone.GrantKind(rawValue: original.kind) else { return .none }
        let digest = GatewayControlTombstone.digest(payload: original.canonicalPayload, signature: original.signature)
        let control = try GatewayControlTombstone(registration: registration, revision: revision, originalKind: kind,
            operationID: original.operationID, originalDigest: digest)
        if let retained = try abandonedGrant(original.operationID, registration: registration) {
            guard retained.control == control else { throw GatewayAuthorityError.corruptData }
            return retained.isRetired ? .eligible(control) : .none
        }
        let binding: GatewayTokenBinding, expiry: UInt64
        switch kind {
        case .candidate:
            let value = try storedCandidate(original.canonicalPayload)
            binding = value.binding; expiry = value.expiresAtUnixMillis
        case .activation:
            let value = try storedActivation(original.canonicalPayload)
            binding = value.binding; expiry = value.expiresAtUnixMillis
        }
        guard let enrolled = enrollments.first(where: { $0.approval.phoneID == binding.phoneID && $0.epoch == binding.enrollmentEpoch }),
              enrolled.notificationTag == binding.enrollmentTag else { return .none }
        if !enrolled.approval.active || wall >= expiry { return .eligible(control) }
        if let desired = try desiredCandidate(binding.phoneID), desired != binding.candidateID { return .expiresBeforeRetirement }
        return .none
    }

    func stageGrantAbandonment(_ proposed: GatewayControlTombstone, enrollments: [StoredApprovalEnrollment], wall: UInt64) throws {
        guard try grantRetirement(at: proposed.revision, registration: proposed.registration,
            enrollments: enrollments, wall: wall) == .eligible(proposed) else { throw GatewayAuthorityError.wrongScope }
        if try abandonedGrant(proposed.operationID, registration: proposed.registration) != nil { return }
        if try !abandonmentHistoryInstalled() {
            let version = try AuthorityJournalSchema.featureTier(on: db)
            guard (15...17).contains(version) else { throw JournalDatabaseError.incompatibleStore }
            if version < 17 { try UpdateSchedulingJournal.createStorage(connection: db, from: version) }
            let result = sqlite3_exec(db, """
                CREATE TABLE main.gateway_abandoned_grants_v1 (
                    operation BLOB PRIMARY KEY REFERENCES gateway_outbox_v1(operation),
                    revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8),
                    kind BLOB NOT NULL CHECK(length(kind)=8),
                    digest BLOB NOT NULL CHECK(length(digest)=32),
                    signature BLOB CHECK(signature IS NULL OR length(signature)=64),
                    resolution INTEGER NOT NULL CHECK(resolution IN (0,1,2) AND (resolution!=1 OR signature IS NOT NULL)),
                    first_unconfirmed_ms BLOB CHECK(first_unconfirmed_ms IS NULL OR
                        (length(first_unconfirmed_ms)=8 AND signature IS NOT NULL))
                ) STRICT, WITHOUT ROWID;
                """, nil, nil, nil)
            guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
            try AuthorityJournalSchema.setFeatureTier(18, on: db)
        }
        try statement("INSERT INTO main.gateway_abandoned_grants_v1 VALUES(?,?,?,?,NULL,0,NULL)",
            [proposed.operationID, uint(proposed.revision), uint(proposed.originalKind.rawValue), proposed.originalDigest]) { try done($0) }
    }

    func signedGrantAbandonment(_ proposed: GatewayControlTombstone) throws -> Data? {
        guard let retained = try abandonedGrant(proposed.operationID, registration: proposed.registration),
              retained.control == proposed, retained.isRetired else { return nil }
        return retained.signature
    }

    func finishGrantAbandonment(_ proposed: GatewayControlTombstone, wall: UInt64, sign: (Data) throws -> Data) throws -> Data {
        guard proposed.revision > (try acknowledgment(proposed.registration)?.revision ?? 0),
              let original = try grant(at: proposed.revision, registration: proposed.registration),
              GatewayControlTombstone.GrantKind(rawValue: original.kind) == proposed.originalKind,
              original.operationID == proposed.operationID,
              GatewayControlTombstone.digest(payload: original.canonicalPayload, signature: original.signature) == proposed.originalDigest,
              let retained = try abandonedGrant(proposed.operationID, registration: proposed.registration),
              retained.control == proposed, retained.resolution == .pending else { throw GatewayAuthorityError.wrongScope }
        if let signature = retained.signature { return signature }
        let payload = try proposed.encode()
        let signature = try sign(GatewayControlTombstone.signingInput(payload))
        _ = try GatewayControlTombstone.authenticate(payload, signature: signature, registration: proposed.registration)
        // Once signed, the next network effect may succeed even if its reply is lost.
        try statement("""
            UPDATE main.gateway_abandoned_grants_v1 SET signature=?,first_unconfirmed_ms=?
            WHERE operation=? AND resolution=0 AND signature IS NULL
            """, [signature, uint(wall), proposed.operationID]) {
            try done($0); guard sqlite3_changes(db) == 1 else { throw GatewayAuthorityError.corruptData }
        }
        return signature
    }

    /// A registration publisher cannot skip another retained control, even after that control expires.
    /// Only a fresh verified gateway head can establish that this ordering barrier has passed.
    func firstNonRegistrationControl(after revision: UInt64, identity: GatewayRegistrationIdentity) throws -> UInt64? {
        guard revision <= (try head(identity)) else { throw GatewayAuthorityError.headMismatch }
        let submission = try AuthorityJournalSchema.featureTier(on: db) >= 16
            ? " UNION ALL SELECT operation,revision FROM main.gateway_submission_outbox_v1 WHERE revision>?" : ""
        var arguments = [uint(revision)]
        if !submission.isEmpty { arguments.append(uint(revision)) }
        return try statement("SELECT operation,revision FROM main.gateway_revocations_v1 WHERE revision>?" + submission + " ORDER BY revision LIMIT 1", arguments) { row in
            let result = sqlite3_step(row)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let next = try unsigned(blob(row, 1, maximum: 8))
            guard let retained = try envelope(blob(row, 0, maximum: 16), identity: identity), retained.revision == next,
                  retained.kind == 3 || GatewaySubmissionKind(rawValue: retained.kind) != nil else { throw GatewayAuthorityError.corruptData }
            return next
        }
    }

    func prepare(token: String, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data, trust: GatewayAuthorityTrust,
                 expectedHead: UInt64, wall: UInt64, now: AuthorityMoment,
                 sign: (GatewayTokenCandidate) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try authenticate(phone: authenticatedPhoneID, epoch: authenticatedEnrollmentEpoch, trust: trust)
        try clock(now)
        guard !token.isEmpty, token.utf8.count <= 16384, token.utf8.allSatisfy({ (33...126).contains($0) }) else {
            throw GatewayAuthorityError.invalidToken
        }
        try requireHead(expectedHead, identity: trust.registration)
        let (expiry, overflow) = wall.addingReportingOverflow(policy.candidateLifetimeMillis)
        let (deadline, monoOverflow) = now.milliseconds.addingReportingOverflow(policy.candidateLifetimeMillis)
        guard !overflow, !monoOverflow else { throw GatewayAuthorityError.invalidClock }
        let r = trust.registration, e = trust.enrollment, candidateID = uuid(UUID()), operation = uuid(UUID())
        let challenge = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let binding = try GatewayTokenBinding(ownerID: r.ownerID, macID: mac, accountID: account, gatewayID: r.gatewayID,
            lifecycleEpoch: r.lifecycleEpoch, phoneID: e.phoneID, enrollmentEpoch: e.epoch, candidateID: candidateID,
            tokenDigest: Data(SHA256.hash(data: Data(token.utf8))), challenge: challenge, enrollmentTag: e.tag)
        let candidate = try GatewayTokenCandidate(binding: binding, revision: expectedHead + 1, operationID: operation,
            issuedAtUnixMillis: wall, expiresAtUnixMillis: expiry)
        let payload = try candidate.encode(limits: policy.payloadLimits), signature = try sign(candidate)
        guard try GatewayTokenCandidateSignature.verify(signature: signature, publicKey: r.rootPublicKey, wireVersion: 1,
            canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits) else { throw GatewayAuthorityError.invalidSignature }
        let envelope = GatewayAuthorityEnvelope(kind: 1, operationID: operation, revision: candidate.revision,
            canonicalPayload: payload, signature: signature, registrationToken: token)
        try insert(envelope, candidate: candidateID)
        try statement("INSERT INTO main.gateway_root_candidates_v1 VALUES(?,?,?,?,?,?,?,NULL)",
            [candidateID, e.phoneID, e.epoch, operation, uuid(run), uint(now.milliseconds), uint(deadline)]) { try done($0) }
        try statement("INSERT INTO main.gateway_desired_tokens_v1 VALUES(?,?) ON CONFLICT(phone) DO UPDATE SET candidate=excluded.candidate",
            [e.phoneID, candidateID]) { try done($0) }
        try advance(from: expectedHead, to: candidate.revision)
        return envelope
    }

    /// Reissue current retained desired state after expiry or restart; never refresh an arbitrary historical outbox entry.
    func renewDesired(trust: GatewayAuthorityTrust, expectedHead: UInt64, wall: UInt64, now: AuthorityMoment,
                      sign: (GatewayTokenCandidate) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try authenticate(phone: trust.enrollment.phoneID, epoch: trust.enrollment.epoch, trust: trust)
        try requireHead(expectedHead, identity: trust.registration)
        _ = try desiredCandidate(trust.enrollment.phoneID)
        let token: String = try statement("""
            SELECT c.operation FROM main.gateway_desired_tokens_v1 d
            JOIN main.gateway_root_candidates_v1 c ON d.candidate=c.candidate WHERE d.phone=?
            """, [trust.enrollment.phoneID]) {
            guard sqlite3_step($0) == SQLITE_ROW,
                  let entry = try envelope(blob($0, 0, maximum: 16), identity: trust.registration), entry.kind == 1,
                  let token = entry.registrationToken else { throw GatewayAuthorityError.unconfigured }
            let candidate = try storedCandidate(entry.canonicalPayload)
            guard candidate.binding.phoneID == trust.enrollment.phoneID, candidate.binding.enrollmentEpoch == trust.enrollment.epoch,
                  candidate.binding.enrollmentTag == trust.enrollment.tag else { throw GatewayAuthorityError.wrongScope }
            guard candidate.binding.tokenDigest == Data(SHA256.hash(data: Data(token.utf8))) else { throw GatewayAuthorityError.corruptData }
            return token
        }
        return try prepare(token: token, authenticatedPhoneID: trust.enrollment.phoneID, authenticatedEnrollmentEpoch: trust.enrollment.epoch,
            trust: trust, expectedHead: expectedHead, wall: wall, now: now, sign: sign)
    }

    func consume(proofBytes: Data, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data, trust: GatewayAuthorityTrust,
                 expectedHead: UInt64, wall: UInt64, now: AuthorityMoment,
                 sign: (GatewayMappingActivation) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try authenticate(phone: authenticatedPhoneID, epoch: authenticatedEnrollmentEpoch, trust: trust)
        try clock(now); try requireHead(expectedHead, identity: trust.registration)
        let proof = try GatewayTokenProof.decode(proofBytes, limits: policy.payloadLimits)
        let retained = try candidate(proof.binding.candidateID, trust: trust, wall: wall, now: now)
        guard proof.binding == retained.value.binding else { throw GatewayAuthorityError.wrongScope }
        guard retained.consumed == nil else { throw GatewayAuthorityError.alreadyConsumed }
        let activation = try GatewayMappingActivation(binding: retained.value.binding, revision: expectedHead + 1,
            operationID: uuid(UUID()), issuedAtUnixMillis: wall, expiresAtUnixMillis: retained.value.expiresAtUnixMillis)
        let payload = try activation.encode(limits: policy.payloadLimits), signature = try sign(activation)
        guard try GatewayRecipientSignature.verify(signature: signature, publicKey: trust.registration.rootPublicKey, wireVersion: 1,
            kind: .activation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits) else {
            throw GatewayAuthorityError.invalidSignature
        }
        let envelope = GatewayAuthorityEnvelope(kind: 2, operationID: activation.operationID, revision: activation.revision,
            canonicalPayload: payload, signature: signature, registrationToken: nil)
        try insert(envelope, candidate: proof.binding.candidateID)
        try statement("UPDATE main.gateway_root_candidates_v1 SET consumed=? WHERE candidate=? AND consumed IS NULL",
            [activation.operationID, proof.binding.candidateID]) {
            try done($0); guard sqlite3_changes(db) == 1 else { throw GatewayAuthorityError.alreadyConsumed }
        }
        try advance(from: expectedHead, to: activation.revision)
        return envelope
    }

    func pending(operationID: Data, trust: GatewayAuthorityTrust, wall: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        try authenticate(phone: trust.enrollment.phoneID, epoch: trust.enrollment.epoch, trust: trust)
        try clock(now); _ = try head(trust.registration)
        guard let envelope = try envelope(operationID, identity: trust.registration) else { return nil }
        let recovered = try statement("SELECT count(*) FROM main.gateway_reconciled_controls_v1 WHERE operation=?", [operationID]) {
            guard sqlite3_step($0) == SQLITE_ROW else { throw GatewayAuthorityError.corruptData }
            return sqlite3_column_int64($0, 0) != 0
        }
        if try recovered || abandonedGrant(operationID, registration: trust.registration)?.isRetired == true { return nil }
        guard envelope.kind != 3 else { throw GatewayAuthorityError.wrongScope }
        let candidateID: Data
        if envelope.kind == 1 { candidateID = try storedCandidate(envelope.canonicalPayload).binding.candidateID }
        else { candidateID = try storedActivation(envelope.canonicalPayload).binding.candidateID }
        let retained = try candidate(candidateID, trust: trust, wall: wall, now: now)
        if envelope.kind == 1 { guard retained.consumed == nil else { return nil } }
        else { guard retained.consumed == envelope.operationID else { throw GatewayAuthorityError.corruptData } }
        return envelope
    }

    func revoked(trust: GatewayAuthorityTrust) throws -> Bool {
        _ = try head(trust.registration)
        return try latestRevocation(trust: trust) != nil || recoveredRevocation(phone: trust.enrollment.phoneID, epoch: trust.enrollment.epoch, identity: trust.registration) != nil
    }

    /// The signed row is both the permanent epoch tombstone and its retryable delivery control.
    func revoke(trust: GatewayAuthorityTrust, expectedHead: UInt64, wall: UInt64, now: AuthorityMoment,
                sign: (GatewayPhoneRevocation) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try scope(trust.registration); try clock(now); try requireHead(expectedHead, identity: trust.registration)
        let previous = try latestRevocation(trust: trust)
        let (expiry, overflow) = wall.addingReportingOverflow(policy.candidateLifetimeMillis)
        let (deadline, monoOverflow) = now.milliseconds.addingReportingOverflow(policy.candidateLifetimeMillis)
        guard !overflow, !monoOverflow else { throw GatewayAuthorityError.invalidClock }
        let r = trust.registration, e = trust.enrollment
        let binding = try GatewayPhoneEpochBinding(ownerID: r.ownerID, macID: mac, accountID: account, gatewayID: r.gatewayID,
            lifecycleEpoch: r.lifecycleEpoch, phoneID: e.phoneID, enrollmentEpoch: e.epoch)
        let value = try GatewayPhoneRevocation(binding: binding, revision: expectedHead + 1, operationID: uuid(UUID()),
            issuedAtUnixMillis: wall, expiresAtUnixMillis: expiry)
        let payload = try value.encode(limits: policy.payloadLimits), signature = try sign(value)
        guard try GatewayRecipientSignature.verify(signature: signature, publicKey: r.rootPublicKey, wireVersion: 1,
            kind: .phoneRevocation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits) else {
            throw GatewayAuthorityError.invalidSignature
        }
        let first = try previous == nil && hasRetainedEnrollment(phone: e.phoneID, epoch: e.epoch)
        try requireCapacity(first ? .firstRevocation : .revocationHistory)
        try statement("INSERT INTO main.gateway_revocations_v1 VALUES(?,?,?,?,?,?,?,?,?)",
            [value.operationID, uint(value.revision), e.phoneID, e.epoch, payload, signature, uuid(run), uint(now.milliseconds), uint(deadline)]) { try done($0) }
        try statement("""
            DELETE FROM main.gateway_desired_tokens_v1 WHERE phone=? AND candidate IN
                (SELECT candidate FROM main.gateway_root_candidates_v1 WHERE phone=? AND enrollment=?)
            """, [e.phoneID, e.phoneID, e.epoch]) { try done($0) }
        try advance(from: expectedHead, to: value.revision)
        return GatewayAuthorityEnvelope(kind: 3, operationID: value.operationID, revision: value.revision,
            canonicalPayload: payload, signature: signature, registrationToken: nil)
    }

    func pendingRevocation(operationID: Data, trust: GatewayAuthorityTrust, wall: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        try clock(now); _ = try head(trust.registration)
        guard trust.active else { throw GatewayAuthorityError.unavailableRegistration }
        guard let entry = try revocation(operationID, identity: trust.registration) else { return nil }
        guard entry.value.binding.phoneID == trust.enrollment.phoneID,
              entry.value.binding.enrollmentEpoch == trust.enrollment.epoch else { throw GatewayAuthorityError.wrongScope }
        guard try latestRevocation(trust: trust)?.envelope.operationID == operationID else { throw GatewayAuthorityError.superseded }
        guard entry.run == uuid(run), entry.started <= now.milliseconds, now.milliseconds < entry.deadline,
              entry.value.issuedAtUnixMillis <= wall, wall < entry.value.expiresAtUnixMillis else { throw GatewayAuthorityError.expired }
        return entry.envelope
    }

    func localRevocation(for phone: DeliveryRecipient, registration: GatewayRegistrationIdentity) throws -> GatewayAuthorityEnvelope? {
        _ = try head(registration)
        return try latestRevocation(phone: phone.phoneID, epoch: phone.enrollmentEpoch, identity: registration)?.envelope
    }

    func localRevocation(at revision: UInt64, registration: GatewayRegistrationIdentity) throws -> GatewayAuthorityEnvelope? {
        guard revision <= (try head(registration)) else { throw GatewayAuthorityError.headMismatch }
        let operation = try statement("SELECT operation FROM main.gateway_revocations_v1 WHERE revision=?", [uint(revision)]) { row -> Data? in
            let result = sqlite3_step(row)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            return try blob(row, 0, maximum: 16)
        }
        guard let operation else { return nil }
        guard let entry = try revocation(operation, identity: registration), entry.value.revision == revision else {
            throw GatewayAuthorityError.corruptData
        }
        // Recovery reuses the durable signed record, including its original lifetime and operation identity.
        return entry.envelope
    }

    private struct Revocation {
        let value: GatewayPhoneRevocation
        let envelope: GatewayAuthorityEnvelope
        let run: Data
        let started: UInt64
        let deadline: UInt64
    }
    private func latestRevocation(trust: GatewayAuthorityTrust) throws -> Revocation? {
        try latestRevocation(phone: trust.enrollment.phoneID, epoch: trust.enrollment.epoch, identity: trust.registration)
    }
    private func latestRevocation(phone: Data, epoch: Data, identity: GatewayRegistrationIdentity) throws -> Revocation? {
        try statement("SELECT operation FROM main.gateway_revocations_v1 WHERE phone=? AND enrollment=? ORDER BY revision DESC LIMIT 1",
            [phone, epoch]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW, let entry = try revocation(blob($0, 0, maximum: 16), identity: identity),
                  entry.value.binding.phoneID == phone,
                  entry.value.binding.enrollmentEpoch == epoch else { throw GatewayAuthorityError.corruptData }
            return entry
        }
    }
    private func revocation(_ operation: Data, identity: GatewayRegistrationIdentity) throws -> Revocation? {
        guard operation.count == 16 else { throw GatewayAuthorityError.wrongScope }
        return try statement("SELECT revision,phone,enrollment,payload,signature,run,started,deadline FROM main.gateway_revocations_v1 WHERE operation=?", [operation]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let payload = try blob($0, 3, maximum: policy.payloadLimits.maxBytes), signature = try blob($0, 4, maximum: 64)
            let value: GatewayPhoneRevocation
            do { value = try GatewayPhoneRevocation.decode(payload, limits: policy.payloadLimits) }
            catch { throw GatewayAuthorityError.corruptData }
            guard try GatewayRecipientSignature.verify(signature: signature, publicKey: identity.rootPublicKey, wireVersion: 1,
                      kind: .phoneRevocation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits),
                  GatewayStoredRecipient.revocation(value).matches(identity), value.operationID == operation,
                  try unsigned(blob($0, 0, maximum: 8)) == value.revision,
                  try blob($0, 1, maximum: 16) == value.binding.phoneID,
                  try blob($0, 2, maximum: 16) == value.binding.enrollmentEpoch else { throw GatewayAuthorityError.corruptData }
            let started = try unsigned(blob($0, 6, maximum: 8)), deadline = try unsigned(blob($0, 7, maximum: 8))
            guard deadline > started, deadline - started == value.expiresAtUnixMillis - value.issuedAtUnixMillis else { throw GatewayAuthorityError.corruptData }
            return Revocation(value: value, envelope: GatewayAuthorityEnvelope(kind: 3, operationID: operation, revision: value.revision,
                canonicalPayload: payload, signature: signature, registrationToken: nil), run: try blob($0, 5, maximum: 16), started: started, deadline: deadline)
        }
    }

    private struct Retained { let value: GatewayTokenCandidate; let consumed: Data?; let state: GatewayCurrentTokenState }
    private func candidate(_ id: Data, trust: GatewayAuthorityTrust, wall: UInt64, now: AuthorityMoment, allowExpired: Bool = false) throws -> Retained {
        guard try desiredCandidate(trust.enrollment.phoneID) == id else { throw GatewayAuthorityError.superseded }
        return try statement("""
            SELECT c.phone,c.enrollment,c.operation,c.run,c.started,c.deadline,c.consumed,d.candidate
            FROM main.gateway_root_candidates_v1 c LEFT JOIN main.gateway_desired_tokens_v1 d ON c.phone=d.phone WHERE c.candidate=?
            """, [id]) {
            guard sqlite3_step($0) == SQLITE_ROW else { throw GatewayAuthorityError.wrongScope }
            guard try blob($0, 0, maximum: 16) == trust.enrollment.phoneID,
                  try blob($0, 1, maximum: 16) == trust.enrollment.epoch else { throw GatewayAuthorityError.wrongScope }
            guard try blob($0, 7, maximum: 16) == id else { throw GatewayAuthorityError.superseded }
            let sameRun = try blob($0, 3, maximum: 16) == uuid(run)
            let started = try unsigned(blob($0, 4, maximum: 8)), deadline = try unsigned(blob($0, 5, maximum: 8))
            let candidateOperation = try blob($0, 2, maximum: 16)
            let candidateRetired = try abandonedGrant(candidateOperation, registration: trust.registration)?.isRetired == true
            let liveMoment = sameRun && !candidateRetired && started <= now.milliseconds && now.milliseconds < deadline
            if !allowExpired && !liveMoment { throw GatewayAuthorityError.expired }
            guard let entry = try envelope(candidateOperation, identity: trust.registration), entry.kind == 1,
                  let token = entry.registrationToken else { throw GatewayAuthorityError.corruptData }
            let value = try storedCandidate(entry.canonicalPayload)
            guard value.binding.candidateID == id, value.binding.phoneID == trust.enrollment.phoneID,
                  value.binding.enrollmentEpoch == trust.enrollment.epoch, value.binding.enrollmentTag == trust.enrollment.tag,
                  value.binding.tokenDigest == Data(SHA256.hash(data: Data(token.utf8))) else { throw GatewayAuthorityError.corruptData }
            guard deadline > started, deadline - started == value.expiresAtUnixMillis - value.issuedAtUnixMillis else {
                throw GatewayAuthorityError.corruptData
            }
            let liveWall = value.issuedAtUnixMillis <= wall && wall < value.expiresAtUnixMillis
            if !allowExpired && !liveWall { throw GatewayAuthorityError.expired }
            let consumed = sqlite3_column_type($0, 6) == SQLITE_NULL ? nil : try blob($0, 6, maximum: 16)
            let activation = try statement("SELECT operation FROM main.gateway_outbox_v1 WHERE candidate=? AND kind=2", [id]) { stmt -> GatewayAuthorityEnvelope? in
                let result = sqlite3_step(stmt)
                if result == SQLITE_DONE { return nil }
                guard result == SQLITE_ROW, let entry = try envelope(blob(stmt, 0, maximum: 16), identity: trust.registration),
                      sqlite3_step(stmt) == SQLITE_DONE else { throw GatewayAuthorityError.corruptData }
                let activation = try storedActivation(entry.canonicalPayload)
                guard activation.binding == value.binding, activation.revision > value.revision,
                      activation.expiresAtUnixMillis == value.expiresAtUnixMillis else { throw GatewayAuthorityError.corruptData }
                return entry
            }
            guard activation?.operationID == consumed else { throw GatewayAuthorityError.corruptData }
            let activationAbandonment = try activation.flatMap { try abandonedGrant($0.operationID, registration: trust.registration) }
            let retired = candidateRetired || activationAbandonment?.isRetired == true
            return Retained(value: value, consumed: consumed, state: GatewayCurrentTokenState(candidate: entry,
                activation: retired ? nil : activation, candidateExpired: retired || !liveMoment || !liveWall,
                activationAbandonmentConfirmed: activationAbandonment?.resolution == .confirmed && !candidateRetired))
        }
    }

    /// Expiry is returned as data for explicit renewal. Corrupt signatures and mismatched scope still fail closed.
    func currentTokenState(trust: GatewayAuthorityTrust, wall: UInt64, now: AuthorityMoment) throws -> GatewayCurrentTokenState? {
        try authenticate(phone: trust.enrollment.phoneID, epoch: trust.enrollment.epoch, trust: trust)
        try clock(now); _ = try head(trust.registration)
        guard let id = try desiredCandidate(trust.enrollment.phoneID) else { return nil }
        return try candidate(id, trust: trust, wall: wall, now: now, allowExpired: true).state
    }

    private func desiredCandidate(_ phone: Data) throws -> Data? {
        try statement("""
            SELECT d.candidate,c.candidate FROM main.gateway_desired_tokens_v1 d
            JOIN main.gateway_root_candidates_v1 c ON c.phone=d.phone
            JOIN main.gateway_outbox_v1 o ON o.operation=c.operation
            WHERE d.phone=? ORDER BY o.revision DESC LIMIT 1
            """, [phone]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let desired = try blob($0, 0, maximum: 16)
            guard desired.count == 16, try blob($0, 1, maximum: 16) == desired else { throw GatewayAuthorityError.corruptData }
            return desired
        }
    }

    private func envelope(_ operation: Data, identity: GatewayRegistrationIdentity) throws -> GatewayAuthorityEnvelope? {
        guard operation.count == 16 else { throw GatewayAuthorityError.wrongScope }
        if let submission = try submissionEntry(operation, identity: identity) { return submission.envelope }
        if let revoked = try revocation(operation, identity: identity) { return revoked.envelope }
        return try statement("SELECT revision,kind,candidate,payload,signature,token,0 FROM main.gateway_outbox_v1 WHERE operation=? UNION ALL SELECT revision,kind,candidate,payload,signature,NULL,1 FROM main.gateway_reconciled_controls_v1 WHERE operation=?", [operation, operation]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let revision = try unsigned(blob($0, 0, maximum: 8))
            guard sqlite3_column_type($0, 1) == SQLITE_INTEGER, let kind = UInt64(exactly: sqlite3_column_int64($0, 1)) else { throw GatewayAuthorityError.corruptData }
            let payload = try blob($0, 3, maximum: policy.payloadLimits.maxBytes), signature = try blob($0, 4, maximum: 64)
            let binding: GatewayTokenBinding, storedOperation: Data, storedRevision: UInt64
            let valid: Bool
            switch kind {
            case 1:
                let value = try storedCandidate(payload)
                binding = value.binding; storedOperation = value.operationID; storedRevision = value.revision
                valid = try GatewayTokenCandidateSignature.verify(signature: signature, publicKey: identity.rootPublicKey,
                    wireVersion: 1, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits)
            case 2:
                let value = try storedActivation(payload)
                binding = value.binding; storedOperation = value.operationID; storedRevision = value.revision
                valid = try GatewayRecipientSignature.verify(signature: signature, publicKey: identity.rootPublicKey,
                    wireVersion: 1, kind: .activation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits)
            default: throw GatewayAuthorityError.corruptData
            }
            guard valid, identity.matches(binding), storedOperation == operation, storedRevision == revision,
                  try blob($0, 2, maximum: 16) == binding.candidateID else { throw GatewayAuthorityError.corruptData }
            let token = sqlite3_column_type($0, 5) == SQLITE_NULL ? nil : try String(data: blob($0, 5, maximum: 16384), encoding: .utf8)
            let recovered = sqlite3_column_int64($0, 6) == 1
            guard recovered ? token == nil : (kind == 1) == (token != nil) else { throw GatewayAuthorityError.corruptData }
            if let token {
                guard !token.isEmpty, token.utf8.allSatisfy({ (33...126).contains($0) }) else { throw GatewayAuthorityError.corruptData }
            }
            return GatewayAuthorityEnvelope(kind: kind, operationID: operation, revision: revision, canonicalPayload: payload,
                signature: signature, registrationToken: token)
        }
    }
    private func storedCandidate(_ payload: Data) throws -> GatewayTokenCandidate {
        do { return try GatewayTokenCandidate.decode(payload, limits: policy.payloadLimits) }
        catch { throw GatewayAuthorityError.corruptData }
    }
    private func storedActivation(_ payload: Data) throws -> GatewayMappingActivation {
        do { return try GatewayMappingActivation.decode(payload, limits: policy.payloadLimits) }
        catch { throw GatewayAuthorityError.corruptData }
    }

    private struct RevokedEpoch: Hashable {
        let phone: Data
        let epoch: Data
    }

    enum CapacityClass: CaseIterable {
        case delivery, firstRevocation, firstRecoveredRevocation
        case revocationHistory, otherRecoveredRevocation, trustRestriction
    }

    private static let firstRevocationCount = """
        SELECT count(*) FROM main.approval_enrollments_v1 AS e
        WHERE EXISTS (SELECT 1 FROM main.gateway_revocations_v1 AS r
                      WHERE r.phone=e.phone AND r.enrollment=e.epoch)
        """
    private static let firstRecoveredRevocationCount = """
        SELECT count(*) FROM main.approval_enrollments_v1 AS e
        WHERE EXISTS (SELECT 1 FROM main.gateway_recovered_revocations_v1 AS r
                      WHERE r.phone=e.phone AND r.enrollment=e.epoch)
        """

    private func hasRetainedEnrollment(phone: Data, epoch: Data) throws -> Bool {
        try statement("SELECT 1 FROM main.approval_enrollments_v1 WHERE phone=? AND epoch=?", [phone, epoch]) {
            switch sqlite3_step($0) {
            case SQLITE_ROW: return true
            case SQLITE_DONE: return false
            default: throw GatewayAuthorityError.corruptData
            }
        }
    }

    // Count only the class that will grow. Legacy excess in another class cannot use this class's slots.
    func requireCapacity(_ capacity: CapacityClass, additional: Int = 1) throws {
        let query: String
        let maximum: Int
        switch capacity {
        case .delivery:
            query = "SELECT (SELECT count(*) FROM main.gateway_outbox_v1)+(SELECT count(*) FROM main.gateway_reconciled_controls_v1)" + (try submissionCountSQL())
            maximum = policy.maximumControls
        case .firstRevocation:
            query = Self.firstRevocationCount
            maximum = EnrollmentJournal.maximumRows
        case .firstRecoveredRevocation:
            query = Self.firstRecoveredRevocationCount
            maximum = EnrollmentJournal.maximumRows
        case .revocationHistory:
            query = "SELECT (SELECT count(*) FROM main.gateway_revocations_v1)-(\(Self.firstRevocationCount))"
            maximum = 4096
        case .otherRecoveredRevocation:
            query = "SELECT (SELECT count(*) FROM main.gateway_recovered_revocations_v1)-(\(Self.firstRecoveredRevocationCount))"
            maximum = 1024
        case .trustRestriction:
            query = "SELECT count(*) FROM main.gateway_trust_restrictions_v1"
            maximum = 1024
        }
        let count = try statement(query, []) {
            guard sqlite3_step($0) == SQLITE_ROW,
                  let count = Int(exactly: sqlite3_column_int64($0, 0)), count >= 0 else {
                throw GatewayAuthorityError.corruptData
            }
            return count
        }
        guard additional > 0, count <= maximum, additional <= maximum - count else {
            throw GatewayAuthorityError.capacityExceeded
        }
    }

    private func insert(_ entry: GatewayAuthorityEnvelope, candidate: Data) throws {
        try requireCapacity(.delivery)
        try statement("INSERT INTO main.gateway_outbox_v1 VALUES(?,?,\(entry.kind),?,?,?,?)",
            [entry.operationID, uint(entry.revision), candidate, entry.canonicalPayload, entry.signature, entry.registrationToken.map { Data($0.utf8) }]) { try done($0) }
    }

    /// Creates dormant storage. The caller owns the schema version and continuity checkpoint.
    static func createSubmissionHistoryStorage(connection db: OpaquePointer) throws {
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        let result = sqlite3_exec(db, """
                CREATE TABLE main.gateway_submission_outbox_v1(
                    operation BLOB PRIMARY KEY CHECK(length(operation)=16), revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8),
                    kind INTEGER NOT NULL CHECK(kind IN (4,5)), credential BLOB NOT NULL CHECK(length(credential)=16),
                    payload BLOB NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64),
                    run BLOB NOT NULL CHECK(length(run)=16), started BLOB NOT NULL CHECK(length(started)=8),
                    deadline BLOB NOT NULL CHECK(length(deadline)=8)
                ) STRICT, WITHOUT ROWID;
                """, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    /// Protected setup only. The host must commit the new authority digest to its continuity boundary before activation.
    func installSubmissionHistory(identity: GatewayRegistrationIdentity) throws {
        try scope(identity); _ = try head(identity)
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        let version = try AuthorityJournalSchema.featureTier(on: db)
        guard (15...18).contains(version) else { throw GatewayAuthorityError.unsupportedSubmissionControl }
        guard try CodePolicyJournal(connection: db).read() != nil else { throw GatewayAuthorityError.unconfigured }
        if version == 15 {
            try Self.createSubmissionHistoryStorage(connection: db)
            try AuthorityJournalSchema.setFeatureTier(16, on: db)
        }
        try statement("SELECT operation,revision,kind,credential,payload,signature,run,started,deadline FROM main.gateway_submission_outbox_v1 LIMIT 0", []) {
            guard sqlite3_step($0) == SQLITE_DONE else { throw GatewayAuthorityError.corruptData }
        }
    }

    /// The privileged host supplies a staged public key. Root assigns the new identity and signed control revision.
    func rotateSubmission(publicKey: Data, identity: GatewayRegistrationIdentity, active: Bool,
                          expectedHead: UInt64, wall: UInt64, now: AuthorityMoment,
                          sign: (GatewaySubmissionControl) throws -> Data) throws -> GatewayAuthorityEnvelope {
        guard (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil else { throw GatewaySubmissionVerificationError.invalidCredential }
        return try issueSubmission(kind: .rotation, credential: uuid(UUID()), publicKey: publicKey, identity: identity,
            active: active, expectedHead: expectedHead, wall: wall, now: now, sign: sign)
    }

    func revokeSubmission(credentialID: Data, identity: GatewayRegistrationIdentity, active: Bool,
                          expectedHead: UInt64, wall: UInt64, now: AuthorityMoment,
                          sign: (GatewaySubmissionControl) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try issueSubmission(kind: .revocation, credential: credentialID, publicKey: nil, identity: identity,
            active: active, expectedHead: expectedHead, wall: wall, now: now, sign: sign)
    }

    private func issueSubmission(kind: GatewaySubmissionKind, credential: Data, publicKey: Data?,
                                 identity: GatewayRegistrationIdentity, active: Bool, expectedHead: UInt64,
                                 wall: UInt64, now: AuthorityMoment, sign: (GatewaySubmissionControl) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try scope(identity); try clock(now); try requireHead(expectedHead, identity: identity)
        guard active else { throw GatewayAuthorityError.unavailableRegistration }
        guard try (16...18).contains(AuthorityJournalSchema.featureTier(on: db)) else { throw GatewayAuthorityError.unsupportedSubmissionControl }
        guard credential.count == 16 else { throw GatewayAuthorityError.wrongScope }
        let (expiry, overflow) = wall.addingReportingOverflow(policy.candidateLifetimeMillis)
        let (deadline, monoOverflow) = now.milliseconds.addingReportingOverflow(policy.candidateLifetimeMillis)
        guard !overflow, !monoOverflow else { throw GatewayAuthorityError.invalidClock }
        let r = identity
        let value = try GatewaySubmissionControl(kind: kind,
            binding: GatewaySubmissionBinding(ownerID: r.ownerID, macID: mac, accountID: account, gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch),
            revision: expectedHead + 1, operationID: uuid(UUID()), issuedAtUnixMillis: wall, expiresAtUnixMillis: expiry,
            credentialID: credential, publicKey: publicKey)
        let payload = try value.encode(limits: policy.payloadLimits), signature = try sign(value)
        _ = try GatewaySubmissionVerifier.authenticate(canonicalPayload: payload, signature: signature, wireVersion: 1,
            registration: identity, payloadLimits: policy.payloadLimits, signingLimits: policy.signingLimits)
        let entries = try submissionEntries(identity)
        if kind == .rotation, entries.contains(where: { $0.receipt.control.credentialID == credential }) { throw GatewayAuthorityError.superseded }
        guard try envelope(value.operationID, identity: identity) == nil else { throw GatewayAuthorityError.corruptData }
        try requireCapacity(.delivery)
        try statement("INSERT INTO main.gateway_submission_outbox_v1 VALUES(?,?,\(kind.rawValue),?,?,?,?,?,?)",
            [value.operationID, uint(value.revision), credential, payload, signature, uuid(run), uint(now.milliseconds), uint(deadline)]) { try done($0) }
        try advance(from: expectedHead, to: value.revision)
        return GatewayAuthorityEnvelope(kind: kind.rawValue, operationID: value.operationID, revision: value.revision,
            canonicalPayload: payload, signature: signature, registrationToken: nil)
    }

    /// Historical Root intent only. It is not evidence that the gateway applied this control or that a private key is available.
    func desiredSubmission(identity: GatewayRegistrationIdentity) throws -> GatewaySubmissionReceipt? {
        _ = try head(identity)
        let entries = try submissionEntries(identity)
        guard let latest = entries.last(where: { $0.receipt.control.kind == .rotation }) else { return nil }
        guard !entries.contains(where: {
            $0.receipt.control.kind == .revocation && $0.receipt.control.credentialID == latest.receipt.control.credentialID
        }) else { return nil }
        return latest.receipt
    }

    func pendingSubmission(operationID: Data, identity: GatewayRegistrationIdentity, active: Bool,
                           wall: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        try clock(now); _ = try head(identity)
        guard active else { throw GatewayAuthorityError.unavailableRegistration }
        guard try (16...18).contains(AuthorityJournalSchema.featureTier(on: db)) else { throw GatewayAuthorityError.unsupportedSubmissionControl }
        let entries = try submissionEntries(identity)
        guard let entry = entries.first(where: { $0.receipt.control.operationID == operationID }) else { return nil }
        let value = entry.receipt.control
        if value.kind == .rotation {
            guard try desiredSubmission(identity: identity)?.control.operationID == operationID else { throw GatewayAuthorityError.superseded }
        } else {
            guard entries.last(where: { $0.receipt.control.kind == .revocation && $0.receipt.control.credentialID == value.credentialID })?.receipt.control.operationID == operationID else {
                throw GatewayAuthorityError.superseded
            }
        }
        guard entry.run == uuid(run), entry.started <= now.milliseconds, now.milliseconds < entry.deadline,
              value.issuedAtUnixMillis <= wall, wall < value.expiresAtUnixMillis else { throw GatewayAuthorityError.expired }
        return entry.envelope
    }

    /// Renew only the retained current intent. Never use an arbitrary historical rotation to restore an older credential.
    func renewSubmission(operationID: Data, identity: GatewayRegistrationIdentity, active: Bool, expectedHead: UInt64,
                         wall: UInt64, now: AuthorityMoment, sign: (GatewaySubmissionControl) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try scope(identity); try clock(now); try requireHead(expectedHead, identity: identity)
        guard active else { throw GatewayAuthorityError.unavailableRegistration }
        let entries = try submissionEntries(identity)
        guard let previous = entries.first(where: { $0.receipt.control.operationID == operationID }) else { throw GatewayAuthorityError.unconfigured }
        let value = previous.receipt.control
        if value.kind == .rotation {
            guard try desiredSubmission(identity: identity)?.control.operationID == operationID, let key = value.publicKey else {
                throw GatewayAuthorityError.superseded
            }
            return try rotateSubmission(publicKey: key, identity: identity, active: active, expectedHead: expectedHead, wall: wall, now: now, sign: sign)
        }
        guard entries.last(where: { $0.receipt.control.kind == .revocation && $0.receipt.control.credentialID == value.credentialID })?.receipt.control.operationID == operationID else {
            throw GatewayAuthorityError.superseded
        }
        return try revokeSubmission(credentialID: value.credentialID, identity: identity, active: active,
            expectedHead: expectedHead, wall: wall, now: now, sign: sign)
    }

    private struct SubmissionEntry {
        let receipt: GatewaySubmissionReceipt
        let envelope: GatewayAuthorityEnvelope
        let run: Data
        let started: UInt64
        let deadline: UInt64
    }

    private func submissionEntry(_ operation: Data, identity: GatewayRegistrationIdentity) throws -> SubmissionEntry? {
        guard try AuthorityJournalSchema.featureTier(on: db) >= 16 else { return nil }
        return try statement("SELECT revision,kind,credential,payload,signature,run,started,deadline FROM main.gateway_submission_outbox_v1 WHERE operation=?", [operation]) { row in
            let rc = sqlite3_step(row)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW else { throw JournalDatabaseError.storage(rc) }
            let payload = try blob(row, 3, maximum: policy.payloadLimits.maxBytes), signature = try blob(row, 4, maximum: 64)
            let value: GatewaySubmissionControl
            do {
                value = try GatewaySubmissionVerifier.authenticate(canonicalPayload: payload, signature: signature, wireVersion: 1,
                    registration: identity, payloadLimits: policy.payloadLimits, signingLimits: policy.signingLimits)
            } catch { throw GatewayAuthorityError.corruptData }
            let started = try unsigned(blob(row, 6, maximum: 8)), deadline = try unsigned(blob(row, 7, maximum: 8))
            guard sqlite3_column_type(row, 1) == SQLITE_INTEGER, value.kind.rawValue == UInt64(exactly: sqlite3_column_int64(row, 1)),
                  value.operationID == operation, value.revision == (try unsigned(blob(row, 0, maximum: 8))),
                  value.credentialID == (try blob(row, 2, maximum: 16)), deadline > started,
                  deadline - started == value.expiresAtUnixMillis - value.issuedAtUnixMillis else { throw GatewayAuthorityError.corruptData }
            let receipt = GatewaySubmissionReceipt(control: value, canonicalPayload: payload, signature: signature)
            return SubmissionEntry(receipt: receipt, envelope: GatewayAuthorityEnvelope(kind: value.kind.rawValue,
                operationID: operation, revision: value.revision, canonicalPayload: payload, signature: signature, registrationToken: nil),
                run: try blob(row, 5, maximum: 16), started: started, deadline: deadline)
        }
    }

    private func submissionEntries(_ identity: GatewayRegistrationIdentity) throws -> [SubmissionEntry] {
        guard try AuthorityJournalSchema.featureTier(on: db) >= 16 else { return [] }
        let operations: [Data] = try statement("SELECT operation FROM main.gateway_submission_outbox_v1 ORDER BY revision", []) { row in
            var result: [Data] = []
            while true {
                let rc = sqlite3_step(row)
                if rc == SQLITE_DONE { return result }
                guard rc == SQLITE_ROW else { throw JournalDatabaseError.storage(rc) }
                guard result.count < policy.maximumControls else { throw GatewayAuthorityError.capacityExceeded }
                result.append(try blob(row, 0, maximum: 16))
            }
        }
        return try operations.map {
            guard let entry = try submissionEntry($0, identity: identity) else { throw GatewayAuthorityError.corruptData }
            return entry
        }
    }

    func submissionHistoryInstalled() throws -> Bool { try (16...18).contains(AuthorityJournalSchema.featureTier(on: db)) }

    private func submissionCountSQL() throws -> String {
        try AuthorityJournalSchema.featureTier(on: db) >= 16 ? "+(SELECT count(*) FROM main.gateway_submission_outbox_v1)" : ""
    }

    private func authenticate(phone: Data, epoch: Data, trust: GatewayAuthorityTrust) throws {
        try scope(trust.registration)
        guard trust.active, trust.enrollment.active else { throw GatewayAuthorityError.unavailableEnrollment }
        guard phone == trust.enrollment.phoneID, epoch == trust.enrollment.epoch else { throw GatewayAuthorityError.wrongScope }
        guard try !revoked(trust: trust), try !trustRestricted(phone: phone, identity: trust.registration) else { throw GatewayAuthorityError.unavailableEnrollment }
    }
    private func scope(_ identity: GatewayRegistrationIdentity) throws {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        guard identity.macID == mac, identity.accountID == account else { throw GatewayAuthorityError.wrongScope }
    }
    private func clock(_ now: AuthorityMoment) throws {
        guard now.epoch == policy.clockEpoch, lastMoment.map({ now.milliseconds >= $0 }) ?? true else { throw GatewayAuthorityError.invalidClock }
        lastMoment = now.milliseconds
    }
    private func requireHead(_ expected: UInt64, identity: GatewayRegistrationIdentity) throws {
        guard expected < UInt64.max, try head(identity) == expected else { throw GatewayAuthorityError.headMismatch }
    }
    private func advance(from: UInt64, to: UInt64) throws {
        try statement("UPDATE main.gateway_authority_v1 SET head=? WHERE id=1 AND head=?", [uint(to), uint(from)]) {
            try done($0); guard sqlite3_changes(db) == 1 else { throw GatewayAuthorityError.headMismatch }
        }
    }
    private func statement<T>(_ sql: String, _ values: [Data?], _ body: (OpaquePointer) throws -> T) throws -> T {
        var stmt: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard result == SQLITE_OK, let stmt else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(stmt) }
        for (index, value) in values.enumerated() {
            let result: Int32
            if let value { result = value.withUnsafeBytes { sqlite3_bind_blob(stmt, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) } }
            else { result = sqlite3_bind_null(stmt, Int32(index + 1)) }
            guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
        }
        return try body(stmt)
    }
    private func done(_ stmt: OpaquePointer) throws { guard sqlite3_step(stmt) == SQLITE_DONE else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) } }
    private func blob(_ stmt: OpaquePointer, _ index: Int32, maximum: Int) throws -> Data {
        let count = Int(sqlite3_column_bytes(stmt, index))
        guard sqlite3_column_type(stmt, index) == SQLITE_BLOB, count > 0, count <= maximum,
              let bytes = sqlite3_column_blob(stmt, index) else { throw GatewayAuthorityError.corruptData }
        return Data(bytes: bytes, count: count)
    }
    private func uint(_ value: UInt64) -> Data { withUnsafeBytes(of: value.bigEndian) { Data($0) } }
    private func unsigned(_ value: Data) throws -> UInt64 {
        guard value.count == 8 else { throw GatewayAuthorityError.corruptData }
        return value.reduce(0) { ($0 << 8) | UInt64($1) }
    }
    private func uuid(_ value: UUID) -> Data { var value = value.uuid; return withUnsafeBytes(of: &value) { Data($0) } }
}
