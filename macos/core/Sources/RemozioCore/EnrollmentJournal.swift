import CryptoKit
import Foundation
import RemozioProtocol
import SQLite3

public enum EnrollmentJournalError: Error, Equatable {
    case unconfigured, alreadyConfigured, invalidState, staleRevision, unavailableEnrollment, reusedIdentity, capacityExceeded, corruptData, gatewayRequired, recoveryRequired
}

enum GatewayRevocationProgress: UInt64, Codable, Sendable {
    case pending = 1, blocked = 2, applied = 3
}

struct GatewayRevocationIntent: Sendable {
    let registration: GatewayRegistrationIdentity
    let progress: GatewayRevocationProgress
}

/// Protected setup input. The host must verify administrator authorization and the phone enrollment proof first.
public struct StoredApprovalEnrollment: Sendable {
    public let epoch: Data
    public let notificationTag: Data
    public let identityPublicKey: Data
    public let approval: ApprovalEnrollment
    let gatewayRevocation: GatewayRevocationIntent?
    public init(epoch: Data, notificationTag: Data, identityPublicKey: Data, approval: ApprovalEnrollment) throws {
        try self.init(epoch: epoch, notificationTag: notificationTag, identityPublicKey: identityPublicKey,
            approval: approval, gatewayRevocation: nil)
    }
    fileprivate init(epoch: Data, notificationTag: Data, identityPublicKey: Data, approval: ApprovalEnrollment,
                     gatewayRevocation: GatewayRevocationIntent?) throws {
        guard epoch.count == 16, notificationTag.count == 32, approval.keys.count == 2,
              gatewayRevocation == nil || !approval.active,
              Set(approval.keys.map(\.keyClass)).count == 2,
              Set(approval.keys.map(\.publicKey)).count == 2,
              ([identityPublicKey] + approval.keys.map(\.publicKey)).allSatisfy({
                  $0.count == 65 && (try? P256.Signing.PublicKey(x963Representation: $0)) != nil
              }) else { throw EnrollmentJournalError.invalidState }
        try EnrollmentEncoding.validate(approval.capabilities)
        self.epoch = epoch; self.notificationTag = notificationTag; self.identityPublicKey = identityPublicKey; self.approval = approval; self.gatewayRevocation = gatewayRevocation
    }
}

/// Parameters for the root-local signer. No provider token or phone-supplied trust is accepted here.
public struct EnrollmentGatewayRemoval {
    public let registration: GatewayRegistrationIdentity
    public let expectedHead: UInt64
    public let nowUnixMillis: UInt64
    public let now: AuthorityMoment
    public let sign: (GatewayPhoneRevocation) throws -> Data
    public init(registration: GatewayRegistrationIdentity, expectedHead: UInt64, nowUnixMillis: UInt64,
                now: AuthorityMoment, sign: @escaping (GatewayPhoneRevocation) throws -> Data) {
        self.registration = registration; self.expectedHead = expectedHead; self.nowUnixMillis = nowUnixMillis
        self.now = now; self.sign = sign
    }
}

/// Database-only encoding. It is not an enrollment wire protocol or evidence of authentication.
private enum EnrollmentEncoding {
    struct Contract: Codable {
        let kind: String; let wire: UInt64; let schema: UInt64; let features: [UInt64]
    }
    struct Policy: Codable { let version: Int; let contracts: [Contract]; let allowed: [Contract] }
    struct Key: Codable { let id: Data; let kind: String; let publicKey: Data }
    struct Revocation: Codable {
        let registration: Data
        let progress: GatewayRevocationProgress
    }
    struct Phone: Codable {
        let version: Int; let phone: Data; let epoch: Data; let tag: Data; let identity: Data
        let contracts: [Contract]; let keys: [Key]
        let gatewayRevocation: Revocation?
    }
    static let maximumBytes = 32768
    static func validate(_ capabilities: ContractCapabilities) throws {
        guard !capabilities.contracts.isEmpty, capabilities.contracts.count <= 64,
              capabilities.contracts.values.allSatisfy({ $0.count <= 128 }) else { throw EnrollmentJournalError.invalidState }
    }
    static func contracts(_ capabilities: ContractCapabilities) -> [Contract] {
        capabilities.contracts.map { Contract(kind: $0.key.requestKind.rawValue, wire: $0.key.wireVersion,
            schema: $0.key.schemaVersion, features: $0.value.sorted()) }.sorted {
                ($0.kind, $0.wire, $0.schema) < ($1.kind, $1.wire, $1.schema)
            }
    }
    static func capabilities(_ values: [Contract]) throws -> ContractCapabilities {
        var result: [RequestContract: Set<UInt64>] = [:]
        guard values.count <= 64 else { throw EnrollmentJournalError.corruptData }
        for value in values {
            guard let kind = RequestKind(rawValue: value.kind), value.features.count <= 128,
                  Set(value.features).count == value.features.count else { throw EnrollmentJournalError.corruptData }
            let contract = try RequestContract(requestKind: kind, wireVersion: value.wire, schemaVersion: value.schema)
            guard result.updateValue(Set(value.features), forKey: contract) == nil else { throw EnrollmentJournalError.corruptData }
        }
        let capabilities = ContractCapabilities(contracts: result)
        try validate(capabilities)
        return capabilities
    }
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
        guard data.count <= maximumBytes else { throw EnrollmentJournalError.invalidState }
        return data
    }
    static func decode<T: Codable>(_ type: T.Type, _ data: Data) throws -> T {
        do {
            guard data.count <= maximumBytes else { throw EnrollmentJournalError.corruptData }
            let value = try JSONDecoder().decode(type, from: data)
            guard try encode(value) == data else { throw EnrollmentJournalError.corruptData }
            return value
        } catch { throw EnrollmentJournalError.corruptData }
    }
    static func encode(_ value: StoredApprovalEnrollment) throws -> Data {
        try encode(Phone(version: 1, phone: value.approval.phoneID, epoch: value.epoch, tag: value.notificationTag,
            identity: value.identityPublicKey, contracts: contracts(value.approval.capabilities), keys: value.approval.keys.map {
                Key(id: $0.id, kind: $0.keyClass.rawValue, publicKey: $0.publicKey)
            }.sorted { $0.id.lexicographicallyPrecedes($1.id) }, gatewayRevocation: try value.gatewayRevocation.map {
                Revocation(registration: try $0.registration.encode(), progress: $0.progress)
            }))
    }
    static func phone(_ data: Data, active: Bool) throws -> StoredApprovalEnrollment {
        do {
            let value = try decode(Phone.self, data)
            guard value.version == 1 else { throw EnrollmentJournalError.corruptData }
            return try StoredApprovalEnrollment(epoch: value.epoch, notificationTag: value.tag, identityPublicKey: value.identity,
                approval: ApprovalEnrollment(phoneID: value.phone, active: active, capabilities: capabilities(value.contracts), keys: value.keys.map {
                    guard let kind = ApprovalKeyClass(rawValue: $0.kind) else { throw EnrollmentJournalError.corruptData }
                    return try EnrolledApprovalKey(id: $0.id, keyClass: kind, publicKey: $0.publicKey)
                }), gatewayRevocation: try value.gatewayRevocation.map {
                    try GatewayRevocationIntent(registration: GatewayRegistrationIdentity.decode($0.registration), progress: $0.progress)
                })
        } catch { throw EnrollmentJournalError.corruptData }
    }
}

/// Private owner. Enrollment, revocation, decision consumption and audit writes share the journal transaction.
final class EnrollmentJournal {
    private let db: OpaquePointer
    private let mac: Data
    private let account: Data
    static let maximumRows = 1024
    init(connection: OpaquePointer, macID: Data, accountID: Data) { db = connection; mac = macID; account = accountID }

    static func createSchema(_ db: OpaquePointer) throws {
        let result = sqlite3_exec(db, """
            CREATE TABLE main.approval_authority_v1(id INTEGER PRIMARY KEY CHECK(id=1), policy BLOB NOT NULL,
                revision BLOB NOT NULL CHECK(length(revision)=16)) STRICT;
            CREATE TABLE main.approval_enrollments_v1(phone BLOB NOT NULL CHECK(length(phone)=16),
                epoch BLOB NOT NULL CHECK(length(epoch)=16), active INTEGER NOT NULL CHECK(active IN (0,1)),
                body BLOB NOT NULL, PRIMARY KEY(phone,epoch)) STRICT, WITHOUT ROWID;
            CREATE UNIQUE INDEX main.approval_current_phone_v1 ON approval_enrollments_v1(phone) WHERE active=1;
            """, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    static func createPairingSchema(_ db: OpaquePointer) throws {
        let result = sqlite3_exec(db, """
            CREATE TABLE main.pairing_commits_v1(setup BLOB PRIMARY KEY CHECK(length(setup)=16),
                phone BLOB NOT NULL CHECK(length(phone)=16), epoch BLOB NOT NULL CHECK(length(epoch)=16),
                transcript BLOB NOT NULL CHECK(length(transcript)<=132000),
                proof BLOB NOT NULL CHECK(length(proof)=64), UNIQUE(phone,epoch),
                FOREIGN KEY(phone,epoch) REFERENCES approval_enrollments_v1(phone,epoch)) STRICT, WITHOUT ROWID;
            """, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    func retainPairing(_ transcript: PairingTranscript, biometricProof: Data, enrollment: StoredApprovalEnrollment) throws {
        let body = try transcript.encode()
        try statement("INSERT INTO main.pairing_commits_v1 VALUES(?,?,?,?,?)",
            [transcript.setupID, enrollment.approval.phoneID, enrollment.epoch, body, biometricProof]) { try done($0) }
    }

    func committedPairing(setupID: Data, phoneID: Data, epoch: Data) throws -> PairingTranscript? {
        guard setupID.count == 16, phoneID.count == 16, epoch.count == 16 else { throw EnrollmentJournalError.invalidState }
        guard try !restrictedPhones().contains(phoneID),
              let enrollment = try all().first(where: { $0.approval.phoneID == phoneID && $0.epoch == epoch }),
              enrollment.approval.active else { return nil }
        return try pairing(enrollment, expectedSetupID: setupID)
    }

    private func pairing(_ enrollment: StoredApprovalEnrollment, expectedSetupID: Data? = nil) throws -> PairingTranscript? {
        try statement("SELECT setup,transcript,proof FROM main.pairing_commits_v1 WHERE phone=? AND epoch=?",
                      [enrollment.approval.phoneID, enrollment.epoch]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            do {
                let setupID = try blob($0, 0, maximum: 16)
                guard setupID.count == 16 else { throw EnrollmentJournalError.corruptData }
                if let expectedSetupID, expectedSetupID != setupID { return nil }
                let transcript = try PairingTranscript.decode(blob($0, 1, maximum: 132000))
                guard try transcript.verify(signature: blob($0, 2, maximum: 64),
                      publicKey: transcript.biometricKey.publicKey, purpose: .phoneBiometric),
                      transcript.setupID == setupID,
                      transcript.phone.scope == (try ChannelScope(macID: mac, accountID: account,
                          phoneID: enrollment.approval.phoneID, enrollmentEpoch: enrollment.epoch)),
                      transcript.transportKey.publicKey == enrollment.identityPublicKey,
                      transcript.enrollmentTag == enrollment.notificationTag,
                      try PairingEnrollmentAttempt.capabilities(transcript).contracts == enrollment.approval.capabilities.contracts,
                      enrollment.approval.keys.contains(where: { $0.keyClass == .decision && $0.id == transcript.decisionKey.keyID && $0.publicKey == transcript.decisionKey.publicKey }),
                      enrollment.approval.keys.contains(where: { $0.keyClass == .biometric && $0.id == transcript.biometricKey.keyID && $0.publicKey == transcript.biometricKey.publicKey }) else {
                    throw EnrollmentJournalError.corruptData
                }
                return transcript
            } catch { throw EnrollmentJournalError.corruptData }
        }
    }

    func directApprovalTrust(maximumPayloadBytes: Int, minimumEnvelopeVersion: UInt64,
                             auditVersions: Set<UInt64>) throws -> DirectApprovalTrust {
        let trust = try snapshot()
        let active = Set(trust.enrollments.map(\.phoneID))
        var peers: [DirectApprovalPeer] = []
        for enrollment in try all() where enrollment.approval.active && active.contains(enrollment.approval.phoneID) {
            let transcript = try pairing(enrollment)
            let requests = try trust.allowedContracts.compactMap { contract -> ChannelRequestCapability? in
                guard let local = trust.authorityCapabilities.contracts[contract],
                      let remote = enrollment.approval.capabilities.contracts[contract] else { return nil }
                let kind: UInt64
                switch contract.requestKind {
                case .command: kind = 0
                case .onePasswordAccess: kind = 1
                case .onePasswordUnlock: kind = 2
                case .littleSnitch: kind = 3
                }
                return try ChannelRequestCapability(kind: kind, wireVersion: contract.wireVersion,
                    schemaVersion: contract.schemaVersion, features: Set(local.intersection(remote).sorted().prefix(64)))
            }
            peers.append(try DirectApprovalPeer(scope: ChannelScope(macID: mac, accountID: account,
                phoneID: enrollment.approval.phoneID, enrollmentEpoch: enrollment.epoch),
                transportPublicKey: P256.Signing.PublicKey(x963Representation: enrollment.identityPublicKey).derRepresentation,
                requests: requests, auditVersions: auditVersions,
                minimumEnvelopeVersion: max(minimumEnvelopeVersion, transcript?.minimumEnvelopeVersion ?? 1),
                maximumPayloadBytes: maximumPayloadBytes))
        }
        if !peers.isEmpty { _ = try DirectPeerSnapshot(peers) }
        return DirectApprovalTrust(macID: mac, accountID: account, revision: trust.revision, peers: peers)
    }

    func requireDirectPeer(_ peer: DirectApprovalPeer, revision: UUID) throws {
        try requireDirectBinding(AuthorityPeerBinding(peer: peer, revision: revision))
    }
    func requireDirectBinding(_ peer: AuthorityPeerBinding) throws {
        let revision = peer.revision
        let trust = try snapshot()
        guard revision == trust.revision else { throw EnrollmentJournalError.staleRevision }
        guard peer.scope.macID == mac, peer.scope.accountID == account,
              trust.enrollments.contains(where: { $0.phoneID == peer.scope.phoneID }),
              let enrollment = try all().first(where: {
                  $0.approval.active && $0.approval.phoneID == peer.scope.phoneID && $0.epoch == peer.scope.enrollmentEpoch
              }),
              try P256.Signing.PublicKey(derRepresentation: peer.transportPublicKey).x963Representation == enrollment.identityPublicKey else {
            throw EnrollmentJournalError.unavailableEnrollment
        }
    }

    func configure(capabilities: ContractCapabilities, allowed: Set<RequestContract>) throws -> UUID {
        try EnrollmentEncoding.validate(capabilities)
        guard !allowed.isEmpty, allowed.isSubset(of: Set(capabilities.contracts.keys)) else { throw EnrollmentJournalError.invalidState }
        guard try scalar("SELECT count(*) FROM main.approval_authority_v1") == 0 else { throw EnrollmentJournalError.alreadyConfigured }
        guard try scalar("SELECT count(*) FROM main.approval_enrollments_v1") == 0 else { throw EnrollmentJournalError.corruptData }
        let policy = try EnrollmentEncoding.encode(EnrollmentEncoding.Policy(version: 1, contracts: EnrollmentEncoding.contracts(capabilities),
            allowed: EnrollmentEncoding.contracts(ContractCapabilities(contracts: Dictionary(uniqueKeysWithValues: allowed.map { ($0, Set<UInt64>()) })))))
        let revision = UUID()
        try statement("INSERT INTO main.approval_authority_v1 VALUES(1,?,?)", [policy, bytes(revision)]) { try done($0) }
        return revision
    }

    func snapshot() throws -> ApprovalTrustSnapshot {
        try statement("SELECT policy,revision FROM main.approval_authority_v1 WHERE id=1", []) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { throw EnrollmentJournalError.unconfigured }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let policy = try EnrollmentEncoding.decode(EnrollmentEncoding.Policy.self, blob($0, 0))
            let revision = try uuid(blob($0, 1))
            do {
                let capabilities = try EnrollmentEncoding.capabilities(policy.contracts)
                let allowed = Set(try EnrollmentEncoding.capabilities(policy.allowed).contracts.keys)
                guard policy.version == 1, policy.allowed.allSatisfy({ $0.features.isEmpty }),
                      allowed.isSubset(of: Set(capabilities.contracts.keys)) else { throw EnrollmentJournalError.corruptData }
                let restricted = try restrictedPhones()
                return try ApprovalTrustSnapshot(macID: mac, accountID: account, revision: revision,
                    authorityCapabilities: capabilities, allowedContracts: allowed, enrollments: all().filter { $0.approval.active && !restricted.contains($0.approval.phoneID) }.map(\.approval))
            } catch { throw EnrollmentJournalError.corruptData }
        }
    }

    func restrictedPhones() throws -> Set<Data> {
        try statement("SELECT phone FROM main.gateway_trust_restrictions_v1 LIMIT 1025", []) {
            var phones: Set<Data> = []
            while true {
                let result = sqlite3_step($0)
                if result == SQLITE_DONE { return phones }
                guard result == SQLITE_ROW, phones.count < Self.maximumRows else { throw EnrollmentJournalError.corruptData }
                let phone = try blob($0, 0)
                guard phone.count == 16, phones.insert(phone).inserted else { throw EnrollmentJournalError.corruptData }
            }
        }
    }
    func advanceForRestriction(expected: UUID) throws -> UUID { try require(expected); return try advance(expected) }

    func all() throws -> [StoredApprovalEnrollment] {
        try statement("SELECT phone,epoch,active,body FROM main.approval_enrollments_v1 ORDER BY phone,epoch LIMIT 1025", []) {
            var values: [StoredApprovalEnrollment] = []
            while true {
                let result = sqlite3_step($0)
                if result == SQLITE_DONE { return values }
                guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
                guard values.count < Self.maximumRows else { throw EnrollmentJournalError.corruptData }
                let active = sqlite3_column_int64($0, 2)
                guard active == 0 || active == 1 else { throw EnrollmentJournalError.corruptData }
                let value = try EnrollmentEncoding.phone(blob($0, 3), active: active == 1)
                guard try blob($0, 0) == value.approval.phoneID, try blob($0, 1) == value.epoch else { throw EnrollmentJournalError.corruptData }
                if let intent = value.gatewayRevocation {
                    guard intent.registration.macID == mac, intent.registration.accountID == account else {
                        throw EnrollmentJournalError.corruptData
                    }
                }
                values.append(value)
            }
        }
    }

    func add(_ enrollment: StoredApprovalEnrollment, expected: UUID) throws -> UUID {
        try require(expected)
        guard try !restrictedPhones().contains(enrollment.approval.phoneID) else { throw EnrollmentJournalError.recoveryRequired }
        guard enrollment.approval.active else { throw EnrollmentJournalError.invalidState }
        let previous = try all()
        guard previous.count < Self.maximumRows else { throw EnrollmentJournalError.capacityExceeded }
        for old in previous {
            guard !(old.approval.phoneID == enrollment.approval.phoneID && (old.approval.active || old.epoch == enrollment.epoch)),
                  old.epoch != enrollment.epoch,
                  Set(old.approval.keys.map(\.id)).isDisjoint(with: enrollment.approval.keys.map(\.id)),
                  Set(old.approval.keys.map(\.publicKey)).isDisjoint(with: enrollment.approval.keys.map(\.publicKey)) else {
                throw EnrollmentJournalError.reusedIdentity
            }
        }
        try statement("SELECT (SELECT count(*) FROM main.gateway_revocations_v1 WHERE phone=? AND enrollment=?)+(SELECT count(*) FROM main.gateway_recovered_revocations_v1 WHERE phone=? AND enrollment=?)", [enrollment.approval.phoneID, enrollment.epoch, enrollment.approval.phoneID, enrollment.epoch]) {
            guard sqlite3_step($0) == SQLITE_ROW, sqlite3_column_int64($0, 0) == 0 else { throw EnrollmentJournalError.reusedIdentity }
        }
        try statement("INSERT INTO main.approval_enrollments_v1 VALUES(?,?,1,?)",
            [enrollment.approval.phoneID, enrollment.epoch, try EnrollmentEncoding.encode(enrollment)]) { try done($0) }
        return try advance(expected)
    }

    func revoke(phone: Data, epoch: Data, expected: UUID,
                gatewayIntent: GatewayRegistrationIdentity? = nil) throws -> (StoredApprovalEnrollment, UUID) {
        try require(expected)
        guard let old = try all().first(where: { $0.approval.phoneID == phone && $0.epoch == epoch }), old.approval.active else {
            throw EnrollmentJournalError.unavailableEnrollment
        }
        let intent = gatewayIntent.map { GatewayRevocationIntent(registration: $0, progress: .pending) }
        let updated = try inactive(old, intent: intent)
        try statement("UPDATE main.approval_enrollments_v1 SET active=0,body=? WHERE phone=? AND epoch=? AND active=1",
                      [EnrollmentEncoding.encode(updated), phone, epoch]) {
            try done($0); guard sqlite3_changes(db) == 1 else { throw EnrollmentJournalError.staleRevision }
        }
        return (old, try advance(expected))
    }

    func gatewayRegistration() throws -> GatewayRegistrationIdentity? {
        try statement("SELECT identity FROM main.gateway_authority_v1 WHERE id=1", []) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let identity = try GatewayRegistrationIdentity.decode(blob($0, 0))
            guard identity.macID == mac, identity.accountID == account else { throw EnrollmentJournalError.corruptData }
            return identity
        }
    }

    func updateGatewayRevocation(_ phone: DeliveryRecipient, registration: GatewayRegistrationIdentity,
                                 progress: GatewayRevocationProgress) throws {
        guard let row = try all().first(where: { DeliveryRecipient($0) == phone }),
              row.gatewayRevocation?.registration == registration else { throw EnrollmentJournalError.unavailableEnrollment }
        guard row.gatewayRevocation?.progress != .applied, row.gatewayRevocation?.progress != progress else { return }
        let updated = try inactive(row, intent: GatewayRevocationIntent(registration: registration, progress: progress))
        try statement("UPDATE main.approval_enrollments_v1 SET body=? WHERE phone=? AND epoch=? AND active=0",
                      [EnrollmentEncoding.encode(updated), phone.phoneID, phone.enrollmentEpoch]) {
            try done($0); guard sqlite3_changes(db) == 1 else { throw EnrollmentJournalError.unavailableEnrollment }
        }
    }

    private func inactive(_ row: StoredApprovalEnrollment, intent: GatewayRevocationIntent?) throws -> StoredApprovalEnrollment {
        let approval = try ApprovalEnrollment(phoneID: row.approval.phoneID, active: false,
            capabilities: row.approval.capabilities, keys: row.approval.keys)
        return try StoredApprovalEnrollment(epoch: row.epoch, notificationTag: row.notificationTag,
            identityPublicKey: row.identityPublicKey, approval: approval, gatewayRevocation: intent)
    }
    func restrictRecovered(phone: Data, epoch: Data, expected: UUID, evidenceChanged: Bool) throws -> UUID {
        try require(expected)
        try statement("UPDATE main.approval_enrollments_v1 SET active=0 WHERE phone=? AND epoch=? AND active=1", [phone, epoch]) { try done($0) }
        let changed = sqlite3_changes(db) != 0
        return changed || evidenceChanged ? try advance(expected) : expected
    }
    func hasGateway() throws -> Bool { try scalar("SELECT count(*) FROM main.gateway_authority_v1") != 0 }
    private func require(_ revision: UUID) throws {
        guard try snapshot().revision == revision else { throw EnrollmentJournalError.staleRevision }
    }
    private func advance(_ expected: UUID) throws -> UUID {
        let next = UUID()
        try statement("UPDATE main.approval_authority_v1 SET revision=? WHERE id=1 AND revision=?", [bytes(next), bytes(expected)]) {
            try done($0); guard sqlite3_changes(db) == 1 else { throw EnrollmentJournalError.staleRevision }
        }
        return next
    }
    private func scalar(_ sql: String) throws -> Int64 {
        try statement(sql, []) { guard sqlite3_step($0) == SQLITE_ROW else { throw EnrollmentJournalError.corruptData }; return sqlite3_column_int64($0, 0) }
    }
    private func statement<T>(_ sql: String, _ values: [Data], _ body: (OpaquePointer) throws -> T) throws -> T {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        var value: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &value, nil)
        guard result == SQLITE_OK, let value else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(value) }
        for (index, data) in values.enumerated() {
            let bound = data.withUnsafeBytes { sqlite3_bind_blob(value, Int32(index + 1), $0.baseAddress, Int32(data.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
            guard bound == SQLITE_OK else { throw JournalDatabaseError.storage(bound) }
        }
        return try body(value)
    }
    private func done(_ stmt: OpaquePointer) throws { guard sqlite3_step(stmt) == SQLITE_DONE else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) } }
    private func blob(_ stmt: OpaquePointer, _ index: Int32, maximum: Int = EnrollmentEncoding.maximumBytes) throws -> Data {
        let count = Int(sqlite3_column_bytes(stmt, index))
        guard sqlite3_column_type(stmt, index) == SQLITE_BLOB, count > 0, count <= maximum,
              let pointer = sqlite3_column_blob(stmt, index) else { throw EnrollmentJournalError.corruptData }
        return Data(bytes: pointer, count: count)
    }
    private func bytes(_ value: UUID) -> Data { var value = value.uuid; return withUnsafeBytes(of: &value) { Data($0) } }
    private func uuid(_ data: Data) throws -> UUID {
        guard data.count == 16 else { throw EnrollmentJournalError.corruptData }
        return data.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
    }
}
