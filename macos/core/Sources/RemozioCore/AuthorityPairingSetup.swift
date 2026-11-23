import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Security

public enum AuthorityPairingSetupError: Error, Equatable {
    case invalidConfiguration, unavailable, policyChanged, wrongScope, unsupportedReplacement, invalidConfirmation
}

/// Root-private setup inputs. Provisioning supplies the existing transport pin; setup never discovers or replaces it.
public struct AuthorityPairingSetupConfiguration: Sendable, CustomStringConvertible {
    public let transportPublicKey: Data
    public let lifetimeMilliseconds: UInt64
    public let canonicalBytes: Data
    public var description: String { "AuthorityPairingSetupConfiguration(redacted)" }
    public init(transportPublicKey: Data, lifetimeMilliseconds: UInt64 = 120_000) throws {
        guard transportPublicKey.count == 65, transportPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: transportPublicKey)) != nil,
              (1...300_000).contains(lifetimeMilliseconds) else { throw AuthorityPairingSetupError.invalidConfiguration }
        self.transportPublicKey = transportPublicKey; self.lifetimeMilliseconds = lifetimeMilliseconds
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(transportPublicKey),
            2: .unsigned(lifetimeMilliseconds)]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...2),
              fields[0] == .unsigned(1), case .bytes(let key) = fields[1], case .unsigned(let lifetime) = fields[2] else {
            throw AuthorityPairingSetupError.invalidConfiguration
        }
        let result = try Self(transportPublicKey: key, lifetimeMilliseconds: lifetime)
        guard result.canonicalBytes == bytes else { throw AuthorityPairingSetupError.invalidConfiguration }; return result
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 512, maxDepth: 1, maxItems: 7) } }
}

/// Trusted local app access to the existing authority. It owns no database, key creation or network listener.
final class AuthorityPairingSetupAccess: Sendable {
    typealias Commit = @Sendable (PairingEnrollmentAttempt, Data, Data, () throws -> Void,
                                 @Sendable (JournalTransaction) throws -> Void) throws -> Data
    private let journal: AuthorityJournal
    let maintenanceAdmission: AuthorityMaintenancePairingAdmission
    private let macID: Data
    private let accountID: Data
    private let authorityPublicKey: Data
    private let configuration: AuthorityPairingSetupConfiguration
    private let minimumEnvelopeVersion: UInt64
    private let auditVersions: Set<UInt64>
    private let appEntry: AuthorityCodeEntry
    private let appRevision: UUID
    private let now: @Sendable () throws -> AuthorityMoment
    private let unixMilliseconds: @Sendable () throws -> UInt64
    private let random: @Sendable (Int) throws -> Data
    private let validateSelf: @Sendable (JournalTransaction) throws -> Void
    private let commitPairing: Commit
    private let gatewayRevocations: AuthorityGatewayRevocationState?

    convenience init(journal: AuthorityJournal, signer: EnclaveAuthorityRequestSigner, appPolicy: XPCPeerPolicy,
                     configuration: AuthorityPairingSetupConfiguration, minimumEnvelopeVersion: UInt64, auditVersions: Set<UInt64>,
                     now: @escaping @Sendable () throws -> AuthorityMoment,
                     gatewayRevocations: AuthorityGatewayRevocationState? = nil) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try self.init(journal: journal, macID: signer.macID, accountID: signer.accountID, authorityPublicKey: signer.publicKey,
            appPolicy: appPolicy, configuration: configuration, minimumEnvelopeVersion: minimumEnvelopeVersion, auditVersions: auditVersions, now: now,
            unixMilliseconds: {
                let value = Date().timeIntervalSince1970 * 1000
                guard value.isFinite, value >= 0, value < Double(UInt64.max) else { throw AuthorityPairingSetupError.unavailable }
                return UInt64(value)
            }, random: Self.secureRandom, validateSelf: AuthoritySelfValidation.validate,
            gatewayRevocations: gatewayRevocations, commit: { attempt, proof, event, authorize, validate in
                try journal.commitPairing(attempt, biometricProof: proof, signer: signer, addEventID: event,
                    receiptTimeMs: nil, recheckAdministrator: authorize, now: now, validateSetupCode: validate).receipt
            })
    }

    // Logical fixtures can inject software signing and code checks. Product construction requires the existing enclave signer.
    init(journal: AuthorityJournal, macID: Data, accountID: Data, authorityPublicKey: Data, appPolicy: XPCPeerPolicy,
         configuration: AuthorityPairingSetupConfiguration, minimumEnvelopeVersion: UInt64, auditVersions: Set<UInt64>,
         now: @escaping @Sendable () throws -> AuthorityMoment, unixMilliseconds: @escaping @Sendable () throws -> UInt64,
         random: @escaping @Sendable (Int) throws -> Data = AuthorityPairingSetupAccess.secureRandom,
         validateSelf: @escaping @Sendable (JournalTransaction) throws -> Void,
         gatewayRevocations: AuthorityGatewayRevocationState? = nil,
         commit: @escaping Commit) throws {
        guard macID.count == 16, accountID.count == 16, appPolicy.expectedUserID > 0, appPolicy.expectedUserID < UInt32.max,
              minimumEnvelopeVersion == 1, auditVersions.count <= 16, !auditVersions.contains(0), authorityPublicKey.count == 65,
              (try? P256.Signing.PublicKey(x963Representation: authorityPublicKey)) != nil,
              authorityPublicKey != configuration.transportPublicKey else { throw AuthorityPairingSetupError.invalidConfiguration }
        let retained = try journal.read { tx in
            try validateSelf(tx)
            let trust = try tx.approvalTrustSnapshot()
            guard trust.macID == macID, trust.accountID == accountID, let policy = try tx.codePolicy(),
                  let entry = policy.policy.entries.first(where: { $0.role == .app }), entry.active,
                  let revision = policy.roleRevisions[.app] else { throw AuthorityPairingSetupError.policyChanged }
            let current = try XPCPeerPolicy(teamID: entry.teamID, componentIdentifier: entry.identifier,
                approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: appPolicy.expectedUserID,
                expectedAuditSessionID: appPolicy.expectedAuditSessionID)
            guard current.requirement == appPolicy.requirement else { throw AuthorityPairingSetupError.policyChanged }
            return (entry, revision)
        }
        var incarnation = try now().epoch.uuid
        maintenanceAdmission = try .init(accountID: accountID, incarnation: withUnsafeBytes(of: &incarnation) { Data($0) })
        self.journal = journal; self.macID = macID; self.accountID = accountID; self.authorityPublicKey = authorityPublicKey
        self.configuration = configuration; self.minimumEnvelopeVersion = minimumEnvelopeVersion; self.auditVersions = auditVersions
        appEntry = retained.0; appRevision = retained.1
        self.now = now; self.unixMilliseconds = unixMilliseconds; self.random = random; self.validateSelf = validateSelf; self.commitPairing = commit
        self.gatewayRevocations = gatewayRevocations
    }

    func acquireReleaseActivity() throws -> ReleaseActivityToken? { try journal.acquireReleaseActivity() }
    func isExpired(_ attempt: PairingEnrollmentAttempt) throws -> Bool {
        try attempt.remainingMilliseconds(at: now()) == 0
    }

    func verifyCurrent() throws { try journal.read { try self.requireCurrent($0) } }
    func context() throws -> Data {
        try verifyCurrent()
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID),
            3: .bytes(authorityPublicKey), 4: .bytes(configuration.transportPublicKey),
            5: .unsigned(minimumEnvelopeVersion), 6: .unsigned(configuration.lifetimeMilliseconds)]),
            limits: .init(maxBytes: 512, maxDepth: 1, maxItems: 15))
    }

    /// The proposal supplies phone claims only. Root chooses fresh setup identity, challenge, tag, nonce and expiry.
    /// The app and phone must compare the returned transcript before producing the biometric proof.
    func stage(_ proposalBytes: Data) throws -> PairingEnrollmentAttempt {
        let proposal: PairingPhoneProposal
        if let legacy = try? PairingTranscript.decode(proposalBytes) {
            guard legacy.replacement == nil else { throw AuthorityPairingSetupError.unsupportedReplacement }
            proposal = try PairingPhoneProposal(phone: legacy.phone, transportKey: legacy.transportKey,
                decisionKey: legacy.decisionKey, biometricKey: legacy.biometricKey)
        } else {
            proposal = try PairingPhoneProposal.decode(proposalBytes)
            guard proposal.replacement != nil else { throw AuthorityPairingSetupError.unsupportedReplacement }
        }
        let scope = proposal.phone.scope
        guard scope.macID == macID, scope.accountID == accountID else { throw AuthorityPairingSetupError.wrongScope }
        let started = try now(), wall = try unixMilliseconds()
        let deadline = started.milliseconds.addingReportingOverflow(configuration.lifetimeMilliseconds)
        let expiry = wall.addingReportingOverflow(configuration.lifetimeMilliseconds)
        guard !deadline.overflow, !expiry.overflow else { throw AuthorityPairingSetupError.unavailable }
        return try journal.read { tx in
            try self.requireCurrent(tx)
            let trust = try tx.approvalTrustSnapshot()
            let requests = try trust.allowedContracts.sorted {
                ($0.requestKind.rawValue, $0.wireVersion, $0.schemaVersion) < ($1.requestKind.rawValue, $1.wireVersion, $1.schemaVersion)
            }.map { contract -> ChannelRequestCapability in
                let kind: UInt64
                switch contract.requestKind {
                case .command: kind = 0
                case .onePasswordAccess: kind = 1
                case .onePasswordUnlock: kind = 2
                case .littleSnitch: kind = 3
                }
                return try .init(kind: kind, wireVersion: contract.wireVersion, schemaVersion: contract.schemaVersion,
                    features: trust.authorityCapabilities.contracts[contract] ?? [])
            }
            let nonce = try self.random(32)
            guard nonce != proposal.phone.nonce else { throw AuthorityPairingSetupError.unavailable }
            let offer = try ChannelOffer(role: .mac, scope: scope, nonce: nonce, envelopeVersions: [1], requests: requests, auditVersions: self.auditVersions)
            var revision = trust.revision.uuid
            let transcript = try PairingTranscript(setupID: self.random(16), challenge: self.random(32), phone: proposal.phone, mac: offer,
                minimumEnvelopeVersion: self.minimumEnvelopeVersion, selectedEnvelopeVersion: CompatibilityPolicy.envelopeVersion(
                    local: [1], peer: proposal.phone.envelopeVersions, trustedMinimum: self.minimumEnvelopeVersion),
                macAuthorityKey: self.authorityPublicKey, macTransportKey: self.configuration.transportPublicKey,
                transportKey: proposal.transportKey, decisionKey: proposal.decisionKey, biometricKey: proposal.biometricKey,
                enrollmentTag: self.random(32), replacement: proposal.replacement, expectedTrustRevision: withUnsafeBytes(of: &revision) { Data($0) },
                issuedAtUnixMillis: wall, expiresAtUnixMillis: expiry.partialValue)
            let attempt = try PairingEnrollmentAttempt(transcript: transcript, trusted: trust,
                replacement: proposal.replacement.map(PairingEnrollmentAttempt.Replacement.requireRevoked) ?? .none,
                authorityPublicKey: self.authorityPublicKey, transportPublicKey: self.configuration.transportPublicKey,
                minimumEnvelopeVersion: self.minimumEnvelopeVersion, started: started, startedAtUnixMillis: wall,
                deadlineMilliseconds: deadline.partialValue)
            try attempt.validateEnrollmentHistory(tx)
            return attempt
        }
    }

    func commit(_ attempt: PairingEnrollmentAttempt, setupID: Data, confirmedDigest: Data, proof: Data,
                authorize: @escaping () throws -> Void) throws -> Data {
        guard setupID.count == 16, confirmedDigest.count == 32, proof.count == 64,
              setupID == attempt.transcript.setupID, try confirmedDigest == attempt.transcript.digest() else {
            throw AuthorityPairingSetupError.invalidConfirmation
        }
        return try commitPairing(attempt, proof, random(16), authorize, { tx in try self.requireCurrent(tx) })
    }
    func pairedPhones() throws -> PairedPhoneSnapshot {
        try journal.read { tx in
            try self.requireCurrent(tx)
            let trust = try tx.requestDeliveryTrust()
            let now = try self.now()
            let gateway = try tx.hasApprovalGateway()
            let availability: PairedPhoneRevocationAvailability = gateway
                ? self.gatewayRevocations?.availability(now: now) ?? .gatewayUnavailable : .available
            let inconclusiveSince = try tx.firstUnconfirmedGrantAbandonment()
            let liveHealth = self.gatewayRevocations?.health(trust.enrollments, now: now)
                ?? GatewayRevocationHealth.read(trust.enrollments, availability: availability)
            let health = inconclusiveSince != nil && (liveHealth == .clear || liveHealth == .pending)
                ? .grantAbandonmentInconclusive : liveHealth
            return PairedPhoneSnapshot(macID: self.macID, accountID: self.accountID, revision: trust.approval.revision,
                phones: trust.enrollments.filter { $0.approval.active }.map(DeliveryRecipient.init),
                revocationAvailability: availability, gatewayRevocationHealth: health,
                gatewayInconclusiveSinceUnixMillis: health == .grantAbandonmentInconclusive ? inconclusiveSince : nil)
        }
    }

    func revocationStatus(_ selection: PairedPhoneSelection) throws -> PhoneRevocationStatus {
        try requireSameScope(selection)
        do {
            return try journal.read { tx in
                try self.requireCurrent(tx)
                guard let row = try tx.approvalEnrollments().first(where: { DeliveryRecipient($0) == selection.phone }) else { return .unknown }
                if row.approval.active { return .active }
                if let intent = row.gatewayRevocation {
                    switch intent.progress {
                    case .applied: return .gatewayApplied
                    case .blocked: return .gatewayBlocked
                    case .pending:
                        if try self.gatewayRevocations?.availability(now: self.now()) == .gatewayUnsupported { return .gatewayUnsupported }
                        if let gateway = self.gatewayRevocations,
                           let receipt = try? tx.gatewayLocalRevocation(for: selection.phone, registration: intent.registration),
                           gateway.deliveryStatus(receipt.operationID) == .gatewayInconclusive { return .gatewayInconclusive }
                        return .gatewayPending
                    }
                }
                guard try tx.hasApprovalGateway() else { return .revokedOnMac }
                guard let gateway = self.gatewayRevocations,
                      let control = try tx.gatewayLocalRevocation(for: selection.phone, registration: gateway.registration) else { return .gatewayNotRequired }
                return gateway.deliveryStatus(control.operationID)
            }
        } catch GatewayAuthorityError.wrongScope { return .gatewayBlocked }
        catch GatewayAuthorityError.unconfigured { return .gatewayBlocked }
    }

    func revokePhone(_ selection: PairedPhoneSelection, authorize: () throws -> Void) throws -> PhoneRevocationStatus {
        try requireSameScope(selection)
        return try journal.revokePairedPhone(selection, eventID: random(16), recheckAdministrator: authorize,
            validateSetupCode: requireCurrent)
    }

    private func requireSameScope(_ selection: PairedPhoneSelection) throws {
        guard selection.macID == macID, selection.accountID == accountID else { throw AuthorityPairingSetupError.wrongScope }
    }

    private func requireCurrent(_ tx: JournalTransaction) throws {
        try validateSelf(tx)
        let trust = try tx.approvalTrustSnapshot()
        guard trust.macID == macID, trust.accountID == accountID, let policy = try tx.codePolicy(),
              policy.roleRevisions[.app] == appRevision, policy.policy.entries.first(where: { $0.role == .app }) == appEntry else {
            throw AuthorityPairingSetupError.policyChanged
        }
    }
    static func secureRandom(_ count: Int) throws -> Data {
        var result = Data(count: count)
        guard result.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }) == errSecSuccess else {
            throw AuthorityPairingSetupError.unavailable
        }
        return result
    }
}
