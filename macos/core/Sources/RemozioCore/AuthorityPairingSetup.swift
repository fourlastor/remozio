import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Security
import Synchronization

public enum AuthorityPairingSetupError: Error, Equatable {
    case invalidConfiguration, unavailable, policyChanged, wrongScope, unsupportedReplacement, invalidConfirmation
}

/// Root-private setup inputs. Provisioning supplies the existing transport pin; setup never discovers or replaces it.
public struct AuthorityPairingSetupConfiguration: Sendable, CustomStringConvertible {
    static let maximumLifetimeMilliseconds: UInt64 = 300_000
    public let transportPublicKey: Data
    public let lifetimeMilliseconds: UInt64
    public let v2ActivationEnabled: Bool?
    public let lanScope: PairingLANScope?
    public let canonicalBytes: Data
    public var description: String { "AuthorityPairingSetupConfiguration(redacted)" }
    public init(transportPublicKey: Data, lifetimeMilliseconds: UInt64 = 120_000,
                v2ActivationEnabled: Bool? = nil, lanScope: PairingLANScope? = nil) throws {
        guard transportPublicKey.count == 65, transportPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: transportPublicKey)) != nil,
              (1...Self.maximumLifetimeMilliseconds).contains(lifetimeMilliseconds),
              lanScope == nil || v2ActivationEnabled == true else { throw AuthorityPairingSetupError.invalidConfiguration }
        self.transportPublicKey = transportPublicKey; self.lifetimeMilliseconds = lifetimeMilliseconds
        self.v2ActivationEnabled = v2ActivationEnabled; self.lanScope = lanScope
        let version: UInt64 = lanScope != nil ? 3 : v2ActivationEnabled == nil ? 1 : 2
        var fields: [UInt64: CBORValue] = [0: .unsigned(version), 1: .bytes(transportPublicKey), 2: .unsigned(lifetimeMilliseconds)]
        if let v2ActivationEnabled { fields[3] = .boolean(v2ActivationEnabled) }
        if let lanScope { fields[4] = lanScope.cborValue }
        canonicalBytes = try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              case .bytes(let key) = fields[1], case .unsigned(let lifetime) = fields[2] else {
            throw AuthorityPairingSetupError.invalidConfiguration
        }
        let activation: Bool?
        let lanScope: PairingLANScope?
        switch fields[0] {
        case .unsigned(1) where Set(fields.keys) == Set(UInt64(0)...2):
            activation = nil; lanScope = nil
        case .unsigned(2) where Set(fields.keys) == Set(UInt64(0)...3):
            guard case .boolean(let flag) = fields[3] else { throw AuthorityPairingSetupError.invalidConfiguration }
            activation = flag; lanScope = nil
        case .unsigned(3) where Set(fields.keys) == Set(UInt64(0)...4):
            guard fields[3] == .boolean(true), let scope = fields[4] else { throw AuthorityPairingSetupError.invalidConfiguration }
            activation = true; lanScope = try PairingLANScope.decode(scope)
        default:
            throw AuthorityPairingSetupError.invalidConfiguration
        }
        let result = try Self(transportPublicKey: key, lifetimeMilliseconds: lifetime, v2ActivationEnabled: activation, lanScope: lanScope)
        guard result.canonicalBytes == bytes else { throw AuthorityPairingSetupError.invalidConfiguration }; return result
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 512, maxDepth: 2, maxItems: 13) } }
}

/// Trusted local app access to the existing authority. It owns no database, key creation or network listener.
final class AuthorityPairingSetupAccess: Sendable {
    typealias Commit = @Sendable (PairingEnrollmentAttempt, Data, Data, () throws -> Void,
                                 @Sendable (JournalTransaction) throws -> Void) throws -> Data
    enum PairingVersion: Equatable { case legacy, v2 }
    enum LegacyAdmissionError: Error { case disabled }
    enum V2ActivationResult: Equatable { case draining, active }

    struct V2ActivationRevision: Equatable, Sendable {
        let authorityEpoch: UUID
        let configurationDigest: Data
    }

    private struct PairingAdmissionState {
        enum Mode { case compatibility, draining, v2 }
        var mode: Mode
        var leases: [UUID: PairingVersion] = [:]
    }

    final class VersionAdmission: Sendable {
        private let access: AuthorityPairingSetupAccess
        private let id: UUID
        fileprivate init(access: AuthorityPairingSetupAccess, id: UUID) {
            self.access = access
            self.id = id
        }
        deinit { _ = access.pairingVersions.withLock { $0.leases.removeValue(forKey: id) } }
    }

    private let pairingVersions: Mutex<PairingAdmissionState>
    let activationRevision: V2ActivationRevision
    private let pairingWindowOwner = UUID()
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
        let epoch = try now().epoch
        var incarnation = epoch.uuid
        maintenanceAdmission = try .init(accountID: accountID, incarnation: withUnsafeBytes(of: &incarnation) { Data($0) })
        activationRevision = .init(authorityEpoch: epoch, configurationDigest: Data(SHA256.hash(data: configuration.canonicalBytes)))
        // Restore the admission closure before any endpoint can open. A new owner must promote explicitly.
        pairingVersions = Mutex(.init(mode: configuration.v2ActivationEnabled == true ? .draining : .compatibility))
        self.journal = journal; self.macID = macID; self.accountID = accountID; self.authorityPublicKey = authorityPublicKey
        self.configuration = configuration; self.minimumEnvelopeVersion = minimumEnvelopeVersion; self.auditVersions = auditVersions
        appEntry = retained.0; appRevision = retained.1
        self.now = now; self.unixMilliseconds = unixMilliseconds; self.random = random; self.validateSelf = validateSelf; self.commitPairing = commit
        self.gatewayRevocations = gatewayRevocations
    }

    var requiresInstalledV2: Bool { configuration.v2ActivationEnabled == true }
    var lanScope: PairingLANScope? { configuration.lanScope }

    /// Endpoints retain the admission through the attempt and its in-flight replies.
    func admitPairingVersion(_ version: PairingVersion) throws -> VersionAdmission {
        try pairingVersions.withLock { state in
            switch state.mode {
            case .compatibility:
                guard state.leases.values.allSatisfy({ $0 == version }) else { throw AuthorityPairingSetupError.unavailable }
            case .draining:
                if version == .legacy { throw LegacyAdmissionError.disabled }
                throw AuthorityPairingSetupError.unavailable
            case .v2:
                guard version == .v2 else { throw LegacyAdmissionError.disabled }
            }
            let id = UUID()
            state.leases[id] = version
            return VersionAdmission(access: self, id: id)
        }
    }

    /// The protected owner retries only when its installed v2 composition is ready.
    func requestV2Activation(revision: V2ActivationRevision, compositionReady: Bool) throws -> V2ActivationResult {
        guard revision == activationRevision else { throw AuthorityPairingSetupError.policyChanged }
        guard configuration.v2ActivationEnabled == true, compositionReady else {
            throw AuthorityPairingSetupError.unavailable
        }
        try verifyCurrent()
        return try pairingVersions.withLock { state in
            switch state.mode {
            case .compatibility:
                throw AuthorityPairingSetupError.unavailable
            case .draining:
                guard state.leases.isEmpty else { return .draining }
                state.mode = .v2
                return .active
            case .v2:
                return .active
            }
        }
    }

    func acquireReleaseActivity() throws -> ReleaseActivityToken? { try journal.acquireReleaseActivity() }
    func isExpired(_ attempt: PairingEnrollmentAttempt) throws -> Bool {
        if attempt.recoveryProposalDigest != nil {
            let activity = try journal.acquireReleaseActivity()
            defer { activity?.close() }
            return try journal.expireRePair(attempt, now: now)
        }
        return try attempt.remainingMilliseconds(at: now()) == 0
    }

    func verifyCurrent() throws { try journal.read { try self.requireCurrent($0) } }
    func context() throws -> Data {
        try verifyCurrent()
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID),
            3: .bytes(authorityPublicKey), 4: .bytes(configuration.transportPublicKey),
            5: .unsigned(minimumEnvelopeVersion), 6: .unsigned(configuration.lifetimeMilliseconds)]),
            limits: .init(maxBytes: 512, maxDepth: 1, maxItems: 15))
    }

    func openV2Window(label: String, predecessor: PairedPhoneSelection?) throws -> AuthorityPairingV2Window {
        try verifyCurrent()
        if let predecessor, try !canRePair(predecessor) { throw AuthorityPairingSetupError.unsupportedReplacement }
        let invitation = try PairingInvitation(macID: macID, accountID: accountID, label: label,
            authorityPublicKey: authorityPublicKey, transportPublicKey: configuration.transportPublicKey,
            minimumEnvelopeVersion: minimumEnvelopeVersion)
        let started = try now()
        let v2 = try PairingInvitationV2(invitation: invitation, windowID: random(16), secret: random(32),
            replacement: predecessor?.predecessor, lifetimeMilliseconds: configuration.lifetimeMilliseconds)
        return try AuthorityPairingV2Window(invitation: v2, predecessor: predecessor, started: started,
                                            authorityOwner: pairingWindowOwner)
    }

    /// Bind the proof connection only to a window created by this Authority owner.
    func proofReservations(for window: AuthorityPairingV2Window,
                           link: AuthorityPairingProofLink) throws -> AuthorityPairingProofReservations {
        try .init(window: window, authorityOwner: pairingWindowOwner, link: link, now: now,
                  makeChallenge: { [random] in try random(32) },
                         verifyWindow: { [self] in try verifyV2Window(window) })
    }

    private func verifyV2Window(_ window: AuthorityPairingV2Window) throws {
        try verifyCurrent()
        if let predecessor = window.predecessor, try !canRePair(predecessor) {
            throw AuthorityPairingSetupError.unsupportedReplacement
        }
    }

    func expireV2WindowIfDue(_ window: AuthorityPairingV2Window) throws {
        try window.expireIfDue(now())
    }

    func exportV2Window(_ window: AuthorityPairingV2Window) throws -> Data {
        try window.export(at: now()).encode()
    }

    func reserveV2(_ window: AuthorityPairingV2Window, proof: PairingSetupV2Proof) throws {
        try verifyV2Window(window)
        try window.reserve(proof, at: now())
    }

    func stageV2(_ window: AuthorityPairingV2Window, connection: UUID, proposalBytes: Data,
                 authorize: () throws -> Void) throws -> PairingEnrollmentAttempt {
        let proposal = try window.takeProposal(connection: connection, matching: proposalBytes, at: now())
        return try stage(proposal, proposalBytes: proposalBytes, window: window, authorize: authorize)
    }

    /// The proposal supplies phone claims only. Root chooses fresh setup identity, challenge, tag, nonce and expiry.
    /// The app and phone must compare the returned transcript before producing the biometric proof.
    func stage(_ proposalBytes: Data, authorize: () throws -> Void = {}) throws -> PairingEnrollmentAttempt {
        try stage(Self.decodeLegacyProposal(proposalBytes), proposalBytes: proposalBytes, window: nil, authorize: authorize)
    }

    static func decodeLegacyProposal(_ proposalBytes: Data) throws -> PairingPhoneProposal {
        if let legacy = try? PairingTranscript.decode(proposalBytes) {
            guard legacy.replacement == nil else { throw AuthorityPairingSetupError.unsupportedReplacement }
            return try PairingPhoneProposal(phone: legacy.phone, transportKey: legacy.transportKey,
                decisionKey: legacy.decisionKey, biometricKey: legacy.biometricKey)
        }
        let proposal = try PairingPhoneProposal.decode(proposalBytes)
        guard proposal.replacement != nil else { throw AuthorityPairingSetupError.unsupportedReplacement }
        return proposal
    }

    private func stage(_ proposal: PairingPhoneProposal, proposalBytes: Data, window: AuthorityPairingV2Window?,
                       authorize: () throws -> Void) throws -> PairingEnrollmentAttempt {
        let scope = proposal.phone.scope
        guard scope.macID == macID, scope.accountID == accountID else { throw AuthorityPairingSetupError.wrongScope }
        let proposalDigest = proposal.replacement.map { _ in Data(SHA256.hash(data: proposalBytes)) }
        let prepare: @Sendable (JournalTransaction, AuthorityMoment, PairingRecoveryStage?) throws -> PairingEnrollmentAttempt = { tx, started, retained in
            try self.requireCurrent(tx)
            let trust = try tx.approvalTrustSnapshot()
            try window?.validateTransport(tx)
            try window?.requireStaging(self.now())
            if let predecessor = window?.predecessor, trust.revision != predecessor.revision {
                throw AuthorityPairingSetupError.unsupportedReplacement
            }
            let replacement = proposal.replacement.map(PairingEnrollmentAttempt.Replacement.requireRevoked) ?? .none
            if let retained {
                try proposal.validate(retained.transcript)
                let attempt = try PairingEnrollmentAttempt(transcript: retained.transcript, trusted: trust, replacement: replacement,
                    authorityPublicKey: self.authorityPublicKey, transportPublicKey: self.configuration.transportPublicKey,
                    minimumEnvelopeVersion: self.minimumEnvelopeVersion,
                    started: .init(epoch: retained.incarnation, milliseconds: retained.started),
                    startedAtUnixMillis: retained.transcript.issuedAtUnixMillis, deadlineMilliseconds: retained.deadline,
                    recoveryProposalDigest: proposalDigest)
                try attempt.validateEnrollmentHistory(tx)
                if let window {
                    try window.publicInvitation.validateMacClaims(in: retained.transcript)
                    try window.requireStaging(self.now())
                }
                return attempt
            }
            let wall = try self.unixMilliseconds()
            let deadline = started.milliseconds.addingReportingOverflow(self.configuration.lifetimeMilliseconds)
            let expiry = wall.addingReportingOverflow(self.configuration.lifetimeMilliseconds)
            guard !deadline.overflow, !expiry.overflow else { throw AuthorityPairingSetupError.unavailable }
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
            if let window {
                try proposal.validate(transcript)
                try window.publicInvitation.validateMacClaims(in: transcript)
                try window.requireStaging(self.now())
            }
            let attempt = try PairingEnrollmentAttempt(transcript: transcript, trusted: trust, replacement: replacement,
                authorityPublicKey: self.authorityPublicKey, transportPublicKey: self.configuration.transportPublicKey,
                minimumEnvelopeVersion: self.minimumEnvelopeVersion, started: started, startedAtUnixMillis: wall,
                deadlineMilliseconds: deadline.partialValue, recoveryProposalDigest: proposalDigest)
            try attempt.validateEnrollmentHistory(tx)
            return attempt
        }
        if let proposalDigest {
            return try journal.stageRePair(phoneID: scope.phoneID, proposalDigest: proposalDigest,
                                          now: now, authorize: authorize, prepare: prepare)
        }
        let started = try now()
        return try journal.read { try prepare($0, started, nil) }
    }

    func commit(_ attempt: PairingEnrollmentAttempt, setupID: Data, confirmedDigest: Data, proof: Data,
                window: AuthorityPairingV2Window? = nil, authorize: @escaping () throws -> Void) throws -> Data {
        guard setupID.count == 16, confirmedDigest.count == 32, proof.count == 64,
              setupID == attempt.transcript.setupID, try confirmedDigest == attempt.transcript.digest() else {
            throw AuthorityPairingSetupError.invalidConfirmation
        }
        return try commitPairing(attempt, proof, random(16), {
            try authorize()
            try window?.requireStaging(self.now())
        }, { tx in
            try self.requireCurrent(tx)
            try window?.validateTransport(tx)
            try window?.requireStaging(self.now())
        })
    }
    func pairedPhones(includeRePair: Bool = false) throws -> PairedPhoneSnapshot {
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
            let rePairable = try includeRePair ? tx.rePairPredecessors(in: trust.enrollments) : []
            return PairedPhoneSnapshot(macID: self.macID, accountID: self.accountID, revision: trust.approval.revision,
                phones: trust.enrollments.filter { $0.approval.active }.map(DeliveryRecipient.init),
                rePairablePhones: rePairable,
                revocationAvailability: availability, gatewayRevocationHealth: health,
                gatewayInconclusiveSinceUnixMillis: health == .grantAbandonmentInconclusive ? inconclusiveSince : nil)
        }
    }

    func canRePair(_ selection: PairedPhoneSelection) throws -> Bool {
        try requireSameScope(selection)
        return try journal.read { tx in
            try self.requireCurrent(tx)
            let trust = try tx.requestDeliveryTrust()
            guard selection.revision == trust.approval.revision else { return false }
            let samePhone = trust.enrollments.filter { $0.approval.phoneID == selection.phone.phoneID }
            return try tx.rePairPredecessors(in: samePhone).contains(selection.phone)
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

    func expiredRePairs() throws -> ExpiredRePairSnapshot {
        try journal.read { tx in
            try self.requireCurrent(tx)
            let records = try tx.expiredRePairStages().map { stage in
                let scope = stage.transcript.phone.scope
                guard scope.macID == macID, scope.accountID == accountID, let reason = stage.state.expiryReason else {
                    throw AuthorityPairingSetupError.wrongScope
                }
                return ExpiredRePairRecord(macID: macID, accountID: accountID, phoneID: scope.phoneID,
                    originalExpiryUnixMilliseconds: stage.transcript.expiresAtUnixMillis, reason: reason,
                    setupID: stage.transcript.setupID, transcriptDigest: stage.transcriptDigest)
            }
            return ExpiredRePairSnapshot(macID: macID, accountID: accountID, records: records)
        }
    }

    func discardExpiredRePair(setupID: Data, digest: Data, authorize: () throws -> Void) throws {
        guard setupID.count == 16, digest.count == 32 else { throw AuthorityPairingSetupError.invalidConfirmation }
        try journal.discardExpiredRePair(setupID: setupID, digest: digest, verifyHost: requireCurrent, authorize: authorize)
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
