import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class UpdateSchedulingAccountFixture {
    enum UpdateOwner: Equatable { case currentAccount, otherAccount, undesignated, absentRegistration }
    private enum Fault: Error { case injected }
    let root: URL
    let machine: UpdateCandidateStorageFixture
    private var offeredMarker: UInt8?
    var macID: Data { machine.mac }
    var accountID: Data { machine.account }
    let epoch = Data(repeating: 3, count: 16)
    let clock = UUID()
    let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
    let decision = P256.Signing.PrivateKey(), identity = P256.Signing.PrivateKey(), biometric = P256.Signing.PrivateKey()
    let rootKey = P256.Signing.PrivateKey()
    let maximum: Int
    let enabled: Bool
    let gatewayEnabled: Bool
    private var tick: UInt64 = 100
    var db: JournalDatabase!
    var store: ContinuityStore!
    var writer: AuditEpochWriter!
    var commits: CheckpointedJournal!
    func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    func now(_ n: UInt64 = 100) -> AuthorityMoment { .init(epoch: clock, milliseconds: n) }
    func nextNow() -> AuthorityMoment { tick += 1; return now(tick) }
    var gateway: GatewayRegistrationIdentity {
        get throws { try .init(ownerID: id(20), macID: macID, accountID: accountID, gatewayID: id(21),
            lifecycleEpoch: id(22), rootPublicKey: rootKey.publicKey.x963Representation) }
    }
    init(prepare: Bool = true, maximum: Int = 20, enabled: Bool = true,
         gatewayEnabled: Bool = true, submissionHistory: Bool = true, updateOwner: UpdateOwner = .currentAccount) throws {
        self.maximum = maximum; self.enabled = enabled; self.gatewayEnabled = gatewayEnabled
        machine = try UpdateCandidateStorageFixture(admission: true)
        if updateOwner != .absentRegistration {
            let admission = try BoundAdmissionRegistrationFixture(machine: machine)
            switch updateOwner {
            case .currentAccount: _ = try admission.prepare(ownerSelection: .designate(machine.account))
            case .undesignated: _ = try admission.prepare()
            case .otherAccount:
                let first = try admission.prepare(), other = Data(repeating: 96, count: 16)
                try admission.addAccount(other)
                _ = try admission.prepare(accountID: other, replacing: first, ownerSelection: .designate(other))
            case .absentRegistration: break
            }
        }
        guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Fault.injected }
        defer { free(canonical) }
        root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        for name in ["journal", "continuity"] {
            let path = root.appendingPathComponent(name)
            try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for file in ["writer.lock", "\(name).sqlite"] {
                let fd = Darwin.open(path.appendingPathComponent(file).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Fault.injected }; Darwin.close(fd)
            }
        }
        db = try open(initialize: true)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(epoch), 4: .unsigned(1),
            5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        writer = try db.write { try $0.createEpoch(descriptor) }
        try db.write { tx in
            let configured = try tx.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract])
            let enrollment = try StoredApprovalEnrollment(epoch: id(4), notificationTag: id(5, count: 32),
                identityPublicKey: identity.publicKey.x963Representation,
                approval: ApprovalEnrollment(phoneID: id(6), active: true, capabilities: capabilities, keys: [
                    EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: decision.publicKey.x963Representation),
                    EnrolledApprovalKey(id: id(8), keyClass: .biometric, publicKey: biometric.publicKey.x963Representation),
                ]))
            _ = try tx.addApprovalEnrollment(enrollment, expectedTrustRevision: configured, eventID: id(9),
                receiptTimeMs: 1000, writer: writer, expectedAuditHead: 0)
            if gatewayEnabled { try tx.configureGatewayAuthority(gateway) }
            if prepare {
                _ = try tx.installCodePolicy(AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .authority,
                    teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority", installedGeneration: 1, minimumGeneration: 1,
                    codeDirectoryHash: id(10, count: 20), active: true)]), expectedRevision: nil)
                try tx.installCommandSubmissionReplay()
                if gatewayEnabled && submissionHistory { try tx.installGatewaySubmissionHistory(gateway) }
            }
        }
        let initial = try db.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: epoch, generation: 1) }
        store = try openStore(initial: initial)
        commits = CheckpointedJournal(journal: db, continuity: store)
    }
    deinit { try? db?.close(); store?.close(); try? FileManager.default.removeItem(at: root) }
    private func open(initialize: Bool = false, schedulingEnabled: Bool? = nil) throws -> JournalDatabase {
        try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: getuid()),
            macID: macID, accountID: accountID, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 20, busyMilliseconds: 100, initialize: initialize,
            gatewayPolicy: gatewayEnabled ? GatewayAuthorityPolicy(payloadLimits: limits, signingLimits: limits, maximumControls: 20,
                candidateLifetimeMillis: 1000, clockEpoch: clock) : nil,
            updateSchedulingPolicy: (schedulingEnabled ?? enabled) ? UpdateSchedulingJournalPolicy(clockEpoch: clock, challengeLifetimeMillis: 1000,
                maximumOperations: maximum, payloadLimits: limits, signingLimits: limits) : nil)
    }
    private func openStore(initial: ContinuityCheckpoint? = nil) throws -> ContinuityStore {
        try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
            macID: macID, accountID: accountID, initialize: initial)
    }
    func reopen(schedulingEnabled: Bool? = nil) throws {
        try db.close(); store.close(); db = try open(schedulingEnabled: schedulingEnabled); store = try openStore()
        commits = CheckpointedJournal(journal: db, continuity: store)
    }
    func install() throws { try commits.write(epoch: epoch, recoverRejectedBody: true) { try $0.installUpdateSchedulingStorage() } }
    func restoreCandidateForFault(_ record: UpdateSchedulingCandidateRecord) throws {
        func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
        var generation = record.generation.bigEndian
        var revision = record.revision.uuid
        let generationBytes = withUnsafeBytes(of: &generation) { Data($0) }
        let revisionBytes = withUnsafeBytes(of: &revision) { Data($0) }
        try machine.sql("UPDATE update_scheduling_candidate_v1 SET generation=x'\(hex(generationBytes))',revision=x'\(hex(revisionBytes))',record=x'\(try hex(record.encoded))' WHERE id=1")
    }
    func withCandidate<Value: Sendable>(_ body: (LiveUpdateSchedulingCandidate) throws -> Value) throws -> Value {
        let selected = try XCTUnwrap(machine.store.updateCandidate())
        return try machine.withLiveCandidate(selected, body)
    }
    func retainCurrent(expected: UpdateSchedulingSnapshot? = nil) throws -> UpdateSchedulingIntent {
        try withCandidate { candidate in
            try commits.write(epoch: epoch, recoverRejectedBody: true) {
                try $0.retainUpdateSchedulingOffer(candidate: candidate, expected: expected)
            }
        }
    }
    func offer(update: UInt8 = 30, expected: UpdateSchedulingSnapshot? = nil) throws -> UpdateSchedulingIntent {
        let current = try machine.store.updateCandidate()
        if offeredMarker != update || current?.selected != true {
            let signed = try SignedReleaseEvidence(manifest: .init(release: "0.1.\(update)",
                build: machine.release.manifest.build, components: machine.release.manifest.components),
                codeDirectoryHashes: Dictionary(uniqueKeysWithValues: machine.policy.entries.filter(\.active).map { ($0.role, $0.codeDirectoryHash) }))
            _ = try machine.select(machine.copy(release: signed), replacing: current)
            offeredMarker = update
        }
        return try retainCurrent(expected: expected)
    }
    func binding() throws -> AuthorityPeerBinding {
        try .init(scope: ChannelScope(macID: macID, accountID: accountID, phoneID: id(6), enrollmentEpoch: id(4)),
            transportPublicKey: identity.publicKey.derRepresentation, revision: db.read { try $0.approvalTrustSnapshot().revision })
    }
    func issue(_ action: UpdateSchedulingAction) throws -> UpdateSchedulingControl {
        let peer = try binding(), snapshot = try XCTUnwrap(commits.read { try $0.updateSchedulingIntent() }).snapshot
        let issued = nextNow()
        return try withCandidate { candidate in
            try commits.write(epoch: epoch, recoverRejectedBody: true) { try $0.issueUpdateSchedulingControl(candidate: candidate, action: action,
                expected: snapshot, binding: peer, nowUnixMillis: 1000, now: issued) }
        }
    }
    func sign(_ control: UpdateSchedulingControl) throws -> Data {
        try decision.signature(for: UpdateSchedulingSigningInput.make(wireVersion: 1, canonicalPayload: control.encode(limits: limits),
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    func consume(_ control: UpdateSchedulingControl, signature: Data? = nil, binding: AuthorityPeerBinding? = nil,
                 wall: UInt64 = 1500) throws -> UpdateSchedulingIntent {
        let peer = try binding ?? self.binding(), bytes = try control.encode(limits: limits), signature = try signature ?? sign(control)
        let consumed = nextNow()
        return try withCandidate { candidate in
            try commits.write(epoch: epoch, recoverRejectedBody: true) { try $0.consumeUpdateSchedulingControl(candidate: candidate, canonicalControl: bytes,
                signature: signature, binding: peer, nowUnixMillis: wall, now: consumed) }
        }
    }
    func sql(_ query: String, journal: Bool = false) throws {
        var connection: OpaquePointer?
        guard sqlite3_open(root.appendingPathComponent(journal ? "journal/journal.sqlite" : "continuity/continuity.sqlite").path, &connection) == SQLITE_OK,
              let connection else { throw Fault.injected }
        defer { sqlite3_close(connection) }
        guard sqlite3_exec(connection, query, nil, nil, nil) == SQLITE_OK else { throw Fault.injected }
    }
}
