import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityUpdateSchedulingTransportTests: XCTestCase {
    private final class Sample {
        let root: URL
        let journal: AuthorityJournal
        let binding: AuthorityPeerBinding
        let access: AuthorityTransportAccess
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let directory = root.appendingPathComponent("journal")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory.appendingPathComponent(name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }; Darwin.close(fd)
            }
            let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
            let epoch = Data(repeating: 3, count: 16), identity = P256.Signing.PrivateKey()
            let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
            let database = try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: getuid()),
                macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 20, busyMilliseconds: 100, initialize: true)
            let entry = try AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.transport",
                installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 41, count: 20), active: true)
            try database.write { tx in
                let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                    0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(epoch), 4: .unsigned(1),
                    5: .unsigned(1), 6: .null, 7: .null, 8: .null,
                ]), limits: limits), limits: limits)
                let writer = try tx.createEpoch(descriptor)
                let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
                let capabilities = ContractCapabilities(contracts: [contract: []])
                let revision = try tx.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract])
                let enrollment = try StoredApprovalEnrollment(epoch: Data(repeating: 4, count: 16), notificationTag: Data(repeating: 5, count: 32),
                    identityPublicKey: identity.publicKey.x963Representation,
                    approval: ApprovalEnrollment(phoneID: Data(repeating: 6, count: 16), active: true, capabilities: capabilities, keys: [
                        EnrolledApprovalKey(id: Data(repeating: 7, count: 16), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                        EnrolledApprovalKey(id: Data(repeating: 8, count: 16), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                    ]))
                _ = try tx.addApprovalEnrollment(enrollment, expectedTrustRevision: revision, eventID: Data(repeating: 9, count: 16),
                    receiptTimeMs: 1000, writer: writer, expectedAuditHead: 0)
                _ = try tx.installCodePolicy(AuthorityCodePolicy(entries: [entry]), expectedRevision: nil)
            }
            let owner = AuthorityJournal(database: database)
            journal = owner
            binding = try AuthorityPeerBinding(scope: ChannelScope(macID: mac, accountID: account, phoneID: Data(repeating: 6, count: 16),
                enrollmentEpoch: Data(repeating: 4, count: 16)), transportPublicKey: identity.publicKey.derRepresentation,
                revision: owner.read { try $0.approvalTrustSnapshot().revision })
            let peer = try XPCPeerPolicy(teamID: entry.teamID, componentIdentifier: entry.identifier,
                approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: getuid())
            access = try AuthorityTransportAccess(journal: owner, peerPolicy: peer, macID: mac, accountID: account,
                maximumPayloadBytes: PhoneUpdateSchedulingFrame.maximumBytes, minimumEnvelopeVersion: 1, auditVersions: [])
        }
        deinit { try? journal.close(); try? FileManager.default.removeItem(at: root) }
        func retiredPolicy() throws -> (AuthorityCodePolicy, UUID) {
            let snapshot = try XCTUnwrap(journal.read { try $0.codePolicy() })
            let entries = try snapshot.policy.entries.map { entry in
                try AuthorityCodeEntry(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                    installedGeneration: entry.installedGeneration, minimumGeneration: entry.minimumGeneration,
                    codeDirectoryHash: entry.codeDirectoryHash, active: entry.role == .transport ? false : entry.active)
            }
            return try (AuthorityCodePolicy(entries: entries), snapshot.revision)
        }
    }
    private func request() -> PhoneUpdateSchedulingFrame { .status(queryNonce: Data(repeating: 42, count: 32)) }

    func testProviderAcquiresItsScopeOutsideTheAccountTransactionAndValidatesInsideIt() throws {
        let sample = try Sample(), binding = sample.binding, request = request()
        let result = try sample.access.phoneUpdateScheduling(binding: binding, frame: request) { owner, peer, frame, validate in
            try owner.read { transaction in
                try validate(transaction)
                XCTAssertEqual(peer.scope, binding.scope)
                XCTAssertEqual(try transaction.approvalTrustSnapshot().accountID, binding.scope.accountID)
            }
            return .failure(queryNonce: frame.queryNonce, reason: .unavailable)
        }
        guard case .failure(_, .unavailable) = result else { return XCTFail("Observation became acceptance") }
    }
    func testPolicyRotationBetweenInitialReadAndAccountOperationRejectsTheOldCaller() throws {
        let sample = try Sample(), next = try sample.retiredPolicy()
        XCTAssertThrowsError(try sample.access.phoneUpdateScheduling(binding: sample.binding, frame: request()) { owner, _, _, validate in
            _ = try owner.write { try $0.installCodePolicy(next.0, expectedRevision: next.1) }
            try owner.read { try validate($0) }
            XCTFail("Old caller reached the account operation")
            return .failure(queryNonce: Data(count: 32), reason: .unavailable)
        }) { XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch) }
    }
    func testPolicyRotationAfterProviderWorkRejectsTheReply() throws {
        let sample = try Sample(), next = try sample.retiredPolicy()
        XCTAssertThrowsError(try sample.access.phoneUpdateScheduling(binding: sample.binding, frame: request()) { owner, _, frame, validate in
            try owner.read { try validate($0) }
            _ = try owner.write { try $0.installCodePolicy(next.0, expectedRevision: next.1) }
            return .failure(queryNonce: frame.queryNonce, reason: .unavailable)
        }) { XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch) }
    }
    func testRejectedScopeOrResponseRoleNeverAcquiresTheProvider() throws {
        let sample = try Sample(), request = request()
        let stale = try AuthorityPeerBinding(scope: sample.binding.scope, transportPublicKey: sample.binding.transportPublicKey,
            revision: UUID())
        XCTAssertThrowsError(try sample.access.phoneUpdateScheduling(binding: stale, frame: request) { _, _, _, _ in
            XCTFail("Stale enrollment reached machine acquisition"); return .failure(queryNonce: request.queryNonce, reason: .unavailable)
        })
        XCTAssertThrowsError(try sample.access.phoneUpdateScheduling(binding: sample.binding,
            frame: .failure(queryNonce: request.queryNonce, reason: .unavailable)) { _, _, _, _ in
            XCTFail("Response reached machine acquisition"); return .failure(queryNonce: request.queryNonce, reason: .unavailable)
        })
    }
}
