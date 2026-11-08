import CryptoKit
import Darwin
import Synchronization
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MachineUpdateHealthJournalTests: XCTestCase {
    private enum Failure: Error { case injected }
    private typealias Fixture = CheckpointedJournalTests.Fixture

    private func close(_ fixture: Fixture) throws {
        try fixture.journal.close()
        fixture.store.close()
    }

    private func bytes(_ fixture: Fixture) throws -> [Data] {
        try ["journal/journal.sqlite", "continuity/continuity.sqlite"].map {
            try Data(contentsOf: fixture.root.appendingPathComponent($0))
        }
    }

    private func open(_ fixture: Fixture,
                      validateSelf: (JournalTransaction) throws -> Void = { _ in }) throws -> AuthorityJournal {
        try AuthorityJournal(updateHealthStorage: fixture.openTransferredStorage(readOnlyForCutover: true),
            validateSelf: validateSelf)
    }

    func testMatchingCheckpointAllowsHealthReadButNeverRequestStartupOrWrites() throws {
        let fixture = try Fixture(), epoch = fixture.epoch
        let checkpoint = try fixture.store.read().committed
        try close(fixture)
        let before = try bytes(fixture), owner = try open(fixture)
        XCTAssertEqual(try owner.readForUpdateHealth { try $0.epoch(epoch)?.head }, 0)
        for _ in 0..<2 {
            XCTAssertThrowsError(try owner.prepareRequests(clockEpoch: UUID(), maximumPayloadBytes: 16384)) {
                XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
            }
            XCTAssertThrowsError(try owner.write { _ in true }) {
                XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
            }
        }
        XCTAssertThrowsError(try owner.withRequests { _ in true })
        XCTAssertEqual(try owner.readForUpdateHealth { try $0.epoch(epoch)?.head }, 0)
        try owner.close()
        XCTAssertEqual(try bytes(fixture), before)
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read().committed, checkpoint)
    }

    func testUpdateHealthFactoryUsesTheConfiguredReadOnlyPair() throws {
        let fixture = try Fixture()
        let journalPath = fixture.root.appendingPathComponent("journal").path
        let continuityPath = fixture.root.appendingPathComponent("continuity").path
        let configuration = try AuthorityServiceConfiguration(macID: Data(repeating: 1, count: 16),
            accountID: Data(repeating: 2, count: 16), journalDirectory: journalPath,
            serviceName: "dev.sebastiano.remozio.macos.authority.health-test", teamID: "ABCDEFGHIJ",
            transportIdentifier: "dev.sebastiano.remozio.macos.transport",
            transportHashes: [Data(repeating: 3, count: 20)], transportUID: 501, continuityDirectory: continuityPath)
        try close(fixture)
        let before = try bytes(fixture)
        if geteuid() != 0 {
            XCTAssertThrowsError(try AuthorityStorage.openForUpdateHealth(configuration: configuration)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
        let storage = try AuthorityStorage.openForUpdateHealth(configuration: configuration,
            acquireJournal: { path in
                XCTAssertEqual(path, journalPath)
                return try ProtectedJournalLease(anchor: fixture.root.path, relativeDirectory: "journal", owner: geteuid())
            }, acquireContinuity: { path, excluded in
                XCTAssertEqual(path, continuityPath)
                XCTAssertNotNil(excluded)
                return try ProtectedContinuityLease(anchor: fixture.root.path, relativeDirectory: "continuity",
                    owner: geteuid(), excludingDirectory: excluded)
            })
        XCTAssertTrue(storage.journal.readOnlyForCutover)
        XCTAssertTrue(storage.continuity.readOnlyForCutover)
        XCTAssertEqual(try storage.journal.read { try $0.epoch(fixture.epoch)?.head }, 0)
        XCTAssertEqual(try storage.continuity.read().committed.journalEpoch, fixture.epoch)
        try storage.close()
        XCTAssertEqual(try bytes(fixture), before)
    }

    func testWritableStoresAreRejectedAndBothLeasesAreReleased() throws {
        let fixture = try Fixture()
        try close(fixture)
        let before = try bytes(fixture)
        XCTAssertThrowsError(try AuthorityJournal(updateHealthStorage: fixture.openTransferredStorage(), validateSelf: { _ in })) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        let owner = try open(fixture)
        try owner.close()
        XCTAssertEqual(try bytes(fixture), before)
    }

    func testPendingCheckpointIsNeitherFinalizedNorDiscarded() throws {
        for committed in [false, true] {
            let fixture = try Fixture(), old = try fixture.store.read().committed
            do {
                try fixture.journal.write { transaction in
                    try fixture.append(transaction)
                    let candidate = try CheckpointedJournal.checkpoint(transaction: transaction,
                        epoch: fixture.epoch, generation: old.generation + 1, authorityGeneration: old.authorityGeneration)
                    try fixture.store.prepare(expected: old, candidate: candidate)
                    if !committed { throw Failure.injected }
                }
            } catch {
                guard !committed, error is Failure else { throw error }
            }
            let pending = try XCTUnwrap(fixture.store.read().pending)
            try close(fixture)
            let before = try bytes(fixture)
            XCTAssertThrowsError(try open(fixture))
            XCTAssertEqual(try bytes(fixture), before)
            try fixture.reopen()
            XCTAssertEqual(try fixture.store.read().committed, old)
            XCTAssertEqual(try fixture.store.read().pending, pending)
        }
    }

    func testCheckpointMismatchDoesNotCreateRecoveryEvidenceOrChangeEitherStore() throws {
        let fixture = try Fixture()
        try fixture.journal.write { try fixture.append($0) }
        try close(fixture)
        let before = try bytes(fixture)
        XCTAssertThrowsError(try open(fixture))
        XCTAssertEqual(try bytes(fixture), before)
        try fixture.reopen()
        XCTAssertNil(try fixture.store.historyRecovery())
        XCTAssertNil(try fixture.store.historyRecoveryCandidate())
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testHistoryRecoveryIntentAndCandidateRemainUnchanged() throws {
        for candidate in [false, true] {
            let fixture = try Fixture()
            let policy = try AuthorityCodePolicy(entries: [.init(role: .authority, teamID: "ABCDEF1234",
                identifier: "dev.remozio.authority", installedGeneration: 4, minimumGeneration: 2,
                codeDirectoryHash: Data(repeating: 8, count: 20), active: true)])
            let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
            _ = try commits.write(epoch: fixture.epoch) { try $0.installCodePolicy(policy, expectedRevision: nil) }
            let old = try fixture.store.read()
            if candidate { try fixture.journal.write { try fixture.append($0) } }
            else {
                XCTAssertEqual(try fixture.observed(generation: old.committed.generation,
                    authorityGeneration: old.committed.authorityGeneration), old.committed)
            }
            let digests = try fixture.journal.read { try $0.continuityDigests() }
            let intent = try HistoryRecoveryIntent(previous: old, authorityDigest: digests.authority,
                ledgerDigest: digests.ledger, recoveryEpoch: Data(repeating: 9, count: 16))
            try fixture.store.prepareHistoryRecovery(intent)
            if candidate {
                try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.history IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
                XCTAssertThrowsError(try JournalHistoryRecovery.resume(journal: fixture.journal, continuity: fixture.store,
                    macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16)))
                try fixture.sql("DROP TRIGGER fail_finalize")
            }
            let retained = try fixture.store.historyRecoveryCandidate()
            XCTAssertEqual(retained != nil, candidate)
            try close(fixture)
            let before = try bytes(fixture)
            XCTAssertThrowsError(try open(fixture)) {
                guard case ContinuityStoreError.historyRecoveryPending = $0 else {
                    return XCTFail("Expected historyRecoveryPending, got \($0)")
                }
            }
            XCTAssertEqual(try bytes(fixture), before)
            try fixture.reopen()
            XCTAssertEqual(try fixture.store.historyRecovery(), intent)
            XCTAssertEqual(try fixture.store.historyRecoveryCandidate(), retained)
        }
    }

    func testRepairRequiredStateRemainsClosedAndUnchanged() throws {
        let fixture = try Fixture()
        try fixture.store.requireRecovery()
        try close(fixture)
        let before = try bytes(fixture)
        XCTAssertThrowsError(try open(fixture))
        XCTAssertEqual(try bytes(fixture), before)
        try fixture.reopen()
        XCTAssertTrue(try fixture.store.read().recoveryRequired)
    }

    func testSelfValidationFailureReleasesBothStoresWithoutRecovery() throws {
        let fixture = try Fixture()
        try close(fixture)
        let before = try bytes(fixture)
        XCTAssertThrowsError(try open(fixture, validateSelf: { _ in throw Failure.injected })) {
            XCTAssertTrue($0 is Failure)
        }
        XCTAssertEqual(try bytes(fixture), before)
        let owner = try open(fixture)
        try owner.close()
        XCTAssertEqual(try bytes(fixture), before)
    }

    private struct ContractFixture {
        let files: Fixture
        let journal: AuthorityJournal
        let configuration: AuthorityServiceConfiguration
        let binding: RuntimeReleaseBinding
        let policy: AuthorityCodePolicySnapshot

        init(registration: GatewayRegistrationIdentity? = nil, updateHealthOnly: Bool = true) throws {
            let files = try Fixture()
            let requirement = try MachineUpdateRoleChallengeTests.Fixture().requirement(mac: 1, account: 2)
            let gatewayPolicy: GatewayAuthorityPolicy?
            if registration != nil {
                let value = try GatewayAuthorityPolicy(payloadLimits: files.limits, signingLimits: files.limits,
                    maximumControls: 20, candidateLifetimeMillis: 1000, clockEpoch: UUID())
                try files.journal.enableGatewayPolicy(value, macID: requirement.binding.macID, accountID: requirement.binding.accountID)
                gatewayPolicy = value
            } else {
                gatewayPolicy = nil
            }
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            let code = try AuthorityCodePolicy(entries: [requirement.code])
            let commits = CheckpointedJournal(journal: files.journal, continuity: files.store)
            let policy = try commits.write(epoch: files.epoch) {
                _ = try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: [1]]),
                    allowedContracts: [contract])
                if let registration { try $0.configureGatewayAuthority(registration) }
                return try $0.installCodePolicy(code, expectedRevision: nil)
            }
            let configuration = try AuthorityServiceConfiguration(macID: requirement.binding.macID,
                accountID: requirement.binding.accountID, journalDirectory: files.root.appendingPathComponent("journal").path,
                serviceName: "dev.sebastiano.remozio.macos.authority.health-test", teamID: "ABCDEFGHIJ",
                transportIdentifier: "dev.sebastiano.remozio.macos.transport",
                transportHashes: [Data(repeating: 3, count: 20)], transportUID: 501,
                continuityDirectory: files.root.appendingPathComponent("continuity").path)
            try files.journal.close()
            files.store.close()
            self.files = files
            self.configuration = configuration
            self.binding = requirement.binding
            self.policy = policy
            if updateHealthOnly {
                journal = try AuthorityJournal(updateHealthStorage: files.openTransferredStorage(readOnlyForCutover: true,
                    gatewayPolicy: gatewayPolicy), validateSelf: { _ in })
            } else {
                journal = try AuthorityJournal(storage: files.openTransferredStorage(gatewayPolicy: gatewayPolicy))
            }
        }

        func validate(binding: RuntimeReleaseBinding? = nil, policy: AuthorityCodePolicySnapshot? = nil,
                      requests: [ReleaseRequestContract]) throws {
            let configuration = configuration, expectedBinding = binding ?? self.binding, expectedPolicy = policy ?? self.policy
            try journal.readForUpdateHealth {
                try MachineUpdateAuthorityHealthJournalValidation.requireCurrent($0, configuration: configuration,
                    binding: expectedBinding, policy: expectedPolicy, requests: requests)
            }
        }

        func declaration(schema: UInt64 = 1, features: Set<UInt64> = [1]) throws -> ReleaseRequestContract {
            try .init(kind: 0, wireVersion: 1, schemaVersion: schema, actions: [0], purposes: [.issuedRequest], features: features)
        }
    }

    func testHealthJournalValidatesRetainedPolicyAndContractsWithoutWriting() throws {
        let fixture = try ContractFixture()
        let before = try bytes(fixture.files)
        try fixture.validate(requests: [fixture.declaration()])
        try fixture.journal.close()
        XCTAssertEqual(try bytes(fixture.files), before)
    }

    func testHealthJournalRejectsAStalePolicyAndForeignBinding() throws {
        let fixture = try ContractFixture()
        let request = try fixture.declaration()
        let stale = AuthorityCodePolicySnapshot(revision: UUID(), policy: fixture.policy.policy,
            roleRevisions: fixture.policy.roleRevisions)
        XCTAssertThrowsError(try fixture.validate(policy: stale, requests: [request])) {
            XCTAssertEqual($0 as? AuthorityCodePolicyError, .staleRevision)
        }
        let other = try MachineUpdateRoleChallengeTests.Fixture().requirement(mac: 9, account: 2).binding
        XCTAssertThrowsError(try fixture.validate(binding: other, requests: [request])) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        try fixture.validate(requests: [request])
    }

    func testHealthJournalRequiresTheExactRequestVersionAndEveryFeature() throws {
        let fixture = try ContractFixture()
        let wrongVersion = try fixture.declaration(schema: 2)
        let missingFeature = try fixture.declaration(features: [])
        for requests in [[], [wrongVersion], [missingFeature]] {
            XCTAssertThrowsError(try fixture.validate(requests: requests)) {
                XCTAssertEqual($0 as? ReleaseCompatibilityError, .invalidRequirements)
            }
        }
        try fixture.validate(requests: [fixture.declaration()])
    }

    private final class ScopeState: Sendable {
        let valid = Mutex(true)
        let releases = Mutex(0)
    }

    private struct GatewayFixture {
        let paired: ContractFixture
        let signer: MachineUpdateRoleChallengeTests.Fixture
        let gateway: GatewayServiceConfiguration
        let requirement: MachineUpdateRestartHealthPlan.Requirement
        let state = ScopeState()

        init(updateHealthOnly: Bool = true) throws {
            let signer = MachineUpdateRoleChallengeTests.Fixture()
            let seed = try signer.requirement(role: .notificationGateway, uid: 20001, mac: 1, account: 2)
            let registration = try GatewayRegistrationIdentity(ownerID: Data(repeating: 1, count: 16),
                macID: seed.binding.macID, accountID: seed.binding.accountID,
                gatewayID: Data(repeating: 4, count: 16), lifecycleEpoch: Data(repeating: 5, count: 16),
                rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
            let paired = try ContractFixture(registration: registration, updateHealthOnly: updateHealthOnly)
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: seed.binding.encoded) as? [String: Any])
            fields["sourcePolicyRevision"] = paired.policy.revision.uuidString
            fields["sourcePolicyDigest"] = try MachineUpdateActivationRecord.digest(paired.policy.storedBytes).base64EncodedString()
            let binding = try RuntimeReleaseBinding.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            let settings = try GatewayServiceSettings(delivery: .init(maximumFlights: 1, minimumSendIntervalMillis: 1000),
                probe: .init(maximumAttempts: 1, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 60),
                wake: .init(maximumEntries: 8, maximumAttempts: 1, minimumEnrollmentIntervalMillis: 1000,
                    maximumLifetimeMillis: 10000, maximumTTLSeconds: 60))
            let root = paired.files.root
            gateway = try .init(registration: registration, receiptPublicKey: seed.publicKey,
                directoryPath: root.appendingPathComponent("gateway").path, providerPath: root.appendingPathComponent("provider.json").path,
                receiptKeyPath: root.appendingPathComponent("receipt.cbor").path, serviceUID: seed.executionUID, ownerUID: 20002,
                serviceName: "dev.sebastiano.remozio.macos.gateway.health-test", teamID: "ABCDEFGHIJ",
                authorityIdentifier: "dev.sebastiano.remozio.macos.authority", authorityHashes: [Data(repeating: 7, count: 20)],
                project: "health-fixture", packageName: "dev.remozio.fixture", settings: settings)
            requirement = .init(binding: binding, configurationEpoch: seed.configurationEpoch,
                configurationRevision: seed.configurationRevision, backendEpoch: seed.backendEpoch,
                backendRevision: seed.backendRevision, role: seed.role, executionUID: seed.executionUID,
                code: seed.code, publicKey: seed.publicKey)
            self.paired = paired
            self.signer = signer
        }

        func owner(policy: AuthorityCodePolicySnapshot? = nil) throws -> MachineUpdateGatewayPairedHealthReader {
            let state = state
            return try .init(journal: paired.journal, configuration: paired.configuration, expected: requirement,
                gateway: gateway, rootPublicKey: gateway.registration.rootPublicKey,
                policy: policy ?? paired.policy, requests: [paired.declaration()],
                verifyCurrent: {
                    guard state.valid.withLock({ $0 }) else { throw Failure.injected }
                }, release: { state.releases.withLock { $0 += 1 } })
        }

        func proof() throws -> MachineUpdateConsumerHealthProof {
            let registration = gateway.registration
            let moment = AuthorityMoment(epoch: UUID(), milliseconds: 100)
            let session = try MachineUpdateConsumerHealthChallengeSession(requirement: requirement, registration: registration,
                clock: { moment }, verifyCurrent: {})
            let request = try session.makeRequest()
            let role = try signer.answer(request, expected: requirement)
            let fields: [UInt64: CBORValue] = [0: .unsigned(1), 1: .unsigned(1), 2: .bytes(try registration.encode()),
                3: .bytes(MachineUpdateGatewayHealthQuery.nonce(request)), 4: .unsigned(0), 5: .unsigned(0),
                6: .bytes(Data()), 7: .bytes(Data())]
            let payload = try DeterministicCBOR.encode(.map(fields), limits: paired.files.limits)
            let signature = try signer.key.signature(for: Data("Remozio/GatewayHeadReply/v1\u{0}".utf8) + payload).rawRepresentation
            let packet = try MachineUpdateConsumerHealthPacket(roleReply: role,
                gatewayHead: .init(canonicalPayload: payload, signature: signature)).encoded
            return try session.accept(packet, authenticatePeer: { _ in })
        }
    }

    func testPairedGatewayReaderConsumesOneProofWithoutWriting() throws {
        let fixture = try GatewayFixture()
        let before = try bytes(fixture.paired.files)
        let owner = try fixture.owner()
        XCTAssertThrowsError(try owner.validateHealthScope())
        let proof = try fixture.proof()
        try owner.accept(proof)
        try owner.validateHealthScope()
        XCTAssertThrowsError(try owner.accept(proof))
        try owner.close()
        try owner.close()
        XCTAssertEqual(fixture.state.releases.withLock { $0 }, 1)
        XCTAssertEqual(try bytes(fixture.paired.files), before)
    }

    func testPairedGatewayReaderRetiresAfterAnInvalidScope() throws {
        let fixture = try GatewayFixture()
        let owner = try fixture.owner()
        defer { try? owner.close() }
        try owner.accept(fixture.proof())
        fixture.state.valid.withLock { $0 = false }
        XCTAssertThrowsError(try owner.validateHealthScope()) { XCTAssertTrue($0 is Failure) }
        fixture.state.valid.withLock { $0 = true }
        XCTAssertThrowsError(try owner.validateHealthScope()) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
        }
    }

    func testPairedGatewayReaderRejectsAWritableOwnerAndReleasesItsStores() throws {
        let fixture = try GatewayFixture(updateHealthOnly: false)
        XCTAssertNoThrow(try fixture.paired.journal.readForUpdateHealth { _ in true })
        XCTAssertThrowsError(try fixture.owner()) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        XCTAssertEqual(fixture.state.releases.withLock { $0 }, 1)
        try fixture.paired.files.reopen()
    }

    func testPairedGatewayReaderRejectsForeignSourcePolicyAndReleasesItsStores() throws {
        let fixture = try GatewayFixture()
        let policy = fixture.paired.policy
        let foreign = AuthorityCodePolicySnapshot(revision: UUID(), policy: policy.policy, roleRevisions: policy.roleRevisions)
        XCTAssertThrowsError(try fixture.owner(policy: foreign)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        XCTAssertEqual(fixture.state.releases.withLock { $0 }, 1)
        try fixture.paired.files.reopen()
    }
}
