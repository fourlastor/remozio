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

    private final class AuthoritySigner: Sendable {
        private let key = Mutex(P256.Signing.PrivateKey())
        let count = Mutex(0)
        var publicKey: Data { key.withLock { $0.publicKey.x963Representation } }
        func sign(_ data: Data) throws -> Data {
            count.withLock { $0 += 1 }
            return try signFixtureReceipt(data)
        }
        func signFixtureReceipt(_ data: Data) throws -> Data {
            try key.withLock { try $0.signature(for: data).rawRepresentation }
        }
    }

    private struct AuthorityFixture {
        let paired: ContractFixture
        let requirement: MachineUpdateRestartHealthPlan.Requirement
        let state = ScopeState()
        let signer: AuthoritySigner

        init(updateHealthOnly: Bool = true) throws {
            let paired = try ContractFixture(updateHealthOnly: updateHealthOnly)
            let signer = AuthoritySigner()
            let seed = try MachineUpdateRoleChallengeTests.Fixture().requirement(mac: 1, account: 2, publicKey: signer.publicKey)
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: seed.binding.encoded) as? [String: Any])
            fields["sourcePolicyRevision"] = paired.policy.revision.uuidString
            fields["sourcePolicyDigest"] = try MachineUpdateActivationRecord.digest(paired.policy.storedBytes).base64EncodedString()
            let binding = try RuntimeReleaseBinding.decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
            requirement = .init(binding: binding, configurationEpoch: seed.configurationEpoch,
                configurationRevision: seed.configurationRevision, backendEpoch: seed.backendEpoch,
                backendRevision: seed.backendRevision, role: seed.role, executionUID: seed.executionUID,
                code: seed.code, publicKey: seed.publicKey)
            self.paired = paired; self.signer = signer
        }

        func open(publicKey: Data? = nil, verify: @escaping @Sendable () throws -> Void = {},
                  afterSign: @escaping @Sendable () -> Void = {}) throws -> MachineUpdateAuthorityHealthOwner {
            let state = state, signer = signer
            return try .init(journal: paired.journal, configuration: paired.configuration, requirement: requirement,
                policy: paired.policy, requests: [paired.declaration()], keyPublicKey: publicKey ?? requirement.publicKey,
                verifyCurrent: {
                    guard state.valid.withLock({ $0 }) else { throw Failure.injected }
                    try verify()
                }, sign: { bytes in
                    let signature = try signer.sign(bytes)
                    afterSign()
                    return signature
                }, release: { state.releases.withLock { $0 += 1 } })
        }

        func challenge() throws -> MachineUpdateRoleChallengeSession {
            try .init(requirement: requirement, verifyCurrent: {})
        }
    }

    func testRestartAuthorityCoordinatorBlocksOnVerifierRefusal() throws {
        let fixture = try AuthorityFixture(), status = ScopeState()
        let owner = try fixture.open(verify: {
            guard status.valid.withLock({ $0 }) else { throw InstalledAuthorityCommandError.wrongRelease }
        })
        let coordinator = MachineUpdateRestartAuthorityCoordinator(owner: owner)
        defer { try? coordinator.close() }
        status.valid.withLock { $0 = false }
        XCTAssertThrowsError(try coordinator.check()) { XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongRelease) }
        status.valid.withLock { $0 = true }
        XCTAssertThrowsError(try coordinator.check())
        XCTAssertThrowsError(try coordinator.validate())
        XCTAssertEqual(fixture.signer.count.withLock { $0 }, 0)
    }

    func testRestartAuthorityCanRetryTransientSourceContention() throws {
        let fixture = try AuthorityFixture(), busy = Mutex(false)
        let owner = try fixture.open(verify: {
            if busy.withLock({ $0 }) { throw MachineUpdateHealthSourceError.busy }
        })
        let coordinator = MachineUpdateRestartAuthorityCoordinator(owner: owner)
        defer { try? coordinator.close() }
        busy.withLock { $0 = true }
        XCTAssertThrowsError(try coordinator.check()) { XCTAssertEqual($0 as? MachineUpdateHealthSourceError, .busy) }
        XCTAssertEqual(fixture.signer.count.withLock { $0 }, 0)
        busy.withLock { $0 = false }
        XCTAssertEqual(try coordinator.check().requirement, fixture.requirement)
        busy.withLock { $0 = true }
        XCTAssertThrowsError(try coordinator.validate()) { XCTAssertEqual($0 as? MachineUpdateHealthSourceError, .busy) }
        busy.withLock { $0 = false }
        try coordinator.validate()
        XCTAssertEqual(fixture.signer.count.withLock { $0 }, 1)
    }

    func testAuthorityAnswerCanRetryWhenItsSourceIsBusy() throws {
        let fixture = try AuthorityFixture(), busy = Mutex(false)
        let owner = try fixture.open(verify: {
            if busy.withLock({ $0 }) { throw MachineUpdateHealthSourceError.busy }
        })
        defer { try? owner.close() }
        let refused = try fixture.challenge()
        busy.withLock { $0 = true }
        XCTAssertThrowsError(try owner.answer(refused.request)) { XCTAssertEqual($0 as? MachineUpdateHealthSourceError, .busy) }
        XCTAssertEqual(fixture.signer.count.withLock { $0 }, 0)
        busy.withLock { $0 = false }
        let retry = try fixture.challenge()
        let reply = try owner.answer(retry.request)
        XCTAssertEqual(try retry.accept(reply, authenticatePeer: { _ in }).requirement, fixture.requirement)
        XCTAssertEqual(fixture.signer.count.withLock { $0 }, 1)
    }

    func testAuthorityAnswerRetiresAfterAnUnlentStoreTransaction() throws {
        let fixture = try AuthorityFixture(), active = Mutex(false)
        let owner = try fixture.open(verify: {
            if active.withLock({ $0 }) { throw PreparationStoreError.transactionActive }
        })
        defer { try? owner.close() }
        active.withLock { $0 = true }
        XCTAssertThrowsError(try owner.answer(fixture.challenge().request)) {
            XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
        }
        active.withLock { $0 = false }
        XCTAssertThrowsError(try owner.answer(fixture.challenge().request)) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
        }
        XCTAssertEqual(fixture.signer.count.withLock { $0 }, 0)
    }

    func testRestartAuthorityCoordinatorDiscardsTheReplyWhenScopeExpiresDuringSigning() throws {
        let fixture = try AuthorityFixture(), status = ScopeState()
        let owner = try fixture.open(verify: {
            guard status.valid.withLock({ $0 }) else { throw JournalLeaseError.invalidated }
        }, afterSign: { status.valid.withLock { $0 = false } })
        let coordinator = MachineUpdateRestartAuthorityCoordinator(owner: owner)
        defer { try? coordinator.close() }
        XCTAssertThrowsError(try coordinator.check()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertThrowsError(try coordinator.validate())
        XCTAssertEqual(fixture.signer.count.withLock { $0 }, 1)
        XCTAssertEqual(fixture.state.releases.withLock { $0 }, 0)
        try coordinator.close()
        XCTAssertEqual(fixture.state.releases.withLock { $0 }, 1)
    }

    func testAuthorityHealthSignsFromThePairedReadWithoutChangingEitherStore() throws {
        let fixture = try AuthorityFixture(), before = try bytes(fixture.paired.files)
        let owner = try fixture.open(); defer { try? owner.close() }
        let challenge = try fixture.challenge(), requirement = fixture.requirement
        let reply = try owner.answer(challenge.request)
        let authenticated = try challenge.accept(reply, authenticatePeer: { XCTAssertEqual($0, requirement) })
        XCTAssertEqual(authenticated.requirement, requirement)
        XCTAssertEqual(fixture.signer.count.withLock { $0 }, 1)
        try owner.close()
        XCTAssertEqual(try bytes(fixture.paired.files), before)
        XCTAssertEqual(fixture.state.releases.withLock { $0 }, 1)
    }

    func testAuthorityHealthRejectsAnOrdinaryJournalAndTheWrongKey() throws {
        let ordinary = try AuthorityFixture(updateHealthOnly: false)
        XCTAssertThrowsError(try ordinary.open()) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        let fixture = try AuthorityFixture()
        XCTAssertThrowsError(try fixture.open(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        for value in [ordinary, fixture] {
            XCTAssertEqual(value.signer.count.withLock { $0 }, 0)
            XCTAssertEqual(value.state.releases.withLock { $0 }, 1)
        }
    }

    func testAuthorityHealthRetiresAfterAChangedScope() throws {
        let fixture = try AuthorityFixture(), owner = try fixture.open(); defer { try? owner.close() }
        let request = try fixture.challenge().request
        fixture.state.valid.withLock { $0 = false }
        XCTAssertThrowsError(try owner.answer(request))
        fixture.state.valid.withLock { $0 = true }
        XCTAssertThrowsError(try owner.answer(request))
        XCTAssertEqual(fixture.signer.count.withLock { $0 }, 0)
    }

    func testAuthorityHealthCloseDuringValidationCannotReachTheSigner() throws {
        let fixture = try AuthorityFixture(), reference = Mutex<MachineUpdateAuthorityHealthOwner?>(nil)
        let checks = Mutex(0)
        let owner = try fixture.open(verify: {
            let check = checks.withLock { $0 += 1; return $0 }
            if check == 2 { try reference.withLock { try $0?.close() } }
        })
        reference.withLock { $0 = owner }; checks.withLock { $0 = 0 }
        defer { reference.withLock { $0 = nil }; try? owner.close() }
        XCTAssertThrowsError(try owner.validateHealthScope()) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
        }
        XCTAssertEqual(checks.withLock { $0 }, 2)
        XCTAssertEqual(fixture.signer.count.withLock { $0 }, 0)
        XCTAssertEqual(fixture.state.releases.withLock { $0 }, 1)
    }

    func testAuthorityHealthRetainsActivityUntilTheJournalCloses() throws {
        let fixture = try AuthorityFixture(), owner = try fixture.open(); defer { try? owner.close() }
        try fixture.paired.journal.readForUpdateHealth { _ in
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
        }
        XCTAssertEqual(fixture.state.releases.withLock { $0 }, 0)
        XCTAssertThrowsError(try owner.answer(fixture.challenge().request))
        try owner.close(); try owner.close()
        XCTAssertEqual(fixture.state.releases.withLock { $0 }, 1)
    }

    private struct GatewayFixture {
        let paired: ContractFixture
        let signer: MachineUpdateRoleChallengeTests.Fixture
        let gateway: GatewayServiceConfiguration
        let requirement: MachineUpdateRestartHealthPlan.Requirement
        let state = ScopeState()
        let rootSigner = AuthoritySigner()

        init(updateHealthOnly: Bool = true) throws {
            let signer = MachineUpdateRoleChallengeTests.Fixture()
            let seed = try signer.requirement(role: .notificationGateway, uid: 20001, mac: 1, account: 2)
            let registration = try GatewayRegistrationIdentity(ownerID: Data(repeating: 1, count: 16),
                macID: seed.binding.macID, accountID: seed.binding.accountID,
                gatewayID: Data(repeating: 4, count: 16), lifecycleEpoch: Data(repeating: 5, count: 16),
                rootPublicKey: rootSigner.publicKey)
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

        func authority() throws -> (MachineUpdateAuthorityHealthOwner, MachineUpdateRoleChallengeSession) {
            let seed = try signer.requirement(mac: 1, account: 2, publicKey: rootSigner.publicKey)
            let root = MachineUpdateRestartHealthPlan.Requirement(binding: requirement.binding,
                configurationEpoch: requirement.configurationEpoch, configurationRevision: requirement.configurationRevision,
                backendEpoch: requirement.backendEpoch, backendRevision: requirement.backendRevision,
                role: .authority, executionUID: 0, code: seed.code, publicKey: rootSigner.publicKey)
            let owner = try MachineUpdateAuthorityHealthOwner(journal: paired.journal, configuration: paired.configuration,
                requirement: root, policy: paired.policy, requests: [paired.declaration()], keyPublicKey: rootSigner.publicKey,
                restartGateway: .init(requirement: requirement, registration: gateway.registration),
                verifyCurrent: {}, sign: rootSigner.sign)
            return (owner, try .init(requirement: root, verifyCurrent: {}))
        }

        func readiness(challenge: Data, aheadOfJournal: Bool = false) throws -> MachineUpdateAuthorityReadinessRequest {
            let session = try MachineUpdateRoleChallengeSession(requirement: requirement,
                authorityReadinessRequest: challenge, verifyCurrent: {})
            let request = try session.request
            let exchange = MachineUpdateConsumerHealthExchange(request: request,
                response: try packet(request, aheadOfJournal: aheadOfJournal))
            return try .init(challenge: challenge, gateway: exchange)
        }

        func proof() throws -> MachineUpdateConsumerHealthProof {
            let registration = gateway.registration
            let moment = AuthorityMoment(epoch: UUID(), milliseconds: 100)
            let session = try MachineUpdateConsumerHealthChallengeSession(requirement: requirement, registration: registration,
                clock: { moment }, verifyCurrent: {})
            let request = try session.makeRequest()
            return try session.accept(packet(request), authenticatePeer: { _ in })
        }

        private func packet(_ request: Data, aheadOfJournal: Bool = false) throws -> Data {
            let registration = gateway.registration
            let role = try signer.answer(request, expected: requirement)
            var receipt = Data(), receiptSignature = Data()
            if aheadOfJournal {
                let id: (UInt8) -> Data = { Data(repeating: $0, count: 16) }
                let candidate = try GatewayTokenCandidate(binding: .init(ownerID: registration.ownerID,
                    macID: registration.macID, accountID: registration.accountID, gatewayID: registration.gatewayID,
                    lifecycleEpoch: registration.lifecycleEpoch, phoneID: id(6), enrollmentEpoch: id(7), candidateID: id(8),
                    tokenDigest: Data(repeating: 9, count: 32), challenge: Data(repeating: 10, count: 32),
                    enrollmentTag: Data(repeating: 11, count: 32)), revision: 1, operationID: id(12),
                    issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000)
                receipt = try candidate.encode(limits: paired.files.limits)
                receiptSignature = try rootSigner.signFixtureReceipt(GatewayTokenCandidateSigningInput.make(wireVersion: 1,
                    canonicalPayload: receipt, payloadLimits: paired.files.limits, inputLimits: paired.files.limits))
            }
            let fields: [UInt64: CBORValue] = [0: .unsigned(1), 1: .unsigned(1), 2: .bytes(try registration.encode()),
                3: .bytes(MachineUpdateGatewayHealthQuery.nonce(request)), 4: .unsigned(aheadOfJournal ? 1 : 0),
                5: .unsigned(aheadOfJournal ? 1 : 0), 6: .bytes(receipt), 7: .bytes(receiptSignature)]
            let payload = try DeterministicCBOR.encode(.map(fields), limits: paired.files.limits)
            let signature = try signer.key.signature(for: Data("Remozio/GatewayHeadReply/v1\u{0}".utf8) + payload).rawRepresentation
            return try MachineUpdateConsumerHealthPacket(roleReply: role,
                gatewayHead: .init(canonicalPayload: payload, signature: signature)).encoded
        }
    }

    func testAuthorityReadinessReconcilesTheFreshGatewayProofBeforeSigning() throws {
        let fixture = try GatewayFixture(), before = try bytes(fixture.paired.files)
        let (owner, session) = try fixture.authority(); defer { try? owner.close() }
        let request = try fixture.readiness(challenge: session.request)
        let selected = try MachineUpdateAuthorityReadinessGateway(requirement: fixture.requirement,
            registration: fixture.gateway.registration)
        let reply = try owner.answerReadiness(request, gateway: selected, now: .init(epoch: UUID(), milliseconds: 100))
        _ = try session.accept(reply, authenticatePeer: { _ in })
        XCTAssertEqual(fixture.rootSigner.count.withLock { $0 }, 1)
        try owner.close()
        XCTAssertEqual(try bytes(fixture.paired.files), before)
    }

    func testAuthorityReadinessRejectsASignedGatewayHeadAheadOfThePairedJournal() throws {
        let fixture = try GatewayFixture(), (owner, session) = try fixture.authority()
        defer { try? owner.close() }
        let selected = try MachineUpdateAuthorityReadinessGateway(requirement: fixture.requirement,
            registration: fixture.gateway.registration)
        let request = try fixture.readiness(challenge: session.request, aheadOfJournal: true)
        let now = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        let proof = try XCTUnwrap(request.gatewayProof(expected: selected, now: now))
        XCTAssertEqual(proof.gatewayHead?.evidence.revision, 1)
        XCTAssertThrowsError(try owner.answerReadiness(request, gateway: selected, now: now)) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .headMismatch)
        }
        XCTAssertEqual(fixture.rootSigner.count.withLock { $0 }, 0)
    }

    func testRegisteredGatewayCannotBeOmittedFromAuthorityReadiness() throws {
        for plain in [true, false] {
            let fixture = try GatewayFixture(), (owner, session) = try fixture.authority()
            defer { try? owner.close() }
            let challenge = try session.request
            if plain {
                XCTAssertThrowsError(try owner.answer(challenge)) {
                    XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope)
                }
            } else {
                let request = try MachineUpdateAuthorityReadinessRequest(challenge: challenge, gateway: nil)
                XCTAssertThrowsError(try owner.answerReadiness(request, gateway: nil, now: .init(epoch: UUID(), milliseconds: 100))) {
                    XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope)
                }
            }
            XCTAssertEqual(fixture.rootSigner.count.withLock { $0 }, 0)
        }
    }

    func testAuthorityReadinessRefusesMissingOrDamagedGatewayProofBeforeSigning() throws {
        for missing in [true, false] {
            let fixture = try GatewayFixture()
            let (owner, session) = try fixture.authority(); defer { try? owner.close() }
            let selected = try MachineUpdateAuthorityReadinessGateway(requirement: fixture.requirement,
                registration: fixture.gateway.registration)
            let challenge = try session.request, complete = try fixture.readiness(challenge: challenge)
            var gateway: MachineUpdateConsumerHealthExchange?
            if !missing {
                let exchange = try XCTUnwrap(complete.gateway)
                let packet = try MachineUpdateConsumerHealthPacket.decode(exchange.response)
                let head = try XCTUnwrap(packet.gatewayHead)
                var damaged = head.signature; damaged[damaged.count - 1] ^= 1
                let encoded = try MachineUpdateConsumerHealthPacket(roleReply: packet.roleReply,
                    gatewayHead: .init(canonicalPayload: head.canonicalPayload, signature: damaged)).encoded
                gateway = .init(request: exchange.request, response: encoded)
            }
            let request = try MachineUpdateAuthorityReadinessRequest(challenge: challenge, gateway: gateway)
            let now = AuthorityMoment(epoch: UUID(), milliseconds: 100)
            XCTAssertThrowsError(try owner.answerReadiness(request, gateway: selected, now: now)) {
                if missing { XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .changedScope) }
                else { XCTAssertEqual($0 as? GatewayHeadReplyError, .invalidSignature) }
            }
            XCTAssertThrowsError(try owner.answerReadiness(complete, gateway: selected, now: now))
            XCTAssertEqual(fixture.rootSigner.count.withLock { $0 }, 0)
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
