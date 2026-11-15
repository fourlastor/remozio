import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses actual retained rows with ordinary ownership. It proves commitments, not native execution or administrator rights.
final class RuntimeMaintenanceCommitmentsTests: XCTestCase {
    private typealias Binding = SetupRetainedCallerBinding
    private typealias Commitments = RuntimeMaintenanceCommitments
    private func binding(_ f: RetainedMaterialWriterFixture, incarnation: UUID = UUID(), pid: Int32 = getpid(),
        changedGroupFor: UInt32? = nil) throws -> Binding {
        let state = try f.machine().retainedSetupCallerState(candidate: f.candidate)
        let entry = try f.machine().retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
        let authority = try XCTUnwrap(state.source.actual.inventory.accounts.first)
        let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(runtime: entry.runtime, accountID: authority.accountID)
        let app = try XCTUnwrap(host.codePolicy.entries.first { $0.role == .app && $0.active })
        let peer = XPCPeerCredentials(processID: pid, userID: authority.ownerUID, auditSessionID: 1)
        let accepted = try XPCPeerPolicy(teamID: app.teamID, componentIdentifier: app.identifier,
            approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: peer.userID)
        return try Binding.resolve(state: state, peer: peer, incarnation: incarnation, accepted: accepted, entry: entry, lookup: { uid in
            let account = try XCTUnwrap(state.source.preparations.first { $0.ownerUID == uid })
            return .init(uid: uid, primaryGroupID: getgid() + (changedGroupFor == uid ? 1 : 0), directoryID: account.directoryID)
        })
    }
    private func inputs(_ binding: Binding) throws -> MachineUpdateRetainedSetupRuntimeInputs {
        try .capture(expected: binding.entry.runtime, journal: nil, verifyCurrent: {},
            readRelay: { _ in throw SharedSetupImportError.wrongScope })
    }
    private func capture(_ f: RetainedMaterialWriterFixture, _ binding: Binding) throws -> Commitments {
        try .capture(binding: binding, inputs: inputs(binding), candidate: f.candidate, purpose: .retainedRuntime)
    }
    private func digest(_ domain: String, _ value: CBORValue) throws -> Data {
        Data(SHA256.hash(data: try DeterministicCBOR.encode(.array([.text("remozio.maintenance." + domain + ".v1"), value]),
            limits: .init(maxBytes: 2 * 1024 * 1024, maxDepth: 8, maxItems: 4096))))
    }
    func testCandidateUsesTheSelectedReleaseEvidenceAndPublishedPolicyFloors() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let binding = try binding(f), actual = try capture(f, binding)
            XCTAssertEqual(actual.scope.candidateDigest, try InstallationInventory.digest(f.candidate))
            XCTAssertEqual(actual.scope.releaseDigest, binding.entry.runtime.setup.source.actual.inventory.releaseDigest)
            XCTAssertEqual(actual.scope.authorityPolicyDigest, try digest("authorityPolicy", .bytes(binding.publishedAuthorityPolicy.bytes)))
            let historical = try binding.entry.runtime.preparation.initialAuthority.codePolicy
            XCTAssertNotEqual(actual.scope.authorityPolicyDigest, try digest("authorityPolicy", .bytes(historical.bytes)))
            try actual.requirePolicy(binding.publishedAuthorityPolicy)
            XCTAssertThrowsError(try actual.requirePolicy(historical))
        }
    }
    func testGrantAndConsentRemainStableAcrossAnotherInvocationAndProcess() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let first = try binding(f), second = try binding(f, incarnation: UUID(), pid: getpid() + 1)
            XCTAssertNotEqual(first.peer, second.peer); XCTAssertNotEqual(first.incarnation, second.incarnation)
            XCTAssertEqual(try capture(f, first), try capture(f, second))
        }
    }
    func testAuthorityGroupChangeChangesOnlyItsGrantCommitment() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let original = try binding(f), before = try capture(f, original)
            let after = try capture(f, binding(f, changedGroupFor: original.authorityOwner.uid))
            XCTAssertNotEqual(before.scope.authorityGrantDigest, after.scope.authorityGrantDigest)
            XCTAssertEqual(before.scope.targetConsentDigest, after.scope.targetConsentDigest)
            XCTAssertEqual(before.scope.operationDigest, after.scope.operationDigest)
            XCTAssertEqual(before.scope.restorationDigest, after.scope.restorationDigest)
            XCTAssertEqual(before.scope.administratorIntentDigest, after.scope.administratorIntentDigest)
        }
    }
    func testTargetGroupChangeChangesOnlyItsConsentCommitment() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let original = try binding(f), before = try capture(f, original)
            let after = try capture(f, binding(f, changedGroupFor: original.targetOwner.uid))
            XCTAssertNotEqual(before.scope.targetConsentDigest, after.scope.targetConsentDigest)
            XCTAssertEqual(before.scope.authorityGrantDigest, after.scope.authorityGrantDigest)
            XCTAssertEqual(before.scope.operationDigest, after.scope.operationDigest)
            XCTAssertEqual(before.scope.mutationFootprintDigest, after.scope.mutationFootprintDigest)
            XCTAssertEqual(before.scope.administratorIntentDigest, after.scope.administratorIntentDigest)
        }
    }
    func testUnsupportedPurposesRefuseBeforeAnyWindowWrite() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let binding = try binding(f), choices = try inputs(binding)
            let before = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            for purpose in [RuntimeMaintenanceWindowRecord.Purpose.retainedPolicy, .markerReplacement] {
                XCTAssertThrowsError(try Commitments.capture(binding: binding, inputs: choices, candidate: f.candidate, purpose: purpose)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                }
            }
            try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before)
        }
    }
    func testStableOperationAndIntentIgnoreMaterialProgressWithoutChangingRestorationOrFootprint() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let original = try binding(f), before = try capture(f, original)
            let expected = try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)
            _ = try f.machine().retainRetainedSetupRuntimeMaterial(f.material.reference, expected: expected, candidate: f.candidate,
                directory: f.directory, admission: f.admission, fileCustodyAccepted: true, verifyScoped: { _, _ in })
            let after = try capture(f, binding(f))
            XCTAssertEqual(before.scope.operationDigest, after.scope.operationDigest)
            XCTAssertEqual(before.scope.administratorIntentDigest, after.scope.administratorIntentDigest)
            XCTAssertEqual(before.scope.authorityGrantDigest, after.scope.authorityGrantDigest)
            XCTAssertEqual(before.scope.targetConsentDigest, after.scope.targetConsentDigest)
            XCTAssertEqual(before.scope.restorationDigest, after.scope.restorationDigest)
            XCTAssertEqual(before.scope.mutationFootprintDigest, after.scope.mutationFootprintDigest)
        }
    }
    func testAdministratorIntentHasItsOwnDomainAndExactAcyclicInputs() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let binding = try binding(f), value = try capture(f, binding).scope
            let fields = CBORValue.array([.unsigned(RuntimeMaintenanceWindowRecord.Purpose.retainedRuntime.rawValue),
                .bytes(value.authority.accountID), .bytes(value.target.accountID), .bytes(value.releaseDigest),
                .bytes(value.candidateDigest), .bytes(value.operationDigest)])
            XCTAssertEqual(value.administratorIntentDigest, try digest("administratorIntent", fields))
            XCTAssertNotEqual(value.administratorIntentDigest, try digest("operation", fields))
            XCTAssertNotEqual(value.administratorIntentDigest, value.operationDigest)
        }
    }
    func testOperationUsesV2AndConsentCannotMatchItsHistoricalV1Domain() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let binding = try binding(f), actual = try capture(f, binding), runtime = binding.entry.runtime
            let initial = try XCTUnwrap(runtime.setup.account?.initialization)
            let choices = CBORValue.array([.unsigned(0), .null, .null, .null])
            let fields = CBORValue.array([.unsigned(RuntimeMaintenanceWindowRecord.Purpose.retainedRuntime.rawValue),
                .bytes(try runtime.preparation.bytes), .bytes(try initial.bytes), .bytes(try runtime.plan.encoded), choices])
            let expected = Data(SHA256.hash(data: try DeterministicCBOR.encode(
                .array([.text("remozio.maintenance.operation.v2"), fields]),
                limits: .init(maxBytes: 2 * 1024 * 1024, maxDepth: 8, maxItems: 4096))))
            XCTAssertEqual(actual.scope.operationDigest, expected)
            XCTAssertNotEqual(actual.scope.operationDigest, try digest("operation", fields))
            var uuid = binding.targetOwner.directoryID.uuid
            let owner = CBORValue.array([.unsigned(UInt64(binding.targetOwner.uid)),
                .unsigned(UInt64(binding.targetOwner.primaryGroupID)), .bytes(withUnsafeBytes(of: &uuid) { Data($0) })])
            XCTAssertNotEqual(actual.scope.targetConsentDigest,
                try digest("targetConsent", .array([.bytes(runtime.preparation.accountID), owner, choices])))
        }
    }
    func testUnsupportedObservationPhasesRefuseBeforeAnyRead() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let binding = try binding(f), scope = try capture(f, binding).scope
            for phase in [RuntimeMaintenanceWindowRecord.Phase.authorized, .draining, .workSettled, .restoring, .needsOwnerRecovery] {
                let early = phase == .authorized || phase == .draining
                let row = try RuntimeMaintenanceWindowRecord(id: AccountPreparationIntent.randomID(),
                    revision: AccountPreparationIntent.randomID(), purpose: .retainedRuntime, scope: scope, phase: phase,
                    operation: early ? .notStarted : .unknown, service: early ? .notStopped : .unknown,
                    failure: phase == .needsOwnerRecovery ? .repairRequired : nil)
                var reads = 0
                let result = RuntimeMaintenanceRuntimeObservation.observeOwned(window: row, candidate: f.candidate,
                    readFrame: { reads += 1; throw RuntimePreparationError.changedScope },
                    readPolicy: { reads += 1; throw RuntimePreparationError.changedScope },
                    readMaterial: { _ in reads += 1; throw RuntimePreparationError.changedScope },
                    readFile: { _, _ in reads += 1; throw RuntimePreparationError.changedScope },
                    lookup: { _ in reads += 1; throw RuntimePreparationError.changedScope }, verifyCurrent: { reads += 1 })
                XCTAssertEqual(result, .unknown); XCTAssertEqual(reads, 0)
            }
        }
    }
    func testDeclaredFootprintUsesItsAnchorAndAcceptsOnlyFixedOrExactStagingLeaves() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let binding = try binding(f), inputs = try inputs(binding)
            let declared = try Commitments.MutationFootprint(runtime: binding.entry.runtime, inputs: inputs).declaration
            XCTAssertEqual(declared.files.count, Set(declared.files).count)
            XCTAssertTrue(declared.directories.contains("."))
            XCTAssertTrue(declared.files.allSatisfy { !$0.hasPrefix("/") && !$0.contains("..") })
            for path in declared.files { XCTAssertTrue(declared.containsFile(path)) }
            for pattern in declared.staging {
                let prefix = String(pattern.dropLast("{UUID}".count))
                XCTAssertTrue(declared.containsFile(prefix + UUID().uuidString))
                XCTAssertFalse(declared.containsFile(prefix + "not-a-uuid"))
                XCTAssertFalse(declared.containsFile(prefix + UUID().uuidString + "/other"))
            }
            XCTAssertFalse(declared.containsFile("outside.cbor"))
            XCTAssertThrowsError(try Commitments.MutationFootprint.relative("/Users/501/Library/outside.cbor"))
            XCTAssertThrowsError(try Commitments.MutationFootprint.relative(RuntimePreparationPaths.sharedDirectory + "/../outside.cbor"))
        }
    }

}
