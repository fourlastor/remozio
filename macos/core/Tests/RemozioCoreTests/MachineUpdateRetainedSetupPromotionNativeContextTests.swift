import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Values from owned stores only. The machine has no completed retained registration or native custody.
struct RetainedPromotionNativeContextFixture {
    let completion: MachineUpdateRetainedSetupCompletionSnapshot
    let candidate: SignedReleaseEvidence
    let material: RuntimePreparationMaterial
    let machine: PreparationIntentStore
    let changingFrame: (Int64, Data, Set<UInt32>?) throws -> MachineUpdateRetainedSetupCompletionSnapshot

    let policy: AuthorityCodePolicy

}

final class MachineUpdateRetainedSetupPromotionNativeContextTests: XCTestCase {
    private typealias Context = MachineUpdateRetainedSetupPromotionNativeContext
    private enum Failed: Error { case injected }
    private func fixture(_ body: (RetainedPromotionNativeContextFixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPromotionNativeContextFixture(body)
    }

    func testOrdinaryIdentityFailsBeforeAnyNativePathAccess() throws {
        try fixture { f in
            XCTAssertNotEqual(getuid(), 0)
            XCTAssertThrowsError(try Context.withNativeScope(machineDirectory: "/does-not-exist",
                expected: f.completion, candidate: f.candidate, currentCodePolicy: f.policy) { _ in
                    XCTFail("An ordinary identity entered the native context")
                }) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
            XCTAssertNoThrow(try f.machine.inventory())
        }
    }

    func testOwnedApprovalComparisonKeepsTheInitialFrameAndOnlyThePromotionMetadataStep() throws {
        try fixture { f in
            XCTAssertNoThrow(try Context.requireApproved(f.completion, from: f.completion, candidate: f.candidate))
            let promoted = try f.changingFrame(27, Data(repeating: 89, count: 32), nil)
            XCTAssertNoThrow(try Context.requireApproved(promoted, from: f.completion, candidate: f.candidate))
            let readiness = try f.changingFrame(28, Data(repeating: 90, count: 32), nil)
            XCTAssertNoThrow(try Context.requireApproved(readiness, from: readiness, candidate: f.candidate))
            XCTAssertThrowsError(try Context.requireApproved(readiness, from: f.completion, candidate: f.candidate))
            XCTAssertThrowsError(try Context.requireApproved(readiness, from: promoted, candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try Context.requireApproved(f.completion, from: promoted, candidate: f.candidate))
        }
    }

    func testAnApprovedFrameCannotChangeAnImmutableReservation() throws {
        try fixture { f in
            let reserved = f.completion.activation.runtime.reservedNumbers.union([29999])
            let changed = try f.changingFrame(27, Data(repeating: 89, count: 32), reserved)
            try changed.requireSame(as: changed)
            XCTAssertThrowsError(try Context.requireApproved(changed, from: f.completion, candidate: f.candidate))
        }
    }

    func testAnApprovedFrameCannotReplaceTheRecordedCompletionReceipt() throws {
        try fixture { f in
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(f.completion.intent).encoded) as? [String: Any])
            fields["revision"] = UUID().uuidString
            let record = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            let changed = try MachineUpdateRetainedSetupCompletionSnapshot(activation: f.completion.activation,
                intent: record, candidate: f.candidate)
            try changed.requireSame(as: changed)
            XCTAssertThrowsError(try Context.requireApproved(changed, from: f.completion, candidate: f.candidate))
        }
    }

    func testExactActualFrameComparisonRejectsOnlyTheRowsDigestChanging() throws {
        try fixture { f in
            let approved = try f.changingFrame(27, Data(repeating: 89, count: 32), nil)
            let actual = try f.changingFrame(27, Data(repeating: 90, count: 32), nil)
            XCTAssertNoThrow(try Context.requireApproved(approved, from: f.completion, candidate: f.candidate))
            XCTAssertNoThrow(try Context.requireApproved(actual, from: f.completion, candidate: f.candidate))
            XCTAssertThrowsError(try actual.requireSame(as: approved)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
        }
    }

    func testOwnedReleaseEvidencePinsTheAppAndSetupCodePolicies() throws {
        try fixture { f in
            let policy = f.policy
            XCTAssertNoThrow(try Context.requireRelease(f.candidate, approved: f.completion,
                candidate: f.candidate, currentCodePolicy: policy))
            for role in [AuthorityCodeRole.app, .setupController] {
                let missing = try AuthorityCodePolicy(entries: policy.entries.filter { $0.role != role })
                XCTAssertThrowsError(try Context.requireRelease(f.candidate, approved: f.completion,
                    candidate: f.candidate, currentCodePolicy: missing))
                let changed = try AuthorityCodePolicy(entries: policy.entries.map { entry in
                    if entry.role != role { return entry }
                    return try .init(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                        installedGeneration: entry.installedGeneration, minimumGeneration: entry.minimumGeneration,
                        codeDirectoryHash: Data(repeating: 77, count: 20), active: true)
                })
                XCTAssertThrowsError(try Context.requireRelease(f.candidate, approved: f.completion,
                    candidate: f.candidate, currentCodePolicy: changed))
            }
        }
    }

    func testIncompleteCompletionAndForeignPolicyFailBeforeOpeningTheMachineStore() throws {
        try fixture { f in
            let changed = try f.policy.retainingFormat(with: f.policy.entries.map { entry in
                guard entry.role == .app else { return entry }
                var hash = entry.codeDirectoryHash; hash[hash.startIndex] ^= 1
                return try .init(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                    installedGeneration: entry.installedGeneration, minimumGeneration: entry.minimumGeneration,
                    codeDirectoryHash: hash, active: entry.active)
            })
            XCTAssertNotEqual(changed, f.policy)
            XCTAssertEqual(try AuthorityCodePolicy.decode(changed.bytes), changed)
            var opened = 0
            let controls = Context.Controls(openMachine: { opened += 1; throw Failed.injected },
                lookupOwner: { _ in XCTFail("A foreign policy reached owner lookup"); throw Failed.injected },
                validateCustody: { XCTFail("A foreign policy reached custody validation") },
                inspectRelease: { XCTFail("A foreign policy reached release inspection"); throw Failed.injected },
                validateExecutingCode: { XCTFail("A foreign policy reached code validation") },
                validateServices: { _ in XCTFail("A foreign policy reached service lookup") },
                readMaterial: { _ in XCTFail("A foreign policy reached material read"); throw Failed.injected },
                validateActivity: { _, _, _ in XCTFail("A foreign policy reached activity validation") })
            XCTAssertThrowsError(try Context.withOwnedContext(expected: f.completion, candidate: f.candidate,
                currentCodePolicy: changed, controls: controls) { _ in XCTFail("A foreign policy entered the context") }) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            var incomplete = [try MachineUpdateRetainedSetupCompletionSnapshot(activation: f.completion.activation,
                intent: nil, candidate: f.candidate)]
            for phase in [MachineUpdateRetainedSetupCompletionIntentRecord.Phase.prepared, .writing] {
                var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(f.completion.intent).encoded) as? [String: Any])
                fields["phase"] = phase.rawValue
                fields["committedPolicy"] = nil; fields["committedCheckpoint"] = nil
                let intent = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(JSONSerialization.data(withJSONObject: fields,
                    options: [.sortedKeys, .withoutEscapingSlashes]))
                incomplete.append(try .init(activation: f.completion.activation, intent: intent, candidate: f.candidate))
            }
            for snapshot in incomplete {
                XCTAssertThrowsError(try Context.withOwnedContext(expected: snapshot, candidate: f.candidate,
                    currentCodePolicy: changed, controls: controls) { _ in XCTFail("An incomplete intent entered the context") }) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
                }
                XCTAssertThrowsError(try Context.requireApproved(snapshot, from: snapshot, candidate: f.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
                }
            }
            XCTAssertEqual(opened, 0); XCTAssertNoThrow(try f.machine.inventory())
        }
    }

    func testOwnedMaterialRejectsMalformedAndAnotherAccountsValidBytes() throws {
        try fixture { f in
            XCTAssertNoThrow(try Context.requireMaterial(f.material.encoded, approved: f.completion))
            XCTAssertThrowsError(try Context.requireMaterial(Data(), approved: f.completion))
            XCTAssertThrowsError(try Context.requireMaterial(f.material.encoded + Data([0]), approved: f.completion))
            try fixture { other in
                XCTAssertNotEqual(try other.material.reference.services.accountID, try f.material.reference.services.accountID)
                XCTAssertThrowsError(try Context.requireMaterial(other.material.encoded, approved: f.completion))
            }
        }
    }

    func testFreshActualStoreRefusesValueOnlyCompletionAndClosesTheConnection() throws {
        try fixture { f in
            var opened = 0, inspected = 0
            let controls = Context.Controls(openMachine: { opened += 1; return f.machine }, lookupOwner: { _ in
                f.completion.activation.runtime.setup.owner
            }, validateCustody: {}, inspectRelease: { inspected += 1; return f.candidate },
                validateExecutingCode: {}, validateServices: { _ in }, readMaterial: { _ in try f.material.encoded },
                validateActivity: { _, _, _ in XCTFail("Activity was checked without an actual completed frame") })
            XCTAssertThrowsError(try Context.withOwnedContext(expected: f.completion, candidate: f.candidate,
                currentCodePolicy: f.policy, controls: controls) { _ in XCTFail("Value-only completion entered the context") })
            XCTAssertEqual(opened, 1); XCTAssertEqual(inspected, 0)
            XCTAssertThrowsError(try f.machine.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
        }
    }

    func testAcquisitionFailureCannotReachExternalReadsOrTheBody() throws {
        try fixture { f in
            var opened = 0
            let controls = Context.Controls(openMachine: { opened += 1; throw Failed.injected },
                lookupOwner: { _ in XCTFail("Owner lookup preceded the fresh store"); throw Failed.injected },
                validateCustody: {}, inspectRelease: { XCTFail("Release inspection preceded the fresh store"); throw Failed.injected },
                validateExecutingCode: { XCTFail("Code validation preceded the fresh store") },
                validateServices: { _ in XCTFail("Service lookup preceded the fresh store") },
                readMaterial: { _ in XCTFail("Material read preceded the fresh store"); throw Failed.injected },
                validateActivity: { _, _, _ in XCTFail("Activity check preceded the fresh store") })
            XCTAssertThrowsError(try Context.withOwnedContext(expected: f.completion, candidate: f.candidate,
                currentCodePolicy: f.policy, controls: controls) { _ in XCTFail("The body ran after acquisition failed") }) {
                XCTAssertTrue($0 is Failed)
            }
            XCTAssertEqual(opened, 1); XCTAssertNoThrow(try f.machine.inventory())
        }
    }
}
