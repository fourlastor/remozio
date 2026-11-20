import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeMaintenanceUnboundRecordTests: XCTestCase {
    private typealias Row = RuntimeMaintenanceWindowRecord
    private func bytes(_ value: UInt8, _ count: Int = 16) -> Data { Data(repeating: value, count: count) }
    private func authorized() throws -> Row {
        let scope = try Row.Scope(macID: bytes(1), installationID: bytes(2),
            authority: .init(accountID: bytes(3), ownerUID: 501, directoryID: bytes(4)),
            target: .init(accountID: bytes(5), ownerUID: 1501, directoryID: bytes(6)),
            releaseDigest: bytes(7, 32), candidateDigest: bytes(8, 32), authorityPolicyDigest: bytes(9, 32),
            operationDigest: bytes(10, 32), restorationDigest: bytes(11, 32), mutationFootprintDigest: bytes(12, 32),
            authorityGrantDigest: bytes(13, 32), targetConsentDigest: bytes(14, 32), administratorIntentDigest: bytes(15, 32))
        return try .init(id: bytes(16), revision: bytes(17), purpose: .retainedRuntime, scope: scope)
    }
    private func pending(_ origin: Row) throws -> Row {
        let descriptor = try RuntimeMaintenanceUnboundRelease(authorized: origin, previous: origin,
            pendingRevision: bytes(18), intentID: bytes(19))
        return try .init(id: origin.id, revision: bytes(18), purpose: origin.purpose, scope: origin.scope,
            phase: .reopenPending, unboundRelease: descriptor)
    }
    private func recovery(_ previous: Row) throws -> Row {
        try .init(id: previous.id, revision: bytes(20), purpose: previous.purpose, scope: previous.scope,
            phase: .needsOwnerRecovery, failure: .admissionUnconfirmed, unboundRelease: previous.unboundRelease)
    }
    private func restored(_ previous: Row, requestRevision: Data? = nil) throws -> Row {
        let gate = try Row.GateReadback(attemptID: previous.id,
            requestRevision: requestRevision ?? XCTUnwrap(previous.unboundRelease).pendingRevision,
            identity: .init(device: 1, inode: 2), authorityIncarnation: bytes(21), challenge: bytes(22),
            responseDigest: bytes(23, 32), hold: .released, admission: .available)
        return try .init(id: previous.id, revision: bytes(24), purpose: previous.purpose, scope: previous.scope,
            phase: .restored, gate: gate)
    }
    func testDescriptorRoundTripsAndRejectsUnknownFields() throws {
        let row = try pending(authorized()), descriptor = try XCTUnwrap(row.unboundRelease)
        XCTAssertEqual(try RuntimeMaintenanceUnboundRelease.decode(descriptor.encoded), descriptor)
        guard case .map(var fields) = try DeterministicCBOR.decode(descriptor.encoded, limits: Row.limits) else { return XCTFail() }
        fields.removeValue(forKey: 7); fields[8] = .unsigned(1)
        XCTAssertThrowsError(try RuntimeMaintenanceUnboundRelease.decode(DeterministicCBOR.encode(.map(fields), limits: Row.limits))) {
            XCTAssertEqual($0 as? RuntimePreparationError, .invalidRecord)
        }
        XCTAssertEqual(try Row.decode(row.encoded), row)
        XCTAssertEqual(row.formatVersion, 3)
    }
    func testDescriptorOnlyFitsPendingOrUnstartedRecovery() throws {
        let origin = try authorized(), row = try pending(origin)
        for phase in Row.Phase.allCases where phase != .reopenPending && phase != .needsOwnerRecovery {
            XCTAssertThrowsError(try Row(id: origin.id, revision: row.revision, purpose: origin.purpose,
                scope: origin.scope, phase: phase, unboundRelease: row.unboundRelease))
        }
        XCTAssertThrowsError(try Row(id: origin.id, revision: bytes(25), purpose: origin.purpose,
            scope: origin.scope, phase: .reopenPending, unboundRelease: row.unboundRelease))
        XCTAssertThrowsError(try Row(id: origin.id, revision: bytes(25), purpose: origin.purpose,
            scope: origin.scope, phase: .needsOwnerRecovery, operation: .unknown, failure: .repairRequired,
            unboundRelease: row.unboundRelease))
    }
    func testIntentRequiresExactCanonicalOriginAndDedicatedEdge() throws {
        let origin = try authorized(), row = try pending(origin)
        try row.requireUnboundIntentReplacing(origin, authorized: origin)
        XCTAssertThrowsError(try row.requireReplacing(origin))
        let changed = try Row(id: origin.id, revision: bytes(26), purpose: origin.purpose, scope: origin.scope)
        XCTAssertThrowsError(try row.requireUnboundIntentReplacing(changed, authorized: origin))
        XCTAssertThrowsError(try row.requireUnboundIntentReplacing(origin, authorized: changed))
    }
    func testGenericFailurePreservesDescriptorAndCannotRepeatOrRestore() throws {
        let p = try pending(authorized()), r = try recovery(p)
        try r.requireReplacing(p)
        XCTAssertEqual(r.unboundRelease, p.unboundRelease)
        let again = try Row(id: r.id, revision: bytes(27), purpose: r.purpose, scope: r.scope,
            phase: .needsOwnerRecovery, failure: .serviceUnavailable, unboundRelease: r.unboundRelease)
        XCTAssertThrowsError(try again.requireReplacing(r))
        XCTAssertThrowsError(try restored(p).requireReplacing(p))
        XCTAssertThrowsError(try restored(r).requireReplacing(r))
    }
    func testTypedCompletionDropsDescriptorAndUsesOriginalPendingRevision() throws {
        let p = try pending(authorized()), r = try recovery(p)
        for previous in [p, r] {
            let completed = try restored(previous)
            try completed.requireUnboundCompletionReplacing(previous)
            XCTAssertEqual(completed.formatVersion, 1)
            XCTAssertNil(completed.unboundRelease)
            XCTAssertEqual(try Row.decode(completed.encoded), completed)
        }
        XCTAssertThrowsError(try restored(r, requestRevision: r.revision).requireUnboundCompletionReplacing(r))
    }
    func testStartupDiscardKeepsRepairClosureAndRequiresDedicatedEdge() throws {
        let p = try pending(authorized()), r = try recovery(p)
        let dropped = try Row(id: r.id, revision: bytes(28), purpose: r.purpose, scope: r.scope,
            phase: .needsOwnerRecovery, failure: .repairRequired)
        try dropped.requireUnboundStartupDiscardReplacing(r)
        XCTAssertThrowsError(try dropped.requireReplacing(r))
        XCTAssertThrowsError(try dropped.requireUnboundStartupDiscardReplacing(p))
        XCTAssertEqual(dropped.formatVersion, 1)
        XCTAssertNil(dropped.gate)
        XCTAssertEqual(dropped.failure, .repairRequired)
    }
    func testLegacyAuthorizedShapeHasNoNewKeys() throws {
        let row = try authorized()
        XCTAssertEqual(row.formatVersion, 1)
        guard case .map(let fields) = try DeterministicCBOR.decode(row.encoded, limits: Row.limits) else { return XCTFail() }
        XCTAssertEqual(Set(fields.keys), Set(UInt64(0)...10))
        XCTAssertEqual(try Row.decode(row.encoded), row)
    }
    func testFrozenReaderOneKeepsClosedRowsAndRefusesBothUnfinishedRows() throws {
        let pending = try pending(authorized()), recovery = try recovery(pending)
        let dropped = try Row(id: recovery.id, revision: bytes(30), purpose: recovery.purpose,
            scope: recovery.scope, phase: .needsOwnerRecovery, failure: .repairRequired)
        for row in [dropped, try restored(pending), try restored(recovery)] {
            XCTAssertEqual(try FrozenMaintenanceWindowReader1.decode(row.encoded).encoded, try row.encoded)
        }
        for row in [pending, recovery] {
            XCTAssertThrowsError(try FrozenMaintenanceWindowReader1.decode(row.encoded)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .invalidRecord)
            }
            let projection = RuntimeMaintenanceAdmissionProjection.startup { () throws -> RuntimeMaintenanceAdmissionProjection in
                _ = try FrozenMaintenanceWindowReader1.decode(row.encoded)
                throw RuntimePreparationError.changedScope
            }
            XCTAssertTrue(projection.requiresLocalHold); XCTAssertTrue(projection.needsOwnerRecovery)
        }
    }
    func testGenericEdgesCannotRestartPendingOrRemoveTheDescriptor() throws {
        let p = try pending(authorized()), r = try recovery(p)
        let restoring = try Row(id: r.id, revision: bytes(31), purpose: r.purpose, scope: r.scope,
            phase: .restoring, service: .restartPending)
        let secondPending = try Row(id: p.id, revision: bytes(32), purpose: p.purpose, scope: p.scope,
            phase: .reopenPending)
        let noDescriptor = try Row(id: p.id, revision: bytes(33), purpose: p.purpose, scope: p.scope,
            phase: .needsOwnerRecovery, failure: .repairRequired)
        for (next, previous) in [(restoring, r), (secondPending, p), (noDescriptor, p)] {
            XCTAssertThrowsError(try next.requireReplacing(previous)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
        }
    }
    func testDescriptorRejectsContradictoryOriginAndPendingRevision() throws {
        let descriptor = try XCTUnwrap(pending(authorized()).unboundRelease)
        guard case .map(let original) = try DeterministicCBOR.decode(descriptor.encoded, limits: Row.limits) else { return XCTFail() }
        var variants = [[UInt64: CBORValue]]()
        var fields = original; fields[7] = .unsigned(2); variants.append(fields)
        fields = original; fields[4] = .bytes(bytes(34)); variants.append(fields)
        fields = original; fields[6] = original[2]; variants.append(fields)
        for fields in variants {
            XCTAssertThrowsError(try RuntimeMaintenanceUnboundRelease.decode(DeterministicCBOR.encode(.map(fields), limits: Row.limits))) {
                XCTAssertEqual($0 as? RuntimePreparationError, .invalidRecord)
            }
        }
    }

}
