import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class RuntimeMaintenanceBindingRecordTests: XCTestCase {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private let limits = try! CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024)
    private func d(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func base() throws -> Record {
        let scope = try Record.Scope(macID: d(1), installationID: d(2),
            authority: .init(accountID: d(3), ownerUID: 501, directoryID: d(4)),
            target: .init(accountID: d(5), ownerUID: 1501, directoryID: d(6)),
            releaseDigest: d(7, 32), candidateDigest: d(8, 32), authorityPolicyDigest: d(9, 32),
            operationDigest: d(10, 32), restorationDigest: d(11, 32), mutationFootprintDigest: d(12, 32),
            authorityGrantDigest: d(13, 32), targetConsentDigest: d(14, 32), administratorIntentDigest: d(15, 32))
        return try .init(id: d(16), revision: d(17), purpose: .retainedRuntime, scope: scope, phase: .draining)
    }
    private func binding(_ row: Record) throws -> AuthorityMaintenanceBinding {
        try .init(accountID: row.scope.authority.accountID, attemptID: row.id, revision: row.revision, incarnation: d(18), connectionID: d(19))
    }
    private func fields(_ row: Record) throws -> [UInt64: CBORValue] {
        guard case .map(let f) = try DeterministicCBOR.decode(row.encoded, limits: limits) else { throw RuntimePreparationError.invalidRecord }; return f
    }
    private func decode(_ f: [UInt64: CBORValue]) throws -> Record {
        try .decode(DeterministicCBOR.encode(.map(f), limits: limits))
    }
    func testBindingAdvancesTheRevisionWhileKeepingAllFiveOriginalValues() throws {
        let old = try base(), target = try binding(old), next = try old.retainingShutdownBinding(target, revision: d(20))
        XCTAssertNotEqual(next.revision, old.revision); XCTAssertEqual(next.shutdownBinding, target)
        XCTAssertEqual(next.shutdownBinding?.revision, old.revision); XCTAssertEqual(next.scope, old.scope)
        XCTAssertEqual(next.formatVersion, 2); try next.requireReplacing(old)
        XCTAssertEqual(try Record.decode(next.encoded), next)
    }
    func testSameRevisionStillRefusesAndTheBindingCanBeAssignedOnlyOnce() throws {
        let old = try base(), target = try binding(old), same = try old.retainingShutdownBinding(target, revision: old.revision)
        XCTAssertThrowsError(try same.requireReplacing(old)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
        let next = try old.retainingShutdownBinding(target)
        XCTAssertThrowsError(try next.retainingShutdownBinding(target))
        var changed = try fields(next); changed[3] = .bytes(d(21))
        XCTAssertThrowsError(try decode(changed).requireReplacing(next))
    }
    func testTheBindingAssignmentCannotChangeAnyOtherWindowField() throws {
        let old = try base(), next = try old.retainingShutdownBinding(binding(old))
        for (key, value) in [(UInt64(4), CBORValue.unsigned(Record.Purpose.markerReplacement.rawValue)),
                             (8, .unsigned(Record.ServiceOutcome.unknown.rawValue)),
                             (9, .unsigned(Record.Failure.busy.rawValue))] {
            var f = try fields(next); f[key] = value
            XCTAssertThrowsError(try decode(f).requireReplacing(old))
        }
        var f = try fields(next); f[6] = .unsigned(Record.Phase.stopping.rawValue)
        XCTAssertThrowsError(try decode(f).requireReplacing(old))
    }
    func testWrongAccountAttemptOrOriginalRevisionCannotBeInstalled() throws {
        let row = try base(), good = try binding(row)
        for index in 0..<3 {
            let wrong = try AuthorityMaintenanceBinding(accountID: index == 0 ? d(99) : good.accountID,
                attemptID: index == 1 ? d(99) : good.attemptID, revision: index == 2 ? d(99) : good.revision,
                incarnation: good.incarnation, connectionID: good.connectionID)
            XCTAssertThrowsError(try row.retainingShutdownBinding(wrong).requireReplacing(row))
        }
    }
    func testEveryInstalledBindingValueRemainsExactDuringLaterTransitions() throws {
        let old = try base(), target = try binding(old), installed = try old.retainingShutdownBinding(target)
        for index in 0..<5 {
            let wrong = try AuthorityMaintenanceBinding(accountID: index == 0 ? d(99) : target.accountID,
                attemptID: index == 1 ? d(99) : target.attemptID, revision: index == 2 ? d(99) : target.revision,
                incarnation: index == 3 ? d(99) : target.incarnation, connectionID: index == 4 ? d(99) : target.connectionID)
            var f = try fields(installed); f[3] = .bytes(d(21)); f[6] = .unsigned(Record.Phase.stopping.rawValue); f[11] = .bytes(try wrong.encoded)
            XCTAssertThrowsError(try decode(f).requireReplacing(installed))
        }
        for phase in [Record.Phase.stopping, .needsOwnerRecovery] {
            var f = try fields(installed); f[0] = .unsigned(1); f[11] = nil; f[3] = .bytes(d(21)); f[6] = .unsigned(phase.rawValue)
            if phase == .needsOwnerRecovery { f[9] = .unsigned(Record.Failure.repairRequired.rawValue) }
            XCTAssertThrowsError(try decode(f).requireReplacing(installed)) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
        }
    }
    func testOnlyRestoredDropsTheBindingAndReturnsToTheFrozenVersionOneEncoding() throws {
        let old = try base(), target = try binding(old)
        var row = try old.retainingShutdownBinding(target)
        let steps: [(Record.Phase, Record.OperationOutcome, Record.ServiceOutcome)] = [
            (.stopping, .notStarted, .notStopped), (.stopped, .notStarted, .stopped), (.executing, .unknown, .stopped),
            (.workSettled, .committed, .stopped), (.restoring, .committed, .restartPending), (.reopenPending, .committed, .healthy)]
        for (index, step) in steps.enumerated() {
            let next = try Record(id: row.id, revision: d(UInt8(30 + index)), purpose: row.purpose, scope: row.scope,
                phase: step.0, operation: step.1, service: step.2, shutdownBinding: target)
            try next.requireReplacing(row); XCTAssertEqual(next.formatVersion, 2); row = next
        }
        let gate = try Record.GateReadback(attemptID: row.id, requestRevision: row.revision, identity: .init(device: 1, inode: 2),
            authorityIncarnation: target.incarnation, challenge: d(40), responseDigest: d(41, 32), hold: .released, admission: .available)
        let restored = try Record(id: row.id, revision: d(42), purpose: row.purpose, scope: row.scope, phase: .restored,
            operation: .committed, service: .healthy, gate: gate)
        try restored.requireReplacing(row); XCTAssertNil(restored.shutdownBinding); XCTAssertEqual(restored.formatVersion, 1)
        XCTAssertEqual(try FrozenMaintenanceWindowReader1.decode(restored.encoded).encoded, try restored.encoded)
        XCTAssertThrowsError(try Record(id: row.id, revision: d(42), purpose: row.purpose, scope: row.scope, phase: .restored,
            operation: .committed, service: .healthy, gate: gate, shutdownBinding: target))
    }
    func testFrozenReaderOneAcceptsLegacyBytesAndRefusesAnOpenVersionTwoWithoutCrashing() throws {
        let old = try base(), upgraded = try old.retainingShutdownBinding(binding(old))
        XCTAssertEqual(try FrozenMaintenanceWindowReader1.decode(old.encoded).encoded, try old.encoded)
        XCTAssertThrowsError(try FrozenMaintenanceWindowReader1.decode(upgraded.encoded))
        let projection = RuntimeMaintenanceAdmissionProjection.startup { () throws -> RuntimeMaintenanceAdmissionProjection in
            _ = try FrozenMaintenanceWindowReader1.decode(upgraded.encoded)
            throw RuntimePreparationError.changedScope
        }
        XCTAssertTrue(projection.requiresLocalHold); XCTAssertTrue(projection.needsOwnerRecovery)
    }
    func testVersionTwoRequiresTheCanonicalCompleteBindingAndTheExactFieldSet() throws {
        let old = try base(), upgraded = try old.retainingShutdownBinding(binding(old)), original = try fields(upgraded)
        for value in [CBORValue.null, .bytes(Data()), .bytes(Data([0xff]))] {
            var f = original; f[11] = value; XCTAssertThrowsError(try decode(f))
        }
        var f = original; f[11] = nil; XCTAssertThrowsError(try decode(f))
        f = original; f[0] = .unsigned(1); XCTAssertThrowsError(try decode(f))
        f = original; f[12] = .null; XCTAssertThrowsError(try decode(f))
    }
}
