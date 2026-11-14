import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeMaintenanceWindowRecordTests: XCTestCase {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private enum Fault: Error { case shape }
    private let wide = try! CBORLimits(maxBytes: 16384, maxDepth: 16, maxItems: 1024)
    private func bytes(_ value: UInt8, _ count: Int = 16) -> Data { Data(repeating: value, count: count) }
    private func scope() throws -> Record.Scope {
        try .init(macID: bytes(1), installationID: bytes(2),
            authority: .init(accountID: bytes(11), ownerUID: 501, directoryID: bytes(12)),
            target: .init(accountID: bytes(21), ownerUID: 1501, directoryID: bytes(22)),
            releaseDigest: bytes(31, 32), candidateDigest: bytes(32, 32), authorityPolicyDigest: bytes(33, 32),
            operationDigest: bytes(34, 32), restorationDigest: bytes(35, 32), mutationFootprintDigest: bytes(36, 32),
            authorityGrantDigest: bytes(37, 32), targetConsentDigest: bytes(38, 32), administratorIntentDigest: bytes(39, 32))
    }
    private func gate(hold: Record.GateReadback.Hold = .released, admission: Record.GateReadback.Admission = .available,
        attempt: Data? = nil) throws -> Record.GateReadback {
        try .init(attemptID: attempt ?? bytes(3), requestRevision: bytes(4), identity: .init(device: 7, inode: 17),
            authorityIncarnation: bytes(5), challenge: bytes(6), responseDigest: bytes(40, 32), hold: hold, admission: admission)
    }
    private func record(purpose: Record.Purpose = .retainedRuntime, phase: Record.Phase = .authorized,
        operation: Record.OperationOutcome = .notStarted, service: Record.ServiceOutcome = .notStopped,
        failure: Record.Failure? = nil, gate: Record.GateReadback? = nil) throws -> Record {
        try .init(id: bytes(3), revision: bytes(7), purpose: purpose, scope: scope(), phase: phase,
            operation: operation, service: service, failure: failure, gate: gate)
    }
    private func fields(_ value: Record) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(value.encoded, limits: wide) else { throw Fault.shape }
        return fields
    }
    private func decode(_ fields: [UInt64: CBORValue]) throws -> Record {
        try Record.decode(DeterministicCBOR.encode(.map(fields), limits: wide))
    }
    private func array(_ value: CBORValue?) throws -> [CBORValue] {
        guard case .array(let result)? = value else { throw Fault.shape }; return result
    }

    func testAllPurposesAndPhasesHaveExactCanonicalRoundTrips() throws {
        for purpose in Record.Purpose.allCases {
            for phase in Record.Phase.allCases {
                let early = [Record.Phase.authorized, .draining, .stopping, .stopped].contains(phase)
                let operation: Record.OperationOutcome = phase == .executing ? .unknown : early ? .notStarted : .committed
                let healthy = phase == .reopenPending || phase == .restored
                let value = try record(purpose: purpose, phase: phase, operation: operation,
                    service: healthy ? .healthy : .unknown,
                    failure: phase == .needsOwnerRecovery ? .admissionUnconfirmed : nil,
                    gate: phase == .restored ? gate() : nil)
                let encoded = try value.encoded, decoded = try Record.decode(encoded)
                XCTAssertEqual(decoded, value); XCTAssertEqual(try decoded.encoded, encoded)
                XCTAssertLessThan(encoded.count, Record.limits.maxBytes)
                XCTAssertEqual(value.description, "RuntimeMaintenanceWindowRecord(redacted)")
                XCTAssertEqual(value.debugDescription, value.description)
            }
        }
        XCTAssertEqual(try fields(record())[1], .text(Record.formatName))
    }

    func testCommittedOperationAndFailedRestorationRemainIndependent() throws {
        let committed = try record(phase: .needsOwnerRecovery, operation: .committed, service: .failed, failure: .healthFailed)
        let decoded = try Record.decode(committed.encoded)
        XCTAssertEqual(decoded.operation, .committed); XCTAssertEqual(decoded.service, .failed)
        XCTAssertEqual(decoded.phase, .needsOwnerRecovery); XCTAssertEqual(decoded.failure, .healthFailed)
        for operation in Record.OperationOutcome.allCases {
            let restored = try record(phase: .restored, operation: operation, service: .healthy, gate: gate())
            XCTAssertEqual(try Record.decode(restored.encoded).operation, operation)
        }
        XCTAssertThrowsError(try record(phase: .authorized, operation: .committed))
        XCTAssertThrowsError(try record(phase: .executing, operation: .notStarted))
        XCTAssertThrowsError(try record(phase: .needsOwnerRecovery))
        XCTAssertThrowsError(try record(phase: .reopenPending, service: .registered))
    }

    func testRestoredNeedsGateReadbackRatherThanAnAcknowledgement() throws {
        XCTAssertThrowsError(try record(phase: .restored, operation: .committed, service: .healthy))
        for hold in Record.GateReadback.Hold.allCases {
            for admission in Record.GateReadback.Admission.allCases {
                let observed = try gate(hold: hold, admission: admission)
                let pending = try record(phase: .needsOwnerRecovery, operation: .committed, service: .healthy,
                    failure: .admissionUnconfirmed, gate: observed)
                XCTAssertEqual(try Record.decode(pending.encoded).gate, observed)
                if hold == .released && admission == .available {
                    XCTAssertNoThrow(try record(phase: .restored, operation: .committed, service: .healthy, gate: observed))
                } else {
                    XCTAssertThrowsError(try record(phase: .restored, operation: .committed, service: .healthy, gate: observed))
                }
            }
        }
        XCTAssertThrowsError(try record(phase: .restored, operation: .committed, service: .healthy,
            gate: gate(attempt: bytes(99))))
        var f = try fields(record(phase: .restored, operation: .committed, service: .healthy, gate: gate()))
        f[10] = .unsigned(1); XCTAssertThrowsError(try decode(f))
        f[10] = .null; XCTAssertThrowsError(try decode(f))
    }

    func testPreStopCancellationAndRestartRemainDistinctWithNoRestoredFailure() throws {
        let cancelled = try record(phase: .restored, service: .notStopped, gate: gate())
        let restarted = try record(phase: .restored, operation: .committed, service: .healthy, gate: gate())
        XCTAssertEqual(try Record.decode(cancelled.encoded), cancelled)
        XCTAssertEqual(try Record.decode(restarted.encoded), restarted)
        XCTAssertNotEqual(cancelled.service, restarted.service)
        XCTAssertNotEqual(cancelled.operation, restarted.operation)
        XCTAssertThrowsError(try record(phase: .restored, service: .notStopped))
        for operation in Record.OperationOutcome.allCases where operation != .notStarted {
            XCTAssertThrowsError(try record(phase: .restored, operation: operation, service: .notStopped, gate: gate()))
            var changed = try fields(cancelled); changed[7] = .unsigned(operation.rawValue)
            XCTAssertThrowsError(try decode(changed))
        }
        for failure in Record.Failure.allCases {
            for value in [cancelled, restarted] {
                XCTAssertThrowsError(try record(phase: .restored, operation: value.operation,
                    service: value.service, failure: failure, gate: gate()))
                var changed = try fields(value); changed[9] = .unsigned(failure.rawValue)
                XCTAssertThrowsError(try decode(changed))
            }
        }
    }

    func testReopenPendingPreservesCancellationAndRejectsAnyStartedOperation() throws {
        let pending = try record(phase: .reopenPending, service: .notStopped)
        XCTAssertEqual(try Record.decode(pending.encoded), pending)
        for operation in Record.OperationOutcome.allCases where operation != .notStarted {
            XCTAssertThrowsError(try record(phase: .reopenPending, operation: operation, service: .notStopped))
            var changed = try fields(pending); changed[7] = .unsigned(operation.rawValue)
            XCTAssertThrowsError(try decode(changed))
            let restarted = try record(phase: .reopenPending, operation: operation, service: .healthy)
            XCTAssertEqual(try Record.decode(restarted.encoded), restarted)
        }
    }

    func testUnknownFieldsTagsVersionsEnumsAndWrongTypesRefuse() throws {
        let original = try fields(record())
        for key in original.keys {
            var f = original; f.removeValue(forKey: key); XCTAssertThrowsError(try decode(f))
        }
        var f = original; f[11] = .null; XCTAssertThrowsError(try decode(f))
        for version in [UInt64(0), 2, .max] {
            f = original; f[0] = .unsigned(version); XCTAssertThrowsError(try decode(f))
        }
        f = original; f[1] = .text("remozio-audit-upgrade-cutover"); XCTAssertThrowsError(try decode(f))
        for (key, firstUnknown) in [(UInt64(4), UInt64(4)), (6, 11), (7, 5), (8, 8), (9, 9)] {
            for value in [UInt64(0), firstUnknown, .max] {
                f = original; f[key] = .unsigned(value); XCTAssertThrowsError(try decode(f))
            }
            f = original; f[key] = .text("1"); XCTAssertThrowsError(try decode(f))
        }
        f = original; f[5] = .array([]); XCTAssertThrowsError(try decode(f))
        XCTAssertThrowsError(try Record.decode(DeterministicCBOR.encode(.array([]), limits: wide)))
    }

    func testScopeAndGateFieldSizesUIDsAndIdentitiesAreBounded() throws {
        let original = try fields(record()), scopeFields = try array(original[5])
        for index in 0..<13 where index != 2 && index != 3 {
            for count in [0, index < 2 ? 15 : 31, index < 2 ? 17 : 33] {
                var a = scopeFields; a[index] = .bytes(bytes(9, count)); var f = original; f[5] = .array(a)
                XCTAssertThrowsError(try decode(f))
            }
        }
        for index in [2, 3] {
            let account = try array(scopeFields[index])
            for uid in [UInt64(0), UInt64(UInt32.max), UInt64.max] {
                var a = scopeFields, fields = account; fields[1] = .unsigned(uid); a[index] = .array(fields)
                var f = original; f[5] = .array(a); XCTAssertThrowsError(try decode(f))
            }
            for field in [0, 2] {
                var a = scopeFields, fields = account; fields[field] = .bytes(bytes(9, 15)); a[index] = .array(fields)
                var f = original; f[5] = .array(a); XCTAssertThrowsError(try decode(f))
            }
        }
        var a = scopeFields, target = try array(a[3]), authority = try array(a[2])
        target[0] = authority[0]; a[3] = .array(target); var f = original; f[5] = .array(a); XCTAssertThrowsError(try decode(f))
        a = scopeFields; target = try array(a[3]); target[1] = authority[1]; a[3] = .array(target)
        f = original; f[5] = .array(a); XCTAssertThrowsError(try decode(f))
        a = scopeFields; target = try array(a[3]); target[2] = authority[2]; a[3] = .array(target)
        f = original; f[5] = .array(a); XCTAssertThrowsError(try decode(f))
        let restored = try fields(record(phase: .restored, operation: .committed, service: .healthy, gate: gate()))
        let readback = try array(restored[10])
        for index in 0..<9 {
            var b = readback
            switch index {
            case 2: b[index] = .unsigned(UInt64(UInt32.max) + 1)
            case 3, 7, 8: b[index] = .unsigned(0)
            default: b[index] = .bytes(bytes(9, index == 6 ? 31 : 15))
            }
            f = restored; f[10] = .array(b); XCTAssertThrowsError(try decode(f))
        }
        a = scopeFields; target = try array(a[3]); target[1] = .unsigned(UInt64(UInt32.max) - 1); a[3] = .array(target)
        f = original; f[5] = .array(a); XCTAssertNoThrow(try decode(f))
        var maximumGate = readback; maximumGate[2] = .unsigned(UInt64(UInt32.max)); maximumGate[3] = .unsigned(UInt64.max)
        f = restored; f[10] = .array(maximumGate)
        XCTAssertEqual(try decode(f).gate?.identity, PreparationFileIdentity(device: UInt32.max, inode: UInt64.max))
        for key in [UInt64(2), 3] {
            f = original; f[key] = .bytes(bytes(9, 15)); XCTAssertThrowsError(try decode(f))
        }
    }

    func testScopeComparisonBindsPurposeAttemptIdentitiesAndEveryDigest() throws {
        let value = try record(), original = try fields(value), before = try array(original[5])
        for index in 0..<13 where index != 2 && index != 3 {
            var a = before; a[index] = .bytes(bytes(99, index < 2 ? 16 : 32)); var f = original; f[5] = .array(a)
            XCTAssertThrowsError(try value.requireSameScope(as: decode(f)))
        }
        for index in [2, 3] {
            for field in 0..<3 {
                var a = before, account = try array(before[index])
                account[field] = field == 1 ? .unsigned(2501) : .bytes(bytes(99))
                a[index] = .array(account); var f = original; f[5] = .array(a)
                XCTAssertThrowsError(try value.requireSameScope(as: decode(f)))
            }
        }
        var f = original; f[2] = .bytes(bytes(99)); XCTAssertThrowsError(try value.requireSameScope(as: decode(f)))
        f = original; f[4] = .unsigned(Record.Purpose.markerReplacement.rawValue)
        XCTAssertThrowsError(try value.requireSameScope(as: decode(f)))
        f = original; f[3] = .bytes(bytes(99)); f[6] = .unsigned(Record.Phase.draining.rawValue)
        XCTAssertNoThrow(try value.requireSameScope(as: decode(f)))
    }

    func testNoncanonicalDuplicateTruncatedTrailingAndOversizeInputsRefuse() throws {
        let encoded = try record().encoded
        for end in 0..<encoded.count { XCTAssertThrowsError(try Record.decode(encoded.prefix(end))) }
        XCTAssertThrowsError(try Record.decode(encoded + Data([0])))
        XCTAssertThrowsError(try Record.decode(encoded + bytes(0, 4096)))
        XCTAssertThrowsError(try Record.decode(Data([0xab, 0, 0x18, 1]) + Data(encoded.dropFirst(3))))
        XCTAssertThrowsError(try Record.decode(Data([0xac, 0, 1]) + Data(encoded.dropFirst())))
        let a = Data([0, 1]), b = Data([1]) + (try DeterministicCBOR.encode(.text(Record.formatName), limits: wide))
        XCTAssertTrue(encoded.dropFirst().starts(with: a + b))
        XCTAssertThrowsError(try Record.decode(Data([0xab]) + b + a + Data(encoded.dropFirst(1 + a.count + b.count))))
        var deep: CBORValue = .null
        for _ in 0..<8 { deep = .array([deep]) }
        var f = try fields(record()); f[5] = deep; XCTAssertThrowsError(try decode(f))
        f[5] = .array(Array(repeating: .null, count: 130)); XCTAssertThrowsError(try decode(f))
    }
}
