import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned snapshots prove no native identity, file custody, startup, or command admission.
final class MachineUpdateStableRuntimeViewInputTests: XCTestCase {
    private typealias Inputs = MachineUpdateStableRuntimeViewInputs
    private typealias Fixture = RetainedRuntimeCompatibilityFixture
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedRuntimeCompatibilityFixture(body)
    }
    private func read(_ f: Fixture, _ retained: MachineUpdateRetainedSetupActivationSnapshot) throws -> Inputs {
        try f.machine.stableRuntimeViewInputs(expected: retained.runtime.setup.source, retained: [retained], candidate: f.candidate)
    }

    func testActualBridgeKeepsMixedTypedCompatibilityAndTheOrdinaryReaderRefusal() throws {
        try fixture { f in
            try f.inject()
            let retained = try f.capture(), source = retained.runtime.setup.source
            let before = try f.machine.stableMachineUpdateSnapshot(candidate: f.candidate)
            let ordinary = try f.read(retained), actual = try read(f, retained)
            XCTAssertEqual(actual.runtime.inputs, ordinary.inputs)
            try actual.source.requireSame(as: source)
            XCTAssertEqual(actual.retained.count, 1)
            try XCTUnwrap(actual.retained.first).requireSame(as: retained)
            XCTAssertTrue(actual.currentJournals.isEmpty)
            let projections = try actual.runtime.inputs.runtimes.compactMap { runtime in
                try runtime.activationRecord.map(RuntimeActivationCompatibilityProjection.decode)
            }
            XCTAssertTrue(projections.contains { if case .retained = $0 { return true }; return false })
            XCTAssertTrue(projections.contains { if case .ordinary = $0 { return true }; return false })
            let selected = try XCTUnwrap(actual.runtime.inputs.runtimes.first { $0.reference == f.plan.reference })
            XCTAssertEqual(selected.activationRecord, try f.plan.encoded)
            XCTAssertFalse(selected.jobsRegistered)
            XCTAssertThrowsError(try RuntimeActivationPlan.decode(f.plan.encoded))
            XCTAssertThrowsError(try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try actual.requireCurrent(machine: f.machine, candidate: f.candidate)
            try read(f, retained).requireSame(as: actual)
            try f.machine.stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before)
        }
    }

    func testBridgePreservesMissingDuplicateAndStaleRetainedSnapshotRefusalsWithoutQuarantine() throws {
        try fixture { f in
            let empty = try f.capture()
            try f.inject()
            let retained = try f.capture(), source = retained.runtime.setup.source
            for (provided, error) in [([], RuntimeActivationCompatibilityError.missingRetainedSnapshot),
                ([retained, retained], .unexpectedRetainedSnapshot), ([empty], .unexpectedRetainedSnapshot),
                ([retained, empty], .unexpectedRetainedSnapshot)] {
                XCTAssertThrowsError(try f.machine.stableRuntimeViewInputs(expected: source,
                    retained: provided, candidate: f.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationCompatibilityError, error)
                }
                XCTAssertNoThrow(try f.machine.inventory())
                XCTAssertNoThrow(try read(f, retained))
                XCTAssertNoThrow(try f.read(retained))
            }
            let control = try read(f, retained)
            XCTAssertThrowsError(try Inputs(source: source, retained: [retained, retained],
                runtime: control.runtime, currentJournals: [:])) {
                XCTAssertEqual($0 as? RuntimeActivationCompatibilityError, .unexpectedRetainedSnapshot)
            }
            let extra = [Data(repeating: 211, count: 16): GatewayJournalPreparationState(intent: nil, initialized: false)]
            XCTAssertThrowsError(try Inputs(source: source, retained: [retained], runtime: control.runtime, currentJournals: extra)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            try read(f, retained).requireSame(as: control)
        }
    }

    func testTwoRetainedOwnersHaveCanonicalInputOrderAndCannotUseAForeignHeader() throws {
        try MachineUpdateReplacementTests.withTwoRetainedRuntimeCompatibilityFixtures { fixtures in
            let first = try XCTUnwrap(fixtures.first), retained = try fixtures.map { try $0.capture() }
            let source = try XCTUnwrap(retained.first).runtime.setup.source
            let left = try first.machine.stableRuntimeViewInputs(expected: source, retained: retained, candidate: first.candidate)
            let right = try first.machine.stableRuntimeViewInputs(expected: source, retained: Array(retained.reversed()), candidate: first.candidate)
            try left.requireSame(as: right)
            XCTAssertEqual(left.retained.map { $0.runtime.preparation.accountID },
                right.retained.map { $0.runtime.preparation.accountID })
            let actual = source.actual
            let changedFrame = MachineUpdateStableReleaseSnapshot(schemaVersion: actual.schemaVersion + 1,
                inventory: actual.inventory, activation: actual.activation, admission: actual.admission,
                candidate: actual.candidate, installed: actual.installed, seal: actual.seal, currentRowsDigest: actual.currentRowsDigest)
            let changed = try MachineUpdateStableRuntimeSource(actual: changedFrame, preparations: source.preparations,
                initializations: source.initializations, candidate: first.candidate)
            XCTAssertThrowsError(try Inputs(source: changed, retained: retained, runtime: left.runtime, currentJournals: left.currentJournals)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try left.requireCurrent(machine: first.machine, candidate: first.candidate)
        }
    }

    func testNewImportEvidenceInvalidatesTheFrozenInputsAndFreshCaptureKeepsTheStoreUsable() throws {
        try fixture { f in
            try f.inject()
            let before = try f.capture(), original = try read(f, before)
            try f.createImportJournal()
            XCTAssertThrowsError(try original.requireCurrent(machine: f.machine, candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertNoThrow(try f.machine.inventory())
            let retained = try f.capture(), actual = try read(f, retained)
            XCTAssertNotEqual(actual.runtime.inputs.sharedImport, original.runtime.inputs.sharedImport)
            XCTAssertThrowsError(try actual.requireSame(as: original)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try actual.requireCurrent(machine: f.machine, candidate: f.candidate)
            XCTAssertEqual(actual.runtime.inputs, try f.read(retained).inputs)
        }
    }
}
