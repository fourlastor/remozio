import Foundation
import XCTest
@testable import RemozioCore

/// Owned metadata fixtures prove no protected file custody, service identity, hardware key, or native startup.
final class MachineUpdateRetainedSetupMaterialValueTests: XCTestCase {
    private typealias Frame = MachineUpdateRetainedSetupMaterialSnapshot
    private func fixture(_ body: (PreparationIntentStore, SignedReleaseEvidence, Frame) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedMaterialValueFixture(body)
    }
    private func value(_ before: Frame, reference: RuntimeMaterialReference?, published: Bool = false) throws -> Frame {
        let runtime = try MachineUpdateStableRuntimePreparationSnapshot(setup: before.runtime.setup,
            services: .init(plan: before.runtime.plan, complete: true),
            state: .init(reference: reference, configurationPublished: published),
            reservedNumbers: before.runtime.reservedNumbers)
        return try .init(runtime: runtime, activation: before.activation)
    }

    func testActualRetainedFrameKeepsUnpublishedConfigurationAndNoActivation() throws {
        try fixture { machine, candidate, frame in
            XCTAssertEqual(frame.runtime.setup.account?.origin, .retained)
            XCTAssertEqual(frame.runtime.setup.account?.inInventory, false)
            XCTAssertFalse(frame.runtime.state.configurationPublished)
            XCTAssertNil(frame.activation.plan); XCTAssertFalse(frame.activation.jobsRegistered)
            try frame.requireSame(as: frame)
            try frame.requireCurrent(machine: machine, candidate: candidate)
            try frame.requireRetained(XCTUnwrap(frame.runtime.state.reference), from: frame)
        }
    }

    func testReferenceComparisonAllowsOnlyTheExactUnpublishedTransition() throws {
        try fixture { _, _, frame in
            let reference = try XCTUnwrap(frame.runtime.state.reference)
            // Local comparison controls model an absent row. The fixture's actual retained row remains unchanged.
            let missing = try value(frame, reference: nil)
            try frame.requireRetained(reference, from: missing)
            XCTAssertThrowsError(try missing.requireRetained(reference, from: frame)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
        }
    }

    func testDifferentHistoricalReferenceStopsWithoutReplacingMaterial() throws {
        try fixture { _, _, frame in
            let now = Date()
            let material = try RuntimePreparationMaterial.create(services: frame.runtime.plan,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
            let different = try material.reference
            XCTAssertNotEqual(different, frame.runtime.state.reference)
            XCTAssertThrowsError(try frame.requireReference(different)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertThrowsError(try self.value(frame, reference: different).requireRetained(different, from: frame)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
        }
    }

    func testPublishedMetadataCannotEnterTheRetainedMaterialFrame() throws {
        try fixture { _, _, frame in
            XCTAssertThrowsError(try value(frame, reference: XCTUnwrap(frame.runtime.state.reference), published: true)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
        }
    }

    func testRegisteredJobsCannotEnterTheRetainedMaterialFrame() throws {
        try fixture { _, _, frame in
            // A negative local control grants no native registration fact.
            XCTAssertThrowsError(try Frame(runtime: frame.runtime, activation: .init(plan: nil, jobsRegistered: true))) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
        }
    }
}
