import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owns fixture records only. The closures resolve the current store after each reopen.
struct RetainedRuntimeCompatibilityFixture {
    let readMachine: () -> PreparationIntentStore
    let candidate: SignedReleaseEvidence
    let owner: LocalAccountIdentity
    let plan: RuntimeRetainedSetupActivationPlan
    let injectRow: (Data, Data, Data?, Int) throws -> Void
    let createImportJournal: () throws -> Void
    var machine: PreparationIntentStore { readMachine() }

    func inject(bytes: Data? = nil, materialID: Data? = nil, digest: Data? = nil, registered: Int = 0) throws {
        try injectRow(bytes ?? plan.encoded, materialID ?? plan.reference.materialID, digest, registered)
    }
    func capture() throws -> MachineUpdateRetainedSetupActivationSnapshot {
        try machine.retainedSetupActivationSnapshot(owner: owner, candidate: candidate)
    }
    func read(_ snapshot: MachineUpdateRetainedSetupActivationSnapshot) throws -> RuntimeReleaseCompatibilitySnapshot {
        try machine.stableRuntimeCompatibilitySnapshot(expected: snapshot.runtime.setup.source,
            retained: [snapshot], candidate: candidate)
    }
}

final class RuntimeStableCompatibilityTests: XCTestCase {
    private func fixture(_ body: (RetainedRuntimeCompatibilityFixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedRuntimeCompatibilityFixture(body)
    }

    func testTwoRetainedOwnersResolveOutsideTransactionsAndRefuseUnavailableOrChangedIdentities() throws {
        try MachineUpdateReplacementTests.withTwoRetainedRuntimeCompatibilityFixtures { fixtures in
            XCTAssertEqual(fixtures.count, 2)
            let first = try XCTUnwrap(fixtures.first), snapshots = try fixtures.map { try $0.capture() }
            let source = try XCTUnwrap(snapshots.first).runtime.setup.source
            let owners = Dictionary(uniqueKeysWithValues: fixtures.map { ($0.owner.uid, $0.owner) })
            XCTAssertEqual(owners.count, 2)
            var lookedUp: [UInt32] = []
            func capture() throws -> RuntimeReleaseCompatibilitySnapshot {
                try RuntimeStableCompatibilityCapture.capture(machine: first.machine, expected: source,
                    candidate: first.candidate, lookup: { uid in
                        XCTAssertNoThrow(try first.machine.inventory())
                        lookedUp.append(uid)
                        return try XCTUnwrap(owners[uid])
                    })
            }
            let result = try capture()
            XCTAssertEqual(Set(lookedUp), Set(owners.keys))
            let retained = try result.inputs.runtimes.compactMap { runtime -> Data? in
                guard let bytes = runtime.activationRecord,
                      case .retained = try RuntimeActivationCompatibilityProjection.decode(bytes) else { return nil }
                return runtime.reference.services.accountID
            }
            XCTAssertEqual(Set(retained), Set(fixtures.map { $0.plan.accountID }))
            for missing in owners.keys {
                XCTAssertThrowsError(try RuntimeStableCompatibilityCapture.capture(machine: first.machine,
                    expected: source, candidate: first.candidate, lookup: { uid in
                        XCTAssertNoThrow(try first.machine.inventory())
                        guard uid != missing else { throw LocalAccountLookupError.missing }
                        return try XCTUnwrap(owners[uid])
                    })) {
                    XCTAssertEqual($0 as? RuntimeActivationCompatibilityError, .ownerUnavailable(missing))
                }
                XCTAssertNoThrow(try first.machine.inventory())
                XCTAssertNoThrow(try capture())
                XCTAssertThrowsError(try RuntimeStableCompatibilityCapture.capture(machine: first.machine,
                    expected: source, candidate: first.candidate, lookup: { uid in
                        let owner = try XCTUnwrap(owners[uid])
                        return uid == missing
                            ? .init(uid: owner.uid, primaryGroupID: owner.primaryGroupID, directoryID: UUID()) : owner
                    })) {
                    XCTAssertEqual($0 as? RuntimeActivationCompatibilityError, .ownerIdentityChanged(missing))
                }
                XCTAssertNoThrow(try capture())
            }
        }
    }

    func testDirectoryLookupCannotReturnAFrameChangedAfterEnumeration() throws {
        try fixture { f in
            try f.inject(); let retained = try f.capture(), source = retained.runtime.setup.source
            XCTAssertNoThrow(try f.read(retained))
            var calls = 0
            XCTAssertThrowsError(try RuntimeStableCompatibilityCapture.capture(machine: f.machine,
                expected: source, candidate: f.candidate, lookup: { uid in
                    XCTAssertNoThrow(try f.machine.inventory())
                    XCTAssertEqual(uid, f.owner.uid); calls += 1
                    try f.createImportJournal()
                    return f.owner
                })) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(calls, 1)
            XCTAssertNoThrow(try f.machine.inventory())
        }
    }

    func testStableV6AndOrdinaryRefusalKeepTheStoreUsable() throws {
        try fixture { f in
            try f.inject()
            let retained = try f.capture(), before = try f.machine.inventory()
            let snapshot = try f.read(retained)
            let runtime = try XCTUnwrap(snapshot.inputs.runtimes.first { $0.reference == f.plan.reference })
            XCTAssertEqual(runtime.activationRecord, try f.plan.encoded)
            XCTAssertFalse(runtime.jobsRegistered)
            XCTAssertEqual(snapshot.inputs.schemaVersion, 25)
            XCTAssertEqual(try f.machine.inventory(), before)
            XCTAssertThrowsError(try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertEqual(try f.machine.inventory(), before)
            XCTAssertNoThrow(try f.read(retained))
        }
    }

    func testMissingDuplicateAndExtraSnapshotsRefuseWithoutQuarantine() throws {
        try fixture { f in
            let empty = try f.capture()
            try f.inject()
            let retained = try f.capture(), source = retained.runtime.setup.source
            for (provided, error) in [([], RuntimeActivationCompatibilityError.missingRetainedSnapshot),
                ([retained, retained], .unexpectedRetainedSnapshot), ([empty], .unexpectedRetainedSnapshot),
                ([retained, empty], .unexpectedRetainedSnapshot)] {
                XCTAssertThrowsError(try f.machine.stableRuntimeCompatibilitySnapshot(expected: source,
                    retained: provided, candidate: f.candidate)) {
                    XCTAssertEqual($0 as? RuntimeActivationCompatibilityError, error)
                }
                XCTAssertNoThrow(try f.machine.inventory())
                XCTAssertNoThrow(try f.read(retained))
            }
        }
    }

    func testForeignSnapshotCannotCoverAnotherAccount() throws {
        try fixture { f in
            try f.inject(); let current = try f.capture()
            try fixture { other in
                try other.inject(); let foreign = try other.capture()
                XCTAssertNotEqual(current.runtime.preparation.accountID, foreign.runtime.preparation.accountID)
                XCTAssertThrowsError(try f.machine.stableRuntimeCompatibilitySnapshot(expected: current.runtime.setup.source,
                    retained: [foreign], candidate: f.candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertNoThrow(try f.read(current))
            }
        }
    }

    func testStaleSnapshotRefusesAfterAnotherValidV6RowReplacesIt() throws {
        try fixture { f in
            try f.inject(); let before = try f.capture()
            XCTAssertNoThrow(try f.read(before))
            let archive = f.plan.archive
            let changed = try RuntimeRetainedSetupActivationArchive(reference: archive.reference,
                bundlePath: archive.bundlePath, host: archive.host, transport: archive.transport,
                gatewaySettingsHost: archive.gatewaySettingsHost, phoneRoutingVersion: 1,
                phoneAuditVersion: archive.phoneAuditVersion, phoneUpdateSchedulingVersion: archive.phoneUpdateSchedulingVersion,
                binding: archive.binding, inventory: archive.inventory)
            XCTAssertNotEqual(try changed.encoded, try f.plan.encoded)
            try f.inject(bytes: changed.encoded)
            let current = try f.capture()
            XCTAssertThrowsError(try f.machine.stableRuntimeCompatibilitySnapshot(expected: current.runtime.setup.source,
                retained: [before], candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertNoThrow(try f.read(current))
            XCTAssertNoThrow(try f.machine.inventory())
        }
    }

    func testStableReadRetainsAllMixedAccountRowsAndRequirements() throws {
        try fixture { f in
            try f.inject(); let retained = try f.capture(), snapshot = try f.read(retained)
            XCTAssertGreaterThan(snapshot.inputs.runtimes.count, 1)
            let decoded = try snapshot.inputs.runtimes.compactMap { runtime in
                try runtime.activationRecord.map(RuntimeActivationCompatibilityProjection.decode)
            }
            XCTAssertTrue(decoded.contains { if case .ordinary = $0 { return true }; return false })
            XCTAssertTrue(decoded.contains { if case .retained = $0 { return true }; return false })
            XCTAssertEqual(Set(snapshot.inputs.runtimes.map { $0.reference.services.accountID }).count,
                snapshot.inputs.runtimes.count)
            XCTAssertEqual(snapshot.inputs.runtimes.filter {
                $0.activationRecord == (try? f.plan.encoded)
            }.count, 1)
            for runtime in snapshot.inputs.runtimes {
                if let bytes = runtime.activationRecord {
                    let projection = try RuntimeActivationCompatibilityProjection.decode(bytes)
                    for role in [AuthorityCodeRole.authority, .setupController] {
                        let requirement = try XCTUnwrap(snapshot.requirements.formats.first {
                            $0.role == role && $0.name == RuntimeActivationPlan.formatName
                        })
                        XCTAssertTrue(requirement.readVersions.contains(projection.formatVersion))
                    }
                }
            }
            try retained.runtime.setup.source.requireSame(as: f.machine.stableRuntimeSource(candidate: f.candidate))
        }
    }

    func testCorruptColumnsAndMalformedRowsStillMakeTheStoreUnavailable() throws {
        try fixture { f in
            let valid = try f.plan.encoded
            for (bytes, material, digest) in [(valid, AccountPreparationIntent.randomID(), Optional<Data>.none),
                (valid, f.plan.reference.materialID, Data(repeating: 0, count: 32)),
                (valid + Data([0]), f.plan.reference.materialID, nil)] {
                try f.inject(); XCTAssertNoThrow(try f.read(f.capture()))
                try f.inject(bytes: bytes, materialID: material, digest: digest)
                let source = try f.machine.stableRuntimeSource(candidate: f.candidate)
                XCTAssertThrowsError(try f.machine.stableRuntimeCompatibilitySnapshot(expected: source,
                    retained: [], candidate: f.candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
                XCTAssertThrowsError(try f.machine.inventory()) {
                    XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
                }
            }
            try f.inject(); XCTAssertNoThrow(try f.read(f.capture()))
        }
    }

    func testChangedExternalImportEvidenceRefusesTheOldStableFrameWithoutQuarantine() throws {
        try fixture { f in
            try f.inject(); let retained = try f.capture(), before = try f.read(retained)
            XCTAssertNil(before.inputs.sharedImport)
            try f.createImportJournal()
            let current = try f.machine.stableRuntimeSource(candidate: f.candidate)
            XCTAssertNotEqual(current.actual.currentRowsDigest, retained.runtime.setup.source.actual.currentRowsDigest)
            XCTAssertThrowsError(try f.read(retained)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertNoThrow(try f.machine.inventory())
        }
    }

    func testAValidForeignV6RowCannotPassTheAccountColumnCheck() throws {
        try fixture { f in
            try f.inject(); XCTAssertNoThrow(try f.read(f.capture()))
            try fixture { other in
                XCTAssertNotEqual(other.plan.accountID, f.plan.accountID)
                XCTAssertNoThrow(try RuntimeRetainedSetupActivationPlan.decode(other.plan.encoded))
                try f.inject(bytes: other.plan.encoded, materialID: other.plan.reference.materialID)
                let source = try f.machine.stableRuntimeSource(candidate: f.candidate)
                XCTAssertThrowsError(try f.machine.stableRuntimeCompatibilitySnapshot(expected: source,
                    retained: [], candidate: f.candidate)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
            }
        }
    }

    func testRegistrationCannotBeInventedByTheCompatibilityCaller() throws {
        try fixture { f in
            try f.inject(); let actual = try f.capture()
            XCTAssertNoThrow(try f.read(actual))
            XCTAssertThrowsError(try MachineUpdateRetainedSetupActivationSnapshot(runtime: actual.runtime,
                state: .init(plan: actual.state.plan, jobsRegistered: true), intent: actual.intent,
                candidate: f.candidate)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
            XCTAssertNoThrow(try f.read(actual))
        }
    }
}
