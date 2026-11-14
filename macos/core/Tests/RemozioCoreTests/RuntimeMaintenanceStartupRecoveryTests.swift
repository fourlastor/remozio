import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses owned SQLite metadata. These tests do not start a native host or release an admission token.
final class RuntimeMaintenanceStartupRecoveryTests: XCTestCase {
    private typealias Projection = RuntimeMaintenanceAdmissionProjection
    private typealias Storage = RuntimeMaintenanceWindowStorage
    private func fixture(_ body: (RuntimeMaintenanceReaderFixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceReaderFixture(body)
    }
    private func requireRecovery(_ value: Projection, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(value.requiresLocalHold, file: file, line: line)
        XCTAssertTrue(value.needsOwnerRecovery, file: file, line: line)
        XCTAssertNil(value.attemptID, file: file, line: line)
        XCTAssertNil(value.revision, file: file, line: line)
        XCTAssertEqual(value.description, "RuntimeMaintenanceAdmissionProjection(redacted)", file: file, line: line)
    }
    func testCorruptWindowReadBecomesStartupHoldInsteadOfAnError() throws {
        try fixture { f in
            let account = f.authority.accountID.map { String(format: "%02x", $0) }.joined()
            try f.edit([Storage.createSQL, "PRAGMA user_version=29",
                "INSERT INTO runtime_maintenance_windows_v1 VALUES(X'\(account)',zeroblob(16),zeroblob(16),1,X'01')"])
            let value = f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate)
            requireRecovery(value)
            XCTAssertThrowsError(try f.machine().inventory()) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
        }
    }
    func testMissingReaderRequirementsBecomeStartupHold() throws {
        try fixture { f in
            try f.edit([Storage.createSQL, "PRAGMA user_version=29"])
            let components = try f.candidate.manifest.components.map { component in
                try ReleaseComponent(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: component.formats.filter { $0.name != RuntimeMaintenanceWindowRecord.formatName },
                    requests: component.requests)
            }
            let old = try SignedReleaseEvidence(manifest: .init(release: f.candidate.manifest.release, build: f.candidate.manifest.build,
                components: components, dependencies: f.candidate.manifest.dependencies), codeDirectoryHashes: f.candidate.codeDirectoryHashes,
                dependencyCodeDirectoryHashes: f.candidate.dependencyCodeDirectoryHashes)
            requireRecovery(f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: old))
        }
    }
    func testIncompatibleStoreOpeningIsInsideTheStartupBoundary() throws {
        try fixture { f in
            var opened = false
            let value = Projection.startup {
                try f.edit(["CREATE TABLE runtime_maintenance_windows_v1(account BLOB PRIMARY KEY,attempt BLOB,revision BLOB,phase INTEGER,record BLOB) STRICT",
                    "PRAGMA user_version=29"])
                opened = true
                return f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate)
            }
            XCTAssertFalse(opened)
            requireRecovery(value)
        }
    }
    func testHealthyReadStaysOpenAndClosedConnectionBecomesRecovery() throws {
        try fixture { f in
            let healthy = f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate)
            XCTAssertFalse(healthy.requiresLocalHold); XCTAssertFalse(healthy.needsOwnerRecovery)
            XCTAssertEqual(Projection.startup { healthy }, healthy)
            try f.machine().close()
            requireRecovery(f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate))
        }
    }
}
