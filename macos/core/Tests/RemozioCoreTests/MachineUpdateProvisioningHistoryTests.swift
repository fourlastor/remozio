import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MachineUpdateProvisioningHistoryTests: XCTestCase {
    private typealias Source = (inventory: InstallationInventory, preparation: AccountPreparationIntent, key: Data)
    private func source() throws -> Source {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner fixture") }
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        return try (XCTUnwrap(machine.inventory()), f.begin(machine), f.key)
    }
    private func inventory(_ value: InstallationInventory, revision: Data? = nil, release: Data? = nil,
        macID: Data? = nil, installationID: Data? = nil, bundlePath: String? = nil) throws -> InstallationInventory {
        try .init(macID: macID ?? value.macID, installationID: installationID ?? value.installationID,
            revision: revision ?? value.revision, bundlePath: bundlePath ?? value.bundlePath,
            releaseDigest: release ?? value.releaseDigest, accounts: value.accounts, services: value.services,
            formatVersion: value.formatVersion)
    }
    private func preparation(_ value: AccountPreparationIntent, setupID: Data? = nil,
        directoryID: UUID? = nil, release: Data? = nil) throws -> AccountPreparationIntent {
        try .init(setupID: setupID ?? value.setupID, revision: value.revision, macID: value.macID,
            installationID: value.installationID, releaseDigest: release ?? value.releaseDigest,
            accountID: value.accountID, ownerUID: value.ownerUID, directoryID: directoryID ?? value.directoryID,
            policyBytes: value.policyBytes, initializationBytes: value.initializationBytes,
            authorityPublicKey: value.authorityPublicKey, storagePrepared: value.storagePrepared)
    }
    private var limits: CBORLimits { get throws {
        try .init(maxBytes: MachineUpdateProvisioningHistory.maximumBytes + 1024, maxDepth: 3, maxItems: 2048)
    } }
    private func changed(_ value: MachineUpdateProvisioningHistory,
        edit: (inout [UInt64: CBORValue]) throws -> Void) throws -> Data {
        guard case .map(var fields) = try DeterministicCBOR.decode(value.encoded, limits: limits) else {
            throw PreparationStoreError.corruptRecord
        }
        try edit(&fields)
        return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testHistoryRetainsTheExactOriginalInventoryAndRoundTrips() throws {
        let f = try source(), record = try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [f.preparation])
        let decoded = try MachineUpdateProvisioningHistory.decode(record.encoded)
        XCTAssertEqual(decoded, record)
        XCTAssertEqual(try decoded.inventory(for: f.preparation, current: f.inventory), f.inventory)
        XCTAssertEqual(decoded.inventories.first?.bytes, f.inventory.canonicalBytes)
        XCTAssertEqual(String(describing: decoded), "MachineUpdateProvisioningHistory(redacted)")
        XCTAssertEqual(String(reflecting: decoded), "MachineUpdateProvisioningHistory(redacted)")
    }
    func testHistoryCarriesOriginalABytesAcrossBAndCWithoutRewritingTheirRelease() throws {
        let f = try source()
        let original = try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [f.preparation])
        let b = try inventory(f.inventory, revision: Data(repeating: 241, count: 16), release: Data(repeating: 242, count: 32))
        let afterB = try MachineUpdateProvisioningHistory.capture(current: b, preparations: [f.preparation], retained: original)
        let c = try inventory(b, revision: Data(repeating: 243, count: 16), release: Data(repeating: 244, count: 32))
        let afterC = try MachineUpdateProvisioningHistory.capture(current: c, preparations: [f.preparation],
            retained: .decode(afterB.encoded))
        XCTAssertEqual(afterC, original)
        let selected = try afterC.inventory(for: f.preparation, current: c)
        XCTAssertEqual(selected.canonicalBytes, f.inventory.canonicalBytes)
        XCTAssertNotEqual(selected.releaseDigest, b.releaseDigest); XCTAssertNotEqual(selected.releaseDigest, c.releaseDigest)
        XCTAssertEqual(f.preparation.initializationBytes, try AccountPreparationIntent.decode(f.preparation.bytes).initializationBytes)
    }
    func testHistoryRejectsMissingOriginalProvenanceAfterTheInstalledReleaseChanges() throws {
        let f = try source(), b = try inventory(f.inventory, release: Data(repeating: 242, count: 32))
        XCTAssertThrowsError(try MachineUpdateProvisioningHistory.capture(current: b, preparations: [f.preparation])) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }
    func testHistoryKeepsTheOriginalRevisionEvenWhenTheCurrentReleaseDigestMatches() throws {
        let f = try source(), original = try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [f.preparation])
        let current = try inventory(f.inventory, revision: Data(repeating: 245, count: 16))
        let next = try MachineUpdateProvisioningHistory.capture(current: current, preparations: [f.preparation], retained: original)
        XCTAssertEqual(try next.inventory(for: f.preparation, current: current), f.inventory)
        XCTAssertNotEqual(current.canonicalBytes, next.inventories.first?.bytes)
    }
    func testHistoryAllowsKeyPinProgressWithoutChangingTheReviewedInitialScope() throws {
        let f = try source(), original = try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [f.preparation])
        let pinned = try f.preparation.pinning(f.key)
        XCTAssertNotEqual(pinned.revision, f.preparation.revision)
        let next = try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [pinned], retained: original)
        XCTAssertEqual(next, original)
        XCTAssertEqual(try next.inventory(for: pinned, current: f.inventory), f.inventory)
        XCTAssertEqual(pinned.initializationBytes, f.preparation.initializationBytes)
    }
    func testHistoryRejectsSetupDirectoryAndProvisioningReleaseRebinding() throws {
        let f = try source(), original = try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [f.preparation])
        for changed in try [preparation(f.preparation, setupID: Data(repeating: 246, count: 16)),
                            preparation(f.preparation, directoryID: UUID()),
                            preparation(f.preparation, release: Data(repeating: 247, count: 32))] {
            XCTAssertThrowsError(try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [changed], retained: original))
            XCTAssertThrowsError(try original.inventory(for: changed, current: f.inventory))
        }
    }
    func testHistoryRejectsAnotherMachineInstallationOrBundlePath() throws {
        let f = try source(), original = try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [f.preparation])
        for changed in try [inventory(f.inventory, macID: Data(repeating: 248, count: 16)),
                            inventory(f.inventory, installationID: Data(repeating: 249, count: 16)),
                            inventory(f.inventory, bundlePath: "/Applications/Another.app")] {
            XCTAssertThrowsError(try MachineUpdateProvisioningHistory.capture(current: changed, preparations: [f.preparation], retained: original))
            XCTAssertThrowsError(try original.inventory(for: f.preparation, current: changed))
        }
    }
    func testHistoryDeduplicatesExactInventoriesForIndependentPreparations() throws {
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let first = try f.begin(machine), second = try f.begin(machine,
            identity: .init(uid: getuid() + 1, primaryGroupID: getgid(), directoryID: UUID()))
        let current = try XCTUnwrap(machine.inventory())
        let record = try MachineUpdateProvisioningHistory.capture(current: current, preparations: [second, first])
        XCTAssertEqual(record.accounts.count, 2); XCTAssertEqual(record.inventories.count, 1)
        XCTAssertEqual(try record.inventory(for: first, current: current), current)
        XCTAssertEqual(try record.inventory(for: second, current: current), current)
        XCTAssertEqual(try MachineUpdateProvisioningHistory.decode(record.encoded), record)
    }
    func testHistoryRejectsDuplicateAccountsAndMoreThanSixtyFourPreparations() throws {
        let f = try source()
        for values in [[f.preparation, f.preparation], Array(repeating: f.preparation, count: 65)] {
            XCTAssertThrowsError(try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: values))
        }
    }
    func testHistoryCodecRejectsMissingAlteredAndUnusedInventoryOperands() throws {
        let f = try source(), record = try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [f.preparation])
        for mutation: (inout [UInt64: CBORValue]) throws -> Void in [
            { $0[6] = .array([]) },
            { fields in
                guard case .array(var rows) = fields[6], case .map(var row) = rows[0] else { throw PreparationStoreError.corruptRecord }
                row[1] = .bytes(Data([0])); rows[0] = .map(row); fields[6] = .array(rows)
            },
            { fields in
                let other = try self.inventory(f.inventory, revision: Data(repeating: 250, count: 16)).canonicalBytes
                guard case .array(var rows) = fields[6] else { throw PreparationStoreError.corruptRecord }
                rows.append(.map([0: .bytes(MachineUpdateActivationRecord.digest(other)), 1: .bytes(other)]))
                fields[6] = .array(rows)
            }
        ] {
            XCTAssertThrowsError(try MachineUpdateProvisioningHistory.decode(changed(record, edit: mutation)))
        }
    }
    func testHistoryCodecRejectsUnknownFieldsVersionsDuplicateRowsAndTrailingBytes() throws {
        let f = try source(), record = try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [f.preparation])
        for mutation: (inout [UInt64: CBORValue]) throws -> Void in [
            { $0[0] = .unsigned(2) }, { $0[7] = .boolean(true) }, { $0[4] = .text("relative.app") },
            { fields in
                guard case .array(let rows) = fields[5] else { throw PreparationStoreError.corruptRecord }
                fields[5] = .array(rows + rows)
            }
        ] { XCTAssertThrowsError(try MachineUpdateProvisioningHistory.decode(changed(record, edit: mutation))) }
        XCTAssertThrowsError(try MachineUpdateProvisioningHistory.decode(record.encoded + Data([0])))
        XCTAssertThrowsError(try MachineUpdateProvisioningHistory.decode(Data(repeating: 0,
            count: MachineUpdateProvisioningHistory.maximumBytes + 1)))
    }
    func testEmptyHistoryProvidesNoAccountOperand() throws {
        let f = try source(), record = try MachineUpdateProvisioningHistory.capture(current: f.inventory, preparations: [])
        XCTAssertTrue(record.accounts.isEmpty); XCTAssertTrue(record.inventories.isEmpty)
        XCTAssertEqual(try MachineUpdateProvisioningHistory.decode(record.encoded), record)
        XCTAssertThrowsError(try record.inventory(for: f.preparation, current: f.inventory))
    }
    func testHistorySupportsSixtyFourIndependentPreparationsWithinItsCodecBounds() throws {
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let preparations = try (UInt32(0)..<64).map { index in
            try f.begin(machine, identity: .init(uid: getuid() + index, primaryGroupID: getgid(), directoryID: UUID()))
        }
        let current = try XCTUnwrap(machine.inventory())
        let record = try MachineUpdateProvisioningHistory.capture(current: current, preparations: preparations)
        XCTAssertEqual(record.accounts.count, 64); XCTAssertEqual(record.inventories.count, 1)
        let decoded = try MachineUpdateProvisioningHistory.decode(record.encoded)
        XCTAssertEqual(decoded, record)
        for preparation in preparations { XCTAssertEqual(try decoded.inventory(for: preparation, current: current), current) }
    }

    func testHistoryRequiresBothHostParticipantsToDeclareItsReaderAndWriter() throws {
        let f = try AccountPreparationFixture()
        let policy = try AuthorityCodePolicy(entries: f.policy.entries + [
            .init(role: .app, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos", installedGeneration: 1,
                minimumGeneration: 1, codeDirectoryHash: Data(repeating: 5, count: 20), active: true),
            .init(role: .setupController, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.setup", installedGeneration: 1,
                minimumGeneration: 1, codeDirectoryHash: Data(repeating: 6, count: 20), active: true)
        ])
        func release(omit: AuthorityCodeRole? = nil, wrongReader: AuthorityCodeRole? = nil,
            missingWriter: AuthorityCodeRole? = nil) throws -> SignedReleaseEvidence {
            try NativeHostReleaseFixture.make(policy: policy) { component in
                guard [.authority, .setupController].contains(component.role), component.role != omit else { return component }
                let readers: Set<UInt64> = component.role == wrongReader ? [2] : [1]
                let writers: Set<UInt64> = component.role == missingWriter ? [] : readers
                return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: component.formats + [.init(name: MachineUpdateProvisioningHistory.formatName,
                        readers: readers, writers: writers)], requests: component.requests)
            }
        }
        XCTAssertNoThrow(try MachineUpdateProvisioningHistory.requireFormats(release()))
        for role in [AuthorityCodeRole.authority, .setupController] {
            for value in try [release(omit: role), release(wrongReader: role), release(missingWriter: role)] {
                XCTAssertThrowsError(try MachineUpdateProvisioningHistory.requireFormats(value)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                }
            }
        }
    }

}
