import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// These values grant no writer authority. A01 still needs private authorization and the digest of every other row.
final class StableAccountReservationValueTests: XCTestCase {
    private struct Control {
        let source: MachineUpdateStableRuntimeSource
        let candidate: SignedReleaseEvidence
        let owner: LocalAccountIdentity
        let value: AccountPreparationIntent
        let before: MachineUpdateStableAccountSetupSnapshot
        let after: MachineUpdateStableAccountSetupSnapshot

        init(source: MachineUpdateStableRuntimeSource, candidate: SignedReleaseEvidence,
            owner suppliedOwner: LocalAccountIdentity? = nil) throws {
            self.source = source; self.candidate = candidate
            let uid = try XCTUnwrap(source.accounts.map(\.ownerUID).max()) + 1
            owner = suppliedOwner ?? .init(uid: uid, primaryGroupID: uid, directoryID: UUID())
            before = try .init(source: source, owner: owner)
            XCTAssertNil(before.account)
            let template = try XCTUnwrap(source.preparations.first).initialAuthority
            var account = AccountPreparationIntent.randomID()
            while source.accounts.contains(where: { $0.accountID == account }) { account = AccountPreparationIntent.randomID() }
            let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(source.actual.inventory.macID), 2: .bytes(account),
                3: .bytes(AccountPreparationIntent.randomID()), 4: .unsigned(1),
                5: .unsigned(AuditEpochCause.initial.rawValue), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
            let initial = AuthorityJournalInitialization(descriptor: descriptor, codePolicy: template.codePolicy,
                capabilities: template.capabilities, allowedContracts: template.allowedContracts)
            let policy = try CommandElevationPolicy(macID: source.actual.inventory.macID, accountID: account,
                callerUID: owner.uid, allowedTargetUIDs: [0], independentPolicyDisclosureAccepted: true)
            value = try .init(setupID: AccountPreparationIntent.randomID(), revision: AccountPreparationIntent.randomID(),
                macID: source.actual.inventory.macID, installationID: source.actual.inventory.installationID,
                releaseDigest: source.actual.inventory.releaseDigest, accountID: account, ownerUID: owner.uid,
                directoryID: owner.directoryID, policyBytes: policy.canonicalBytes, initializationBytes: initial.initializationBytes)
            var digest = source.actual.currentRowsDigest
            digest[0] ^= 1
            let actual = Self.frame(source.actual, digest: digest)
            after = try .init(source: .init(actual: actual, preparations: source.preparations + [value],
                initializations: source.initializations, candidate: candidate), owner: owner)
        }

        static func frame(_ base: MachineUpdateStableReleaseSnapshot, schema: Int64? = nil,
            inventory: InstallationInventory? = nil, digest: Data? = nil) -> MachineUpdateStableReleaseSnapshot {
            .init(schemaVersion: schema ?? base.schemaVersion, inventory: inventory ?? base.inventory,
                activation: base.activation, admission: base.admission, candidate: base.candidate,
                installed: base.installed, seal: base.seal, currentRowsDigest: digest ?? base.currentRowsDigest)
        }

        func snapshot(actual: MachineUpdateStableReleaseSnapshot? = nil, value: AccountPreparationIntent? = nil,
            extra: [AccountPreparationIntent] = [], initializations: [AuthorityInitializationIntent]? = nil) throws
            -> MachineUpdateStableAccountSetupSnapshot {
            try .init(source: .init(actual: actual ?? after.source.actual,
                preparations: source.preparations + [value ?? self.value] + extra,
                initializations: initializations ?? source.initializations, candidate: candidate), owner: owner)
        }

        func copiedValue(revision: Data? = nil, key: Data? = nil, prepared: Bool = false) throws -> AccountPreparationIntent {
            try .init(setupID: value.setupID, revision: revision ?? value.revision, macID: value.macID,
                installationID: value.installationID, releaseDigest: value.releaseDigest, accountID: value.accountID,
                ownerUID: value.ownerUID, directoryID: value.directoryID, policyBytes: value.policyBytes,
                initializationBytes: value.initializationBytes, authorityPublicKey: key, storagePrepared: prepared)
        }

        func valid(file: StaticString = #filePath, line: UInt = #line) throws {
            XCTAssertNoThrow(try after.requireReservation(value, from: before), file: file, line: line)
        }

        func rejects(_ snapshot: MachineUpdateStableAccountSetupSnapshot,
            value supplied: AccountPreparationIntent? = nil, before prior: MachineUpdateStableAccountSetupSnapshot? = nil,
            file: StaticString = #filePath, line: UInt = #line) throws {
            try valid(file: file, line: line)
            XCTAssertThrowsError(try snapshot.requireReservation(supplied ?? value, from: prior ?? before), file: file, line: line)
        }
    }

    private func fixture(_ body: (Control) throws -> Void) throws {
        try MachineUpdateReplacementTests.withStableAccountReservationValues { source, candidate in
            try body(Control(source: source, candidate: candidate))
        }
    }

    func testPureComparisonAcceptsTheSingleUnpreparedReservation() throws {
        try fixture { c in
            try c.valid()
            XCTAssertEqual(c.after.preparation, c.value)
            XCTAssertNil(c.value.authorityPublicKey)
            XCTAssertFalse(c.value.storagePrepared)
            XCTAssertNil(c.after.account?.initialization)
            XCTAssertEqual(c.after.account?.origin, .currentRelease)
            XCTAssertEqual(c.after.account?.inInventory, false)
            XCTAssertEqual(c.after.source.preparations.count, c.before.source.preparations.count + 1)
            XCTAssertNotEqual(c.after.source.actual.currentRowsDigest, c.before.source.actual.currentRowsDigest)
            try c.before.source.actual.seal.requireCurrentInventory(c.after.source.actual.inventory,
                epoch: c.after.source.actual.installed, candidate: c.candidate)
        }
    }

    func testChangedSchemaAndInventoryRevisionCannotPassTheComparison() throws {
        try fixture { c in
            let actual = c.after.source.actual, inventory = actual.inventory
            let changed = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID,
                revision: AccountPreparationIntent.randomID(), bundlePath: inventory.bundlePath,
                releaseDigest: inventory.releaseDigest, accounts: inventory.accounts, services: inventory.services,
                formatVersion: inventory.formatVersion)
            for frame in [Control.frame(actual, schema: actual.schemaVersion + 1), Control.frame(actual, inventory: changed)] {
                let snapshot = try c.snapshot(actual: frame)
                try c.rejects(snapshot)
            }
        }
    }

    func testAnotherValidSealedInstallationCannotReplaceTheOriginalFrame() throws {
        try fixture { c in
            try MachineUpdateReplacementTests.withStableAccountReservationValues { source, candidate in
                let other = try Control(source: source, candidate: candidate, owner: c.owner)
                try other.valid()
                XCTAssertNotEqual(try other.after.source.actual.seal.encoded, try c.after.source.actual.seal.encoded)
                try c.rejects(other.after, value: other.value)
            }
        }
    }

    func testExistingAccountChangedOperandAndChangedOwnerRefuse() throws {
        try fixture { c in
            try c.rejects(c.after, before: c.after)
            let operand = try c.copiedValue(revision: AccountPreparationIntent.randomID())
            try c.rejects(c.after, value: operand)
            let foreign = LocalAccountIdentity(uid: c.owner.uid, primaryGroupID: c.owner.primaryGroupID, directoryID: UUID())
            let before = try MachineUpdateStableAccountSetupSnapshot(source: c.source, owner: foreign)
            try c.rejects(c.after, before: before)
        }
    }

    func testPinnedKeysPreparedStorageAndOtherAccountChangesRefuse() throws {
        try fixture { c in
            let key = try XCTUnwrap(c.source.preparations.compactMap(\.authorityPublicKey).first)
            for prepared in [false, true] {
                let value = try c.copiedValue(key: key, prepared: prepared)
                let snapshot = try c.snapshot(value: value)
                try c.rejects(snapshot, value: value)
            }
            let otherOwner = LocalAccountIdentity(uid: c.owner.uid + 1, primaryGroupID: c.owner.primaryGroupID, directoryID: UUID())
            let other = try Control(source: c.source, candidate: c.candidate, owner: otherOwner)
            try other.valid()
            try c.rejects(c.snapshot(extra: [other.value]))
            XCTAssertFalse(c.source.initializations.isEmpty)
            try c.rejects(c.snapshot(initializations: Array(c.source.initializations.dropFirst())))
        }
    }

    func testValueComparisonDoesNotProveTheOtherRowsDigestOrWriterAuthority() throws {
        try fixture { c in
            try c.valid()
            // A comparison cannot authenticate this digest. The future A01 writer must capture and protect actual database rows.
            let frame = Control.frame(c.after.source.actual, digest: Data(repeating: 0xA5, count: 32))
            let values = try c.snapshot(actual: frame)
            XCTAssertNoThrow(try values.requireReservation(c.value, from: c.before))
            try c.source.requireSame(as: c.before.source)
        }
    }
}
