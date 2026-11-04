import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeAuditUpgradeFilesTests: XCTestCase {
    private enum Interrupted: Error { case expected }
    private final class Harness {
        let base: RuntimeAuditUpgradeCutoverTests.Fixture
        let activityFixture: ReleaseActivityFixture
        let barrier: ReleaseActivityBarrier
        var token: ReleaseActivityToken
        var valid = true
        init(_ base: RuntimeAuditUpgradeCutoverTests.Fixture) throws {
            self.base = base; activityFixture = try .init(); barrier = try activityFixture.open(); token = try barrier.acquireExclusive()
        }
        deinit { token.close() }
        func verify() throws { try token.validateExclusive(); if !valid { throw Interrupted.expected } }
        func inspect(_ expectation: RuntimeAuditUpgradeFiles.Expectation) throws -> [String: RuntimeAuditUpgradeFiles.State] {
            try RuntimeAuditUpgradeFiles.validate(base.graph, directories: base.collector.files.directories, owner: getuid(),
                expectation: expectation, verifyOwnerAndBarrier: verify)
        }
        func begin(fence: Bool = true) throws -> RuntimeAuditUpgradeCutoverRecord {
            let selected = try base.select()
            if fence {
                _ = try RuntimeAuditUpgradeStartupFenceStorage.publishOwned(machine: base.runtime.machine, expected: selected,
                    installedRelease: base.release, currentPolicy: base.policy,
                    directory: XCTUnwrap(base.collector.files.directories[.services]), owner: getuid(), verifyOwnerAndBarrier: verify)
            }
            return try base.advance(selected, .filesChanging, verify: { _ = try self.inspect(.sourceOnly) })
        }
        func apply(_ record: RuntimeAuditUpgradeCutoverRecord,
                   stage: (String, AdministrativeSetupPublication.Stage) throws -> Void = { _, _ in }) throws -> [String: RuntimeAuditUpgradeFiles.State] {
            try RuntimeAuditUpgradeFiles.applyOwned(machine: base.runtime.machine, expected: record, graph: base.graph,
                installedRelease: base.release, currentPolicy: base.policy, directories: base.collector.files.directories,
                owner: getuid(), rootActivity: token, verifyOwnerAndBarrier: verify, didStage: stage)
        }
        func finish(_ record: RuntimeAuditUpgradeCutoverRecord) throws -> RuntimeAuditUpgradeCutoverRecord {
            let verified = try base.advance(record, .filesVerified, verify: { _ = try self.inspect(.targetOnly) })
            let committed = try base.commit(verified, verify: { _ = try self.inspect(.targetOnly) })
            _ = try RuntimeAuditUpgradeStartupFenceStorage.removeOwned(machine: base.runtime.machine, expected: committed,
                installedRelease: base.release, currentPolicy: base.policy,
                directory: XCTUnwrap(base.collector.files.directories[.services]), owner: getuid(),
                verifyOwnerBarrierAndTargets: { _ = try self.inspect(.targetOnly) })
            return committed
        }
        func path(_ leaf: RuntimeAuditUpgradeArtifactSnapshot.Leaf) throws -> URL {
            URL(fileURLWithPath: try XCTUnwrap(base.collector.files.directories[leaf.entry.directory]).path).appendingPathComponent(leaf.entry.file.name)
        }
        func files() throws -> [String: Data] {
            var values: [String: Data] = [:]
            for leaf in base.graph.snapshot.leaves {
                let path = try path(leaf)
                if FileManager.default.fileExists(atPath: path.path) { values[leaf.entry.key] = try Data(contentsOf: path) }
            }
            return values
        }
        func identities() throws -> [String: ProtectedStorageLease.DirectoryIdentity] {
            var values: [String: ProtectedStorageLease.DirectoryIdentity] = [:]
            for leaf in base.graph.snapshot.leaves {
                var metadata = stat()
                if lstat(try path(leaf).path, &metadata) == 0 { values[leaf.entry.key] = .init(device: metadata.st_dev, inode: metadata.st_ino) }
                else if errno != ENOENT { throw JournalLeaseError.system(errno) }
            }
            return values
        }
        func changingLeaf() throws -> RuntimeAuditUpgradeArtifactSnapshot.Leaf {
            try XCTUnwrap(base.graph.snapshot.leaves.first { $0.source != $0.target && $0.source != nil })
        }
        func assertFencePresent() throws {
            let directory = try XCTUnwrap(base.collector.files.directories[.services])
            XCTAssertTrue(FileManager.default.fileExists(atPath: directory.path + "/" + AdministrativeSetupPublication.File.auditUpgradeStartupFence.name))
        }
    }
    func testRealOwnedFilesAndMachineRowsReachTargetBeforeFenceRemoval() throws {
        let h = try Harness(.init(gateway: true, activeAndPending: true)), changing = try h.begin()
        let result = try h.apply(changing)
        XCTAssertTrue(result.values.contains(.target)); XCTAssertFalse(result.values.contains(.source))
        XCTAssertEqual(try h.base.runtime.machine.runtimePreparation(accountID: h.base.runtime.account.accountID).reference,
            h.base.graph.upgrade.intent.source)
        _ = try h.finish(changing); try h.base.assertTarget(self)
        for leaf in h.base.graph.snapshot.leaves where leaf.source != nil {
            var metadata = stat(); XCTAssertEqual(lstat(try h.path(leaf).path, &metadata), 0)
            if leaf.source == leaf.target { XCTAssertEqual(metadata.st_ino, leaf.metadata?.inode) }
            else { XCTAssertNotEqual(metadata.st_ino, leaf.metadata?.inode) }
        }
    }
    func testMissingFenceAndSharedRootActivityRefuseBeforeAnyFileChange() throws {
        for missing in [true, false] {
            let h = try Harness(.init()), changing = try h.begin(fence: !missing), before = try h.files()
            if !missing { h.token.close(); h.token = try h.barrier.acquireShared() }
            XCTAssertThrowsError(try h.apply(changing)); XCTAssertEqual(try h.files(), before)
        }
    }
    func testPublicationFaultsLeaveChangingRecordAndResumeWithoutRepeatingCompletedReplacements() throws {
        for point in [AdministrativeSetupPublication.Stage.staged, .published] {
            let h = try Harness(.init()), changing = try h.begin()
            var interrupted = false
            XCTAssertThrowsError(try h.apply(changing) { _, stage in
                if !interrupted && stage == point { interrupted = true; throw Interrupted.expected }
            })
            XCTAssertTrue(interrupted); try h.assertFencePresent()
            XCTAssertEqual(try h.base.runtime.machine.runtimeAuditCutover(accountID: h.base.runtime.account.accountID), changing)
            _ = try h.apply(changing)
            let after = try h.files(), identities = try h.identities()
            _ = try h.apply(changing); XCTAssertEqual(try h.files(), after); XCTAssertEqual(try h.identities(), identities)
            _ = try h.finish(changing); try h.base.assertTarget(self)
        }
    }
    func testImportedRunReferenceChangesAtomicallyWhileProviderReceiptIdentitiesRemainStable() throws {
        let imported = try RuntimeAuditUpgradeImportTests.Fixture(), h = try Harness(.init(imported: imported))
        let before = try XCTUnwrap(h.base.graph.snapshot.plan.sourceImport?.source), changing = try h.begin()
        var original = stat(); XCTAssertEqual(lstat(imported.runPath, &original), 0)
        _ = try h.apply(changing)
        var current = stat(); XCTAssertEqual(lstat(imported.runPath, &current), 0); XCTAssertNotEqual(current.st_ino, original.st_ino)
        let plan = try XCTUnwrap(h.base.graph.snapshot.plan.sourceImport)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: imported.runPath)), try plan.targetReference?.encoded)
        _ = try h.apply(changing)
        var retried = stat(); XCTAssertEqual(lstat(imported.runPath, &retried), 0); XCTAssertEqual(retried.st_ino, current.st_ino)
        _ = try h.finish(changing); try h.base.assertTarget(self)
        let after = try XCTUnwrap(h.base.runtime.machine.retainedRuntimeCompatibilityInputs().sharedImport?.records.first)
        XCTAssertEqual(after.relay, before.relay); XCTAssertEqual(after.relayProvisioning, before.relayProvisioning)
        XCTAssertEqual(after.accessApplication, before.accessApplication); XCTAssertEqual(after.dnsRecord, before.dnsRecord)
        XCTAssertEqual(after.runCredential?.reference, plan.targetReference)
    }
    func testUnregisteredAndPartialGatewayStatesKeepTheirOriginalPublicationFlags() throws {
        // Gateway preparation requires registered foreground jobs. Exercise the two valid staged states separately.
        for partial in [false, true] {
            let h = try Harness(.init(partialGateway: partial, registered: partial)), changing = try h.begin()
            let missing = Set(try h.base.graph.snapshot.leaves.filter { $0.source == nil }.map { try h.path($0).path })
            _ = try h.apply(changing); _ = try h.finish(changing); try h.base.assertTarget(self)
            for path in missing { XCTAssertFalse(FileManager.default.fileExists(atPath: path)) }
        }
    }
    func testTargetBytesWrittenIntoTheOldInodeDoNotCountAsAnAtomicReplacement() throws {
        let h = try Harness(.init()), changing = try h.begin(), leaf = try h.changingLeaf(), path = try h.path(leaf)
        try XCTUnwrap(leaf.target).write(to: path); XCTAssertEqual(chmod(path.path, leaf.entry.file.mode), 0)
        let before = try h.files()
        XCTAssertThrowsError(try h.apply(changing)) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertEqual(try h.files(), before); try h.assertFencePresent()
    }
    func testUnexpectedSourceBytesAndSameBytesOnAnotherInodeArePreserved() throws {
        for replaced in [false, true] {
            let h = try Harness(.init()), changing = try h.begin(), leaf = try h.changingLeaf(), path = try h.path(leaf)
            var bytes = try XCTUnwrap(leaf.source)
            if replaced { try FileManager.default.moveItem(at: path, to: path.appendingPathExtension("original")) }
            else { bytes[bytes.count - 1] ^= 1 }
            try bytes.write(to: path); XCTAssertEqual(chmod(path.path, leaf.entry.file.mode), 0)
            let before = try h.files()
            XCTAssertThrowsError(try h.apply(changing)); XCTAssertEqual(try h.files(), before); try h.assertFencePresent()
        }
    }
    func testUnchangedCapturedFilesCannotBeReplacedEvenWithTheSameBytes() throws {
        let h = try Harness(.init()), changing = try h.begin()
        let leaf = try XCTUnwrap(h.base.graph.snapshot.leaves.first { $0.source != nil && $0.source == $0.target })
        let path = try h.path(leaf); try FileManager.default.moveItem(at: path, to: path.appendingPathExtension("original"))
        try XCTUnwrap(leaf.source).write(to: path); XCTAssertEqual(chmod(path.path, leaf.entry.file.mode), 0)
        let before = try h.files()
        XCTAssertThrowsError(try h.apply(changing)); XCTAssertEqual(try h.files(), before)
    }
    func testOwnerLossAfterOnePublicationKeepsFenceAndAllowsFreshScopeRecovery() throws {
        let h = try Harness(.init()), changing = try h.begin(); var stopped = false
        XCTAssertThrowsError(try h.apply(changing) { _, stage in
            if !stopped && stage == .published { stopped = true; h.valid = false }
        })
        XCTAssertTrue(stopped); try h.assertFencePresent()
        h.valid = true; _ = try h.apply(changing); _ = try h.finish(changing)
    }
    func testSourceIdentityChangeDuringStagingRefusesTheSwap() throws {
        let h = try Harness(.init()), changing = try h.begin(); var changed: URL?
        XCTAssertThrowsError(try h.apply(changing) { key, stage in
            guard changed == nil, stage == .staged else { return }
            let leaf = try XCTUnwrap(h.base.graph.snapshot.leaves.first { $0.entry.key == key })
            let path = try h.path(leaf); changed = path
            try FileManager.default.moveItem(at: path, to: path.appendingPathExtension("original"))
            try XCTUnwrap(leaf.source).write(to: path); XCTAssertEqual(chmod(path.path, leaf.entry.file.mode), 0)
        })
        let path = try XCTUnwrap(changed), leaf = try XCTUnwrap(h.base.graph.snapshot.leaves.first { (try? h.path($0)) == path })
        XCTAssertEqual(try Data(contentsOf: path), leaf.source); try h.assertFencePresent()
    }
    func testStaleDurablePhaseDoesNotStartFileMutation() throws {
        let h = try Harness(.init()), changing = try h.begin(), before = try h.files()
        _ = try h.base.advance(changing, .filesVerified)
        XCTAssertThrowsError(try h.apply(changing)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
        XCTAssertEqual(try h.files(), before)
    }
    func testNativeFileApplicationRefusesOrdinaryIdentityBeforeOpeningDirectories() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary owner") }
        let h = try Harness(.init()), changing = try h.begin()
        XCTAssertThrowsError(try RuntimeAuditUpgradeFiles.apply(machine: h.base.runtime.machine, expected: changing,
            graph: h.base.graph, installedRelease: h.base.release, currentPolicy: h.base.policy, rootActivity: h.token,
            verifyOwnerAndBarrier: { XCTFail("Root guard must precede filesystem access") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
    }
}
