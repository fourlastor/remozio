import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Disposable owned files and SQLite only. No native service stop, administrator session or protected cutover is qualified.
final class RuntimeAuditUpgradeStartupFenceTests: XCTestCase {
    private typealias Fixture = RuntimeAuditUpgradeCutoverTests.Fixture
    private struct Interrupted: Error {}
    private func directory(_ f: Fixture) throws -> ProtectedSetupDirectory { try XCTUnwrap(f.collector.files.directories[.services]) }
    private func path(_ f: Fixture) throws -> String { try directory(f).path + "/" + RuntimeAuditUpgradeStartupFence.fileName }
    private func read(_ f: Fixture) throws -> Data? {
        try ProtectedServiceConfiguration.readOptional(anchor: directory(f).path, relativePath: RuntimeAuditUpgradeStartupFence.fileName, owner: getuid())
    }
    private func gate(_ f: Fixture) throws {
        try RuntimeAuditUpgradeStartupFence.requireOpen(macID: f.runtime.account.macID, accountID: f.runtime.account.accountID, read: { try read(f) })
    }
    @discardableResult private func publish(_ f: Fixture, _ expected: RuntimeAuditUpgradeCutoverRecord,
        verify: () throws -> Void = {}, stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        try RuntimeAuditUpgradeStartupFenceStorage.publishOwned(machine: f.runtime.machine, expected: expected,
            installedRelease: f.release, currentPolicy: f.policy, directory: directory(f), owner: getuid(),
            verifyOwnerAndBarrier: verify, didStage: stage)
    }
    @discardableResult private func remove(_ f: Fixture, _ expected: RuntimeAuditUpgradeCutoverRecord,
        verify: () throws -> Void = {}, validated: () throws -> Void = {}, removed: () throws -> Void = {}) throws -> GatewaySettingsFenceRemoval.Result {
        try RuntimeAuditUpgradeStartupFenceStorage.removeOwned(machine: f.runtime.machine, expected: expected,
            installedRelease: f.release, currentPolicy: f.policy, directory: directory(f), owner: getuid(),
            verifyOwnerBarrierAndTargets: verify, didValidate: validated, didRemove: removed)
    }
    func testCodecContainsOnlyPublicBindingsAndRejectsUnknownValues() throws {
        let f = try Fixture(), selected = try f.select(), fence = try RuntimeAuditUpgradeStartupFence(selected)
        XCTAssertEqual(try RuntimeAuditUpgradeStartupFence.decode(fence.encoded), fence)
        XCTAssertEqual(String(reflecting: fence), "RuntimeAuditUpgradeStartupFence(redacted)")
        XCTAssertNil(try fence.encoded.range(of: f.runtime.material.transportIdentity))
        let limits = try CBORLimits(maxBytes: 512, maxDepth: 1, maxItems: 19)
        guard case .map(let fields) = try DeterministicCBOR.decode(fence.encoded, limits: limits) else { return XCTFail() }
        for (key, value) in [(UInt64(0), CBORValue.unsigned(2)), (1, .text("other")), (2, .bytes(Data())), (6, .bytes(Data())), (8, .null)] {
            var edited = fields; edited[key] = value
            XCTAssertThrowsError(try RuntimeAuditUpgradeStartupFence.decode(DeterministicCBOR.encode(.map(edited), limits: limits)))
        }
    }
    func testAbsentGateCreatesNothingAndEveryExistingFenceBlocksStartup() throws {
        let f = try Fixture(), selected = try f.select(); try gate(f)
        XCTAssertFalse(FileManager.default.fileExists(atPath: try path(f)))
        XCTAssertEqual(try publish(f, selected), .created)
        XCTAssertThrowsError(try gate(f)) { XCTAssertEqual($0 as? RuntimeAuditUpgradeStartupError, .recoveryRequired) }
        XCTAssertThrowsError(try RuntimeAuditUpgradeStartupFence.requireOpen(macID: Data(repeating: 99, count: 16),
            accountID: f.runtime.account.accountID, read: { try self.read(f) }))
        var original = stat(); XCTAssertEqual(lstat(try path(f), &original), 0)
        XCTAssertEqual(original.st_mode & 0o7777, 0o644)
        XCTAssertEqual(try publish(f, selected), .retained)
        var again = stat(); XCTAssertEqual(lstat(try path(f), &again), 0); XCTAssertEqual(original.st_ino, again.st_ino)
    }
    func testMissingLegacyContainersAreOptionalOnlyForTheTypedFenceReader() throws {
        let f = try Fixture(), root = f.runtime.f.root.path, relative = "legacy/Services/account"
        XCTAssertNil(try ProtectedServiceConfiguration.readOptionalAuditFence(anchor: root, relativeDirectory: relative, owner: getuid()))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root + "/legacy"))
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readOptional(anchor: root,
            relativePath: relative + "/" + RuntimeAuditUpgradeStartupFence.fileName, owner: getuid()))
        try FileManager.default.createDirectory(atPath: root + "/legacy", withIntermediateDirectories: false)
        XCTAssertEqual(chmod(root + "/legacy", 0o777), 0)
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readOptionalAuditFence(anchor: root, relativeDirectory: relative, owner: getuid()))
    }
    func testMalformedLinksAndUnsafeAncestorsNeverBecomeAnAbsentFence() throws {
        for kind in 0...2 {
            let f = try Fixture(), selected = try f.select(), name = try path(f)
            if kind == 0 {
                try publish(f, selected); try Data("bad fence".utf8).write(to: URL(fileURLWithPath: name))
            } else if kind == 1 { XCTAssertEqual(symlink("missing-target", name), 0) }
            else { XCTAssertEqual(mkfifo(name, 0o644), 0) }
            XCTAssertThrowsError(try gate(f)); XCTAssertThrowsError(try publish(f, selected))
            var info = stat(); XCTAssertEqual(lstat(name, &info), 0)
        }
        let f = try Fixture(), root = f.runtime.f.root.path
        XCTAssertEqual(symlink("missing-parent", root + "/legacy"), 0)
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readOptionalAuditFence(anchor: root, relativeDirectory: "legacy/Services/account", owner: getuid()))
    }
    func testPublicationInterruptionLeavesTheExpectedConservativeStartupState() throws {
        for afterRename in [false, true] {
            let f = try Fixture(), selected = try f.select()
            XCTAssertThrowsError(try publish(f, selected, stage: { if ($0 == .published) == afterRename { throw Interrupted() } }))
            XCTAssertEqual(FileManager.default.fileExists(atPath: try path(f)), afterRename)
            _ = try publish(f, selected)
            XCTAssertThrowsError(try gate(f))
            XCTAssertEqual(try f.runtime.machine.runtimeAuditCutover(accountID: f.runtime.account.accountID), selected)
        }
    }
    func testFenceCannotBeRemovedBeforeMetadataCommitOrRepublishedAfterIt() throws {
        let f = try Fixture(), selected = try f.select(); try publish(f, selected)
        XCTAssertThrowsError(try remove(f, selected))
        let changing = try f.advance(selected, .filesChanging), verified = try f.advance(changing, .filesVerified)
        XCTAssertThrowsError(try remove(f, verified))
        let committed = try f.commit(verified)
        XCTAssertThrowsError(try gate(f)); XCTAssertEqual(try remove(f, committed), .removed)
        try gate(f); XCTAssertEqual(try remove(f, committed), .absent)
        XCTAssertThrowsError(try publish(f, committed))
        XCTAssertFalse(FileManager.default.fileExists(atPath: try path(f)))
    }
    func testLostCleanupReplyReconcilesAbsenceWithoutCreatingAnotherFence() throws {
        let f = try Fixture(), selected = try f.select(); try publish(f, selected)
        let committed = try f.commit(f.verified())
        XCTAssertThrowsError(try remove(f, committed, removed: { throw Interrupted() }))
        XCTAssertFalse(FileManager.default.fileExists(atPath: try path(f)))
        XCTAssertEqual(try remove(f, committed), .absent); try gate(f)
    }
    func testRemovalPreservesAReplacementInodeAndUnsafeModes() throws {
        for replacement in [false, true] {
            let f = try Fixture(), selected = try f.select(); try publish(f, selected)
            let committed = try f.commit(f.verified()), name = try path(f)
            if replacement {
                XCTAssertThrowsError(try remove(f, committed, validated: {
                    let bytes = try Data(contentsOf: URL(fileURLWithPath: name))
                    XCTAssertEqual(unlink(name), 0); try bytes.write(to: URL(fileURLWithPath: name))
                    XCTAssertEqual(chmod(name, 0o644), 0)
                }))
            } else {
                XCTAssertEqual(chmod(name, 0o600), 0); XCTAssertThrowsError(try remove(f, committed))
            }
            XCTAssertTrue(FileManager.default.fileExists(atPath: name)); XCTAssertThrowsError(try gate(f))
        }
    }
    func testExpiredOwnerAndStaleProgressCannotPublishOrRemove() throws {
        let f = try Fixture(), selected = try f.select()
        XCTAssertThrowsError(try publish(f, selected, verify: { throw Interrupted() }))
        XCTAssertFalse(FileManager.default.fileExists(atPath: try path(f)))
        let changing = try f.advance(selected, .filesChanging)
        XCTAssertThrowsError(try publish(f, selected))
        try publish(f, changing)
        let committed = try f.commit(f.advance(changing, .filesVerified))
        XCTAssertThrowsError(try remove(f, committed, verify: { throw Interrupted() }))
        XCTAssertTrue(FileManager.default.fileExists(atPath: try path(f)))
    }
    func testPublishedFencePreventsReplacingAnUnstartedGraphSelection() throws {
        let f = try Fixture(), selected = try f.select(); try publish(f, selected)
        let files = f.collector.files
        try files.write(f.runtime.material.encoded, files.entry("runtime-material.cbor", files.plan()))
        let scope = try f.collector.scope(); defer { scope.close() }
        let newer = try RuntimeAuditUpgradeGraph(observation: f.collector.collect(scope), upgrade: f.collector.record,
            installedRelease: f.release, currentPolicy: f.policy)
        let retained = try f.runtime.machine.retainRuntimeAuditGraph(newer, installedRelease: f.release, currentPolicy: f.policy)
        let stored = try RuntimeAuditUpgradeGraphStorage.restoreOwned(machine: f.runtime.machine, expected: retained,
            installedRelease: f.release, currentPolicy: f.policy, directory: XCTUnwrap(files.directories[.runtime]), owner: getuid(), verifyOwner: {})
        XCTAssertThrowsError(try f.runtime.machine.selectRuntimeAuditCutover(newer, record: stored, replacing: selected,
            installedRelease: f.release, currentPolicy: f.policy)) { XCTAssertEqual($0 as? RuntimeAuditUpgradeStartupError, .recoveryRequired) }
        XCTAssertEqual(try f.runtime.machine.runtimeAuditCutover(accountID: f.runtime.account.accountID), selected)
    }
    func testNormalSetupChecksTheFenceBeforeMutationAndPreservesItsAccountScope() throws {
        let f = try Fixture(), selected = try f.select(); var preparations = 0
        let owner = try SetupAccountOwner(machine: f.runtime.machine, expectedReleaseDigest: f.runtime.f.release,
            resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.policy, lookupAccount: { _ in f.runtime.f.identity },
            prepareAccount: { _, expected, _ in preparations += 1; return expected },
            verifyAccountStartup: { mac, account in
                XCTAssertEqual(mac, f.runtime.account.macID); XCTAssertEqual(account, f.runtime.account.accountID)
                try RuntimeAuditUpgradeStartupFence.requireOpen(macID: mac, accountID: account, read: { try self.read(f) })
            })
        defer { try? owner.close() }
        XCTAssertEqual(try owner.enrollment(callerUID: getuid()), f.runtime.account)
        try publish(f, selected)
        XCTAssertThrowsError(try owner.enrollment(callerUID: getuid()))
        XCTAssertThrowsError(try owner.beginEnrollment(callerUID: getuid(), allowedTargetUIDs: [0], disclosureAccepted: true))
        XCTAssertThrowsError(try owner.resumeEnrollment(callerUID: getuid(), setupID: f.runtime.account.setupID, expectedRevision: f.runtime.account.revision))
        XCTAssertEqual(preparations, 0)
        XCTAssertEqual(try f.runtime.machine.accountPreparation(ownerUID: getuid()), f.runtime.account)
    }
    func testNativeRoleChecksUseTheFenceAfterIdentityValidation() throws {
        let f = try Fixture(gateway: true), selected = try f.select()
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 8, maxItems: 256)
        func edit(_ bytes: Data, owner: UInt64, service: UInt64) throws -> Data {
            guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw Interrupted() }
            fields[owner] = .unsigned(UInt64(getuid()) + 1000); fields[service] = .unsigned(UInt64(getuid()))
            return try DeterministicCBOR.encode(.map(fields), limits: limits)
        }
        let transport = try ApprovalTransportConfiguration.decode(edit(f.runtime.plan.transport.transport.canonicalBytes, owner: 3, service: 4))
        let gateway = try GatewayServiceConfiguration.decode(edit(XCTUnwrap(f.graph.snapshot.plan.sourceGateway.journal.intent).configuration.canonicalBytes, owner: 7, service: 6))
        var identityChecks = 0, fenceChecks = 0
        let identity: (uid_t, uid_t) throws -> Void = { service, owner in
            identityChecks += 1; XCTAssertEqual(service, getuid()); XCTAssertNotEqual(service, owner)
        }
        let check: (Data, Data) throws -> Void = { mac, account in
            fenceChecks += 1
            try RuntimeAuditUpgradeStartupFence.requireOpen(macID: mac, accountID: account, read: { try self.read(f) })
        }
        try transport.requireNativeProcess(validate: identity, requireStartupOpen: check)
        try gateway.requireNativeProcess(validate: identity, requireStartupOpen: check)
        try publish(f, selected)
        XCTAssertThrowsError(try transport.requireNativeProcess(validate: identity, requireStartupOpen: check))
        XCTAssertThrowsError(try gateway.requireNativeProcess(validate: identity, requireStartupOpen: check))
        XCTAssertEqual(identityChecks, 4); XCTAssertEqual(fenceChecks, 4)
        XCTAssertThrowsError(try f.runtime.plan.transport.transport.requireNativeProcess(validate: identity, requireStartupOpen: check))
        XCTAssertEqual(identityChecks, 4); XCTAssertEqual(fenceChecks, 4)
    }
    func testEveryParticipantMustDeclareFenceSupportBeforeCutover() throws {
        let f = try Fixture()
        _ = try f.select()
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.runtime.machine)
        XCTAssertEqual(Set(snapshot.requirements.formats.filter { $0.name == RuntimeAuditUpgradeStartupFence.formatName }.map(\.role)),
            [.authority, .transport, .notificationGateway, .setupController])
        for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
            let release = try NativeHostReleaseFixture.make(policy: f.policy, phoneAudit: true, auditDelivery: true, edit: { component in
                guard component.role == role else { return component }
                return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: component.formats.filter { $0.name != RuntimeAuditUpgradeStartupFence.formatName })
            })
            XCTAssertThrowsError(try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(release, policy: f.policy))
        }
    }
    func testAnotherAccountDirectoryRemainsOpenWhileThisAccountIsFenced() throws {
        let f = try Fixture(), selected = try f.select(); try publish(f, selected)
        let other = try ProtectedSetupDirectory(anchor: f.runtime.f.root.path, relativePath: "other-services", owner: getuid(), visibility: .sharedMetadata)
        defer { other.close() }
        try RuntimeAuditUpgradeStartupFence.requireOpen(macID: f.runtime.account.macID, accountID: Data(repeating: 99, count: 16), read: {
            try ProtectedServiceConfiguration.readOptional(anchor: other.path, relativePath: RuntimeAuditUpgradeStartupFence.fileName, owner: getuid())
        })
        XCTAssertThrowsError(try gate(f))
        XCTAssertFalse(FileManager.default.fileExists(atPath: other.path + "/" + RuntimeAuditUpgradeStartupFence.fileName))
    }
    func testNativeEntryPointsRefuseBeforeCallbacksOrProductionStorageAccess() throws {
        let f = try Fixture(), selected = try f.select(); var calls = 0
        XCTAssertThrowsError(try RuntimeAuditUpgradeStartupFenceStorage.publish(machine: f.runtime.machine, expected: selected,
            installedRelease: f.release, currentPolicy: f.policy, verifyOwnerAndBarrier: { calls += 1 })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try RuntimeAuditUpgradeStartupFenceStorage.removeAfterMetadataCommit(machine: f.runtime.machine, expected: selected,
            installedRelease: f.release, currentPolicy: f.policy, verifyOwnerBarrierAndTargets: { calls += 1 })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.load(path: f.runtime.f.root.path + "/missing-command-host.cbor")) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertThrowsError(try AuthorityService.openJournal(configuration: f.runtime.plan.host.command.presence.wake.request.service)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(calls, 0)
    }
}
