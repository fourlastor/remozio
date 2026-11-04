import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SetupAuditUpgradeScopeTests: XCTestCase {
    private enum Failure: Error { case host, account, rights }
    private final class Harness {
        let base: RuntimeAuditUpgradeCutoverTests.Fixture
        let activity: ReleaseActivityFixture
        let installer: ReleaseActivityBarrier
        var hostValid = true
        var accountValid = true
        init() throws {
            base = try .init(); activity = try .init(); installer = try activity.open()
            let selected = try base.select()
            _ = try RuntimeAuditUpgradeStartupFenceStorage.publishOwned(machine: base.runtime.machine, expected: selected,
                installedRelease: base.release, currentPolicy: base.policy,
                directory: XCTUnwrap(base.collector.files.directories[.services]), owner: getuid(), verifyOwnerAndBarrier: {})
            try base.runtime.machine.close()
        }
        func owner() throws -> SetupAccountOwner {
            try .init(openMachine: { try self.base.runtime.f.open() }, expectedReleaseDigest: base.runtime.f.release,
                resume: { _, _ in throw Failure.host }, verifyHost: { _ in if !self.hostValid { throw Failure.host } },
                accountCodePolicy: base.policy, lookupAccount: { uid in
                    guard self.accountValid, uid == self.base.runtime.f.identity.uid else { throw Failure.account }
                    return self.base.runtime.f.identity
                }, releaseActivity: activity.open(), verifyAccountStartup: { mac, account in
                    let directory = try XCTUnwrap(self.base.collector.files.directories[.services])
                    try RuntimeAuditUpgradeStartupFence.requireOpen(macID: mac, accountID: account,
                        read: { try ProtectedServiceConfiguration.readOptional(anchor: directory.path,
                            relativePath: RuntimeAuditUpgradeStartupFence.fileName, owner: getuid()) })
                })
        }
        func grant(_ valid: @escaping () throws -> Void = {}) throws -> SetupAuditUpgradeAuthorization {
            try .openOwned(verifyRights: valid)
        }
        func requireWriterAvailable() throws { let machine = try base.runtime.f.open(); try machine.close() }
    }
    func testAuthorizedRecoveryBypassesOnlyTheNormalStartupFence() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        XCTAssertThrowsError(try owner.runtimeProgress(callerUID: getuid())) { XCTAssertEqual($0 as? RuntimeAuditUpgradeStartupError, .recoveryRequired) }
        let grant = try h.grant(), scope = try owner.acquireAuditUpgradeScope(authorization: grant)
        XCTAssertEqual(scope.account, h.base.runtime.account); XCTAssertEqual(scope.inventory.macID, h.base.runtime.account.macID)
        XCTAssertTrue(scope.initialization.complete); try scope.validateLifetime(); try h.requireWriterAvailable()
        XCTAssertEqual(scope.description, "SetupAuditUpgradeScope(redacted)"); XCTAssertTrue(scope.customMirror.children.isEmpty)
        try scope.close(); try scope.close()
        XCTAssertThrowsError(try grant.validate())
        XCTAssertThrowsError(try owner.runtimeProgress(callerUID: getuid())) { XCTAssertEqual($0 as? RuntimeAuditUpgradeStartupError, .recoveryRequired) }
    }
    func testReservationExcludesSetupButAllowsExclusiveRootActivity() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let scope = try owner.acquireAuditUpgradeScope(authorization: h.grant()); defer { try? scope.close() }
        XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
        let update = try h.installer.acquireExclusive(); defer { update.close() }
        try scope.validateLifetime(); try h.requireWriterAvailable()
        XCTAssertThrowsError(try owner.acquireReleaseActivity()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
    }
    func testLifetimeChecksCanRunInsideAMachineTransactionWithoutReentry() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let scope = try owner.acquireAuditUpgradeScope(authorization: h.grant()); defer { try? scope.close() }
        let update = try h.installer.acquireExclusive(); defer { update.close() }
        try scope.withMachine { machine in
            let selected = try XCTUnwrap(machine.runtimeAuditCutover(accountID: scope.account.accountID))
            _ = try machine.advanceRuntimeAuditCutover(selected, graph: h.base.graph, to: .filesChanging,
                installedRelease: h.base.release, currentPolicy: h.base.policy, verifyBarrierAndArtifacts: scope.validateLifetime)
        }
        try h.requireWriterAvailable()
    }
    func testReentrantMachineBorrowAndCloseCannotDropTheReservation() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let scope = try owner.acquireAuditUpgradeScope(authorization: h.grant()); defer { try? scope.close() }
        try scope.withMachine { _ in
            try scope.validateLifetime()
            XCTAssertThrowsError(try scope.withMachine { _ in XCTFail("Nested borrow") })
            XCTAssertThrowsError(try scope.close()); XCTAssertThrowsError(try owner.verifyCurrent())
        }
        try scope.validateLifetime(); try h.requireWriterAvailable()
    }
    func testRightsExpiryStopsFurtherUseAndCleanupReleasesAdmission() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        var valid = true
        let grant = try h.grant { if !valid { throw Failure.rights } }
        let scope = try owner.acquireAuditUpgradeScope(authorization: grant)
        valid = false
        XCTAssertThrowsError(try scope.validateLifetime()); XCTAssertThrowsError(try scope.withMachine { _ in XCTFail("Expired rights") })
        try scope.close(); try owner.verifyCurrent(); try h.requireWriterAvailable()
    }
    func testHostAndLocalAccountChangesRefuseMaintenanceUse() throws {
        for changeHost in [false, true] {
            let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
            let scope = try owner.acquireAuditUpgradeScope(authorization: h.grant()); defer { try? scope.close() }
            if changeHost { h.hostValid = false } else { h.accountValid = false }
            XCTAssertThrowsError(try scope.validateLifetime()); try h.requireWriterAvailable()
        }
    }
    func testFailedAdmissionLeavesAuthorizationWithCallerAndDoesNotReserveSetup() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let grant = try SetupAuditUpgradeAuthorization.openOwned(callerUID: getuid() + 1, verifyRights: {})
        defer { grant.close() }
        XCTAssertThrowsError(try owner.acquireAuditUpgradeScope(authorization: grant))
        try grant.validate(); try owner.verifyCurrent(); try h.requireWriterAvailable()
    }
    func testSecondScopeCannotStealOrCloseTheFirstReservation() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let first = try owner.acquireAuditUpgradeScope(authorization: h.grant()), next = try h.grant()
        defer { try? first.close(); next.close() }
        XCTAssertThrowsError(try owner.acquireAuditUpgradeScope(authorization: next))
        try first.validateLifetime(); try next.validate(); try first.close()
        let retry = try owner.acquireAuditUpgradeScope(authorization: next); try retry.close()
    }
    func testOwnerShutdownWaitsForTheReservationAndInvalidatesFurtherUse() throws {
        let h = try Harness(), owner = try h.owner()
        let scope = try owner.acquireAuditUpgradeScope(authorization: h.grant())
        XCTAssertThrowsError(try owner.close()); XCTAssertThrowsError(try scope.validateLifetime())
        try scope.close(); try owner.close(); try h.requireWriterAvailable()
    }
}
