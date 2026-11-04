import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SetupAuditUpgradeAuthorizationTests: XCTestCase {
    private enum Failure: Error { case expected }
    func testEveryUseRechecksRightsAndCloseReleasesOnlyOnce() throws {
        var valid = true, checks = 0, closes = 0
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {
            checks += 1; if !valid { throw Failure.expected }
        }, closeRights: { closes += 1 })
        XCTAssertEqual(grant.callerUID, getuid()); XCTAssertEqual(checks, 1)
        try grant.validate(); XCTAssertEqual(checks, 2)
        valid = false; XCTAssertThrowsError(try grant.validate()); XCTAssertEqual(checks, 3)
        XCTAssertEqual(grant.description, "SetupAuditUpgradeAuthorization(redacted)")
        XCTAssertTrue(grant.customMirror.children.isEmpty)
        grant.close(); grant.close(); XCTAssertEqual(closes, 1)
        XCTAssertThrowsError(try grant.validate()); XCTAssertEqual(checks, 3)
    }
    func testFailedConstructionReleasesItsImportedReference() throws {
        var closes = 0
        XCTAssertThrowsError(try SetupAuditUpgradeAuthorization.openOwned(verifyRights: { throw Failure.expected }, closeRights: { closes += 1 }))
        XCTAssertEqual(closes, 1)
    }
    func testNativeImportRefusesOrdinaryIdentityBeforeInvocationOrRightsAccess() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary owner") }
        let connection = NSXPCConnection(machServiceName: "dev.remozio.tests.not-registered")
        let policy = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.sebastiano.remozio.macos",
            approvedCodeDirectoryHashes: [Data(repeating: 0, count: 20)], expectedUserID: getuid())
        let invocation = XPCInvocationGuard(connection: connection, policy: policy)
        XCTAssertThrowsError(try SetupAuditUpgradeAuthorization.open(externalForm: Data(), invocation: invocation)) {
            XCTAssertEqual($0 as? SetupAdministratorAuthorizationError, .wrongProcess)
        }
    }
}
