import Darwin
import Foundation
import Security
import XCTest
@testable import RemozioCore

final class SetupAdministratorAuthorizationTests: XCTestCase {
    private var rule: [String: Any] {
        ["class": "user", "group": "admin", "authenticate-user": true,
         "session-owner": false, "shared": false, "timeout": 300]
    }

    func testRejectsRulesThatRemoveAdministratorAuthentication() throws {
        for replacement: (String, Any) in [("class", "allow"), ("class", "rule"), ("group", "staff"),
            ("authenticate-user", false), ("session-owner", true), ("shared", true),
            ("authenticate-user", 1), ("session-owner", 0), ("shared", 0),
            ("timeout", true), ("timeout", -1), ("timeout", 0), ("timeout", 301), ("timeout", Double.infinity)] {
            var changed = rule; changed[replacement.0] = replacement.1
            XCTAssertThrowsError(try SetupAdministratorNative.validatePolicy(changed as NSDictionary))
        }
        for key in rule.keys {
            var changed = rule; changed.removeValue(forKey: key)
            XCTAssertThrowsError(try SetupAdministratorNative.validatePolicy(changed as NSDictionary))
        }
        for timeout in [1, 30, 300] {
            var changed = rule; changed["timeout"] = timeout
            try SetupAdministratorNative.validatePolicy(changed as NSDictionary)
        }
    }

    func testUncredentialledNativeReferenceCannotAuthorizeHelperOperation() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary account control") }
        var reference: AuthorizationRef?
        try SetupAdministratorNative.status(AuthorizationCreate(nil, nil, [], &reference))
        let created = try XCTUnwrap(reference)
        defer { _ = AuthorizationFree(created, .destroyRights) }
        var form = AuthorizationExternalForm()
        try SetupAdministratorNative.status(AuthorizationMakeExternalForm(created, &form))
        let bytes = withUnsafeBytes(of: &form) { Data($0) }
        XCTAssertThrowsError(try SetupAdministratorNative.validate(externalForm: bytes))
        XCTAssertThrowsError(try SetupAdministratorNative.copyRights(created, flags: []))
    }

    func testNewClientCannotExportAndClosePreventsUse() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary account control") }
        let session = try SetupAdministratorSession()
        XCTAssertEqual(session.description, "SetupAdministratorSession(redacted)")
        XCTAssertThrowsError(try session.externalForm())
        session.close(); session.close()
        XCTAssertThrowsError(try session.authorize()) { error in
            XCTAssertEqual(error as? SetupAdministratorAuthorizationError, .closed)
        }
        XCTAssertThrowsError(try session.externalForm())
    }

    func testMalformedFormsRefuseBeforeNativeAuthorization() throws {
        for length in [0, 1, 31, 33, 65536] {
            XCTAssertThrowsError(try SetupAdministratorNative.validate(externalForm: Data(repeating: 0, count: length))) { error in
                XCTAssertEqual(error as? SetupAdministratorAuthorizationError, .invalidExternalForm)
            }
        }
        XCTAssertThrowsError(try SetupAdministratorNative.validate(externalForm: Data(repeating: 0, count: 32)))
    }

    func testPublicHelperRefusesOrdinaryCallerBeforeConnectionOrRightsAccess() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary account control") }
        let connection = NSXPCConnection(machServiceName: "dev.remozio.tests.not-registered")
        let policy = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.remozio.mac",
            approvedCodeDirectoryHashes: [Data(repeating: 0, count: 20)], expectedUserID: getuid())
        let invocation = XPCInvocationGuard(connection: connection, policy: policy)
        XCTAssertThrowsError(try SetupAdministratorAuthorization.validate(externalForm: Data(), invocation: invocation)) { error in
            XCTAssertEqual(error as? SetupAdministratorAuthorizationError, .wrongProcess)
        }
    }

    func testCancellationRemainsDistinctFromDenial() throws {
        try SetupAdministratorNative.status(errAuthorizationSuccess)
        XCTAssertThrowsError(try SetupAdministratorNative.status(errAuthorizationCanceled)) { error in
            XCTAssertEqual(error as? SetupAdministratorAuthorizationError, .cancelled)
        }
        XCTAssertThrowsError(try SetupAdministratorNative.status(errAuthorizationDenied)) { error in
            XCTAssertEqual(error as? SetupAdministratorAuthorizationError, .denied(errAuthorizationDenied))
        }
    }
}
