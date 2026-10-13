import Darwin
import XCTest
@testable import RemozioCore

final class DedicatedServiceAccountTests: XCTestCase {
    private func account(uid: uid_t = 601, gid: gid_t = 602, shell: String = "/usr/bin/false",
                         groups: Set<gid_t> = [602]) -> DedicatedServiceAccount {
        .init(uid: uid, gid: gid, shell: shell, groups: groups)
    }

    func testAllowsNonloginAccountsAndUnprivilegedGroups() throws {
        for shell in ["/usr/bin/false", "/sbin/nologin"] {
            try account(shell: shell, groups: [602, 603]).validate(ownerUID: 501)
        }
    }

    func testRejectsRootOwnerSentinelsAndLoginShells() throws {
        for value in [account(uid: 0), account(uid: 501), account(uid: UInt32.max), account(gid: 0),
                      account(gid: UInt32.max), account(shell: "/bin/zsh"), account(shell: ""),
                      account(shell: "/usr/local/bin/false")] {
            XCTAssertThrowsError(try value.validate(ownerUID: 501))
        }
        for owner in [uid_t(0), uid_t(UInt32.max), uid_t(601)] {
            XCTAssertThrowsError(try account().validate(ownerUID: owner))
        }
    }

    func testRejectsMissingPrimaryAdministrativeAndUnboundedDirectoryGroups() throws {
        for groups: Set<gid_t> in [[], [603], [0, 602], [80, 602], [602, UInt32.max], Set(602...1626)] {
            XCTAssertThrowsError(try account(groups: groups).validate(ownerUID: 501))
        }
    }

    func testProcessUsesBothUIDsAndGIDsWithoutRequiringSupplementaryPrimary() throws {
        let value = account(groups: [602, 603])
        for groups: Set<gid_t> in [[], [602], [603], [602, 603]] {
            try value.validateProcess(realUID: 601, effectiveUID: 601, realGID: 602, effectiveGID: 602, groups: groups)
        }
        for credentials: (uid_t, uid_t, gid_t, gid_t) in [(0, 601, 602, 602), (601, 0, 602, 602),
            (501, 601, 602, 602), (601, 501, 602, 602), (601, 601, 0, 602), (601, 601, 602, 0),
            (601, 601, 603, 602), (601, 601, 602, 603)] {
            XCTAssertThrowsError(try value.validateProcess(realUID: credentials.0, effectiveUID: credentials.1,
                realGID: credentials.2, effectiveGID: credentials.3, groups: []))
        }
    }

    func testProcessRejectsRetainedForeignAdministrativeAndUnboundedGroups() throws {
        for groups: Set<gid_t> in [[604], [0], [80], [UInt32.max], Set(602...1626)] {
            XCTAssertThrowsError(try account().validateProcess(realUID: 601, effectiveUID: 601,
                realGID: 602, effectiveGID: 602, groups: groups))
        }
    }

    func testRejectsNestedMembershipAndLookupFailureForEachAdministrativeGroup() throws {
        var observed: [String] = []
        try DedicatedServiceAccount.rejectAdministrators(uid: 601) { uid, name in
            XCTAssertEqual(uid, 601); observed.append(name); return false
        }
        XCTAssertEqual(observed, ["wheel", "admin"])
        for rejected in ["wheel", "admin"] {
            XCTAssertThrowsError(try DedicatedServiceAccount.rejectAdministrators(uid: 601) { _, name in name == rejected })
            XCTAssertThrowsError(try DedicatedServiceAccount.rejectAdministrators(uid: 601) { _, name in
                if name == rejected { throw DedicatedServiceAccountError.unsafeAccount }
                return false
            })
        }
    }

    func testNativeBoundaryRejectsInteractiveOwnerBeforeCredentialAccess() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary-user refusal control") }
        XCTAssertThrowsError(try DedicatedServiceAccount.requireCurrent(serviceUID: getuid(), ownerUID: getuid()))
        XCTAssertThrowsError(try DedicatedServiceAccount.requireCurrent(serviceUID: 0, ownerUID: getuid()))
        XCTAssertThrowsError(try DedicatedServiceAccount.resolve(uid: UInt32.max))
    }
}
