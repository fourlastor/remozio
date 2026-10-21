import Foundation
import Security
import XCTest
@testable import RemozioCore

final class XPCPeerPolicyTests: XCTestCase {
    private let codeHash = Data(repeating: 1, count: 20)
    private func policy(team: String = "AB12345678", identifier: String = "dev.remozio.transport",
                        hashes: Set<Data>? = nil, session: au_asid_t? = nil) throws -> XPCPeerPolicy {
        try XPCPeerPolicy(teamID: team, componentIdentifier: identifier, approvedCodeDirectoryHashes: hashes ?? [codeHash],
            expectedUserID: 501, expectedAuditSessionID: session)
    }
    func testReleaseRequirementCompilesAndPinsCertificateRoleTeamIdentifierAndHashes() throws {
        let value = try policy(hashes: [codeHash, Data(repeating: 2, count: 20)])
        var compiled: SecRequirement?
        XCTAssertEqual(SecRequirementCreateWithString(value.requirement as CFString, [], &compiled), errSecSuccess)
        XCTAssertNotNil(compiled)
        XCTAssertTrue(value.requirement.contains("anchor apple generic"))
        XCTAssertTrue(value.requirement.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"))
        XCTAssertTrue(value.requirement.contains("certificate leaf[subject.OU] = \"AB12345678\""))
        XCTAssertTrue(value.requirement.contains("identifier \"dev.remozio.transport\""))
        XCTAssertEqual(value.requirement.components(separatedBy: "cdhash H\"").count - 1, 2)
        XCTAssertTrue(value.requirement.contains("!(entitlement[\"com.apple.security.get-task-allow\"] exists)"))
    }
    func testMalformedAndUnboundedPolicyInputsCannotBecomeRequirements() throws {
        for team in ["", "AB1234567", "AB123456789", "ab12345678", "A\"12345678"] {
            XCTAssertThrowsError(try policy(team: team))
        }
        for identifier in ["", "dev.\" or true", "dev.remozio\n", String(repeating: "x", count: 256), "dev.é"] {
            XCTAssertThrowsError(try policy(identifier: identifier))
        }
        for hashes: Set<Data> in [[], [Data(count: 19)], [Data(count: 21)], Set((0..<17).map { Data(repeating: UInt8($0), count: 20) })] {
            XCTAssertThrowsError(try policy(hashes: hashes))
        }
        XCTAssertEqual(try policy(hashes: [codeHash, Data(repeating: 2, count: 20)]).requirement,
                       try policy(hashes: [Data(repeating: 2, count: 20), codeHash]).requirement)
    }
    func testConnectionCredentialsRequireExpectedUserAndOptionalSession() throws {
        let value = try policy(session: 42)
        XCTAssertEqual(try value.credentials(processID: 100, userID: 501, auditSessionID: 42).userID, 501)
        XCTAssertThrowsError(try value.credentials(processID: 0, userID: 501, auditSessionID: 42))
        XCTAssertThrowsError(try value.credentials(processID: 100, userID: 0, auditSessionID: 42))
        XCTAssertThrowsError(try value.credentials(processID: 100, userID: 502, auditSessionID: 42))
        XCTAssertThrowsError(try value.credentials(processID: 100, userID: 501, auditSessionID: 43))
        XCTAssertNoThrow(try policy().credentials(processID: 100, userID: 501, auditSessionID: 43))
    }
    func testHexadecimalCodeDirectoryHashesMatchThePreviousFormatterForEveryByte() {
        for byte in UInt8.min...UInt8.max {
            let hash = Data(repeating: byte, count: 20)
            XCTAssertEqual(XPCPeerPolicy.hexadecimalCodeDirectoryHash(hash),
                           hash.map { String(format: "%02x", $0) }.joined())
        }
        let bytes = Data(UInt8.min...UInt8.max)
        for start in 0...(bytes.count - 20) {
            let hash = bytes[start..<(start + 20)]
            XCTAssertEqual(XPCPeerPolicy.hexadecimalCodeDirectoryHash(hash),
                           hash.map { String(format: "%02x", $0) }.joined())
        }
    }
    func testAllApprovedHashesRetainTheirExactSortedRequirementText() throws {
        let hashes = Set((0..<16).map { offset in
            Data((0..<20).map { UInt8(($0 * 13 + offset * 17) & 255) })
        })
        let formatted = hashes.map { hash in
            "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
        }.sorted().joined(separator: " or ")
        let expected = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
            + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
            + "and certificate leaf[subject.OU] = \"AB12345678\" and identifier \"dev.remozio.transport\" "
            + "and (\(formatted)) and !(entitlement[\"com.apple.security.get-task-allow\"] exists) "
            + "and !(entitlement[\"com.apple.security.cs.disable-library-validation\"] exists) "
            + "and !(entitlement[\"com.apple.security.cs.allow-dyld-environment-variables\"] exists) "
            + "and !(entitlement[\"com.apple.security.cs.allow-jit\"] exists) "
            + "and !(entitlement[\"com.apple.security.cs.allow-unsigned-executable-memory\"] exists)"
        XCTAssertEqual(try policy(hashes: hashes).requirement, expected)
    }
    func testInvocationOutsideAcceptedConnectionIsRejected() throws {
        let connection = NSXPCConnection(machServiceName: "dev.remozio.synthetic.unavailable")
        defer { connection.invalidate() }
        let guardObject = XPCInvocationGuard(connection: connection, policy: try policy())
        XCTAssertThrowsError(try guardObject.verifyInvocation())
    }
}
