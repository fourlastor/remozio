import Foundation
import XCTest
@testable import RemozioCore

final class PureResultMemoTests: XCTestCase {
    private struct Refused: Error {}

    func testDifferentKeysNeverShareAResultAndRefusalsKeepNoRecord() throws {
        let memo = PureResultMemo<Data, String>(capacity: 4)
        var calls = 0
        func value(_ key: Data) throws -> String {
            try memo.value(for: key) {
                calls += 1
                if key.isEmpty { throw Refused() }
                return LowercaseHexadecimal.encode(key)
            }
        }
        XCTAssertEqual(try value(Data([1])), "01")
        XCTAssertEqual(try value(Data([2])), "02")
        XCTAssertEqual(try value(Data([1])), "01")
        XCTAssertEqual(calls, 2)
        XCTAssertThrowsError(try value(Data()))
        XCTAssertThrowsError(try value(Data()))
        XCTAssertEqual(calls, 4, "A refused input must run the function again")
        for byte in UInt8(3)...UInt8(9) { _ = try value(Data([byte])) }
        XCTAssertEqual(try value(Data([1])), "01", "Clearing at capacity must not change a result")
    }

    func testCodePolicyEncodingAndDecodingFollowTheExactInput() throws {
        func policy(installed: UInt64) throws -> AuthorityCodePolicy {
            try AuthorityCodePolicy(entries: [.init(role: .app, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.app",
                installedGeneration: installed, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 7, count: 20),
                active: true)])
        }
        let first = try policy(installed: 1), second = try policy(installed: 2)
        let firstBytes = try first.bytes, secondBytes = try second.bytes
        XCTAssertNotEqual(firstBytes, secondBytes)
        for _ in 0..<2 {
            XCTAssertEqual(try AuthorityCodePolicy.decode(firstBytes), first)
            XCTAssertEqual(try AuthorityCodePolicy.decode(secondBytes), second)
            XCTAssertEqual(try first.bytes, firstBytes)
            XCTAssertEqual(try second.bytes, secondBytes)
        }
        // Bytes that differ from a decoded input never return its value, and refused bytes stay refused.
        var changed = firstBytes
        changed[changed.count - 1] ^= 0x01
        XCTAssertNotEqual(try? AuthorityCodePolicy.decode(changed), first)
        for _ in 0..<2 { XCTAssertThrowsError(try AuthorityCodePolicy.decode(firstBytes + Data([0]))) }
    }

    func testServiceAccountPlanEncodingAndDecodingFollowTheExactInput() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner account fixture") }
        let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .commandFrontend,
                                          .commandMonitor, .commandChild]
        let policy = try AuthorityCodePolicy(entries: roles.map { role in
            try .init(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\(role.rawValue)", installedGeneration: 1,
                minimumGeneration: 1, codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
        })
        let f = try AccountPreparationFixture(policy: policy), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        func plan(transport: UInt32) throws -> ServiceAccountPlan {
            try ServiceAccountPlan(account: account, planID: Data(repeating: 9, count: 16), claims: [
                .init(accountID: account.accountID, role: .transport, number: transport,
                      userID: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
                      groupID: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!),
                .init(accountID: account.accountID, role: .gateway, number: 30001,
                      userID: UUID(uuidString: "00000000-0000-0000-0000-000000000003")!,
                      groupID: UUID(uuidString: "00000000-0000-0000-0000-000000000004")!)])
        }
        let first = try plan(transport: 30000), second = try plan(transport: 30002)
        let firstBytes = try first.encoded, secondBytes = try second.encoded
        XCTAssertNotEqual(firstBytes, secondBytes)
        for _ in 0..<2 {
            XCTAssertEqual(try ServiceAccountPlan.decode(firstBytes), first)
            XCTAssertEqual(try ServiceAccountPlan.decode(secondBytes), second)
            XCTAssertEqual(try first.encoded, firstBytes)
            XCTAssertEqual(try second.encoded, secondBytes)
        }
        for _ in 0..<2 { XCTAssertThrowsError(try ServiceAccountPlan.decode(firstBytes + Data([0]))) }
    }
}
