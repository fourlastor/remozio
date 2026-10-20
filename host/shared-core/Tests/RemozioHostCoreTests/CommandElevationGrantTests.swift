import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioHostCore

final class CommandElevationGrantTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16)
    private let account = Data(repeating: 2, count: 16)
    private func policy(targets: Set<UInt32> = [0, 502]) throws -> CommandElevationPolicy {
        try .init(macID: mac, accountID: account, callerUID: 501, allowedTargetUIDs: targets,
                  independentPolicyDisclosureAccepted: true)
    }
    func testOnlyExplicitAccountAndTargetGrantsAuthorize() throws {
        let policy = try policy()
        for uid: UInt32 in [0, 502] {
            XCTAssertNoThrow(try policy.authorize(macID: mac, accountID: account, callerUID: 501, requestedTargetUID: uid))
        }
        for (m, a, caller, target): (Data, Data, UInt32, UInt32) in [
            (mac, account, 501, 503), (mac, account, 502, 0), (mac, account, 0, 0),
            (Data(repeating: 3, count: 16), account, 501, 0), (mac, Data(repeating: 4, count: 16), 501, 0)
        ] {
            XCTAssertThrowsError(try policy.authorize(macID: m, accountID: a, callerUID: caller, requestedTargetUID: target)) {
                XCTAssertEqual($0 as? CommandElevationPolicyError, .policyRejected)
            }
        }
    }
    func testEmptyGrantsDisableElevationAndRemovalRevokesOldTarget() throws {
        let enabled = try policy()
        XCTAssertNoThrow(try enabled.authorize(macID: mac, accountID: account, callerUID: 501, requestedTargetUID: 0))
        for targets: Set<UInt32> in [[], [502]] {
            XCTAssertThrowsError(try policy(targets: targets).authorize(macID: mac, accountID: account,
                callerUID: 501, requestedTargetUID: 0))
        }
    }
    func testRoundTripRetainsIndependentPolicyAndDisclosure() throws {
        for targets: Set<UInt32> in [[], [0], [502, 0]] {
            let original = try policy(targets: targets), decoded = try CommandElevationPolicy.decode(original.canonicalBytes)
            XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
            XCTAssertEqual(decoded.allowedTargetUIDs, targets)
            XCTAssertEqual(decoded.description, "CommandElevationPolicy(redacted)")
        }
        XCTAssertThrowsError(try CommandElevationPolicy(macID: mac, accountID: account, callerUID: 501,
            allowedTargetUIDs: [0], independentPolicyDisclosureAccepted: false)) {
            XCTAssertEqual($0 as? CommandElevationPolicyError, .disclosureRequired)
        }
    }
    func testMalformedOrAmbiguousConfigurationCannotGrantAuthority() throws {
        let original = try policy(), limits = try CBORLimits(maxBytes: 4096, maxDepth: 2, maxItems: 96)
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        for (field, value): (UInt64, CBORValue) in [
            (0, .unsigned(2)), (1, .text("sudoers")), (2, .bytes(Data())), (3, .bytes(Data())),
            (4, .unsigned(0)), (4, .unsigned(UInt64(UInt32.max))), (4, .unsigned(UInt64(UInt32.max) + 1)),
            (5, .array([.unsigned(0), .unsigned(0)])), (5, .array([.unsigned(502), .unsigned(0)])),
            (5, .array([.unsigned(UInt64(UInt32.max))])), (5, .array([.text("root")])),
            (6, .boolean(false)), (6, .unsigned(1)), (7, .null)
        ] {
            var changed = fields; changed[field] = value
            XCTAssertThrowsError(try CommandElevationPolicy.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        for field in fields.keys {
            var changed = fields; changed.removeValue(forKey: field)
            XCTAssertThrowsError(try CommandElevationPolicy.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        XCTAssertThrowsError(try policy(targets: Set(UInt32(0)...64)))
    }
    func testCanonicalBytesMatchExistingMacPolicyVector() throws {
        let expected = Data([0xa7, 0x00, 0x01, 0x01, 0x73]) + Data("independent-remozio".utf8)
            + Data([0x02, 0x50]) + mac + Data([0x03, 0x50]) + account
            + Data([0x04, 0x19, 0x01, 0xf5, 0x05, 0x82, 0x00, 0x19, 0x01, 0xf6, 0x06, 0xf5])
        XCTAssertEqual(try policy().canonicalBytes, expected)
        XCTAssertEqual(try CommandElevationPolicy.decode(expected).canonicalBytes, expected)
        // Own-account execution also needs an explicit grant; no administrator/phone inference exists.
        XCTAssertThrowsError(try policy().authorize(macID: mac, accountID: account,
            callerUID: 501, requestedTargetUID: 501))
        XCTAssertNoThrow(try policy(targets: [501]).authorize(macID: mac, accountID: account,
            callerUID: 501, requestedTargetUID: 501))
    }
}
