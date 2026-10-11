import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandElevationPolicyTests: XCTestCase {
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
    func testCaptureRecheckRejectsChangedCallerOrRevokedTarget() throws {
        func capture(realUID: UInt32 = 501, effectiveUID: UInt32 = 501, targetUID: UInt32 = 0) throws -> CommandCapture {
            try .init(schemaVersion: 1,
                executable: .init(path: Data("/usr/bin/true".utf8), identity: .init(device: 1, inode: 2), sha256: Data(count: 32)),
                arguments: [Data("true".utf8)], directory: .init(path: Data("/tmp".utf8), identity: .init(device: 1, inode: 3)),
                target: .init(uid: targetUID, gid: 0, supplementaryGroups: [0], observedName: "root"), environment: [],
                input: .init(kind: .null, streamBinding: nil, observedPath: nil, identity: nil),
                ioMode: .pipes, disconnectBehavior: .terminate,
                requester: .init(executablePath: Data("/fixture/caller".utf8), realUID: realUID, effectiveUID: effectiveUID,
                    pid: 10, pidVersion: 11, signing: .init(status: .unsigned, identifier: nil, team: nil, cdHash: nil),
                    sessionID: nil, ttyPath: nil),
                ancestry: .init(completeness: .unavailable, entries: [], reason: .unsupported), unverifiedRationale: nil,
                submission: .init(id: Data(count: 16), nonce: Data(count: 32), callerBinding: Data(count: 16)),
                limits: .init(maxBytes: 8192, maxDepth: 16, maxItems: 1024))
        }
        let enabled = try policy(), approvedCapture = try capture()
        XCTAssertNoThrow(try enabled.validate(capture: approvedCapture, macID: mac, accountID: account, resolveTarget: { _ in approvedCapture.target }))
        for changed in [try capture(realUID: 502), try capture(effectiveUID: 0),
                        try capture(realUID: 502, effectiveUID: 502), try capture(targetUID: 503)] {
            XCTAssertThrowsError(try enabled.validate(capture: changed, macID: mac, accountID: account, resolveTarget: { _ in XCTFail("Rejected grants must not resolve a target"); return changed.target }))
        }
        for target in [CommandTarget(uid: 0, gid: 1, supplementaryGroups: [0], observedName: "root"),
                       CommandTarget(uid: 0, gid: 0, supplementaryGroups: [0, 80], observedName: "root"),
                       CommandTarget(uid: 0, gid: 0, supplementaryGroups: [0], observedName: "renamed")] {
            XCTAssertThrowsError(try enabled.validate(capture: approvedCapture, macID: mac, accountID: account,
                resolveTarget: { _ in target }))
        }
        XCTAssertThrowsError(try enabled.validate(capture: approvedCapture, macID: mac, accountID: account,
            resolveTarget: { _ in throw CommandTargetResolutionError.unavailable }))
        XCTAssertThrowsError(try policy(targets: [502]).validate(capture: approvedCapture, macID: mac, accountID: account, resolveTarget: { _ in XCTFail("Revoked grants must not resolve a target"); return approvedCapture.target }))
    }
    func testNativeResolutionAndValidationUseActualTargetCredentials() throws {
        let policy = try policy(), root = try CommandTargetResolver.resolve(uid: 0)
        XCTAssertEqual(root.uid, 0)
        XCTAssertFalse(root.observedName?.isEmpty ?? true)
        XCTAssertTrue(root.supplementaryGroups.contains(root.gid))
        XCTAssertEqual(root.supplementaryGroups, Array(Set(root.supplementaryGroups)).sorted())
        XCTAssertEqual(try policy.resolveTarget(macID: mac, accountID: account, callerUID: 501, requestedTargetUID: 0), root)
        XCTAssertThrowsError(try policy.resolveTarget(macID: mac, accountID: account, callerUID: 502, requestedTargetUID: 0))
        XCTAssertThrowsError(try CommandTargetResolver.resolve(uid: UInt32.max))
    }
    func testOrdinaryAccountCannotLoadProtectedPolicy() throws {
        guard getuid() != 0 else { throw XCTSkip("Requires an ordinary account") }
        XCTAssertThrowsError(try CommandElevationPolicy.load(path: "/Library/Remozio/elevation.cbor")) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
