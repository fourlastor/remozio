import Darwin
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class CurrentCommandElevationPolicyTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private struct State: Sendable { var grants: Set<UInt32> = [0]; var reads = 0; var unavailable = false }
    private final class StateBox: Sendable { let value = Mutex(State()) }
    private enum FixtureFailure: Error { case unavailable }

    private func gate(_ state: StateBox) throws -> CurrentCommandElevationPolicy {
        let mac = mac, account = account
        return try .init(macID: mac, accountID: account, callerUID: 501, load: {
            try state.value.withLock {
                $0.reads += 1
                if $0.unavailable { throw FixtureFailure.unavailable }
                return try .init(macID: mac, accountID: account, callerUID: 501, allowedTargetUIDs: $0.grants,
                    independentPolicyDisclosureAccepted: true)
            }
        })
    }

    func testEveryResolutionReadsCurrentGrantsAndFailureNeverUsesOldGrant() throws {
        let state = StateBox(), gate = try gate(state)
        XCTAssertEqual(try gate.resolveTarget(macID: mac, accountID: account, callerUID: 501, requestedTargetUID: 0).uid, 0)
        state.value.withLock { $0.grants = [] }
        XCTAssertThrowsError(try gate.resolveTarget(macID: mac, accountID: account, callerUID: 501, requestedTargetUID: 0))
        state.value.withLock { $0.grants = [0]; $0.unavailable = true }
        XCTAssertThrowsError(try gate.resolveTarget(macID: mac, accountID: account, callerUID: 501, requestedTargetUID: 0)) {
            XCTAssertTrue($0 is FixtureFailure)
        }
        XCTAssertEqual(state.value.withLock { $0.reads }, 3)
    }

    func testFinalCaptureValidationReloadsRevocationAndReadFailures() throws {
        let state = StateBox(), gate = try gate(state), root = try CommandTargetResolver.resolve(uid: 0)
        let capture = try CommandCapture(schemaVersion: 1,
            executable: .init(path: Data("/usr/bin/true".utf8), identity: .init(device: 1, inode: 2), sha256: Data(count: 32)),
            arguments: [Data("true".utf8)], directory: .init(path: Data("/tmp".utf8), identity: .init(device: 1, inode: 3)),
            target: root, environment: [], input: .init(kind: .null, streamBinding: nil, observedPath: nil, identity: nil),
            ioMode: .pipes, disconnectBehavior: .terminate,
            requester: .init(executablePath: Data("/fixture/caller".utf8), realUID: 501, effectiveUID: 501,
                pid: 10, pidVersion: 11, signing: .init(status: .unsigned, identifier: nil, team: nil, cdHash: nil), sessionID: nil, ttyPath: nil),
            ancestry: .init(completeness: .unavailable, entries: [], reason: .unsupported), unverifiedRationale: nil,
            submission: .init(id: Data(count: 16), nonce: Data(count: 32), callerBinding: Data(count: 16)),
            limits: .init(maxBytes: 8192, maxDepth: 16, maxItems: 1024))
        XCTAssertNoThrow(try gate.validate(capture: capture))
        state.value.withLock { $0.grants = [] }
        XCTAssertThrowsError(try gate.validate(capture: capture))
        state.value.withLock { $0.grants = [0]; $0.unavailable = true }
        XCTAssertThrowsError(try gate.validate(capture: capture)) { XCTAssertTrue($0 is FixtureFailure) }
        XCTAssertEqual(state.value.withLock { $0.reads }, 3)
    }

    func testWrongAuthenticatedScopeOrCallerCannotReadAnotherAccountPolicy() throws {
        let state = StateBox(), gate = try gate(state)
        for (mac, account, caller): (Data, Data, UInt32) in [
            (Data(count: 16), account, 501), (mac, Data(count: 16), 501), (mac, account, 502), (mac, account, 0)
        ] {
            XCTAssertThrowsError(try gate.resolveTarget(macID: mac, accountID: account, callerUID: caller, requestedTargetUID: 0))
        }
        XCTAssertEqual(state.value.withLock { $0.reads }, 0)
    }

    func testWrongLoadedPolicyScopeCannotReplaceConfiguredAccount() throws {
        let other = try CommandElevationPolicy(macID: Data(repeating: 3, count: 16), accountID: account,
            callerUID: 501, allowedTargetUIDs: [0], independentPolicyDisclosureAccepted: true)
        let gate = try CurrentCommandElevationPolicy(macID: mac, accountID: account, callerUID: 501, load: { other })
        XCTAssertThrowsError(try gate.resolveTarget(macID: mac, accountID: account, callerUID: 501, requestedTargetUID: 0))
    }

    func testProductionLoaderCannotUseUserOwnedPolicy() throws {
        guard getuid() != 0 else { throw XCTSkip("Requires an ordinary account") }
        let gate = try CurrentCommandElevationPolicy(path: "/tmp/remozio-elevation.cbor", macID: mac, accountID: account, callerUID: 501)
        XCTAssertThrowsError(try gate.resolveTarget(macID: mac, accountID: account, callerUID: 501, requestedTargetUID: 0)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
