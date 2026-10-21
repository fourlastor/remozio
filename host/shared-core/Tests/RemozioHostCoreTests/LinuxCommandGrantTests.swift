#if os(Linux)
import Foundation
import Glibc
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioHostCore

final class LinuxCommandGrantTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private enum Failure: Error { case missingPolicy, unreadablePolicy, credentialsUnavailable, nssUnavailable }
    private static func credentials(uid: UInt32 = 501, gid: UInt32 = 20, groups: [UInt32] = [20, 40],
                                    savedUID: UInt32? = nil, filesystemGID: UInt32? = nil) -> CapturedLinuxCredentials {
        .init(realUID: uid, effectiveUID: uid, savedUID: savedUID ?? uid, filesystemUID: uid,
            realGID: gid, effectiveGID: gid, savedGID: gid, filesystemGID: filesystemGID ?? gid,
            supplementaryGroups: groups)
    }
    private static let target = CommandTarget(uid: 501, gid: 20, supplementaryGroups: [20, 40], observedName: "fixture")
    private struct State: Sendable {
        var grants: Set<UInt32> = [501]
        var loadFailure: Failure?
        var wrongScope = false
        var reads = 0, credentialReads = 0, targetReads = 0
        var credentials = LinuxCommandGrantTests.credentials()
        var target = LinuxCommandGrantTests.target
        var unavailableCredentials = false, unavailableTarget = false
    }
    private final class Box: Sendable { let state = Mutex(State()) }
    private func gate(_ box: Box) throws -> LinuxCurrentCommandElevationPolicy {
        let mac = mac, account = account
        return try .init(macID: mac, accountID: account, callerUID: 501, load: {
            try box.state.withLock {
                $0.reads += 1
                if let failure = $0.loadFailure { throw failure }
                return try .init(macID: $0.wrongScope ? Data(count: 16) : mac, accountID: account,
                    callerUID: 501, allowedTargetUIDs: $0.grants, independentPolicyDisclosureAccepted: true)
            }
        }, readCallerCredentials: {
            try box.state.withLock {
                $0.credentialReads += 1
                if $0.unavailableCredentials { throw Failure.credentialsUnavailable }
                return $0.credentials
            }
        }, resolve: { caller, requested in
            try box.state.withLock {
                $0.targetReads += 1
                guard caller == 501, requested == 501 else { throw Failure.nssUnavailable }
                if $0.unavailableTarget { throw Failure.nssUnavailable }
                return $0.target
            }
        })
    }
    private func capture(target: CommandTarget = LinuxCommandGrantTests.target,
                         credentials: CapturedLinuxCredentials = LinuxCommandGrantTests.credentials()) throws -> LinuxCommandCapture {
        let stream = CapturedCommandInput(kind: .null, streamBinding: nil, observedPath: nil, identity: nil)
        let executable = CapturedExecutable(path: Data("/fixture/frontend".utf8),
            identity: .init(device: 1, inode: 2), sha256: Data(count: 32))
        return try .init(executable: executable, arguments: [Data("frontend".utf8)],
            directory: .init(path: Data("/tmp".utf8), identity: .init(device: 1, inode: 3)),
            target: target, environment: [], input: stream,
            requester: .init(pid: 42, processBinding: Data(count: 16), monitorIncarnation: Data(count: 16),
                execEpoch: 1, executable: executable, credentials: credentials, sessionID: nil,
                codePolicyDigest: Data(count: 32)), unverifiedRationale: nil,
            submission: .init(id: Data(count: 16), nonce: Data(count: 32), callerBinding: Data(count: 16)),
            stdioLayout: .init(input: .init(source: stream, access: .readOnly, flags: []),
                output: .init(source: stream, access: .writeOnly, flags: []),
                error: .init(source: stream, access: .writeOnly, flags: []), terminal: nil, ptyMask: 0),
            limits: .init(maxBytes: 8192, maxDepth: 16, maxItems: 1024))
    }
    private func resolve(_ gate: LinuxCurrentCommandElevationPolicy) throws -> CommandTarget {
        try gate.resolveTarget(macID: mac, accountID: account, callerUID: 501, requestedTargetUID: 501)
    }

    func testOwnAccountRequiresExplicitGrantAndEveryCallReloads() throws {
        let box = Box(), gate = try gate(box)
        XCTAssertEqual(try resolve(gate), Self.target)
        box.state.withLock { $0.grants = [] }
        XCTAssertThrowsError(try resolve(gate)) { XCTAssertEqual($0 as? CommandElevationPolicyError, .policyRejected) }
        box.state.withLock { $0.grants = [501]; $0.loadFailure = .missingPolicy }
        XCTAssertThrowsError(try resolve(gate)) { XCTAssertEqual($0 as? Failure, .missingPolicy) }
        box.state.withLock { $0.loadFailure = .unreadablePolicy }
        XCTAssertThrowsError(try resolve(gate)) { XCTAssertEqual($0 as? Failure, .unreadablePolicy) }
        XCTAssertEqual(box.state.withLock { $0.reads }, 4)
        XCTAssertEqual(box.state.withLock { $0.targetReads }, 1)
    }

    func testFinalValidationRefreshesPolicyAfterCaptureAndDoesNotCacheSuccess() throws {
        let box = Box(), gate = try gate(box), capture = try capture(target: resolve(gate))
        XCTAssertNoThrow(try gate.validate(capture: capture))
        box.state.withLock { $0.grants = [] }
        XCTAssertThrowsError(try gate.validate(capture: capture))
        box.state.withLock { $0.grants = [501]; $0.loadFailure = .unreadablePolicy }
        XCTAssertThrowsError(try gate.validate(capture: capture)) { XCTAssertEqual($0 as? Failure, .unreadablePolicy) }
        XCTAssertEqual(box.state.withLock { $0.reads }, 4)
        XCTAssertEqual(box.state.withLock { $0.credentialReads }, 2)
    }

    func testWrongScopeAndRootOrOtherTargetRefuseBeforeAnyLoaderOrNSSCall() throws {
        let box = Box(), gate = try gate(box)
        box.state.withLock { $0.grants = [0, 501, 502] }
        for (m, a, uid, target): (Data, Data, UInt32, UInt32) in [
            (Data(count: 16), account, 501, 501), (mac, Data(count: 16), 501, 501),
            (mac, account, 502, 502), (mac, account, 501, 0), (mac, account, 501, 502)
        ] {
            XCTAssertThrowsError(try gate.resolveTarget(macID: m, accountID: a, callerUID: uid, requestedTargetUID: target))
        }
        for uid: UInt32 in [0, 502] {
            let changed = CommandTarget(uid: uid, gid: 20, supplementaryGroups: [20, 40], observedName: "other")
            XCTAssertThrowsError(try gate.validate(capture: capture(target: changed)))
        }
        XCTAssertEqual(box.state.withLock { $0.reads }, 0)
        XCTAssertEqual(box.state.withLock { $0.targetReads }, 0)
        box.state.withLock { $0.wrongScope = true }
        XCTAssertThrowsError(try resolve(gate))
        XCTAssertEqual(box.state.withLock { $0.credentialReads }, 0)
    }

    func testCurrentCallerCredentialChangesAndMissingObservationsFail() throws {
        let box = Box(), gate = try gate(box), capture = try capture()
        XCTAssertNoThrow(try gate.validate(capture: capture))
        for changed in [Self.credentials(uid: 502), Self.credentials(gid: 21), Self.credentials(groups: [20]),
                        Self.credentials(savedUID: 502), Self.credentials(filesystemGID: 21),
                        Self.credentials(groups: [20, 20]), Self.credentials(groups: [40, 20]),
                        Self.credentials(groups: [20, UInt32.max])] {
            box.state.withLock { $0.credentials = changed }
            XCTAssertThrowsError(try gate.validate(capture: capture)) { XCTAssertEqual($0 as? CommandElevationPolicyError, .policyRejected) }
        }
        box.state.withLock { $0.credentials = Self.credentials(); $0.unavailableCredentials = true }
        XCTAssertThrowsError(try gate.validate(capture: capture)) { XCTAssertEqual($0 as? Failure, .credentialsUnavailable) }
        XCTAssertThrowsError(try resolve(gate)) { XCTAssertEqual($0 as? Failure, .credentialsUnavailable) }
    }

    func testTargetCredentialsAndNameAreResolvedAgainBeforeValidation() throws {
        let box = Box(), gate = try gate(box), capture = try capture(target: resolve(gate))
        for changed in [CommandTarget(uid: 502, gid: 20, supplementaryGroups: [20, 40], observedName: "fixture"),
                        .init(uid: 501, gid: 21, supplementaryGroups: [20, 21, 40], observedName: "fixture"),
                        .init(uid: 501, gid: 20, supplementaryGroups: [20], observedName: "fixture"),
                        .init(uid: 501, gid: 20, supplementaryGroups: [20, 40], observedName: "renamed")] {
            box.state.withLock { $0.target = changed }
            XCTAssertThrowsError(try gate.validate(capture: capture)) { XCTAssertEqual($0 as? CommandElevationPolicyError, .policyRejected) }
        }
        box.state.withLock { $0.unavailableTarget = true }
        XCTAssertThrowsError(try gate.validate(capture: capture)) { XCTAssertEqual($0 as? Failure, .nssUnavailable) }
        XCTAssertThrowsError(try resolve(gate)) { XCTAssertEqual($0 as? Failure, .nssUnavailable) }
    }

    func testNSSResolverBoundsOwnAccountAndMalformedOrUnavailableResults() throws {
        for (caller, requested): (UInt32, UInt32) in [(0, 0), (UInt32.max, UInt32.max), (501, 0), (501, 502)] {
            XCTAssertThrowsError(try LinuxOwnAccountTargetResolver.resolve(callerUID: caller, requestedTargetUID: requested,
                lookup: { _ in XCTFail("unsupported identity must not reach NSS"); return Self.target })) {
                XCTAssertEqual($0 as? LinuxTargetResolutionError, .unsupportedTarget)
            }
        }
        XCTAssertThrowsError(try LinuxOwnAccountTargetResolver.resolve(callerUID: 501, requestedTargetUID: 501,
            lookup: { _ in throw LinuxTargetResolutionError.unavailable })) {
            XCTAssertEqual($0 as? LinuxTargetResolutionError, .unavailable)
        }
        for invalid in [CommandTarget(uid: 502, gid: 20, supplementaryGroups: [20], observedName: "fixture"),
                        .init(uid: 501, gid: UInt32.max, supplementaryGroups: [UInt32.max], observedName: "fixture"),
                        .init(uid: 501, gid: 20, supplementaryGroups: [], observedName: "fixture"),
                        .init(uid: 501, gid: 20, supplementaryGroups: [40], observedName: "fixture"),
                        .init(uid: 501, gid: 20, supplementaryGroups: [20, 20], observedName: "fixture"),
                        .init(uid: 501, gid: 20, supplementaryGroups: [20], observedName: nil)] {
            XCTAssertThrowsError(try LinuxOwnAccountTargetResolver.resolve(callerUID: 501, requestedTargetUID: 501,
                lookup: { _ in invalid })) { XCTAssertEqual($0 as? LinuxTargetResolutionError, .invalidIdentity) }
        }
    }

    func testInvalidAdapterScopeAndRootCallerCannotBeConfigured() throws {
        for (m, a, uid): (Data, Data, UInt32) in [(Data(), account, 501), (mac, Data(), 501),
                                                (mac, account, 0), (mac, account, UInt32.max)] {
            XCTAssertThrowsError(try LinuxCurrentCommandElevationPolicy(macID: m, accountID: a, callerUID: uid,
                load: { XCTFail("invalid configuration must not load policy"); throw Failure.missingPolicy },
                readCallerCredentials: { XCTFail("invalid configuration must not read credentials"); return Self.credentials() })) {
                XCTAssertEqual($0 as? CommandElevationPolicyError, .invalidConfiguration)
            }
        }
    }

    func testNativeNSSOwnAccountResolutionWithExplicitObservationSeam() throws {
        let uid = getuid()
        guard uid > 0, uid == geteuid() else { throw XCTSkip("Requires ordinary current account") }
        let target = try LinuxOwnAccountTargetResolver.resolve(callerUID: uid, requestedTargetUID: uid)
        XCTAssertEqual(target.uid, uid)
        XCTAssertFalse(try XCTUnwrap(target.observedName).isEmpty)
        XCTAssertTrue(target.supplementaryGroups.contains(target.gid))
        // Credential reader is explicitly synthetic here; this tests native NSS, not caller authentication.
        let credentials = Self.credentials(uid: uid, gid: target.gid, groups: target.supplementaryGroups)
        let policy = try CommandElevationPolicy(macID: mac, accountID: account, callerUID: uid,
            allowedTargetUIDs: [uid], independentPolicyDisclosureAccepted: true)
        let gate = try LinuxCurrentCommandElevationPolicy(macID: mac, accountID: account, callerUID: uid,
            load: { policy }, readCallerCredentials: { credentials })
        XCTAssertEqual(try gate.resolveTarget(macID: mac, accountID: account, callerUID: uid, requestedTargetUID: uid), target)
        XCTAssertNoThrow(try gate.validate(capture: capture(target: target, credentials: credentials)))

    }
}
#endif
