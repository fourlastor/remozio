import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class SetupOrphanRecoveryEndpointTests: XCTestCase, @unchecked Sendable {
    typealias W = SetupOrphanRecoveryWire
    enum Failure: Error { case expected }
    final class Harness: @unchecked Sendable {
        private let root: URL
        let owner: SetupAccountOwner
        let peer: SetupOrphanRecoveryOperations.Peer
        let live = Mutex(true), imports = Mutex(0), hostChecks = Mutex(0), failImport = Mutex(false)
        let route = Mutex(AdministrativeSetupLifecycle.State.serving)
        let clock = Mutex(ContinuousClock.now)
        var hasHost = true
        var onImport: (@Sendable () -> Void)?
        init() throws {
            try RuntimeMaintenanceOwnedControl.require()
            let root = URL(fileURLWithPath: "/private/tmp/remozio-orphan-endpoint-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
            let mac = Data(repeating: 1, count: 16), release = Data(repeating: 7, count: 32)
            do {
                let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "machine", owner: getuid())
                defer { directory.close() }
                _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .installation, owner: getuid())
                let machine = try PreparationIntentStore(lease: InstallationStorageLease(anchor: root.path,
                    relativeDirectory: "machine", owner: getuid()), macID: mac, maximumRecords: 10, initialize: true)
                defer { try? machine.close() }
                try machine.upgradeInventoryStorage()
                let account = Data(repeating: 2, count: 16)
                _ = try machine.writeInventory(.init(macID: mac, installationID: Data(repeating: 3, count: 16),
                    revision: Data(repeating: 4, count: 16), bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: release,
                    accounts: [.init(accountID: account, ownerUID: getuid())], services: [.init(role: .authority, kind: .daemon,
                        domainUID: nil, executionUID: 0, label: "dev.sebastiano.remozio.macos.authority",
                        plistName: "dev.sebastiano.remozio.macos.authority.plist", accountID: account)]), expectedRevision: nil)
                try machine.close()
                owner = try .init(openMachine: {
                    try PreparationIntentStore(lease: InstallationStorageLease(anchor: root.path,
                        relativeDirectory: "machine", owner: getuid()), macID: mac, maximumRecords: 10, initialize: false)
                }, expectedReleaseDigest: release, resume: { _, value in value })
            } catch { try? FileManager.default.removeItem(at: root); throw error }
            self.root = root
            peer = .init(credentials: .init(processID: getpid(), userID: getuid(), auditSessionID: 1),
                owner: .init(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID()))
        }
        func session(verify: (@Sendable () throws -> SetupOrphanRecoveryOperations.Peer)? = nil) throws -> SetupOrphanRecoveryEndpoint {
            let host: (@Sendable () throws -> Void)?
            if hasHost { host = { @Sendable [self] in hostChecks.withLock { $0 += 1 } } } else { host = nil }
            let effects = SetupOrphanRecoveryOperations.Effects(verifyPeer: { [self] in
                guard live.withLock({ $0 }) else { throw Failure.expected }
                return try verify?() ?? peer
            }, routing: { [self] in route.withLock { $0 } }, checkHost: host, importAuthorization: { [self] _ in
                imports.withLock { $0 += 1 }; onImport?()
                guard !failImport.withLock({ $0 }) else { throw Failure.expected }
                return try .openOwned(peer: peer.credentials, currentOwner: peer.owner, incarnation: UUID(), verifyRights: {})
            }, restore: { _, _, _ in throw Failure.expected }, adopt: { _, _ in throw Failure.expected }, now: { [self] in clock.withLock { $0 } })
            return try .openOwned(operations: .owned(owner: owner, effects: effects), maximumConnections: 8)
        }
        deinit { try? owner.close(); try? FileManager.default.removeItem(at: root) }
    }
    static func request(_ action: W.Action = .restore, id: UInt8 = 1,
        identity: SetupRetainedInvocationStatus.Identity? = nil) throws -> W.Request {
        try .init(requestID: Data(repeating: id, count: 16), action: action, identity: identity)
    }
    @discardableResult
    static func start(_ session: SetupOrphanRecoveryEndpoint, _ request: W.Request, form: Data = Data(),
        onReply: (@Sendable () -> Void)? = nil) throws -> Data {
        let result = Mutex<Data?>(nil)
        session.start(try request.bytes, authorization: form) { bytes in result.withLock { $0 = bytes }; onReply?() }
        return try XCTUnwrap(result.withLock { $0 })
    }
    static func code(_ session: SetupOrphanRecoveryEndpoint, _ request: W.Request) throws -> W.Code {
        let bytes = try XCTUnwrap(session.progress(W.Progress(requestID: request.requestID).bytes))
        return try W.Reply.decode(bytes).code
    }
    func testDuplicateWithDifferentAuthorizationFormImportsExactlyOnce() throws {
        let h = try Harness(), s = try h.session(), r = try Self.request()
        defer { s.close() }
        let first = try Self.start(s, r, form: Data([1]))
        XCTAssertEqual(try Self.start(s, r, form: Data([2])), first)
        XCTAssertEqual(h.imports.withLock { $0 }, 1)
        XCTAssertEqual(try W.Reply.decode(first).code, .requestRecorded)
    }
    func testChangedPayloadAndDifferentIDRefuseOnlyThatCall() throws {
        let h = try Harness(), s = try h.session(), r = try Self.request()
        defer { s.close() }
        let first = try Self.start(s, r)
        for other in [try Self.request(.releaseWindowFree), try Self.request(id: 2)] {
            XCTAssertEqual(try W.Reply.decode(Self.start(s, other)).code, .refusedUnavailable)
        }
        XCTAssertEqual(try Self.start(s, r), first)
        XCTAssertEqual(h.imports.withLock { $0 }, 1)
    }
    func testMissingHostRefusesWithoutImportOrClaim() throws {
        let h = try Harness(); h.hasHost = false
        let s = try h.session(), r = try Self.request(); defer { s.close() }
        try Self.start(s, r)
        XCTAssertEqual(try Self.code(s, r), .refusedUnavailable)
        XCTAssertEqual(h.imports.withLock { $0 }, 0)
        XCTAssertEqual(h.hostChecks.withLock { $0 }, 0)
    }
    func testRightsImportFailureOccursAfterTheRecordedReplyWithoutAClaim() throws {
        let h = try Harness(); h.failImport.withLock { $0 = true }
        let s = try h.session(), r = try Self.request(); defer { s.close() }
        try Self.start(s, r, onReply: { XCTAssertEqual(h.imports.withLock { $0 }, 0) })
        XCTAssertEqual(try Self.code(s, r), .failedAuthorization)
        XCTAssertEqual(h.imports.withLock { $0 }, 1)
        XCTAssertEqual(h.hostChecks.withLock { $0 }, 0)
    }
    func testStatusAndNormalRefusalsDoNotResetTheRecordedRequest() throws {
        let h = try Harness(), s = try h.session(), r = try Self.request(); defer { s.close() }
        let first = try Self.start(s, r)
        XCTAssertNotNil(s.refuseForeignSelector()); XCTAssertNotNil(s.refuseForeignSelector())
        XCTAssertEqual(try Self.start(s, r), first)
        XCTAssertEqual(h.imports.withLock { $0 }, 1)
    }
    func testInvalidProgressDoesNotCloseTheSession() throws {
        let h = try Harness(), s = try h.session(), r = try Self.request(); defer { s.close() }
        let first = try Self.start(s, r)
        XCTAssertNil(s.progress(Data([0])))
        XCTAssertEqual(try Self.start(s, r), first)
    }
    func testFailedPeerCheckClosesTheSession() throws {
        for selector in ["hello", "start", "progress"] {
            let h = try Harness(), checks = Mutex(0), endpointChecks = Mutex(0)
            let session = try h.session(verify: {
                endpointChecks.withLock { $0 += 1 }
                guard h.live.withLock({ $0 }) else { throw Failure.expected }; return h.peer
            })
            let facade = AdministrativeSetupConnectionFacade(verify: {
                checks.withLock { $0 += 1 }
                guard h.live.withLock({ $0 }) else { throw Failure.expected }; return h.peer.credentials
            }, select: { _ in true }, openNormal: { _ in throw Failure.expected }, status: { _ in .unavailable },
                openRecovery: { _ in session }, recoveryAllowed: { true }, invalidate: {})
            defer { facade.close() }
            let hello = Mutex<UInt64?>(nil)
            facade.recoveryHello { value in hello.withLock { $0 = value } }
            XCTAssertEqual(hello.withLock { $0 }, 13); XCTAssertEqual(facade.state, .recoveryOnly)
            let before = checks.withLock { $0 }; h.live.withLock { $0 = false }
            switch selector {
            case "hello":
                let reply = Mutex<UInt64?>(nil); facade.recoveryHello { value in reply.withLock { $0 = value } }
                XCTAssertEqual(reply.withLock { $0 }, 0)
            case "start":
                let reply = Mutex<Data?>(nil)
                facade.startRecovery(try Self.request().bytes, authorization: Data()) { value in reply.withLock { $0 = value } }
                XCTAssertNil(reply.withLock { $0 })
            default:
                let reply = Mutex<Data?>(nil)
                facade.recoveryProgress(try W.Progress(requestID: Self.request().requestID).bytes) { value in reply.withLock { $0 = value } }
                XCTAssertNil(reply.withLock { $0 })
            }
            XCTAssertEqual(checks.withLock { $0 }, before + 1, selector)
            XCTAssertEqual(facade.state, .closed); XCTAssertEqual(h.imports.withLock { $0 }, 0)
            XCTAssertEqual(endpointChecks.withLock { $0 }, 1)
        }
        for selector in ["start", "progress", "foreign"] {
            let h = try Harness(), checks = Mutex(0), peerLive = Mutex(true), request = try Self.request()
            let session = try h.session(verify: {
                checks.withLock { $0 += 1 }
                guard peerLive.withLock({ $0 }) else { throw Failure.expected }; return h.peer
            })
            defer { session.close() }; XCTAssertEqual(checks.withLock { $0 }, 1)
            peerLive.withLock { $0 = false }
            switch selector {
            case "start":
                let reply = Mutex<Data?>(nil)
                session.start(try request.bytes, authorization: Data()) { value in reply.withLock { $0 = value } }
                XCTAssertNil(reply.withLock { $0 })
            case "progress": XCTAssertNil(session.progress(try W.Progress(requestID: request.requestID).bytes))
            default: XCTAssertNil(session.refuseForeignSelector())
            }
            XCTAssertEqual(checks.withLock { $0 }, 2, selector); XCTAssertEqual(h.imports.withLock { $0 }, 0)
            peerLive.withLock { $0 = true }
            XCTAssertNil(session.progress(try W.Progress(requestID: request.requestID).bytes))
        }
    }
    func testStartupAndClosedRoutingRefuseWithoutImport() throws {
        for state in [AdministrativeSetupLifecycle.State.starting, .discovering, .closed] {
            let h = try Harness(), s = try h.session(), r = try Self.request(); defer { s.close() }
            h.route.withLock { $0 = state }; try Self.start(s, r)
            XCTAssertEqual(try Self.code(s, r), .refusedUnavailable)
            XCTAssertEqual(h.imports.withLock { $0 }, 0)
        }
    }
    func testRetirementDoesNotStartARestorationImport() throws {
        let h = try Harness(), s = try h.session(), r = try Self.request(); defer { s.close() }
        h.route.withLock { $0 = .retiring }; try Self.start(s, r)
        XCTAssertEqual(try Self.code(s, r), .refusedUnavailable)
        XCTAssertEqual(h.imports.withLock { $0 }, 0)
    }
    func testCloseDuringImportCannotInstallALateClaim() throws {
        let h = try Harness(), s = try h.session(), r = try Self.request()
        h.onImport = { [weak s] in s?.close() }; defer { h.onImport = nil }
        try Self.start(s, r)
        XCTAssertNil(s.progress(try W.Progress(requestID: r.requestID).bytes))
        XCTAssertEqual(h.imports.withLock { $0 }, 1)
    }
    func testPeerDriftBeforeTheStartReplyClosesWithoutReturningBytesOrImporting() throws {
        let h = try Harness(), calls = Mutex(0)
        let changed = SetupOrphanRecoveryOperations.Peer(credentials: h.peer.credentials,
            owner: .init(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID()))
        let s = try h.session(verify: {
            let count = calls.withLock { $0 += 1; return $0 }
            return count == 3 ? changed : h.peer
        })
        let replies = Mutex<[Data?]>([]), r = try Self.request()
        s.start(try r.bytes, authorization: Data()) { value in replies.withLock { $0.append(value) } }
        XCTAssertEqual(replies.withLock { $0.count }, 1)
        XCTAssertTrue(replies.withLock { $0.allSatisfy { $0 == nil } })
        XCTAssertEqual(h.imports.withLock { $0 }, 0)
        XCTAssertNil(s.progress(try W.Progress(requestID: r.requestID).bytes))
    }
    func testPeerDriftBeforeTheProgressReplyClosesWithoutReturningBytes() throws {
        let h = try Harness(), calls = Mutex(0), driftAt = Mutex<Int?>(nil)
        let changed = SetupOrphanRecoveryOperations.Peer(credentials: h.peer.credentials,
            owner: .init(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID()))
        let s = try h.session(verify: {
            let count = calls.withLock { $0 += 1; return $0 }
            return driftAt.withLock({ $0 == count }) ? changed : h.peer
        }), r = try Self.request()
        try Self.start(s, r)
        driftAt.withLock { $0 = calls.withLock { $0 } + 2 }
        XCTAssertNil(s.progress(try W.Progress(requestID: r.requestID).bytes))
        driftAt.withLock { $0 = nil }
        XCTAssertNil(s.progress(try W.Progress(requestID: r.requestID).bytes))
        XCTAssertEqual(h.imports.withLock { $0 }, 1)
    }
}
