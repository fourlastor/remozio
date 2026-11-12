import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MachineUpdateRetainedSetupPromotionNativeSupportTests: XCTestCase {
    private typealias Support = MachineUpdateRetainedSetupPromotionNativeSupport
    private enum Failed: Error { case injected }

    private final class Fixture {
        let root: URL
        let initial: AuthorityInitializationIntent
        private let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)

        init() throws {
            let root = URL(fileURLWithPath: "/private/tmp/remozio-promotion-native-support-" + UUID().uuidString)
            self.root = root
            let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700])
            for (name, kind) in [("journal", SetupDatabaseKind.journal), ("continuity", .continuity)] {
                let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: name, owner: getuid())
                defer { directory.close() }
                _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: kind, owner: getuid())
            }
            let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(Data(repeating: 3, count: 16)),
                4: .unsigned(1), 5: .unsigned(AuditEpochCause.initial.rawValue), 6: .null, 7: .null, 8: .null]),
                limits: limits), limits: limits)
            let policy = try AuthorityCodePolicy(entries: [.init(role: .authority, teamID: "ABCDEFGHIJ",
                identifier: "dev.sebastiano.remozio.macos.authority", installedGeneration: 1, minimumGeneration: 1,
                codeDirectoryHash: Data(repeating: 4, count: 20), active: true)])
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 3)
            let seed = AuthorityJournalInitialization(descriptor: descriptor, codePolicy: policy,
                capabilities: .init(contracts: [contract: []]), allowedContracts: [contract])
            let journalPath = root.path + "/journal/journal.sqlite"
            let continuityPath = root.path + "/continuity/continuity.sqlite"
            let journal = try JournalDatabase(lease: .init(anchor: root.path, relativeDirectory: "journal", owner: getuid()),
                macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 10, busyMilliseconds: 100, initialize: true, initialAuthority: seed)
            defer { try? journal.close() }
            let checkpoint = try journal.initialAuthorityCheckpoint(initial: seed, databasePath: journalPath)
            let continuity = try ContinuityStore(lease: .init(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
                macID: mac, accountID: account, initialize: checkpoint)
            continuity.close()
            initial = try .init(setupID: Data(repeating: 5, count: 16), revision: Data(repeating: 6, count: 16),
                installationID: Data(repeating: 7, count: 16), macID: mac, accountID: account,
                releaseDigest: Data(repeating: 8, count: 32), initializationDigest: seed.initializationDigest,
                initializationBytes: seed.initializationBytes, journalPath: journalPath, continuityPath: continuityPath,
                checkpoint: checkpoint, complete: true)
        }
        deinit { try? FileManager.default.removeItem(at: root) }

        func open() throws -> sending AuthorityStorage {
            let anchor = root.path
            return try Support.openExistingStorage(initial: initial, openJournalLease: {
                try ProtectedJournalLease(anchor: anchor, relativeDirectory: "journal", owner: getuid())
            }, openContinuityLease: { excluded in
                try ProtectedContinuityLease(anchor: anchor, relativeDirectory: "continuity", owner: getuid(),
                    excludingDirectory: excluded)
            })
        }
        func openMutable() throws -> sending AuthorityStorage {
            let anchor = root.path, initial = initial, limits = limits
            return try AuthorityStorage(openJournal: {
                try JournalDatabase(lease: .init(anchor: anchor, relativeDirectory: "journal", owner: getuid()),
                    macID: initial.macID, accountID: initial.accountID, recordLimits: limits, descriptorLimits: limits,
                    decisionLimits: limits, maximumConsumptions: 10, busyMilliseconds: 100, initialize: false)
            }, openContinuity: { excluded in
                try ContinuityStore(lease: .init(anchor: anchor, relativeDirectory: "continuity", owner: getuid(),
                    excludingDirectory: excluded), macID: initial.macID, accountID: initial.accountID, initialize: nil)
            })
        }
        func bytes() throws -> [Data] {
            try [initial.journalPath, initial.continuityPath].map { try Data(contentsOf: URL(fileURLWithPath: $0)) }
        }
        func assertReleased(file: StaticString = #filePath, line: UInt = #line) throws {
            let journal = try ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: getuid())
            defer { journal.close() }
            let continuity = try ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: getuid())
            defer { continuity.close() }
            XCTAssertNoThrow(try journal.validate(), file: file, line: line)
            XCTAssertNoThrow(try continuity.validate(), file: file, line: line)
        }
    }

    func testAccountPathsRequireTheExactSeparateNativeDirectories() throws {
        let account = Data(repeating: 2, count: 16)
        let directory = try AccountPreparationController.authorityDirectory(accountID: account)
        let journal = directory + "/Journal/journal.sqlite", continuity = directory + "/Continuity/continuity.sqlite"
        let paths = try Support.Paths(accountID: account, journalPath: journal, continuityPath: continuity)
        XCTAssertEqual(paths.journalDirectory, directory + "/Journal")
        XCTAssertEqual(paths.continuityDirectory, directory + "/Continuity")
        for pair in [(continuity, journal), (journal + "/child", continuity),
                     (journal, directory + "/Journal/continuity.sqlite"), (journal.replacingOccurrences(of: "/Journal/", with: "/journal/"), continuity)] {
            XCTAssertThrowsError(try Support.Paths(accountID: account, journalPath: pair.0, continuityPath: pair.1))
        }
        XCTAssertThrowsError(try Support.Paths(accountID: Data(repeating: 9, count: 16), journalPath: journal, continuityPath: continuity))
        XCTAssertThrowsError(try Support.Paths(accountID: Data(count: 15), journalPath: journal, continuityPath: continuity))
    }

    func testReadOnlyPairClosesBothStoresAndExpiresTheRetainedCallback() throws {
        let fixture = try Fixture(), before = try fixture.bytes()
        var retained: AuthorityJournal?, callback: Support.Verify?, calls = 0
        let value = try Support.withReadOnlyPair(initial: fixture.initial, verifyCurrent: { calls += 1 }, openStorage: fixture.open) {
            journal, verify in
            retained = journal; callback = verify
            XCTAssertTrue(journal.updateHealthOnly)
            XCTAssertEqual(try journal.captureRetainedSetupPolicyBoundary(expected: fixture.initial).accountID, fixture.initial.accountID)
            try verify(); return 17
        }
        XCTAssertEqual(value, 17); XCTAssertGreaterThan(calls, 2)
        let callsAtReturn = calls
        XCTAssertThrowsError(try XCTUnwrap(callback)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertEqual(calls, callsAtReturn)
        XCTAssertThrowsError(try XCTUnwrap(retained).captureRetainedSetupPolicyBoundary(expected: fixture.initial))
        XCTAssertEqual(try fixture.bytes(), before); try fixture.assertReleased()
    }

    func testBothConnectionsRefuseWritesWithoutChangingTheirBytes() throws {
        let fixture = try Fixture(), before = try fixture.bytes()
        let storage = try fixture.open()
        XCTAssertTrue(storage.journal.readOnlyForCutover)
        XCTAssertTrue(storage.continuity.readOnlyForCutover)
        XCTAssertThrowsError(try storage.journal.write { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        XCTAssertThrowsError(try storage.continuity.requireRecovery())
        try storage.close()
        XCTAssertEqual(try fixture.bytes(), before); try fixture.assertReleased()
    }

    func testBodyFailureClosesBothStoresWithoutChangingBytes() throws {
        let fixture = try Fixture(), before = try fixture.bytes()
        var callback: Support.Verify?
        XCTAssertThrowsError(try Support.withReadOnlyPair(initial: fixture.initial, verifyCurrent: {}, openStorage: fixture.open) {
            _, verify -> Void in callback = verify; throw Failed.injected
        }) { XCTAssertTrue($0 is Failed) }
        XCTAssertThrowsError(try XCTUnwrap(callback)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertEqual(try fixture.bytes(), before); try fixture.assertReleased()
    }

    func testVerifierFailureAfterTheBodyClosesBothStores() throws {
        let fixture = try Fixture(), before = try fixture.bytes()
        var fail = false
        XCTAssertThrowsError(try Support.withReadOnlyPair(initial: fixture.initial,
            verifyCurrent: { if fail { throw Failed.injected } }, openStorage: fixture.open) { _, _ in fail = true }) {
            XCTAssertTrue($0 is Failed)
        }
        XCTAssertEqual(try fixture.bytes(), before); try fixture.assertReleased()
    }

    // This probe holds no store ownership. Only the synchronous verifier reads its weak reference.
    private final class JournalReadProbe: @unchecked Sendable {
        weak var journal: JournalDatabase?
        var reads = 0
        func verify() throws {
            if let journal { try journal.read { _ in }; reads += 1 }
        }
    }

    func testEveryCustodyCallbackCanReadTheSameConnectionOutsideATransaction() throws {
        let fixture = try Fixture(), probe = JournalReadProbe(), before = try fixture.bytes()
        var events = [String]()
        try Support.withReadOnlyPair(initial: fixture.initial, verifyCurrent: {
            events.append("verify"); try probe.verify()
        }, openStorage: {
            events.append("open")
            let storage = try fixture.open()
            probe.journal = storage.journal
            return storage
        }) { _, verify in
            events.append("body")
            XCTAssertEqual(events, ["verify", "open", "verify", "verify", "verify", "body"])
            try verify()
        }
        XCTAssertEqual(Array(events.prefix(3)), ["verify", "open", "verify"])
        XCTAssertGreaterThan(probe.reads, 0)
        XCTAssertEqual(try fixture.bytes(), before); try fixture.assertReleased()
    }

    func testFailureImmediatelyAfterTheConstructorClosesBothStores() throws {
        let fixture = try Fixture(), before = try fixture.bytes()
        var verifies = 0, opened = false
        XCTAssertThrowsError(try Support.withReadOnlyPair(initial: fixture.initial, verifyCurrent: {
            verifies += 1
            if verifies == 2 { throw Failed.injected }
        }, openStorage: {
            XCTAssertEqual(verifies, 1)
            opened = true
            return try fixture.open()
        }) { _, _ in XCTFail("The body ran after verification failed") }) { XCTAssertTrue($0 is Failed) }
        XCTAssertTrue(opened); XCTAssertEqual(verifies, 2)
        XCTAssertEqual(try fixture.bytes(), before); try fixture.assertReleased()
    }

    func testMutableStorageIsRefusedBeforeTheBodyAndIsClosed() throws {
        let fixture = try Fixture(), before = try fixture.bytes()
        XCTAssertThrowsError(try Support.withReadOnlyPair(initial: fixture.initial, verifyCurrent: {}, openStorage: fixture.openMutable) {
            _, _ in XCTFail("The body received mutable storage")
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        XCTAssertEqual(try fixture.bytes(), before); try fixture.assertReleased()
    }

    func testIncompleteIntentIsRefusedBeforeOpeningStorage() throws {
        let fixture = try Fixture(), initial = try fixture.initial.advancing(checkpoint: XCTUnwrap(fixture.initial.checkpoint), complete: false)
        XCTAssertThrowsError(try Support.withReadOnlyPair(initial: initial, verifyCurrent: { XCTFail("The verifier ran") },
            openStorage: { XCTFail("Storage opened"); throw Failed.injected }, perform: { _, _ in XCTFail("The body ran") })) {
            XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
        }
        XCTAssertThrowsError(try Support.openExistingStorage(initial: initial,
            openJournalLease: { XCTFail("The journal opened"); throw Failed.injected },
            openContinuityLease: { _ in XCTFail("Continuity opened"); throw Failed.injected }))
    }

    func testJournalOpenFailureDoesNotAcquireContinuity() throws {
        let fixture = try Fixture(), before = try fixture.bytes()
        XCTAssertThrowsError(try Support.openExistingStorage(initial: fixture.initial,
            openJournalLease: { throw Failed.injected }, openContinuityLease: { _ in
                XCTFail("Continuity opened after journal failure"); throw Failed.injected
            })) { XCTAssertTrue($0 is Failed) }
        XCTAssertEqual(try fixture.bytes(), before); try fixture.assertReleased()
    }

    func testContinuityOpenFailureReleasesTheJournalLease() throws {
        let fixture = try Fixture(), anchor = fixture.root.path, before = try fixture.bytes()
        XCTAssertThrowsError(try Support.openExistingStorage(initial: fixture.initial, openJournalLease: {
            try ProtectedJournalLease(anchor: anchor, relativeDirectory: "journal", owner: getuid())
        }, openContinuityLease: { _ in throw Failed.injected })) { XCTAssertTrue($0 is Failed) }
        XCTAssertEqual(try fixture.bytes(), before); try fixture.assertReleased()
    }

    func testAFactoryCannotSubstituteAnotherValidJournalPath() throws {
        let expected = try Fixture(), other = try Fixture(), anchor = other.root.path
        XCTAssertThrowsError(try Support.openExistingStorage(initial: expected.initial, openJournalLease: {
            try ProtectedJournalLease(anchor: anchor, relativeDirectory: "journal", owner: getuid())
        }, openContinuityLease: { _ in XCTFail("Continuity opened after the wrong path"); throw Failed.injected })) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
        }
        try expected.assertReleased(); try other.assertReleased()
    }

    func testAFactoryCannotSubstituteAnotherValidContinuityPath() throws {
        let expected = try Fixture(), other = try Fixture(), anchor = expected.root.path, otherAnchor = other.root.path
        XCTAssertThrowsError(try Support.openExistingStorage(initial: expected.initial, openJournalLease: {
            try ProtectedJournalLease(anchor: anchor, relativeDirectory: "journal", owner: getuid())
        }, openContinuityLease: { excluded in
            try ProtectedContinuityLease(anchor: otherAnchor, relativeDirectory: "continuity", owner: getuid(), excludingDirectory: excluded)
        })) { XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary) }
        try expected.assertReleased(); try other.assertReleased()
    }

    func testContinuityAcquisitionReceivesTheJournalIdentityAndRejectsItsDirectory() throws {
        let fixture = try Fixture(), anchor = fixture.root.path
        let lease = try ProtectedJournalLease(anchor: anchor, relativeDirectory: "journal", owner: getuid())
        let identity = try XCTUnwrap(lease.directoryIdentities().last); lease.close()
        XCTAssertThrowsError(try Support.openExistingStorage(initial: fixture.initial, openJournalLease: {
            try ProtectedJournalLease(anchor: anchor, relativeDirectory: "journal", owner: getuid())
        }, openContinuityLease: { excluded in
            XCTAssertEqual(excluded, identity)
            return try ProtectedContinuityLease(anchor: anchor, relativeDirectory: "journal", owner: getuid(), excludingDirectory: excluded)
        })) { XCTAssertEqual($0 as? JournalLeaseError, .invalidPath) }
        try fixture.assertReleased()
    }

    func testMissingStorageIsNotCreatedAndTheOtherStoreIsUnchanged() throws {
        for path in ["journal/journal.sqlite", "continuity/continuity.sqlite"] {
            let fixture = try Fixture(), missing = fixture.root.appendingPathComponent(path)
            try FileManager.default.removeItem(at: missing)
            let other = path.hasPrefix("journal/") ? fixture.initial.continuityPath : fixture.initial.journalPath
            let before = try Data(contentsOf: URL(fileURLWithPath: other))
            XCTAssertThrowsError(try fixture.open())
            XCTAssertFalse(FileManager.default.fileExists(atPath: missing.path))
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: other)), before)
            if path.hasPrefix("journal/") {
                let lease = try ProtectedContinuityLease(anchor: fixture.root.path, relativeDirectory: "continuity", owner: getuid())
                lease.close()
            } else {
                let lease = try ProtectedJournalLease(anchor: fixture.root.path, relativeDirectory: "journal", owner: getuid())
                lease.close()
            }
        }
    }

    func testSQLitePreflightRejectsRecoveryFilesWithoutRemovingThem() throws {
        let fixture = try Fixture(), before = try fixture.bytes()
        for suffix in ["-journal", "-wal", "-shm"] {
            let path = fixture.initial.continuityPath + suffix, bytes = Data([4, 5, 6])
            try bytes.write(to: URL(fileURLWithPath: path))
            XCTAssertThrowsError(try fixture.open()) { XCTAssertEqual($0 as? JournalDatabaseError, .incompatibleStore) }
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), bytes)
            XCTAssertEqual(try fixture.bytes(), before); try fixture.assertReleased()
            try FileManager.default.removeItem(atPath: path)
        }
    }

    func testScopedVerificationExpiresAndReleasesItsBorrowedCapture() throws {
        final class Capture {}
        weak var released: Capture?
        var callback: Support.Verify?
        do {
            let capture = Capture(); released = capture
            try Support.withScopedVerification({ _ = capture }) { verify in callback = verify; try verify() }
        }
        XCTAssertNil(released)
        XCTAssertThrowsError(try XCTUnwrap(callback)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }

    func testReentrantVerificationRetiresTheLoanEvenIfTheBodyCatchesIt() throws {
        var callback: Support.Verify?, calls = 0
        try Support.withScopedVerification({
            calls += 1
            XCTAssertThrowsError(try XCTUnwrap(callback)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }) { verify in
            callback = verify
            XCTAssertThrowsError(try verify()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try verify()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
        XCTAssertEqual(calls, 1)
    }

    func testVerifierFailureRetiresTheLoanWithoutRetryingItsBody() throws {
        var calls = 0
        try Support.withScopedVerification({ calls += 1; throw Failed.injected }) { verify in
            XCTAssertThrowsError(try verify()) { XCTAssertTrue($0 is Failed) }
            XCTAssertThrowsError(try verify()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
        XCTAssertEqual(calls, 1)
    }

    private final class ForeignThreadCall: @unchecked Sendable {
        let verify: Support.Verify
        init(_ verify: @escaping Support.Verify) { self.verify = verify }
        func rejected() -> Bool {
            do { try verify(); return false }
            catch JournalLeaseError.invalidated { return true }
            catch { return false }
        }
    }

    func testAnotherThreadCannotInvokeTheBorrowedVerifier() throws {
        var calls = 0
        try Support.withScopedVerification({ calls += 1 }) { verify in
            let call = ForeignThreadCall(verify), done = DispatchSemaphore(value: 0)
            DispatchQueue.global().async { XCTAssertTrue(call.rejected()); done.signal() }
            XCTAssertEqual(done.wait(timeout: .now() + 2), .success)
            XCTAssertEqual(calls, 0)
            try verify()
        }
        XCTAssertEqual(calls, 1)
    }

    func testAForkedChildCannotInvokeTheBorrowedVerifier() throws {
        try Support.withScopedVerification({ _exit(11) }) { verify in
            let child = Self.forkProcess()
            guard child >= 0 else { throw JournalLeaseError.system(errno) }
            if child == 0 {
                do { try verify(); _exit(12) }
                catch JournalLeaseError.invalidated { _exit(0) }
                catch { _exit(13) }
            }
            let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
            var status: Int32 = 0
            while DispatchTime.now().uptimeNanoseconds < deadline {
                let result = waitpid(child, &status, WNOHANG)
                if result == child { XCTAssertEqual(status, 0); return }
                if result < 0, errno != EINTR { throw JournalLeaseError.system(errno) }
                usleep(10_000)
            }
            _ = kill(child, SIGKILL)
            while waitpid(child, &status, 0) < 0 && errno == EINTR {}
            XCTFail("The child did not reject the borrowed verifier")
        }
    }

    private static let forkProcess: @convention(c) () -> pid_t = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork") else { preconditionFailure("fork is not available") }
        return unsafeBitCast(symbol, to: (@convention(c) () -> pid_t).self)
    }()
}
