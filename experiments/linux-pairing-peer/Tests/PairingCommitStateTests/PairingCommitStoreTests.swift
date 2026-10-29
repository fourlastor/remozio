import Crypto
import Foundation
import RemozioProtocol
import XCTest
@testable import PairingCommitState

private struct InjectedCrash: Error, Equatable { let step: PairingPersistenceStep }

private final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64
    init(_ value: UInt64) { self.value = value }
    var now: UInt64 { lock.lock(); defer { lock.unlock() }; return value }
    func set(_ new: UInt64) { lock.lock(); value = new; lock.unlock() }
}

final class PairingCommitStoreTests: XCTestCase {
    private let revision = Data(repeating: 0x11, count: 16)
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("pairing-commit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    private var stateDirectory: URL { root.appendingPathComponent("state") }

    private struct Candidate {
        let transcript: PairingTranscript
        let proof: Data
    }

    /// A transcript with fresh keys, signed by its own biometric key. Distinct `tag` values give distinct phones.
    private func candidate(tag: UInt8, setupTag: UInt8? = nil, expected: Data? = nil, replacement: PairingReplacement? = nil,
                           sharedPhoneID: Data? = nil, sharedBiometric: P256.Signing.PrivateKey? = nil,
                           sharedDecision: P256.Signing.PrivateKey? = nil) throws -> Candidate {
        let phoneID = sharedPhoneID ?? Data(repeating: tag, count: 16)
        let scope = try ChannelScope(macID: Data(repeating: 0xA1, count: 16), accountID: Data(repeating: 0xA2, count: 16),
                                     phoneID: phoneID, enrollmentEpoch: Data(repeating: tag &+ 0x40, count: 16))
        let phone = try ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: tag, count: 32),
                                     envelopeVersions: [1], requests: [], auditVersions: [])
        let mac = try ChannelOffer(role: .mac, scope: scope, nonce: Data(repeating: tag &+ 1, count: 32),
                                   envelopeVersions: [1], requests: [], auditVersions: [])
        func key(_ id: UInt8, _ secret: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) throws -> PairingKey {
            try PairingKey(keyID: Data(repeating: id, count: 16), publicKey: secret.publicKey.x963Representation)
        }
        let biometricPrivate = sharedBiometric ?? P256.Signing.PrivateKey()
        let transcript = try PairingTranscript(
            setupID: Data(repeating: setupTag ?? tag, count: 16), challenge: Data(repeating: tag, count: 32),
            phone: phone, mac: mac, minimumEnvelopeVersion: 1, selectedEnvelopeVersion: 1,
            macAuthorityKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            macTransportKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            transportKey: key(1), decisionKey: key(2, sharedDecision ?? P256.Signing.PrivateKey()), biometricKey: key(3, biometricPrivate),
            enrollmentTag: Data(repeating: tag, count: 32), replacement: replacement,
            expectedTrustRevision: expected ?? revision, issuedAtUnixMillis: 1_000, expiresAtUnixMillis: 301_000)
        let proof = try biometricPrivate.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation
        return Candidate(transcript: transcript, proof: proof)
    }

    private func store(clock: Clock = Clock(1_000), crash: (@Sendable (PairingPersistenceStep) throws -> Void)? = nil,
                       initial: Data? = nil) -> PairingCommitStore {
        PairingCommitStore(directory: stateDirectory, initialTrustRevision: initial ?? revision,
                           clock: { clock.now }, crashHook: crash)
    }

    private func commit(_ store: PairingCommitStore, _ candidate: Candidate, deadline: UInt64 = 10_000,
                        cancelled: @escaping @Sendable () -> Bool = { false }) throws -> Data {
        try store.commit(transcript: candidate.transcript, biometricProof: candidate.proof,
                         deadlineMilliseconds: deadline, isCancelled: cancelled)
    }

    // MARK: Basic commit

    func testInitialStateHasTheConfiguredRevisionAndNoPhones() throws {
        let store = store()
        XCTAssertEqual(try store.trustRevision(), revision)
        XCTAssertEqual(try store.list(), [])
        XCTAssertEqual(try self.store(initial: Data(repeating: 0x22, count: 16)).trustRevision(), revision,
                       "an existing state keeps its revision")
    }

    func testRandomInitialRevisionIsSixteenBytesAndStable() throws {
        let store = PairingCommitStore(directory: stateDirectory)
        let first = try store.trustRevision()
        XCTAssertEqual(first.count, 16)
        XCTAssertEqual(try PairingCommitStore(directory: stateDirectory).trustRevision(), first)
    }

    func testCommitStoresTheEnrollmentAndAdvancesTheRevisionDurably() throws {
        let one = try candidate(tag: 1)
        let next = try commit(store(), one)
        XCTAssertEqual(next.count, 16)
        XCTAssertNotEqual(next, revision)
        let reopened = store()
        XCTAssertEqual(try reopened.trustRevision(), next)
        XCTAssertEqual(try reopened.list(), [PairingEnrollmentSummary(
            phoneID: one.transcript.phone.scope.phoneID, epoch: one.transcript.phone.scope.enrollmentEpoch,
            setupID: one.transcript.setupID)])
    }

    func testDirectoryAndFilesArePrivate() throws {
        _ = try commit(store(), candidate(tag: 1))
        func mode(_ name: String?) throws -> Int {
            let url = name.map { stateDirectory.appendingPathComponent($0) } ?? stateDirectory
            return try (FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as! NSNumber).intValue
        }
        XCTAssertEqual(try mode(nil), 0o700)
        XCTAssertEqual(try mode("state.json"), 0o600)
        XCTAssertEqual(try mode("state.lock"), 0o600)
        XCTAssertFalse(FileManager.default.fileExists(atPath: stateDirectory.appendingPathComponent("state.json.tmp").path))
    }

    func testWorldReadableDirectoryAndSymlinkAreRefused() throws {
        try FileManager.default.createDirectory(at: stateDirectory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o755])
        XCTAssertThrowsError(try store().trustRevision()) { XCTAssertEqual($0 as? PairingCommitError, .unsafeDirectory) }
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root)
        XCTAssertThrowsError(try PairingCommitStore(directory: link).trustRevision()) {
            XCTAssertEqual($0 as? PairingCommitError, .unsafeDirectory)
        }
    }

    func testCorruptStateIsRefusedNeverReset() throws {
        _ = try store().trustRevision()
        try Data("not json".utf8).write(to: stateDirectory.appendingPathComponent("state.json"))
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: stateDirectory.appendingPathComponent("state.json").path)
        XCTAssertThrowsError(try store().trustRevision()) { XCTAssertEqual($0 as? PairingCommitError, .corruptState) }
        XCTAssertEqual(try String(contentsOf: stateDirectory.appendingPathComponent("state.json"), encoding: .utf8), "not json")
    }

    // MARK: Rules

    func testInvalidBiometricProofIsRejectedAndStateIsUnchanged() throws {
        let one = try candidate(tag: 1)
        var bad = one.proof; bad[0] ^= 1
        let store = store()
        XCTAssertThrowsError(try store.commit(transcript: one.transcript, biometricProof: bad,
                                              deadlineMilliseconds: 10_000, isCancelled: { false })) {
            XCTAssertEqual($0 as? PairingCommitError, .invalidProof)
        }
        XCTAssertEqual(try store.trustRevision(), revision)
        XCTAssertEqual(try store.list(), [])
    }

    func testReplacementIsRejectedInVersionOne() throws {
        let old = try PairingReplacement(phoneID: Data(repeating: 9, count: 16), epoch: Data(repeating: 8, count: 16))
        let replacing = try candidate(tag: 1, replacement: old)
        XCTAssertThrowsError(try commit(store(), replacing)) {
            XCTAssertEqual($0 as? PairingCommitError, .replacementUnsupported)
        }
    }

    func testStaleTrustRevisionIsRejected() throws {
        let stale = try candidate(tag: 1, expected: Data(repeating: 0x33, count: 16))
        let store = store()
        XCTAssertThrowsError(try commit(store, stale)) { XCTAssertEqual($0 as? PairingCommitError, .staleRevision) }
        XCTAssertEqual(try store.list(), [])
    }

    func testTranscriptStagedBeforeAnotherCommitIsStale() throws {
        let store = store()
        let first = try candidate(tag: 1)
        let second = try candidate(tag: 2)
        _ = try commit(store, first)
        XCTAssertThrowsError(try commit(store, second)) { XCTAssertEqual($0 as? PairingCommitError, .staleRevision) }
    }

    func testUsedSetupIDIsRejectedEvenWithTheCurrentRevision() throws {
        let store = store()
        let first = try candidate(tag: 1)
        let next = try commit(store, first)
        let again = try candidate(tag: 2, setupTag: 1, expected: next)
        XCTAssertThrowsError(try commit(store, again)) { XCTAssertEqual($0 as? PairingCommitError, .duplicateSetupID) }
        XCTAssertEqual(try store.trustRevision(), next)
    }

    func testRetryOfTheSameTranscriptIsNotAnotherEnrollment() throws {
        let store = store()
        let first = try candidate(tag: 1)
        _ = try commit(store, first)
        XCTAssertThrowsError(try commit(store, first)) { XCTAssertEqual($0 as? PairingCommitError, .staleRevision) }
        XCTAssertEqual(try store.list().count, 1)
    }

    func testEnrolledPhoneIDIsRejected() throws {
        let store = store()
        let first = try candidate(tag: 1)
        let next = try commit(store, first)
        let samePhone = try candidate(tag: 2, expected: next, sharedPhoneID: first.transcript.phone.scope.phoneID)
        XCTAssertThrowsError(try commit(store, samePhone)) { XCTAssertEqual($0 as? PairingCommitError, .alreadyEnrolled) }
        XCTAssertEqual(try store.list().count, 1)
    }

    func testEnrolledBiometricKeyIsRejectedForAnotherPhone() throws {
        let store = store()
        let key = P256.Signing.PrivateKey()
        let first = try candidate(tag: 1, sharedBiometric: key)
        let next = try commit(store, first)
        let sameKey = try candidate(tag: 2, expected: next, sharedBiometric: key)
        XCTAssertThrowsError(try commit(store, sameKey)) { XCTAssertEqual($0 as? PairingCommitError, .alreadyEnrolled) }
    }

    func testTwoDifferentPhonesCanEnrollInSequence() throws {
        let store = store()
        let first = try candidate(tag: 1)
        let afterFirst = try commit(store, first)
        let second = try candidate(tag: 2, expected: afterFirst)
        let afterSecond = try commit(store, second)
        XCTAssertNotEqual(afterFirst, afterSecond)
        XCTAssertEqual(try store.list().count, 2)
    }

    // MARK: Deadline, cancellation, lock

    func testCommitAtOrAfterTheDeadlineIsRejectedWithoutChange() throws {
        let clock = Clock(10_000)
        let store = store(clock: clock)
        XCTAssertThrowsError(try commit(store, candidate(tag: 1), deadline: 10_000)) {
            XCTAssertEqual($0 as? PairingCommitError, .expired)
        }
        clock.set(9_999)
        XCTAssertEqual(try store.list(), [])
        XCTAssertNoThrow(try commit(store, candidate(tag: 1), deadline: 10_000))
    }

    func testCancelledBeforeCommitIsRejectedWithoutChange() throws {
        let store = store()
        XCTAssertThrowsError(try commit(store, candidate(tag: 1), cancelled: { true })) {
            XCTAssertEqual($0 as? PairingCommitError, .cancelled)
        }
        XCTAssertEqual(try store.list(), [])
    }

    func testDeadlinePassingAfterTheDurableWriteReportsCommittedLate() throws {
        let clock = Clock(1_000)
        _ = try self.store().trustRevision()  // the hook must not fire while the initial state is written
        let store = store(clock: clock, crash: { step in if step == .finished { clock.set(10_000) } })
        let one = try candidate(tag: 1)
        var late: Data?
        XCTAssertThrowsError(try commit(store, one, deadline: 10_000)) { error in
            guard case let .committedLate(revision)? = error as? PairingCommitError else { return XCTFail("\(error)") }
            late = revision
        }
        let reopened = self.store(clock: Clock(1_000))
        XCTAssertEqual(try reopened.trustRevision(), late)
        XCTAssertEqual(try reopened.list().count, 1)
        XCTAssertThrowsError(try commit(reopened, one)) { XCTAssertEqual($0 as? PairingCommitError, .staleRevision) }
    }

    func testCancelAfterTheDurableWriteReportsCommittedLate() throws {
        let cancelled = ManagedAtomicFlag()
        _ = try self.store().trustRevision()
        let store = store(crash: { step in if step == .finished { cancelled.set() } })
        XCTAssertThrowsError(try commit(store, candidate(tag: 1), cancelled: { cancelled.isSet })) {
            guard case .committedLate? = $0 as? PairingCommitError else { return XCTFail("\($0)") }
        }
        XCTAssertEqual(try self.store().list().count, 1)
    }

    /// Holds the state lock inside a commit until `release` is signalled. The initial state already exists, so the
    /// hook blocks the one write of the holder's commit.
    private func holdLock(release: DispatchSemaphore) throws -> (held: XCTestExpectation, finished: XCTestExpectation) {
        _ = try store().trustRevision()
        let held = expectation(description: "lock held")
        let finished = expectation(description: "holder finished")
        let holderStore = store(crash: { step in
            if step == .syncTemporary { held.fulfill(); release.wait() }
        })
        let one = try candidate(tag: 1)
        Thread {
            _ = try? self.commit(holderStore, one)
            finished.fulfill()
        }.start()
        return (held, finished)
    }

    func testCommitWaitingForTheLockPastItsDeadlineIsRejected() throws {
        let release = DispatchSemaphore(value: 0)
        let (held, finished) = try holdLock(release: release)
        wait(for: [held], timeout: 5)
        // The waiter's clock moves past its deadline while the holder keeps the lock.
        let waiterClock = Clock(1_000)
        let waiter = store(clock: waiterClock)
        let late = try candidate(tag: 2)
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { waiterClock.set(5_000) }
        XCTAssertThrowsError(try commit(waiter, late, deadline: 2_000)) {
            XCTAssertEqual($0 as? PairingCommitError, .expired)
        }
        release.signal()
        wait(for: [finished], timeout: 5)
        XCTAssertEqual(try store().list().count, 1, "only the holder committed")
    }

    func testCancelWhileWaitingForTheLockIsRejected() throws {
        let release = DispatchSemaphore(value: 0)
        let (held, finished) = try holdLock(release: release)
        wait(for: [held], timeout: 5)
        let flag = ManagedAtomicFlag()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { flag.set() }
        XCTAssertThrowsError(try commit(store(), candidate(tag: 2), cancelled: { flag.isSet })) {
            XCTAssertEqual($0 as? PairingCommitError, .cancelled)
        }
        release.signal()
        wait(for: [finished], timeout: 5)
    }

    func testTwoConcurrentCommitsWithTheSameRevisionLetExactlyOneWin() throws {
        let transcripts = try (1...8).map { try candidate(tag: UInt8($0)) }
        let results = ResultBox()
        DispatchQueue.concurrentPerform(iterations: transcripts.count) { index in
            let outcome = Result { try self.commit(self.store(), transcripts[index]) }
            results.add(outcome)
        }
        XCTAssertEqual(results.successes, 1)
        XCTAssertEqual(results.failures.filter { ($0 as? PairingCommitError) == .staleRevision }.count, transcripts.count - 1)
        XCTAssertEqual(try store().list().count, 1)
    }

    func testEnrolledDecisionKeyIsRejectedForAnotherPhone() throws {
        let store = store()
        let key = P256.Signing.PrivateKey()
        let next = try commit(store, candidate(tag: 1, sharedDecision: key))
        XCTAssertThrowsError(try commit(store, candidate(tag: 2, expected: next, sharedDecision: key))) {
            XCTAssertEqual($0 as? PairingCommitError, .alreadyEnrolled)
        }
    }

    // MARK: Sync failures

    /// Counts `fsync` calls and fails the listed call numbers (1-based) with EIO.
    private final class SyncProbe: @unchecked Sendable {
        private let lock = NSLock()
        private var calls = 0
        private let failing: Set<Int>
        init(failing: Set<Int> = []) { self.failing = failing }
        var count: Int { lock.lock(); defer { lock.unlock() }; return calls }
        func sync(_ fd: Int32) -> Int32 {
            lock.lock(); calls += 1; let number = calls; lock.unlock()
            if failing.contains(number) { errno = EIO; return -1 }
            return fsync(fd)
        }
    }

    private func store(probe: SyncProbe) -> PairingCommitStore {
        PairingCommitStore(directory: stateDirectory, initialTrustRevision: revision, clock: { 1_000 },
                           syncFile: { probe.sync($0) })
    }

    func testEveryOpenSyncsTheParentSoARetryAfterAFailedSyncCannotSkipIt() throws {
        let failing = SyncProbe(failing: [1])
        XCTAssertThrowsError(try store(probe: failing).trustRevision()) {
            guard case .storage(operation: "fsync parent", errno: EIO)? = $0 as? PairingCommitError else { return XCTFail("\($0)") }
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: stateDirectory.path), "the directory is present after the failure")
        let retry = SyncProbe()
        let one = try candidate(tag: 1)
        _ = try commit(store(probe: retry), one)
        XCTAssertGreaterThanOrEqual(retry.count, 3, "parent, temporary file and directory are all synced for the retry")
        let open = SyncProbe()
        XCTAssertNoThrow(try store(probe: open).list())
        XCTAssertEqual(open.count, 1, "a read-only open still syncs the parent once")
    }

    func testAFailedParentSyncStopsACommitBeforeItWrites() throws {
        _ = try store().trustRevision()
        let probe = SyncProbe(failing: [1])
        XCTAssertThrowsError(try commit(store(probe: probe), candidate(tag: 1)))
        XCTAssertEqual(try store().list(), [])
        XCTAssertEqual(try store().trustRevision(), revision)
    }

    func testConcurrentOpenersEachSyncTheParent() throws {
        let probe = SyncProbe()
        DispatchQueue.concurrentPerform(iterations: 6) { _ in _ = try? self.store(probe: probe).trustRevision() }
        XCTAssertGreaterThanOrEqual(probe.count, 6)
    }

    func testDirectorySyncFailureAfterTheRenameReportsCommittedUnconfirmed() throws {
        _ = try store().trustRevision()
        let one = try candidate(tag: 1)
        // Calls in a commit on an existing state: 1 parent, 2 temporary file, 3 directory.
        let probe = SyncProbe(failing: [3])
        XCTAssertThrowsError(try commit(store(probe: probe), one)) { error in
            guard case let .committedUnconfirmed(next, code)? = error as? PairingCommitError else { return XCTFail("\(error)") }
            XCTAssertEqual(code, EIO)
            XCTAssertEqual(next.count, 16)
            XCTAssertNotEqual(next, self.revision)
            XCTAssertEqual(try? self.store().trustRevision(), next, "the reported revision is the stored one")
        }
        XCTAssertEqual(try store().list().count, 1)
        XCTAssertThrowsError(try commit(store(), one)) { XCTAssertEqual($0 as? PairingCommitError, .staleRevision) }
    }

    func testDirectorySyncFailureWhileCreatingTheInitialStateIsAStorageError() throws {
        let probe = SyncProbe(failing: [3])
        XCTAssertThrowsError(try store(probe: probe).trustRevision()) {
            guard case .storage(operation: "fsync directory", errno: EIO)? = $0 as? PairingCommitError else { return XCTFail("\($0)") }
        }
    }

    // MARK: Bounds, umask, links

    func testEnrollmentLimitIsEnforcedBeforeTheWrite() throws {
        let limited = PairingCommitStore(directory: stateDirectory, initialTrustRevision: revision,
                                         maximumEnrollments: 1, clock: { 1_000 })
        let next = try commit(limited, candidate(tag: 1))
        XCTAssertThrowsError(try commit(limited, candidate(tag: 2, expected: next))) {
            XCTAssertEqual($0 as? PairingCommitError, .stateFull)
        }
        XCTAssertEqual(try limited.trustRevision(), next)
        XCTAssertEqual(try limited.list().count, 1)
    }

    func testConsumedSetupIDLimitIsEnforcedBeforeTheWrite() throws {
        let limited = PairingCommitStore(directory: stateDirectory, initialTrustRevision: revision,
                                         maximumConsumedSetupIDs: 1, clock: { 1_000 })
        let next = try commit(limited, candidate(tag: 1))
        XCTAssertThrowsError(try commit(limited, candidate(tag: 2, expected: next))) {
            XCTAssertEqual($0 as? PairingCommitError, .stateFull)
        }
    }

    func testStateThatWouldExceedTheByteLimitIsRefusedAndStaysReadable() throws {
        let limited = PairingCommitStore(directory: stateDirectory, initialTrustRevision: revision,
                                         maximumStateBytes: 600, clock: { 1_000 })
        XCTAssertEqual(try limited.trustRevision(), revision)
        XCTAssertThrowsError(try commit(limited, candidate(tag: 1))) { XCTAssertEqual($0 as? PairingCommitError, .stateFull) }
        XCTAssertEqual(try limited.trustRevision(), revision, "the old state still loads")
        XCTAssertEqual(try limited.list(), [])
    }

    func testPrivateModesHoldUnderAnOpenUmask() throws {
        let previous = umask(0)
        defer { umask(previous) }
        _ = try commit(store(), candidate(tag: 1))
        for (name, expected) in [(nil, 0o700), ("state.json", 0o600), ("state.lock", 0o600)] as [(String?, Int)] {
            let url = name.map { stateDirectory.appendingPathComponent($0) } ?? stateDirectory
            let mode = try (FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as! NSNumber).intValue
            XCTAssertEqual(mode, expected, name ?? "directory")
        }
        XCTAssertEqual(try store().list().count, 1, "the next open accepts what the commit wrote")
    }

    func testSymlinkedStateAndLockFilesAreRefused() throws {
        _ = try store().trustRevision()
        let target = root.appendingPathComponent("elsewhere")
        try Data("x".utf8).write(to: target)
        let state = stateDirectory.appendingPathComponent("state.json")
        try FileManager.default.removeItem(at: state)
        try FileManager.default.createSymbolicLink(at: state, withDestinationURL: target)
        XCTAssertThrowsError(try store().trustRevision()) { XCTAssertEqual($0 as? PairingCommitError, .unsafeDirectory) }
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "x", "the link target is untouched")
        try FileManager.default.removeItem(at: state)

        let lock = stateDirectory.appendingPathComponent("state.lock")
        try FileManager.default.removeItem(at: lock)
        try FileManager.default.createSymbolicLink(at: lock, withDestinationURL: target)
        XCTAssertThrowsError(try store().trustRevision()) { XCTAssertEqual($0 as? PairingCommitError, .unsafeDirectory) }
    }

    func testPlantedFifoAsTheLockFileIsRefusedWithoutBlocking() throws {
        _ = try store().trustRevision()
        let lock = stateDirectory.appendingPathComponent("state.lock")
        try FileManager.default.removeItem(at: lock)
        XCTAssertEqual(mkfifo(lock.path, 0o600), 0)
        XCTAssertThrowsError(try store().trustRevision()) { XCTAssertEqual($0 as? PairingCommitError, .unsafeDirectory) }
    }

    func testHardLinkedTemporaryFileIsNotTruncated() throws {
        _ = try store().trustRevision()
        let outside = root.appendingPathComponent("outside")
        try Data("keep".utf8).write(to: outside)
        let temporary = stateDirectory.appendingPathComponent("state.json.tmp")
        XCTAssertEqual(link(outside.path, temporary.path), 0)
        _ = try commit(store(), candidate(tag: 1))
        XCTAssertEqual(try String(contentsOf: outside, encoding: .utf8), "keep")
    }

    func testUndecodableStoredTranscriptIsCorruptState() throws {
        let one = try candidate(tag: 1)
        _ = try commit(store(), one)
        let url = stateDirectory.appendingPathComponent("state.json")
        var state = try JSONDecoder().decode(PairingCommitStore.StoredState.self, from: Data(contentsOf: url))
        state.enrollments[0].transcript = Data([1, 2, 3])
        try JSONEncoder().encode(state).write(to: url)
        XCTAssertThrowsError(try store().list()) { XCTAssertEqual($0 as? PairingCommitError, .corruptState) }
        XCTAssertThrowsError(try commit(store(), candidate(tag: 2, expected: state.trustRevision))) {
            XCTAssertEqual($0 as? PairingCommitError, .corruptState)
        }
    }

    func testProofSignedByAnotherKeyIsRejected() throws {
        let one = try candidate(tag: 1)
        let other = P256.Signing.PrivateKey()
        let forged = try other.signature(for: one.transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation
        XCTAssertThrowsError(try store().commit(transcript: one.transcript, biometricProof: forged,
                                                deadlineMilliseconds: 10_000, isCancelled: { false })) {
            XCTAssertEqual($0 as? PairingCommitError, .invalidProof)
        }
    }

    // MARK: Crash injection

    func testCrashAtEachPersistenceStepLeavesTheOldOrTheCompleteNewState() throws {
        let beforeRename: Set<PairingPersistenceStep> = [.createTemporary, .syncTemporary, .rename]
        for step in PairingPersistenceStep.allCases {
            try? FileManager.default.removeItem(at: stateDirectory)
            XCTAssertEqual(try store().trustRevision(), revision)
            let one = try candidate(tag: 1)
            let crashing = store(crash: { if $0 == step { throw InjectedCrash(step: step) } })
            XCTAssertThrowsError(try commit(crashing, one), "\(step)") { XCTAssertEqual($0 as? InjectedCrash, InjectedCrash(step: step)) }

            let reopened = store()
            if beforeRename.contains(step) {
                XCTAssertEqual(try reopened.trustRevision(), revision, "\(step) keeps the old revision")
                XCTAssertEqual(try reopened.list(), [], "\(step) keeps no enrollment")
                XCTAssertNoThrow(try commit(reopened, one), "\(step): the setup ID is not consumed, so a new attempt works")
            } else {
                XCTAssertNotEqual(try reopened.trustRevision(), revision, "\(step) keeps the full new state")
                XCTAssertEqual(try reopened.list().count, 1, "\(step) keeps the enrollment")
                XCTAssertThrowsError(try commit(reopened, one), "\(step): never commit again") {
                    XCTAssertEqual($0 as? PairingCommitError, .staleRevision)
                }
                XCTAssertEqual(try reopened.list().count, 1)
            }
        }
    }

    func testStateFileIsNeverPartial() throws {
        // After a crash between the temporary write and the rename, the visible file still decodes.
        _ = try store().trustRevision()
        let crashing = store(crash: { if $0 == .rename { throw InjectedCrash(step: .rename) } })
        XCTAssertThrowsError(try commit(crashing, candidate(tag: 1)))
        let data = try Data(contentsOf: stateDirectory.appendingPathComponent("state.json"))
        XCTAssertNoThrow(try JSONDecoder().decode(PairingCommitStore.StoredState.self, from: data))
    }
}

private final class ManagedAtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    func set() { lock.lock(); flag = true; lock.unlock() }
    var isSet: Bool { lock.lock(); defer { lock.unlock() }; return flag }
}

private final class ResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var outcomes: [Result<Data, Error>] = []
    func add(_ outcome: Result<Data, Error>) { lock.lock(); outcomes.append(outcome); lock.unlock() }
    var successes: Int { lock.lock(); defer { lock.unlock() }; return outcomes.filter { if case .success = $0 { true } else { false } }.count }
    var failures: [Error] {
        lock.lock(); defer { lock.unlock() }
        return outcomes.compactMap { if case let .failure(error) = $0 { error } else { nil } }
    }
}
