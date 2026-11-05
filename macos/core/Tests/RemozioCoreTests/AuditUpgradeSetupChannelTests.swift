import Darwin
import Foundation
import RemozioProtocol
import Security
import Synchronization
import XCTest
@testable import RemozioCore

/// Typed callback fixtures. Native peer signing and native authorization remain separate platform gates.
final class AuditUpgradeSetupChannelTests: XCTestCase, @unchecked Sendable {
    private final class Driver: AuditUpgradeSetupDriver, Sendable {
        struct State {
            var version: UInt64 = 11
            var response: SetupClientReply = .progress(Data())
            var history: [String] = []
            var held: (@Sendable (SetupClientReply) -> Void)?
            var onClose: (@Sendable () -> Void)?
            var hold = false, holdHello = false, peerValid = true, accountValid = true, closed = false
            var closes = 0, forms = 0
        }
        let state = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) { state.withLock { $0.onClose = closed } }
        func verifyPeer() throws {
            try state.withLock { if !$0.peerValid || $0.closed { throw AdministrativeSetupChannelError.closed } }
        }
        func invoke(_ call: AuditUpgradeSetupCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            let value: SetupClientReply? = state.withLock {
                switch call {
                case .hello:
                    $0.history.append("hello")
                    if $0.holdHello { $0.held = reply; return nil }
                    return .version($0.version)
                case .progress: $0.history.append("progress")
                case .perform: $0.history.append("perform")
                }
                if $0.hold { $0.held = reply; return nil }; return $0.response
            }
            if let value { reply(value) }
        }
        func close() {
            let notify: (@Sendable () -> Void)? = state.withLock {
                $0.closes += 1
                guard !$0.closed else { return nil }; $0.closed = true; return $0.onClose
            }
            notify?()
        }
        func deliver(_ value: SetupClientReply) { state.withLock { $0.held }?(value) }
    }
    private var limits: CBORLimits { try! .init(maxBytes: 2048, maxDepth: 2, maxItems: 64) }
    private var form: Data { Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size) }
    private func progress(seed: UInt8 = 1, uid: uid_t = getuid()) throws -> SetupAuditUpgradeProgress {
        func id(_ offset: UInt8, _ count: Int = 16) -> CBORValue { .bytes(Data(repeating: seed + offset, count: count)) }
        let runtime = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: id(0), 2: id(1), 3: id(2),
            4: id(3), 5: .unsigned(UInt64(uid)), 6: id(4), 7: id(5), 8: .boolean(true)]), limits: limits)
        return try .decode(DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(runtime), 2: id(6),
            3: id(7, 32), 4: id(8, 32), 5: .unsigned(1), 6: .array([])]), limits: limits))
    }
    private func until(_ predicate: () -> Bool) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(3))
        while !predicate() { guard ContinuousClock.now < end else { throw AdministrativeSetupChannelError.timedOut }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testHelloMustFinishAtTheExactVersionBeforeAnyAuthorizationIsRead() async throws {
        let value = try progress()
        for version: UInt64 in [0, 1, 9, 10, 12] {
            let driver = Driver(); driver.state.withLock { $0.version = version }
            let channel = AuditUpgradeSetupChannel(driver: driver, expected: value)
            do { try await channel.start(); XCTFail("Version") } catch {
                // Zero is the endpoint's refusal, not a version. It reports unknown state instead of an old daemon.
                if version == 0 { XCTAssertEqual(error as? AuditUpgradeSetupChannelError, .progressUnavailable) }
                else { XCTAssertEqual(error as? AdministrativeSetupChannelError, .unsupportedVersion) }
            }
            do { _ = try await channel.perform(value, readAuthorization: { driver.state.withLock { $0.forms += 1 }; return self.form }); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.forms }, 0)
            XCTAssertEqual(driver.state.withLock { $0.history }, ["hello"])
        }
        let driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver, expected: value)
        do { _ = try await channel.perform(value, readAuthorization: { XCTFail("No hello"); return self.form }); XCTFail() } catch {}
        XCTAssertTrue(driver.state.withLock { $0.history.isEmpty })
    }
    func testProgressPinsTheScopeAndMutationClosesItsConnectionAfterOneResult() async throws {
        let value = try progress(), driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver)
        try await channel.start(); let empty = try await channel.progress(); XCTAssertNil(empty)
        driver.state.withLock { $0.response = .progress(try! value.bytes) }
        let current = try await channel.progress(); XCTAssertEqual(current, value)
        let result = try value.observing(.registrationObserved(.init(selectedRoles: [.authority, .transport], registrationConfirmed: [.authority, .transport])))
        driver.state.withLock { $0.response = .progress(try! result.bytes) }
        let actual = try await channel.perform(value, readAuthorization: { driver.state.withLock { $0.forms += 1 }; return self.form })
        XCTAssertEqual(actual, result); XCTAssertEqual(driver.state.withLock { $0.forms }, 1)
        do { _ = try await channel.progress(); XCTFail("One-shot connection") } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
        XCTAssertEqual(driver.state.withLock { $0.history }, ["hello", "progress", "progress", "perform"])
    }
    func testMutationNeedsReviewedScopeAndAValidFormBeforeSending() async throws {
        let value = try progress()
        for missingScope in [false, true] {
            let driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver, expected: missingScope ? nil : value)
            try await channel.start()
            do { _ = try await channel.perform(value, readAuthorization: { if missingScope { XCTFail("Missing scope") }; return Data() }); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.history }, ["hello"])
        }
    }
    func testPeerRevalidationSurroundsAuthorizationExport() async throws {
        let value = try progress()
        for changeDuringReader in [false, true] {
            let driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver, expected: value)
            try await channel.start()
            if !changeDuringReader { driver.state.withLock { $0.peerValid = false } }
            do {
                _ = try await channel.perform(value, readAuthorization: {
                    driver.state.withLock { $0.forms += 1; $0.peerValid = false }; return self.form
                }); XCTFail()
            } catch {}
            XCTAssertEqual(driver.state.withLock { $0.forms }, changeDuringReader ? 1 : 0)
            XCTAssertEqual(driver.state.withLock { $0.history }, ["hello"])
        }
    }
    func testReadRejectsCrossedScopeOrMutatingOnlyObservations() async throws {
        let value = try progress(), other = try progress(seed: 31)
        for response in [try other.bytes, try progress(uid: getuid() + 1).bytes,
            try value.observing(.registrationObserved(.init(selectedRoles: [], registrationConfirmed: []))).bytes,
            Data(), Data([0]), Data(repeating: 0, count: SetupAuditUpgradeProgress.maximumBytes + 1)] {
            let driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver, expected: value)
            try await channel.start(); driver.state.withLock { $0.response = .progress(response) }
            do { _ = try await channel.progress(); XCTFail() } catch {}
            XCTAssertTrue(driver.state.withLock { $0.closed })
        }
    }
    func testMutationRejectsUnknownMalformedCrossedAndReadOnlyRepliesWithoutReplay() async throws {
        let value = try progress(), other = try progress(seed: 31)
        let crossed = try other.observing(.alreadyCurrent)
        let replies: [Data?] = [nil, Data(), Data([0]), Data(repeating: 0, count: SetupAuditUpgradeProgress.maximumBytes + 1),
            try crossed.bytes, try value.bytes, try value.observing(.metadataCommitted).bytes]
        for bytes in replies {
            let driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver, expected: value)
            try await channel.start(); driver.state.withLock { $0.response = .progress(bytes) }
            do { _ = try await channel.perform(value, authorization: form); XCTFail() } catch {}
            do { _ = try await channel.perform(value, readAuthorization: { XCTFail("No replay"); return self.form }); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.history }, ["hello", "perform"])
        }
    }
    func testBusyCallDoesNotReadMoreRightsOrCancelTheFirstMutation() async throws {
        let value = try progress(), driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver, expected: value)
        try await channel.start(); driver.state.withLock { $0.hold = true }
        let first = Task { try await channel.perform(value, authorization: self.form) }
        try await until { driver.state.withLock { $0.held != nil } }
        do { _ = try await channel.perform(value, readAuthorization: { XCTFail("Busy reader"); return self.form }); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .busy) }
        do { _ = try await channel.progress(); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .busy) }
        let result = try value.observing(.waitingForActivity)
        driver.deliver(.progress(try result.bytes)); let actual = try await first.value; XCTAssertEqual(actual, result)
        XCTAssertEqual(driver.state.withLock { $0.history }, ["hello", "perform"])
    }
    func testTimeoutClosesTheMutationAndFreshRecoveryReadNeverReplaysIt() async throws {
        let value = try progress(), driver = Driver()
        let channel = AuditUpgradeSetupChannel(driver: driver, expected: value, operationTimeoutMilliseconds: 15)
        try await channel.start(); driver.state.withLock { $0.hold = true }
        do { _ = try await channel.perform(value, authorization: form); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .timedOut) }
        driver.deliver(.progress(try value.observing(.alreadyCurrent).bytes))
        let reader = Driver(), recovery = AuditUpgradeSetupChannel(driver: reader, expected: value)
        reader.state.withLock { $0.response = .progress(try! value.observing(.metadataCommitted).bytes) }
        try await recovery.start(); let observed = try await recovery.progress()
        XCTAssertEqual(observed?.stage, .metadataCommitted); XCTAssertTrue(observed?.registrationObserved.isEmpty == true)
        XCTAssertEqual(driver.state.withLock { $0.history }, ["hello", "perform"])
        XCTAssertEqual(reader.state.withLock { $0.history }, ["hello", "progress"])
        await recovery.close()
    }
    func testCancellationAndLateCallbacksCannotReviveTheChannelOrReplayWork() async throws {
        let value = try progress(), driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver, expected: value)
        try await channel.start(); driver.state.withLock { $0.hold = true }
        let task = Task { try await channel.perform(value, authorization: self.form) }
        try await until { driver.state.withLock { $0.held != nil } }; task.cancel()
        do { _ = try await task.value; XCTFail() } catch {}
        driver.deliver(.progress(try value.observing(.alreadyCurrent).bytes)); driver.deliver(.failed)
        do { _ = try await channel.progress(); XCTFail() } catch {}
        XCTAssertEqual(driver.state.withLock { $0.history }, ["hello", "perform"])
    }
    func testAbortDuringTheFormReaderDoesNotWaitForTheActorOrSendCredentials() async throws {
        let value = try progress(), driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver, expected: value)
        try await channel.start()
        do { _ = try await channel.perform(value, readAuthorization: { channel.abort(); return self.form }); XCTFail() } catch {}
        XCTAssertEqual(driver.state.withLock { $0.history }, ["hello"])
        XCTAssertTrue(driver.state.withLock { $0.closed })
    }
    func testAccountOrPeerChangesWhileAwaitingReplyDiscardTheObservation() async throws {
        for changeAccount in [false, true] {
            let driver = Driver(), value = try progress()
            let channel = AuditUpgradeSetupChannel(driver: driver, expected: value, verifyAccount: {
                if !driver.state.withLock({ $0.accountValid }) { throw AdministrativeSetupChannelError.wrongAccount }
            })
            try await channel.start(); driver.state.withLock { $0.hold = true }
            let task = Task { try await channel.progress() }
            try await until { driver.state.withLock { $0.held != nil } }
            driver.state.withLock { if changeAccount { $0.accountValid = false } else { $0.peerValid = false } }
            driver.deliver(.progress(try value.bytes))
            do { _ = try await task.value; XCTFail() } catch {}
            XCTAssertTrue(driver.state.withLock { $0.closed })
        }
    }
    func testEveryNamespaceFieldIsBoundOnMutationReplies() async throws {
        let base = try progress(), terminal = try base.observing(.alreadyCurrent)
        guard case .map(let original) = try DeterministicCBOR.decode(terminal.bytes, limits: limits),
              case .bytes(let runtime) = original[1], case .map(let runtimeFields) = try DeterministicCBOR.decode(runtime, limits: limits) else { return XCTFail() }
        var variants: [Data] = []
        for field: UInt64 in [2, 3, 4] {
            var edited = original; edited[field] = .bytes(Data(repeating: 97, count: field == 2 ? 16 : 32))
            variants.append(try DeterministicCBOR.encode(.map(edited), limits: limits))
        }
        for field: UInt64 in [1, 2, 3, 4, 5, 6, 7] {
            var edited = original, nested = runtimeFields
            nested[field] = field == 5 ? .unsigned(UInt64(getuid() + 1)) : .bytes(Data(repeating: 98, count: 16))
            edited[1] = .bytes(try DeterministicCBOR.encode(.map(nested), limits: limits))
            variants.append(try DeterministicCBOR.encode(.map(edited), limits: limits))
        }
        for bytes in variants {
            let driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver, expected: base)
            try await channel.start(); driver.state.withLock { $0.response = .progress(bytes) }
            do { _ = try await channel.perform(base, authorization: form); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.history }, ["hello", "perform"])
        }
    }
    /// A daemon held by maintenance on another connection refuses or drops reads. The channel reports unknown state, never data.
    func testRefusedDroppedOrExpiredReadsReportUnavailableProgressWithoutReplay() async throws {
        enum Failure: CaseIterable { case helloRefused, helloFailed, helloDropped, readRefused, readFailed, readDropped, readExpired }
        let value = try progress()
        for failure in Failure.allCases {
            let driver = Driver()
            let channel = AuditUpgradeSetupChannel(driver: driver, expected: value, timeoutMilliseconds: failure == .readExpired ? 15 : 5000)
            do {
                switch failure {
                case .helloRefused:
                    driver.state.withLock { $0.version = 0 }; try await channel.start()
                case .helloFailed, .helloDropped:
                    driver.state.withLock { $0.holdHello = true }
                    let task = Task { try await channel.start() }
                    try await until { driver.state.withLock { $0.held != nil } }
                    if failure == .helloFailed { driver.deliver(.failed) } else { driver.close() }
                    try await task.value
                case .readRefused, .readFailed:
                    try await channel.start()
                    driver.state.withLock { $0.response = failure == .readRefused ? .progress(nil) : .failed }
                    _ = try await channel.progress()
                case .readDropped, .readExpired:
                    try await channel.start(); driver.state.withLock { $0.hold = true }
                    let task = Task { try await channel.progress() }
                    try await until { driver.state.withLock { $0.held != nil } }
                    if failure == .readDropped { driver.close() }
                    _ = try await task.value
                }
                XCTFail("\(failure)")
            } catch { XCTAssertEqual(error as? AuditUpgradeSetupChannelError, .progressUnavailable, "\(failure)") }
            XCTAssertTrue(driver.state.withLock { $0.closed })
            do { _ = try await channel.progress(); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
            do { _ = try await channel.perform(value, readAuthorization: { XCTFail("No mutation"); return self.form }); XCTFail() } catch {}
            XCTAssertFalse(driver.state.withLock { $0.history.contains("perform") })
            // A fresh connection reads retained progress. Nothing is replayed.
            let reader = Driver(), recovery = AuditUpgradeSetupChannel(driver: reader, expected: value)
            reader.state.withLock { $0.response = .progress(try! value.bytes) }
            try await recovery.start(); let observed = try await recovery.progress(); XCTAssertEqual(observed, value)
            XCTAssertEqual(reader.state.withLock { $0.history }, ["hello", "progress"])
            await recovery.close()
        }
    }
    /// Local closes, cancellation and peer rejection keep their own errors. Only remote refusal or loss means unknown state.
    func testLocalCloseCancellationAndPeerRejectionAreNotReportedAsUnavailableProgress() async throws {
        enum Ending: CaseIterable { case abort, cancel, peerRejected }
        let value = try progress()
        for ending in Ending.allCases {
            let driver = Driver(), channel = AuditUpgradeSetupChannel(driver: driver, expected: value)
            try await channel.start(); driver.state.withLock { $0.hold = true }
            let task = Task { try await channel.progress() }
            try await until { driver.state.withLock { $0.held != nil } }
            switch ending {
            case .abort: channel.abort()
            case .cancel: task.cancel()
            case .peerRejected: driver.state.withLock { $0.peerValid = false }; driver.deliver(.progress(try value.bytes))
            }
            do { _ = try await task.value; XCTFail("\(ending)") } catch {
                XCTAssertNotEqual(error as? AuditUpgradeSetupChannelError, .progressUnavailable, "\(ending)")
                if ending != .cancel { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed, "\(ending)") }
            }
            XCTAssertTrue(driver.state.withLock { $0.closed })
            XCTAssertEqual(driver.state.withLock { $0.history }, ["hello", "progress"])
        }
    }
}
