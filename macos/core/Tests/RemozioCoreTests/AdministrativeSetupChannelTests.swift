import Darwin
import Foundation
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

final class AdministrativeSetupChannelTests: XCTestCase, @unchecked Sendable {
    private let account = Data(repeating: 1, count: 16)
    private let setup = Data(repeating: 2, count: 16)
    private let revision = Data(repeating: 3, count: 16)
    private let form = Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)
    private final class Driver: SetupClientDriver, @unchecked Sendable {
        private let lock = NSRecursiveLock()
        private var history: [String] = []
        private var closedCallback: (@Sendable () -> Void)?
        private var retainedReply: (@Sendable (SetupClientReply) -> Void)?
        private var versions: UInt64 = 1
        private var response: Data? = Data()
        private var paused = false
        private var closes = 0
        private var called: (@Sendable () -> Void)?
        var calls: [String] { lock.withLock { history } }
        var closeCount: Int { lock.withLock { closes } }
        func configure(version: UInt64 = 1, response: Data? = Data(), paused: Bool = false,
                       called: (@Sendable () -> Void)? = nil) {
            lock.withLock { versions = version; self.response = response; self.paused = paused; self.called = called }
        }
        func start(closed: @escaping @Sendable () -> Void) { lock.withLock { closedCallback = closed } }
        func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            let result: SetupClientReply? = lock.withLock {
                switch call {
                case .enrollmentHello, .enrollmentProgress, .beginEnrollment, .resumeEnrollment, .serviceAccountsHello, .serviceAccountsProgress, .prepareServiceAccounts, .runtimeHello, .runtimeProgress, .prepareRuntime, .activationHello, .activationProgress, .activateRuntime: history.append("unexpected enrollment call")
                case .hello: history.append("hello")
                case .progress: history.append("progress")
                case .resume: history.append("resume")
                }
                if paused { retainedReply = reply; called?(); return nil }
                if case .hello = call { return .version(versions) }
                return .progress(response)
            }
            if let result { reply(result) }
        }
        func disconnect() { let callback = lock.withLock { closedCallback }; callback?() }
        func deliver(_ reply: SetupClientReply) { let callback = lock.withLock { retainedReply }; callback?(reply) }
        func close() { lock.withLock { closes += 1 } }
    }
    private func progressBytes(account: Data? = nil, setup: Data? = nil, revision: Data? = nil,
                               captured: Bool = false, complete: Bool = false) throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(account ?? self.account),
            2: .bytes(setup ?? self.setup), 3: .bytes(revision ?? self.revision),
            4: .unsigned(captured ? 1 : 0), 5: .unsigned(complete ? 1 : 0)]), limits: .init(maxBytes: 256, maxDepth: 2, maxItems: 16))
    }
    private func channel(_ driver: Driver, timeout: UInt64 = 5000) -> AdministrativeSetupChannel {
        .init(driver: driver, accountID: account, timeoutMilliseconds: timeout)
    }
    func testHelloPrecedesScopeAndEmptyProgressIsNotCompletion() async throws {
        let driver = Driver(), channel = channel(driver)
        try await channel.start()
        XCTAssertEqual(driver.calls, ["hello"])
        let value = try await channel.progress()
        XCTAssertNil(value); XCTAssertEqual(driver.calls, ["hello", "progress"])
        await channel.close()
    }
    func testBeforeHelloAndUnsupportedVersionsNeverSendScopeOrCredentials() async throws {
        let expected = try SetupAccountProgress.decode(progressBytes())
        for version: UInt64 in [0, 2, UInt64.max] {
            let driver = Driver(), channel = channel(driver)
            do { _ = try await channel.resume(expected, authorization: form); XCTFail() }
            catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
            XCTAssertTrue(driver.calls.isEmpty)
            driver.configure(version: version)
            do { try await channel.start(); XCTFail() }
            catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .unsupportedVersion) }
            XCTAssertEqual(driver.calls, ["hello"]); XCTAssertEqual(driver.closeCount, 1)
        }
    }
    func testScopedCompletionIsAcceptedAndIsNotRuntimeHealth() async throws {
        let driver = Driver(), channel = channel(driver)
        try await channel.start()
        driver.configure(response: try progressBytes())
        let observed = try await channel.progress()
        let initial = try XCTUnwrap(observed)
        driver.configure(response: try progressBytes(revision: Data(repeating: 4, count: 16), captured: true, complete: true))
        let result = try await channel.resume(initial, authorization: form)
        XCTAssertEqual(result.accountID, account); XCTAssertEqual(result.setupID, setup)
        XCTAssertTrue(result.complete); XCTAssertNotEqual(result.revision, initial.revision)
        XCTAssertEqual(driver.calls, ["hello", "progress", "resume"])
        await channel.close()
    }
    func testMalformedWrongAccountAndMissingRepliesRetireTheConnection() async throws {
        let responses: [Data?] = [nil, Data(repeating: 0, count: 257), Data([0xff]),
            try progressBytes(account: Data(repeating: 9, count: 16)), try progressBytes(complete: true)]
        for response in responses {
            let driver = Driver(), channel = channel(driver)
            try await channel.start(); driver.configure(response: response)
            do { _ = try await channel.progress(); XCTFail() }
            catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .invalidMessage) }
            do { _ = try await channel.progress(); XCTFail() }
            catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
            XCTAssertEqual(driver.calls, ["hello", "progress"]); XCTAssertEqual(driver.closeCount, 1)
        }
    }
    func testResumeCannotConfirmWrongSetupPartialOrUnchangedIncompleteProgress() async throws {
        let expected = try SetupAccountProgress.decode(progressBytes())
        let responses = [Data(), try progressBytes(), try progressBytes(captured: true),
            try progressBytes(captured: true, complete: true),
            try progressBytes(setup: Data(repeating: 9, count: 16), revision: Data(repeating: 4, count: 16), captured: true, complete: true)]
        for response in responses {
            let driver = Driver(), channel = channel(driver)
            try await channel.start(); driver.configure(response: response)
            do { _ = try await channel.resume(expected, authorization: form); XCTFail() }
            catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .invalidMessage) }
            XCTAssertEqual(driver.calls, ["hello", "resume"]); XCTAssertEqual(driver.closeCount, 1)
        }
    }
    func testCompletedIntentRetainsExactHistoricalProgress() async throws {
        let bytes = try progressBytes(captured: true, complete: true)
        let expected = try SetupAccountProgress.decode(bytes)
        for changed in [false, true] {
            let driver = Driver(), channel = channel(driver)
            try await channel.start()
            driver.configure(response: changed ? try progressBytes(revision: Data(repeating: 4, count: 16), captured: true, complete: true) : bytes)
            do {
                let value = try await channel.resume(expected, authorization: form)
                XCTAssertFalse(changed); XCTAssertEqual(value, expected)
            } catch { XCTAssertTrue(changed); XCTAssertEqual(error as? AdministrativeSetupChannelError, .invalidMessage) }
            XCTAssertEqual(driver.calls, ["hello", "resume"])
            await channel.close()
        }
    }
    func testInvalidLocalScopeAndFormNeverLeaveTheClient() async throws {
        let driver = Driver(), channel = channel(driver)
        try await channel.start()
        let wrong = try SetupAccountProgress.decode(progressBytes(account: Data(repeating: 9, count: 16)))
        let valid = try SetupAccountProgress.decode(progressBytes())
        for (expected, authorization) in [(wrong, form), (valid, Data()), (valid, form + Data([0]))] {
            do { _ = try await channel.resume(expected, authorization: authorization); XCTFail() }
            catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .invalidMessage) }
        }
        XCTAssertEqual(driver.calls, ["hello"]); XCTAssertEqual(driver.closeCount, 0)
        await channel.close()
    }
    func testLostMutationReplyTimesOutWithoutReplayingAndLateRepliesCannotReopen() async throws {
        let driver = Driver(), channel = channel(driver, timeout: 100)
        let expected = try SetupAccountProgress.decode(progressBytes())
        try await channel.start(); driver.configure(paused: true)
        do { _ = try await channel.resume(expected, authorization: form); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .timedOut) }
        driver.deliver(.progress(try progressBytes(revision: Data(repeating: 4, count: 16), captured: true, complete: true)))
        do { _ = try await channel.progress(); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
        XCTAssertEqual(driver.calls, ["hello", "resume"]); XCTAssertEqual(driver.closeCount, 1)
    }
    func testBusyCancellationAndDuplicateRepliesReleaseOnlyThePendingCall() async throws {
        let driver = Driver(), channel = channel(driver)
        let expected = try SetupAccountProgress.decode(progressBytes())
        try await channel.start()
        let sent = expectation(description: "Progress sent")
        driver.configure(paused: true, called: { sent.fulfill() })
        let task = Task { try await channel.progress() }
        await fulfillment(of: [sent], timeout: 2)
        do { _ = try await channel.resume(expected, authorization: form); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .busy) }
        task.cancel()
        do { _ = try await task.value; XCTFail() } catch { }
        driver.deliver(.progress(Data())); driver.deliver(.progress(Data()))
        do { _ = try await channel.progress(); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
        XCTAssertEqual(driver.calls, ["hello", "progress"])
    }
    func testInterruptionAndSynchronousAbortBlockSensitiveCalls() async throws {
        let expected = try SetupAccountProgress.decode(progressBytes())
        for interrupt in [false, true] {
            let driver = Driver(), channel = channel(driver)
            try await channel.start()
            if interrupt { driver.disconnect() } else { channel.abort() }
            do { _ = try await channel.resume(expected, authorization: form); XCTFail() }
            catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
            XCTAssertEqual(driver.calls, ["hello"])
            await channel.close()
        }
    }
    func testWrongLocalIdentityStopsBeforeHelloAndBeforeLaterOperations() async throws {
        final class Identity: @unchecked Sendable {
            let lock = NSLock(); var valid = false
            func verify() throws { try lock.withLock { if !valid { throw AdministrativeSetupChannelError.wrongAccount } } }
            func set(_ value: Bool) { lock.withLock { valid = value } }
        }
        let identity = Identity(), driver = Driver()
        let channel = AdministrativeSetupChannel(driver: driver, accountID: account, verifyAccount: { try identity.verify() })
        do { try await channel.start(); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .wrongAccount) }
        XCTAssertTrue(driver.calls.isEmpty)
        identity.set(true)
        let next = AdministrativeSetupChannel(driver: driver, accountID: account, verifyAccount: { try identity.verify() })
        try await next.start(); identity.set(false)
        do { _ = try await next.progress(); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .wrongAccount) }
        XCTAssertEqual(driver.calls, ["hello"])
    }
    func testPublicConfigurationRefusesInvalidScopeBeforeCreatingConnection() throws {
        let root = try XPCPeerPolicy(teamID: "TEAMID1234", componentIdentifier: "dev.remozio.setup",
            approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: 0)
        for (name, uid, timeout) in [("other.service", getuid(), UInt64(5000)), ("dev.remozio.setup", uid_t(0), UInt64(5000)),
                                    ("dev.remozio.setup", getuid(), UInt64(0))] {
            XCTAssertThrowsError(try AdministrativeSetupChannel(serviceName: name, rootPolicy: root, accountID: account,
                ownerUID: uid, timeoutMilliseconds: timeout)) { XCTAssertEqual($0 as? AdministrativeSetupChannelError, .invalidConfiguration) }
        }
    }
}
