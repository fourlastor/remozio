import Darwin
import Foundation
import RemozioProtocol
import Security
import Synchronization
import XCTest
@testable import RemozioCore

private enum AuditAppFixture {
    static func progress(seed: UInt8 = 1, stage: SetupAuditUpgradeProgress.Stage = .ready) throws -> SetupAuditUpgradeProgress {
        let limits = try CBORLimits(maxBytes: 2048, maxDepth: 2, maxItems: 64)
        func id(_ offset: UInt8, _ count: Int = 16) -> CBORValue { .bytes(Data(repeating: seed + offset, count: count)) }
        let runtime = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: id(0), 2: id(1), 3: id(2),
            4: id(3), 5: .unsigned(UInt64(getuid())), 6: id(4), 7: id(5), 8: .boolean(true)]), limits: limits)
        return try .decode(DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(runtime), 2: id(6),
            3: id(7, 32), 4: id(8, 32), 5: .unsigned(stage.rawValue), 6: .array([])]), limits: limits))
    }
    static func done(_ value: SetupAuditUpgradeProgress) throws -> SetupAuditUpgradeProgress {
        try value.observing(.registrationObserved(.init(selectedRoles: [.authority, .transport], registrationConfirmed: [.authority, .transport])))
    }
}

@MainActor
final class MacAuditUpgradeControlsTests: XCTestCase {
    private actor Driver: MacAuditUpgradeDriver {
        var value: SetupAuditUpgradeProgress?
        var result: SetupAuditUpgradeProgress?
        var failure: MacAuditUpgradeDriverError?
        var readFails = false, readUnavailable = false, invalidSettings = false
        var reads = 0, writes = 0
        var held: CheckedContinuation<Void, Never>?
        var pause = false
        init(_ value: SetupAuditUpgradeProgress?) { self.value = value }
        func configure(result: SetupAuditUpgradeProgress? = nil, failure: MacAuditUpgradeDriverError? = nil, readFails: Bool = false, readUnavailable: Bool = false, pause: Bool = false) {
            self.result = result; self.failure = failure; self.readFails = readFails; self.readUnavailable = readUnavailable; self.pause = pause
        }
        func progress() throws -> SetupAuditUpgradeProgress? {
            reads += 1
            if invalidSettings { throw MacAuditUpgradeSettingsError.invalidPreferences }
            if readUnavailable { throw AuditUpgradeSetupChannelError.progressUnavailable }
            if readFails { throw AdministrativeSetupChannelError.closed }
            return value
        }
        func perform(_ expected: SetupAuditUpgradeProgress) async throws -> SetupAuditUpgradeProgress {
            writes += 1
            if invalidSettings { throw MacAuditUpgradeSettingsError.invalidPreferences }
            if pause { await withCheckedContinuation { held = $0 } }
            if let failure { throw failure }; return result ?? expected
        }
        func setInvalidSettings(_ value: Bool) { invalidSettings = value }
        func counts() -> [Int] { [reads, writes] }
        func release() { held?.resume(); held = nil }
    }
    private func waitForWrite(_ driver: Driver) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(3))
        while await driver.counts()[1] == 0 {
            guard ContinuousClock.now < end else { throw AdministrativeSetupChannelError.timedOut }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testUnavailableReadDisablesChangesUntilAnExplicitFreshRead() async throws {
        let driver = Driver(try AuditAppFixture.progress()), controls = MacAuditUpgradeControls(driver: driver)
        await driver.configure(readUnavailable: true); await controls.refresh()
        XCTAssertEqual(controls.notice, .progressUnavailable); XCTAssertNil(controls.progress)
        XCTAssertFalse(controls.loaded); XCTAssertFalse(controls.canUpgrade)
        await controls.upgrade(); var counts = await driver.counts(); XCTAssertEqual(counts, [1, 0])
        await driver.configure(); await controls.refresh()
        XCTAssertTrue(controls.loaded); XCTAssertTrue(controls.canUpgrade); XCTAssertNil(controls.notice)
        counts = await driver.counts(); XCTAssertEqual(counts, [2, 0])
    }
    func testUnavailablePreflightKeepsTheRemoteStateUnknownUntilRefresh() async throws {
        let driver = Driver(try AuditAppFixture.progress()), controls = MacAuditUpgradeControls(driver: driver)
        await controls.refresh(); await driver.configure(failure: .progressUnavailable); await controls.upgrade()
        XCTAssertEqual(controls.notice, .progressUnavailable); XCTAssertNil(controls.progress)
        XCTAssertFalse(controls.loaded); XCTAssertFalse(controls.canUpgrade)
        await controls.upgrade(); var counts = await driver.counts(); XCTAssertEqual(counts, [1, 1])
        await controls.refresh(); counts = await driver.counts(); XCTAssertEqual(counts, [2, 1])
        XCTAssertTrue(controls.canUpgrade); XCTAssertNil(controls.notice)
    }
    func testInitialReadAndExplicitActionAreRequired() async throws {
        let value = try AuditAppFixture.progress(), driver = Driver(value), controls = MacAuditUpgradeControls(driver: driver)
        await controls.upgrade(); var counts = await driver.counts(); XCTAssertEqual(counts, [0, 0])
        await controls.refresh(); XCTAssertTrue(controls.canUpgrade); counts = await driver.counts(); XCTAssertEqual(counts, [1, 0])
        await driver.configure(result: try AuditAppFixture.done(value)); await controls.upgrade()
        XCTAssertEqual(controls.progress?.stage, .registrationObserved); XCTAssertFalse(controls.canUpgrade)
        await controls.upgrade(); counts = await driver.counts(); XCTAssertEqual(counts, [1, 1])
        await controls.refresh(); XCTAssertTrue(controls.progress?.registrationObserved.isEmpty == true)
        XCTAssertEqual(controls.progress, value)
    }
    func testNilAndAlreadyCurrentReadsCannotMutate() async throws {
        for value in [nil, try AuditAppFixture.progress(stage: .alreadyCurrent)] {
            let driver = Driver(value), controls = MacAuditUpgradeControls(driver: driver)
            await controls.refresh(); XCTAssertTrue(controls.loaded); XCTAssertFalse(controls.canUpgrade)
            await controls.upgrade(); let counts = await driver.counts(); XCTAssertEqual(counts, [1, 0])
        }
    }
    func testUnknownResultDisablesFurtherWritesUntilAnExplicitFreshRead() async throws {
        let value = try AuditAppFixture.progress(), driver = Driver(value), controls = MacAuditUpgradeControls(driver: driver)
        await controls.refresh(); await driver.configure(failure: .outcomeUnknown); await controls.upgrade()
        XCTAssertFalse(controls.loaded); XCTAssertNil(controls.progress); XCTAssertEqual(controls.notice, .outcomeUnknown)
        await controls.upgrade(); var counts = await driver.counts(); XCTAssertEqual(counts, [1, 1])
        await controls.refresh(); counts = await driver.counts(); XCTAssertEqual(counts, [2, 1]); XCTAssertTrue(controls.canUpgrade)
    }
    func testKnownPreSubmissionFailureAndChangedProgressStayDistinct() async throws {
        for (failure, notice) in [(MacAuditUpgradeDriverError.notSubmitted, MacAuditUpgradeNotice.notSubmitted), (.progressChanged, .progressChanged)] {
            let driver = Driver(try AuditAppFixture.progress()), controls = MacAuditUpgradeControls(driver: driver)
            await controls.refresh(); await driver.configure(failure: failure); await controls.upgrade()
            XCTAssertEqual(controls.notice, notice); XCTAssertFalse(controls.canUpgrade); XCTAssertNil(controls.progress)
        }
    }
    func testForeignScopeOrReadOnlyMutationResultRequiresRecovery() async throws {
        for foreign in [false, true] {
            let value = try AuditAppFixture.progress(), driver = Driver(value), controls = MacAuditUpgradeControls(driver: driver)
            let result = foreign ? try AuditAppFixture.done(AuditAppFixture.progress(seed: 20)) : value
            await driver.configure(result: result); await controls.refresh(); await controls.upgrade()
            XCTAssertEqual(controls.notice, .outcomeUnknown); XCTAssertFalse(controls.canUpgrade)
        }
    }
    func testWaitingResultNeverRetriesItselfAndPermitsOneExplicitRetry() async throws {
        let value = try AuditAppFixture.progress(), driver = Driver(value), controls = MacAuditUpgradeControls(driver: driver)
        await driver.configure(result: try value.observing(.waitingForQuiescence)); await controls.refresh(); await controls.upgrade()
        var counts = await driver.counts(); XCTAssertEqual(counts, [1, 1]); XCTAssertTrue(controls.canUpgrade)
        await controls.upgrade(); counts = await driver.counts(); XCTAssertEqual(counts, [1, 2])
    }
    func testBusyAndCloseCannotReplaceAnOperationOrPublishItsLateResult() async throws {
        let value = try AuditAppFixture.progress(), driver = Driver(value), controls = MacAuditUpgradeControls(driver: driver)
        await driver.configure(result: try AuditAppFixture.done(value), pause: true); await controls.refresh()
        let task = Task { await controls.upgrade() }; try await waitForWrite(driver)
        await controls.refresh(); await controls.upgrade(); let counts = await driver.counts(); XCTAssertEqual(counts, [1, 1])
        controls.close(); await driver.release(); await task.value
        XCTAssertNil(controls.progress); XCTAssertFalse(controls.loaded); XCTAssertFalse(controls.canUpgrade); XCTAssertNil(controls.notice)
        await controls.refresh(); let after = await driver.counts(); XCTAssertEqual(after, counts)
    }
    func testRefreshFailureDropsPreviousRegistrationObservations() async throws {
        let value = try AuditAppFixture.progress(), driver = Driver(value), controls = MacAuditUpgradeControls(driver: driver)
        await driver.configure(result: try AuditAppFixture.done(value)); await controls.refresh(); await controls.upgrade()
        await driver.configure(readFails: true); await controls.refresh()
        XCTAssertEqual(controls.notice, .refreshFailed); XCTAssertNil(controls.progress); XCTAssertFalse(controls.loaded)
    }
    func testInvalidSettingsPointToSettingsInsteadOfSuggestingRepeatedReads() async throws {
        let driver = Driver(try AuditAppFixture.progress()), controls = MacAuditUpgradeControls(driver: driver)
        await driver.setInvalidSettings(true); await controls.refresh()
        XCTAssertEqual(controls.notice, .invalidSettings); XCTAssertFalse(controls.loaded)
        await driver.setInvalidSettings(false); await controls.refresh(); XCTAssertTrue(controls.canUpgrade)
        await driver.setInvalidSettings(true); await controls.upgrade()
        XCTAssertEqual(controls.notice, .invalidSettings); XCTAssertFalse(controls.canUpgrade)
    }
    func testMutationOnlyStageCannotBePresentedAsASavedRead() async throws {
        let driver = Driver(try AuditAppFixture.progress(stage: .waitingForMachine)), controls = MacAuditUpgradeControls(driver: driver)
        await controls.refresh(); XCTAssertEqual(controls.notice, .refreshFailed); XCTAssertFalse(controls.canUpgrade)
    }
}

final class MacAuditUpgradeDriverTests: XCTestCase, @unchecked Sendable {
    private final class Wire: AuditUpgradeSetupDriver, Sendable {
        struct State {
            var history: [String] = []
            var peerValid = true, closed = false, hold = false, refuseRead = false
            var held: (@Sendable (SetupClientReply) -> Void)?
        }
        let state = Mutex(State())
        let value: SetupAuditUpgradeProgress, result: SetupAuditUpgradeProgress
        init(_ value: SetupAuditUpgradeProgress, result: SetupAuditUpgradeProgress? = nil) throws {
            self.value = value; self.result = try result ?? AuditAppFixture.done(value)
        }
        func start(closed: @escaping @Sendable () -> Void) {}
        func verifyPeer() throws { try state.withLock { if !$0.peerValid || $0.closed { throw AdministrativeSetupChannelError.closed } } }
        func invoke(_ call: AuditUpgradeSetupCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            let response: SetupClientReply? = state.withLock {
                switch call {
                case .hello: $0.history.append("hello"); return .version(11)
                case .progress: $0.history.append("read"); return $0.refuseRead ? .progress(nil) : .progress(try! value.bytes)
                case .perform:
                    $0.history.append("write"); if $0.hold { $0.held = reply; return nil }; return .progress(try! result.bytes)
                }
            }
            if let response { reply(response) }
        }
        func close() { state.withLock { $0.closed = true } }
    }
    private final class Grant: MacAuditUpgradeAppAuthorization, Sendable {
        struct State { var authorizes = 0, exports = 0, closes = 0; var onMain = false, cancelled = false }
        let state = Mutex(State())
        let authorized: @Sendable () -> Void
        init(authorized: @escaping @Sendable () -> Void = {}) { self.authorized = authorized }
        func authorize() throws {
            try state.withLock {
                $0.authorizes += 1; $0.onMain = Thread.isMainThread
                if $0.cancelled { throw SetupAdministratorAuthorizationError.cancelled }
            }
            authorized()
        }
        func externalForm() throws -> Data { state.withLock { $0.exports += 1 }; return Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size) }
        func close() { state.withLock { $0.closes += 1 } }
    }
    private func driver(_ wire: Wire, grant: Grant) -> NativeMacAuditUpgradeDriver {
        NativeMacAuditUpgradeDriver(open: { expected in AuditUpgradeSetupChannel(driver: wire, expected: expected) }, authorization: { grant })
    }
    func testUnavailablePreflightNeverPromptsExportsRightsOrSubmits() async throws {
        let value = try AuditAppFixture.progress(), wire = try Wire(value), grant = Grant()
        wire.state.withLock { $0.refuseRead = true }
        do { _ = try await driver(wire, grant: grant).perform(value); XCTFail("Unavailable progress") }
        catch { XCTAssertEqual(error as? MacAuditUpgradeDriverError, .progressUnavailable) }
        XCTAssertEqual(grant.state.withLock { [$0.authorizes, $0.exports, $0.closes] }, [0, 0, 0])
        XCTAssertEqual(wire.state.withLock { $0.history }, ["hello", "read"])
        XCTAssertTrue(wire.state.withLock { $0.closed })
    }
    func testReadDoesNotAcquireOrExportAdministratorRights() async throws {
        let value = try AuditAppFixture.progress(), wire = try Wire(value), grant = Grant(), driver = driver(wire, grant: grant)
        let result = try await driver.progress(); XCTAssertEqual(result, value)
        XCTAssertEqual(grant.state.withLock { [$0.authorizes, $0.exports, $0.closes] }, [0, 0, 0])
        XCTAssertEqual(wire.state.withLock { $0.history }, ["hello", "read"])
    }
    func testExplicitAttemptReadsScopeBeforeAuthorizationAndClosesGrantAfterReply() async throws {
        let value = try AuditAppFixture.progress(), wire = try Wire(value)
        let grant = Grant { XCTAssertEqual(wire.state.withLock { $0.history }, ["hello", "read"]) }
        let result = try await driver(wire, grant: grant).perform(value)
        XCTAssertEqual(result.stage, .registrationObserved)
        XCTAssertEqual(grant.state.withLock { [$0.authorizes, $0.exports, $0.closes] }, [1, 1, 1])
        XCTAssertFalse(grant.state.withLock { $0.onMain }); XCTAssertTrue(wire.state.withLock { $0.closed })
    }
    func testForeignFreshReadAndFailedPeerNeverPromptOrSend() async throws {
        let expected = try AuditAppFixture.progress()
        for badPeer in [false, true] {
            let wire = try Wire(badPeer ? expected : AuditAppFixture.progress(seed: 20)), grant = Grant()
            if badPeer { wire.state.withLock { $0.peerValid = false } }
            do { _ = try await driver(wire, grant: grant).perform(expected); XCTFail("Refused preflight") }
            catch { XCTAssertEqual(error as? MacAuditUpgradeDriverError, badPeer ? .notSubmitted : .progressChanged) }
            XCTAssertEqual(grant.state.withLock { $0.authorizes }, 0)
            XCTAssertFalse(wire.state.withLock { $0.history.contains("write") })
        }
    }
    func testPeerChangeDuringPromptCannotExportRights() async throws {
        let value = try AuditAppFixture.progress(), wire = try Wire(value), grant = Grant { wire.state.withLock { $0.peerValid = false } }
        do { _ = try await driver(wire, grant: grant).perform(value); XCTFail("Changed peer") }
        catch { XCTAssertEqual(error as? MacAuditUpgradeDriverError, .notSubmitted) }
        XCTAssertEqual(grant.state.withLock { [$0.authorizes, $0.exports, $0.closes] }, [1, 0, 1])
    }
    func testCancelledPromptClosesGrantWithoutExportOrMutation() async throws {
        let value = try AuditAppFixture.progress(), wire = try Wire(value), grant = Grant(); grant.state.withLock { $0.cancelled = true }
        do { _ = try await driver(wire, grant: grant).perform(value); XCTFail("Cancelled prompt") } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(grant.state.withLock { [$0.authorizes, $0.exports, $0.closes] }, [1, 0, 1])
        XCTAssertFalse(wire.state.withLock { $0.history.contains("write") })
    }
    func testCancellationAfterPossibleSendStaysUnknownAndNeverReplays() async throws {
        let value = try AuditAppFixture.progress(), wire = try Wire(value), grant = Grant(); wire.state.withLock { $0.hold = true }
        let driver = driver(wire, grant: grant), task = Task { try await driver.perform(value) }
        let end = ContinuousClock.now.advanced(by: .seconds(3))
        while !wire.state.withLock({ $0.history.contains("write") }) {
            guard ContinuousClock.now < end else { task.cancel(); throw AdministrativeSetupChannelError.timedOut }
            try await Task.sleep(for: .milliseconds(2))
        }
        task.cancel()
        do { _ = try await task.value; XCTFail("Unknown result") } catch { XCTAssertEqual(error as? MacAuditUpgradeDriverError, .outcomeUnknown) }
        XCTAssertEqual(wire.state.withLock { $0.history }, ["hello", "read", "write"])
        XCTAssertEqual(grant.state.withLock { $0.closes }, 1)
    }
    func testInvalidTimeoutIsRefusedWithoutOpeningServices() throws {
        for timeout: UInt64 in [0, 300_001, .max] { XCTAssertThrowsError(try NativeMacAuditUpgradeDriver(operationTimeoutMilliseconds: timeout)) }
    }
}
