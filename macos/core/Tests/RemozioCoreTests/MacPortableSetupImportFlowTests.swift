import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Logical Root replies test client sequencing. These fixtures do not qualify native authorization or service activation.
final class MacPortableSetupImportFlowTests: XCTestCase, @unchecked Sendable {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var value = ContinuousClock.now
        func now() -> ContinuousClock.Instant { lock.withLock { value } }
        func expire() { lock.withLock { value = value.advanced(by: .seconds(300)) } }
    }
    private actor Events {
        var actions: [SetupPortableImportOperation.Action] = []
        var recoveryReads = 0
        func recoveryRead() { recoveryReads += 1 }
        var prompts = 0, forms = 0, rightsClosed = 0, connectionsClosed = 0, connectionsStarted = 0
        func action(_ action: SetupPortableImportOperation.Action) { actions.append(action) }
        func authorize(prompt: Bool) { if prompt { prompts += 1 }; forms += 1 }
        func closed(rights: Bool) { if rights { rightsClosed += 1 } else { connectionsClosed += 1 } }
        func started() { connectionsStarted += 1 }
    }
    private actor Administrator: MacPortableSetupImportAdministrator {
        let events: Events
        let onAuthorization: @Sendable () -> Void
        var granted = false
        init(_ events: Events, onAuthorization: @escaping @Sendable () -> Void = {}) {
            self.events = events; self.onAuthorization = onAuthorization
        }
        func authorization() async throws -> Data {
            await events.authorize(prompt: !granted); granted = true; onAuthorization(); return Data([1, 2, 3])
        }
        func close() async { await events.closed(rights: true) }
    }
    private actor Root: MacPortableSetupImportRoot {
        var current: SetupPortableImportProgress
        let events: Events
        let recoveryValue: SetupPortableImportRecovery?
        let failureAction: SetupPortableImportOperation.Action?
        let failRecoveryAfterWrites: Bool
        private var hasWritten = false
        let pausedAction: SetupPortableImportOperation.Action?
        let pausedStatus: SetupPortableImportOperationResult.Status
        let didPerform: @Sendable (SetupPortableImportOperation.Action) -> Void
        init(_ expected: SetupPortableImportProgress, events: Events, recovery: SetupPortableImportRecovery? = nil, failureAction: SetupPortableImportOperation.Action? = nil, failRecoveryAfterWrites: Bool = false, pausedAction: SetupPortableImportOperation.Action? = nil,
             status: SetupPortableImportOperationResult.Status = .requiresReconciliation,
             didPerform: @escaping @Sendable (SetupPortableImportOperation.Action) -> Void = { _ in }) {
            current = expected; self.events = events; recoveryValue = recovery; self.failureAction = failureAction; self.failRecoveryAfterWrites = failRecoveryAfterWrites; self.pausedAction = pausedAction; pausedStatus = status; self.didPerform = didPerform
        }
        func recovery() async throws -> SetupPortableImportRecovery? {
            await events.recoveryRead()
            if hasWritten && failRecoveryAfterWrites { throw AdministrativeSetupChannelError.invalidMessage }
            guard let recoveryValue else { throw AdministrativeSetupChannelError.unsupportedVersion }
            return try .init(progress: current, relayConfigured: recoveryValue.relayConfigured, relayScope: recoveryValue.relayScope, records: recoveryValue.records)
        }
        func start() async throws { await events.started() }
        func progress() async throws -> SetupPortableImportProgress? { current }
        func perform(_ request: SetupPortableImportOperation, authorization: Data) async throws -> SetupPortableImportOperationResult {
            XCTAssertEqual(authorization, Data([1, 2, 3])); XCTAssertEqual(request.expected, current)
            await events.action(request.action); hasWritten = true
            let status: SetupPortableImportOperationResult.Status = request.action == pausedAction ? pausedStatus : .applied
            current = try Self.advance(current, request: request)
            didPerform(request.action)
            if failureAction == request.action { throw AdministrativeSetupChannelError.closed }
            return try .init(request: request, progress: current, status: status)
        }
        func close() async { await events.closed(rights: false) }
        private static func advance(_ source: SetupPortableImportProgress, request: SetupPortableImportOperation) throws -> SetupPortableImportProgress {
            let limits = try CBORLimits(maxBytes: 2000, maxDepth: 2, maxItems: 40)
            guard case .map(var fields) = try DeterministicCBOR.decode(source.bytes, limits: limits),
                  case .map(var runtime) = try DeterministicCBOR.decode(source.runtime.bytes, limits: limits) else { throw PortableSetupError.rejected }
            var phase = source.phase
            if phase == nil {
                fields[4] = .bytes(Data(repeating: 10, count: 16)); fields[5] = .bytes(Data(repeating: 11, count: 16))
                fields[6] = .bytes(Data(SHA256.hash(data: try request.proposal.canonicalBytes())))
                fields[8] = .bytes(Data(repeating: 12, count: 32)); phase = .retained
            }
            if request.action == .prepareRuntime {
                runtime[7] = .bytes(Data(repeating: 13, count: 16)); runtime[8] = .boolean(true); phase = .runtimePublished
            }
            if request.action == .prepareGateway { phase = .gatewayPrepared }
            if request.action == .complete { phase = .rootComplete }
            fields[1] = .bytes(try DeterministicCBOR.encode(.map(runtime), limits: limits))
            fields[7] = .unsigned(try XCTUnwrap(phase).rawValue)
            return try .decode(DeterministicCBOR.encode(.map(fields), limits: limits))
        }
    }
    private func fresh(_ source: SetupPortableImportProgress) throws -> SetupPortableImportProgress {
        let limits = try CBORLimits(maxBytes: 2000, maxDepth: 2, maxItems: 40)
        guard case .map(var fields) = try DeterministicCBOR.decode(source.bytes, limits: limits) else { throw PortableSetupError.rejected }
        for key: UInt64 in 4...8 { fields[key] = .null }
        return try .decode(DeterministicCBOR.encode(.map(fields), limits: limits))
    }
    private let custody = SetupPortableImportCustodyChoices(runtimeFiles: true, pushCredentials: true, relayCredential: true)
    private func driver(root: Root, events: Events, clock: Clock = Clock(), expireOnAuthorization: Bool = false) -> NativeMacPortableSetupImportDriver {
        NativeMacPortableSetupImportDriver(open: { root }, administrator: {
            Administrator(events, onAuthorization: { if expireOnAuthorization { clock.expire() } })
        }, now: { clock.now() })
    }
    private func rejectedDNS() throws -> (DNSRecordFixture, SetupAccountOwner, SetupPortableImportRecovery, ReviewedSetupFile) {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner()
        let first = try f.begin(), sent = try first.transition(to: .dispatched), rejected = try sent.transition(to: .rejected, refusal: .unauthorized)
        try f.replace(sent, previous: first); try f.replace(rejected, previous: sent)
        return try (f, owner, XCTUnwrap(owner.portableImportRecovery(callerUID: getuid())), ReviewedSetupFile(proposal: f.base.h.f.proposal()))
    }
    func testRefusalRetryAndLaterImportStepsShareOneBoundedRightsOwner() async throws {
        let (_, owner, recovery, reviewed) = try rejectedDNS(); defer { try? owner.close(); reviewed.close() }
        let events = Events(), root = Root(recovery.progress, events: events, recovery: recovery)
        let driver = driver(root: root, events: events)
        let snapshot = try await driver.snapshot(); XCTAssertEqual(snapshot.recovery, recovery); XCTAssertEqual(snapshot.progress, recovery.progress)
        let formsBefore = await events.forms; XCTAssertEqual(formsBefore, 0)
        let result = try await driver.retryImportFile(reviewed, recovery: recovery, resource: .dnsRecord, custody: custody) { _, _ in }
        XCTAssertEqual(result.action, .complete); XCTAssertEqual(result.progress.phase, .rootComplete)
        let actions = await events.actions, prompts = await events.prompts, forms = await events.forms, closed = await events.rightsClosed
        XCTAssertEqual(actions.first, .prepareRefusedDNSRetry); XCTAssertEqual(actions.dropFirst().first, .retain)
        XCTAssertEqual(actions.filter { $0 == .prepareRefusedDNSRetry }.count, 1)
        XCTAssertEqual(actions.filter { $0 == .createDNS }.count, 1)
        XCTAssertEqual(prompts, 1); XCTAssertEqual(forms, actions.count); XCTAssertEqual(closed, 1)
    }
    func testChangedRejectedMetadataOrMissingRecoveryCapabilityCannotObtainRights() async throws {
        let (_, owner, recovery, reviewed) = try rejectedDNS(); defer { try? owner.close(); reviewed.close() }
        let rows = try recovery.records.map { row in
            try SetupPortableImportRecovery.Record(resource: row.resource, phase: row.phase, digest: Data(repeating: 55, count: 32),
                attempt: row.attemptNumber, providerID: row.providerID, refusal: row.refusal)
        }
        let changed = try SetupPortableImportRecovery(progress: recovery.progress, relayConfigured: true, relayScope: recovery.relayScope, records: rows)
        for actual in [changed, nil] {
            let events = Events(), root = Root(recovery.progress, events: events, recovery: actual)
            do {
                _ = try await driver(root: root, events: events).retryImportFile(reviewed, recovery: recovery, resource: .dnsRecord, custody: custody) { _, _ in }; XCTFail()
            } catch {
                if actual == nil { XCTAssertEqual(error as? AdministrativeSetupChannelError, .unsupportedVersion) }
                else { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
            }
            let actions = await events.actions, prompts = await events.prompts, closed = await events.rightsClosed
            XCTAssertTrue(actions.isEmpty); XCTAssertEqual(prompts, 0); XCTAssertEqual(closed, 1)
        }
    }
    func testRetryWindowCannotBeExtendedByItsFirstPromptOrPreparedAttempt() async throws {
        let (_, owner, recovery, reviewed) = try rejectedDNS(); defer { try? owner.close(); reviewed.close() }
        for duringPrompt in [true, false] {
            let events = Events(), clock = Clock()
            let root = Root(recovery.progress, events: events, recovery: recovery, didPerform: { _ in if !duringPrompt { clock.expire() } })
            do {
                _ = try await driver(root: root, events: events, clock: clock, expireOnAuthorization: duringPrompt)
                    .retryImportFile(reviewed, recovery: recovery, resource: .dnsRecord, custody: custody) { _, _ in }; XCTFail()
            } catch { XCTAssertEqual(error as? SetupPortableImportFlowError, .authorizationExpired) }
            let actions = await events.actions, closed = await events.rightsClosed
            XCTAssertEqual(actions, duringPrompt ? [] : [.prepareRefusedDNSRetry]); XCTAssertEqual(closed, 1)
        }
    }
    func testRecoveryRefusesUnknownStateOrMissingCustodyBeforeOpeningRoot() async throws {
        let (_, owner, recovery, reviewed) = try rejectedDNS(); defer { try? owner.close(); reviewed.close() }
        let unknownRows = try recovery.records.map { row in
            try SetupPortableImportRecovery.Record(resource: row.resource, phase: row.resource == .dnsRecord ? .unknown : row.phase,
                digest: row.recordDigest, attempt: row.attemptNumber, providerID: row.providerID, refusal: row.resource == .dnsRecord ? nil : row.refusal)
        }
        let unknown = try SetupPortableImportRecovery(progress: recovery.progress, relayConfigured: true, relayScope: recovery.relayScope, records: unknownRows)
        for missingCustody in [true, false] {
            let events = Events(), root = Root(recovery.progress, events: events, recovery: recovery)
            do {
                _ = try await driver(root: root, events: events).retryImportFile(reviewed, recovery: missingCustody ? recovery : unknown,
                    resource: .dnsRecord, custody: missingCustody ? .init() : custody) { _, _ in }; XCTFail()
            } catch {}
            let actions = await events.actions, prompts = await events.prompts, started = await events.connectionsStarted
            XCTAssertTrue(actions.isEmpty); XCTAssertEqual(prompts, 0); XCTAssertEqual(started, 0)
        }
    }
    func testClosingTheReviewAfterRecoveryStopsAllLaterSteps() async throws {
        let (_, owner, recovery, reviewed) = try rejectedDNS(); defer { try? owner.close() }
        let events = Events(), root = Root(recovery.progress, events: events, recovery: recovery)
        do {
            _ = try await driver(root: root, events: events).retryImportFile(reviewed, recovery: recovery, resource: .dnsRecord, custody: custody) { action, _ in
                if action == .retain { reviewed.close() }
            }; XCTFail()
        } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
        let actions = await events.actions, closed = await events.rightsClosed
        XCTAssertEqual(actions, [.prepareRefusedDNSRetry]); XCTAssertEqual(closed, 1)
    }
    func testLostRecoveryReplyStopsWithoutReadbackOrAnotherWrite() async throws {
        let (_, owner, recovery, reviewed) = try rejectedDNS(); defer { try? owner.close(); reviewed.close() }
        let events = Events(), root = Root(recovery.progress, events: events, recovery: recovery, failureAction: .prepareRefusedDNSRetry)
        do {
            _ = try await driver(root: root, events: events).retryImportFile(reviewed, recovery: recovery, resource: .dnsRecord, custody: custody) { _, _ in }; XCTFail()
        } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
        let actions = await events.actions, reads = await events.recoveryReads, closed = await events.rightsClosed
        XCTAssertEqual(actions, [.prepareRefusedDNSRetry]); XCTAssertEqual(reads, 1); XCTAssertEqual(closed, 1)
    }
    @MainActor
    func testAppReadsARejectedResourceAndRetriesWithoutAnotherPromptBetweenSteps() async throws {
        let (_, owner, recovery, reviewed) = try rejectedDNS(); defer { try? owner.close() }
        let events = Events(), root = Root(recovery.progress, events: events, recovery: recovery)
        let controls = MacPortableSetupImportControls(reviewed: reviewed, driver: driver(root: root, events: events))
        defer { controls.close() }
        await controls.refresh(); XCTAssertEqual(controls.recovery, recovery)
        await controls.retryImport(resource: .dnsRecord, custody: .init())
        XCTAssertTrue(controls.loaded); XCTAssertEqual(controls.notice, .custodyRequired); XCTAssertEqual(controls.recovery, recovery)
        await controls.retryImport(resource: .dnsRecord, custody: custody)
        XCTAssertNil(controls.notice); XCTAssertNil(controls.recovery)
        XCTAssertEqual(controls.lastResult?.action, .complete); XCTAssertEqual(controls.progress?.phase, .rootComplete)
        let prompts = await events.prompts, actions = await events.actions
        XCTAssertEqual(prompts, 1); XCTAssertEqual(actions.first, .prepareRefusedDNSRetry)
    }
    @MainActor
    func testAppReadsFreshRecoveryAfterAnotherProviderRefusalWithoutRepeatingIt() async throws {
        let (_, owner, recovery, reviewed) = try rejectedDNS(); defer { try? owner.close() }
        let events = Events(), root = Root(recovery.progress, events: events, recovery: recovery, pausedAction: .createDNS, status: .providerRejected)
        let controls = MacPortableSetupImportControls(reviewed: reviewed, driver: driver(root: root, events: events))
        defer { controls.close() }
        await controls.refresh(); await controls.retryImport(resource: .dnsRecord, custody: custody)
        XCTAssertNil(controls.notice); XCTAssertTrue(controls.loaded)
        XCTAssertEqual(controls.lastResult?.status, .providerRejected)
        XCTAssertEqual(controls.recovery?.progress, controls.progress)
        XCTAssertNotNil(controls.recovery?.rejectedRecord(for: .dnsRecord))
        let prompts = await events.prompts, actions = await events.actions
        XCTAssertEqual(prompts, 1); XCTAssertEqual(actions.last, .createDNS)
        XCTAssertEqual(actions.filter { $0 == .prepareRefusedDNSRetry }.count, 1)
        XCTAssertFalse(actions.contains(.complete))
    }
    @MainActor
    func testFailedMetadataReadPreservesAConfirmedProviderRefusalAndDisablesNewWork() async throws {
        let (_, owner, recovery, reviewed) = try rejectedDNS(); defer { try? owner.close() }
        let events = Events(), root = Root(recovery.progress, events: events, recovery: recovery,
            failRecoveryAfterWrites: true, pausedAction: .createDNS, status: .providerRejected)
        let controls = MacPortableSetupImportControls(reviewed: reviewed, driver: driver(root: root, events: events))
        defer { controls.close() }
        await controls.refresh(); await controls.retryImport(resource: .dnsRecord, custody: custody)
        XCTAssertFalse(controls.loaded); XCTAssertEqual(controls.notice, .refreshFailed); XCTAssertNil(controls.recovery)
        XCTAssertEqual(controls.lastResult?.status, .providerRejected); XCTAssertEqual(controls.lastResult?.action, .createDNS)
        XCTAssertEqual(controls.progress, controls.lastResult?.progress)
        let before = await events.actions
        await controls.importFile(custody: custody); await controls.retryImport(resource: .dnsRecord, custody: custody)
        let after = await events.actions; XCTAssertEqual(after, before)
    }
    func testCompleteRelayAttemptReusesOneRightsOwnerAndAuthenticatesEveryStep() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        defer { reviewed.close() }
        let events = Events(), root = Root(expected, events: events), driver = driver(root: root, events: events)
        let result = try await driver.importFile(reviewed, expected: expected, custody: custody) { _, _ in }
        XCTAssertEqual(result.action, .complete); XCTAssertEqual(result.status, .applied); XCTAssertEqual(result.progress.phase, .rootComplete)
        let actions = await events.actions, prompts = await events.prompts, forms = await events.forms
        let closed = await events.rightsClosed, started = await events.connectionsStarted, connectionsClosed = await events.connectionsClosed
        XCTAssertEqual(actions, [.retain, .prepareRelayPlan, .prepareRuntime, .activateRuntime, .prepareGateway,
            .createTunnel, .applyIngress, .prepareRunCredential, .createAccess, .createDNS, .publishConnector, .complete])
        XCTAssertEqual(prompts, 1); XCTAssertEqual(forms, actions.count); XCTAssertEqual(closed, 1)
        XCTAssertEqual(started, actions.count); XCTAssertEqual(connectionsClosed, actions.count)
        _ = try await driver.importFile(reviewed, expected: result.progress, custody: .init()) { _, _ in }
        let after = await events.actions, finalPrompts = await events.prompts
        XCTAssertEqual(after, actions + [.complete]); XCTAssertEqual(finalPrompts, 2)
    }
    func testCustodyRefusalHappensBeforeRootOrAdministratorWork() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        defer { reviewed.close() }
        for choices in [SetupPortableImportCustodyChoices(), .init(runtimeFiles: true)] {
            let events = Events(), driver = driver(root: Root(expected, events: events), events: events)
            do { _ = try await driver.importFile(reviewed, expected: expected, custody: choices) { _, _ in }; XCTFail() }
            catch { XCTAssertEqual(error as? SetupPortableImportFlowError, .custodyNotAccepted) }
            let prompts = await events.prompts, started = await events.connectionsStarted
            XCTAssertEqual(prompts, 0); XCTAssertEqual(started, 0)
        }
    }
    func testUnknownOrRejectedProviderReplyStopsBeforeIngressAndNeverLoops() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        defer { reviewed.close() }
        for status: SetupPortableImportOperationResult.Status in [.requiresReconciliation, .providerRejected] {
            let events = Events(), root = Root(expected, events: events, pausedAction: .createTunnel, status: status)
            let result = try await driver(root: root, events: events).importFile(reviewed, expected: expected, custody: custody) { _, _ in }
            XCTAssertEqual(result.action, .createTunnel); XCTAssertEqual(result.status, status)
            let actions = await events.actions, closed = await events.rightsClosed
            XCTAssertEqual(actions.last, .createTunnel); XCTAssertEqual(actions.filter { $0 == .createTunnel }.count, 1)
            XCTAssertFalse(actions.contains(.applyIngress)); XCTAssertFalse(actions.contains(.complete)); XCTAssertEqual(closed, 1)
        }
    }
    func testExpiredWindowCannotSendTheFirstWriteOrBeginALaterStep() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        defer { reviewed.close() }
        for duringPrompt in [true, false] {
            let clock = Clock(), events = Events()
            let root = Root(expected, events: events, didPerform: { _ in if !duringPrompt { clock.expire() } })
            let driver = driver(root: root, events: events, clock: clock, expireOnAuthorization: duringPrompt)
            do { _ = try await driver.importFile(reviewed, expected: expected, custody: custody) { _, _ in }; XCTFail() }
            catch { XCTAssertEqual(error as? SetupPortableImportFlowError, .authorizationExpired) }
            let actions = await events.actions, closed = await events.rightsClosed
            XCTAssertEqual(actions, duringPrompt ? [] : [.retain]); XCTAssertEqual(closed, 1)
        }
    }
    func testClosingTheReviewBetweenStepsCannotDispatchAnotherWrite() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        let events = Events(), driver = driver(root: Root(expected, events: events), events: events)
        do {
            _ = try await driver.importFile(reviewed, expected: expected, custody: custody) { action, _ in
                if action == .prepareRelayPlan { reviewed.close() }
            }; XCTFail()
        } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
        let actions = await events.actions, closed = await events.rightsClosed
        XCTAssertEqual(actions, [.retain]); XCTAssertEqual(closed, 1)
    }
    func testGatewayCleanupPauseStopsBeforeRelayProvisioning() async throws {
        let gateway = try SharedSetupImportGatewayApplicationTests.Fixture(prepared: false), proposal = gateway.proposal()
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let selected = PortableSetup(defaults: proposal.defaults, fcm: proposal.fcm,
            cloudflare: try fixture.f.proposal().cloudflare, pushClient: proposal.pushClient)
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: selected)
        defer { reviewed.close() }
        let events = Events(), root = Root(expected, events: events, pausedAction: .activateGateway, status: .waitingForCleanup)
        let result = try await driver(root: root, events: events).importFile(reviewed, expected: expected, custody: custody) { _, _ in }
        XCTAssertEqual(result.status, .waitingForCleanup)
        let actions = await events.actions, closed = await events.rightsClosed
        XCTAssertEqual(actions.last, .activateGateway); XCTAssertFalse(actions.contains(.createTunnel)); XCTAssertEqual(closed, 1)
    }
    private actor Gate {
        private var opened = false
        private var waiter: CheckedContinuation<Void, Never>?
        func wait() async {
            guard !opened else { return }
            await withCheckedContinuation { waiter = $0 }
        }
        func release() { opened = true; waiter?.resume(); waiter = nil }
    }
    func testCancellationAfterAnAppliedStepClosesRightsAndDoesNotAssumeRollback() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        defer { reviewed.close() }
        let events = Events(), root = Root(expected, events: events, didPerform: { _ in withUnsafeCurrentTask { $0?.cancel() } })
        let driver = driver(root: root, events: events)
        let task = Task { try await driver.importFile(reviewed, expected: expected, custody: custody) { _, _ in } }
        do { _ = try await task.value; XCTFail("Accepted cancelled import") }
        catch { XCTAssertTrue(error is CancellationError) }
        let actions = await events.actions, closed = await events.rightsClosed
        XCTAssertEqual(actions, [.retain]); XCTAssertEqual(closed, 1)
        let current = try await driver.progress()
        XCTAssertEqual(current?.phase, .retained); XCTAssertNotNil(current?.operationID)
    }
    func testAnActiveFlowRejectsOverlappingReadsAndWritesWithoutSharingItsRights() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        defer { reviewed.close() }
        let events = Events(), root = Root(expected, events: events), driver = driver(root: root, events: events)
        let entered = expectation(description: "import attempt admitted"), gate = Gate()
        let task = Task {
            try await driver.importFile(reviewed, expected: expected, custody: custody) { action, _ in
                if action == .retain { entered.fulfill(); await gate.wait() }
            }
        }
        await fulfillment(of: [entered], timeout: 10)
        do { _ = try await driver.progress(); XCTFail("Accepted overlapping read") }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .busy) }
        do { _ = try await driver.perform(reviewed.operation(action: .retain, expected: expected)); XCTFail("Accepted overlapping write") }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .busy) }
        await gate.release()
        let result = try await task.value
        XCTAssertEqual(result.action, .complete)
        let prompts = await events.prompts, closed = await events.rightsClosed
        XCTAssertEqual(prompts, 1); XCTAssertEqual(closed, 1)
    }

    @MainActor
    func testAppControlsPublishOnlyTheCompletedFlowAndCloseTheReview() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        let events = Events(), root = Root(expected, events: events), driver = driver(root: root, events: events)
        let controls = MacPortableSetupImportControls(reviewed: reviewed, driver: driver)
        await controls.refresh()
        XCTAssertTrue(controls.loaded); XCTAssertNil(controls.lastResult)
        await controls.importFile(custody: custody)
        XCTAssertFalse(controls.working); XCTAssertNil(controls.notice)
        XCTAssertEqual(controls.lastResult?.action, .complete); XCTAssertEqual(controls.lastResult?.status, .applied)
        XCTAssertEqual(controls.progress?.phase, .rootComplete)
        let prompts = await events.prompts, closed = await events.rightsClosed
        XCTAssertEqual(prompts, 1); XCTAssertEqual(closed, 1)
        controls.close()
        XCTAssertFalse(controls.loaded); XCTAssertNil(controls.progress); XCTAssertNil(controls.lastResult)
        XCTAssertThrowsError(try reviewed.operation(action: .retain, expected: expected))
    }

    @MainActor
    func testCustodyRequirementsKeepThePreviewActionableWithoutAttemptingAWrite() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let expected = try fixture.progress(owner), reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        let requirements = try reviewed.custodyRequirements(expected: expected)
        XCTAssertEqual(requirements, [.runtimeFiles, .relayCredential])
        XCTAssertFalse(SetupPortableImportCustodyChoices().satisfies(requirements))
        XCTAssertTrue(SetupPortableImportCustodyChoices(runtimeFiles: true, relayCredential: true).satisfies(requirements))
        let events = Events(), root = Root(expected, events: events)
        let controls = MacPortableSetupImportControls(reviewed: reviewed, driver: driver(root: root, events: events))
        defer { controls.close() }
        await controls.refresh(); await controls.importFile(custody: .init())
        XCTAssertEqual(controls.requiredCustody, requirements); XCTAssertTrue(controls.loaded)
        XCTAssertEqual(controls.progress, expected); XCTAssertEqual(controls.notice, .custodyRequired)
        let actions = await events.actions, prompts = await events.prompts
        XCTAssertTrue(actions.isEmpty); XCTAssertEqual(prompts, 0)
        let different = ReviewedSetupFile(proposal: PortableSetup(defaults: try fixture.f.proposal().defaults))
        defer { different.close() }
        XCTAssertThrowsError(try different.custodyRequirements(expected: expected)) {
            XCTAssertEqual($0 as? SetupPortableImportFlowError, .differentProposal)
        }
    }
    func testPreferenceValuesRequireMatchingCompletionAndExcludeLocalOnlyKeys() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let preferences = try PortableAppPreferences(preferences: [PortableAppPreferences.menuBarKey: false,
            CommandFrontendCallerSettings.modeKey: "pipes", CommandFrontendCallerSettings.controlRetryKey: "17"])
        let proposal = try fixture.f.proposal().addingAppPreferences(preferences)
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: proposal)
        defer { reviewed.close() }
        XCTAssertThrowsError(try reviewed.appPreferenceValues(completed: expected, readExisting: { _ in nil }))
        let events = Events(), root = Root(expected, events: events)
        let result = try await driver(root: root, events: events).importFile(reviewed, expected: expected, custody: custody) { _, _ in }
        var destination: [String: Any] = [PortableAppPreferences.menuBarKey: true, "currentMode": "present", "loginRegistered": true]
        let values = try reviewed.appPreferenceValues(completed: result.progress, readExisting: { destination[$0] })
        XCTAssertEqual(Set(values.keys), Set([PortableAppPreferences.menuBarKey, CommandFrontendCallerSettings.modeKey, CommandFrontendCallerSettings.controlRetryKey]))
        for (key, value) in values { destination[key] = value }
        XCTAssertEqual(destination[PortableAppPreferences.menuBarKey] as? Bool, false)
        XCTAssertEqual(destination[CommandFrontendCallerSettings.modeKey] as? String, "pipes")
        XCTAssertEqual(destination["currentMode"] as? String, "present"); XCTAssertEqual(destination["loginRegistered"] as? Bool, true)
        let different = ReviewedSetupFile(proposal: PortableSetup(defaults: proposal.defaults)); defer { different.close() }
        XCTAssertThrowsError(try different.appPreferenceValues(completed: result.progress, readExisting: { _ in nil })) {
            XCTAssertEqual($0 as? SetupPortableImportFlowError, .differentProposal)
        }
        XCTAssertTrue(try reviewed.custodyRequirements(expected: result.progress).isEmpty)
    }
    func testSparsePreferencesValidateTheDestinationBeforeReturningAnyWrite() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner(); defer { try? owner.close() }
        let preferences = try PortableAppPreferences(preferences: [CommandFrontendCallerSettings.initialBackoffKey: "1500"])
        let proposal = try fixture.f.proposal().addingAppPreferences(preferences)
        let expected = try fresh(fixture.progress(owner)), reviewed = ReviewedSetupFile(proposal: proposal)
        defer { reviewed.close() }
        let events = Events(), root = Root(expected, events: events)
        let result = try await driver(root: root, events: events).importFile(reviewed, expected: expected, custody: custody) { _, _ in }
        var writes = 0
        do {
            let values = try reviewed.appPreferenceValues(completed: result.progress, readExisting: { key in
                key == CommandFrontendCallerSettings.maximumBackoffKey ? "1000" : nil
            })
            for _ in values { writes += 1 }
            XCTFail("Accepted an invalid destination merge")
        } catch {}
        XCTAssertEqual(writes, 0)
    }

}
