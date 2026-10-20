import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityWakeSettingsTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    final class Driver: GatewayRootDriver {
        struct State {
            var registrations: [PhoneRequestDelivery] = []
            var held: (@Sendable (GatewayRootResponse) -> Void)?
            var holdRegistration = false
            var closes = 0
        }
        let state = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: GatewayRootCall, reply: @escaping @Sendable (GatewayRootResponse) -> Void) {
            do {
                switch call {
                case .hello: reply(.version(3))
                case .synchronize: reply(.synchronized(true))
                case .command(let bytes):
                    switch try GatewayRootCommand.decode(bytes) {
                    case .registerWake(let delivery):
                        let held = state.withLock {
                            $0.registrations.append(delivery)
                            if $0.holdRegistration { $0.held = reply; return true }; return false
                        }
                        if !held { reply(.command(try GatewayRootCommand.reply([.boolean(true)], version: 3))) }
                    case .withdraw: reply(.command(try GatewayRootCommand.reply([.boolean(true)], version: 3)))
                    default: reply(.failed)
                    }
                }
            } catch { reply(.failed) }
        }
        func close() { state.withLock { $0.closes += 1 } }
    }
    final class Fixture: @unchecked Sendable {
        let h: AuthorityPhonePushRegistrationTests.Harness
        let journal: AuthorityJournal
        let capability: AuthorityPhonePushCapability
        let options: AuthorityPhonePushStartupConfiguration
        let request: IssuedRequestPayload
        let starts = Mutex(0), closes = Mutex(0), attempts = Mutex(0), retired = Mutex(false)
        let old = Data(repeating: 71, count: 32), selected = Data(repeating: 72, count: 32)
        init(install: Bool = true, macID: Data = Data(repeating: 1, count: 16),
             accountID: Data = Data(repeating: 2, count: 16)) throws {
            h = try .init(configureGateway: false, gatewayLedgerEnabled: false, macID: macID, accountID: accountID)
            journal = AuthorityJournal(requests: h.owner)
            options = try .init(projectID: "project", senderID: "123", packageName: "dev.remozio.android",
                gatewayReceiptPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                maximumControls: 30, candidateLifetimeMilliseconds: 1000)
            let h = h
            capability = .init(journal: journal, registration: h.registration,
                clock: { .init(epoch: h.clock, milliseconds: 110) }, wall: { 1010 }, makeProvider: { _ in h.provider })
            if install { try capability.install(options, commitDigest: old, verifyCurrent: {}) }
            let draft = ApprovalRequestDraft(contract: try .init(requestKind: .command, wireVersion: 1, schemaVersion: 1),
                requiredFeatures: [], capture: Data([0xa0]),
                actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
                firstObservedAt: .init(epoch: h.clock, milliseconds: 100), deadlineMilliseconds: 5000,
                createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 5900)
            request = try journal.withRequests { try $0.admitFixture(draft, now: .init(epoch: h.clock, milliseconds: 110), receiptTimeMs: nil) }
        }
        deinit { capability.close(); try? journal.close() }
        func change(_ n: UInt8 = 1) throws -> AuthorityPhonePushSettingsChange {
            try .init(revisionDigest: Data(repeating: n, count: 32), previousCommitDigest: old, selectedCommitDigest: selected)
        }
        func state() throws -> ApprovalRequestState {
            try journal.withRequests { try $0.state(requestID: self.request.requestID) }
        }
        func service(_ drivers: [Driver], creationGate: DispatchSemaphore? = nil, binding: GatewaySettingsControlBinding? = nil) throws -> AuthorityWakeService {
            let hints = try AuthorityWakeHintSource(registration: h.registration)
            return try .init(makePublisher: { [self] in
                let index = attempts.withLock { let index = $0; $0 += 1; return index }
                guard index < drivers.count else { throw Denied() }
                if let creationGate { guard creationGate.wait(timeout: .now() + 5) == .success else { throw Denied() } }
                return try AuthorityWakePublisher(journal: journal,
                    channel: GatewayRootChannel(driver: drivers[index]), registration: h.registration, leaseMilliseconds: 1000,
                    clock: { [h] in .init(epoch: h.clock, milliseconds: 110) }, routing: { [h] in
                        var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 100))
                        return router.evaluate(mode: .away, snapshot: PresenceSnapshot(), now: .init(epoch: h.clock, milliseconds: 110))
                    })
            }, hints: hints, interval: 100, startRequests: { [self] in starts.withLock { $0 += 1 } },
                closeRequests: { [self] in closes.withLock { $0 += 1 }; try journal.close() },
                requestsRetired: { [self] in retired.withLock { $0 } }, phonePushCapability: capability, gatewaySettingsBinding: binding)
        }
    }
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw Denied() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testPauseAndRestartKeepTheForegroundOwnerAndItsOriginalRequestDeadline() async throws {
        let f = try Fixture(), first = Driver(), second = Driver(), service = try f.service([first, second]), change = try f.change()
        try await service.start(); try await waitUntil { await service.wakeStatus == .running }
        let before = try f.state(), grant = try XCTUnwrap(first.state.withLock { $0.registrations.first })
        try await service.quiescePhonePushSettings(change, verifyCurrent: {})
        let paused = await service.wakeStatus; XCTAssertEqual(paused, .suspendedForSettings)
        XCTAssertEqual(first.state.withLock { $0.closes }, 1); XCTAssertEqual(f.attempts.withLock { $0 }, 1)
        XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        XCTAssertEqual(try f.state(), before); XCTAssertTrue(try f.journal.validatePeer(f.h.binding)); XCTAssertNil(f.capability.publication)
        try await service.quiescePhonePushSettings(change, verifyCurrent: {})
        let accepted = try await service.acceptPhonePushSettings(change, verifyCurrent: {}); XCTAssertTrue(accepted)
        try await waitUntil { await service.wakeStatus == .running }
        XCTAssertEqual(second.state.withLock { $0.registrations.first }, grant)
        XCTAssertEqual(try f.state(), before); XCTAssertEqual(before.deadlineMilliseconds, 5000); XCTAssertEqual(before.firstObservedAt.epoch, f.h.clock)
        XCTAssertNil(f.capability.publication)
        try await service.installPhonePush(f.options, commitDigest: f.selected, verifyCurrent: {})
        XCTAssertEqual(f.capability.installedCommitDigest, f.selected)
        let retry = try await service.acceptPhonePushSettings(change, verifyCurrent: {}); XCTAssertFalse(retry)
        XCTAssertEqual(f.attempts.withLock { $0 }, 2); XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        try await service.close(); XCTAssertEqual(f.closes.withLock { $0 }, 1)
    }
    func testALateRegistrationReplyCannotPublishAfterTheSettingsBarrier() async throws {
        let f = try Fixture(), first = Driver(), second = Driver(), service = try f.service([first, second]), change = try f.change()
        first.state.withLock { $0.holdRegistration = true }
        try await service.start(); try await waitUntil { first.state.withLock { $0.held != nil } }
        let reply = try XCTUnwrap(first.state.withLock { $0.held }), original = try f.state()
        let grant = try XCTUnwrap(first.state.withLock { $0.registrations.first })
        try await service.quiescePhonePushSettings(change, verifyCurrent: {})
        reply(.command(try GatewayRootCommand.reply([.boolean(true)], version: 3)))
        XCTAssertEqual(try f.state(), original); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        _ = try await service.acceptPhonePushSettings(change, verifyCurrent: {})
        try await waitUntil { await service.wakeStatus == .running }
        XCTAssertEqual(second.state.withLock { $0.registrations.first }, grant)
        let retired = await service.isRetired; XCTAssertFalse(retired)
        try await service.close()
    }
    func testFailedOrCompetingAcceptanceKeepsThePublisherPausedUntilTheSameChangeResumes() async throws {
        let f = try Fixture(), first = Driver(), second = Driver(), service = try f.service([first, second]), change = try f.change()
        try await service.start(); try await waitUntil { await service.wakeStatus == .running }
        try await service.quiescePhonePushSettings(change, verifyCurrent: {})
        do { _ = try await service.acceptPhonePushSettings(f.change(2), verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        do { _ = try await service.acceptPhonePushSettings(change, verifyCurrent: { throw Denied() }); XCTFail() } catch {}
        let paused = await service.wakeStatus; XCTAssertEqual(paused, .suspendedForSettings)
        XCTAssertEqual(f.attempts.withLock { $0 }, 1); XCTAssertEqual(f.closes.withLock { $0 }, 0); XCTAssertNil(f.capability.publication)
        _ = try await service.acceptPhonePushSettings(change, verifyCurrent: {})
        try await waitUntil { await service.wakeStatus == .running }
        try await service.close()
    }
    func testConcurrentShutdownJoinsTheSettingsDrainBeforeClosingTheJournal() async throws {
        let f = try Fixture(), gate = DispatchSemaphore(value: 0), first = Driver()
        let service = try f.service([first], creationGate: gate), change = try f.change()
        defer { gate.signal() }
        try await service.start(); try await waitUntil { f.attempts.withLock { $0 == 1 } }
        let pause = Task { try await service.quiescePhonePushSettings(change, verifyCurrent: {}) }
        try await waitUntil { await service.wakeStatus == .quiescingForSettings }
        let quiescing = await service.wakeStatus; XCTAssertEqual(quiescing, .quiescingForSettings)
        let close = Task { try await service.close() }
        try await waitUntil { await service.wakeStatus == .closed }
        XCTAssertEqual(f.closes.withLock { $0 }, 0); XCTAssertEqual(try f.state().phase, .queued)
        do { _ = try await service.acceptPhonePushSettings(change, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        gate.signal()
        do { try await pause.value; XCTFail("Closed service cannot acknowledge quiescence") } catch {}
        try await close.value; XCTAssertEqual(f.closes.withLock { $0 }, 1); XCTAssertNil(f.capability.publication)
    }
    func testDuplicateQuiescenceWaitsForTheSameDrainAndCannotAdmitADifferentChange() async throws {
        let f = try Fixture(), gate = DispatchSemaphore(value: 0), first = Driver()
        let service = try f.service([first], creationGate: gate), change = try f.change(), checks = Mutex(0), completed = Mutex(0)
        defer { gate.signal() }
        try await service.start(); try await waitUntil { f.attempts.withLock { $0 == 1 } }
        let firstPause = Task { @Sendable in try await service.quiescePhonePushSettings(change, verifyCurrent: {}); completed.withLock { $0 += 1 } }
        try await waitUntil { await service.wakeStatus == .quiescingForSettings }
        let retry = Task { @Sendable in try await service.quiescePhonePushSettings(change, verifyCurrent: { checks.withLock { $0 += 1 } }); completed.withLock { $0 += 1 } }
        try await waitUntil { checks.withLock { $0 } >= 2 }
        XCTAssertEqual(completed.withLock { $0 }, 0)
        do { try await service.quiescePhonePushSettings(f.change(2), verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        gate.signal(); try await firstPause.value; try await retry.value
        XCTAssertEqual(completed.withLock { $0 }, 2); XCTAssertEqual(first.state.withLock { $0.closes }, 1)
        try await service.close(); XCTAssertEqual(f.closes.withLock { $0 }, 1)
    }
    func testARequestRetirementWhilePausedPreventsASettingsRestart() async throws {
        let f = try Fixture(), first = Driver(), service = try f.service([first]), change = try f.change()
        try await service.start(); try await waitUntil { await service.wakeStatus == .running }
        try await service.quiescePhonePushSettings(change, verifyCurrent: {})
        f.retired.withLock { $0 = true }
        let retired = await service.isRetired; XCTAssertTrue(retired)
        do { _ = try await service.acceptPhonePushSettings(change, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        XCTAssertEqual(f.attempts.withLock { $0 }, 1)
        try await service.close()
    }
}
