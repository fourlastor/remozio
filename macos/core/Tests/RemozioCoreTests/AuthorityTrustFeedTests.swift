import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityTrustFeedTests: XCTestCase, @unchecked Sendable {
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        private let lock = NSLock()
        private var bytes: Data
        private var pauseSnapshot = false
        private var pauseValidation = false
        private var snapshotReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var validationReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var invalidated: (@Sendable () -> Void)?
        private var validations = 0
        private var frames = 0
        private var frameReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var version: UInt64 = 1
        let frameSent = XCTestExpectation(description: "held frame")
        var frameCount: Int { lock.withLock { frames } }
        func setVersion(_ value: UInt64) { lock.withLock { version = value } }
        func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            reply(.deliveryVersion(lock.withLock { version }))
        }
        func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { frames += 1; frameReply = reply }
            frameSent.fulfill()
        }
        func finishFrame() {
            let reply = lock.withLock { let value = frameReply; frameReply = nil; return value }
            reply?(.requestFrame(Data()))
        }
        private var discoveries = 0
        private var discoveryReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var discoveryBinding: Data?
        let discoverySent = XCTestExpectation(description: "held discovery")
        var discoveryCount: Int { lock.withLock { discoveries } }
        func discoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            reply(.discoveryVersion(lock.withLock { version }))
        }
        func pendingRequests(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { discoveries += 1; discoveryBinding = binding; discoveryReply = reply }
            discoverySent.fulfill()
        }
        func finishDiscovery() throws {
            let (reply, binding) = lock.withLock {
                let value = (discoveryReply, discoveryBinding); discoveryReply = nil; discoveryBinding = nil; return value
            }
            guard let reply, let binding else { return }
            let peer = try AuthorityTrustCodec.decodeBinding(binding, expectedMacID: Data(repeating: 1, count: 16),
                expectedAccountID: Data(repeating: 2, count: 16))
            reply(.pendingRequests(try AuthorityPendingRequests.encode([Data(repeating: 8, count: 16)], binding: peer)))
        }
        private var exchanges = 0
        private var exchangeReply: (@Sendable (AuthorityXPCReply) -> Void)?
        let exchangeSent = XCTestExpectation(description: "held exchange")
        var exchangeCount: Int { lock.withLock { exchanges } }
        func exchangeVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            reply(.exchangeVersion(lock.withLock { version }))
        }
        func exchange(_ binding: Data, query: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { exchanges += 1; exchangeReply = reply }
            exchangeSent.fulfill()
        }
        func finishExchange() {
            let reply = lock.withLock { let value = exchangeReply; exchangeReply = nil; return value }
            reply?(.exchange(Data()))
        }
        let snapshotSent = XCTestExpectation(description: "held snapshot")
        let validationSent = XCTestExpectation(description: "held validation")
        init(_ trust: DirectApprovalTrust) throws { bytes = try AuthorityTrustCodec.encodeSnapshot(trust) }
        var validationCount: Int { lock.withLock { validations } }
        func replace(_ trust: DirectApprovalTrust) throws { let bytes = try AuthorityTrustCodec.encodeSnapshot(trust); lock.withLock { self.bytes = bytes } }
        func holdSnapshot() { lock.withLock { pauseSnapshot = true } }
        func holdValidation() { lock.withLock { pauseValidation = true } }
        func start(invalidated: @escaping @Sendable () -> Void) { lock.withLock { self.invalidated = invalidated } }
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            let value = lock.withLock { () -> Data? in
                if pauseSnapshot { snapshotReply = reply; return nil }; return bytes
            }
            if let value { reply(.snapshot(value)) } else { snapshotSent.fulfill() }
        }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            let held = lock.withLock {
                validations += 1
                if pauseValidation { validationReply = reply; return true }; return false
            }
            if held { validationSent.fulfill() } else { reply(.validation(true)) }
        }
        func finishSnapshot() {
            let value = lock.withLock { (snapshotReply, bytes) }; value.0?(.snapshot(value.1))
        }
        func finishValidation(_ allowed: Bool = true) {
            let reply = lock.withLock { pauseValidation = false; let value = validationReply; validationReply = nil; return value }
            reply?(.validation(allowed))
        }
        func interrupt() { lock.withLock { invalidated }?() }
        private var closedCalls = 0
        var closeCount: Int { lock.withLock { closedCalls } }
        private var registrationCapability: UInt64? = 0
        private var registrationReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var registrationFrame: Data?
        private var registrationCalls = 0
        let registrationSent = XCTestExpectation(description: "held registration")
        var registrationCount: Int { lock.withLock { registrationCalls } }
        func setRegistrationVersion(_ value: UInt64?) { lock.withLock { registrationCapability = value } }
        func registrationVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            if let version = lock.withLock({ registrationCapability }) { reply(.registrationVersion(version)) }
            else { reply(.failed) }
        }
        func registration(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { registrationCalls += 1; registrationFrame = frame; registrationReply = reply }
            registrationSent.fulfill()
        }
        func finishRegistration() throws {
            let value = lock.withLock { () -> (Data?, (@Sendable (AuthorityXPCReply) -> Void)?) in
                let value = (registrationFrame, registrationReply); registrationFrame = nil; registrationReply = nil; return value
            }
            guard let frame = value.0, let reply = value.1 else { return }
            let request = try PhonePushRegistrationFrame.decode(frame)
            reply(.registration(try PhonePushRegistrationFrame.outcome(correlationID: request.correlationID, outcome: .proofCommitted).encode()))
        }
        private var recoveryCapability: UInt64? = 0
        private var recoveryReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var recoveryFrame: Data?
        private var recoveryCalls = 0
        let recoverySent = XCTestExpectation(description: "held recovery")
        var recoveryCount: Int { lock.withLock { recoveryCalls } }
        func setRecoveryVersion(_ value: UInt64?) { lock.withLock { recoveryCapability = value } }
        func recoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            if let version = lock.withLock({ recoveryCapability }) { reply(.recoveryVersion(version)) }
            else { reply(.failed) }
        }
        func recovery(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { recoveryCalls += 1; recoveryFrame = frame; recoveryReply = reply }
            recoverySent.fulfill()
        }
        func finishRecovery() throws {
            let value = lock.withLock { () -> (Data?, (@Sendable (AuthorityXPCReply) -> Void)?) in
                let value = (recoveryFrame, recoveryReply); recoveryFrame = nil; recoveryReply = nil; return value
            }
            guard let frame = value.0, let reply = value.1 else { return }
            let request = try PhonePushRecoveryFrame.decode(frame)
            reply(.recovery(try PhonePushRecoveryFrame.outcome(correlationID: request.correlationID, failure: .unavailable).encode()))
        }
        private var actorCloseGate: DispatchSemaphore?
        let actorCloseEntered = XCTestExpectation(description: "held channel actor cleanup")
        func holdActorClose() { lock.withLock { actorCloseGate = DispatchSemaphore(value: 0) } }
        func releaseActorClose() { lock.withLock { actorCloseGate }?.signal() }
        func close() {
            let gate = lock.withLock { closedCalls += 1; return closedCalls == 2 ? actorCloseGate : nil }
            if let gate { actorCloseEntered.fulfill(); _ = gate.wait(timeout: .now() + 5) }
        }

    }
    private final class Listener: OwnedDirectListener, @unchecked Sendable {
        private let lock = NSLock()
        private var closed = false
        var isClosed: Bool { lock.withLock { closed } }
        func start() throws { }
        func close() { lock.withLock { closed = true } }
        func closeAndWait() async { close() }
    }
    private final class Listeners: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [Listener] = []
        private var currentGeneration: UUID?
        var generation: UUID? { lock.withLock { currentGeneration } }
        var values: [Listener] { lock.withLock { storage } }
        func make(_ generation: UUID) -> Listener { lock.withLock { currentGeneration = generation; let value = Listener(); storage.append(value); return value } }
    }
    private final class RegistrationFactory: @unchecked Sendable {
        private let lock = NSLock()
        private var calls = 0
        let primary: Driver
        let auxiliary: Driver
        init(primary: Driver, auxiliary: Driver) { self.primary = primary; self.auxiliary = auxiliary }
        var count: Int { lock.withLock { calls } }
        func make(_ onClose: @escaping @Sendable () -> Void) -> AuthorityXPCChannel {
            let selected = lock.withLock { calls += 1; return calls == 1 ? primary : auxiliary }
            return AuthorityXPCChannel(driver: selected, onClose: onClose)
        }
    }
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private func trust(empty: Bool = false) throws -> DirectApprovalTrust {
        let peer = try DirectApprovalPeer(scope: ChannelScope(macID: mac, accountID: account,
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, requests: [], auditVersions: [], maximumPayloadBytes: 1024)
        return DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: empty ? [] : [peer])
    }
    private func feed(_ driver: Driver, maximumWaiting: Int = 8) -> AuthorityTrustFeed {
        AuthorityTrustFeed(macID: mac, accountID: account, maximumWaiting: maximumWaiting,
            factory: { AuthorityXPCChannel(driver: driver, onClose: $0) })
    }
    private func host(_ listeners: Listeners) -> DirectApprovalTransportHost {
        DirectApprovalTransportHost(macID: mac, accountID: account, factory: { generation, _, _, _ in listeners.make(generation) }, validatePeer: { _, _ in })
    }
    private func registrationOffer() throws -> PhonePushRegistrationFrame {
        try .offer(correlationID: Data(repeating: 9, count: 16), offer: PhonePushTokenOffer(token: "synthetic-token", projectID: "project", senderID: "123", packageName: "dev.remozio.android"))
    }
    func testUnsupportedRegistrationKeepsPrimaryApprovalTrustAlive() async throws {
        let capabilities: [UInt64?] = [0, nil]
        for capability in capabilities {
            let trust = try trust(), primary = try Driver(trust), auxiliary = try Driver(trust)
            auxiliary.setRegistrationVersion(capability)
            let factory = RegistrationFactory(primary: primary, auxiliary: auxiliary)
            let feed = AuthorityTrustFeed(macID: mac, accountID: account, factory: { factory.make($0) })
            let listeners = Listeners(), host = host(listeners)
            try await feed.start(host: host); try await host.start()
            do { _ = try await feed.phonePushRegistration(trust.peers[0], revision: trust.revision, frame: registrationOffer()); XCTFail("Expected optional refusal") } catch { }
            try await feed.validatePeer(trust.peers[0], revision: trust.revision)
            XCTAssertEqual(primary.closeCount, 0); XCTAssertEqual(auxiliary.registrationCount, 0)
            XCTAssertFalse(try XCTUnwrap(listeners.values.first).isClosed)
            XCTAssertEqual(factory.count, 2)
            await feed.close(); await host.close()
        }
    }
    func testRegistrationUsesSeparateRPCAndReturnsOnlyForTheCurrentAuthorityLease() async throws {
        let trust = try trust(), primary = try Driver(trust), auxiliary = try Driver(trust)
        auxiliary.setRegistrationVersion(1)
        let factory = RegistrationFactory(primary: primary, auxiliary: auxiliary)
        let feed = AuthorityTrustFeed(macID: mac, accountID: account, factory: { factory.make($0) })
        let listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let request = try registrationOffer()
        let pending = Task { try await feed.phonePushRegistration(trust.peers[0], revision: trust.revision, frame: request) }
        await fulfillment(of: [auxiliary.registrationSent], timeout: 2)
        try auxiliary.finishRegistration()
        guard case .outcome(let correlation, let result) = try await pending.value else { return XCTFail("Missing status") }
        XCTAssertEqual(correlation, request.correlationID); XCTAssertEqual(result, .proofCommitted)
        XCTAssertEqual(primary.registrationCount, 0); XCTAssertEqual(auxiliary.registrationCount, 1); XCTAssertEqual(factory.count, 2)
        try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        await feed.close(); await host.close()
    }
    func testPrimaryInterruptionDiscardsLateRegistrationReply() async throws {
        let trust = try trust(), primary = try Driver(trust), auxiliary = try Driver(trust)
        auxiliary.setRegistrationVersion(1)
        let factory = RegistrationFactory(primary: primary, auxiliary: auxiliary)
        let feed = AuthorityTrustFeed(macID: mac, accountID: account, factory: { factory.make($0) })
        let listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let request = try registrationOffer()
        let pending = Task { try await feed.phonePushRegistration(trust.peers[0], revision: trust.revision, frame: request) }
        await fulfillment(of: [auxiliary.registrationSent], timeout: 2)
        primary.interrupt(); try auxiliary.finishRegistration()
        do { _ = try await pending.value; XCTFail("Retired authority returned registration success") } catch { }
        do { try await feed.validatePeer(trust.peers[0], revision: trust.revision); XCTFail("Retired primary revived") } catch { }
        XCTAssertEqual(auxiliary.registrationCount, 1); XCTAssertGreaterThan(auxiliary.closeCount, 0)
        await feed.close(); await host.close()
    }
    func testCancelledRegistrationRetiresOnlyItsOptionalLink() async throws {
        let trust = try trust(), primary = try Driver(trust), auxiliary = try Driver(trust)
        auxiliary.setRegistrationVersion(1)
        let factory = RegistrationFactory(primary: primary, auxiliary: auxiliary)
        let feed = AuthorityTrustFeed(macID: mac, accountID: account, factory: { factory.make($0) })
        let listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let request = try registrationOffer()
        let pending = Task { try await feed.phonePushRegistration(trust.peers[0], revision: trust.revision, frame: request) }
        await fulfillment(of: [auxiliary.registrationSent], timeout: 2)
        pending.cancel(); try auxiliary.finishRegistration()
        do { _ = try await pending.value; XCTFail("Cancelled registration returned success") } catch { }
        try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        XCTAssertEqual(auxiliary.registrationCount, 1); XCTAssertEqual(primary.closeCount, 0)
        await feed.close(); await host.close()
    }
    private func recoveryOffer() throws -> PhonePushRecoveryFrame {
        try .resume(correlationID: Data(repeating: 9, count: 16), offer: PhonePushTokenOffer(token: "synthetic-token", projectID: "project", senderID: "123", packageName: "dev.remozio.android"))
    }
    func testUnsupportedRecoveryKeepsPrimaryApprovalTrustAlive() async throws {
        let capabilities: [UInt64?] = [0, nil]
        for capability in capabilities {
            let trust = try trust(), primary = try Driver(trust), auxiliary = try Driver(trust)
            auxiliary.setRecoveryVersion(capability)
            let factory = RegistrationFactory(primary: primary, auxiliary: auxiliary)
            let feed = AuthorityTrustFeed(macID: mac, accountID: account, factory: { factory.make($0) })
            let listeners = Listeners(), host = host(listeners)
            try await feed.start(host: host); try await host.start()
            do { _ = try await feed.phonePushRecovery(trust.peers[0], revision: trust.revision, frame: recoveryOffer()); XCTFail("Expected optional refusal") } catch { }
            try await feed.validatePeer(trust.peers[0], revision: trust.revision)
            XCTAssertEqual(primary.closeCount, 0); XCTAssertEqual(auxiliary.recoveryCount, 0)
            XCTAssertFalse(try XCTUnwrap(listeners.values.first).isClosed)
            XCTAssertEqual(factory.count, 2)
            await feed.close(); await host.close()
        }
    }
    func testRecoveryUsesSeparateRPCAndReturnsOnlyForTheCurrentAuthorityLease() async throws {
        let trust = try trust(), primary = try Driver(trust), auxiliary = try Driver(trust)
        auxiliary.setRecoveryVersion(2)
        let factory = RegistrationFactory(primary: primary, auxiliary: auxiliary)
        let feed = AuthorityTrustFeed(macID: mac, accountID: account, factory: { factory.make($0) })
        let listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let request = try recoveryOffer()
        let pending = Task { try await feed.phonePushRecovery(trust.peers[0], revision: trust.revision, frame: request) }
        await fulfillment(of: [auxiliary.recoverySent], timeout: 2)
        try auxiliary.finishRecovery()
        guard case .outcome(let correlation, let result) = try await pending.value else { return XCTFail("Missing status") }
        XCTAssertEqual(correlation, request.correlationID); XCTAssertEqual(result, .unavailable)
        XCTAssertEqual(primary.recoveryCount, 0); XCTAssertEqual(auxiliary.recoveryCount, 1); XCTAssertEqual(factory.count, 2)
        try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        await feed.close(); await host.close()
    }
    func testPrimaryInterruptionDiscardsLateRecoveryReply() async throws {
        let trust = try trust(), primary = try Driver(trust), auxiliary = try Driver(trust)
        auxiliary.setRecoveryVersion(2)
        let factory = RegistrationFactory(primary: primary, auxiliary: auxiliary)
        let feed = AuthorityTrustFeed(macID: mac, accountID: account, factory: { factory.make($0) })
        let listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let request = try recoveryOffer()
        let pending = Task { try await feed.phonePushRecovery(trust.peers[0], revision: trust.revision, frame: request) }
        await fulfillment(of: [auxiliary.recoverySent], timeout: 2)
        primary.interrupt(); try auxiliary.finishRecovery()
        do { _ = try await pending.value; XCTFail("Retired authority returned recovery success") } catch { }
        do { try await feed.validatePeer(trust.peers[0], revision: trust.revision); XCTFail("Retired primary revived") } catch { }
        XCTAssertEqual(auxiliary.recoveryCount, 1); XCTAssertGreaterThan(auxiliary.closeCount, 0)
        await feed.close(); await host.close()
    }
    func testCancelledRecoveryRetiresOnlyItsOptionalLink() async throws {
        let trust = try trust(), primary = try Driver(trust), auxiliary = try Driver(trust)
        auxiliary.setRecoveryVersion(2)
        let factory = RegistrationFactory(primary: primary, auxiliary: auxiliary)
        let feed = AuthorityTrustFeed(macID: mac, accountID: account, factory: { factory.make($0) })
        let listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let request = try recoveryOffer()
        let pending = Task { try await feed.phonePushRecovery(trust.peers[0], revision: trust.revision, frame: request) }
        await fulfillment(of: [auxiliary.recoverySent], timeout: 2)
        pending.cancel(); try auxiliary.finishRecovery()
        do { _ = try await pending.value; XCTFail("Cancelled recovery returned success") } catch { }
        try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        XCTAssertEqual(auxiliary.recoveryCount, 1); XCTAssertEqual(primary.closeCount, 0)
        await feed.close(); await host.close()
    }
    func testAuxiliaryInterruptionDiscardsRecoveryReplyWithoutRetiringPrimary() async throws {
        let trust = try trust(), primary = try Driver(trust), auxiliary = try Driver(trust)
        auxiliary.setRecoveryVersion(2)
        let factory = RegistrationFactory(primary: primary, auxiliary: auxiliary)
        let feed = AuthorityTrustFeed(macID: mac, accountID: account, factory: { factory.make($0) })
        let listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let request = try recoveryOffer()
        let pending = Task { try await feed.phonePushRecovery(trust.peers[0], revision: trust.revision, frame: request) }
        await fulfillment(of: [auxiliary.recoverySent], timeout: 2)
        auxiliary.interrupt(); try auxiliary.finishRecovery()
        do { _ = try await pending.value; XCTFail("Retired optional connection returned a result") } catch {}
        try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        XCTAssertEqual(primary.closeCount, 0); XCTAssertEqual(auxiliary.recoveryCount, 1)
        await feed.close(); await host.close()
    }
    func testRecoveryPreflightDoesNotSendPrivateFieldsOrOpenRepeatedConnections() async throws {
        let trust = try trust(), primary = try Driver(trust), auxiliary = try Driver(trust)
        auxiliary.setRecoveryVersion(2)
        let factory = RegistrationFactory(primary: primary, auxiliary: auxiliary)
        let feed = AuthorityTrustFeed(macID: mac, accountID: account, factory: { factory.make($0) })
        let listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        try await feed.requirePhonePushRecoverySupport(); try await feed.requirePhonePushRecoverySupport()
        XCTAssertEqual(auxiliary.recoveryCount, 0); XCTAssertEqual(primary.recoveryCount, 0)
        XCTAssertEqual(factory.count, 2)
        try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        await feed.close(); await host.close()
    }
    func testServiceStartsAfterTrustAndRetiresOnClose() async throws {
        let listeners = Listeners(), host = host(listeners), feed = feed(try Driver(trust()))
        let service = DirectApprovalTransportService(feed: feed, host: host)
        try await service.start()
        XCTAssertEqual(listeners.values.count, 1)
        do { try await service.start(); XCTFail("Duplicate start accepted") } catch { }
        await service.close(); await service.close()
        XCTAssertTrue(try XCTUnwrap(listeners.values.first).isClosed)
        let state = await service.state; XCTAssertEqual(state, .stopped)
        do { try await service.start(); XCTFail("Closed service restarted") } catch { }
    }
    func testServiceCloseBeforeStartNeverOpensListener() async throws {
        let listeners = Listeners(), host = host(listeners), feed = feed(try Driver(trust()))
        let service = DirectApprovalTransportService(feed: feed, host: host)
        await service.close()
        do { try await service.start(); XCTFail("Closed service started") } catch { }
        XCTAssertTrue(listeners.values.isEmpty)
    }
    func testServiceCloseDuringHandshakePreventsLateListener() async throws {
        let driver = try Driver(trust()), listeners = Listeners(), host = host(listeners), feed = feed(driver)
        driver.holdSnapshot()
        let service = DirectApprovalTransportService(feed: feed, host: host)
        let starting = Task { try await service.start() }
        await fulfillment(of: [driver.snapshotSent], timeout: 2)
        await service.close(); driver.finishSnapshot()
        do { try await starting.value; XCTFail("Closed startup succeeded") } catch { }
        XCTAssertTrue(listeners.values.isEmpty)
        let state = await service.state; XCTAssertEqual(state, .stopped)
    }
    func testServiceRejectsWrongScopeBeforeOpeningListener() async throws {
        let listeners = Listeners(), host = host(listeners)
        let driver = try Driver(trust())
        let feed = AuthorityTrustFeed(macID: Data(repeating: 9, count: 16), accountID: account,
            factory: { AuthorityXPCChannel(driver: driver, onClose: $0) })
        let service = DirectApprovalTransportService(feed: feed, host: host)
        do { try await service.start(); XCTFail("Wrong scope accepted") } catch { }
        XCTAssertTrue(listeners.values.isEmpty)
        let state = await service.state; XCTAssertEqual(state, .stopped)
        do { try await service.start(); XCTFail("Failed service restarted") } catch { }
    }
    func testUnchangedRefreshKeepsListenerAndRevocationStopsIt() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let first = try XCTUnwrap(listeners.values.first)
        try await feed.refresh(); try await feed.refresh()
        XCTAssertEqual(listeners.values.count, 1); XCTAssertFalse(first.isClosed)
        try driver.replace(self.trust(empty: true)); try await feed.refresh()
        XCTAssertTrue(first.isClosed)
        let state = await host.state; XCTAssertEqual(state, .noEligiblePhones)
        await feed.close(); await host.close()
    }
    func testOldReplyAndDisconnectCannotReplaceNewIncarnation() async throws {
        let firstDriver = try Driver(trust()), old = feed(firstDriver), listeners = Listeners(), host = host(listeners)
        try await old.start(host: host); try await host.start()
        firstDriver.holdSnapshot()
        let pending = Task { try await old.refresh() }
        await fulfillment(of: [firstDriver.snapshotSent], timeout: 2)
        let second = feed(try Driver(trust()))
        try await second.start(host: host)
        let current = try XCTUnwrap(listeners.values.last)
        XCTAssertEqual(listeners.values.count, 2)
        firstDriver.finishSnapshot()
        do { try await pending.value; XCTFail("Retired snapshot accepted") } catch { }
        await old.close()
        XCTAssertFalse(current.isClosed)
        try await second.refresh(); XCTAssertEqual(listeners.values.count, 2)
        await second.close(); XCTAssertTrue(current.isClosed); await host.close()
    }
    func testCancelledQueuedValidationDoesNotCancelActiveOperation() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), host = host(Listeners())
        try await feed.start(host: host)
        driver.holdValidation()
        let first = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        await fulfillment(of: [driver.validationSent], timeout: 2)
        let cancelled = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        try await waitForQueue(feed, count: 1)
        cancelled.cancel()
        do { try await cancelled.value; XCTFail("Cancellation ignored") } catch { }
        let next = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        driver.finishValidation()
        try await first.value; try await next.value
        XCTAssertEqual(driver.validationCount, 2)
        await feed.close(); await host.close()
    }
    func testCapacityRejectsExtraWorkAndDenialKeepsConnection() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver, maximumWaiting: 0), host = host(Listeners())
        try await feed.start(host: host); driver.holdValidation()
        let first = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        await fulfillment(of: [driver.validationSent], timeout: 2)
        do { try await feed.validatePeer(trust.peers[0], revision: trust.revision); XCTFail("Capacity ignored") } catch { }
        driver.finishValidation(false)
        do { try await first.value; XCTFail("Denial ignored") } catch { }
        try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        XCTAssertEqual(driver.validationCount, 2)
        await feed.close(); await host.close()
    }
    func testServiceRejectsFrameWhenSessionIsReplacedDuringFetch() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        let service = DirectApprovalTransportService(feed: feed, host: host)
        try await service.start()
        let session = try await host.admit(trust.peers[0], generation: XCTUnwrap(listeners.generation))
        let pending = Task { try await service.requestFrame(for: session, requestID: Data(repeating: 8, count: 16)) }
        await fulfillment(of: [driver.frameSent], timeout: 2)
        try await host.replaceTrust(self.trust(empty: true))
        driver.finishFrame()
        do { _ = try await pending.value; XCTFail("Retired phone session received frame") } catch DirectHostError.staleSession { }
        await service.close()
    }
    func testServiceReturnsAbsenceOnlyForCurrentSession() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        let service = DirectApprovalTransportService(feed: feed, host: host)
        try await service.start()
        let session = try await host.admit(trust.peers[0], generation: XCTUnwrap(listeners.generation))
        let pending = Task { try await service.requestFrame(for: session, requestID: Data(repeating: 8, count: 16)) }
        await fulfillment(of: [driver.frameSent], timeout: 2)
        driver.finishFrame()
        let frame = try await pending.value; XCTAssertNil(frame)
        await service.close()
        do { _ = try await service.requestFrame(for: session, requestID: Data(repeating: 8, count: 16)); XCTFail("Closed service fetched") }
        catch DirectHostError.stopped { }
        XCTAssertEqual(driver.frameCount, 1)
    }
    func testFrameRetrievalSerializesWithValidationAndCancellation() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), host = host(Listeners())
        try await feed.start(host: host)
        let first = Task { try await feed.requestFrame(trust.peers[0], revision: trust.revision,
            requestID: Data(repeating: 8, count: 16)) }
        await fulfillment(of: [driver.frameSent], timeout: 2)
        let cancelled = Task { try await feed.requestFrame(trust.peers[0], revision: trust.revision,
            requestID: Data(repeating: 9, count: 16)) }
        try await waitForQueue(feed, count: 1)
        cancelled.cancel()
        do { _ = try await cancelled.value; XCTFail("Cancelled fetch completed") } catch { }
        let validation = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        try await waitForQueue(feed, count: 1)
        XCTAssertEqual(driver.validationCount, 0)
        driver.finishFrame()
        let frame = try await first.value; XCTAssertNil(frame)
        try await validation.value
        XCTAssertEqual(driver.frameCount, 1); XCTAssertEqual(driver.validationCount, 1)
        await feed.close(); await host.close()
    }
    func testUnsupportedFramesPreserveCommonTrustOperations() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), host = host(Listeners())
        driver.setVersion(0); try await feed.start(host: host)
        do {
            _ = try await feed.requestFrame(trust.peers[0], revision: trust.revision, requestID: Data(repeating: 8, count: 16))
            XCTFail("Unsupported delivery accepted")
        } catch AuthorityXPCError.unsupportedRequestDelivery { }
        XCTAssertEqual(driver.frameCount, 0)
        try await feed.refresh(); try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        await feed.close(); await host.close()
    }
    func testDisconnectRejectsLateFrameReply() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let pending = Task { try await feed.requestFrame(trust.peers[0], revision: trust.revision,
            requestID: Data(repeating: 8, count: 16)) }
        await fulfillment(of: [driver.frameSent], timeout: 2)
        driver.interrupt(); driver.finishFrame()
        do { _ = try await pending.value; XCTFail("Disconnected fetch completed") } catch { }
        await feed.close()
        XCTAssertTrue(try XCTUnwrap(listeners.values.last).isClosed)
        await host.close()
    }
    func testServiceRejectsDiscoveryWhenSessionIsReplacedDuringFetch() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        let service = DirectApprovalTransportService(feed: feed, host: host)
        try await service.start()
        let session = try await host.admit(trust.peers[0], generation: XCTUnwrap(listeners.generation))
        let pending = Task { try await service.pendingRequestIDs(for: session) }
        await fulfillment(of: [driver.discoverySent], timeout: 2)
        try await host.replaceTrust(self.trust(empty: true))
        try driver.finishDiscovery()
        do { _ = try await pending.value; XCTFail("Retired phone session received discovery") } catch DirectHostError.staleSession { }
        await service.close()
    }
    func testServiceReturnsDiscoveryOnlyForCurrentSession() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        let service = DirectApprovalTransportService(feed: feed, host: host)
        try await service.start()
        let session = try await host.admit(trust.peers[0], generation: XCTUnwrap(listeners.generation))
        let pending = Task { try await service.pendingRequestIDs(for: session) }
        await fulfillment(of: [driver.discoverySent], timeout: 2)
        try driver.finishDiscovery()
        let ids = try await pending.value; XCTAssertEqual(ids, [Data(repeating: 8, count: 16)])
        await service.close()
        do { _ = try await service.pendingRequestIDs(for: session); XCTFail("Closed service fetched") }
        catch DirectHostError.stopped { }
        XCTAssertEqual(driver.discoveryCount, 1)
    }
    func testDiscoveryRetrievalSerializesWithValidationAndCancellation() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), host = host(Listeners())
        try await feed.start(host: host)
        let first = Task { try await feed.pendingRequestIDs(trust.peers[0], revision: trust.revision) }
        await fulfillment(of: [driver.discoverySent], timeout: 2)
        let cancelled = Task { try await feed.pendingRequestIDs(trust.peers[0], revision: trust.revision) }
        try await waitForQueue(feed, count: 1)
        cancelled.cancel()
        do { _ = try await cancelled.value; XCTFail("Cancelled fetch completed") } catch { }
        let validation = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        try await waitForQueue(feed, count: 1)
        XCTAssertEqual(driver.validationCount, 0)
        try driver.finishDiscovery()
        let ids = try await first.value; XCTAssertEqual(ids, [Data(repeating: 8, count: 16)])
        try await validation.value
        XCTAssertEqual(driver.discoveryCount, 1); XCTAssertEqual(driver.validationCount, 1)
        await feed.close(); await host.close()
    }
    func testUnsupportedDiscoveryPreserveCommonTrustOperations() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), host = host(Listeners())
        driver.setVersion(0); try await feed.start(host: host)
        do {
            _ = try await feed.pendingRequestIDs(trust.peers[0], revision: trust.revision)
            XCTFail("Unsupported delivery accepted")
        } catch AuthorityXPCError.unsupportedRequestDiscovery { }
        XCTAssertEqual(driver.discoveryCount, 0)
        try await feed.refresh(); try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        await feed.close(); await host.close()
    }
    func testDisconnectRejectsLateDiscoveryReply() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let pending = Task { try await feed.pendingRequestIDs(trust.peers[0], revision: trust.revision) }
        await fulfillment(of: [driver.discoverySent], timeout: 2)
        driver.interrupt(); try driver.finishDiscovery()
        do { _ = try await pending.value; XCTFail("Disconnected discovery completed") } catch { }
        await feed.close()
        XCTAssertTrue(try XCTUnwrap(listeners.values.last).isClosed)
        await host.close()
    }
    func testServiceRejectsExchangeReplyAfterSessionReplacement() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        let service = DirectApprovalTransportService(feed: feed, host: host)
        try await service.start()
        let session = try await host.admit(trust.peers[0], generation: XCTUnwrap(listeners.generation))
        let pending = Task { try await service.exchangeRequest(for: session, requestID: Data(repeating: 8, count: 16)) }
        await fulfillment(of: [driver.exchangeSent], timeout: 2)
        try await host.replaceTrust(self.trust(empty: true)); driver.finishExchange()
        do { _ = try await pending.value; XCTFail("Retired session received status") } catch DirectHostError.staleSession {}
        await service.close()
    }
    func testExchangeUsesOrderedQueueAndDoesNotSendCancelledDecision() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), host = host(Listeners())
        try await feed.start(host: host)
        let first = Task { try await feed.exchangeRequest(trust.peers[0], revision: trust.revision,
            requestID: Data(repeating: 8, count: 16)) }
        await fulfillment(of: [driver.exchangeSent], timeout: 2)
        let cancelled = Task { try await feed.exchangeRequest(trust.peers[0], revision: trust.revision,
            requestID: Data(repeating: 8, count: 16), decisionFrame: Data([1])) }
        try await waitForQueue(feed, count: 1); cancelled.cancel()
        do { _ = try await cancelled.value; XCTFail("Cancelled decision sent") } catch {}
        driver.finishExchange(); let status = try await first.value; XCTAssertNil(status)
        XCTAssertEqual(driver.exchangeCount, 1)
        try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        await feed.close(); await host.close()
    }
    func testUnsupportedExchangeKeepsTrustUsableAndDisconnectRejectsLateReply() async throws {
        for unsupported in [false, true] {
            let trust = try trust(), driver = try Driver(trust), feed = feed(driver), host = host(Listeners())
            if unsupported { driver.setVersion(0) }
            try await feed.start(host: host)
            if unsupported {
                do { _ = try await feed.exchangeRequest(trust.peers[0], revision: trust.revision,
                    requestID: Data(repeating: 8, count: 16)); XCTFail() } catch AuthorityXPCError.unsupportedRequestExchange {}
                try await feed.refresh(); XCTAssertEqual(driver.exchangeCount, 0)
            } else {
                let pending = Task { try await feed.exchangeRequest(trust.peers[0], revision: trust.revision,
                    requestID: Data(repeating: 8, count: 16)) }
                await fulfillment(of: [driver.exchangeSent], timeout: 2)
                driver.interrupt(); driver.finishExchange()
                do { _ = try await pending.value; XCTFail("Disconnected exchange completed") } catch {}
            }
            await feed.close(); await host.close()
        }
    }
    private func waitForQueue(_ feed: AuthorityTrustFeed, count: Int) async throws {
        let deadline = ContinuousClock.now + .seconds(2)
        while await feed.waitingOperationCount != count {
            guard ContinuousClock.now < deadline else { XCTFail("Queue did not reach expected count"); return }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    func testDueRefreshRunsBeforeQueuedValidationAndTicksCoalesce() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start(); driver.holdValidation()
        let first = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        await fulfillment(of: [driver.validationSent], timeout: 2)
        let queued = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        try await waitForQueue(feed, count: 1)
        try driver.replace(self.trust(empty: true)); driver.holdSnapshot()
        await feed.scheduleRefresh(); await feed.scheduleRefresh()
        driver.finishValidation(); try await first.value
        await fulfillment(of: [driver.snapshotSent], timeout: 2)
        XCTAssertEqual(driver.validationCount, 1)
        await feed.scheduleRefresh(); await feed.scheduleRefresh()
        driver.finishSnapshot(); try await queued.value
        XCTAssertEqual(driver.validationCount, 2)
        XCTAssertTrue(try XCTUnwrap(listeners.values.last).isClosed)
        let state = await host.state; XCTAssertEqual(state, .noEligiblePhones)
        await feed.close(); await host.close()
    }
    func testJoinedCloseWaitsForStartupManualRefreshValidationAndQueuedOperations() async throws {
        for operation in ["startup", "refresh", "validation", "queued"] {
            let trust = try trust(), driver = try Driver(trust), feed = feed(driver), host = host(Listeners())
            if operation != "startup" { try await feed.start(host: host) }
            if operation == "startup" || operation == "refresh" { driver.holdSnapshot() }
            else { driver.holdValidation() }
            driver.holdActorClose()
            defer { driver.releaseActorClose() }
            let pending = Task { @Sendable in
                if operation == "startup" { try await feed.start(host: host) }
                else if operation == "refresh" { try await feed.refresh() }
                else { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
            }
            let sent = operation == "startup" || operation == "refresh" ? driver.snapshotSent : driver.validationSent
            await fulfillment(of: [sent], timeout: 2)
            var queued: Task<Void, any Error>?
            if operation == "queued" {
                queued = Task { @Sendable in try await feed.refresh() }
                try await waitForQueue(feed, count: 1)
            }
            let finished = Mutex(false)
            let close = Task { @Sendable in await feed.closeAndWait(); finished.withLock { $0 = true } }
            close.cancel()
            await fulfillment(of: [driver.actorCloseEntered], timeout: 2)
            try await Task.sleep(for: .milliseconds(20))
            XCTAssertFalse(finished.withLock { $0 }, "Joined close returned before the \(operation) operation could resume")
            driver.releaseActorClose(); await close.value
            do { try await pending.value; XCTFail("A closed feed operation succeeded") } catch { }
            if let queued { do { try await queued.value; XCTFail("Queued work survived close") } catch { } }
            await host.close()
        }
    }
    func testLossDuringValidationClearsHostAndRejectsLateAllow() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start(); driver.holdValidation()
        let pending = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        await fulfillment(of: [driver.validationSent], timeout: 2)
        driver.interrupt(); driver.finishValidation()
        do { try await pending.value; XCTFail("Late allow accepted") } catch { }
        await feed.close()
        XCTAssertTrue(try XCTUnwrap(listeners.values.last).isClosed)
        do { try await host.start(); XCTFail("Disconnected host restarted") } catch { }
        await host.close()
    }
}
