import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class DirectApprovalRequestDeliveryTests: XCTestCase, @unchecked Sendable {
    private static func id(_ value: UInt8) -> Data { Data(repeating: value, count: 16) }
    private static func capability(features: Set<UInt64> = []) throws -> ChannelRequestCapability {
        try .init(kind: 0, wireVersion: 1, schemaVersion: 1, features: features)
    }
    private static func scope(phone: UInt8 = 3) throws -> ChannelScope {
        try .init(macID: id(1), accountID: id(2), phoneID: id(phone), enrollmentEpoch: id(4))
    }
    private static func frame(_ request: UInt8, features: Set<UInt64> = [], bodyBytes: Int? = nil, signingKey: P256.Signing.PrivateKey? = nil) throws -> (Data, P256.Signing.PublicKey) {
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 12, maxItems: 256)
        func payload(_ capture: Data) throws -> IssuedRequestPayload {
            try IssuedRequestPayload(contract: .init(requestKind: .command, wireVersion: 1, schemaVersion: 1),
                macID: id(1), accountID: id(2), requestID: id(request), challenge: Data(repeating: 9, count: 32),
                requiredFeatures: features, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 2000,
                canonicalCapture: capture, permittedActions: [.init(choice: .execute, scope: .currentRequest)],
                bodyLimits: limits, captureLimits: limits)
        }
        var requestPayload = try payload(Data([0xa0]))
        if let bodyBytes {
            var found = false
            for padding in 0..<bodyBytes {
                let capture = try DeterministicCBOR.encode(.map([0: .bytes(Data(count: padding))]), limits: limits)
                let candidate = try payload(capture)
                if try candidate.encode(limits: limits).count == bodyBytes {
                    requestPayload = candidate; found = true; break
                }
            }
            guard found else { throw ApprovalChannelError.invalidInput }
        }
        let payload = requestPayload
        let body = try payload.encode(limits: limits), key = signingKey ?? P256.Signing.PrivateKey()
        let input = try SigningInput.make(wireVersion: 1, messageType: .request, purpose: .issuedRequest,
            canonicalPayload: body, payloadLimits: limits, inputLimits: limits)
        let bytes = try ApprovalMessage(wireVersion: 1, type: .request, purpose: .issuedRequest, body: body,
            signature: key.signature(for: input).rawRepresentation).encode(maximumBodyBytes: 3968)
        return (bytes, key.publicKey)
    }
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        private let lock = NSLock()
        let trust: DirectApprovalTrust
        private var ids: [Data]
        private var frames: [Data: Data]
        private var statuses: [Data: Data]
        private var decisions: [Data: Data]
        let exchangeSupported: Bool
        private var exchanges: [AuthorityRequestExchange.Query] = []
        private var exchangeHeld: (@Sendable (AuthorityXPCReply) -> Void)?
        private var holdExchangeReply = false
        let exchanged = XCTestExpectation(description: "exchange held")
        let discovered = XCTestExpectation(description: "first discovery")
        private var held: (@Sendable (AuthorityXPCReply) -> Void)?
        private var hold = false
        private var queries: [Data] = []
        private var discoveries = 0
        var recoveryVersionValue: UInt64? = 0
        private var recoveryVersions = 0
        private var recoveryFrames = 0
        var recoveryCounts: (Int, Int) { lock.withLock { (recoveryVersions, recoveryFrames) } }
        func recoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { recoveryVersions += 1 }
            if let recoveryVersionValue { reply(.recoveryVersion(recoveryVersionValue)) } else { reply(.failed) }
        }
        func recovery(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { recoveryFrames += 1 }
            do {
                let request = try PhonePushRecoveryFrame.decode(frame)
                guard case .resume = request else { return reply(.failed) }
                reply(.recovery(try PhonePushRecoveryFrame.outcome(correlationID: request.correlationID, failure: .expired).encode()))
            } catch { reply(.failed) }
        }
        private var receiptQueries: [Data] = []
        private var receiptReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var holdReceiptReply = false
        let receiptRequested = XCTestExpectation(description: "receipt requested")
        private var receiptValue = Data(repeating: 8, count: 64)
        var receiptBytes: Data {
            get { lock.withLock { receiptValue } }
            set { lock.withLock { receiptValue = newValue } }
        }
        var receiptIDs: [Data] { lock.withLock { receiptQueries } }
        func holdReceipt() { lock.withLock { holdReceiptReply = true } }
        func finishReceipt() {
            let callback = lock.withLock { let value = receiptReply; receiptReply = nil; return value }
            callback?(.receipt(receiptBytes))
        }
        func receiptVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            reply(.receiptVersion(1))
        }
        func receipt(_ binding: Data, setupID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            let held = lock.withLock {
                receiptQueries.append(setupID)
                if holdReceiptReply { receiptReply = reply; return true }
                return false
            }
            receiptRequested.fulfill()
            if !held { reply(.receipt(receiptBytes)) }
        }
        let requested = XCTestExpectation(description: "frame requested")
        init(trust: DirectApprovalTrust, ids: [Data], frames: [Data: Data], exchangeSupported: Bool = false,
             statuses: [Data: Data] = [:], decisions: [Data: Data] = [:]) {
            self.trust = trust; self.ids = ids; self.frames = frames
            self.exchangeSupported = exchangeSupported; self.statuses = statuses; self.decisions = decisions
        }
        var exchangeQueries: [AuthorityRequestExchange.Query] { lock.withLock { exchanges } }
        func setPending(_ ids: [Data]) { lock.withLock { self.ids = ids } }
        func setStatus(_ id: Data, _ bytes: Data, retireCapture: Bool = true) {
            lock.withLock { statuses[id] = bytes; if retireCapture { frames[id] = nil; ids.removeAll { $0 == id } } }
        }
        func holdExchange() { lock.withLock { holdExchangeReply = true } }
        func finishExchange(_ frame: Data) {
            lock.withLock { let callback = exchangeHeld; exchangeHeld = nil; return callback }?(.exchange(frame))
        }
        func exchangeVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.exchangeVersion(exchangeSupported ? 1 : 0)) }
        func exchange(_ binding: Data, query: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            let claim = try! AuthorityRequestExchange.decode(query)
            let bytes: Data? = lock.withLock {
                exchanges.append(claim)
                if holdExchangeReply { exchangeHeld = reply; return nil }
                if claim.decisionFrame != nil, let decision = decisions[claim.requestID] {
                    statuses[claim.requestID] = decision; frames[claim.requestID] = nil; ids.removeAll { $0 == claim.requestID }
                }
                return statuses[claim.requestID] ?? Data()
            }
            if let bytes { reply(.exchange(bytes)) } else { exchanged.fulfill() }
        }
        var frameIDs: [Data] { lock.withLock { queries } }
        var discoveryCount: Int { lock.withLock { discoveries } }
        func holdFrame() { lock.withLock { hold = true } }
        func finishFrame(_ bytes: Data) {
            let callback = lock.withLock { let value = held; held = nil; return value }
            callback?(.requestFrame(bytes))
        }
        func start(invalidated: @escaping @Sendable () -> Void) { }
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            reply(.snapshot(try! AuthorityTrustCodec.encodeSnapshot(trust)))
        }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func discoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.discoveryVersion(1)) }
        func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.deliveryVersion(1)) }
        func pendingRequests(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            let snapshot = lock.withLock { discoveries += 1; if discoveries == 1 { discovered.fulfill() }; return ids }
            let binding = try! AuthorityTrustCodec.decodeBinding(bytes, expectedMacID: SelfID.mac, expectedAccountID: SelfID.account)
            reply(.pendingRequests(try! AuthorityPendingRequests.encode(snapshot, binding: binding)))
        }
        func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            let waiting = lock.withLock {
                queries.append(requestID)
                if hold { held = reply; return true }; return false
            }
            if waiting { requested.fulfill() } else { reply(.requestFrame(lock.withLock { frames[requestID] ?? Data() })) }
        }
        func close() { }
    }
    private enum SelfID { static let mac = id(1), account = id(2) }
    private final class Listener: OwnedDirectListener, @unchecked Sendable {
        func start() throws { }
        func close() { }
        func closeAndWait() async { close() }
    }
    private final class Factory: @unchecked Sendable {
        private let lock = NSLock()
        private var callback: (@Sendable (DirectApprovalPeer, NegotiatedNetworkChannel) async throws -> Void)?
        private var incarnation: UUID?
        var generation: UUID { lock.withLock { incarnation! } }
        func make(_ generation: UUID, _ handler: @escaping @Sendable (DirectApprovalPeer, NegotiatedNetworkChannel) async throws -> Void) -> Listener {
            lock.withLock { incarnation = generation; callback = handler }
            return Listener()
        }
        func run(_ peer: DirectApprovalPeer, _ channel: NegotiatedNetworkChannel) async throws {
            let handler = lock.withLock { callback! }
            try await handler(peer, channel)
        }
    }
    private actor Phone: ApprovalByteStream {
        let owner: ChannelNegotiation
        let maximum: Int
        let failWrite: Bool
        let holdWrite: Bool
        let writing = XCTestExpectation(description: "write held")
        var writeReply: CheckedContinuation<Void, Error>?
        var input: [Data]
        var output = Data()
        var phase = 0
        var payloads: [Data] = []
        var closed = false
        let persistent: Bool
        var readReply: CheckedContinuation<Data?, Error>?
        var sentSequence: UInt64 = 0
        var expectations: [(Int, XCTestExpectation)] = []
        init(scope: ChannelScope, requests: [ChannelRequestCapability], maximum: Int = 4096,
             failWrite: Bool = false, holdWrite: Bool = false, persistent: Bool = false) throws {
            self.maximum = maximum; self.failWrite = failWrite; self.holdWrite = holdWrite; self.persistent = persistent
            owner = try ChannelNegotiation(local: ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: 7, count: 32),
                envelopeVersions: [1], requests: requests, auditVersions: []), trustedMinimum: 1)
            input = [Self.frame(try owner.offer())]
        }
        func awaitOpen(timeoutMilliseconds: UInt64) async throws { }
        func receive() async throws -> Data? {
            if closed { return nil }
            if !input.isEmpty { return input.removeFirst() }
            guard persistent else { throw ApprovalChannelError.closed }
            return try await withCheckedThrowingContinuation { readReply = $0 }
        }
        func send(_ bytes: Data) async throws {
            guard !closed else { throw ApprovalChannelError.closed }
            if phase >= 2 {
                if failWrite { throw ApprovalChannelError.closed }
                if holdWrite {
                    writing.fulfill()
                    try await withCheckedThrowingContinuation { writeReply = $0 }
                    return
                }
            }
            output.append(bytes)
            guard output.count >= 4 else { return }
            let count = output.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
            guard output.count == count + 4 else { return }
            let body = Data(output.dropFirst(4)); output.removeAll()
            switch phase {
            case 0: try owner.receiveOffer(body); input.append(Self.frame(try owner.confirmation()))
            case 1: try owner.receiveConfirmation(body)
            default:
                let envelope = try SessionEnvelope.decode(body, maximumPayloadBytes: maximum)
                XCTAssertEqual(envelope.sessionID, try owner.confirmed().sessionID)
                XCTAssertEqual(envelope.sequence, UInt64(payloads.count))
                payloads.append(envelope.payload)
                let ready = expectations.filter { payloads.count >= $0.0 }
                expectations.removeAll { payloads.count >= $0.0 }
                ready.forEach { $0.1.fulfill() }
            }
            phase += 1
        }
        func close() async {
            closed = true; owner.close()
            writeReply?.resume(throwing: ApprovalChannelError.closed); writeReply = nil
            readReply?.resume(returning: nil); readReply = nil
        }
        func submit(_ payload: Data) throws {
            let bytes = try SessionEnvelope(sessionID: owner.confirmed().sessionID, sequence: sentSequence, payload: payload)
                .encode(maximumPayloadBytes: maximum)
            sentSequence += 1; enqueue(Self.frame(bytes))
        }
        func oversizedHeader() { enqueue(Data([0, 1, 0, 0])) }
        private func enqueue(_ bytes: Data) {
            for start in stride(from: 0, to: bytes.count, by: 32_768) {
                let chunk = Data(bytes[start..<min(start + 32_768, bytes.count)])
                if let readReply { self.readReply = nil; readReply.resume(returning: chunk) }
                else { input.append(chunk) }
            }
        }
        func expectPayloads(_ count: Int) -> XCTestExpectation {
            let expected = XCTestExpectation(description: "received \(count) frames")
            if payloads.count >= count { expected.fulfill() } else { expectations.append((count, expected)) }
            return expected
        }
        static func frame(_ body: Data) -> Data {
            let count = UInt32(body.count)
            return Data([UInt8(truncatingIfNeeded: count >> 24), UInt8(truncatingIfNeeded: count >> 16),
                UInt8(truncatingIfNeeded: count >> 8), UInt8(truncatingIfNeeded: count)]) + body
        }
    }
    private func setup(ids: [Data], frames: [Data: Data], maximum: Int = 4096, features: Set<UInt64> = [],
                       automatic: Bool = true, exchangeSupported: Bool = false, statuses: [Data: Data] = [:],
                       decisions: [Data: Data] = [:], refreshMilliseconds: UInt64 = 5000, recoveryVersion: UInt64? = 0,
                       handler: @escaping @Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void = { _, _ in }) async throws -> (DirectApprovalTransportService, DirectApprovalTransportHost, Driver, Factory, DirectApprovalPeer) {
        let peer = try DirectApprovalPeer(scope: Self.scope(), transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation,
            requests: [Self.capability(features: features)], auditVersions: [], maximumPayloadBytes: maximum)
        let trust = DirectApprovalTrust(macID: Self.id(1), accountID: Self.id(2), revision: UUID(), peers: [peer])
        let driver = Driver(trust: trust, ids: ids, frames: frames, exchangeSupported: exchangeSupported, statuses: statuses, decisions: decisions), factory = Factory()
        driver.recoveryVersionValue = recoveryVersion
        let feed = AuthorityTrustFeed(macID: Self.id(1), accountID: Self.id(2), factory: { AuthorityXPCChannel(driver: driver, onClose: $0) })
        let host = DirectApprovalTransportHost(macID: Self.id(1), accountID: Self.id(2),
            factory: { generation, _, _, handler in factory.make(generation, handler) },
            validatePeer: { try await feed.validatePeer($0, revision: $1) }, handler: handler)
        let service = DirectApprovalTransportService(feed: feed, host: host, useDefaultDelivery: automatic, requestRefreshMilliseconds: refreshMilliseconds)
        try await service.start()
        return (service, host, driver, factory, peer)
    }
    private func connect(_ phone: Phone, _ peer: DirectApprovalPeer,
                         purpose: EnrolledChannelPurpose = .approvals) async throws -> NegotiatedNetworkChannel {
        try await NegotiatedNetworkChannel.accept(stream: phone, scope: peer.scope, requests: purpose == .pushRecovery ? [] : peer.requests, auditVersions: [],
            maximumPayloadBytes: peer.channelMaximumPayloadBytes(for: purpose), purpose: purpose)
    }
    private func recoveryResume(_ id: Data = DirectApprovalRequestDeliveryTests.id(32)) throws -> PhonePushRecoveryFrame {
        try .resume(correlationID: id, offer: PhonePushTokenOffer(token: "synthetic-token", projectID: "project",
            senderID: "123", packageName: "dev.remozio.android"))
    }
    func testRecoveryPreflightPrecedesResumeAndUsesTheDefaultPurposeHandler() async throws {
        let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:], recoveryVersion: 2)
        let phone = try Phone(scope: peer.scope, requests: [], maximum: 8192, persistent: true)
        let channel = try await connect(phone, peer, purpose: .pushRecovery)
        let delivery = Task { try await factory.run(peer, channel) }
        try await phone.submit(PhonePushRecoveryFrame.probe(correlationID: Self.id(31)).encode())
        await fulfillment(of: [await phone.expectPayloads(1)], timeout: 2)
        let preflight = await phone.payloads
        guard case .ready(let id) = try PhonePushRecoveryFrame.decode(preflight[0]) else { return XCTFail("Missing readiness") }
        XCTAssertEqual(id, Self.id(31)); XCTAssertEqual(driver.recoveryCounts.0, 1); XCTAssertEqual(driver.recoveryCounts.1, 0)
        try await phone.submit(recoveryResume().encode()); try await delivery.value
        let replies = await phone.payloads
        XCTAssertEqual(replies.count, 2)
        guard case .outcome(let replyID, let failure) = try PhonePushRecoveryFrame.decode(replies[1]) else { return XCTFail("Missing outcome") }
        XCTAssertEqual(replyID, Self.id(32)); XCTAssertEqual(failure, .expired); XCTAssertEqual(driver.recoveryCounts.1, 1)
        let closed = await phone.closed; XCTAssertTrue(closed); await service.close()
    }
    func testRecoveryDistinguishesUnsupportedAndUnavailableWithoutPrivateInvocation() async throws {
        for version: UInt64? in [0, 1, 3, nil] {
            let (service, host, driver, factory, peer) = try await setup(ids: [], frames: [:], recoveryVersion: version)
            let phone = try Phone(scope: peer.scope, requests: [], maximum: 8192, persistent: true)
            let channel = try await connect(phone, peer, purpose: .pushRecovery)
            try await phone.submit(PhonePushRecoveryFrame.probe(correlationID: Self.id(31)).encode())
            try await factory.run(peer, channel)
            let replies = await phone.payloads; XCTAssertEqual(replies.count, 1)
            guard case .outcome(_, let failure) = try PhonePushRecoveryFrame.decode(replies[0]) else { return XCTFail("Missing refusal") }
            XCTAssertEqual(failure, version == nil ? .unavailable : .incompatible)
            XCTAssertEqual(driver.recoveryCounts.1, 0)
            let admitted = try await host.admit(peer, generation: factory.generation)
            let ordinaryIDs = try await service.pendingRequestIDs(for: admitted)
            XCTAssertTrue(ordinaryIDs.isEmpty)
            await service.close()
        }
    }
    func testRecoveryRejectsPrivateFirstFrameAndRepeatedCorrelationBeforeRoot() async throws {
        for privateFirst in [false, true] {
            let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:], recoveryVersion: 2)
            let phone = try Phone(scope: peer.scope, requests: [], maximum: 8192, persistent: true)
            let channel = try await connect(phone, peer, purpose: .pushRecovery)
            let delivery = Task { try await factory.run(peer, channel) }
            if !privateFirst {
                try await phone.submit(PhonePushRecoveryFrame.probe(correlationID: Self.id(31)).encode())
                await fulfillment(of: [await phone.expectPayloads(1)], timeout: 2)
            }
            try await phone.submit(recoveryResume(Self.id(31)).encode())
            do { try await delivery.value; XCTFail("Invalid exchange accepted") } catch {}
            XCTAssertEqual(driver.recoveryCounts.0, privateFirst ? 0 : 1); XCTAssertEqual(driver.recoveryCounts.1, 0)
            let closed = await phone.closed; XCTAssertTrue(closed); await service.close()
        }
    }
    func testRecoveryCancellationAfterReadyDoesNotInventOrReplayResume() async throws {
        let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:], recoveryVersion: 2)
        let phone = try Phone(scope: peer.scope, requests: [], maximum: 8192, persistent: true)
        let channel = try await connect(phone, peer, purpose: .pushRecovery)
        let delivery = Task { try await factory.run(peer, channel) }
        try await phone.submit(PhonePushRecoveryFrame.probe(correlationID: Self.id(31)).encode())
        await fulfillment(of: [await phone.expectPayloads(1)], timeout: 2)
        delivery.cancel(); do { try await delivery.value; XCTFail("Cancelled exchange completed") } catch {}
        XCTAssertEqual(driver.recoveryCounts.1, 0)
        let closed = await phone.closed; XCTAssertTrue(closed); await service.close()
    }
    func testDefaultHandlerWritesExactSignedFramesAndSkipsAbsentRequests() async throws {
        let (first, key) = try Self.frame(8), second = try Self.frame(10).0
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8), Self.id(9), Self.id(10)],
            frames: [Self.id(8): first, Self.id(10): second])
        let phone = try Phone(scope: peer.scope, requests: peer.requests), channel = try await connect(phone, peer)
        try await factory.run(peer, channel)
        let payloads = await phone.payloads
        XCTAssertEqual(payloads, [first, second]); XCTAssertEqual(driver.discoveryCount, 1)
        XCTAssertEqual(driver.frameIDs, [Self.id(8), Self.id(9), Self.id(10)])
        let message = try ApprovalMessage.decode(payloads[0], maximumBodyBytes: 3968)
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 12, maxItems: 256)
        XCTAssertTrue(try ApprovalSignature.verify(signature: message.signature, publicKey: key.x963Representation,
            wireVersion: 1, messageType: .request, purpose: .issuedRequest, canonicalPayload: message.body,
            payloadLimits: limits, inputLimits: limits))
        await channel.closeAndWait(); await service.close()
    }
    func testReservedBodyBudgetFitsPeerPayloadLimit() async throws {
        let maximum = 1024, bodyMaximum = maximum - ApprovalMessage.overheadBytes
        let frame = try Self.frame(8, bodyBytes: bodyMaximum).0
        let message = try ApprovalMessage.decode(frame, maximumBodyBytes: bodyMaximum)
        XCTAssertEqual(message.body.count, bodyMaximum); XCTAssertLessThanOrEqual(frame.count, maximum)
        let (service, _, _, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame], maximum: maximum)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, maximum: maximum), channel = try await connect(phone, peer)
        try await factory.run(peer, channel)
        let payloads = await phone.payloads
        XCTAssertEqual(payloads, [frame])
        await channel.closeAndWait(); await service.close()
    }
    func testWrongScopeAndNoCommonContractCloseBeforeDiscovery() async throws {
        for wrongScope in [false, true] {
            let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [:])
            let phoneScope = try Self.scope(phone: wrongScope ? 5 : 3)
            let phone = try Phone(scope: phoneScope, requests: wrongScope ? peer.requests : [])
            let channel = try await NegotiatedNetworkChannel.accept(stream: phone, scope: phoneScope, requests: peer.requests,
                auditVersions: [], maximumPayloadBytes: 4096)
            do { try await factory.run(peer, channel); XCTFail("Unbound channel delivered") } catch { }
            let closed = await phone.closed, payloads = await phone.payloads
            XCTAssertTrue(closed); XCTAssertTrue(payloads.isEmpty); XCTAssertEqual(driver.discoveryCount, 0)
            await service.close()
        }
    }
    func testRuntimeFeaturesOmitUnsupportedFrame() async throws {
        let frame = try Self.frame(8, features: [1]).0
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame], features: [1])
        let phone = try Phone(scope: peer.scope, requests: [Self.capability()]), channel = try await connect(phone, peer)
        try await factory.run(peer, channel)
        let payloads = await phone.payloads
        XCTAssertTrue(payloads.isEmpty); XCTAssertEqual(driver.frameIDs, [Self.id(8)])
        await channel.closeAndWait(); await service.close()
    }
    func testRetiredOrClosedSessionCannotWriteLateFrame() async throws {
        for closeService in [false, true] {
            let frame = try Self.frame(8).0
            let (service, host, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [:])
            driver.holdFrame()
            let phone = try Phone(scope: peer.scope, requests: peer.requests), channel = try await connect(phone, peer)
            let delivery = Task { try await factory.run(peer, channel) }
            await fulfillment(of: [driver.requested], timeout: 2)
            if closeService { await service.close() }
            else { try await host.replaceTrust(driver.trust) }
            driver.finishFrame(frame)
            do { try await delivery.value; XCTFail("Retired session wrote") } catch { }
            let payloads = await phone.payloads, closed = await phone.closed
            XCTAssertTrue(payloads.isEmpty); XCTAssertTrue(closed)
            await service.close()
        }
    }
    func testFailedWriteDoesNotFetchAnotherFrame() async throws {
        let first = try Self.frame(8).0, second = try Self.frame(9).0
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8), Self.id(9)],
            frames: [Self.id(8): first, Self.id(9): second])
        let phone = try Phone(scope: peer.scope, requests: peer.requests, failWrite: true), channel = try await connect(phone, peer)
        do { try await factory.run(peer, channel); XCTFail("Failed write succeeded") } catch { }
        XCTAssertEqual(driver.frameIDs, [Self.id(8)])
        let closed = await phone.closed; XCTAssertTrue(closed)
        await service.close()
    }
    func testDeadlineClosesBlockedWrite() async throws {
        let frame = try Self.frame(8).0
        let (service, host, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame])
        let session = try await host.admit(peer, generation: factory.generation)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, holdWrite: true), channel = try await connect(phone, peer)
        do {
            try await service.deliverPendingRequests(for: session, over: channel, timeoutMilliseconds: 100)
            XCTFail("Blocked write exceeded deadline")
        } catch ApprovalChannelError.timedOut { }
        let closed = await phone.closed; XCTAssertTrue(closed)
        XCTAssertEqual(driver.frameIDs, [Self.id(8)])
        await service.close()
    }
    func testCancellationClosesBlockedWrite() async throws {
        let frame = try Self.frame(8).0
        let (service, _, _, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame])
        let phone = try Phone(scope: peer.scope, requests: peer.requests, holdWrite: true), channel = try await connect(phone, peer)
        let delivery = Task { try await factory.run(peer, channel) }
        await fulfillment(of: [phone.writing], timeout: 2)
        delivery.cancel()
        do { try await delivery.value; XCTFail("Cancelled write succeeded") } catch { }
        let closed = await phone.closed; XCTAssertTrue(closed)
        await service.close()
    }
    func testPayloadLimitClosesBeforeFirstWrite() async throws {
        let frame = try Self.frame(8).0
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame], maximum: 128)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, maximum: 128), channel = try await connect(phone, peer)
        do { try await factory.run(peer, channel); XCTFail("Oversized frame sent") } catch { }
        let payloads = await phone.payloads, closed = await phone.closed
        XCTAssertTrue(payloads.isEmpty); XCTAssertTrue(closed); XCTAssertEqual(driver.frameIDs, [Self.id(8)])
        await service.close()
    }
    func testCustomHandlerRemainsInControl() async throws {
        let expected = Data([42])
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [:], automatic: false,
            handler: { _, channel in try await channel.send(expected) })
        let phone = try Phone(scope: peer.scope, requests: peer.requests), channel = try await connect(phone, peer)
        try await factory.run(peer, channel)
        let payloads = await phone.payloads
        XCTAssertEqual(payloads, [expected]); XCTAssertEqual(driver.discoveryCount, 0)
        await channel.closeAndWait(); await service.close()
    }
    func testHandlerCannotChangeAfterHostStarts() async throws {
        let (service, host, _, _, _) = try await setup(ids: [], frames: [:])
        do { try await host.configureHandler { _, _ in }; XCTFail("Live handler replaced") } catch { }
        await service.close()
    }

    func testReceiptHandlerReturnsOneReceiptWithoutDiscoveringCommands() async throws {
        for available in [false, true] {
            let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [:])
            if !available { driver.receiptBytes = Data() }
            let phone = try Phone(scope: peer.scope, requests: [], persistent: true)
            let channel = try await connect(phone, peer, purpose: .pairingReceipt)
            try await phone.submit(PairingReceiptFrame.query(setupID: Self.id(31)).encode())
            try await phone.submit(PairingReceiptFrame.query(setupID: Self.id(32)).encode())
            try await factory.run(peer, channel)
            let payloads = await phone.payloads, closed = await phone.closed
            XCTAssertEqual(payloads, [try PairingReceiptFrame.response(setupID: Self.id(31),
                signature: available ? driver.receiptBytes : nil).encode()])
            XCTAssertEqual(driver.receiptIDs, [Self.id(31)])
            XCTAssertEqual(driver.discoveryCount, 0); XCTAssertTrue(driver.frameIDs.isEmpty)
            XCTAssertTrue(closed)
            await service.close()
        }
    }

    func testReceiptHandlerRejectsInvalidQueriesBeforeAuthorityAccess() async throws {
        let invalid = [Data([0xa0]), try PairingReceiptFrame.response(setupID: Self.id(31), signature: nil).encode(),
                       Data(repeating: 0, count: PairingReceiptFrame.maximumBytes + 1)]
        for query in invalid {
            let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:])
            let phone = try Phone(scope: peer.scope, requests: [], persistent: true)
            let channel = try await connect(phone, peer, purpose: .pairingReceipt)
            try await phone.submit(query)
            do { try await factory.run(peer, channel); XCTFail("Invalid receipt query accepted") } catch { }
            let closed = await phone.closed, payloads = await phone.payloads
            XCTAssertTrue(closed); XCTAssertTrue(payloads.isEmpty); XCTAssertTrue(driver.receiptIDs.isEmpty)
            XCTAssertEqual(driver.discoveryCount, 0)
            await service.close()
        }
    }

    func testReceiptHandlerRejectsWrongPurposeAndScopeBeforeAuthorityAccess() async throws {
        for wrongPurpose in [false, true] {
            let (service, host, driver, factory, peer) = try await setup(ids: [], frames: [:])
            let session = try await host.admit(peer, generation: factory.generation)
            let scope = try Self.scope(phone: wrongPurpose ? 3 : 5)
            let phone = try Phone(scope: scope, requests: [], persistent: true)
            let channel = try await NegotiatedNetworkChannel.accept(stream: phone, scope: scope,
                requests: [], auditVersions: [], maximumPayloadBytes: 4096,
                purpose: wrongPurpose ? .approvals : .pairingReceipt)
            do { try await service.runPairingReceiptRecovery(for: session, over: channel); XCTFail("Unbound receipt accepted") } catch { }
            let closed = await phone.closed
            XCTAssertTrue(closed); XCTAssertTrue(driver.receiptIDs.isEmpty); XCTAssertEqual(driver.discoveryCount, 0)
            await service.close()
        }
    }

    func testReceiptCannotBeSentAfterTransportSessionRetires() async throws {
        let (service, host, driver, factory, peer) = try await setup(ids: [], frames: [:])
        driver.holdReceipt()
        let phone = try Phone(scope: peer.scope, requests: [], persistent: true)
        let channel = try await connect(phone, peer, purpose: .pairingReceipt)
        try await phone.submit(PairingReceiptFrame.query(setupID: Self.id(31)).encode())
        let recovery = Task { try await factory.run(peer, channel) }
        await fulfillment(of: [driver.receiptRequested], timeout: 2)
        try await host.replaceTrust(driver.trust)
        driver.finishReceipt()
        do { try await recovery.value; XCTFail("Retired receipt sent") } catch { }
        let payloads = await phone.payloads, closed = await phone.closed
        XCTAssertTrue(payloads.isEmpty); XCTAssertTrue(closed)
        XCTAssertEqual(driver.receiptIDs, [Self.id(31)]); XCTAssertEqual(driver.discoveryCount, 0)
        await service.close()
    }

    func testReceiptDeadlineAndCancellationClosePendingRead() async throws {
        for cancelled in [false, true] {
            let (service, host, driver, factory, peer) = try await setup(ids: [], frames: [:])
            let session = try await host.admit(peer, generation: factory.generation)
            let phone = try Phone(scope: peer.scope, requests: [], persistent: true)
            let channel = try await connect(phone, peer, purpose: .pairingReceipt)
            let recovery = Task { try await service.runPairingReceiptRecovery(for: session, over: channel,
                timeoutMilliseconds: cancelled ? 5000 : 100) }
            if cancelled { recovery.cancel() }
            do { try await recovery.value; XCTFail("Pending read completed") } catch { }
            let payloads = await phone.payloads, closed = await phone.closed
            XCTAssertTrue(payloads.isEmpty); XCTAssertTrue(closed)
            XCTAssertTrue(driver.receiptIDs.isEmpty); XCTAssertEqual(driver.discoveryCount, 0)
            await service.close()
        }
    }

    func testReceiptDeadlineClosesBlockedResponseWrite() async throws {
        let (service, host, driver, factory, peer) = try await setup(ids: [], frames: [:])
        let session = try await host.admit(peer, generation: factory.generation)
        let phone = try Phone(scope: peer.scope, requests: [], holdWrite: true, persistent: true)
        let channel = try await connect(phone, peer, purpose: .pairingReceipt)
        try await phone.submit(PairingReceiptFrame.query(setupID: Self.id(31)).encode())
        do {
            try await service.runPairingReceiptRecovery(for: session, over: channel, timeoutMilliseconds: 100)
            XCTFail("Blocked receipt write exceeded deadline")
        } catch { }
        let payloads = await phone.payloads, closed = await phone.closed
        XCTAssertTrue(payloads.isEmpty); XCTAssertTrue(closed)
        XCTAssertEqual(driver.receiptIDs, [Self.id(31)]); XCTAssertEqual(driver.discoveryCount, 0)
        await service.close()
    }

    private static func status(_ frame: Data, phase: RequestPhase = .presented, revision: UInt64 = 1,
                               signingKey: P256.Signing.PrivateKey) throws -> Data {
        let limits = try CBORLimits(maxBytes: 3968, maxDepth: 12, maxItems: 256)
        let issued = try IssuedRequestPayload.decode(ApprovalMessage.decode(frame, maximumBodyBytes: 3968).body,
            bodyLimits: limits, captureLimits: limits, localCapabilities: ContractCapabilities(contracts: [try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1): []]))
        let pending = phase == .queued || phase == .presented
        let reason: RequestStatusReason = phase == .expired ? .authorizationExpired : phase == .succeeded ? .verifiedResult : .none
        let status = try RequestStatusPayload(macID: issued.macID, accountID: issued.accountID, requestID: issued.requestID,
            requestDigest: issued.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: issued.challenge,
            revision: revision, phase: phase, reason: reason, observationID: id(20), observedAgeMs: 100,
            authorizationRemainingMs: pending ? 100 : nil, estimatedLifetimeMs: nil, lateObservation: false,
            terminalAgeMs: phase.isTerminal ? 20 : nil, decisionPhoneID: phase == .authorized || phase == .succeeded ? id(3) : nil)
        let body = try status.encode(limits: limits)
        let input = try SigningInput.make(wireVersion: 1, messageType: .status, purpose: .status,
            canonicalPayload: body, payloadLimits: limits, inputLimits: limits)
        return try ApprovalMessage(wireVersion: 1, type: .status, purpose: .status, body: body,
            signature: signingKey.signature(for: input).rawRepresentation).encode(maximumBodyBytes: 3968)
    }
    private static func decision(_ frame: Data, phone: UInt8 = 3, signingKey: P256.Signing.PrivateKey) throws -> Data {
        let limits = try CBORLimits(maxBytes: 3968, maxDepth: 12, maxItems: 256)
        let issued = try IssuedRequestPayload.decode(ApprovalMessage.decode(frame, maximumBodyBytes: 3968).body,
            bodyLimits: limits, captureLimits: limits, localCapabilities: ContractCapabilities(contracts: [try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1): []]))
        let body = try DecisionPayload(macID: issued.macID, accountID: issued.accountID, requestID: issued.requestID,
            requestDigest: issued.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: issued.challenge,
            phoneID: id(phone), keyID: id(13), action: CapturedAction(choice: .execute, scope: .currentRequest)).encode(limits: limits)
        let input = try SigningInput.make(wireVersion: 1, messageType: .decision, purpose: .biometricAuthorization,
            canonicalPayload: body, payloadLimits: limits, inputLimits: limits)
        return try ApprovalMessage(wireVersion: 1, type: .decision, purpose: .biometricAuthorization, body: body,
            signature: signingKey.signature(for: input).rawRepresentation).encode(maximumBodyBytes: 3968)
    }
    private func wait(_ phone: Phone, _ count: Int) async {
        await fulfillment(of: [phone.expectPayloads(count)], timeout: 3)
    }

    func testLiveChannelRoutesExactDecisionAndReturnsSignedRootOutcome() async throws {
        let key = P256.Signing.PrivateKey(), phoneKey = P256.Signing.PrivateKey()
        let frame = try Self.frame(8, signingKey: key).0
        let pending = try Self.status(frame, signingKey: key), accepted = try Self.status(frame, phase: .authorized, revision: 2, signingKey: key)
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame],
            exchangeSupported: true, statuses: [Self.id(8): pending], decisions: [Self.id(8): accepted])
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true), channel = try await connect(phone, peer)
        let loop = Task { try await factory.run(peer, channel) }
        await wait(phone, 2)
        let decision = try Self.decision(frame, signingKey: phoneKey)
        try await phone.submit(decision); await wait(phone, 3)
        let output = await phone.payloads
        XCTAssertEqual(output, [frame, pending, accepted])
        XCTAssertEqual(driver.exchangeQueries.compactMap(\.decisionFrame), [decision])
        let message = try ApprovalMessage.decode(output.last!, maximumBodyBytes: 3968)
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 12, maxItems: 256)
        XCTAssertTrue(try ApprovalSignature.verify(signature: message.signature, publicKey: key.publicKey.x963Representation,
            wireVersion: 1, messageType: .status, purpose: .status, canonicalPayload: message.body, payloadLimits: limits, inputLimits: limits))
        await phone.close(); try await loop.value; await service.close()
    }

    func testReconnectQueryReturnsTerminalStateAbsentFromDiscovery() async throws {
        let key = P256.Signing.PrivateKey(), frame = try Self.frame(8).0
        let expired = try Self.status(frame, phase: .expired, revision: 2, signingKey: key)
        let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:], exchangeSupported: true, statuses: [Self.id(8): expired])
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true), channel = try await connect(phone, peer)
        let loop = Task { try await factory.run(peer, channel) }
        await fulfillment(of: [driver.discovered], timeout: 3)
        try await phone.submit(RequestStatusQuery(requestID: Self.id(8)).encode()); await wait(phone, 1)
        let output = await phone.payloads; XCTAssertEqual(output, [expired]); XCTAssertTrue(driver.frameIDs.isEmpty)
        XCTAssertEqual(driver.exchangeQueries.count, 1); XCTAssertNil(driver.exchangeQueries.first?.decisionFrame)
        await phone.close(); try await loop.value; await service.close()
    }

    func testAbsentQueryEmitsNoUnsignedOutcomeAndLeavesChannelUsable() async throws {
        let key = P256.Signing.PrivateKey(), frame = try Self.frame(8).0
        let terminal = try Self.status(frame, phase: .expired, revision: 2, signingKey: key)
        let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:], exchangeSupported: true, statuses: [Self.id(8): terminal])
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true), channel = try await connect(phone, peer)
        let loop = Task { try await factory.run(peer, channel) }
        try await phone.submit(RequestStatusQuery(requestID: Self.id(9)).encode())
        try await phone.submit(RequestStatusQuery(requestID: Self.id(8)).encode())
        await wait(phone, 1)
        let output = await phone.payloads; XCTAssertEqual(output, [terminal])
        XCTAssertEqual(driver.exchangeQueries.map(\.requestID), [Self.id(9), Self.id(8)])
        XCTAssertTrue(driver.exchangeQueries.allSatisfy { $0.decisionFrame == nil })
        await phone.close(); try await loop.value; await service.close()
    }

    func testPeriodicRefreshFindsNewRequestsAndPreservesCapacityRetry() async throws {
        let key = P256.Signing.PrivateKey(), frame = try Self.frame(8).0, status = try Self.status(frame, signingKey: key)
        let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [Self.id(8): frame], exchangeSupported: true,
            statuses: [Self.id(8): status], refreshMilliseconds: 25)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true), channel = try await connect(phone, peer)
        let loop = Task { try await factory.run(peer, channel) }
        await fulfillment(of: [driver.discovered], timeout: 3)
        driver.setPending([Self.id(8)])
        await wait(phone, 4)
        let output = await phone.payloads
        XCTAssertEqual(Array(output.prefix(4)), [frame, status, frame, status])
        XCTAssertGreaterThanOrEqual(driver.discoveryCount, 3)
        await phone.close(); try await loop.value; await service.close()
    }

    func testOtherPhoneOutcomeAndExpiryReachRetainedOwnersWithoutNewCaptures() async throws {
        for phase: RequestPhase in [.expired, .succeeded] {
            let key = P256.Signing.PrivateKey(), frame = try Self.frame(8).0
            let pending = try Self.status(frame, signingKey: key), terminal = try Self.status(frame, phase: phase, revision: 2, signingKey: key)
            let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame], exchangeSupported: true,
                statuses: [Self.id(8): pending], refreshMilliseconds: 25)
            let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true), channel = try await connect(phone, peer)
            let loop = Task { try await factory.run(peer, channel) }
            await wait(phone, 2); driver.setStatus(Self.id(8), terminal)
            await wait(phone, 3)
            let output = await phone.payloads; XCTAssertEqual(output.last, terminal)
            await phone.close(); try await loop.value; await service.close()
        }
    }

    func testReadOnlyQueriesUseBoundedBackpressureWithoutDroppingFrames() async throws {
        let key = P256.Signing.PrivateKey(), frame = try Self.frame(8).0
        let terminal = try Self.status(frame, phase: .expired, revision: 2, signingKey: key)
        let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:], exchangeSupported: true, statuses: [Self.id(8): terminal])
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true), channel = try await connect(phone, peer)
        let loop = Task { try await factory.run(peer, channel) }
        let query = try RequestStatusQuery(requestID: Self.id(8)).encode()
        for _ in 0..<100 { try await phone.submit(query) }
        await wait(phone, 100)
        let output = await phone.payloads
        XCTAssertEqual(output, Array(repeating: terminal, count: 100)); XCTAssertEqual(driver.exchangeQueries.count, 100)
        XCTAssertTrue(driver.exchangeQueries.allSatisfy { $0.decisionFrame == nil })
        await phone.close(); try await loop.value; await service.close()
    }

    func testMalformedOrWrongScopeInboundFrameClosesBeforeRootExchange() async throws {
        let key = P256.Signing.PrivateKey(), frame = try Self.frame(8).0
        let malformed = try DeterministicCBOR.encode(.map([0: .unsigned(2), 1: .text("request-state"), 2: .bytes(Self.id(8))]),
            limits: CBORLimits(maxBytes: 64, maxDepth: 1, maxItems: 7))
        for input in [malformed, frame, try Self.decision(frame, phone: 7, signingKey: key)] {
            let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:], exchangeSupported: true)
            let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true), channel = try await connect(phone, peer)
            let loop = Task { try await factory.run(peer, channel) }
            try await phone.submit(input)
            do { try await loop.value; XCTFail("Invalid input accepted") } catch { }
            XCTAssertTrue(driver.exchangeQueries.isEmpty)
            let closed = await phone.closed; XCTAssertTrue(closed)
            await service.close()
        }
    }

    func testOversizedInboundHeaderClosesBeforeReadingItsBody() async throws {
        let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:], maximum: 32768, exchangeSupported: true)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, maximum: 32768, persistent: true), channel = try await connect(phone, peer)
        let loop = Task { try await factory.run(peer, channel) }; await phone.oversizedHeader()
        do { try await loop.value; XCTFail("Oversized input accepted") } catch { }
        XCTAssertTrue(driver.exchangeQueries.isEmpty)
        await service.close()
    }

    func testLiveLoopCancellationClosesBlockedReader() async throws {
        let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:], exchangeSupported: true)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true), channel = try await connect(phone, peer)
        let loop = Task { try await factory.run(peer, channel) }
        await fulfillment(of: [driver.discovered], timeout: 3); loop.cancel()
        do { try await loop.value; XCTFail("Cancelled loop stayed active") } catch { }
        let closed = await phone.closed; XCTAssertTrue(closed)
        await service.close()
    }

    func testStatusWriteTimeoutDoesNotRetryIncomingDecision() async throws {
        let key = P256.Signing.PrivateKey(), frame = try Self.frame(8).0, status = try Self.status(frame, phase: .authorized, signingKey: key)
        let (service, host, driver, factory, peer) = try await setup(ids: [], frames: [:], exchangeSupported: true, decisions: [Self.id(8): status])
        let session = try await host.admit(peer, generation: factory.generation)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, holdWrite: true, persistent: true), channel = try await connect(phone, peer)
        let decision = try Self.decision(frame, signingKey: key)
        let loop = Task { try await service.runRequestExchange(for: session, over: channel, timeoutMilliseconds: 100) }
        try await phone.submit(decision)
        do { try await loop.value; XCTFail("Blocked status write exceeded deadline") } catch ApprovalChannelError.timedOut { }
        XCTAssertEqual(driver.exchangeQueries.compactMap(\.decisionFrame), [decision])
        await service.close()
    }

    func testLateRootStatusCannotCrossRetiredSession() async throws {
        let key = P256.Signing.PrivateKey(), frame = try Self.frame(8).0, status = try Self.status(frame, signingKey: key)
        let (service, host, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame], exchangeSupported: true)
        driver.holdExchange()
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true), channel = try await connect(phone, peer)
        let loop = Task { try await factory.run(peer, channel) }
        await fulfillment(of: [driver.exchanged], timeout: 3)
        try await host.replaceTrust(driver.trust); driver.finishExchange(status)
        do { try await loop.value; XCTFail("Retired session wrote status") } catch { }
        let output = await phone.payloads; XCTAssertEqual(output, [frame])
        await service.close()
    }
    func testPendingSnapshotDeliversCapturesAndRetainedTerminalStatuses() async throws {
        let key = P256.Signing.PrivateKey()
        let first = try Self.frame(8, signingKey: key).0, old = try Self.frame(9, signingKey: key).0
        let firstStatus = try Self.status(first, signingKey: key), terminal = try Self.status(old, phase: .expired, signingKey: key)
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): first],
            exchangeSupported: true, statuses: [Self.id(8): firstStatus, Self.id(9): terminal])
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true)
        let channel = try await connect(phone, peer, purpose: .pendingSnapshot)
        let query = PendingRequestSnapshotFrame.query(nonce: Data(repeating: 21, count: 32), maximumFrames: 8,
            maximumBytes: 32_768, retainedRequestIDs: [Self.id(9)])
        try await phone.submit(query.encode()); try await factory.run(peer, channel)
        let output = await phone.payloads, closed = await phone.closed
        var progress = try PendingRequestSnapshotProgress(query: query)
        let frames = try output.compactMap { try progress.accept($0) }
        try progress.requireComplete()
        XCTAssertEqual(frames, [first, firstStatus, terminal]); XCTAssertTrue(closed)
        XCTAssertEqual(driver.exchangeQueries.map(\.requestID), [Self.id(8), Self.id(9)])
        XCTAssertTrue(driver.exchangeQueries.allSatisfy { $0.decisionFrame == nil })
        XCTAssertEqual(driver.discoveryCount, 1)
        await service.close()
    }
    func testPendingSnapshotMissingIndexedCaptureCannotComplete() async throws {
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [:], exchangeSupported: true)
        driver.holdFrame()
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true)
        let channel = try await connect(phone, peer, purpose: .pendingSnapshot)
        try await phone.submit(PendingRequestSnapshotFrame.query(nonce: Data(repeating: 21, count: 32),
            maximumFrames: 8, maximumBytes: 32_768).encode())
        let delivery = Task { try await factory.run(peer, channel) }
        await fulfillment(of: [driver.requested], timeout: 2)
        driver.finishFrame(Data())
        do { try await delivery.value; XCTFail("Missing indexed capture completed") } catch { }
        let output = await phone.payloads, closed = await phone.closed
        XCTAssertTrue(output.isEmpty); XCTAssertTrue(closed); XCTAssertEqual(driver.discoveryCount, 1)
        await service.close()
    }

    func testPendingSnapshotReservesFramingWithoutIncreasingTheRawCaptureLimit() async throws {
        let maximum = 1024
        for oversized in [false, true] {
            let frame = try Self.frame(8, bodyBytes: maximum - ApprovalMessage.overheadBytes + (oversized ? 1 : 0)).0
            let (service, _, _, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame],
                maximum: maximum, exchangeSupported: true)
            let nonce = Data(repeating: 21, count: 32)
            XCTAssertGreaterThan(try PendingRequestSnapshotFrame.item(nonce: nonce, ordinal: 0, frame: frame).encode().count, maximum)
            XCTAssertEqual(peer.channelMaximumPayloadBytes(for: .approvals), maximum)
            let phone = try Phone(scope: peer.scope, requests: peer.requests,
                maximum: peer.channelMaximumPayloadBytes(for: .pendingSnapshot), persistent: true)
            let channel = try await connect(phone, peer, purpose: .pendingSnapshot)
            let query = PendingRequestSnapshotFrame.query(nonce: nonce, maximumFrames: 8, maximumBytes: 32_768)
            try await phone.submit(query.encode())
            if oversized {
                do { try await factory.run(peer, channel); XCTFail("Raw capture limit increased") } catch { }
                let output = await phone.payloads; XCTAssertTrue(output.isEmpty)
            } else {
                try await factory.run(peer, channel)
                var progress = try PendingRequestSnapshotProgress(query: query)
                let output = await phone.payloads, frames = try output.compactMap { try progress.accept($0) }
                try progress.requireComplete(); XCTAssertEqual(frames, [frame])
            }
            await service.close()
        }
    }

    func testPendingSnapshotKeepsTheRawStatusLimit() async throws {
        let key = P256.Signing.PrivateKey(), frame = try Self.frame(8, signingKey: key).0
        let status = try Self.status(frame, signingKey: key)
        let (service, _, _, factory, peer) = try await setup(ids: [], frames: [:], maximum: 256,
            exchangeSupported: true, statuses: [Self.id(8): status])
        let phone = try Phone(scope: peer.scope, requests: peer.requests,
            maximum: peer.channelMaximumPayloadBytes(for: .pendingSnapshot), persistent: true)
        let channel = try await connect(phone, peer, purpose: .pendingSnapshot)
        try await phone.submit(PendingRequestSnapshotFrame.query(nonce: Data(repeating: 21, count: 32),
            maximumFrames: 8, maximumBytes: 32_768, retainedRequestIDs: [Self.id(8)]).encode())
        do { try await factory.run(peer, channel); XCTFail("Raw status limit increased") } catch { }
        let output = await phone.payloads; XCTAssertTrue(output.isEmpty)
        await service.close()
    }

    func testPendingSnapshotAcceptsTheLargestRetainedQueryWithinItsChannelBudget() async throws {
        let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:], maximum: 1024, exchangeSupported: true)
        let phone = try Phone(scope: peer.scope, requests: peer.requests,
            maximum: peer.channelMaximumPayloadBytes(for: .pendingSnapshot), persistent: true)
        let channel = try await connect(phone, peer, purpose: .pendingSnapshot)
        let ids = (0..<PendingRequestSnapshotFrame.maximumRetainedRequests).map { index -> Data in
            var value = Data(count: 16); value[14] = UInt8(truncatingIfNeeded: index >> 8)
            value[15] = UInt8(truncatingIfNeeded: index); return value
        }
        let query = PendingRequestSnapshotFrame.query(nonce: Data(repeating: 21, count: 32),
            maximumFrames: PendingRequestSnapshotFrame.maximumFrames,
            maximumBytes: PendingRequestSnapshotFrame.maximumSnapshotBytes, retainedRequestIDs: ids)
        try await phone.submit(query.encode()); try await factory.run(peer, channel)
        let output = await phone.payloads
        var progress = try PendingRequestSnapshotProgress(query: query)
        for frame in output { _ = try progress.accept(frame) }
        try progress.requireComplete(); XCTAssertEqual(driver.exchangeQueries.count, ids.count)
        XCTAssertTrue(driver.exchangeQueries.allSatisfy { $0.decisionFrame == nil })
        await service.close()
    }

    func testPendingSnapshotEmptySetHasExplicitCompletion() async throws {
        let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:])
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true)
        let channel = try await connect(phone, peer, purpose: .pendingSnapshot)
        let nonce = Data(repeating: 21, count: 32)
        try await phone.submit(PendingRequestSnapshotFrame.query(nonce: nonce, maximumFrames: 1, maximumBytes: 1).encode())
        try await factory.run(peer, channel)
        let output = await phone.payloads
        XCTAssertEqual(output, [try PendingRequestSnapshotFrame.complete(nonce: nonce, frames: 0, bytes: 0).encode()])
        XCTAssertEqual(driver.discoveryCount, 1); XCTAssertTrue(driver.exchangeQueries.isEmpty)
        await service.close()
    }
    func testPendingSnapshotRejectsReplyFramesBeforeDiscovery() async throws {
        let nonce = Data(repeating: 21, count: 32)
        let invalid = [Data([0xa0]), try PendingRequestSnapshotFrame.complete(nonce: nonce, frames: 0, bytes: 0).encode(),
                       try PendingRequestSnapshotFrame.item(nonce: nonce, ordinal: 0, frame: Data([1])).encode()]
        for bytes in invalid {
            let (service, _, driver, factory, peer) = try await setup(ids: [], frames: [:])
            let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true)
            let channel = try await connect(phone, peer, purpose: .pendingSnapshot)
            try await phone.submit(bytes)
            do { try await factory.run(peer, channel); XCTFail("Invalid snapshot query accepted") } catch { }
            let output = await phone.payloads, closed = await phone.closed
            XCTAssertTrue(output.isEmpty); XCTAssertTrue(closed); XCTAssertEqual(driver.discoveryCount, 0)
            await service.close()
        }
    }
    func testPendingSnapshotLimitsNeverProduceCompletionForPartialData() async throws {
        for itemLimit in [false, true] {
            let key = P256.Signing.PrivateKey()
            let frame = try Self.frame(8, signingKey: key).0
            let status = try Self.status(frame, signingKey: key)
            let (service, _, _, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame],
                exchangeSupported: true, statuses: [Self.id(8): status])
            let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true)
            let channel = try await connect(phone, peer, purpose: .pendingSnapshot)
            let query = PendingRequestSnapshotFrame.query(nonce: Data(repeating: 21, count: 32), maximumFrames: itemLimit ? 1 : 8,
                maximumBytes: itemLimit ? 32_768 : 1)
            try await phone.submit(query.encode())
            do { try await factory.run(peer, channel); XCTFail("Snapshot limit ignored") } catch { }
            let output = await phone.payloads
            XCTAssertEqual(output.count, itemLimit ? 1 : 0)
            var progress = try PendingRequestSnapshotProgress(query: query)
            for bytes in output { _ = try progress.accept(bytes) }
            XCTAssertThrowsError(try progress.requireComplete())
            await service.close()
        }
    }
    func testPendingSnapshotWrongPurposeAndScopeCloseBeforeDiscovery() async throws {
        for wrongPurpose in [false, true] {
            let (service, host, driver, factory, peer) = try await setup(ids: [], frames: [:], automatic: false)
            let scope = try wrongPurpose ? peer.scope : Self.scope(phone: 5)
            let phone = try Phone(scope: scope, requests: peer.requests, persistent: true)
            let channel = try await NegotiatedNetworkChannel.accept(stream: phone, scope: scope, requests: peer.requests,
                auditVersions: [], maximumPayloadBytes: 4096, purpose: wrongPurpose ? .approvals : .pendingSnapshot)
            let session = try await host.admit(peer, generation: factory.generation)
            do { try await service.runPendingRequestSnapshot(for: session, over: channel); XCTFail("Unbound snapshot accepted") } catch { }
            let closed = await phone.closed
            XCTAssertTrue(closed); XCTAssertEqual(driver.discoveryCount, 0)
            await service.close()
        }
    }
    func testPendingSnapshotTrustRetirementCannotWriteLateCapture() async throws {
        let frame = try Self.frame(8).0
        let (service, host, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [:])
        driver.holdFrame()
        let phone = try Phone(scope: peer.scope, requests: peer.requests, persistent: true)
        let channel = try await connect(phone, peer, purpose: .pendingSnapshot)
        try await phone.submit(PendingRequestSnapshotFrame.query(nonce: Data(repeating: 21, count: 32), maximumFrames: 8, maximumBytes: 32_768).encode())
        let delivery = Task { try await factory.run(peer, channel) }
        await fulfillment(of: [driver.requested], timeout: 2)
        try await host.replaceTrust(driver.trust); driver.finishFrame(frame)
        do { try await delivery.value; XCTFail("Retired snapshot wrote") } catch { }
        let output = await phone.payloads, closed = await phone.closed
        XCTAssertTrue(output.isEmpty); XCTAssertTrue(closed)
        await service.close()
    }
    func testPendingSnapshotBlockedWriteHasDeadline() async throws {
        let frame = try Self.frame(8).0
        let (service, host, _, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame], automatic: false)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, holdWrite: true, persistent: true)
        let channel = try await connect(phone, peer, purpose: .pendingSnapshot), session = try await host.admit(peer, generation: factory.generation)
        try await phone.submit(PendingRequestSnapshotFrame.query(nonce: Data(repeating: 21, count: 32), maximumFrames: 8, maximumBytes: 32_768).encode())
        let start = ContinuousClock.now
        do { try await service.runPendingRequestSnapshot(for: session, over: channel, timeoutMilliseconds: 100); XCTFail("Blocked snapshot wrote") } catch { }
        XCTAssertLessThan(start.duration(to: .now), .seconds(2))
        let closed = await phone.closed; XCTAssertTrue(closed)
        await service.close()
    }
}
