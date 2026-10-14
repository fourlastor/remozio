import CryptoKit
import Foundation
import Synchronization
import XCTest
import RemozioProtocol
@testable import RemozioCore

// Software keys and logical IPC only. This fixture proves no installed service identity or Root authorization.
struct TransportPairingFixture {
    let authority = P256.Signing.PrivateKey(), macTransport = P256.Signing.PrivateKey()
    let transport = P256.Signing.PrivateKey(), decision = P256.Signing.PrivateKey(), biometric = P256.Signing.PrivateKey()
    let configuration: TransportPairingControlConfiguration
    let proposal: PairingPhoneProposal
    let transcript: PairingTranscript
    let invitation: PairingInvitation
    init(timeout: UInt64 = 5000) throws {
        configuration = try .init(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            ownerUID: 501, transportUID: 20002, serviceName: "dev.remozio.fixture.pairing", teamID: "ABCDE12345",
            appIdentifier: "dev.remozio.mac", appHashes: [Data(repeating: 1, count: 20)],
            transportIdentifier: "dev.remozio.transport", transportHashes: [Data(repeating: 2, count: 20)], timeoutMilliseconds: timeout)
        let scope = try ChannelScope(macID: configuration.macID, accountID: configuration.accountID,
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
        let phone = try ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: 5, count: 32), envelopeVersions: [1], requests: [], auditVersions: [])
        let mac = try ChannelOffer(role: .mac, scope: scope, nonce: Data(repeating: 6, count: 32), envelopeVersions: [1], requests: [], auditVersions: [])
        proposal = try .init(phone: phone, transportKey: .init(keyID: Data(repeating: 7, count: 16), publicKey: transport.publicKey.x963Representation),
            decisionKey: .init(keyID: Data(repeating: 8, count: 16), publicKey: decision.publicKey.x963Representation),
            biometricKey: .init(keyID: Data(repeating: 9, count: 16), publicKey: biometric.publicKey.x963Representation))
        transcript = try .init(setupID: Data(repeating: 10, count: 16), challenge: Data(repeating: 11, count: 32), phone: phone, mac: mac,
            minimumEnvelopeVersion: 1, selectedEnvelopeVersion: 1, macAuthorityKey: authority.publicKey.x963Representation,
            macTransportKey: macTransport.publicKey.x963Representation, transportKey: proposal.transportKey,
            decisionKey: proposal.decisionKey, biometricKey: proposal.biometricKey, enrollmentTag: Data(repeating: 12, count: 32),
            replacement: nil, expectedTrustRevision: Data(repeating: 13, count: 16), issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000)
        invitation = try .init(macID: configuration.macID, accountID: configuration.accountID, label: "Fixture",
            authorityPublicKey: authority.publicKey.x963Representation, transportPublicKey: macTransport.publicKey.x963Representation, minimumEnvelopeVersion: 1)
    }
    func proof() throws -> Data { try biometric.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation }
    func receipt() throws -> Data { try authority.signature(for: transcript.signingInput(purpose: .macCommit)).rawRepresentation }
    func transportConfiguration() throws -> ApprovalTransportConfiguration {
        try .init(macID: configuration.macID, accountID: configuration.accountID, ownerUID: configuration.ownerUID,
            serviceUID: configuration.transportUID, authorityServiceName: "dev.remozio.fixture.authority", teamID: "ABCDE12345",
            authorityIdentifier: "dev.remozio.authority", authorityHashes: [Data(repeating: 3, count: 20)],
            identityReference: Data([1]), identityPublicKeyInfo: macTransport.publicKey.derRepresentation)
    }
}
final class PairingControlIngressFixture: TransportPairingIngress, @unchecked Sendable {
    private let lock = NSLock()
    private var event: (@Sendable (DirectListenerEvent) -> Void)?
    private var handler: (@Sendable (any TransportPairingPeer) async throws -> Void)?
    private var tasks: [Task<Void, Never>] = []
    private var closed = false
    private(set) var starts = 0
    func prepare(event: @escaping @Sendable (DirectListenerEvent) -> Void,
                 handler: @escaping @Sendable (any TransportPairingPeer) async throws -> Void) {
        lock.withLock { self.event = event; self.handler = handler }
    }
    func start() throws { let event = lock.withLock { starts += 1; return self.event }; event?(.ready(port: 4321)) }
    func accept(_ peer: any TransportPairingPeer) {
        lock.withLock {
            guard !closed, let handler else { peer.abort(); return }
            tasks.append(Task { do { try await handler(peer) } catch {} })
        }
    }
    func close() { lock.withLock { closed = true; for task in tasks { task.cancel() } } }
    func closeAndWait() async { close(); let tasks = lock.withLock { self.tasks }; for task in tasks { await task.value } }
    func owner(_ configuration: TransportPairingControlConfiguration) -> TransportPairingSetupOwner {
        .init(configuration: configuration, factory: { [self] _, event, handler in prepare(event: event, handler: handler); return self })
    }
}
actor PairingControlPeerFixture: TransportPairingPeer {
    private let aborted = Mutex(false)
    let value: PairingPhoneProposal
    var proof: Data?
    let holdAfterAbort: Bool
    private var waiting: CheckedContinuation<Data, any Error>?
    private var closed = false
    var receipts: [Data] = []
    var stages = 0
    var reading: Bool { waiting != nil }
    var isClosed: Bool { aborted.withLock { $0 } }
    init(_ value: PairingPhoneProposal, proof: Data? = nil, holdAfterAbort: Bool = false) {
        self.value = value; self.proof = proof; self.holdAfterAbort = holdAfterAbort
    }
    func proposal() async throws -> PairingPhoneProposal { value }
    func stage(_ transcript: PairingTranscript) async throws { stages += 1 }
    func receiveProof() async throws -> Data {
        if let proof { return proof }
        return try await withCheckedThrowingContinuation { waiting = $0 }
    }
    func sendReceipt(_ signature: Data) async throws { receipts.append(signature) }
    nonisolated func abort() { aborted.withLock { $0 = true }; Task { await self.close() } }
    func close() async {
        guard !closed else { return }; closed = true
        if !holdAfterAbort { let old = waiting; waiting = nil; old?.resume(throwing: TransportPairingControlError.closed) }
    }
    func release(_ proof: Data) { let old = waiting; waiting = nil; old?.resume(returning: proof) }
}
final class PairingControlLocalDriver: TransportPairingDriver, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var endpoint: TransportPairingXPCEndpoint?
    private var closed: (@Sendable () -> Void)?
    var holdReceipt = false
    var holdSnapshot = false
    var helloVersion: UInt64?
    var snapshotOverride: Data?
    var calls: [String] = []
    private var lateReceipt: (@Sendable (TransportPairingReply) -> Void)?
    private var lateSnapshot: (@Sendable (TransportPairingReply) -> Void)?
    init(owner: TransportPairingSetupOwner) {
        endpoint = TransportPairingXPCEndpoint(owner: owner, verify: {}, invalidate: { [weak self] in self?.invalidated() })
    }
    func start(closed: @escaping @Sendable () -> Void) { lock.withLock { self.closed = closed } }
    func invoke(_ call: TransportPairingCall, reply: @escaping @Sendable (TransportPairingReply) -> Void) {
        lock.withLock {
            guard let endpoint else { reply(.failed); return }
            switch call {
            case .hello:
                calls.append("hello"); if let helloVersion { reply(.number(helloVersion)) } else { endpoint.setupHello { reply(.number($0)) } }
            case .begin(let bytes): calls.append("begin"); endpoint.beginSetup(bytes) { reply(.number($0)) }
            case .snapshot:
                calls.append("snapshot")
                if holdSnapshot { lateSnapshot = reply }
                else if let snapshotOverride { reply(.bytes(snapshotOverride)) }
                else { endpoint.setupCandidates { reply(.bytes($0)) } }
            case .stage(let id, let bytes): calls.append("stage"); endpoint.stageSetup(id, transcript: bytes) { reply(.flag($0)) }
            case .receipt(let id, let signature):
                calls.append("receipt")
                if holdReceipt { lateReceipt = reply; endpoint.deliverSetupReceipt(id, signature: signature) { _ in } }
                else { endpoint.deliverSetupReceipt(id, signature: signature) { reply(.flag($0)) } }
            case .cancel(let id): calls.append("cancel"); endpoint.cancelSetupCandidate(id) { reply(.flag($0)) }
            case .stop: calls.append("stop"); endpoint.stopSetup { reply(.flag($0)) }
            }
        }
    }
    func close() { let endpoint = lock.withLock { self.endpoint }; endpoint?.close() }
    private func invalidated() { let closed = lock.withLock { self.closed }; closed?() }
    func counts(_ name: String) -> Int { lock.withLock { calls.filter { $0 == name }.count } }
    func deliverLateSnapshot(_ bytes: Data) { let old = lock.withLock { let old = lateSnapshot; lateSnapshot = nil; return old }; old?(.bytes(bytes)) }
    func deliverLateReceipt() { let old = lock.withLock { let old = lateReceipt; lateReceipt = nil; return old }; old?(.flag(true)) }
}

final class TransportPairingControlTests: XCTestCase, @unchecked Sendable {
    private func until(_ condition: () async throws -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(try await condition()) {
            guard ContinuousClock.now < deadline else { throw TransportPairingControlError.timedOut }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    private func candidate(_ client: TransportPairingChannel) async throws -> TransportPairingCandidate {
        try await until { try await !client.current().candidates.isEmpty }
        let snapshot = try await client.current()
        return try XCTUnwrap(snapshot.candidates.first)
    }
    func testProtectedMetadataAndStartupRoundTripPreserveExistingTransport() throws {
        let f = try TransportPairingFixture(), config = try TransportPairingControlConfiguration.decode(f.configuration.canonicalBytes)
        XCTAssertEqual(config.appPolicy.expectedUserID, 501); XCTAssertEqual(config.transportPolicy.expectedUserID, 20002)
        XCTAssertEqual(config.canonicalBytes, f.configuration.canonicalBytes)
        for port in [UInt16?.none, UInt16(4322)] {
            let value = try TransportPairingStartupConfiguration(transport: f.transportConfiguration(), control: config, relayPort: port)
            let decoded = try TransportPairingStartupConfiguration.decode(value.canonicalBytes)
            XCTAssertEqual(decoded.transport.canonicalBytes, try f.transportConfiguration().canonicalBytes)
            XCTAssertEqual(decoded.control.canonicalBytes, config.canonicalBytes); XCTAssertEqual(decoded.relayPort, port)
        }
        XCTAssertThrowsError(try TransportPairingStartupConfiguration(transport: f.transportConfiguration(), control: config, relayPort: 0))
        var fields: [UInt64: CBORValue]
        guard case .map(let parsed) = try DeterministicCBOR.decode(config.canonicalBytes, limits: .init(maxBytes: 4096, maxDepth: 2, maxItems: 128)) else { return XCTFail() }
        fields = parsed; fields[0] = .unsigned(2)
        XCTAssertThrowsError(try TransportPairingControlConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: .init(maxBytes: 4096, maxDepth: 2, maxItems: 128))))
        fields = parsed; fields[4] = fields[3]
        XCTAssertThrowsError(try TransportPairingControlConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: .init(maxBytes: 4096, maxDepth: 2, maxItems: 128))))
        fields = parsed; fields[14] = .null
        XCTAssertThrowsError(try TransportPairingControlConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: .init(maxBytes: 4096, maxDepth: 2, maxItems: 128))))
    }
    func testCandidateSnapshotsRejectContradictoryProofsAndDuplicateIDs() throws {
        let f = try TransportPairingFixture(), id = Data(repeating: 1, count: 16)
        let row = try TransportPairingCandidate(id: id, proposal: f.proposal, phase: .proposed, biometricProof: nil)
        let value = try TransportPairingSnapshot(port: 4321, candidates: [row])
        XCTAssertEqual(try TransportPairingSnapshot.decode(value.encode()).candidates.first?.id, id)
        XCTAssertThrowsError(try TransportPairingCandidate(id: id, proposal: f.proposal, phase: .proofReady, biometricProof: nil))
        XCTAssertThrowsError(try TransportPairingCandidate(id: id, proposal: f.proposal, phase: .proposed, biometricProof: f.proof()))
        XCTAssertThrowsError(try TransportPairingSnapshot(port: 4321, candidates: [row, row]))
        XCTAssertThrowsError(try TransportPairingSnapshot(port: 0, candidates: []))
        XCTAssertThrowsError(try TransportPairingSnapshot.decode(value.encode() + Data([0])))
    }
    func testLogicalAppControlTransfersOneVerifiedProofAndOneReceipt() async throws {
        let f = try TransportPairingFixture(), ingress = PairingControlIngressFixture(), owner = ingress.owner(f.configuration)
        let driver = PairingControlLocalDriver(owner: owner), client = TransportPairingChannel(configuration: f.configuration, driver: driver)
        let port = try await client.start(invitation: f.invitation); XCTAssertEqual(port, 4321)
        let peer = PairingControlPeerFixture(f.proposal, proof: try f.proof()); ingress.accept(peer)
        let candidate = try await candidate(client)
        try await client.stage(candidateID: candidate.id, transcript: f.transcript)
        try await until { try await client.current().candidates.first?.phase == .proofReady }
        let receipt = try f.receipt(); try await client.deliverReceipt(candidateID: candidate.id, signature: receipt)
        do { try await client.deliverReceipt(candidateID: candidate.id, signature: receipt); XCTFail() } catch {}
        XCTAssertEqual(driver.counts("stage"), 1); XCTAssertEqual(driver.counts("receipt"), 1)
        let sent = await peer.receipts; XCTAssertEqual(sent, [receipt])
        await owner.closeAndWait(); await client.close()
    }
    func testLostReceiptReplyClosesWithoutRepeatingTheSubmission() async throws {
        let f = try TransportPairingFixture(timeout: 100), ingress = PairingControlIngressFixture(), owner = ingress.owner(f.configuration)
        let driver = PairingControlLocalDriver(owner: owner), client = TransportPairingChannel(configuration: f.configuration, driver: driver)
        _ = try await client.start(invitation: f.invitation)
        let peer = PairingControlPeerFixture(f.proposal, proof: try f.proof()); ingress.accept(peer)
        let candidate = try await candidate(client); try await client.stage(candidateID: candidate.id, transcript: f.transcript)
        try await until { try await client.current().candidates.first?.phase == .proofReady }
        driver.holdReceipt = true
        do { try await client.deliverReceipt(candidateID: candidate.id, signature: f.receipt()); XCTFail() } catch {}
        driver.deliverLateReceipt()
        do { try await client.deliverReceipt(candidateID: candidate.id, signature: f.receipt()); XCTFail() } catch {}
        XCTAssertEqual(driver.counts("receipt"), 1)
        let receipts = await peer.receipts; XCTAssertEqual(receipts.count, 1)
        await owner.closeAndWait()
    }
    func testUnknownControlVersionCannotStartTheNetworkListener() async throws {
        let f = try TransportPairingFixture(), ingress = PairingControlIngressFixture(), owner = ingress.owner(f.configuration)
        let driver = PairingControlLocalDriver(owner: owner); driver.helloVersion = 2
        let client = TransportPairingChannel(configuration: f.configuration, driver: driver)
        do { _ = try await client.start(invitation: f.invitation); XCTFail() } catch {}
        XCTAssertEqual(driver.counts("begin"), 0); XCTAssertEqual(ingress.starts, 0)
        await owner.closeAndWait()
    }
    func testInvalidProofNeverReachesReceiptDelivery() async throws {
        let f = try TransportPairingFixture(), ingress = PairingControlIngressFixture(), owner = ingress.owner(f.configuration)
        let driver = PairingControlLocalDriver(owner: owner), client = TransportPairingChannel(configuration: f.configuration, driver: driver)
        _ = try await client.start(invitation: f.invitation)
        let peer = PairingControlPeerFixture(f.proposal); ingress.accept(peer)
        let candidate = try await candidate(client); try await client.stage(candidateID: candidate.id, transcript: f.transcript)
        try await until { await peer.reading }; await peer.release(Data(count: 64))
        try await until { try await owner.snapshot().candidates.first?.phase == .proofReady }
        do { _ = try await client.current(); XCTFail() } catch {}
        XCTAssertEqual(driver.counts("receipt"), 0); await owner.closeAndWait()
    }
    func testConcurrentCloseWaitsForTheActualBlockedProofReader() async throws {
        let f = try TransportPairingFixture(), ingress = PairingControlIngressFixture(), owner = ingress.owner(f.configuration)
        _ = try await owner.begin(f.invitation)
        let peer = PairingControlPeerFixture(f.proposal, holdAfterAbort: true); ingress.accept(peer)
        try await until { try await !owner.snapshot().candidates.isEmpty }
        let snapshot = try await owner.snapshot()
        let id = try XCTUnwrap(snapshot.candidates.first?.id)
        try await owner.stage(candidateID: id, transcript: f.transcript); try await until { await peer.reading }
        let complete = Mutex(0)
        let first = Task { @Sendable in await owner.closeAndWait(); complete.withLock { $0 += 1 } }
        try await until { await peer.isClosed }
        let second = Task { @Sendable in await owner.closeAndWait(); complete.withLock { $0 += 1 } }
        try await Task.sleep(for: .milliseconds(40)); XCTAssertEqual(complete.withLock { $0 }, 0)
        try await peer.release(f.proof()); await first.value; await second.value
        XCTAssertEqual(complete.withLock { $0 }, 2)
        do { _ = try await owner.snapshot(); XCTFail() } catch {}
    }
    func testPeerExpiryRemovesTheCandidateAndCannotReopenTheOwner() async throws {
        let f = try TransportPairingFixture(), ingress = PairingControlIngressFixture(), owner = ingress.owner(f.configuration)
        _ = try await owner.begin(f.invitation)
        let peer = PairingControlPeerFixture(f.proposal); ingress.accept(peer)
        try await until { try await !owner.snapshot().candidates.isEmpty }
        peer.abort(); try await until { try await owner.snapshot().candidates.isEmpty }
        await owner.closeAndWait()
        do { _ = try await owner.begin(f.invitation); XCTFail() } catch {}
        XCTAssertEqual(ingress.starts, 1)
    }
    func testChangedProposalForAnExistingCandidateCannotReachStaging() async throws {
        let f = try TransportPairingFixture(), ingress = PairingControlIngressFixture(), owner = ingress.owner(f.configuration)
        let driver = PairingControlLocalDriver(owner: owner), client = TransportPairingChannel(configuration: f.configuration, driver: driver)
        _ = try await client.start(invitation: f.invitation)
        let peer = PairingControlPeerFixture(f.proposal); ingress.accept(peer)
        let candidate = try await candidate(client)
        let phone = try ChannelOffer(role: .phone, scope: f.proposal.phone.scope, nonce: Data(repeating: 55, count: 32),
            envelopeVersions: [1], requests: [], auditVersions: [])
        let changed = try PairingPhoneProposal(phone: phone, transportKey: f.proposal.transportKey,
            decisionKey: f.proposal.decisionKey, biometricKey: f.proposal.biometricKey)
        driver.snapshotOverride = try TransportPairingSnapshot(port: 4321, candidates: [
            .init(id: candidate.id, proposal: changed, phase: .proposed, biometricProof: nil)]).encode()
        do { _ = try await client.current(); XCTFail() } catch {}
        XCTAssertEqual(driver.counts("stage"), 0); await owner.closeAndWait()
    }
    func testCallerCancellationSettlesAReadAndRejectsItsLateReply() async throws {
        let f = try TransportPairingFixture(), ingress = PairingControlIngressFixture(), owner = ingress.owner(f.configuration)
        let driver = PairingControlLocalDriver(owner: owner), client = TransportPairingChannel(configuration: f.configuration, driver: driver)
        _ = try await client.start(invitation: f.invitation); driver.holdSnapshot = true
        let read = Task { try await client.current() }
        try await until { driver.counts("snapshot") == 1 }; read.cancel()
        do { _ = try await read.value; XCTFail() } catch {}
        driver.deliverLateSnapshot(try TransportPairingSnapshot(port: 4321, candidates: []).encode())
        do { _ = try await client.current(); XCTFail() } catch {}
        XCTAssertEqual(driver.counts("snapshot"), 1); await owner.closeAndWait()
    }
    func testUnderlyingByteChannelFailureReleasesAnUnstagedCandidate() async throws {
        let f = try TransportPairingFixture(), ingress = PairingControlIngressFixture(), owner = ingress.owner(f.configuration)
        _ = try await owner.begin(f.invitation)
        let proposal = try PairingSetupFrame.proposal(f.proposal).encode(), size = UInt32(proposal.count)
        let bytes = Data([UInt8(size >> 24), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)]) + proposal
        final class Driver: ByteConnectionDriver, @unchecked Sendable {
            let event = Mutex<(@Sendable (ByteConnectionEvent) -> Void)?>(nil)
            let bytes: Data
            init(_ bytes: Data) { self.bytes = bytes }
            func start(_ callback: @escaping @Sendable (ByteConnectionEvent) -> Void) { event.withLock { $0 = callback }; callback(.ready) }
            func receive(_ result: @escaping @Sendable (Data?, Bool, Bool) -> Void) { result(bytes, false, false) }
            func send(_ data: Data, result: @escaping @Sendable (Bool) -> Void) { result(false) }
            func cancel() {}
            func fail() { let callback = event.withLock { $0 }; callback?(.failed) }
        }
        let driver = Driver(bytes), channel = NetworkByteChannel(driver: driver)
        try await channel.start()
        let session = try await PairingSetupNetworkSession.acceptStarted(channel: channel, invitation: f.invitation,
            peerPoint: f.transport.publicKey.x963Representation, timeoutMilliseconds: 300000)
        ingress.accept(session)
        try await until { try await owner.snapshot().candidates.count == 1 }
        driver.fail()
        try await until { await session.isClosed }
        try await until { try await owner.snapshot().candidates.isEmpty }
        await owner.closeAndWait()
    }
    func testEndpointVerifiesTheOriginalInvocationBeforeSchedulingSetup() async throws {
        let f = try TransportPairingFixture(), ingress = PairingControlIngressFixture(), owner = ingress.owner(f.configuration)
        let checks = Mutex(0), closed = Mutex(0)
        let endpoint = TransportPairingXPCEndpoint(owner: owner, verify: { checks.withLock { $0 += 1 }; throw XPCPeerPolicyError.wrongConnection },
            invalidate: { closed.withLock { $0 += 1 } })
        let invitation = try f.invitation.encode()
        let result = await withCheckedContinuation { c in endpoint.beginSetup(invitation) { c.resume(returning: $0) } }
        XCTAssertEqual(result, 0); XCTAssertEqual(checks.withLock { $0 }, 1); XCTAssertEqual(closed.withLock { $0 }, 1)
        XCTAssertEqual(ingress.starts, 0); await endpoint.closeAndWait()
    }
}
