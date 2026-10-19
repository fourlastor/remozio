import CryptoKit
import Foundation
import Network
import Security
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class DirectTransportDrainTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class Listener: OwnedDirectListener, Sendable {
        struct State { var closed = false; var gate: CheckedContinuation<Void, Never>? }
        let value = Mutex(State())
        func start() throws {}
        func close() { value.withLock { $0.closed = true } }
        func closeAndWait() async {
            close(); await withCheckedContinuation { c in value.withLock { $0.gate = c } }
        }
        func finish() { value.withLock { s in let c = s.gate; s.gate = nil; return c }?.resume() }
    }
    private func trust() throws -> DirectApprovalTrust {
        let peer = try DirectApprovalPeer(scope: .init(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, requests: [], auditVersions: [], maximumPayloadBytes: 1024)
        return .init(macID: peer.scope.macID, accountID: peer.scope.accountID, revision: UUID(), peers: [peer])
    }
    private func until(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() { guard ContinuousClock.now < deadline else { throw Failed() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testServiceCloseJoinsTheCurrentListenerDespiteCancelledWaiter() async throws {
        let listener = Listener(), trust = try trust()
        let host = DirectApprovalTransportHost(macID: trust.macID, accountID: trust.accountID,
            factory: { _, _, _, _ in listener }, validatePeer: { _, _ in })
        try await host.replaceTrust(trust); try await host.start()
        let feed = AuthorityTrustFeed(macID: trust.macID, accountID: trust.accountID, factory: { _ in XCTFail(); throw Failed() })
        let service = DirectApprovalTransportService(feed: feed, host: host), finished = Mutex(false)
        let close = Task { await service.closeAndWait(); finished.withLock { $0 = true } }; close.cancel()
        defer { listener.finish() }
        try await until { finished.withLock { $0 } || listener.value.withLock { $0.gate != nil } }
        XCTAssertFalse(finished.withLock { $0 }); XCTAssertTrue(listener.value.withLock { $0.closed })
        listener.finish(); await close.value; XCTAssertTrue(finished.withLock { $0 })
    }
    func testServiceCloseAlsoJoinsListenerRetiredByTrustReplacement() async throws {
        let old = Listener(), current = Listener(), made = Mutex(0), trust = try trust()
        let host = DirectApprovalTransportHost(macID: trust.macID, accountID: trust.accountID,
            factory: { _, _, _, _ in made.withLock { $0 += 1; return $0 } == 1 ? old : current }, validatePeer: { _, _ in })
        try await host.replaceTrust(trust); try await host.start(); try await host.replaceTrust(self.trust())
        let feed = AuthorityTrustFeed(macID: trust.macID, accountID: trust.accountID, factory: { _ in XCTFail(); throw Failed() })
        let service = DirectApprovalTransportService(feed: feed, host: host), finished = Mutex(false)
        let close = Task { await service.closeAndWait(); finished.withLock { $0 = true } }
        defer { old.finish(); current.finish() }
        try await until { finished.withLock { $0 } || (old.value.withLock { $0.gate != nil } && current.value.withLock { $0.gate != nil }) }
        XCTAssertFalse(finished.withLock { $0 })
        current.finish(); try await Task.sleep(for: .milliseconds(10)); XCTAssertFalse(finished.withLock { $0 })
        old.finish(); await close.value
    }
    func testTaskReservationWaitsForLateInstallationAndActualTerminalResult() async throws {
        let work = OwnedTaskHandoff(), gate = Mutex<CheckedContinuation<Void, Never>?>(nil), done = Mutex(false)
        let waiter = Task { await work.wait(); done.withLock { $0 = true } }; waiter.cancel(); work.cancel()
        try await Task.sleep(for: .milliseconds(10)); XCTAssertFalse(done.withLock { $0 })
        let task = Task { await withCheckedContinuation { c in gate.withLock { $0 = c } } }
        work.install(task); try await until { gate.withLock { $0 != nil } }
        XCTAssertFalse(done.withLock { $0 }); XCTAssertTrue(task.isCancelled)
        gate.withLock { c in let old = c; c = nil; return old }?.resume()
        await waiter.value; XCTAssertTrue(done.withLock { $0 })
    }
    func testRegistryJoinsReservedWorkAndConcurrentCancelledClosers() async throws {
        let registry = OwnedTaskHandoffRegistry(), work = registry.reserve(), done = Mutex(0)
        let gate = Mutex<CheckedContinuation<Void, Never>?>(nil)
        let first = Task { @Sendable in await registry.waitAll(); done.withLock { $0 += 1 } }, second = Task { @Sendable in await registry.waitAll(); done.withLock { $0 += 1 } }
        first.cancel(); registry.cancelAll()
        try await Task.sleep(for: .milliseconds(10)); XCTAssertEqual(done.withLock { $0 }, 0)
        work.install(Task { await withCheckedContinuation { c in gate.withLock { $0 = c } } })
        try await until { gate.withLock { $0 != nil } }; XCTAssertEqual(done.withLock { $0 }, 0)
        gate.withLock { c in let old = c; c = nil; return old }?.resume()
        await first.value; await second.value; XCTAssertEqual(done.withLock { $0 }, 2)
    }

    func testNativeLoopbackCloseJoinsAnUnfinishedTLSHandshakeAndReleasesBudgetOnce() async throws {
        let key = P256.Signing.PrivateKey()
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits as String: 256]
        let nativeKey = try XCTUnwrap(SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, nil))
        let now = Date(), certificate = try TransportTLSCertificate.issue(key: nativeKey,
            notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
        let record = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-transport-identity"),
            2: .bytes(key.x963Representation), 3: .bytes(certificate)]), limits: CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 128))
        let identity = try TransportFileIdentity.load(bytes: record, publicKeyInfo: key.publicKey.derRepresentation)
        let trust = try trust(), port = Mutex<UInt16?>(nil), budget = try AuthorityXPCWorkBudget(maximum: 1)
        let listener = try DirectApprovalListener(identity: identity, peers: trust.peers, binding: .loopback,
            maximumConnections: 1, timeoutMilliseconds: 10000, event: { event in
                if case .ready(let value) = event { port.withLock { $0 = value } }
            }, handler: { _, _ in XCTFail("A raw TCP fixture must never pass mutual TLS or enter the handler") }, sharedWorkBudget: budget)
        try listener.start(); defer { listener.close() }
        try await until { port.withLock { $0 != nil } }
        let number = try XCTUnwrap(port.withLock { $0 }), endpoint = try XCTUnwrap(NWEndpoint.Port(rawValue: number))
        let raw = NWConnection(host: "127.0.0.1", port: endpoint, using: .tcp)
        raw.start(queue: DispatchQueue(label: "dev.remozio.tests.raw-direct-handshake")); defer { raw.cancel() }
        try await until { listener.retainedConnectionCount == 1 }
        let unexpectedlyFree = budget.acquire(); if unexpectedlyFree { budget.release() }; XCTAssertFalse(unexpectedlyFree)
        let first = Task { await listener.closeAndWait() }, second = Task { await listener.closeAndWait() }; first.cancel()
        await first.value; await second.value
        XCTAssertEqual(listener.retainedConnectionCount, 0)
        let released = budget.acquire(); XCTAssertTrue(released)
        if released { XCTAssertFalse(budget.acquire()); budget.release() }
    }

    func testLegacyCloseRemainsImmediateAndExplicitJoinRetainsTheDrain() async throws {
        let listener = Listener(), trust = try trust()
        let host = DirectApprovalTransportHost(macID: trust.macID, accountID: trust.accountID,
            factory: { _, _, _, _ in listener }, validatePeer: { _, _ in })
        try await host.replaceTrust(trust); try await host.start()
        let feed = AuthorityTrustFeed(macID: trust.macID, accountID: trust.accountID, factory: { _ in XCTFail(); throw Failed() })
        let service = DirectApprovalTransportService(feed: feed, host: host)
        await service.close(); XCTAssertTrue(listener.value.withLock { $0.closed })
        let done = Mutex(false), join = Task { await service.closeAndWait(); done.withLock { $0 = true } }
        defer { listener.finish() }; try await until { listener.value.withLock { $0.gate != nil } }
        XCTAssertFalse(done.withLock { $0 }); listener.finish(); await join.value
    }

}
