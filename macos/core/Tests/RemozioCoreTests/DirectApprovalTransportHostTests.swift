import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

@MainActor
final class DirectApprovalTransportHostTests: XCTestCase {
    private enum Failure: Error { case injected }
    nonisolated private static func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private final class FakeListener: OwnedDirectListener, @unchecked Sendable {
        let generation: UUID
        let peers: [DirectApprovalPeer]
        private let lock = NSLock()
        private var closed = false
        var isClosed: Bool { lock.withLock { closed } }
        init(_ generation: UUID, _ peers: [DirectApprovalPeer]) { self.generation = generation; self.peers = peers }
        func start() throws { }
        func close() { lock.withLock { closed = true } }
        func closeAndWait() async { close() }
    }
    private final class Factory: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [FakeListener] = []
        private var fail = false
        var listeners: [FakeListener] { lock.withLock { values } }
        func failNext() { lock.withLock { fail = true } }
        func make(_ generation: UUID, _ peers: [DirectApprovalPeer]) throws -> FakeListener {
            try lock.withLock {
                if fail { fail = false; throw Failure.injected }
                if let previous = values.last { XCTAssertTrue(previous.isClosed) }
                let value = FakeListener(generation, peers); values.append(value); return value
            }
        }
    }
    private actor Validator {
        var calls = 0
        var allowed = true
        func deny() { allowed = false }
        func validate(_ peer: DirectApprovalPeer, _ revision: UUID) throws {
            calls += 1
            if !allowed { throw Failure.injected }
        }
    }
    private actor Gate {
        var started = false
        var observer: CheckedContinuation<Void, Never>?
        var pending: CheckedContinuation<Void, Never>?
        func validate() async {
            started = true; observer?.resume(); observer = nil
            await withCheckedContinuation { pending = $0 }
        }
        func waitUntilStarted() async {
            if !started { await withCheckedContinuation { observer = $0 } }
        }
        func release() { pending?.resume(); pending = nil }
    }
    private func trust(empty: Bool = false, maximum: Int = 1024, revision: UUID = UUID()) throws -> DirectApprovalTrust {
        let peer = try DirectApprovalPeer(scope: ChannelScope(macID: Self.id(1), accountID: Self.id(2),
            phoneID: Self.id(5), enrollmentEpoch: Self.id(9)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation,
            requests: [], auditVersions: [], maximumPayloadBytes: maximum)
        return DirectApprovalTrust(macID: Self.id(1), accountID: Self.id(2), revision: revision, peers: empty ? [] : [peer])
    }
    private func host(_ factory: Factory, _ validator: Validator = Validator()) -> DirectApprovalTransportHost {
        DirectApprovalTransportHost(macID: Self.id(1), accountID: Self.id(2),
            factory: { generation, peers, _, _ in try factory.make(generation, peers) },
            validatePeer: { peer, revision in try await validator.validate(peer, revision) })
    }

    func testEmptySnapshotAndRevocationCloseListenerAndRejectOldSession() async throws {
        let factory = Factory(), host = host(factory)
        try await host.replaceTrust(trust(empty: true)); try await host.start()
        let empty = await host.state
        XCTAssertEqual(empty, .noEligiblePhones); XCTAssertTrue(factory.listeners.isEmpty)
        try await host.replaceTrust(trust())
        let listener = try XCTUnwrap(factory.listeners.last)
        let session = try await host.admit(listener.peers[0], generation: listener.generation)
        try await host.replaceTrust(trust(empty: true))
        XCTAssertTrue(listener.isClosed)
        do { try await host.validate(session); XCTFail("Old session accepted") } catch { }
        await host.close()
    }

    func testPolicyReplacementAndRestartRejectStaleEventsAndSessions() async throws {
        let factory = Factory(), host = host(factory), revision = UUID()
        try await host.replaceTrust(trust(revision: revision)); try await host.start()
        let first = try XCTUnwrap(factory.listeners.last)
        let old = try await host.admit(first.peers[0], generation: first.generation)
        try await host.replaceTrust(trust(maximum: 2048, revision: revision))
        let second = try XCTUnwrap(factory.listeners.last)
        XCTAssertEqual(second.peers[0].maximumPayloadBytes, 2048)
        XCTAssertNotEqual(first.generation, second.generation)
        await host.changed(.failed, generation: first.generation)
        await host.changed(.ready(port: 999), generation: first.generation)
        let state = await host.state
        XCTAssertEqual(state, .starting); XCTAssertFalse(second.isClosed)
        do { try await host.validate(old); XCTFail("Old policy session accepted") } catch { }
        await host.stop(); XCTAssertTrue(second.isClosed)
        try await host.start(); XCTAssertEqual(factory.listeners.count, 3)
        await host.close()
        do { try await host.start(); XCTFail("Closed host restarted") } catch { }
    }

    func testAuthorityDisconnectRequiresFreshSnapshotAndRejectsInFlightValidation() async throws {
        let factory = Factory(), gate = Gate()
        let host = DirectApprovalTransportHost(macID: Self.id(1), accountID: Self.id(2),
            factory: { generation, peers, _, _ in try factory.make(generation, peers) },
            validatePeer: { _, _ in await gate.validate() })
        try await host.replaceTrust(trust()); try await host.start()
        let listener = try XCTUnwrap(factory.listeners.last)
        let pending = Task { try await host.admit(listener.peers[0], generation: listener.generation) }
        await gate.waitUntilStarted()
        await host.authorityDisconnected()
        XCTAssertTrue(listener.isClosed)
        await gate.release()
        do { _ = try await pending.value; XCTFail("Late authority response accepted") } catch { }
        do { try await host.start(); XCTFail("Disconnected authority accepted") } catch { }
        try await host.replaceTrust(trust())
        XCTAssertEqual(factory.listeners.count, 2)
        await host.close()
    }

    func testEachValidationContactsAuthorityAndPropagatesDenial() async throws {
        let factory = Factory(), validator = Validator(), host = host(factory, validator)
        try await host.replaceTrust(trust()); try await host.start()
        let listener = try XCTUnwrap(factory.listeners.last)
        let session = try await host.admit(listener.peers[0], generation: listener.generation)
        try await host.validate(session)
        await validator.deny()
        do { try await host.validate(session); XCTFail("Authority denial ignored") } catch { }
        let count = await validator.calls
        XCTAssertEqual(count, 3)
        await host.close()
    }

    func testFailureRetryAndWrongScopeNeverKeepOldListener() async throws {
        let factory = Factory(), host = host(factory)
        try await host.replaceTrust(trust()); factory.failNext()
        do { try await host.start(); XCTFail("Expected listener failure") } catch { }
        let failed = await host.state
        XCTAssertEqual(failed, .failed)
        try await host.start()
        let listener = try XCTUnwrap(factory.listeners.last)
        let wrong = DirectApprovalTrust(macID: Self.id(8), accountID: Self.id(2), revision: UUID(), peers: [])
        do { try await host.replaceTrust(wrong); XCTFail("Wrong authority scope accepted") } catch { }
        XCTAssertTrue(listener.isClosed)
        do { try await host.start(); XCTFail("Old trust retained") } catch { }
        await host.close()
    }
}
