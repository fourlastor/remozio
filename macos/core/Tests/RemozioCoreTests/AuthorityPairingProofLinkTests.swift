import Darwin
import Foundation
import Security
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityPairingProofLinkTests: XCTestCase, @unchecked Sendable {
    private enum FixtureError: Error { case invalidSignature, retiredRole }

    private final class ResultBox<Value: Sendable>: Sendable {
        let value = Mutex<Value?>(nil)
    }

    /// An anonymous bootstrap listener pins the running test binary. No installed service is used.
    private final class Fixture: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        let listener = NSXPCListener.anonymous()
        let links: AuthorityPairingProofLinks
        final class Events: Sendable {
            let roleCurrent = Mutex(true)
            let acceptedProofLinks = Mutex(0)
            let closedBootstrapLinks = Mutex(0)
        }
        let events: Events
        let requirement: String
        let policy: XPCPeerPolicy
        let registry: AuthorityConnectionRegistry
        private let budget = try! AuthorityXPCWorkBudget()
        private let peerPIDOffset: pid_t
        private let enableProofs: Bool

        init(timeout: Duration = .seconds(5), peerPIDOffset: pid_t = 0, enableProofs: Bool = true,
             rejectProofSignature: Bool = false) throws {
            self.peerPIDOffset = peerPIDOffset
            self.enableProofs = enableProofs
            var code: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
            guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
                  SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
                  SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
                  let fields = info as? [String: Any], let hash = fields[kSecCodeInfoUnique as String] as? Data,
                  hash.count == 20 else { throw FixtureError.invalidSignature }
            let requirement = "cdhash H\"" + XPCPeerPolicy.hexadecimalCodeDirectoryHash(hash) + "\""
            self.requirement = requirement
            let policy = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.remozio.fixture",
                                           approvedCodeDirectoryHashes: [hash], expectedUserID: geteuid())
            self.policy = policy
            registry = try .init(maximum: 8, timeoutMilliseconds: 2_000)
            let events = Events()
            self.events = events
            let proofRequirement = rejectProofSignature
                ? "cdhash H\"" + XPCPeerPolicy.hexadecimalCodeDirectoryHash(Data(hash.map { $0 ^ 0xff })) + "\""
                : requirement
            links = .init(policy: policy, timeout: timeout, verifyCurrent: {
                guard events.roleCurrent.withLock({ $0 }) else { throw FixtureError.retiredRole }
            }, configureListener: { $0.setConnectionCodeSigningRequirement(proofRequirement) },
               configureConnection: {
                   $0.setCodeSigningRequirement(proofRequirement)
                   events.acceptedProofLinks.withLock { $0 += 1 }
               })
            super.init()
            try registry.start()
            listener.setConnectionCodeSigningRequirement(requirement)
            listener.delegate = self
            listener.activate()
        }

        deinit {
            links.close()
            listener.invalidate()
            registry.close()
        }

        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            guard listener === self.listener, let id = registry.reserve() else { return false }
            let invocation = XPCInvocationGuard(connection: connection, policy: policy)
            let offset = peerPIDOffset
            let endpoint = AuthorityXPCEndpoint(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                budget: budget, verify: { _ = try invocation.verifyInvocation() }, pairingProofs: enableProofs ? links : nil,
                verifyProofPeer: {
                    let peer = try invocation.verifyInvocation()
                    return .init(processID: peer.processID + offset, userID: peer.userID, auditSessionID: peer.auditSessionID)
                }, invalidate: { [weak registry, weak connection, events] in
                    connection?.invalidate()
                    registry?.remove(id)
                    events.closedBootstrapLinks.withLock { $0 += 1 }
                },
                onHandshake: { [weak registry] in registry?.handshake(id) }, snapshot: { throw FixtureError.retiredRole },
                validate: { _ in false })
            connection.exportedInterface = NSXPCInterface(with: TransportAuthorityXPCProtocol.self)
            connection.exportedObject = endpoint
            connection.setCodeSigningRequirement(requirement)
            connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
            connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }
            return registry.install(Owned(connection: connection, endpoint: endpoint), id: id)
        }

        private final class Owned: OwnedAuthorityConnection, @unchecked Sendable {
            let connection: NSXPCConnection
            let endpoint: AuthorityXPCEndpoint
            init(connection: NSXPCConnection, endpoint: AuthorityXPCEndpoint) {
                self.connection = connection
                self.endpoint = endpoint
            }
            func activate() { connection.activate() }
            func close() { endpoint.close(); connection.invalidate() }
        }
    }

    private func exchange<Value: Sendable>(fallback: Value,
        send: (@escaping @Sendable (Value) -> Void) -> Void) async -> Value {
        let expected = expectation(description: "XPC reply")
        let result = ResultBox<Value>()
        send { value in
            let first = result.value.withLock {
                guard $0 == nil else { return false }
                $0 = value
                return true
            }
            if first { expected.fulfill() }
        }
        await fulfillment(of: [expected], timeout: 3)
        return result.value.withLock { $0 ?? fallback }
    }

    private func bootstrap(_ fixture: Fixture) async throws -> NSXPCConnection {
        let connection = NSXPCConnection(listenerEndpoint: fixture.listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: TransportAuthorityXPCProtocol.self)
        connection.setCodeSigningRequirement(fixture.requirement)
        connection.activate()
        let version: UInt64 = await exchange(fallback: 0) { reply in
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(0) }) as? any TransportAuthorityXPCProtocol
            else { reply(0); return }
            proxy.hello(reply: reply)
        }
        guard version == 1 else { connection.invalidate(); throw FixtureError.retiredRole }
        return connection
    }

    private func offer(on connection: NSXPCConnection) async -> (UInt64, NSXPCListenerEndpoint?) {
        await exchange(fallback: (0, nil)) { reply in
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply((0, nil)) }) as? any TransportAuthorityXPCProtocol,
                  let open = proxy.openPairingProof else { reply((0, nil)); return }
            open { reply(($0, $1)) }
        }
    }

    private func waitFor(_ condition: () -> Bool) async throws -> Bool {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !condition() && ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(20))
        }
        return condition()
    }

    private func waitForOffer(on connection: NSXPCConnection) async throws -> NSXPCListenerEndpoint {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        repeat {
            let result = await offer(on: connection)
            if let endpoint = result.1 { return endpoint }
            try await Task.sleep(for: .milliseconds(20))
        } while ContinuousClock.now < deadline
        throw AuthorityXPCEndpointError.unavailable
    }

    private func proofConnection(to endpoint: NSXPCListenerEndpoint, requirement: String,
                                 useGeneralInterface: Bool = false) -> NSXPCConnection {
        let connection = NSXPCConnection(listenerEndpoint: endpoint)
        connection.remoteObjectInterface = useGeneralInterface
            ? NSXPCInterface(with: TransportAuthorityXPCProtocol.self)
            : NSXPCInterface(with: AuthorityPairingProofXPCProtocol.self)
        connection.setCodeSigningRequirement(requirement)
        connection.activate()
        return connection
    }

    private func hello(on connection: NSXPCConnection) async -> UInt64 {
        await exchange(fallback: 0) { reply in
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(0) }) as? any AuthorityPairingProofXPCProtocol
            else { reply(0); return }
            proxy.hello(reply: reply)
        }
    }

    func testProofSlotIsAvailableAtGeneralCapacityAndRejectsASecondLink() async throws {
        let fixture = try Fixture()
        var general: [NSXPCConnection] = []
        defer { general.forEach { $0.invalidate() } }
        for _ in 0..<8 { general.append(try await bootstrap(fixture)) }
        XCTAssertNil(fixture.registry.reserve())
        let offered = await offer(on: general[0])
        XCTAssertEqual(offered.0, 1)
        let endpoint = try XCTUnwrap(offered.1)
        let first = proofConnection(to: endpoint, requirement: fixture.requirement)
        defer { first.invalidate() }
        let firstVersion = await hello(on: first)
        XCTAssertEqual(firstVersion, 1)

        let second = proofConnection(to: endpoint, requirement: fixture.requirement)
        defer { second.invalidate() }
        let secondVersion = await hello(on: second)
        XCTAssertEqual(secondVersion, 0)
        let another = await offer(on: general[1])
        XCTAssertEqual(another.0, 1)
        XCTAssertNil(another.1)
        XCTAssertEqual(fixture.events.acceptedProofLinks.withLock { $0 }, 1)
    }

    func testNativeInvalidationLetsAnotherBootstrapLinkObtainTheSlot() async throws {
        let fixture = try Fixture()
        let firstBootstrap = try await bootstrap(fixture)
        let another = try await bootstrap(fixture)
        defer { firstBootstrap.invalidate(); another.invalidate() }
        let offered = await offer(on: firstBootstrap)
        let first = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.requirement)
        defer { first.invalidate() }
        let version = await hello(on: first)
        XCTAssertEqual(version, 1)
        first.invalidate()

        let next = try await waitForOffer(on: another)
        let replacement = proofConnection(to: next, requirement: fixture.requirement)
        defer { replacement.invalidate() }
        let closedBefore = fixture.events.closedBootstrapLinks.withLock { $0 }
        firstBootstrap.invalidate()
        let serverClosed = try await waitFor { fixture.events.closedBootstrapLinks.withLock { $0 } > closedBefore }
        XCTAssertTrue(serverClosed)
        let competing = await offer(on: another)
        XCTAssertNil(competing.1)
        let replacementVersion = await hello(on: replacement)
        XCTAssertEqual(replacementVersion, 1)
    }

    func testEndpointRejectsCorrectlySignedClientWithDifferentBootstrapPID() async throws {
        // The bootstrap fixture changes only the expected PID. The real connecting binary still meets the signing requirement.
        let fixture = try Fixture(peerPIDOffset: 1)
        let parent = try await bootstrap(fixture)
        defer { parent.invalidate() }
        let offered = await offer(on: parent)
        let client = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.requirement)
        defer { client.invalidate() }
        let version = await hello(on: client)
        XCTAssertEqual(version, 0)
    }

    func testRetiredTransportRoleCannotObtainAnEndpoint() async throws {
        let fixture = try Fixture()
        let parent = try await bootstrap(fixture)
        defer { parent.invalidate() }
        fixture.events.roleCurrent.withLock { $0 = false }
        let retired = await offer(on: parent)
        XCTAssertNil(retired.1)
        fixture.events.roleCurrent.withLock { $0 = true }
        let current = await offer(on: parent)
        XCTAssertNotNil(current.1)
    }

    func testUnusedEndpointExpiresAndReleasesTheSlot() async throws {
        let fixture = try Fixture(timeout: .seconds(1))
        let parent = try await bootstrap(fixture)
        defer { parent.invalidate() }
        let first = await offer(on: parent)
        XCTAssertNotNil(first.1)
        let initiallyBusy = await offer(on: parent)
        XCTAssertNil(initiallyBusy.1)

        let next = try await waitForOffer(on: parent)
        XCTAssertEqual(fixture.events.acceptedProofLinks.withLock { $0 }, 0)
        let client = proofConnection(to: next, requirement: fixture.requirement)
        defer { client.invalidate() }
        let freshVersion = await hello(on: client)
        XCTAssertEqual(freshVersion, 1)
    }

    func testFirstHelloAfterOfferExpiryIsRejectedWithoutTakingTheSlot() async throws {
        let fixture = try Fixture(timeout: .seconds(2))
        let parent = try await bootstrap(fixture)
        defer { parent.invalidate() }
        let offered = await offer(on: parent)
        let client = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.requirement)
        defer { client.invalidate() }
        // Activating the client sends no hello. The first invocation arrives after the offer expires.
        let initiallyBusy = await offer(on: parent)
        XCTAssertNil(initiallyBusy.1)

        let next = try await waitForOffer(on: parent)
        let staleVersion = await hello(on: client)
        XCTAssertEqual(staleVersion, 0)
        XCTAssertEqual(fixture.events.acceptedProofLinks.withLock { $0 }, 0)
        let replacement = proofConnection(to: next, requirement: fixture.requirement)
        defer { replacement.invalidate() }
        let freshVersion = await hello(on: replacement)
        XCTAssertEqual(freshVersion, 1)
    }

    func testClosingBootstrapRetiresReadyProofLink() async throws {
        let fixture = try Fixture()
        let parent = try await bootstrap(fixture)
        let another = try await bootstrap(fixture)
        defer { parent.invalidate(); another.invalidate() }
        let offered = await offer(on: parent)
        let client = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.requirement)
        defer { client.invalidate() }
        let version = await hello(on: client)
        XCTAssertEqual(version, 1)

        parent.invalidate()
        let serverClosed = try await waitFor { fixture.events.closedBootstrapLinks.withLock { $0 } == 1 }
        XCTAssertTrue(serverClosed)
        let next = try await waitForOffer(on: another)
        let staleReplied: Bool = await exchange(fallback: true) { reply in
            guard let proxy = client.remoteObjectProxyWithErrorHandler({ _ in reply(false) }) as? any AuthorityPairingProofXPCProtocol else {
                reply(false)
                return
            }
            proxy.hello { _ in reply(true) }
        }
        XCTAssertFalse(staleReplied)
        let replacement = proofConnection(to: next, requirement: fixture.requirement)
        defer { replacement.invalidate() }
        let replacementVersion = await hello(on: replacement)
        XCTAssertEqual(replacementVersion, 1)
    }

    func testClosingBootstrapBeforeConnectRefusesTheOfferedEndpoint() async throws {
        let fixture = try Fixture()
        let parent = try await bootstrap(fixture)
        let another = try await bootstrap(fixture)
        defer { parent.invalidate(); another.invalidate() }
        let offered = await offer(on: parent)
        parent.invalidate()
        let serverClosed = try await waitFor { fixture.events.closedBootstrapLinks.withLock { $0 } == 1 }
        XCTAssertTrue(serverClosed)
        let stale = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.requirement)
        defer { stale.invalidate() }
        let staleVersion = await hello(on: stale)
        XCTAssertEqual(staleVersion, 0)
        XCTAssertEqual(fixture.events.acceptedProofLinks.withLock { $0 }, 0)
        let available = await offer(on: another)
        XCTAssertNotNil(available.1)
    }

    func testProofLinkDoesNotExportGeneralTransportSelectors() async throws {
        let fixture = try Fixture()
        let parent = try await bootstrap(fixture)
        defer { parent.invalidate() }
        let offered = await offer(on: parent)
        let client = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.requirement, useGeneralInterface: true)
        defer { client.invalidate() }
        let replied: Bool = await exchange(fallback: true) { reply in
            guard let proxy = client.remoteObjectProxyWithErrorHandler({ _ in reply(false) }) as? any TransportAuthorityXPCProtocol else {
                reply(false); return
            }
            proxy.trustSnapshot { _ in reply(true) }
        }
        XCTAssertFalse(replied)
    }

    func testProofListenerRejectsClientOutsideSigningRequirement() async throws {
        let fixture = try Fixture(rejectProofSignature: true)
        let parent = try await bootstrap(fixture)
        defer { parent.invalidate() }
        let offered = await offer(on: parent)
        let client = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.requirement)
        defer { client.invalidate() }
        let version = await hello(on: client)
        XCTAssertEqual(version, 0)
        XCTAssertEqual(fixture.events.acceptedProofLinks.withLock { $0 }, 0)
    }

    func testSecondHelloRetiresReadyProofLink() async throws {
        let fixture = try Fixture()
        let parent = try await bootstrap(fixture)
        defer { parent.invalidate() }
        let offered = await offer(on: parent)
        let client = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.requirement)
        defer { client.invalidate() }
        let firstVersion = await hello(on: client)
        XCTAssertEqual(firstVersion, 1)
        let initiallyBusy = await offer(on: parent)
        XCTAssertNil(initiallyBusy.1)

        let secondVersion = await hello(on: client)
        XCTAssertEqual(secondVersion, 0)
        _ = try await waitForOffer(on: parent)
    }

    func testBootstrapWithoutPairingOwnerReportsUnsupported() async throws {
        let fixture = try Fixture(enableProofs: false)
        let parent = try await bootstrap(fixture)
        defer { parent.invalidate() }
        let result = await offer(on: parent)
        XCTAssertEqual(result.0, 0)
        XCTAssertNil(result.1)
    }
}
