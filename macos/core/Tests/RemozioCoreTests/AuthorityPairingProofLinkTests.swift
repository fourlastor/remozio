import CryptoKit
import Darwin
import Foundation
import Network
import RemozioProtocol
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
    final class Fixture: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
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
             rejectProofSignature: Bool = false, bindReservations: AuthorityPairingProofLinks.BindReservations? = nil,
             lookupRendezvous: @escaping @Sendable (Data) -> AuthorityPairingRendezvous? = { _ in nil },
             onProofLinkRetired: (@Sendable () -> Void)? = nil) throws {
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
               }, bindReservations: bindReservations, lookupRendezvous: lookupRendezvous,
               onProofLinkRetired: onProofLinkRetired)
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

    func testProofBudgetRejectsAnXPCVerificationBeforeItConsumesTheCandidate() async throws {
        let instant = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        let owner = UUID()
        let scope = try ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
        let invitation = try PairingInvitation(macID: scope.macID, accountID: scope.accountID, label: "Proof fixture",
            authorityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            transportPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation, minimumEnvelopeVersion: 1)
        let full = try PairingInvitationV2(invitation: invitation, windowID: Data(repeating: 5, count: 16),
            secret: Data(repeating: 6, count: 32), lifetimeMilliseconds: 5_000)
        let window = try AuthorityPairingV2Window(invitation: full, predecessor: nil, started: instant, authorityOwner: owner)
        let fixture = try Fixture(bindReservations: { id, link in
            guard id == full.windowID else { throw FixtureError.retiredRole }
            return try .init(window: window, authorityOwner: owner, link: link, now: { instant },
                makeChallenge: { Data(repeating: 7, count: 32) }, verifyWindow: {})
        })
        let primary = try await bootstrap(fixture)
        defer { primary.invalidate() }
        let offered = await offer(on: primary)
        let endpoint = try XCTUnwrap(offered.1)
        let connection = proofConnection(to: endpoint, requirement: fixture.requirement)
        defer { connection.invalidate() }
        let version = await hello(on: connection)
        XCTAssertEqual(version, AuthorityPairingProofWire.handoffVersion)

        let bound: Bool = await proofExchange(on: connection, fallback: false) {
            $0.bindWindow(full.windowID, reply: $1)
        }
        XCTAssertTrue(bound)
        let transferred = await proofExchange(on: connection, fallback: false) { $0.finishBootstrap(reply: $1) }
        XCTAssertTrue(transferred)

        func key(_ id: UInt8) throws -> PairingKey {
            try PairingKey(keyID: Data(repeating: id, count: 16), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        }
        let phone = try ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: 8, count: 32),
            envelopeVersions: [1], requests: [], auditVersions: [])
        let proposal = try PairingPhoneProposal(phone: phone, transportKey: key(10), decisionKey: key(11), biometricKey: key(12))
        let bytes = try proposal.encode(), exporter = Data(repeating: 9, count: 32)
        let registration: (Data?, Data?) = await proofExchange(on: connection, fallback: (nil, nil)) { proxy, reply in
            proxy.registerCandidate(AuthorityPairingProofWire.bytes(UUID()), acceptedAt: instant.milliseconds,
                peerPoint: proposal.transportKey.publicKey, exporter: exporter) { reply(($0, $1)) }
        }
        let candidate = try XCTUnwrap(registration.0)
        let challenge = try XCTUnwrap(registration.1)
        let tag = try full.proof(proposal: proposal, challenge: challenge, exporter: exporter)
        let acquired = window.proofXPCBudget.acquire()
        XCTAssertTrue(acquired)
        guard acquired else { return }
        let refused: Bool = await proofExchange(on: connection, fallback: true) {
            $0.verifyCandidate(candidate, proposal: Data([0xff]), tag: tag, reply: $1)
        }
        window.proofXPCBudget.release()
        XCTAssertFalse(refused)

        let verified: Bool = await proofExchange(on: connection, fallback: false) {
            $0.verifyCandidate(candidate, proposal: bytes, tag: tag, reply: $1)
        }
        XCTAssertTrue(verified)
        let id = try AuthorityPairingProofWire.identifier(candidate)
        XCTAssertThrowsError(try window.takeProposal(connection: id, matching: bytes, at: instant))
        let confirmed: Bool = await proofExchange(on: connection, fallback: false) {
            $0.confirmCandidate(candidate, reply: $1)
        }
        XCTAssertTrue(confirmed)
        XCTAssertEqual(try window.takeProposal(connection: id, matching: bytes, at: instant).encode(), bytes)
    }

    func testConcurrentRegistrationDoesNotInterruptValidVerificationAndConfirmation() async throws {
        let f = try TransportPairingFixture()
        let now = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        let owner = UUID()
        let full = try PairingInvitationV2(invitation: f.invitation, windowID: Data(repeating: 5, count: 16),
            secret: Data(repeating: 6, count: 32), lifetimeMilliseconds: 5_000)
        let window = try AuthorityPairingV2Window(invitation: full, predecessor: nil, started: now, authorityOwner: owner)
        let pause = Mutex(false)
        let verifying = expectation(description: "Valid verification entered Authority")
        let release = DispatchSemaphore(value: 0)
        let fixture = try Fixture(bindReservations: { id, link in
            guard id == full.windowID else { throw FixtureError.retiredRole }
            return try .init(window: window, authorityOwner: owner, link: link, now: { now },
                makeChallenge: { Data(repeating: 7, count: 32) }, verifyWindow: {
                    let armed = pause.withLock { armed in
                        let previous = armed
                        armed = false
                        return previous
                    }
                    if armed {
                        verifying.fulfill()
                        guard release.wait(timeout: .now() + .seconds(2)) == .success else { throw FixtureError.retiredRole }
                    }
                })
        })
        let primary = try await bootstrap(fixture)
        defer { primary.invalidate() }
        let offered = await offer(on: primary)
        let client = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.requirement)
        defer { client.invalidate() }
        let version = await hello(on: client)
        XCTAssertEqual(version, AuthorityPairingProofWire.handoffVersion)
        let bound = await proofExchange(on: client, fallback: false) {
            $0.bindWindow(full.windowID, reply: $1)
        }
        XCTAssertTrue(bound)
        let transferred = await proofExchange(on: client, fallback: false) { $0.finishBootstrap(reply: $1) }
        XCTAssertTrue(transferred)

        let exporter = Data(repeating: 9, count: 32), proposal = try f.proposal.encode()
        let registration: (Data?, Data?) = await proofExchange(on: client, fallback: (nil, nil)) { proxy, reply in
            proxy.registerCandidate(AuthorityPairingProofWire.bytes(UUID()), acceptedAt: now.milliseconds,
                peerPoint: f.proposal.transportKey.publicKey, exporter: exporter) { reply(($0, $1)) }
        }
        let candidate = try XCTUnwrap(registration.0), challenge = try XCTUnwrap(registration.1)
        let tag = try full.proof(proposal: f.proposal, challenge: challenge, exporter: exporter)
        pause.withLock { $0 = true }
        let completed = expectation(description: "Valid verification returned")
        let verification = ResultBox<Bool>()
        let reply: @Sendable (Bool) -> Void = { result in
            let first = verification.value.withLock { value in
                guard value == nil else { return false }
                value = result
                return true
            }
            if first { completed.fulfill() }
        }
        let proxy = try XCTUnwrap(client.remoteObjectProxyWithErrorHandler { _ in reply(false) }
            as? any AuthorityPairingProofXPCProtocol)
        proxy.verifyCandidate(candidate, proposal: proposal, tag: tag, reply: reply)
        await fulfillment(of: [verifying], timeout: 2)
        let competing: (Data?, Data?) = await proofExchange(on: client, fallback: (Data(), Data())) { proxy, reply in
            proxy.registerCandidate(AuthorityPairingProofWire.bytes(UUID()), acceptedAt: now.milliseconds,
                peerPoint: f.proposal.transportKey.publicKey, exporter: Data(repeating: 10, count: 32)) { reply(($0, $1)) }
            release.signal()
        }
        XCTAssertNil(competing.0)
        await fulfillment(of: [completed], timeout: 3)
        XCTAssertEqual(verification.value.withLock { $0 }, true)
        let confirmed = await proofExchange(on: client, fallback: false) {
            $0.confirmCandidate(candidate, reply: $1)
        }
        XCTAssertTrue(confirmed)
        let selected = try window.takeProposal(connection: AuthorityPairingProofWire.identifier(candidate), matching: proposal, at: now)
        XCTAssertEqual(try selected.encode(), proposal)
    }

    private func proofExchange<Value: Sendable>(on connection: NSXPCConnection, fallback: Value,
        send: (any AuthorityPairingProofXPCProtocol, @escaping @Sendable (Value) -> Void) -> Void) async -> Value {
        await exchange(fallback: fallback) { reply in
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(fallback) })
                    as? any AuthorityPairingProofXPCProtocol else { reply(fallback); return }
            send(proxy, reply)
        }
    }

    func testTransportOwnerOpensAndBindsNativeLinkAndClosesOnInterruption() async throws {
        try await exerciseTransportOwner(rejectPublication: false)
    }

    func testTransportOwnerRetiresTheLinkWhenPublicationIsTooLate() async throws {
        try await exerciseTransportOwner(rejectPublication: true)
    }

    private func exerciseTransportOwner(rejectPublication: Bool) async throws {
        let authority = P256.Signing.PrivateKey(), transport = P256.Signing.PrivateKey()
        let macID = Data(repeating: 1, count: 16), accountID = Data(repeating: 2, count: 16)
        let invitation = try PairingInvitation(macID: macID, accountID: accountID, label: "Proof fixture",
            authorityPublicKey: authority.publicKey.x963Representation,
            transportPublicKey: transport.publicKey.x963Representation, minimumEnvelopeVersion: 1)
        let full = try PairingInvitationV2(invitation: invitation, windowID: Data(repeating: 5, count: 16),
            secret: Data(repeating: 6, count: 32), lifetimeMilliseconds: 15_000)
        let clock = try AuthorityClock(), id = UUID()
        let window = try AuthorityPairingV2Window(invitation: full, predecessor: nil, started: clock.now(), authorityOwner: id)
        let bound = Mutex<AuthorityPairingProofReservations?>(nil)
        let fixture = try Fixture(bindReservations: { windowID, link in
            guard windowID == full.windowID else { throw FixtureError.retiredRole }
            let reservations = try AuthorityPairingProofReservations(window: window, authorityOwner: id, link: link,
                now: clock.now, makeChallenge: { Data(repeating: 7, count: 32) }, verifyWindow: {})
            bound.withLock { $0 = reservations }
            return reservations
        })

        let approval = try ApprovalTransportConfiguration(macID: macID, accountID: accountID, ownerUID: 501, serviceUID: 502,
            authorityServiceName: "dev.remozio.tests.proof", teamID: "ABCDEFGHIJ", authorityIdentifier: "dev.remozio.authority",
            authorityHashes: [Data(repeating: 3, count: 20)], identityReference: Data([1]),
            identityPublicKeyInfo: transport.publicKey.derRepresentation)
        let pairing = try TransportPairingControlConfiguration(macID: macID, accountID: accountID,
            ownerUID: 501, transportUID: 502, serviceName: "dev.remozio.tests.pairing",
            teamID: "ABCDEFGHIJ", appIdentifier: "dev.remozio.app", appHashes: [Data(repeating: 4, count: 20)],
            transportIdentifier: "dev.remozio.transport", transportHashes: [Data(repeating: 5, count: 20)])
        let bootstrapConnection = NSXPCConnection(listenerEndpoint: fixture.listener.endpoint)
        let driver = NativeAuthorityXPC(connection: bootstrapConnection, policy: fixture.policy,
                                       configure: { $0.setCodeSigningRequirement(fixture.requirement) })
        let attemptedPublication = Mutex(false)
        let closeCount = Mutex(0)
        let owner = TransportPairingSetupOwner(configuration: pairing, factory: { _, _, _ in throw FixtureError.retiredRole },
            openProofClient: { configuration, windowID, onClose in
                try await AuthorityPairingProofClient.open(configuration: configuration, windowID: windowID, onClose: {
                    closeCount.withLock { $0 += 1 }
                    onClose()
                }) { supplied, ended in
                    XCTAssertEqual(supplied.canonicalBytes, approval.canonicalBytes)
                    let bootstrap = AuthorityXPCChannel(driver: driver, onClose: ended)
                    return .init(channel: bootstrap, policy: fixture.policy, configure: { $0.setCodeSigningRequirement(fixture.requirement) })
                }
            }, publicationTime: {
                attemptedPublication.withLock { $0 = true }
                return ContinuousClock.now.advanced(by: .seconds(rejectPublication ? 4 : 0))
            })
        defer { owner.abort() }
        let port = try await owner.beginV2(.init(id: full.windowID, invitation: invitation, replacement: nil,
            lifetimeMilliseconds: full.lifetimeMilliseconds), identity: AuthorityJournalSchema19MigrationTests.fixtureIdentity(transport),
            authorityConfiguration: approval)
        let bootstrapClosed = try await waitFor { fixture.events.closedBootstrapLinks.withLock { $0 } == 1 }
        XCTAssertTrue(bootstrapClosed)
        XCTAssertEqual(closeCount.withLock { $0 }, 0)
        let reservations = try XCTUnwrap(bound.withLock { $0 })
        let acceptedAt = try clock.now().milliseconds
        let nextPeer = P256.Signing.PrivateKey().publicKey.x963Representation
        _ = try reservations.register(connection: UUID(), acceptedAt: acceptedAt, peerPoint: nextPeer, exporter: Data(repeating: 9, count: 32))
        XCTAssertEqual(reservations.pendingCount, 1)

        let phone: Task<Void, Error>?
        if rejectPublication {
            phone = Task { try await AndroidPairingMacLoopbackTests.pairNativeClient(port: port, invitation: full) }
        } else {
            phone = nil
            fixture.links.close()
        }
        defer { phone?.cancel() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        var closed = false
        while ContinuousClock.now < deadline {
            do {
                let snapshot = try await owner.snapshot()
                if rejectPublication, !snapshot.candidates.isEmpty {
                    XCTFail("The Transport owner published a candidate after its deadline")
                    break
                }
            } catch TransportPairingControlError.closed { closed = true; break }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTAssertTrue(closed)
        if rejectPublication { XCTAssertTrue(attemptedPublication.withLock { $0 }) }
        await owner.closeAndWait()
        if let phone, case .success = await phone.result {
            XCTFail("The candidate received a pairing receipt after its deadline")
        }
        let cleared = try await waitFor { reservations.pendingCount == 0 && fixture.events.closedBootstrapLinks.withLock { $0 } > 0 }
        XCTAssertTrue(cleared)
        XCTAssertEqual(closeCount.withLock { $0 }, 1)
        XCTAssertThrowsError(try window.export(at: clock.now()))
    }

    func testTLSLoopbackProofAndReceiptUseTheDedicatedXPCLink() async throws {
        try await pairUsingDedicatedLink(rePair: false)
    }

    func testTLSLoopbackReplacementUsesTheDedicatedXPCLink() async throws {
        try await pairUsingDedicatedLink(rePair: true)
    }

    func testNativePairingRecoversAfterTemporaryRegistrationRefusal() async throws {
        try await pairUsingDedicatedLink(rePair: false, exhaustBudget: true)
    }

    func testSixteenLoopbackCandidatesRegisterInOneWindowAndOnlyOnePairs() async throws {
        try await pairUsingDedicatedLink(rePair: false, multipleSources: true)
    }

    private func pairUsingDedicatedLink(rePair: Bool, exhaustBudget: Bool = false,
                                        multipleSources: Bool = false) async throws {
        let authority = P256.Signing.PrivateKey(), transport = P256.Signing.PrivateKey()
        let macID = Data(repeating: 1, count: 16), accountID = Data(repeating: 2, count: 16)
        let invitation = try PairingInvitation(macID: macID, accountID: accountID, label: "Proof fixture",
            authorityPublicKey: authority.publicKey.x963Representation,
            transportPublicKey: transport.publicKey.x963Representation, minimumEnvelopeVersion: 1)
        let predecessor: PairedPhoneSelection? = rePair ? .init(macID: macID, accountID: accountID, revision: UUID(),
            phone: DeliveryRecipient(phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 8, count: 16))) : nil
        let full = try PairingInvitationV2(invitation: invitation, windowID: Data(repeating: 5, count: 16),
            secret: Data(repeating: 6, count: 32), replacement: predecessor?.predecessor, lifetimeMilliseconds: 15_000)
        let clock = try AuthorityClock(), owner = UUID()
        let window = try AuthorityPairingV2Window(invitation: full, predecessor: predecessor, started: clock.now(), authorityOwner: owner)
        let frozenTime = Mutex<AuthorityMoment?>(nil)
        let sampled = Mutex(0)
        let bound = Mutex<AuthorityPairingProofReservations?>(nil)
        let authorityRetired = expectation(description: "Authority retired the proof link")
        let fixture = try Fixture(bindReservations: { id, link in
            guard id == full.windowID else { throw FixtureError.retiredRole }
            let reservations = try AuthorityPairingProofReservations(window: window, authorityOwner: owner, link: link,
                now: {
                    sampled.withLock { $0 += 1 }
                    if let frozen = frozenTime.withLock({ $0 }) { return frozen }
                    return try clock.now()
                }, makeChallenge: { try AuthorityPairingSetupAccess.secureRandom(32) }, verifyWindow: {})
            bound.withLock { $0 = reservations }
            return reservations
        }, onProofLinkRetired: { authorityRetired.fulfill() })
        let primary = try await bootstrap(fixture)
        defer { primary.invalidate() }
        let offered = await offer(on: primary)
        let endpoint = try XCTUnwrap(offered.1)
        let client = AuthorityPairingProofClient(endpoint: endpoint, peerPolicy: fixture.policy, onClose: {},
            configure: { $0.setCodeSigningRequirement(fixture.requirement) })
        defer { client.close() }
        try await client.start(windowID: full.windowID)

        let ingress = PairingSetupV2Ingress(windowID: full.windowID, lifetimeMilliseconds: full.lifetimeMilliseconds, authority: client)
        let ready = AsyncStream<UInt16>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let served = Mutex(0)
        let receiptSendCompleted = XCTestExpectation(description: "Server finished sending the receipt")
        receiptSendCompleted.assertForOverFulfill = true
        let receiptSendResult = Mutex<Result<Void, any Error>?>(nil)
        let awaitReceiptSend: @Sendable () async throws -> Void = {
            // The phone must keep the channel open through the server's post-write check.
            await self.fulfillment(of: [receiptSendCompleted], timeout: 3)
            let result = receiptSendResult.withLock { $0 }
            try XCTUnwrap(result, "The server did not finish sending the receipt").get()
        }
        let sourceIndex = Mutex<UInt32>(0)
        let sourceKey: @Sendable (NWEndpoint) -> PairingSetupV2Source? = { endpoint in
            guard let key = PairingSetupV2Source(endpoint) else { return nil }
            guard multipleSources else { return key }
            return sourceIndex.withLock {
                $0 += 1
                return .ipv4($0)
            }
        }
        let listener = try PairingSetupListener(identity: AuthorityJournalSchema19MigrationTests.fixtureIdentity(transport),
            invitation: invitation, binding: .loopback, maximumConnections: 4, handshakeTimeoutMilliseconds: 3_000,
            setupTimeoutMilliseconds: full.lifetimeMilliseconds, v2: ingress, sourceKey: sourceKey, event: { event in
                if case .ready(let port) = event { ready.continuation.yield(port) }
                ready.continuation.finish()
            }, handler: { session in
                let proposal = try await session.proposal()
                let candidate = await session.provedConnection
                let id = try XCTUnwrap(candidate)
                // This step can succeed only after the proof link confirms the candidate.
                let selected = try window.takeProposal(connection: id, matching: proposal.encode(), at: clock.now())
                let transcript = try AndroidPairingMacLoopbackTests.transcript(for: selected, invitation: invitation)
                try await session.stage(transcript)
                _ = try await session.receiveProof()
                let receipt = try authority.signature(for: transcript.signingInput(purpose: .macCommit)).rawRepresentation
                defer { receiptSendCompleted.fulfill() }
                do {
                    try await session.sendReceipt(receipt)
                    served.withLock { $0 += 1 }
                    receiptSendResult.withLock { $0 = .success(()) }
                } catch {
                    receiptSendResult.withLock { $0 = .failure(error) }
                    throw error
                }
            })
        do {
            try listener.start()
            var ports = ready.stream.makeAsyncIterator()
            let readyPort = await ports.next()
            let port = try XCTUnwrap(readyPort)
            if exhaustBudget {
                let reservations = try XCTUnwrap(bound.withLock { $0 })
                let now = try clock.now()
                frozenTime.withLock { $0 = now }
                for attempt in 0..<PairingRegistrationBudget.authorityBurst {
                    let candidate = try reservations.register(connection: UUID(), acceptedAt: now.milliseconds,
                        peerPoint: transport.publicKey.x963Representation, exporter: Data(repeating: UInt8(attempt), count: 32))
                    reservations.retire(candidate: candidate.id)
                }
                let before = sampled.withLock { $0 }
                do {
                    try await AndroidPairingMacLoopbackTests.pairNativeClient(port: port, invitation: full)
                    XCTFail("Pairing completed while Authority had no registration credit")
                } catch {}
                XCTAssertGreaterThan(sampled.withLock { $0 }, before)
                XCTAssertEqual(served.withLock { $0 }, 0)
                frozenTime.withLock { $0 = nil }
                let refill = (1_000 + PairingRegistrationBudget.registrationsPerSecond - 1) / PairingRegistrationBudget.registrationsPerSecond
                while try clock.now().milliseconds < now.milliseconds + refill {
                    try await Task.sleep(for: .milliseconds(5))
                }
            }
            if multipleSources {
                let reservations = try XCTUnwrap(bound.withLock { $0 })
                try await pairOnlyOneOfSixteenNativePeers(port: port, invitation: full, reservations: reservations,
                    afterVerifiedReceipt: awaitReceiptSend)
            } else {
                try await AndroidPairingMacLoopbackTests.pairNativeClient(port: port, invitation: full,
                    afterVerifiedReceipt: awaitReceiptSend)
            }
        } catch {
            await listener.closeAndWait()
            throw error
        }
        await listener.closeAndWait()
        XCTAssertEqual(served.withLock { $0 }, 1)
        let drainedAt = try clock.now()
        XCTAssertLessThan(drainedAt.milliseconds, window.deadline)
        XCTAssertThrowsError(try window.export(at: drainedAt))
        // The listener joins its tasks. The Authority receives XPC invalidation asynchronously.
        await fulfillment(of: [authorityRetired], timeout: 3)
        XCTAssertThrowsError(try window.requireStaging(drainedAt))
    }

    private func pairOnlyOneOfSixteenNativePeers(port: UInt16, invitation: PairingInvitationV2,
                                                 reservations: AuthorityPairingProofReservations,
                                                 afterVerifiedReceipt: @escaping @Sendable () async throws -> Void) async throws {
        let capacity = PairingSetupV2Admissions.maximumPending
        let burst = Int(PairingRegistrationBudget.ingressBurst)
        let rate = PairingRegistrationBudget.registrationsPerSecond
        XCTAssertEqual(capacity, 16)
        let reached = (0..<capacity).map { XCTestExpectation(description: "Peer \($0 + 1) got its challenge") }
        let release = reached.map { _ in AsyncStream<Void>.makeStream() }

        func start(_ indexes: Range<Int>) -> [Task<Bool, Never>] {
            indexes.map { index in
                Task { @Sendable in
                    do {
                        try await AndroidPairingMacLoopbackTests.pairNativeClient(port: port, invitation: invitation,
                            afterVerifiedReceipt: afterVerifiedReceipt) {
                            reached[index].fulfill()
                            for await _ in release[index].stream {}
                        }
                        return true
                    } catch { return false }
                }
            }
        }

        var peers = start(0..<burst)
        defer {
            for signal in release { signal.continuation.finish() }
            for peer in peers { peer.cancel() }
        }
        await fulfillment(of: Array(reached[..<burst]), timeout: 1)
        let refillMilliseconds = (1_000 * UInt64(capacity - burst) + rate - 1) / rate
        try await Task.sleep(for: .milliseconds(Int64(refillMilliseconds)))
        peers += start(burst..<capacity)
        await fulfillment(of: Array(reached[burst...]), timeout: 1)
        XCTAssertEqual(reservations.pendingCount, capacity)

        release[0].continuation.finish()
        let firstPaired = await peers[0].value
        XCTAssertTrue(firstPaired)
        XCTAssertEqual(reservations.pendingCount, 0)
        for signal in release.dropFirst() { signal.continuation.finish() }
        for peer in peers.dropFirst() {
            let alsoPaired = await peer.value
            XCTAssertFalse(alsoPaired)
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

    private struct HandoffFixture {
        let native: Fixture
        let window: AuthorityPairingV2Window
        let full: PairingInvitationV2
        let proposal: PairingPhoneProposal
        let now = AuthorityMoment(epoch: UUID(), milliseconds: 100)

        init() throws {
            let f = try TransportPairingFixture(), owner = UUID()
            let full = try PairingInvitationV2(invitation: f.invitation, windowID: Data(repeating: 5, count: 16),
                secret: Data(repeating: 6, count: 32), lifetimeMilliseconds: 5_000)
            let time = now
            let window = try AuthorityPairingV2Window(invitation: full, predecessor: nil, started: time, authorityOwner: owner)
            native = try Fixture(bindReservations: { id, link in
                guard id == full.windowID else { throw FixtureError.retiredRole }
                return try .init(window: window, authorityOwner: owner, link: link, now: { time },
                    makeChallenge: { Data(repeating: 7, count: 32) }, verifyWindow: {})
            })
            self.window = window; self.full = full; proposal = f.proposal
        }
    }

    private func boundProofLink(_ fixture: HandoffFixture, on bootstrap: NSXPCConnection) async throws -> NSXPCConnection {
        let offered = await offer(on: bootstrap)
        let client = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.native.requirement)
        let version = await hello(on: client)
        XCTAssertEqual(version, AuthorityPairingProofWire.handoffVersion)
        let premature = await proofExchange(on: client, fallback: true) { $0.finishBootstrap(reply: $1) }
        XCTAssertFalse(premature)
        let bound = await proofExchange(on: client, fallback: false) {
            $0.bindWindow(fixture.full.windowID, reply: $1)
        }
        XCTAssertTrue(bound)
        return client
    }

    private func register(on link: NSXPCConnection, fixture: HandoffFixture, exporter: Data) async -> (Data?, Data?) {
        await proofExchange(on: link, fallback: (nil, nil)) { proxy, reply in
            proxy.registerCandidate(AuthorityPairingProofWire.bytes(UUID()), acceptedAt: fixture.now.milliseconds,
                peerPoint: fixture.proposal.transportKey.publicKey, exporter: exporter) { reply(($0, $1)) }
        }
    }

    func testRejectedLegacyBindRetiresTheLinkBeforeTheBootstrapCloses() async throws {
        let fixture = try HandoffFixture()
        let parent = try await bootstrap(fixture.native)
        let replacement = try await bootstrap(fixture.native)
        defer { parent.invalidate(); replacement.invalidate() }
        let offered = await offer(on: parent)
        let client = proofConnection(to: try XCTUnwrap(offered.1), requirement: fixture.native.requirement)
        defer { client.invalidate() }
        let version = await hello(on: client)
        XCTAssertEqual(version, AuthorityPairingProofWire.handoffVersion)

        let bound = await proofExchange(on: client, fallback: false) { $0.bindWindow(Data(count: 16), reply: $1) }
        XCTAssertFalse(bound)
        let next = try await waitForOffer(on: replacement)
        XCTAssertNotNil(next)
    }

    func testClosingBootstrapBeforeHandoffRetiresTheBoundProofLink() async throws {
        let fixture = try HandoffFixture()
        let parent = try await bootstrap(fixture.native)
        let spare = try await bootstrap(fixture.native)
        defer { parent.invalidate(); spare.invalidate() }
        let client = try await boundProofLink(fixture, on: parent)
        defer { client.invalidate() }
        let attempted = await register(on: client, fixture: fixture, exporter: Data(repeating: 8, count: 32))
        XCTAssertNil(attempted.0)

        parent.invalidate()
        let retired = try await waitFor { fixture.native.events.closedBootstrapLinks.withLock { $0 } == 1 }
        XCTAssertTrue(retired)
        _ = try await waitForOffer(on: spare)
        let transferred = await proofExchange(on: client, fallback: false) { $0.finishBootstrap(reply: $1) }
        XCTAssertFalse(transferred)
        XCTAssertThrowsError(try fixture.window.export(at: fixture.now))
    }

    func testHandoffFreesAGeneralSlotAndPreservesProofAndPolicyChecks() async throws {
        let fixture = try HandoffFixture()
        var ordinary: [NSXPCConnection] = []
        defer { ordinary.forEach { $0.invalidate() } }
        for _ in 0..<7 { ordinary.append(try await bootstrap(fixture.native)) }
        let parent = try await bootstrap(fixture.native)
        defer { parent.invalidate() }
        XCTAssertNil(fixture.native.registry.reserve())
        let client = try await boundProofLink(fixture, on: parent)
        defer { client.invalidate() }
        let transferred = await proofExchange(on: client, fallback: false) { $0.finishBootstrap(reply: $1) }
        XCTAssertTrue(transferred)
        parent.invalidate()
        let freed = try await waitFor { fixture.native.events.closedBootstrapLinks.withLock { $0 } == 1 }
        XCTAssertTrue(freed)
        ordinary.append(try await bootstrap(fixture.native))
        XCTAssertNil(fixture.native.registry.reserve())

        let exporter = Data(repeating: 9, count: 32)
        let registration = await register(on: client, fixture: fixture, exporter: exporter)
        let candidate = try XCTUnwrap(registration.0), challenge = try XCTUnwrap(registration.1)
        let proposal = try fixture.proposal.encode()
        let tag = try fixture.full.proof(proposal: fixture.proposal, challenge: challenge, exporter: exporter)
        fixture.native.events.roleCurrent.withLock { $0 = false }
        let refused = await proofExchange(on: client, fallback: true) {
            $0.verifyCandidate(candidate, proposal: proposal, tag: tag, reply: $1)
        }
        XCTAssertFalse(refused)
        fixture.native.events.roleCurrent.withLock { $0 = true }
        let verified = await proofExchange(on: client, fallback: false) {
            $0.verifyCandidate(candidate, proposal: proposal, tag: tag, reply: $1)
        }
        XCTAssertTrue(verified)
        let confirmed = await proofExchange(on: client, fallback: false) { $0.confirmCandidate(candidate, reply: $1) }
        XCTAssertTrue(confirmed)
        let selected = try fixture.window.takeProposal(connection: AuthorityPairingProofWire.identifier(candidate),
            matching: proposal, at: fixture.now)
        XCTAssertEqual(try selected.encode(), proposal)
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
