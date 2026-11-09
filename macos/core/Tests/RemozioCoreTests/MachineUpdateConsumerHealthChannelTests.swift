import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class MachineUpdateConsumerHealthChannelTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}

    private final class TestState<Value: Sendable>: Sendable {
        let lock: Mutex<Value>
        init(_ value: Value) { lock = Mutex(value) }
    }
    private final class Driver: MachineUpdateConsumerHealthDriver, @unchecked Sendable {
        struct State {
            var hellos = 0, checks = 0, closes = 0, peerChecks = 0
            var version: UInt64 = 1
            var greeting: Data? = Data([1, 2, 3])
            var holdHello = false, holdCheck = false, failAfterHello = false, loseAfterHello = false
            var badPeer = false, malformed = false, wrongSignature = false, duplicate = false, missingHead = false, wrongHeadNonce = false
            var recoveryRequired = false
            var lost: (@Sendable () -> Void)?
            var held: (@Sendable (MachineUpdateConsumerHealthReply) -> Void)?
            var request: Data?
            var onHello: (@Sendable () -> Void)?
        }
        let state = Mutex(State())
        let fixture: MachineUpdateRoleChallengeTests.Fixture
        let requirement: MachineUpdateRestartHealthPlan.Requirement
        let registration: GatewayRegistrationIdentity?
        init(gateway: Bool = false, authority: Bool = false,
             boundTo root: MachineUpdateRestartHealthPlan.Requirement? = nil) throws {
            let fixture = MachineUpdateRoleChallengeTests.Fixture(); self.fixture = fixture
            let role: AuthorityCodeRole = authority ? .authority : (gateway ? .notificationGateway : .transport)
            let uid: UInt32 = authority ? 0 : (gateway ? 20001 : 20000)
            let requirement = try fixture.requirement(role: role, uid: uid,
                configurationID: root?.configurationEpoch, configurationRevision: root?.configurationRevision,
                backendID: root?.backendEpoch, backendRevision: root?.backendRevision)
            self.requirement = requirement
            if gateway {
                registration = try GatewayRegistrationIdentity(ownerID: Data(repeating: 8, count: 16), macID: requirement.binding.macID,
                    accountID: requirement.binding.accountID, gatewayID: Data(repeating: 9, count: 16), lifecycleEpoch: Data(repeating: 10, count: 16),
                    rootPublicKey: root?.publicKey ?? MachineUpdateRoleChallengeTests.Fixture().key.publicKey.x963Representation)
            } else { registration = nil }
        }
        func start(closed: @escaping @Sendable () -> Void) { state.withLock { $0.lost = closed } }
        func requirePeer() throws {
            try state.withLock { $0.peerChecks += 1; if $0.badPeer { throw Denied() } }
        }
        func packet(_ payload: Data) throws -> Data {
            if state.withLock({ $0.malformed }) { return Data([0]) }
            if state.withLock({ $0.recoveryRequired }) { return MachineUpdateGatewayRecoverySignal.bytes }
            let request = requirement.role == .authority
                ? try MachineUpdateAuthorityReadinessRequest.decode(payload).challenge : payload
            var role = try fixture.answer(request, expected: requirement)
            if state.withLock({ $0.wrongSignature }) { role[role.count - 1] ^= 1 }
            let head: GatewayHeadReply?
            if let registration, !state.withLock({ $0.missingHead }) {
                let nonce = state.withLock({ $0.wrongHeadNonce }) ? Data(repeating: 0, count: 32) : MachineUpdateGatewayHealthQuery.nonce(request)
                let payload = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .unsigned(1), 2: .bytes(registration.encode()),
                    3: .bytes(nonce), 4: .unsigned(0), 5: .unsigned(0), 6: .bytes(Data()), 7: .bytes(Data())]),
                    limits: CBORLimits(maxBytes: 16384, maxDepth: 2, maxItems: 128))
                head = .init(canonicalPayload: payload,
                    signature: try fixture.key.signature(for: Data("Remozio/GatewayHeadReply/v1\0".utf8) + payload).rawRepresentation)
            } else { head = nil }
            return try MachineUpdateConsumerHealthPacket(roleReply: role, gatewayHead: head).encoded
        }
        func invoke(_ call: MachineUpdateConsumerHealthCall, reply: @escaping @Sendable (MachineUpdateConsumerHealthReply) -> Void) {
            do {
                switch call {
                case .hello:
                    if state.withLock({ $0.hellos += 1; if $0.holdHello { $0.held = reply; return true }; return false }) { return }
                    state.withLock { $0.onHello }?()
                    reply(.greeting(state.withLock { $0.version }, state.withLock { $0.greeting }))
                    if state.withLock({ $0.failAfterHello }) { reply(.failed) }
                    if state.withLock({ $0.loseAfterHello }) { state.withLock { $0.lost }?() }
                case .check(let bytes):
                    if state.withLock({ $0.checks += 1; $0.request = bytes; if $0.holdCheck { $0.held = reply; return true }; return false }) { return }
                    let value = try packet(bytes); reply(.response(value))
                    if state.withLock({ $0.duplicate }) { reply(.response(value)) }
                }
            } catch { reply(.failed) }
        }
        func finish() throws {
            let held = state.withLock { value in let held = value.held; value.held = nil; return (held, value.request) }
            if let request = held.1 { held.0?(.response(try packet(request))) }
            else { held.0?(.greeting(1, Data([1, 2, 3]))) }
        }
        func close() { state.withLock { $0.closes += 1 } }
    }
    private func channel(_ driver: Driver, timeout: UInt64 = 1000,
        authorityInstalledReadiness: Bool = false, authorityReadinessRequest: Data? = nil,
        verify: @escaping @Sendable () throws -> Void = {}, release: @escaping @Sendable () -> Void = {}) throws
        -> MachineUpdateConsumerHealthChannel {
        let moment = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        return try .init(driver: driver, expectedHello: Data([1, 2, 3]), requirement: driver.requirement,
            registration: driver.registration, authorityInstalledReadiness: authorityInstalledReadiness,
            authorityReadinessRequest: authorityReadinessRequest, timeoutMilliseconds: timeout,
            clock: { moment }, verifyCurrent: verify, release: release)
    }
    private func waitUntil(_ body: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !body() { guard ContinuousClock.now < deadline else { throw Denied() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testOneExchangeReturnsTheBoundProofAndClosesBeforeReturning() async throws {
        let driver = try Driver(), releases = TestState(0)
        let client = try channel(driver, release: { releases.lock.withLock { $0 += 1 } })
        let proof = try await client.execute()
        XCTAssertEqual(proof.role.requirement, driver.requirement); XCTAssertNil(proof.gatewayHead)
        XCTAssertEqual(proof.role.challengeDigest, try MachineUpdateActivationRecord.digest(XCTUnwrap(driver.state.withLock { $0.request })))
        XCTAssertEqual(driver.state.withLock { $0.hellos }, 1); XCTAssertEqual(driver.state.withLock { $0.checks }, 1)
        XCTAssertEqual(driver.state.withLock { $0.closes }, 1); XCTAssertEqual(releases.lock.withLock { $0 }, 1)
        do { _ = try await client.execute(); XCTFail() } catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .closed) }
        await client.close(); XCTAssertEqual(releases.lock.withLock { $0 }, 1)
    }
    private func gatewayScope(boundTo driver: Driver, request: Data) async throws -> MachineUpdateConsumerHealthConnectionScope {
        let gateway = try Driver(gateway: true, boundTo: driver.requirement)
        return try await channel(gateway, authorityReadinessRequest: request).openScope()
    }

    func testInstalledAuthoritySendsItsPreparedChallengeAndExactGatewayExchange() async throws {
        let driver = try Driver(authority: true), client = try channel(driver, authorityInstalledReadiness: true)
        let root = try await client.prepareAuthorityReadinessChallenge()
        let gateway = try await gatewayScope(boundTo: driver, request: root)
        let scope = try await client.openScope(authorityGatewayExchange: gateway.exchange)
        let wire = try XCTUnwrap(driver.state.withLock { $0.request })
        let envelope = try MachineUpdateAuthorityReadinessRequest.decode(wire)
        XCTAssertEqual(envelope.challenge, root)
        XCTAssertEqual(envelope.gateway?.request, gateway.exchange.request)
        XCTAssertEqual(envelope.gateway?.response, gateway.exchange.response)
        XCTAssertEqual(scope.proof.role.requirement, driver.requirement)
        XCTAssertEqual(scope.proof.role.challengeDigest, MachineUpdateActivationRecord.digest(root))
        await scope.close()
        await gateway.close()
    }

    func testInstalledAuthorityRejectsGatewayExchangeForAnotherRootChallenge() async throws {
        let driver = try Driver(authority: true)
        let client = try channel(driver, authorityInstalledReadiness: true)
        let root = try await client.prepareAuthorityReadinessChallenge()
        let other = try MachineUpdateRoleChallengeSession(requirement: driver.requirement, verifyCurrent: {}).request
        XCTAssertNotEqual(root, other)
        let gateway = try await gatewayScope(boundTo: driver, request: other)
        do { _ = try await client.openScope(authorityGatewayExchange: gateway.exchange); XCTFail() }
        catch { XCTAssertEqual(error as? MachineUpdateRoleChallengeError, .changedScope) }
        XCTAssertEqual(driver.state.withLock { $0.checks }, 0)
        XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        await gateway.close()
    }

    func testOrdinaryChannelRejectsAnInstalledGatewayExchange() async throws {
        let root = try Driver(authority: true)
        let request = try MachineUpdateRoleChallengeSession(requirement: root.requirement, verifyCurrent: {}).request
        let gateway = try await gatewayScope(boundTo: root, request: request)
        let driver = try Driver(), client = try channel(driver)
        do { _ = try await client.openScope(authorityGatewayExchange: gateway.exchange); XCTFail() }
        catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .changedScope) }
        XCTAssertEqual(driver.state.withLock { $0.checks }, 0)
        XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        await gateway.close()
    }

    func testInstalledAuthorityCannotPrepareTwoChallenges() async throws {
        let driver = try Driver(authority: true), client = try channel(driver, authorityInstalledReadiness: true)
        _ = try await client.prepareAuthorityReadinessChallenge()
        do { _ = try await client.prepareAuthorityReadinessChallenge(); XCTFail() }
        catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .busy) }
        XCTAssertEqual(driver.state.withLock { $0.hellos }, 0)
        await client.close()
    }

    func testGatewayHotJournalRoutesOnlyToProtectedRecoveryAndNeverReturnsHealth() async throws {
        for protected in [true, false] {
            let driver = try Driver(gateway: true), recoveries = TestState(0)
            driver.state.withLock { $0.recoveryRequired = true }
            let client = try channel(driver)
            do {
                _ = try await MachineUpdateGatewayHealthRecovery.check(health: { try await client.execute() },
                    verifyRecovery: { if !protected { throw JournalLeaseError.invalidated } },
                    recoverOrdinary: { recoveries.lock.withLock { $0 += 1 } })
                XCTFail("Hot journal returned a health proof")
            } catch {
                if protected { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .gatewayRecoveryRequired) }
                else { XCTAssertEqual(error as? JournalLeaseError, .invalidated) }
            }
            XCTAssertEqual(recoveries.lock.withLock { $0 }, protected ? 1 : 0)
            XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        }
    }

    func testTransportCannotRequestGatewayJournalRecovery() async throws {
        let driver = try Driver(), client = try channel(driver)
        driver.state.withLock { $0.recoveryRequired = true }
        do {
            _ = try await MachineUpdateGatewayHealthRecovery.check(health: { try await client.execute() },
                verifyRecovery: { XCTFail("Transport reached recovery verification") },
                recoverOrdinary: { XCTFail("Transport reached Gateway recovery") })
            XCTFail("Invalid response returned health")
        } catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .invalidReply) }
    }

    func testGatewayExchangeReturnsTheFreshSignedHeadWithoutGrantingReconciliation() async throws {
        let driver = try Driver(gateway: true), proof = try await channel(driver).execute()
        XCTAssertEqual(proof.role.requirement, driver.requirement)
        XCTAssertNotNil(proof.gatewayHead); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
    }
    func testGatewayReplyWithoutTheMatchingHeadCannotComplete() async throws {
        for missing in [false, true] {
            let driver = try Driver(gateway: true)
            driver.state.withLock { $0.missingHead = missing; $0.wrongHeadNonce = !missing }
            do { _ = try await channel(driver).execute(); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.checks }, 1); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        }
    }
    func testWrongVersionMissingOrChangedHelloCannotSendTheChallenge() async throws {
        for mode in 0..<3 {
            let driver = try Driver()
            driver.state.withLock { if mode == 0 { $0.version = 2 }; if mode == 1 { $0.greeting = nil }; if mode == 2 { $0.greeting = Data([9]) } }
            do { _ = try await channel(driver).execute(); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.checks }, 0); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        }
    }
    func testSynchronousLossOrFailureAfterHelloCannotSendTheChallenge() async throws {
        for loss in [false, true] {
            let driver = try Driver()
            driver.state.withLock { $0.failAfterHello = !loss; $0.loseAfterHello = loss }
            do { _ = try await channel(driver).execute(); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.checks }, 0); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        }
    }
    func testPeerAuthenticationRunsBeforeTheChallenge() async throws {
        let driver = try Driver(); driver.state.withLock { $0.badPeer = true }
        do { _ = try await channel(driver).execute(); XCTFail() } catch {}
        XCTAssertGreaterThan(driver.state.withLock { $0.peerChecks }, 0)
        XCTAssertEqual(driver.state.withLock { $0.checks }, 0); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
    }
    func testScopeChangesAfterHelloPreventTheChallenge() async throws {
        let driver = try Driver(), valid = TestState(true)
        driver.state.withLock { $0.onHello = { valid.lock.withLock { $0 = false } } }
        do { _ = try await channel(driver, verify: { if !valid.lock.withLock({ $0 }) { throw Denied() } }).execute(); XCTFail() } catch {}
        XCTAssertEqual(driver.state.withLock { $0.checks }, 0)
    }
    func testChangedPeerCannotCompleteEvenACorrectlySignedReply() async throws {
        let driver = try Driver(); driver.state.withLock { $0.holdCheck = true }
        let client = try channel(driver), task = Task { try await client.execute() }
        try await waitUntil { driver.state.withLock { $0.held != nil } }
        driver.state.withLock { $0.badPeer = true }; try driver.finish()
        do { _ = try await task.value; XCTFail() } catch {}
        XCTAssertEqual(driver.state.withLock { $0.checks }, 1); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
    }
    func testMalformedOrWronglySignedReplyRetiresTheClientWithoutRetry() async throws {
        for malformed in [false, true] {
            let driver = try Driver(); driver.state.withLock { $0.malformed = malformed; $0.wrongSignature = !malformed }
            let client = try channel(driver)
            do { _ = try await client.execute(); XCTFail() } catch {}
            do { _ = try await client.execute(); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.checks }, 1); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        }
    }
    func testTimeoutAtEitherStepClosesAndIgnoresLateSuccess() async throws {
        for check in [false, true] {
            let driver = try Driver(); driver.state.withLock { $0.holdHello = !check; $0.holdCheck = check }
            let releases = TestState(0), client = try channel(driver, timeout: 20, release: { releases.lock.withLock { $0 += 1 } })
            do { _ = try await client.execute(); XCTFail() }
            catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .timedOut) }
            try driver.finish(); await client.close()
            XCTAssertEqual(driver.state.withLock { $0.checks }, check ? 1 : 0)
            XCTAssertEqual(driver.state.withLock { $0.closes }, 1); XCTAssertEqual(releases.lock.withLock { $0 }, 1)
        }
    }
    func testCancellationAtEitherStepClosesAndDoesNotRetry() async throws {
        for check in [false, true] {
            let driver = try Driver(); driver.state.withLock { $0.holdHello = !check; $0.holdCheck = check }
            let client = try channel(driver), task = Task { try await client.execute() }
            try await waitUntil { driver.state.withLock { $0.held != nil } }; task.cancel()
            do { _ = try await task.value; XCTFail() } catch {}
            try driver.finish(); await client.close()
            XCTAssertEqual(driver.state.withLock { $0.checks }, check ? 1 : 0)
            XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
        }
    }
    func testConcurrentExecuteCannotIssueASecondChallenge() async throws {
        let driver = try Driver(); driver.state.withLock { $0.holdCheck = true }
        let client = try channel(driver), first = Task { try await client.execute() }
        try await waitUntil { driver.state.withLock { $0.held != nil } }
        do { _ = try await client.execute(); XCTFail() } catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .busy) }
        try driver.finish(); _ = try await first.value
        XCTAssertEqual(driver.state.withLock { $0.hellos }, 1); XCTAssertEqual(driver.state.withLock { $0.checks }, 1)
    }
    func testDuplicateSuccessResumesOnlyOnce() async throws {
        let driver = try Driver(); driver.state.withLock { $0.duplicate = true }
        _ = try await channel(driver).execute()
        XCTAssertEqual(driver.state.withLock { $0.closes }, 1); XCTAssertEqual(driver.state.withLock { $0.checks }, 1)
    }
    func testClosingAnUnstartedClientReleasesItsScopeWithoutAConnection() async throws {
        let driver = try Driver(), releases = TestState(0), client = try channel(driver, release: { releases.lock.withLock { $0 += 1 } })
        await client.close(); await client.close()
        do { _ = try await client.execute(); XCTFail() } catch {}
        XCTAssertEqual(driver.state.withLock { $0.hellos }, 0); XCTAssertEqual(driver.state.withLock { $0.checks }, 0)
        XCTAssertEqual(driver.state.withLock { $0.closes }, 1); XCTAssertEqual(releases.lock.withLock { $0 }, 1)
    }
    private final class WeakClient {
        weak var value: MachineUpdateConsumerHealthChannel?
        init(_ value: MachineUpdateConsumerHealthChannel?) { self.value = value }
    }
    func testRetainedScopeKeepsTheConnectionAndSourceUntilJoinedClose() async throws {
        let driver = try Driver(), releases = TestState(0), client = try channel(driver, release: { releases.lock.withLock { $0 += 1 } })
        let scope = try await client.openScope()
        XCTAssertEqual(scope.proof.role.requirement, driver.requirement)
        try scope.validate(); try scope.validate()
        XCTAssertEqual(driver.state.withLock { $0.closes }, 0); XCTAssertEqual(releases.lock.withLock { $0 }, 0)
        XCTAssertEqual(driver.state.withLock { $0.checks }, 1)
        await scope.close(); await scope.close()
        XCTAssertEqual(driver.state.withLock { $0.closes }, 1); XCTAssertEqual(releases.lock.withLock { $0 }, 1)
        XCTAssertThrowsError(try scope.validate())
    }
    func testChangedPeerPermanentlyRetiresARetainedScope() async throws {
        let driver = try Driver(), releases = TestState(0), client = try channel(driver, release: { releases.lock.withLock { $0 += 1 } })
        let scope = try await client.openScope()
        driver.state.withLock { $0.badPeer = true }; XCTAssertThrowsError(try scope.validate())
        driver.state.withLock { $0.badPeer = false }; XCTAssertThrowsError(try scope.validate())
        await scope.close()
        XCTAssertEqual(driver.state.withLock { $0.checks }, 1); XCTAssertEqual(releases.lock.withLock { $0 }, 1)
    }
    func testChangedSourcePermanentlyRetiresARetainedScope() async throws {
        let driver = try Driver(), valid = TestState(true), releases = TestState(0)
        let client = try channel(driver, verify: { if !valid.lock.withLock({ $0 }) { throw Denied() } }, release: { releases.lock.withLock { $0 += 1 } })
        let scope = try await client.openScope()
        valid.lock.withLock { $0 = false }; XCTAssertThrowsError(try scope.validate())
        valid.lock.withLock { $0 = true }; XCTAssertThrowsError(try scope.validate())
        await scope.close(); XCTAssertEqual(releases.lock.withLock { $0 }, 1)
    }
    func testDisconnectInvalidatesARetainedScopeWithoutAnotherChallenge() async throws {
        let driver = try Driver(), client = try channel(driver), scope = try await client.openScope()
        driver.state.withLock { $0.lost }?()
        XCTAssertThrowsError(try scope.validate()); await scope.close()
        XCTAssertEqual(driver.state.withLock { $0.checks }, 1); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
    }
    func testTheScopeRetainsItsClientAndDroppingItClosesTheClient() async throws {
        let driver = try Driver(), releases = TestState(0)
        var client: MachineUpdateConsumerHealthChannel? = try channel(driver, release: { releases.lock.withLock { $0 += 1 } })
        let weak = WeakClient(client)
        var scope = try await client?.openScope(); client = nil
        XCTAssertNotNil(weak.value); try XCTUnwrap(scope).validate()
        scope = nil
        try await waitUntil { weak.value == nil && releases.lock.withLock { $0 == 1 } }
        XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
    }
    func testExplicitClientCloseInvalidatesTheRetainedScope() async throws {
        let driver = try Driver(), client = try channel(driver), scope = try await client.openScope()
        await client.close(); XCTAssertThrowsError(try scope.validate())
        await scope.close(); XCTAssertEqual(driver.state.withLock { $0.closes }, 1)
    }
    func testARetainedScopeCannotIssueAnotherChallenge() async throws {
        let driver = try Driver(), client = try channel(driver), scope = try await client.openScope()
        do { _ = try await client.openScope(); XCTFail() } catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .busy) }
        await scope.close()
        do { _ = try await client.openScope(); XCTFail() } catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .closed) }
        XCTAssertEqual(driver.state.withLock { $0.checks }, 1)
    }


    private final class AnonymousHealthEndpoint: NSObject, MachineUpdateConsumerHealthXPCProtocol, NSXPCListenerDelegate, @unchecked Sendable {
        let fixture: Driver
        private let lock = NSLock()
        private var connections: [NSXPCConnection] = []
        init(_ fixture: Driver) { self.fixture = fixture }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            connection.exportedInterface = NSXPCInterface(with: MachineUpdateConsumerHealthXPCProtocol.self)
            connection.exportedObject = self
            lock.withLock { connections.append(connection) }
            connection.activate()
            return true
        }
        func close() {
            let owned = lock.withLock {
                let owned = connections
                connections.removeAll()
                return owned
            }
            for connection in owned { connection.invalidate() }
        }
        func healthHello(reply: @escaping @Sendable (UInt64, Data?) -> Void) {
            fixture.state.withLock { $0.hellos += 1 }
            reply(MachineUpdateConsumerHealthChannel.wireVersion, Data([1, 2, 3]))
        }
        func checkUpdateHealth(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) {
            fixture.state.withLock { $0.checks += 1 }
            reply(try? fixture.packet(payload))
        }
    }

    /// The anonymous listener exercises NSXPC transport with injected credentials.
    func testAnonymousNativeDriverReturnsOneAuthenticatedProof() async throws {
        let fixture = try Driver()
        let endpoint = AnonymousHealthEndpoint(fixture), listener = NSXPCListener.anonymous()
        listener.delegate = endpoint
        listener.activate()
        defer { listener.invalidate(); endpoint.close() }
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        let credentials = XPCPeerCredentials(processID: 123, userID: fixture.requirement.executionUID, auditSessionID: 0)
        let driver = NativeMachineUpdateConsumerHealthDriver(connection: connection, inspectPeer: { credentials })
        let moment = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        let channel = try MachineUpdateConsumerHealthChannel(driver: driver, expectedHello: Data([1, 2, 3]),
            requirement: fixture.requirement, registration: nil, timeoutMilliseconds: 4000, clock: { moment })

        let proof = try await channel.execute()
        XCTAssertEqual(proof.role.requirement, fixture.requirement)
        XCTAssertEqual(fixture.state.withLock { $0.hellos }, 1)
        XCTAssertEqual(fixture.state.withLock { $0.checks }, 1)
    }

    func testAnonymousNativeDriverRejectsChangedCredentialsBeforeChallenge() async throws {
        let fixture = try Driver()
        let endpoint = AnonymousHealthEndpoint(fixture), listener = NSXPCListener.anonymous()
        listener.delegate = endpoint
        listener.activate()
        defer { listener.invalidate(); endpoint.close() }
        let inspections = TestState(0)
        let uid = fixture.requirement.executionUID
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        let driver = NativeMachineUpdateConsumerHealthDriver(connection: connection, inspectPeer: {
            let count = inspections.lock.withLock { $0 += 1; return $0 }
            return XPCPeerCredentials(processID: count == 1 ? 123 : 124, userID: uid, auditSessionID: 0)
        })
        let moment = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        let channel = try MachineUpdateConsumerHealthChannel(driver: driver, expectedHello: Data([1, 2, 3]),
            requirement: fixture.requirement, registration: nil, timeoutMilliseconds: 4000, clock: { moment })

        do {
            _ = try await channel.execute()
            XCTFail("A changed peer sent a challenge")
        } catch XPCPeerPolicyError.wrongPeer {}
        XCTAssertEqual(fixture.state.withLock { $0.hellos }, 1)
        XCTAssertEqual(fixture.state.withLock { $0.checks }, 0)
        XCTAssertEqual(inspections.lock.withLock { $0 }, 2)
    }

    func testAnonymousNativeDriverRejectsChangedCredentialsOnTheChallengeReply() async throws {
        let fixture = try Driver(), listener = NSXPCListener.anonymous()
        let endpoint = AnonymousHealthEndpoint(fixture), replyInspections = TestState(0)
        listener.delegate = endpoint
        listener.activate()
        defer { listener.invalidate(); endpoint.close() }
        let uid = fixture.requirement.executionUID
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        let driver = NativeMachineUpdateConsumerHealthDriver(connection: connection, inspectPeer: {
            let answering = fixture.state.withLock { $0.checks == 1 }
            if answering { replyInspections.lock.withLock { $0 += 1 } }
            return XPCPeerCredentials(processID: answering ? 124 : 123, userID: uid, auditSessionID: 0)
        })
        let moment = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        let channel = try MachineUpdateConsumerHealthChannel(driver: driver, expectedHello: Data([1, 2, 3]),
            requirement: fixture.requirement, registration: nil, timeoutMilliseconds: 4000, clock: { moment })
        do {
            _ = try await channel.execute()
            XCTFail("A reply from a changed peer supplied a proof")
        } catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .closed) }
        XCTAssertEqual(fixture.state.withLock { $0.hellos }, 1)
        XCTAssertEqual(fixture.state.withLock { $0.checks }, 1)
        XCTAssertEqual(replyInspections.lock.withLock { $0 }, 1)
        do { _ = try await channel.execute(); XCTFail() }
        catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .closed) }
    }
}
