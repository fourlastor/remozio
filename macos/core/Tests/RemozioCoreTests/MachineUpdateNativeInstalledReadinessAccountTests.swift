import CryptoKit
import Dispatch
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned peers test cleanup and nonce composition. These controls establish no native process identity or runtime readiness.
final class MachineUpdateNativeInstalledReadinessAccountTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private enum CleanupEvent: Equatable, Sendable { case peerClosed, activityReleased }
    private final class Peer: OwnedMachineUpdateHealthConnection, @unchecked Sendable {
        let proof: MachineUpdateConsumerHealthProof
        let exchange: MachineUpdateConsumerHealthExchange
        let state = Mutex((valid: true, closes: 0))
        private let onClose: @Sendable () -> Void
        init(proof: MachineUpdateConsumerHealthProof, exchange: MachineUpdateConsumerHealthExchange,
            onClose: @escaping @Sendable () -> Void = {}) {
            self.proof = proof; self.exchange = exchange; self.onClose = onClose
        }
        func validate() throws { guard state.withLock({ $0.valid && $0.closes == 0 }) else { throw Refused() } }
        func close() async { state.withLock { $0.closes += 1 }; onClose() }
    }
    private final class Root: OwnedMachineUpdateInstalledRootChannel, @unchecked Sendable {
        let fixture: MachineUpdateRoleChallengeTests.Fixture
        let expected: MachineUpdateRestartHealthPlan.Requirement
        let gateway: MachineUpdateAuthorityReadinessGateway?
        let moment: AuthorityMoment
        let state = Mutex((prepared: 0, connected: 0, closed: 0, session: Optional<MachineUpdateRoleChallengeSession>.none,
            peer: Optional<Peer>.none, beforeConnect: Optional<@Sendable () -> Void>.none, useForeignRequest: false))
        init(fixture: MachineUpdateRoleChallengeTests.Fixture, expected: MachineUpdateRestartHealthPlan.Requirement,
            gateway: MachineUpdateAuthorityReadinessGateway?, moment: AuthorityMoment) {
            self.fixture = fixture; self.expected = expected; self.gateway = gateway; self.moment = moment
        }
        func prepareChallenge() async throws -> Data {
            try state.withLock { state in
                guard state.prepared == 0, state.closed == 0 else { throw Refused() }
                state.prepared += 1
                let session = try MachineUpdateRoleChallengeSession(requirement: expected, verifyCurrent: {})
                state.session = session; return try session.request
            }
        }
        func connect(gateway exchange: MachineUpdateConsumerHealthExchange?) async throws -> any OwnedMachineUpdateHealthConnection {
            state.withLock { $0.beforeConnect }?()
            let session = try state.withLock { state in
                guard state.connected == 0, state.closed == 0, let session = state.session else { throw Refused() }
                state.connected += 1
                if state.useForeignRequest { return try MachineUpdateRoleChallengeSession(requirement: expected, verifyCurrent: {}) }
                return session
            }
            let request = try session.request
            let wire = try MachineUpdateAuthorityReadinessRequest(challenge: request, gateway: exchange)
            _ = try wire.gatewayProof(expected: gateway, now: moment)
            let response = try fixture.answer(request, expected: expected)
            let proof = try session.accept(response, authenticatePeer: { _ in })
            let packet = try MachineUpdateConsumerHealthPacket(roleReply: response, gatewayHead: nil).encoded
            let peer = Peer(proof: .init(role: proof, gatewayHead: nil), exchange: .init(request: request, response: packet))
            state.withLock { $0.peer = peer }; return peer
        }
        func close() async {
            state.withLock { state in
                state.closed += 1
                if state.closed == 1 { state.session?.close() }
            }
        }
    }
    private final class Fixture: @unchecked Sendable {
        let signer: MachineUpdateRoleChallengeTests.Fixture
        let requirements: [MachineUpdateRestartHealthPlan.Requirement]
        let registration: GatewayRegistrationIdentity
        let root: Root
        let moment: AuthorityMoment
        let valid = Mutex(true), releases = Mutex(0)
        let clock: Mutex<AuthorityMoment>
        let peers = Mutex<[UInt64: Peer]>([:])
        let cleanup = Mutex<[CleanupEvent]>([])
        init(withGateway: Bool = true) throws {
            let signer = MachineUpdateRoleChallengeTests.Fixture(); self.signer = signer
            let moment = AuthorityMoment(epoch: UUID(), milliseconds: 100); self.moment = moment; clock = Mutex(moment)
            let authority = try signer.requirement(), transport = try signer.requirement(role: .transport, uid: 20000)
            let gateway = try signer.requirement(role: .notificationGateway, uid: 20001)
            requirements = [authority, transport] + (withGateway ? [gateway] : [])
            let registration = try GatewayRegistrationIdentity(ownerID: Data(repeating: 1, count: 16),
                macID: authority.binding.macID, accountID: authority.binding.accountID,
                gatewayID: Data(repeating: 4, count: 16), lifecycleEpoch: Data(repeating: 5, count: 16),
                rootPublicKey: authority.publicKey)
            self.registration = registration
            root = Root(fixture: signer, expected: authority,
                gateway: withGateway ? try .init(requirement: gateway, registration: registration) : nil, moment: moment)
        }
        func peer(_ requirement: MachineUpdateRestartHealthPlan.Requirement, rootRequest: Data?,
            onClose: @escaping @Sendable () -> Void = {}) throws -> Peer {
            let moment = moment
            let session = try MachineUpdateConsumerHealthChallengeSession(requirement: requirement,
                registration: requirement.role == .notificationGateway ? registration : nil,
                authorityReadinessRequest: rootRequest, clock: { moment }, verifyCurrent: {})
            defer { session.close() }
            let request = try session.makeRequest(), response = try signer.answer(request, expected: requirement)
            let head: GatewayHeadReply?
            if requirement.role == .notificationGateway {
                let payload = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .unsigned(1),
                    2: .bytes(registration.encode()), 3: .bytes(MachineUpdateGatewayHealthQuery.nonce(request)),
                    4: .unsigned(0), 5: .unsigned(0), 6: .bytes(Data()), 7: .bytes(Data())]),
                    limits: .init(maxBytes: 16384, maxDepth: 1, maxItems: 17))
                head = .init(canonicalPayload: payload,
                    signature: try signer.key.signature(for: Data("Remozio/GatewayHeadReply/v1\0".utf8) + payload).rawRepresentation)
            } else { head = nil }
            let packet = try MachineUpdateConsumerHealthPacket(roleReply: response, gatewayHead: head).encoded
            let value = Peer(proof: try session.accept(packet, authenticatePeer: { _ in }),
                exchange: .init(request: request, response: packet), onClose: onClose)
            peers.withLock { $0[requirement.role.rawValue] = value }; return value
        }
        func account(lifetime: UInt64 = 30000, readClock: (@Sendable () throws -> AuthorityMoment)? = nil,
            factory: (@Sendable (MachineUpdateRestartHealthPlan.Requirement, Data?) async throws -> any OwnedMachineUpdateHealthConnection)? = nil) throws
            -> MachineUpdateNativeInstalledReadinessAccount {
            try .init(accountID: requirements[0].binding.accountID, requirements: requirements, lifetimeMilliseconds: lifetime,
                operations: .init(verifyCurrent: { [self] in guard valid.withLock({ $0 }) else { throw Refused() } },
                    clock: readClock ?? { [self] in clock.withLock { $0 } }, makeRoot: { [self] in root },
                    makeConsumer: { [self] requirement, request in
                        if let factory { return try await factory(requirement, request) }
                        return try peer(requirement, rootRequest: request)
                    }, release: { [self] in
                        releases.withLock { $0 += 1 }
                        cleanup.withLock { $0.append(.activityReleased) }
                    }))
        }
        func assertClosed(file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertEqual(root.state.withLock { $0.closed }, 1, file: file, line: line)
            for peer in peers.withLock({ Array($0.values) }) { XCTAssertEqual(peer.state.withLock { $0.closes }, 1, file: file, line: line) }
            if let peer = root.state.withLock({ $0.peer }) { XCTAssertEqual(peer.state.withLock { $0.closes }, 1, file: file, line: line) }
            XCTAssertEqual(releases.withLock { $0 }, 1, file: file, line: line)
        }
    }
    private func until(_ predicate: () -> Bool) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() {
            guard ContinuousClock.now < end else { throw Refused() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testAllLivePeersRemainOwnedUntilJoinedCleanup() async throws {
        let f = try Fixture(), owner = try f.account()
        try owner.validateOrdinaryReadiness()
        let replies = try await owner.check()
        XCTAssertEqual(Set(replies.map { $0.requirement.role }), [.authority, .transport, .notificationGateway])
        XCTAssertEqual(f.root.state.withLock { $0.prepared }, 1); XCTAssertEqual(f.root.state.withLock { $0.connected }, 1)
        try owner.validate(); try owner.validateOrdinaryReadiness()
        for peer in f.peers.withLock({ Array($0.values) }) { XCTAssertEqual(peer.state.withLock { $0.closes }, 0) }
        XCTAssertEqual(f.releases.withLock { $0 }, 0)
        try await owner.close(); try await owner.close(); f.assertClosed()
        XCTAssertThrowsError(try owner.validate()); XCTAssertThrowsError(try owner.validateOrdinaryReadiness())
    }
    func testAnAccountWithoutGatewayUsesOnlyRootAndTransport() async throws {
        let f = try Fixture(withGateway: false), owner = try f.account()
        let replies = try await owner.check()
        XCTAssertEqual(replies.count, 2)
        XCTAssertNil(f.peers.withLock { $0[AuthorityCodeRole.notificationGateway.rawValue] })
        try await owner.close(); f.assertClosed()
    }
    func testAConsumerFailureKeepsRootOwnedAndStopsTheRootSigningRequest() async throws {
        let f = try Fixture(), owner = try f.account(factory: { _,_ in throw Refused() })
        do { _ = try await owner.check(); XCTFail() } catch {}
        XCTAssertEqual(f.root.state.withLock { $0.prepared }, 1); XCTAssertEqual(f.root.state.withLock { $0.connected }, 0)
        XCTAssertEqual(f.releases.withLock { $0 }, 0)
        try await owner.close(); f.assertClosed()
    }
    func testAMismatchedExchangeIsRetainedThenRejectedBeforeRootReplies() async throws {
        let f = try Fixture(withGateway: false)
        let owner = try f.account(factory: { requirement, request in
            let original = try f.peer(requirement, rootRequest: request)
            let changed = Peer(proof: original.proof,
                exchange: .init(request: original.exchange.request + Data([0]), response: original.exchange.response))
            await original.close()
            f.peers.withLock { $0[requirement.role.rawValue] = changed }; return changed
        })
        do { _ = try await owner.check(); XCTFail() } catch {}
        XCTAssertEqual(f.root.state.withLock { $0.connected }, 0)
        try await owner.close(); f.assertClosed()
    }
    func testADuplicateConsumerOwnerIsClosedOnceWithoutARootReply() async throws {
        let f = try Fixture(), shared = Mutex<Peer?>(nil)
        let owner = try f.account(factory: { requirement, request in
            if let peer = shared.withLock({ $0 }) { return peer }
            let peer = try f.peer(requirement, rootRequest: request); shared.withLock { $0 = peer }; return peer
        })
        do { _ = try await owner.check(); XCTFail() }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .duplicateOwner) }
        XCTAssertEqual(f.root.state.withLock { $0.connected }, 0)
        try await owner.close(); f.assertClosed()
    }
    func testALostPeerBeforeRootRepliesPreventsTheReadinessResult() async throws {
        let f = try Fixture(), owner = try f.account()
        f.root.state.withLock { $0.beforeConnect = { f.peers.withLock { $0[AuthorityCodeRole.transport.rawValue] }?.state.withLock { $0.valid = false } } }
        defer { f.root.state.withLock { $0.beforeConnect = nil } }
        do { _ = try await owner.check(); XCTFail() } catch {}
        try await owner.close(); f.assertClosed()
    }
    func testPeerLossAfterTheProofPermanentlyRetiresTheScope() async throws {
        let f = try Fixture(), owner = try f.account(); _ = try await owner.check()
        let peer = try XCTUnwrap(f.peers.withLock { $0[AuthorityCodeRole.notificationGateway.rawValue] })
        peer.state.withLock { $0.valid = false }; XCTAssertThrowsError(try owner.validateOrdinaryReadiness())
        peer.state.withLock { $0.valid = true }; XCTAssertThrowsError(try owner.validate())
        try await owner.close(); f.assertClosed()
    }
    func testConcurrentReadinessValidationsSerializeClockSampling() async throws {
        let f = try Fixture(withGateway: false)
        let firstRead = DispatchSemaphore(value: 0), releaseFirst = DispatchSemaphore(value: 0)
        let secondStarted = DispatchSemaphore(value: 0), secondRead = DispatchSemaphore(value: 0)
        let next = Mutex<Int?>(nil)
        let owner = try f.account(readClock: {
            let sample = next.withLock { value -> Int? in
                guard let sample = value else { return nil }
                value = sample + 1
                return sample
            }
            switch sample {
            case 0:
                firstRead.signal()
                guard releaseFirst.wait(timeout: .now() + .seconds(5)) == .success else { throw Refused() }
            case 1:
                secondRead.signal()
            default:
                break
            }
            return .init(epoch: f.moment.epoch, milliseconds: f.moment.milliseconds + UInt64(sample ?? 0))
        })
        _ = try await owner.check()
        next.withLock { $0 = 0 }
        func validateConcurrently() {
            let done = DispatchGroup()
            let failures = Mutex<[String]>([])
            for index in 0..<2 {
                done.enter()
                DispatchQueue.global().async {
                    defer { done.leave() }
                    if index == 1 { secondStarted.signal() }
                    do { try owner.validateOrdinaryReadiness() }
                    catch { failures.withLock { $0.append(String(describing: error)) } }
                }
                if index == 0 {
                    XCTAssertEqual(firstRead.wait(timeout: .now() + .seconds(4)), .success)
                }
            }
            XCTAssertEqual(secondStarted.wait(timeout: .now() + .seconds(4)), .success)
            // The first clock read cannot return yet. The second validator must wait before sampling.
            XCTAssertEqual(secondRead.wait(timeout: .now() + .milliseconds(300)), .timedOut)
            releaseFirst.signal()
            XCTAssertEqual(done.wait(timeout: .now() + .seconds(4)), .success)
            XCTAssertEqual(failures.withLock { $0 }, [])
        }
        validateConcurrently()
        try owner.validate()
        try await owner.close()
        f.assertClosed()
    }

    func testExpiredBackwardAndChangedEpochClocksCannotReviveTheProof() async throws {
        for variant in 0..<3 {
            let f = try Fixture(), owner = try f.account(lifetime: 1000); _ = try await owner.check()
            f.clock.withLock { $0 = .init(epoch: variant == 2 ? UUID() : f.moment.epoch, milliseconds: variant == 0 ? 1100 : 99) }
            XCTAssertThrowsError(try owner.validate())
            f.clock.withLock { $0 = f.moment }; XCTAssertThrowsError(try owner.validateOrdinaryReadiness())
            try await owner.close(); f.assertClosed()
        }
    }
    func testAChangedMachineScopeAndASecondCheckCannotReuseTheProof() async throws {
        let f = try Fixture(), owner = try f.account(); _ = try await owner.check()
        do { _ = try await owner.check(); XCTFail() } catch {}
        f.valid.withLock { $0 = false }; XCTAssertThrowsError(try owner.validate())
        f.valid.withLock { $0 = true }; XCTAssertThrowsError(try owner.validateOrdinaryReadiness())
        try await owner.close(); f.assertClosed()
    }
    func testCloseJoinsALateConsumerFactoryBeforeItReleasesActivity() async throws {
        let f = try Fixture(withGateway: false), gate = Mutex<CheckedContinuation<Peer, Never>?>(nil)
        let cancelled = Mutex(false)
        let owner = try f.account(factory: { _, _ in
            await withTaskCancellationHandler {
                await withCheckedContinuation { continuation in gate.withLock { $0 = continuation } }
            } onCancel: {
                cancelled.withLock { $0 = true }
            }
        })
        let checking = Task { try await owner.check() }
        try await until { gate.withLock { $0 != nil } }
        let closing = Task { try await owner.close() }
        try await until { cancelled.withLock { $0 } }
        XCTAssertEqual(f.releases.withLock { $0 }, 0)
        let late = try f.peer(XCTUnwrap(f.requirements.first(where: { $0.role == .transport })), rootRequest: nil,
            onClose: { f.cleanup.withLock { $0.append(.peerClosed) } })
        gate.withLock { value in let saved = value; value = nil; return saved }?.resume(returning: late)
        _ = await checking.result; try await closing.value
        f.assertClosed()
        XCTAssertEqual(late.state.withLock { $0.closes }, 1)
        XCTAssertEqual(f.cleanup.withLock { $0 }, [.peerClosed, .activityReleased])
    }

    func testOrdinaryReadinessRefusesAnInProgressCheckWithoutRetiringIt() async throws {
        let f = try Fixture(withGateway: false), gate = Mutex<CheckedContinuation<Peer, Never>?>(nil)
        let peer = try f.peer(XCTUnwrap(f.requirements.first(where: { $0.role == .transport })), rootRequest: nil)
        let owner = try f.account(factory: { _, _ in
            await withCheckedContinuation { continuation in gate.withLock { $0 = continuation } }
        })
        let checking = Task { try await owner.check() }
        try await until { gate.withLock { $0 != nil } }
        XCTAssertThrowsError(try owner.validateOrdinaryReadiness()) {
            XCTAssertEqual($0 as? MachineUpdateHealthCoordinatorError, .incompleteHealth)
        }
        gate.withLock { value in let saved = value; value = nil; return saved }?.resume(returning: peer)
        _ = try await checking.value
        try owner.validateOrdinaryReadiness()
        try await owner.close()
        f.assertClosed()
    }

    func testRetainRefusesGatewayEvidenceWithoutTheHeadAndStillClosesThePeer() async throws {
        let f = try Fixture()
        let owner = try f.account(factory: { requirement, request in
            let peer = try f.peer(requirement, rootRequest: request)
            guard requirement.role == .notificationGateway else { return peer }
            let missing = Peer(proof: .init(role: peer.proof.role, gatewayHead: nil), exchange: peer.exchange)
            await peer.close()
            f.peers.withLock { $0[requirement.role.rawValue] = missing }
            return missing
        })
        do { _ = try await owner.check(); XCTFail("A Gateway proof without its head passed") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .incompleteHealth) }
        XCTAssertEqual(f.root.state.withLock { $0.connected }, 0)
        try await owner.close()
        f.assertClosed()
    }

    func testRetainRejectsARootReplyForAnotherValidRequest() async throws {
        let f = try Fixture(withGateway: false)
        f.root.state.withLock { $0.useForeignRequest = true }
        let owner = try f.account()
        do { _ = try await owner.check(); XCTFail("A foreign Root challenge passed") }
        catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .changedScope) }
        try await owner.close()
        f.assertClosed()
    }

    func testDroppingVerifiedAccountJoinsPeerCleanupBeforeReleasingActivity() async throws {
        let f = try Fixture(withGateway: false)
        var owner: MachineUpdateNativeInstalledReadinessAccount? = try f.account()
        _ = try await owner?.check()
        owner = nil
        try await until { f.releases.withLock { $0 == 1 } }
        f.assertClosed()
    }

    func testInstalledReadinessRefusesGatewayRecoveryWithoutRequestingTheRootReply() async throws {
        let f = try Fixture()
        let owner = try f.account(factory: { requirement, request in
            if requirement.role == .notificationGateway {
                throw MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired
            }
            return try f.peer(requirement, rootRequest: request)
        })
        do { _ = try await owner.check(); XCTFail("A hot journal produced readiness") }
        catch { XCTAssertEqual(error as? MachineUpdateConsumerHealthChannelError, .gatewayRecoveryRequired) }
        XCTAssertEqual(f.root.state.withLock { $0.connected }, 0)
        try await owner.close()
        f.assertClosed()
    }
}
