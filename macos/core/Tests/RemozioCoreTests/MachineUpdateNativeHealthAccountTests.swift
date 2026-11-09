import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned software keys, temporary paired stores and injected peers test composition. Native identity and key custody remain unproven.
final class MachineUpdateNativeHealthAccountTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class Root: OwnedMachineUpdateAuthorityHealth, @unchecked Sendable {
        struct State { var signs = 0, gatewayChecks = 0, closeCalls = 0, closes = 0, closeFailures = 0, invalid = false, badHead = false }
        let state = Mutex(State())
        let signer: MachineUpdateRoleChallengeTests.Fixture
        let requirement: MachineUpdateRestartHealthPlan.Requirement
        init(signer: MachineUpdateRoleChallengeTests.Fixture, requirement: MachineUpdateRestartHealthPlan.Requirement) {
            self.signer = signer; self.requirement = requirement
        }
        func answerRestartReadiness(_ request: MachineUpdateAuthorityReadinessRequest) throws -> Data {
            try validateHealthScope()
            try state.withLock {
                if request.gateway != nil { $0.gatewayChecks += 1; if $0.badHead { throw Failed() } }
                $0.signs += 1
            }
            return try signer.answer(request.challenge, expected: requirement)
        }
        func validateHealthScope() throws { try state.withLock { if $0.invalid || $0.closes > 0 { throw Failed() } } }
        func requireGatewayHealth(_ proof: MachineUpdateConsumerHealthProof) throws {
            try validateHealthScope()
            try state.withLock { $0.gatewayChecks += 1; if $0.badHead || proof.gatewayHead == nil { throw Failed() } }
        }
        func close() throws {
            try state.withLock {
                $0.closeCalls += 1
                if $0.closeFailures > 0 { $0.closeFailures -= 1; throw Failed() }
                $0.closes += 1
            }
        }
    }
    private final class Reader: OwnedMachineUpdateGatewayJournalHealth {
        struct State { var accepts = 0, validations = 0, closes = 0, accepted = false, invalid = false }
        let state = Mutex(State())
        func accept(_ proof: MachineUpdateConsumerHealthProof) throws {
            try state.withLock {
                guard !$0.invalid, !$0.accepted, proof.gatewayHead != nil else { throw Failed() }
                $0.accepted = true; $0.accepts += 1
            }
        }
        func validateHealthScope() throws {
            try state.withLock {
                guard $0.accepted, !$0.invalid, $0.closes == 0 else { throw Failed() }; $0.validations += 1
            }
        }
        func close() { state.withLock { $0.closes += 1 } }
    }
    private final class Connection: OwnedMachineUpdateHealthConnection {
        let proof: MachineUpdateConsumerHealthProof
        let exchange: MachineUpdateConsumerHealthExchange
        let valid = Mutex(true), busy = Mutex(false), closes = Mutex(0)
        init(_ proof: MachineUpdateConsumerHealthProof, exchange: MachineUpdateConsumerHealthExchange) {
            self.proof = proof; self.exchange = exchange
        }
        func validate() throws {
            if busy.withLock({ $0 }) { throw MachineUpdateHealthSourceError.busy }
            if !valid.withLock({ $0 }) || closes.withLock({ $0 > 0 }) { throw Failed() }
        }
        func close() async { closes.withLock { $0 += 1 } }
    }
    private final class Fixture: @unchecked Sendable {
        struct State { var rootFactories = 0, readerFactories = 0, connectionFactories = 0, valid = true, invalidateAfterRoot = false }
        let state = Mutex(State())
        let base: MachineUpdateRoleChallengeTests.Fixture
        let rootSigner: MachineUpdateRoleChallengeTests.Fixture
        let transportSigner: MachineUpdateRoleChallengeTests.Fixture
        let gatewaySigner: MachineUpdateRoleChallengeTests.Fixture
        let root: Root
        let reader: Reader
        let accountID: Data
        let requirements: [MachineUpdateRestartHealthPlan.Requirement]
        let registration: GatewayRegistrationIdentity
        let connections = Mutex<[Connection]>([])
        init(gatewayOnly: Bool = false, gateway: Bool = true) throws {
            let base = MachineUpdateRoleChallengeTests.Fixture(), r = MachineUpdateRoleChallengeTests.Fixture()
            let t = MachineUpdateRoleChallengeTests.Fixture(), g = MachineUpdateRoleChallengeTests.Fixture()
            func requirement(_ role: AuthorityCodeRole, _ uid: UInt32, _ key: Data) throws -> MachineUpdateRestartHealthPlan.Requirement {
                try base.requirement(role: role, uid: uid, publicKey: key)
            }
            let root = try requirement(.authority, 0, r.key.publicKey.x963Representation)
            let transport = try requirement(.transport, 20000, t.key.publicKey.x963Representation)
            let push = try requirement(.notificationGateway, 20001, g.key.publicKey.x963Representation)
            self.base = base; rootSigner = r; transportSigner = t; gatewaySigner = g
            self.root = Root(signer: r, requirement: root); reader = Reader()
            accountID = root.binding.accountID
            requirements = gatewayOnly ? [push] : [root, transport] + (gateway ? [push] : [])
            registration = try .init(ownerID: Data(repeating: 8, count: 16), macID: root.binding.macID,
                accountID: root.binding.accountID, gatewayID: Data(repeating: 9, count: 16),
                lifecycleEpoch: Data(repeating: 10, count: 16), rootPublicKey: root.publicKey)
        }
        func connection(_ requirement: MachineUpdateRestartHealthPlan.Requirement, authorityChallenge: Data? = nil) throws -> Connection {
            let signer = requirement.role == .transport ? transportSigner : gatewaySigner
            let moment = AuthorityMoment(epoch: UUID(), milliseconds: 100)
            let session = try MachineUpdateConsumerHealthChallengeSession(requirement: requirement,
                registration: requirement.role == .notificationGateway ? registration : nil,
                authorityReadinessRequest: authorityChallenge, clock: { moment }, verifyCurrent: {})
            let request = try session.makeRequest(), role = try signer.answer(request, expected: requirement)
            let head: GatewayHeadReply?
            if requirement.role == .notificationGateway {
                let bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .unsigned(1), 2: .bytes(registration.encode()),
                    3: .bytes(MachineUpdateGatewayHealthQuery.nonce(request)), 4: .unsigned(0), 5: .unsigned(0),
                    6: .bytes(Data()), 7: .bytes(Data())]), limits: .init(maxBytes: 16384, maxDepth: 2, maxItems: 128))
                head = .init(canonicalPayload: bytes, signature: try signer.key.signature(for: Data("Remozio/GatewayHeadReply/v1\0".utf8) + bytes).rawRepresentation)
            } else { head = nil }
            let packet = try MachineUpdateConsumerHealthPacket(roleReply: role, gatewayHead: head).encoded
            let value = Connection(try session.accept(packet, authenticatePeer: { _ in }),
                exchange: .init(request: request, response: packet))
            connections.withLock { $0.append(value) }; return value
        }
        func operations(factory: (@Sendable (MachineUpdateRestartHealthPlan.Requirement, Data?) async throws -> any OwnedMachineUpdateHealthConnection)? = nil)
            -> MachineUpdateNativeHealthAccount.Operations {
            .init(verifyCurrent: { [self] in if !state.withLock({ $0.valid }) { throw Failed() } },
                makeAuthority: { [self] in
                    state.withLock { $0.rootFactories += 1; if $0.invalidateAfterRoot { $0.valid = false } }; return root
                }, makeGatewayReader: { [self] in state.withLock { $0.readerFactories += 1 }; return reader },
                makeConnection: { [self] requirement, authorityChallenge in
                    state.withLock { $0.connectionFactories += 1 }
                    if let factory { return try await factory(requirement, authorityChallenge) }
                    return try connection(requirement, authorityChallenge: authorityChallenge)
                })
        }
        func account(factory: (@Sendable (MachineUpdateRestartHealthPlan.Requirement, Data?) async throws -> any OwnedMachineUpdateHealthConnection)? = nil) throws
            -> MachineUpdateNativeHealthAccount {
            try .init(accountID: accountID, requirements: requirements, operations: operations(factory: factory))
        }
    }
    private final class WeakAccount {
        weak var value: MachineUpdateNativeHealthAccount?
        init(_ value: MachineUpdateNativeHealthAccount?) { self.value = value }
    }
    private func until(_ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !predicate() { guard ContinuousClock.now < deadline else { throw Failed() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testForegroundAndGatewayShareOnePairedAuthorityOwnerAndKeepBothConnections() async throws {
        let fixture = try Fixture(), account = try fixture.account(), replies = try await account.check()
        XCTAssertEqual(Set(replies.map { $0.requirement.role.rawValue }), Set(fixture.requirements.map { $0.role.rawValue }))
        XCTAssertEqual(fixture.state.withLock { $0.rootFactories }, 1); XCTAssertEqual(fixture.state.withLock { $0.readerFactories }, 0)
        XCTAssertEqual(fixture.root.state.withLock { $0.signs }, 1); XCTAssertGreaterThan(fixture.root.state.withLock { $0.gatewayChecks }, 0)
        XCTAssertTrue(fixture.connections.withLock { $0.allSatisfy { $0.closes.withLock { $0 == 0 } } })
        try account.validate(); try await account.close()
        XCTAssertEqual(fixture.root.state.withLock { $0.closes }, 1)
        XCTAssertTrue(fixture.connections.withLock { $0.allSatisfy { $0.closes.withLock { $0 == 1 } } })
    }
    func testGatewayOnlyUsesThePairedReaderWithoutAnAuthoritySigner() async throws {
        let fixture = try Fixture(gatewayOnly: true), account = try fixture.account(), replies = try await account.check()
        XCTAssertEqual(replies.map { $0.requirement.role }, [.notificationGateway])
        XCTAssertEqual(fixture.state.withLock { $0.rootFactories }, 0); XCTAssertEqual(fixture.root.state.withLock { $0.signs }, 0)
        XCTAssertEqual(fixture.state.withLock { $0.readerFactories }, 1); XCTAssertEqual(fixture.reader.state.withLock { $0.accepts }, 1)
        try account.validate(); XCTAssertGreaterThan(fixture.reader.state.withLock { $0.validations }, 0)
        try await account.close(); XCTAssertEqual(fixture.reader.state.withLock { $0.closes }, 1)
    }
    func testForegroundWithoutGatewayDoesNotOpenItsReaderOrReconcileAHead() async throws {
        let fixture = try Fixture(gateway: false), account = try fixture.account()
        let replies = try await account.check(); XCTAssertEqual(replies.count, 2)
        XCTAssertEqual(fixture.state.withLock { $0.readerFactories }, 0); XCTAssertEqual(fixture.root.state.withLock { $0.gatewayChecks }, 0)
        try await account.close()
    }
    func testInvalidSourceFailsBeforeAnyFactory() async throws {
        let fixture = try Fixture(), account = try fixture.account(); fixture.state.withLock { $0.valid = false }
        do { _ = try await account.check(); XCTFail() } catch {}
        XCTAssertEqual(fixture.state.withLock { $0.rootFactories + $0.readerFactories + $0.connectionFactories }, 0)
        try await account.close()
    }
    func testSourceChangesAfterOpeningAuthorityCannotReachSigningOrAConsumer() async throws {
        let fixture = try Fixture(), account = try fixture.account(); fixture.state.withLock { $0.invalidateAfterRoot = true }
        do { _ = try await account.check(); XCTFail() } catch {}
        XCTAssertEqual(fixture.root.state.withLock { $0.signs }, 0); XCTAssertEqual(fixture.state.withLock { $0.connectionFactories }, 0)
        try await account.close(); XCTAssertEqual(fixture.root.state.withLock { $0.closes }, 1)
    }
    func testForeignConsumerEvidenceIsRetainedForCleanupAndCannotComplete() async throws {
        let fixture = try Fixture(gateway: false)
        let foreign = try fixture.base.requirement(role: .transport, uid: 20000, account: 99,
            publicKey: fixture.transportSigner.key.publicKey.x963Representation)
        let connection = try fixture.connection(foreign), account = try fixture.account(factory: { _, _ in connection })
        do { _ = try await account.check(); XCTFail() } catch { XCTAssertEqual(error as? MachineUpdateHealthCoordinatorError, .incompleteHealth) }
        try await account.close(); XCTAssertEqual(connection.closes.withLock { $0 }, 1)
        XCTAssertEqual(fixture.root.state.withLock { $0.closes }, 1)
    }
    func testGatewayHeadFailurePreventsAReadyAccount() async throws {
        let fixture = try Fixture(), account = try fixture.account(); fixture.root.state.withLock { $0.badHead = true }
        do { _ = try await account.check(); XCTFail() } catch {}
        XCTAssertThrowsError(try account.validate()); try await account.close()
        XCTAssertEqual(fixture.root.state.withLock { $0.signs }, 0)
        XCTAssertEqual(fixture.root.state.withLock { $0.closes }, 1)
    }
    func testUnboundGatewayExchangeCannotReachAuthoritySigning() async throws {
        let fixture = try Fixture()
        let account = try fixture.account(factory: { requirement, authorityChallenge in
            if requirement.role == .notificationGateway {
                XCTAssertNotNil(authorityChallenge)
                return try fixture.connection(requirement)
            }
            XCTAssertNil(authorityChallenge)
            return try fixture.connection(requirement)
        })
        do { _ = try await account.check(); XCTFail("Unbound Gateway exchange returned health") }
        catch { XCTAssertEqual(error as? MachineUpdateRoleChallengeError, .changedScope) }
        XCTAssertEqual(fixture.root.state.withLock { $0.signs }, 0)
        try await account.close()
    }

    func testFailedJournalCloseRetainsOnlyTheFailedOwnerForRetry() async throws {
        let fixture = try Fixture(), account = try fixture.account(); _ = try await account.check()
        fixture.root.state.withLock { $0.closeFailures = 1 }
        do { try await account.close(); XCTFail() } catch {}
        XCTAssertEqual(fixture.root.state.withLock { $0.closes }, 0)
        XCTAssertTrue(fixture.connections.withLock { $0.allSatisfy { $0.closes.withLock { $0 == 1 } } })
        try await account.close(); XCTAssertEqual(fixture.root.state.withLock { $0.closeCalls }, 2)
        XCTAssertTrue(fixture.connections.withLock { $0.allSatisfy { $0.closes.withLock { $0 == 1 } } })
    }
    func testCloseJoinsAConnectionFactoryThatIgnoresCancellation() async throws {
        let fixture = try Fixture(gateway: false), gate = Mutex<CheckedContinuation<Connection, Never>?>(nil), done = Mutex(false)
        let connection = try fixture.connection(XCTUnwrap(fixture.requirements.first { $0.role == .transport }))
        let account = try fixture.account(factory: { _, _ in await withCheckedContinuation { continuation in gate.withLock { $0 = continuation } } })
        let checking = Task { try await account.check() }
        try await until { gate.withLock { $0 != nil } }
        let closing = Task { try await account.close(); done.withLock { $0 = true } }
        XCTAssertFalse(done.withLock { $0 }); XCTAssertEqual(fixture.root.state.withLock { $0.closes }, 0)
        gate.withLock { value in let old = value; value = nil; old?.resume(returning: connection) }
        _ = await checking.result; try await closing.value
        XCTAssertEqual(connection.closes.withLock { $0 }, 1); XCTAssertEqual(fixture.root.state.withLock { $0.closes }, 1)
    }
    func testChangedLiveConnectionPermanentlyRetiresTheAccount() async throws {
        let fixture = try Fixture(gateway: false), account = try fixture.account(); _ = try await account.check()
        let connection = try XCTUnwrap(fixture.connections.withLock { $0.first })
        connection.busy.withLock { $0 = true }
        XCTAssertThrowsError(try account.validate()) { XCTAssertEqual($0 as? MachineUpdateHealthSourceError, .busy) }
        connection.busy.withLock { $0 = false }
        try account.validate()
        connection.valid.withLock { $0 = false }; XCTAssertThrowsError(try account.validate())
        connection.valid.withLock { $0 = true }; XCTAssertThrowsError(try account.validate())
        try await account.close(); XCTAssertEqual(fixture.root.state.withLock { $0.signs }, 1)
    }
    func testTheAccountCannotRepeatItsHealthAttempt() async throws {
        let fixture = try Fixture(gateway: false), account = try fixture.account(); _ = try await account.check()
        do { _ = try await account.check(); XCTFail() } catch {}
        XCTAssertEqual(fixture.root.state.withLock { $0.signs }, 1); XCTAssertEqual(fixture.state.withLock { $0.connectionFactories }, 1)
        try await account.close()
    }
    func testTheConstructorRejectsAnotherAccountBeforeOpeningResources() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try MachineUpdateNativeHealthAccount(accountID: Data(repeating: 99, count: 16),
            requirements: fixture.requirements, operations: fixture.operations()))
        XCTAssertEqual(fixture.state.withLock { $0.rootFactories + $0.readerFactories + $0.connectionFactories }, 0)
    }
    func testClosingAnUnstartedAccountPreventsEveryFactory() async throws {
        let fixture = try Fixture(), account = try fixture.account(); try await account.close()
        do { _ = try await account.check(); XCTFail() } catch {}
        XCTAssertEqual(fixture.state.withLock { $0.rootFactories + $0.readerFactories + $0.connectionFactories }, 0)
    }
    func testDroppingAReadyAccountRetainsFailedJournalCleanup() async throws {
        let fixture = try Fixture()
        var account: MachineUpdateNativeHealthAccount? = try fixture.account()
        _ = try await account?.check(); fixture.root.state.withLock { $0.closeFailures = 1 }
        let weak = WeakAccount(account); account = nil
        try await until { weak.value == nil && fixture.root.state.withLock { $0.closes == 1 } }
        XCTAssertTrue(fixture.connections.withLock { $0.allSatisfy { $0.closes.withLock { $0 == 1 } } })
    }
}
