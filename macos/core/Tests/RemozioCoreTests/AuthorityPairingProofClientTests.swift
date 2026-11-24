import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Security
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityPairingProofClientTests: XCTestCase, @unchecked Sendable {
    private final class CloseCount: Sendable {
        let value = Mutex(0)
    }
    private typealias RegistrationReply = @Sendable (Data?, Data?) -> Void

    /// Script reply delivery over an anonymous connection with no TCP or installed service.
    private final class Replies: NSObject, AuthorityPairingProofXPCProtocol, NSXPCListenerDelegate, @unchecked Sendable {
        let listener = NSXPCListener.anonymous()
        let registrationArrived = XCTestExpectation(description: "Registration requested")
        let verificationArrived = XCTestExpectation(description: "Verification requested")
        let retirementArrived = XCTestExpectation(description: "Retirement requested")
        let registered = Mutex<RegistrationReply?>(nil)
        let confirmed = Mutex<(@Sendable (Bool) -> Void)?>(nil)
        let holdRegistration = Mutex(true)
        let holdConfirmation = Mutex(false)
        let holdVerification = Mutex(false)
        let verified = Mutex<(@Sendable (Bool) -> Void)?>(nil)
        let live = Mutex<Set<Data>>([])
        let retired = Mutex<[Data]>([])
        let confirmationCount = Mutex(0)
        let advanceBeforeVerifyReply: @Sendable () -> Void
        let advanceBeforeConfirmReply: @Sendable () -> Void
        let policy: XPCPeerPolicy
        let requirement: String

        init(holdConfirm: Bool = false, advanceBeforeVerifyReply: @escaping @Sendable () -> Void = {},
             advanceBeforeConfirmReply: @escaping @Sendable () -> Void = {}) throws {
            self.advanceBeforeVerifyReply = advanceBeforeVerifyReply
            self.advanceBeforeConfirmReply = advanceBeforeConfirmReply
            var dynamic: SecCode?, fixed: SecStaticCode?, info: CFDictionary?
            guard SecCodeCopySelf([], &dynamic) == errSecSuccess, let dynamic,
                  SecCodeCopyStaticCode(dynamic, [], &fixed) == errSecSuccess, let fixed,
                  SecCodeCopySigningInformation(fixed, [], &info) == errSecSuccess,
                  let fields = info as? [String: Any], let hash = fields[kSecCodeInfoUnique as String] as? Data,
                  hash.count == 20 else { throw AuthorityXPCError.invalidConfiguration }
            requirement = "cdhash H\"" + XPCPeerPolicy.hexadecimalCodeDirectoryHash(hash) + "\""
            policy = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.remozio.fixture",
                approvedCodeDirectoryHashes: [hash], expectedUserID: geteuid())
            super.init()
            holdConfirmation.withLock { $0 = holdConfirm }
            listener.setConnectionCodeSigningRequirement(requirement)
            listener.delegate = self
            listener.activate()
        }

        deinit { listener.invalidate() }

        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            connection.setCodeSigningRequirement(requirement)
            connection.exportedInterface = NSXPCInterface(with: AuthorityPairingProofXPCProtocol.self)
            connection.exportedObject = self
            connection.activate()
            return true
        }

        func hello(reply: @escaping @Sendable (UInt64) -> Void) { reply(2) }
        func bindWindow(_ windowID: Data, reply: @escaping @Sendable (Bool) -> Void) { reply(true) }

        func registerCandidate(_ connectionID: Data, acceptedAt: UInt64, peerPoint: Data, exporter: Data,
                               reply: @escaping RegistrationReply) {
            if holdRegistration.withLock({ $0 }) {
                registered.withLock { $0 = reply }
                registrationArrived.fulfill()
            } else {
                let candidate = AuthorityPairingProofWire.bytes(UUID())
                live.withLock { _ = $0.insert(candidate) }
                reply(candidate, Data(repeating: 1, count: 32))
            }
        }

        func verifyCandidate(_ candidateID: Data, proposal: Data, tag: Data, reply: @escaping @Sendable (Bool) -> Void) {
            guard live.withLock({ $0.contains(candidateID) }) else { reply(false); return }
            if holdVerification.withLock({ $0 }) {
                verified.withLock { $0 = reply }
                verificationArrived.fulfill()
            } else {
                advanceBeforeVerifyReply()
                reply(true)
            }
        }

        func confirmCandidate(_ candidateID: Data, reply: @escaping @Sendable (Bool) -> Void) {
            confirmationCount.withLock { $0 += 1 }
            guard live.withLock({ $0.contains(candidateID) }) else { reply(false); return }
            if holdConfirmation.withLock({ $0 }) {
                confirmed.withLock { $0 = reply }
            } else {
                advanceBeforeConfirmReply()
                reply(true)
            }
        }

        func retireCandidate(_ candidateID: Data, reply: @escaping @Sendable (Bool) -> Void) {
            live.withLock { _ = $0.remove(candidateID) }
            let first = retired.withLock { values in values.append(candidateID); return values.count == 1 }
            if first { retirementArrived.fulfill() }
            reply(true)
        }

        func client(closes: CloseCount) async throws -> AuthorityPairingProofClient {
            let client = AuthorityPairingProofClient(endpoint: listener.endpoint, peerPolicy: policy,
                onClose: { closes.value.withLock { $0 += 1 } }, configure: { $0.setCodeSigningRequirement(requirement) })
            try await client.start(windowID: Data(repeating: 2, count: 16))
            return client
        }

        func deliverOldRegistration() {
            let old = registered.withLock { value in
                let old = value
                value = nil
                return old
            }
            old?(AuthorityPairingProofWire.bytes(UUID()), Data(repeating: 3, count: 32))
        }
    }

    private static func register(_ client: AuthorityPairingProofClient, connectionID: UUID = UUID(),
                                 deadline: ContinuousClock.Instant) async throws
        -> AuthorityPairingProofReservations.Candidate {
        try await client.register(connectionID: connectionID, acceptedAt: 0, peerPoint: Data(repeating: 4, count: 65),
                                  exporter: Data(repeating: 5, count: 32), deadline: deadline)
    }

    private func abandonRegistration(cancel: Bool) async throws {
        let replies = try Replies(holdConfirm: false)
        let closes = CloseCount()
        let client = try await replies.client(closes: closes)
        defer { client.close() }
        let cutoff = ContinuousClock.now.advanced(by: .seconds(1))
        let registration = Task { try await Self.register(client, deadline: cutoff) }
        await fulfillment(of: [replies.registrationArrived], timeout: 2)
        if cancel { registration.cancel() }
        do {
            _ = try await registration.value
            XCTFail("An abandoned registration returned a candidate")
        } catch {
            if cancel { XCTAssertTrue(error is CancellationError) }
            else { guard case AuthorityXPCError.timedOut = error else { return XCTFail("Expected registration timeout") } }
        }

        replies.deliverOldRegistration()
        replies.holdRegistration.withLock { $0 = false }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        let next = try await Self.register(client, deadline: deadline)
        XCTAssertTrue(replies.live.withLock { $0.contains(AuthorityPairingProofWire.bytes(next.id)) })
        try await client.verify(candidate: next.id, proposal: Data([1]), tag: Data(repeating: 6, count: 32), deadline: deadline)
        try await client.confirm(candidate: next.id, deadline: deadline)
        XCTAssertEqual(closes.value.withLock { $0 }, 0)
    }

    func testCancelledSlotRegistrationDoesNotRetireTheProofLink() async throws {
        try await abandonRegistration(cancel: true)
    }

    func testExpiredSlotRegistrationDoesNotRetireTheProofLink() async throws {
        try await abandonRegistration(cancel: false)
    }

    func testCancelledVerificationRetiresOnlyTheCandidate() async throws {
        try await abandonVerification(cancel: true)
    }

    func testExpiredVerificationRetiresOnlyTheCandidate() async throws {
        try await abandonVerification(cancel: false)
    }

    private func abandonVerification(cancel: Bool) async throws {
        let replies = try Replies()
        replies.holdRegistration.withLock { $0 = false }
        replies.holdVerification.withLock { $0 = true }
        let closes = CloseCount()
        let client = try await replies.client(closes: closes)
        defer { client.close() }
        let candidate = try await Self.register(client, deadline: ContinuousClock.now.advanced(by: .seconds(2)))
        let cutoff = ContinuousClock.now.advanced(by: .seconds(1))
        let proof = Task {
            try await client.verify(candidate: candidate.id, proposal: Data([1]), tag: Data(repeating: 6, count: 32), deadline: cutoff)
        }
        await fulfillment(of: [replies.verificationArrived], timeout: 2)
        if cancel { proof.cancel() }
        do {
            try await proof.value
            XCTFail("An abandoned verification returned success")
        } catch {
            if cancel { XCTAssertTrue(error is CancellationError) }
            else { guard case AuthorityXPCError.timedOut = error else { return XCTFail("Expected verification timeout") } }
        }
        let first = AuthorityPairingProofWire.bytes(candidate.id)
        XCTAssertEqual(replies.retired.withLock { $0 }, [first])
        XCTAssertFalse(replies.live.withLock { $0.contains(first) })
        replies.verified.withLock { callback in callback?(true); callback = nil }
        replies.holdVerification.withLock { $0 = false }

        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        let new = try await Self.register(client, deadline: deadline)
        XCTAssertNotEqual(new.id, candidate.id)
        try await client.verify(candidate: new.id, proposal: Data([1]), tag: Data(repeating: 6, count: 32), deadline: deadline)
        try await client.confirm(candidate: new.id, deadline: deadline)
        XCTAssertEqual(closes.value.withLock { $0 }, 0)
    }

    func testNativeListenerKeepsItsWindowAfterAnExpiredRegistration() async throws {
        try await expiredNativeCandidate(duringVerification: false)
    }

    func testNativeListenerKeepsItsWindowAfterAnExpiredVerification() async throws {
        try await expiredNativeCandidate(duringVerification: true)
    }

    private func expiredNativeCandidate(duringVerification: Bool) async throws {
        let replies = try Replies()
        replies.holdRegistration.withLock { $0 = !duringVerification }
        replies.holdVerification.withLock { $0 = duringVerification }
        let closes = CloseCount()
        let client = try await replies.client(closes: closes)
        defer { client.close() }
        let fixture = try TransportPairingFixture()
        let invitation = try PairingInvitationV2(invitation: fixture.invitation, windowID: Data(repeating: 2, count: 16),
            secret: Data(repeating: 3, count: 32), lifetimeMilliseconds: 15_000)
        let served = Mutex(false)
        let (listener, port) = try await listen(fixture, invitation: invitation, client: client) { session in
            let proposal = try await session.proposal()
            let transcript = try AndroidPairingMacLoopbackTests.transcript(for: proposal, invitation: fixture.invitation)
            try await session.stage(transcript)
            _ = try await session.receiveProof()
            let receipt = try fixture.authority.signature(for: transcript.signingInput(purpose: .macCommit)).rawRepresentation
            served.withLock { $0 = true }
            try await session.sendReceipt(receipt)
        }
        do {
            do {
                try await AndroidPairingMacLoopbackTests.pairNativeClient(port: port, invitation: invitation)
                XCTFail("The candidate with a delayed reply completed pairing")
            } catch {}
            if duringVerification {
                await fulfillment(of: [replies.retirementArrived], timeout: 2)
                XCTAssertFalse(replies.retired.withLock { $0.isEmpty })
            } else {
                XCTAssertNotNil(replies.registered.withLock { $0 })
                replies.deliverOldRegistration()
            }
            XCTAssertEqual(closes.value.withLock { $0 }, 0)
            XCTAssertFalse(served.withLock { $0 })
            replies.holdRegistration.withLock { $0 = false }
            replies.holdVerification.withLock { $0 = false }
            try await AndroidPairingMacLoopbackTests.pairNativeClient(port: port, invitation: invitation)
        } catch {
            await listener.closeAndWait()
            throw error
        }
        await listener.closeAndWait()
        XCTAssertTrue(served.withLock { $0 })
    }

    func testNativeListenerRejectsAProofExpiredBeforeConfirmation() async throws {
        try await failNativeConfirmation(afterConfirm: false)
    }

    func testNativeListenerRejectsAProofExpiredAfterConfirmation() async throws {
        try await failNativeConfirmation(afterConfirm: true)
    }

    private func failNativeConfirmation(afterConfirm: Bool) async throws {
        let expired = Mutex(false)
        let replies = try Replies(advanceBeforeVerifyReply: { if !afterConfirm { expired.withLock { $0 = true } } },
                                  advanceBeforeConfirmReply: { if afterConfirm { expired.withLock { $0 = true } } })
        replies.holdRegistration.withLock { $0 = false }
        let closes = CloseCount()
        let client = try await replies.client(closes: closes)
        defer { client.close() }
        let fixture = try TransportPairingFixture()
        let invitation = try PairingInvitationV2(invitation: fixture.invitation, windowID: Data(repeating: 2, count: 16),
            secret: Data(repeating: 3, count: 32), lifetimeMilliseconds: 15_000)
        let (listener, port) = try await listen(fixture, invitation: invitation, client: client, proofTime: {
            ContinuousClock.now.advanced(by: .seconds(expired.withLock { $0 } ? 4 : 0))
        }) { _ in XCTFail("An expired proof reached the pairing handler") }
        do {
            try await AndroidPairingMacLoopbackTests.pairNativeClient(port: port, invitation: invitation)
            XCTFail("An expired proof completed pairing")
        } catch {}
        await listener.closeAndWait()
        XCTAssertTrue(expired.withLock { $0 })
        XCTAssertEqual(replies.confirmationCount.withLock { $0 }, afterConfirm ? 1 : 0)
        XCTAssertEqual(closes.value.withLock { $0 }, 1)
    }

    private func listen(_ fixture: TransportPairingFixture, invitation: PairingInvitationV2, client: AuthorityPairingProofClient,
                        proofTime: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now },
                        handler: @escaping @Sendable (PairingSetupNetworkSession) async throws -> Void)
        async throws -> (PairingSetupListener, UInt16) {
        let ready = AsyncStream<UInt16>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let ingress = PairingSetupV2Ingress(windowID: invitation.windowID, lifetimeMilliseconds: invitation.lifetimeMilliseconds, authority: client)
        let listener = try PairingSetupListener(identity: AuthorityJournalSchema19MigrationTests.fixtureIdentity(fixture.macTransport),
            invitation: fixture.invitation, binding: .loopback, maximumConnections: 4, handshakeTimeoutMilliseconds: 3_000,
            setupTimeoutMilliseconds: invitation.lifetimeMilliseconds, v2: ingress, proofTime: proofTime, event: { event in
                if case .ready(let port) = event { ready.continuation.yield(port) }
                ready.continuation.finish()
            }, handler: handler)
        try listener.start()
        var ports = ready.stream.makeAsyncIterator()
        let port = await ports.next()
        return try (listener, XCTUnwrap(port))
    }

    func testLostConfirmationRetiresTheLinkAndIgnoresALateReply() async throws {
        let replies = try Replies(holdConfirm: true)
        let closes = CloseCount()
        let client = try await replies.client(closes: closes)
        defer { client.close() }
        replies.holdRegistration.withLock { $0 = false }
        let deadline = ContinuousClock.now.advanced(by: .seconds(1))
        let candidate = try await Self.register(client, deadline: deadline)
        try await client.verify(candidate: candidate.id, proposal: Data([1]), tag: Data(repeating: 6, count: 32), deadline: deadline)
        do {
            try await client.confirm(candidate: candidate.id, deadline: deadline)
            XCTFail("Expected confirmation timeout")
        } catch {
            guard case AuthorityXPCError.timedOut = error else { return XCTFail("Expected confirmation timeout") }
        }
        replies.confirmed.withLock { callback in callback?(true); callback = nil }
        XCTAssertEqual(closes.value.withLock { $0 }, 1)
        do {
            _ = try await Self.register(client, deadline: ContinuousClock.now.advanced(by: .seconds(1)))
            XCTFail("The retired link registered a candidate")
        } catch {}
    }
}
