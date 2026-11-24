import Darwin
import Foundation
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
        let registered = Mutex<RegistrationReply?>(nil)
        let confirmed = Mutex<(@Sendable (Bool) -> Void)?>(nil)
        let holdRegistration = Mutex(true)
        let holdConfirmation = Mutex(false)
        let nextID = UUID()
        let policy: XPCPeerPolicy
        let requirement: String

        init(holdConfirm: Bool) throws {
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
                reply(AuthorityPairingProofWire.bytes(nextID), Data(repeating: 1, count: 32))
            }
        }

        func verifyCandidate(_ candidateID: Data, proposal: Data, tag: Data, reply: @escaping @Sendable (Bool) -> Void) {
            reply(candidateID == AuthorityPairingProofWire.bytes(nextID))
        }

        func confirmCandidate(_ candidateID: Data, reply: @escaping @Sendable (Bool) -> Void) {
            if holdConfirmation.withLock({ $0 }) {
                confirmed.withLock { $0 = reply }
            } else { reply(true) }
        }

        func retireCandidate(_ candidateID: Data, reply: @escaping @Sendable (Bool) -> Void) { reply(true) }

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
        let slot = UUID(), accepted = ContinuousClock.now
        let cutoff = accepted.advanced(by: .seconds(1))
        var admissions = PairingSetupV2Admissions()
        XCTAssertEqual(admissions.admit(slot, deadline: cutoff, draining: 0), .admitted(evicting: nil))
        let registration = Task { try await Self.register(client, connectionID: slot, deadline: cutoff) }
        await fulfillment(of: [replies.registrationArrived], timeout: 2)
        if cancel {
            for _ in 0..<3 { _ = admissions.admit(UUID(), deadline: cutoff, draining: 0) }
            XCTAssertEqual(admissions.admit(UUID(), deadline: cutoff, draining: 0), .admitted(evicting: slot))
            registration.cancel()
        }
        do {
            _ = try await registration.value
            XCTFail("An abandoned registration returned a candidate")
        } catch {
            if cancel { XCTAssertTrue(error is CancellationError) }
            else { guard case AuthorityXPCError.timedOut = error else { return XCTFail("Expected registration timeout") } }
        }

        if !cancel { XCTAssertTrue(admissions.expire(slot, at: cutoff)) }
        replies.deliverOldRegistration()
        replies.holdRegistration.withLock { $0 = false }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        let next = try await Self.register(client, deadline: deadline)
        XCTAssertEqual(next.id, replies.nextID)
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

    func testLostConfirmationRetiresTheLinkAndIgnoresALateReply() async throws {
        let replies = try Replies(holdConfirm: true)
        let closes = CloseCount()
        let client = try await replies.client(closes: closes)
        defer { client.close() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(1))
        try await client.verify(candidate: replies.nextID, proposal: Data([1]), tag: Data(repeating: 6, count: 32), deadline: deadline)
        do {
            try await client.confirm(candidate: replies.nextID, deadline: deadline)
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
