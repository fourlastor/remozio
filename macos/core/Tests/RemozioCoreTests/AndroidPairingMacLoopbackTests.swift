import CryptoKit
import Darwin
import Foundation
import Network
import RemozioProtocol
import Security
import Synchronization
import XCTest
@testable import RemozioCore

/// The local runner sets a directory to use the API 37 Android client. CI uses the native test client.
final class AndroidPairingMacLoopbackTests: XCTestCase, @unchecked Sendable {
    private enum FixtureError: Error { case timeout, listenerFailed, unexpectedFrame }

    private struct Ready: Encodable {
        let port: UInt16
        let publicInvitation: String
        let windowID: String
    }

    private struct State: Sendable {
        var port: UInt16?
        var failed = false
        var reservations = 0
        var receipts = 0
    }

    private final class Observation: Sendable {
        let value = Mutex(State())
    }

    // The Android test uses the same synthetic secret. Only the test fixture uses it.
    private static let invitationSecret = Data(repeating: 0x63, count: 32)
    private static let lifetimeMilliseconds: UInt64 = 120_000

    func testInvitationProofAndReceiptOnTheNativeListener() async throws {
        try await assertNativePairing()
    }

    func testLANFilterCancelsBeforeAllocatingChannelsOrSpendingIngressCredit() async throws {
        let address = PairingLANRoute.Address.ipv4(try XCTUnwrap(IPv4Address("192.0.2.1")))
        let offset = try XCTUnwrap(MemoryLayout<sockaddr_in>.offset(of: \.sin_addr))
        let mask = [UInt8(offset + 3), UInt8(AF_INET)] + Array(repeating: 0, count: offset - 2) + [255, 255, 255]
        let subnet = try XCTUnwrap(PairingLANSubnet(bound: address, netmask: mask))
        try await assertNativePairing(filteredBy: subnet)
    }

    private func assertNativePairing(filteredBy subnet: PairingLANSubnet? = nil) async throws {
        let authority = P256.Signing.PrivateKey()
        let transport = P256.Signing.PrivateKey()
        let publicInvitation = try PairingInvitation(macID: AuthorityPairingSetupAccess.secureRandom(16),
            accountID: AuthorityPairingSetupAccess.secureRandom(16), label: "Pairing Test Mac",
            authorityPublicKey: authority.publicKey.x963Representation, transportPublicKey: transport.publicKey.x963Representation,
            minimumEnvelopeVersion: 1)
        let invitation = try PairingInvitationV2(invitation: publicInvitation,
            windowID: AuthorityPairingSetupAccess.secureRandom(16), secret: Self.invitationSecret,
            lifetimeMilliseconds: Self.lifetimeMilliseconds)
        let epoch = UUID()
        let now: @Sendable () -> AuthorityMoment = {
            AuthorityMoment(epoch: epoch, milliseconds: DispatchTime.now().uptimeNanoseconds / 1_000_000)
        }
        let window = try AuthorityPairingV2Window(invitation: invitation, predecessor: nil, started: now())
        let observation = Observation()
        let channels = Mutex(0), allowPeer = Mutex(false), offLinkSources = Mutex<UInt32>(0)
        let fixture = subnet.map {
            PairingSetupListener.IngressFixture(peerSubnet: $0,
                now: { .init(epoch: epoch, milliseconds: 100) },
                channelAllocated: { channels.withLock { $0 += 1 } })
        }
        let ingress = PairingSetupV2Ingress(windowID: invitation.windowID, lifetimeMilliseconds: invitation.lifetimeMilliseconds,
            reserve: { proof in
                try window.reserve(proof, at: now())
                observation.value.withLock { $0.reservations += 1 }
            }, disconnect: { _ = window.disconnected($0) })
        let listener = try PairingSetupListener(
            identity: AuthorityJournalSchema19MigrationTests.fixtureIdentity(transport), invitation: publicInvitation,
            binding: .loopback, maximumConnections: 4, handshakeTimeoutMilliseconds: 5_000, setupTimeoutMilliseconds: 30_000,
            v2: ingress, sourceKey: { endpoint in
                guard subnet != nil else { return PairingSetupV2Source(endpoint) }
                if allowPeer.withLock({ $0 }) { return .ipv4(0xc0000202) }
                return offLinkSources.withLock {
                    $0 += 1
                    return .ipv4(0xc6336400 + $0)
                }
            }, ingressFixture: fixture, event: { event in
                observation.value.withLock {
                    switch event {
                    case .ready(let port): $0.port = port
                    case .failed: $0.failed = true
                    case .stopped: break
                    }
                }
            }, handler: { session in
                do {
                    let proposal = try await session.proposal()
                    let provedConnection = await session.provedConnection
                    let connection = try XCTUnwrap(provedConnection)
                    let selected = try window.takeProposal(connection: connection, matching: proposal.encode(), at: now())
                    let transcript = try Self.transcript(for: selected, invitation: publicInvitation)
                    try await session.stage(transcript)
                    _ = try await session.receiveProof()
                    let receipt = try authority.signature(for: transcript.signingInput(purpose: .macCommit)).rawRepresentation
                    try await session.sendReceipt(receipt)
                    observation.value.withLock { $0.receipts += 1 }
                } catch {
                    observation.value.withLock { $0.failed = true }
                    throw error
                }
            })
        try listener.start()
        do {
            try await wait(observation, seconds: 5) { $0.port != nil }
            let port = try XCTUnwrap(observation.value.withLock { $0.port })
            if subnet != nil {
                for _ in 0..<(2 * PairingRegistrationBudget.ingressBurst) {
                    do {
                        try await Self.pairNativeClient(port: port, invitation: invitation)
                        XCTFail("An off-link candidate completed pairing")
                    } catch {}
                }
                XCTAssertEqual(offLinkSources.withLock { $0 }, UInt32(2 * PairingRegistrationBudget.ingressBurst))
                XCTAssertEqual(channels.withLock { $0 }, 0)
                XCTAssertEqual(observation.value.withLock { $0.reservations }, 0)
                allowPeer.withLock { $0 = true }
                try await Self.pairNativeClient(port: port, invitation: invitation)
                XCTAssertEqual(channels.withLock { $0 }, 1)
            } else if let directory = ProcessInfo.processInfo.environment["REMOZIO_ANDROID_PAIRING_LOOPBACK_DIR"] {
                let ready = try Ready(port: port, publicInvitation: publicInvitation.exportText(),
                    windowID: invitation.windowID.map { String(format: "%02x", $0) }.joined())
                try JSONEncoder().encode(ready).write(
                    to: URL(fileURLWithPath: directory, isDirectory: true).appendingPathComponent("ready.json"), options: .atomic)
            } else {
                try await Self.pairNativeClient(port: port, invitation: invitation)
            }
            try await wait(observation, seconds: 110) { $0.receipts == 1 }
            XCTAssertEqual(observation.value.withLock { $0.reservations }, 1)
            XCTAssertEqual(observation.value.withLock { $0.receipts }, 1)
        } catch {
            await listener.closeAndWait()
            throw error
        }
        await listener.closeAndWait()
    }

    private func wait(_ observation: Observation, seconds: Int, until ready: (State) -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(seconds))
        while ContinuousClock.now < deadline {
            let snapshot = observation.value.withLock { $0 }
            if snapshot.failed { throw FixtureError.listenerFailed }
            if ready(snapshot) { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        throw FixtureError.timeout
    }

    static func transcript(for proposal: PairingPhoneProposal, invitation: PairingInvitation) throws -> PairingTranscript {
        let mac = try ChannelOffer(role: .mac, scope: proposal.phone.scope, nonce: AuthorityPairingSetupAccess.secureRandom(32),
            envelopeVersions: [1], requests: [], auditVersions: [])
        let issued = UInt64(Date().timeIntervalSince1970 * 1000)
        return try PairingTranscript(setupID: AuthorityPairingSetupAccess.secureRandom(16),
            challenge: AuthorityPairingSetupAccess.secureRandom(32), phone: proposal.phone, mac: mac,
            minimumEnvelopeVersion: invitation.minimumEnvelopeVersion, selectedEnvelopeVersion: 1,
            macAuthorityKey: invitation.authorityPublicKey, macTransportKey: invitation.transportPublicKey,
            transportKey: proposal.transportKey, decisionKey: proposal.decisionKey, biometricKey: proposal.biometricKey,
            enrollmentTag: AuthorityPairingSetupAccess.secureRandom(32), replacement: proposal.replacement,
            expectedTrustRevision: Data(repeating: 1, count: 16), issuedAtUnixMillis: issued, expiresAtUnixMillis: issued + 30_000)
    }

    static func pairNativeClient(port: UInt16, invitation: PairingInvitationV2,
                                 afterChallenge: @Sendable () async -> Void = {}) async throws {
        let transport = P256.Signing.PrivateKey()
        let biometric = P256.Signing.PrivateKey()
        let scope = try ChannelScope(macID: invitation.invitation.macID, accountID: invitation.invitation.accountID,
            phoneID: invitation.replacement?.phoneID ?? Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
        let proposal = try PairingPhoneProposal(phone: ChannelOffer(role: .phone, scope: scope,
            nonce: AuthorityPairingSetupAccess.secureRandom(32), envelopeVersions: [1], requests: [], auditVersions: []),
            transportKey: .init(keyID: Data(repeating: 5, count: 16), publicKey: transport.publicKey.x963Representation),
            decisionKey: .init(keyID: Data(repeating: 6, count: 16), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            biometricKey: .init(keyID: Data(repeating: 7, count: 16), publicKey: biometric.publicKey.x963Representation), replacement: invitation.replacement)
        let (channel, connection) = try AuthorityJournalSchema19MigrationTests.fixtureConnectLookup(port: port,
            purpose: PairingSetupPreludeV2.applicationProtocol, serverKey: invitation.invitation.transportPublicKey,
            identity: AuthorityJournalSchema19MigrationTests.fixtureIdentity(transport))
        defer { channel.abort() }
        try await channel.start(timeoutMilliseconds: 2_000)
        let metadata = try XCTUnwrap(connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata)
        let label = PairingInvitationV2.exporterLabel
        let secret = try XCTUnwrap(sec_protocol_metadata_create_secret(metadata.securityProtocolMetadata, label.utf8.count, label, 32))
        let exporter = Data(DispatchData._unconditionallyBridgeFromObjectiveC(secret))
        let prelude = try await AuthorityJournalSchema19MigrationTests.fixtureReadNativeFrame(from: channel, maximum: PairingSetupPreludeV2.maximumBytes)
        guard case .challenge(let challenge) = try PairingSetupPreludeV2.decode(prelude) else { throw FixtureError.unexpectedFrame }
        await afterChallenge()
        let tag = try invitation.proof(proposal: proposal, challenge: challenge, exporter: exporter)
        try await AuthorityJournalSchema19MigrationTests.fixtureSendNativeFrame(
            PairingSetupPreludeV2.proposal(proposal, tag: tag).encode(), to: channel)
        let frame = try await AuthorityJournalSchema19MigrationTests.fixtureReadNativeFrame(from: channel, maximum: PairingSetupFrame.maximumBytes)
        guard case .transcript(let transcript) = try PairingSetupFrame.decode(frame) else { throw FixtureError.unexpectedFrame }
        try proposal.validate(transcript)
        try invitation.invitation.validateMacClaims(in: transcript)
        let digest = try transcript.digest()
        let proof = try biometric.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation
        try await AuthorityJournalSchema19MigrationTests.fixtureSendNativeFrame(
            PairingSetupFrame.proof(setupID: transcript.setupID, digest: digest, signature: proof).encode(), to: channel)
        let response = try await AuthorityJournalSchema19MigrationTests.fixtureReadNativeFrame(from: channel, maximum: PairingSetupFrame.maximumBytes)
        guard case .receipt(let setup, let receivedDigest, let signature) = try PairingSetupFrame.decode(response) else {
            throw FixtureError.unexpectedFrame
        }
        XCTAssertEqual(setup, transcript.setupID)
        XCTAssertEqual(receivedDigest, digest)
        XCTAssertTrue(try transcript.verify(signature: signature, publicKey: invitation.invitation.authorityPublicKey, purpose: .macCommit))
        await channel.close()
    }
}
