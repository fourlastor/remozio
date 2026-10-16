import CryptoKit
import Darwin
import Foundation
import Network
import Security
import RemozioCore
import RemozioProtocol

// Synthetic loopback echo only. Never package this executable with the app.
enum ProbeError: Error { case invalidInput, identityImport(OSStatus) }
struct Setup: Decodable { let peerPublicKey: String; let negotiate: Bool?; let commandMessages: Bool?; let secondPeerPublicKey: String?; let maximumConnections: Int?; let pairing: Bool?; let holdPairingStage: Bool?; let receiptRecovery: Bool? }

func emit(_ fields: [String: Int]) {
    guard let data = try? JSONSerialization.data(withJSONObject: fields) else { exit(1) }
    FileHandle.standardOutput.write(data + Data([10]))
}

final class Probe: @unchecked Sendable {
    let queue = DispatchQueue(label: "dev.remozio.experiment.tls")
    let listener: NWListener
    var connections: [UUID: NetworkByteChannel] = [:]

    init(identity: SecIdentity, peerPublicKey: Data) throws {
        let peer = try PinnedTLSPeer(subjectPublicKeyInfo: peerPublicKey)
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        guard let local = sec_identity_create(identity) else { throw ProbeError.invalidInput }
        sec_protocol_options_set_local_identity(options, local)
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_peer_authentication_required(options, true)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_set_tls_tickets_enabled(options, false)
        sec_protocol_options_add_tls_application_protocol(options, "remozio-experiment/1")
        sec_protocol_options_set_verify_block(options, { metadata, _, complete in
            var leaf: SecCertificate?
            let accessible = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
                if leaf == nil { leaf = sec_certificate_copy_ref(certificate).takeRetainedValue() }
            }
            guard accessible, let leaf else { complete(false); return }
            complete(peer.accepts(certificate: SecCertificateCopyData(leaf) as Data))
        }, queue)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        listener = try NWListener(using: parameters)
    }

    func start() {
        listener.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                guard let port = listener.port else { exit(1) }
                emit(["port": Int(port.rawValue)])
            case .failed: exit(1)
            default: break
            }
        }
        listener.newConnectionHandler = { [self] connection in
            guard connections.count < 8 else { connection.cancel(); return }
            let id = UUID()
            let channel = NetworkByteChannel(connection: connection) { connection in
                guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata,
                      let name = sec_protocol_metadata_copy_negotiated_protocol(tls.securityProtocolMetadata) else { return false }
                defer { free(UnsafeMutableRawPointer(mutating: name)) }
                return String(cString: name) == "remozio-experiment/1"
                    && sec_protocol_metadata_get_negotiated_tls_protocol_version(tls.securityProtocolMetadata) == .TLSv13
                    && !sec_protocol_metadata_get_early_data_accepted(tls.securityProtocolMetadata)
            }
            connections[id] = channel
            Task {
                do {
                    try await channel.start(timeoutMilliseconds: 10_000)
                    try await echoFrame(channel)
                } catch { }
                await channel.close()
                queue.async { self.connections.removeValue(forKey: id) }
            }
            queue.asyncAfter(deadline: .now() + 10) { Task { await channel.close() } }

        }
        listener.start(queue: queue)
    }

    func echoFrame(_ channel: NetworkByteChannel) async throws {
        var frame = Data()
        while frame.count < 4 {
            guard let chunk = try await channel.receive() else { throw ProbeError.invalidInput }
            frame.append(chunk)
        }
        let length = frame.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard length <= 65_536 else { throw ProbeError.invalidInput }
        while frame.count < length + 4 {
            guard let chunk = try await channel.receive() else { throw ProbeError.invalidInput }
            frame.append(chunk)
        }
        guard frame.count == length + 4 else { throw ProbeError.invalidInput }
        var offset = 0
        while offset < frame.count {
            let end = min(frame.count, offset + NetworkByteChannel.maximumChunkBytes)
            try await channel.send(Data(frame[offset..<end]))
            offset = end
        }
    }

}

#if !DEBUG
fatalError("The TLS experiment is available only in debug builds.")
#else
guard getuid() != 0, CommandLine.arguments.count == 2 else { fatalError("Run the synthetic TLS peer as an ordinary user.") }
var encodedSetup = Data()
while true {
    let byte = getchar()
    guard byte != EOF else { throw ProbeError.invalidInput }
    if byte == 10 { break }
    guard encodedSetup.count < 16_384 else { throw ProbeError.invalidInput }
    encodedSetup.append(UInt8(byte))
}
let setup = try JSONDecoder().decode(Setup.self, from: encodedSetup)
guard let peer = Data(base64Encoded: setup.peerPublicKey), !peer.isEmpty, peer.count <= 8_192 else { throw ProbeError.invalidInput }
let identityData = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
guard identityData.count <= 65_536 else { throw ProbeError.invalidInput }
var imported: CFArray?
let result = SecPKCS12Import(identityData as CFData, [kSecImportExportPassphrase: "synthetic-only", kSecImportToMemoryOnly: true] as CFDictionary, &imported)
guard result == errSecSuccess else { throw ProbeError.identityImport(result) }
guard let items = imported as? [[String: Any]], let value = items.first?[kSecImportItemIdentity as String] else { throw ProbeError.invalidInput }
let identity = value as! SecIdentity
@Sendable func pairingRandom(_ count: Int) throws -> Data {
    var result = Data(count: count)
    guard result.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }) == errSecSuccess else {
        throw ProbeError.invalidInput
    }
    return result
}
if setup.pairing == true {
    // This fixture signs a synthetic receipt. It has no Root journal, enrollment, hardware key or administrator consent.
    var certificate: SecCertificate?
    guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
          let key = SecCertificateCopyKey(certificate), let transport = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
        throw ProbeError.invalidInput
    }
    let authority = P256.Signing.PrivateKey()
    let invitation = try PairingInvitation(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
        label: "Synthetic pairing fixture", authorityPublicKey: authority.publicKey.x963Representation,
        transportPublicKey: transport, minimumEnvelopeVersion: 1)
    let invitationText = try invitation.exportText()
    let pairing = try PairingSetupListener(identity: identity, invitation: invitation, binding: .loopback,
        maximumConnections: setup.maximumConnections ?? 2, handshakeTimeoutMilliseconds: 4000,
        setupTimeoutMilliseconds: 10000, event: { event in
            switch event {
            case .ready(let port):
                guard let data = try? JSONSerialization.data(withJSONObject: ["port": Int(port), "invitation": invitationText]) else { exit(1) }
                FileHandle.standardOutput.write(data + Data([10]))
            case .failed: exit(1)
            case .stopped: break
            }
        }, handler: { channel in
            let proposal = try await channel.proposal()
            if setup.holdPairingStage == true {
                while !(await channel.isClosed) { try await Task.sleep(for: .milliseconds(10)) }
                return
            }
            let offer = try ChannelOffer(role: .mac, scope: proposal.phone.scope, nonce: pairingRandom(32), envelopeVersions: [1],
                requests: [], auditVersions: [])
            let wall = UInt64(Date().timeIntervalSince1970 * 1000)
            let transcript = try PairingTranscript(setupID: pairingRandom(16), challenge: pairingRandom(32), phone: proposal.phone, mac: offer,
                minimumEnvelopeVersion: 1, selectedEnvelopeVersion: 1, macAuthorityKey: invitation.authorityPublicKey,
                macTransportKey: invitation.transportPublicKey, transportKey: proposal.transportKey,
                decisionKey: proposal.decisionKey, biometricKey: proposal.biometricKey, enrollmentTag: pairingRandom(32),
                replacement: nil, expectedTrustRevision: pairingRandom(16), issuedAtUnixMillis: wall, expiresAtUnixMillis: wall + 10000)
            try await channel.stage(transcript)
            _ = try await channel.receiveProof()
            let receipt = try authority.signature(for: transcript.signingInput(purpose: .macCommit)).rawRepresentation
            try await channel.sendReceipt(receipt)
        })
    try pairing.start()
    DispatchQueue.global().async { _ = getchar(); Task { await pairing.closeAndWait(); exit(0) } }
    dispatchMain()
}
if setup.negotiate == true {
    let scope = try ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
        phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
    let enrolled = try DirectApprovalPeer(scope: scope, transportPublicKey: peer,
        requests: setup.commandMessages == true ? [try ChannelRequestCapability(kind: 0, wireVersion: 1, schemaVersion: 1, features: [])] : [],
        auditVersions: [], maximumPayloadBytes: 65_536)
    var enrolledPeers = [enrolled]
    if let second = setup.secondPeerPublicKey {
        guard let key = Data(base64Encoded: second) else { throw ProbeError.invalidInput }
        enrolledPeers.append(try DirectApprovalPeer(scope: ChannelScope(macID: Data(repeating: 1, count: 16),
            accountID: Data(repeating: 2, count: 16), phoneID: Data(repeating: 5, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: key, requests: [], auditVersions: [], maximumPayloadBytes: 65_536))
    }
    let direct = try DirectApprovalListener(identity: identity, peers: enrolledPeers, binding: .loopback,
        maximumConnections: setup.maximumConnections ?? 8,
        timeoutMilliseconds: 4_000, event: { event in
            switch event {
            case .ready(let port): emit(["port": Int(port)])
            case .failed: exit(1)
            case .stopped: break
            }
        }, handler: { _, channel in
            if setup.receiptRecovery == true {
                guard channel.purpose == .pairingReceipt,
                      let payload = try await channel.receive(maximumBytes: PairingReceiptFrame.maximumBytes),
                      case .query(let setupID) = try PairingReceiptFrame.decode(payload) else { throw ProbeError.invalidInput }
                // Synthetic wire bytes only. This fixture has no committed enrollment or Root signer.
                try await channel.send(PairingReceiptFrame.response(setupID: setupID, signature: Data(repeating: 8, count: 64)).encode())
                return
            }
            while let payload = try await channel.receive() { try await channel.send(payload) }
        })
    try direct.start()
    DispatchQueue.global().async {
        let command = getchar()
        if command == 115 {
            direct.close()
            exit(getchar() == EOF ? 0 : 1)
        }
        exit(command == EOF ? 0 : 1)
    }
    withExtendedLifetime(direct) { dispatchMain() }
}
let probe = try Probe(identity: identity, peerPublicKey: peer)
probe.start()
DispatchQueue.global().async {
    // The controller keeps this pipe open. EOF also handles controller crashes. No further commands are accepted.
    exit(getchar() == EOF ? 0 : 1)
}
dispatchMain()
#endif
