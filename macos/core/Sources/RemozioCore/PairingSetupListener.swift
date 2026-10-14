import CryptoKit
import Foundation
import Network
import Security
import RemozioProtocol

/// Bounded setup ingress for unpaired candidates. Construct in the transport role with its existing identity.
/// The handler relays claims to the signed app; only that app's authenticated Root channel can authorize enrollment.
public final class PairingSetupListener: @unchecked Sendable {
    private final class Slot: @unchecked Sendable {
        let channel: NetworkByteChannel
        var task: Task<Void, Never>?
        init(_ channel: NetworkByteChannel) { self.channel = channel }
    }
    private let listener: NWListener
    private let queue = DispatchQueue(label: "dev.remozio.pairing-listener")
    private let lock = NSLock()
    private let invitation: PairingInvitation
    private let maximumConnections: Int
    private let handshakeTimeoutMilliseconds: UInt64
    private let setupTimeoutMilliseconds: UInt64
    private let handler: @Sendable (PairingSetupNetworkSession) async throws -> Void
    private let event: @Sendable (DirectListenerEvent) -> Void
    private var slots: [UUID: Slot] = [:]
    private var retired: [UUID: Slot] = [:]
    private var started = false
    private var closed = false
    private var ready = false
    public init(identity: SecIdentity, invitation: PairingInvitation,
                binding: DirectApprovalListener.Binding = .localNetwork, maximumConnections: Int = 2,
                handshakeTimeoutMilliseconds: UInt64 = 15_000, setupTimeoutMilliseconds: UInt64 = 300_000,
                event: @escaping @Sendable (DirectListenerEvent) -> Void,
                handler: @escaping @Sendable (PairingSetupNetworkSession) async throws -> Void) throws {
        guard (1...64).contains(maximumConnections), (1...60_000).contains(handshakeTimeoutMilliseconds),
              (1...300_000).contains(setupTimeoutMilliseconds) else { throw DirectListenerError.invalidConfiguration }
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
              Self.candidatePoint(certificate: SecCertificateCopyData(certificate) as Data) == invitation.transportPublicKey,
              let local = sec_identity_create(identity) else { throw DirectListenerError.invalidIdentity }
        self.invitation = invitation; self.maximumConnections = maximumConnections
        self.handshakeTimeoutMilliseconds = handshakeTimeoutMilliseconds; self.setupTimeoutMilliseconds = setupTimeoutMilliseconds
        self.handler = handler; self.event = event
        let tls = NWProtocolTLS.Options(), options = tls.securityProtocolOptions
        sec_protocol_options_set_local_identity(options, local)
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_peer_authentication_required(options, true)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_set_tls_tickets_enabled(options, false)
        sec_protocol_options_add_tls_application_protocol(options, PairingSetupFrame.applicationProtocol)
        sec_protocol_options_set_verify_block(options, { metadata, _, complete in
            complete(Self.candidatePoint(metadata: metadata) != nil)
        }, queue)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        if binding == .loopback { parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any) }
        listener = try NWListener(using: parameters)
        if binding == .localNetwork {
            func id(_ data: Data) -> String {
                data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
            }
            var service = NWListener.Service(name: "R-" + id(invitation.macID) + "-" + id(invitation.accountID),
                type: "_remozio-pairing._tcp.")
            service.noAutoRename = true; listener.service = service
        }
        listener.stateUpdateHandler = { [weak self] in self?.changed($0) }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }; self.accept(connection)
        }
    }
    public func start() throws {
        try lock.withLock {
            guard !started, !closed else { throw DirectListenerError.alreadyStarted }
            started = true; listener.start(queue: queue)
        }
        queue.asyncAfter(deadline: .now() + .milliseconds(Int(handshakeTimeoutMilliseconds))) { [weak self] in
            guard let self else { return }
            if self.lock.withLock({ !self.closed && !self.ready }) { self.finish(.failed) }
        }
    }
    public func close() { finish(.stopped) }
    /// Stop admission and wait for the actual handler tasks. Cancellation alone does not prove quiescence.
    public func closeAndWait() async {
        close()
        let tasks = lock.withLock { retired.values.compactMap(\.task) }
        for task in tasks { await task.value }
    }
    deinit { close() }
    private func changed(_ state: NWListener.State) {
        switch state {
        case .ready:
            guard let port = listener.port else { finish(.failed); return }
            let announce = lock.withLock { () -> Bool in guard !closed, !ready else { return false }; ready = true; return true }
            if announce { event(.ready(port: port.rawValue)) }
        case .failed: finish(.failed)
        case .cancelled: finish(.stopped)
        default: break
        }
    }
    private func accept(_ connection: NWConnection) {
        let id = UUID()
        let slot = lock.withLock { () -> Slot? in
            guard started, !closed, slots.count < maximumConnections else { return nil }
            let value = Slot(NetworkByteChannel(connection: connection) { Self.candidatePoint(connection: $0) != nil })
            slots[id] = value; return value
        }
        guard let slot else { connection.cancel(); return }
        let channel = slot.channel, invitation = invitation, timeout = setupTimeoutMilliseconds
        let handshakeTimeout = handshakeTimeoutMilliseconds, handler = handler
        let keep = lock.withLock { () -> Bool in
            guard !closed, slots[id] === slot else { return false }
            slot.task = Task { [weak self] in
            do {
                try await channel.start(timeoutMilliseconds: handshakeTimeout)
                try Task.checkCancellation()
                guard let point = Self.candidatePoint(connection: connection) else { throw DirectListenerError.invalidIdentity }
                let session = try await PairingSetupNetworkSession.acceptStarted(channel: channel, invitation: invitation,
                    peerPoint: point, timeoutMilliseconds: timeout)
                do { try Task.checkCancellation(); try await handler(session) }
                catch { await session.close(); throw error }
                await session.close()
            } catch {}
            await channel.close(); self?.release(id)
            }
            return true
        }
        if !keep { channel.abort() }
    }
    private func release(_ id: UUID) { lock.withLock { slots[id] = nil; retired[id] = nil } }
    private func finish(_ result: DirectListenerEvent) {
        let owned = lock.withLock { () -> [Slot]? in
            guard !closed else { return nil }; closed = true
            let result = Array(slots.values); retired = slots; slots.removeAll(); return result
        }
        guard let owned else { return }
        listener.cancel()
        for slot in owned { slot.channel.abort(); slot.task?.cancel() }
        queue.async { [event] in event(result) }
    }
    // This verifies a TLS candidate's key, not enrollment, hardware custody or authorization.
    static func candidatePoint(certificate data: Data) -> Data? {
        guard !data.isEmpty, data.count <= 8192, let certificate = SecCertificateCreateWithData(nil, data as CFData),
              let key = SecCertificateCopyKey(certificate), let point = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let publicKey = try? P256.Signing.PublicKey(x963Representation: point),
              let pin = try? PinnedTLSPeer(subjectPublicKeyInfo: publicKey.derRepresentation),
              pin.accepts(certificate: data) else { return nil }
        return point
    }
    private static func candidatePoint(metadata: sec_protocol_metadata_t) -> Data? {
        var leaf: SecCertificate?
        let accessible = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
            if leaf == nil { leaf = sec_certificate_copy_ref(certificate).takeRetainedValue() }
        }
        guard accessible, let leaf else { return nil }
        return candidatePoint(certificate: SecCertificateCopyData(leaf) as Data)
    }
    private static func candidatePoint(connection: NWConnection) -> Data? {
        guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata,
              let name = sec_protocol_metadata_copy_negotiated_protocol(tls.securityProtocolMetadata) else { return nil }
        defer { free(UnsafeMutableRawPointer(mutating: name)) }
        guard String(cString: name) == PairingSetupFrame.applicationProtocol,
              sec_protocol_metadata_get_negotiated_tls_protocol_version(tls.securityProtocolMetadata) == .TLSv13,
              !sec_protocol_metadata_get_early_data_accepted(tls.securityProtocolMetadata) else { return nil }
        return candidatePoint(metadata: tls.securityProtocolMetadata)
    }
}
