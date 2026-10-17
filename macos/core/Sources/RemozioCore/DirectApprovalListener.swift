import CryptoKit
import Foundation
import Network
import Security
import RemozioProtocol

public enum DirectListenerError: Error { case invalidConfiguration, invalidIdentity, alreadyStarted }
public enum DirectListenerEvent: Sendable { case ready(port: UInt16), failed, stopped }

/// A trusted enrollment snapshot supplied by the protected host, never by a connecting phone.
public struct DirectApprovalPeer: Sendable {
    public let scope: ChannelScope
    public let transportPublicKey: Data
    public let requests: [ChannelRequestCapability]
    public let auditVersions: Set<UInt64>
    public let minimumEnvelopeVersion: UInt64
    public let maximumPayloadBytes: Int

    public init(scope: ChannelScope, transportPublicKey: Data, requests: [ChannelRequestCapability],
                auditVersions: Set<UInt64>, minimumEnvelopeVersion: UInt64 = 1, maximumPayloadBytes: Int) throws {
        _ = try PinnedTLSPeer(subjectPublicKeyInfo: transportPublicKey)
        guard (1...16_777_216).contains(maximumPayloadBytes), minimumEnvelopeVersion > 0 else {
            throw DirectListenerError.invalidConfiguration
        }
        _ = try ChannelOffer(role: .mac, scope: scope, nonce: Data(repeating: 1, count: 32),
            envelopeVersions: [1], requests: requests, auditVersions: auditVersions)
        self.scope = scope; self.transportPublicKey = transportPublicKey; self.requests = requests
        self.auditVersions = auditVersions; self.minimumEnvelopeVersion = minimumEnvelopeVersion
        self.maximumPayloadBytes = maximumPayloadBytes
    }

    /// The authority limit still bounds signed frames. Only the snapshot channel reserves outer framing and query space.
    func channelMaximumPayloadBytes(for purpose: EnrolledChannelPurpose) -> Int {
        guard case .pendingSnapshot = purpose else { return maximumPayloadBytes }
        let signedFrames = min(maximumPayloadBytes, PendingRequestSnapshotFrame.maximumFrameBytes) +
            (PendingRequestSnapshotFrame.maximumBytes - PendingRequestSnapshotFrame.maximumFrameBytes)
        let retainedQuery = PendingRequestSnapshotFrame.maximumRetainedRequests * 17 + 256
        return max(signedFrames, retainedQuery)
    }
}

struct DirectPeerSnapshot: Sendable {
    let macID: Data
    private let peers: [Data: DirectApprovalPeer]
    init(_ values: [DirectApprovalPeer]) throws {
        guard let first = values.first, values.count <= 1024 else { throw DirectListenerError.invalidConfiguration }
        var peers: [Data: DirectApprovalPeer] = [:]
        var phones = Set<Data>()
        for peer in values {
            guard peer.scope.macID == first.scope.macID, peer.scope.accountID == first.scope.accountID,
                  phones.insert(peer.scope.phoneID).inserted else { throw DirectListenerError.invalidConfiguration }
            let point = try P256.Signing.PublicKey(derRepresentation: peer.transportPublicKey).x963Representation
            guard peers.updateValue(peer, forKey: point) == nil else { throw DirectListenerError.invalidConfiguration }
        }
        macID = first.scope.macID; self.peers = peers
    }
    var serviceName: String { "Remozio-" + macID.map { String(format: "%02x", $0) }.joined() }

    func peer(certificate data: Data, at date: Date = Date()) -> DirectApprovalPeer? {
        guard !data.isEmpty, data.count <= 8192,
              let certificate = SecCertificateCreateWithData(nil, data as CFData),
              let key = SecCertificateCopyKey(certificate),
              let point = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let peer = peers[point],
              let pin = try? PinnedTLSPeer(subjectPublicKeyInfo: peer.transportPublicKey),
              pin.accepts(certificate: data, at: date) else { return nil }
        return peer
    }
    func peer(metadata: sec_protocol_metadata_t) -> DirectApprovalPeer? {
        var leaf: SecCertificate?
        let accessible = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
            if leaf == nil { leaf = sec_certificate_copy_ref(certificate).takeRetainedValue() }
        }
        guard accessible, let leaf else { return nil }
        return peer(certificate: SecCertificateCopyData(leaf) as Data)
    }
    func purpose(connection: NWConnection) -> EnrolledChannelPurpose? {
        guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata,
              let name = sec_protocol_metadata_copy_negotiated_protocol(tls.securityProtocolMetadata) else { return nil }
        defer { free(UnsafeMutableRawPointer(mutating: name)) }
        guard sec_protocol_metadata_get_negotiated_tls_protocol_version(tls.securityProtocolMetadata) == .TLSv13,
              !sec_protocol_metadata_get_early_data_accepted(tls.securityProtocolMetadata) else { return nil }
        return EnrolledChannelPurpose(applicationProtocol: String(cString: name))
    }
    func peer(connection: NWConnection) -> DirectApprovalPeer? {
        guard purpose(connection: connection) != nil,
              let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else { return nil }
        return peer(metadata: tls.securityProtocolMetadata)
    }
}

/// Owns a bounded native listener and all its channels. Close it before changing the trusted enrollment snapshot.
/// The handler must recheck current enrollment and request authority; TLS grants neither approval nor execution.
public final class DirectApprovalListener: @unchecked Sendable {
    public enum Binding: Sendable { case localNetwork, loopback }
    private final class Slot: @unchecked Sendable {
        let channel: NetworkByteChannel
        var task: Task<Void, Never>?
        init(_ channel: NetworkByteChannel) { self.channel = channel }
    }
    private let listener: NWListener
    private let queue = DispatchQueue(label: "dev.remozio.direct-listener")
    private let lock = NSLock()
    private let peers: DirectPeerSnapshot
    private let maximumConnections: Int
    private let timeoutMilliseconds: UInt64
    private let handler: @Sendable (DirectApprovalPeer, NegotiatedNetworkChannel) async throws -> Void
    private let event: @Sendable (DirectListenerEvent) -> Void
    private var slots: [UUID: Slot] = [:]
    private var started = false
    private var closed = false
    private var ready = false

    /// Loopback mode never advertises. Local-network mode publishes the Android discovery hint on an ephemeral port.
    public init(identity: SecIdentity, peers: [DirectApprovalPeer], binding: Binding = .localNetwork,
                maximumConnections: Int = 8, timeoutMilliseconds: UInt64 = 15_000,
                event: @escaping @Sendable (DirectListenerEvent) -> Void,
                handler: @escaping @Sendable (DirectApprovalPeer, NegotiatedNetworkChannel) async throws -> Void) throws {
        guard (1...64).contains(maximumConnections), (1...60_000).contains(timeoutMilliseconds) else {
            throw DirectListenerError.invalidConfiguration
        }
        let snapshot = try DirectPeerSnapshot(peers)
        self.peers = snapshot; self.maximumConnections = maximumConnections
        self.timeoutMilliseconds = timeoutMilliseconds; self.handler = handler; self.event = event
        let tls = NWProtocolTLS.Options(), options = tls.securityProtocolOptions
        guard let local = sec_identity_create(identity) else { throw DirectListenerError.invalidIdentity }
        sec_protocol_options_set_local_identity(options, local)
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_peer_authentication_required(options, true)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_set_tls_tickets_enabled(options, false)
        for purpose: EnrolledChannelPurpose in [.approvals, .pairingReceipt, .pendingSnapshot] {
            sec_protocol_options_add_tls_application_protocol(options, purpose.applicationProtocol)
        }
        sec_protocol_options_set_verify_block(options, { metadata, _, complete in
            complete(snapshot.peer(metadata: metadata) != nil)
        }, queue)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        if binding == .loopback { parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any) }
        listener = try NWListener(using: parameters)
        if binding == .localNetwork {
            var service = NWListener.Service(name: snapshot.serviceName, type: "_remozio._tcp.")
            service.noAutoRename = true
            listener.service = service
        }
        listener.stateUpdateHandler = { [weak self] state in self?.changed(state) }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            self.accept(connection)
        }
    }

    public func start() throws {
        try lock.withLock {
            guard !started, !closed else { throw DirectListenerError.alreadyStarted }
            started = true
            listener.start(queue: queue)
        }
        queue.asyncAfter(deadline: .now() + .milliseconds(Int(timeoutMilliseconds))) { [weak self] in
            guard let self else { return }
            let expired = self.lock.withLock { !self.closed && !self.ready }
            if expired { self.finish(.failed) }
        }
    }
    public func close() { finish(.stopped) }
    deinit { close() }

    private func changed(_ state: NWListener.State) {
        switch state {
        case .ready:
            guard let port = listener.port else { finish(.failed); return }
            let announce = lock.withLock { () -> Bool in
                guard !closed, !ready else { return false }
                ready = true; return true
            }
            if announce { event(.ready(port: port.rawValue)) }
        case .failed: finish(.failed)
        case .cancelled: finish(.stopped)
        default: break
        }
    }
    private func accept(_ connection: NWConnection) {
        let snapshot = peers
        let id = UUID()
        let owned = lock.withLock { () -> Slot? in
            guard started, !closed, slots.count < maximumConnections else { return nil }
            let slot = Slot(NetworkByteChannel(connection: connection) { snapshot.peer(connection: $0) != nil })
            slots[id] = slot; return slot
        }
        guard let slot = owned else { connection.cancel(); return }
        let channel = slot.channel
        let timeout = timeoutMilliseconds, handler = handler
        let task = Task { [weak self] in
            do {
                try await channel.start(timeoutMilliseconds: timeout)
                try Task.checkCancellation()
                guard let peer = snapshot.peer(connection: connection), let purpose = snapshot.purpose(connection: connection) else {
                    throw DirectListenerError.invalidIdentity
                }
                let framed = try await NegotiatedNetworkChannel.acceptStarted(channel: channel, scope: peer.scope,
                    requests: peer.requests, auditVersions: peer.auditVersions,
                    maximumPayloadBytes: peer.channelMaximumPayloadBytes(for: purpose),
                    trustedMinimum: peer.minimumEnvelopeVersion, timeoutMilliseconds: timeout, purpose: purpose)
                do { try Task.checkCancellation(); try await handler(peer, framed) }
                catch { await framed.closeAndWait(); throw error }
                await framed.closeAndWait()
            } catch { }
            await channel.close()
            self?.release(id)
        }
        let keep = lock.withLock { () -> Bool in
            guard !closed, slots[id] === slot else { return false }
            slot.task = task; return true
        }
        if !keep { task.cancel(); channel.abort() }
    }
    private func release(_ id: UUID) { _ = lock.withLock { slots.removeValue(forKey: id) } }
    private func finish(_ result: DirectListenerEvent) {
        let owned: [Slot]? = lock.withLock {
            guard !closed else { return nil }
            closed = true
            let owned = Array(slots.values); slots.removeAll(); return owned
        }
        guard let owned else { return }
        listener.cancel()
        for slot in owned { slot.channel.abort(); slot.task?.cancel() }
        queue.async { [event] in event(result) }
    }
}
