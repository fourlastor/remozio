import CryptoKit
import Foundation
import Network
import Security
import RemozioProtocol

/// Only public window metadata crosses to Transport. The callbacks target the same Authority owner.
struct PairingSetupV2Ingress: Sendable {
    let windowID: Data
    let lifetimeMilliseconds: UInt64
    private let localReserve: (@Sendable (PairingSetupV2Proof) throws -> Void)?
    private let localDisconnect: (@Sendable (UUID) -> Void)?
    private let authority: AuthorityPairingProofClient?
    private let clock: AuthorityClock?

    init(windowID: Data, lifetimeMilliseconds: UInt64, reserve: @escaping @Sendable (PairingSetupV2Proof) throws -> Void,
         disconnect: @escaping @Sendable (UUID) -> Void) {
        self.windowID = windowID; self.lifetimeMilliseconds = lifetimeMilliseconds
        localReserve = reserve; localDisconnect = disconnect; authority = nil; clock = nil
    }

    init(windowID: Data, lifetimeMilliseconds: UInt64, authority: AuthorityPairingProofClient) throws {
        self.windowID = windowID; self.lifetimeMilliseconds = lifetimeMilliseconds
        localReserve = nil; localDisconnect = nil; self.authority = authority; clock = try AuthorityClock()
    }

    func acceptTime() throws -> UInt64? { try clock?.now().milliseconds }

    func register(connection: UUID, acceptedAt: UInt64?, peerPoint: Data, exporter: Data,
                  deadline: ContinuousClock.Instant) async throws -> PairingSetupV2Connection {
        if let authority, let acceptedAt {
            let candidate = try await authority.register(connectionID: connection, acceptedAt: acceptedAt,
                peerPoint: peerPoint, exporter: exporter, deadline: deadline)
            return .init(connection: candidate.id, challenge: candidate.challenge, publicationDeadline: deadline,
                verify: { proposal, _, tag in
                    try await authority.verify(candidate: candidate.id, proposal: proposal.encode(), tag: tag, deadline: deadline)
                }, confirm: { try await authority.confirm(candidate: candidate.id, deadline: deadline) },
                invalidateLink: authority.close, retire: { await authority.retire(candidate: candidate.id, confirmed: $0) })
        }
        guard let localReserve, let localDisconnect, exporter.count == 32 else { throw PairingSetupChannelError.rejected }
        let challenge = try AuthorityPairingSetupAccess.secureRandom(32)
        return .init(connection: connection, challenge: challenge, publicationDeadline: nil,
            verify: { proposal, peerPoint, tag in
                try localReserve(.init(windowID: windowID, connection: connection, peerPoint: peerPoint, challenge: challenge,
                    exporter: exporter, proposal: proposal, tag: tag))
            }, confirm: {}, invalidateLink: { localDisconnect(connection) }, retire: { _ in localDisconnect(connection) })
    }
}

/// Bounded setup ingress for unpaired candidates. Construct in the transport role with its existing identity.
/// The handler relays claims to the signed app; only that app's authenticated Root channel can authorize enrollment.
public final class PairingSetupListener: @unchecked Sendable {
    private final class Slot: @unchecked Sendable {
        let channel: NetworkByteChannel
        var task: Task<Void, Never>?
        var proofTimer: Task<Void, Never>?
        init(_ channel: NetworkByteChannel) { self.channel = channel }
    }
    private let listener: NWListener
    private let queue = DispatchQueue(label: "dev.remozio.pairing-listener")
    private let lock = NSLock()
    private let invitation: PairingInvitation
    private let v2: PairingSetupV2Ingress?
    private let applicationProtocol: String
    private var v2Admissions = PairingSetupV2Admissions()
    private var sources: [String: (until: ContinuousClock.Instant, count: Int)] = [:]
    private var expiry: Task<Void, Never>?
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
    public convenience init(identity: SecIdentity, invitation: PairingInvitation,
                binding: DirectApprovalListener.Binding = .localNetwork, maximumConnections: Int = 2,
                handshakeTimeoutMilliseconds: UInt64 = 15_000, setupTimeoutMilliseconds: UInt64 = 300_000,
                event: @escaping @Sendable (DirectListenerEvent) -> Void,
                handler: @escaping @Sendable (PairingSetupNetworkSession) async throws -> Void) throws {
        try self.init(identity: identity, invitation: invitation, binding: binding, maximumConnections: maximumConnections,
                      handshakeTimeoutMilliseconds: handshakeTimeoutMilliseconds, setupTimeoutMilliseconds: setupTimeoutMilliseconds,
                      v2: nil, event: event, handler: handler)
    }

    init(identity: SecIdentity, invitation: PairingInvitation, binding: DirectApprovalListener.Binding,
         maximumConnections: Int, handshakeTimeoutMilliseconds: UInt64, setupTimeoutMilliseconds: UInt64,
         v2: PairingSetupV2Ingress?, event: @escaping @Sendable (DirectListenerEvent) -> Void,
         handler: @escaping @Sendable (PairingSetupNetworkSession) async throws -> Void) throws {
        guard (1...64).contains(maximumConnections), (1...60_000).contains(handshakeTimeoutMilliseconds),
              (1...300_000).contains(setupTimeoutMilliseconds) else { throw DirectListenerError.invalidConfiguration }
        if let v2 {
            guard binding == .loopback, v2.windowID.count == 16, (1...300_000).contains(v2.lifetimeMilliseconds) else {
                throw DirectListenerError.invalidConfiguration
            }
        }
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
              Self.candidatePoint(certificate: SecCertificateCopyData(certificate) as Data) == invitation.transportPublicKey,
              let local = sec_identity_create(identity) else { throw DirectListenerError.invalidIdentity }
        self.invitation = invitation; self.maximumConnections = maximumConnections
        self.handshakeTimeoutMilliseconds = handshakeTimeoutMilliseconds; self.setupTimeoutMilliseconds = setupTimeoutMilliseconds
        self.handler = handler; self.event = event; self.v2 = v2
        let applicationProtocol = v2 == nil ? PairingSetupFrame.applicationProtocol : PairingSetupPreludeV2.applicationProtocol
        self.applicationProtocol = applicationProtocol
        let tls = NWProtocolTLS.Options(), options = tls.securityProtocolOptions
        sec_protocol_options_set_local_identity(options, local)
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_peer_authentication_required(options, true)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_set_tls_tickets_enabled(options, false)
        sec_protocol_options_add_tls_application_protocol(options, applicationProtocol)
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
            if let v2 {
                let deadline = ContinuousClock.now.advanced(by: .milliseconds(Int64(v2.lifetimeMilliseconds)))
                expiry = Task { [weak self] in
                    do { try await ContinuousClock().sleep(until: deadline) } catch { return }
                    self?.close()
                }
            }
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
        let accepted = ContinuousClock.now
        let deadline = accepted.advanced(by: PairingSetupV2Admissions.proofTimeout)
        let acceptedAt: UInt64?
        do { acceptedAt = try v2?.acceptTime() }
        catch { connection.cancel(); return }
        let applicationProtocol = applicationProtocol
        var evicted: Slot?
        let slot = lock.withLock { () -> Slot? in
            guard started, !closed else { return nil }
            if self.v2 == nil {
                guard slots.count < maximumConnections else { return nil }
            } else {
                guard admitSource(connection.endpoint, at: accepted) else { return nil }
                switch v2Admissions.admit(id, deadline: deadline, draining: retired.count) {
                case .rejected: return nil
                case .admitted(let victim):
                    if let victim { evicted = retireProof(victim) }
                }
            }
            let value = Slot(NetworkByteChannel(connection: connection) {
                Self.metadata(connection: $0, applicationProtocol: applicationProtocol)
                    .flatMap { Self.candidatePoint(metadata: $0) } != nil
            })
            slots[id] = value
            return value
        }
        if let evicted { cancel(evicted) }
        guard let slot else { connection.cancel(); return }
        let channel = slot.channel, invitation = invitation, timeout = setupTimeoutMilliseconds
        let windowV2 = self.v2
        let handshakeTimeout = windowV2 == nil ? handshakeTimeoutMilliseconds : 3_000
        let handler = handler
        let keep = lock.withLock { () -> Bool in
            guard !closed, slots[id] === slot else { return false }
            if windowV2 != nil {
                slot.proofTimer = Task { [weak self] in
                    do { try await ContinuousClock().sleep(until: deadline) } catch { return }
                    self?.expireProof(id)
                }
            }
            slot.task = Task { [weak self] in
                var registeredProof: PairingSetupV2Connection?
                var confirmed = false
                do {
                    try await channel.start(timeoutMilliseconds: handshakeTimeout)
                    try Task.checkCancellation()
                    guard let metadata = Self.metadata(connection: connection, applicationProtocol: applicationProtocol),
                          let point = Self.candidatePoint(metadata: metadata) else { throw DirectListenerError.invalidIdentity }
                    let proof: PairingSetupV2Connection?
                    if let windowV2 {
                        guard ContinuousClock.now < deadline else { throw PairingSetupChannelError.rejected }
                        let candidate = try await windowV2.register(connection: id, acceptedAt: acceptedAt, peerPoint: point,
                            exporter: Self.exporter(metadata), deadline: deadline)
                        registeredProof = candidate
                        proof = .init(connection: candidate.connection, challenge: candidate.challenge,
                            publicationDeadline: candidate.publicationDeadline, verify: { [weak self] proposal, peer, tag in
                                guard let self else { throw PairingSetupChannelError.closed }
                                try self.beginVerification(id)
                                try await candidate.verify(proposal, peer, tag)
                            }, confirm: { [weak self] in
                                guard let self else { throw PairingSetupChannelError.closed }
                                try self.requireVerification(id)
                                try await candidate.confirm()
                                try self.completeVerification(id)
                            }, invalidateLink: { [weak self] in
                                candidate.invalidateLink()
                                self?.close()
                            }, retire: candidate.retire)
                    } else { proof = nil }
                    let session = try await PairingSetupNetworkSession.acceptStarted(channel: channel, invitation: invitation,
                        peerPoint: point, timeoutMilliseconds: timeout, v2: proof)
                    confirmed = proof != nil
                    do { try Task.checkCancellation() }
                    catch { session.rejectConfirmedProof(); await session.closeAndWait(); throw error }
                    do { try await handler(session) }
                    catch { await session.closeAndWait(); throw error }
                    await session.closeAndWait()
                } catch {}
                await channel.close()
                await registeredProof?.retire(confirmed)
                self?.release(id)
            }
            return true
        }
        if !keep { channel.abort() }
    }

    private func admitSource(_ endpoint: NWEndpoint, at now: ContinuousClock.Instant) -> Bool {
        guard case .hostPort(let host, _) = endpoint else { return false }
        sources = sources.filter { $0.value.until > now }
        let key = String(describing: host)
        if let record = sources[key] {
            guard record.count < 8 else { return false }
            sources[key] = (record.until, record.count + 1)
        } else {
            guard sources.count < 64 else { return false }
            sources[key] = (now.advanced(by: .seconds(1)), 1)
        }
        return true
    }

    private func beginVerification(_ id: UUID) throws {
        try lock.withLock {
            guard !closed, slots[id] != nil, v2Admissions.beginVerification(id, at: ContinuousClock.now) else {
                throw PairingSetupChannelError.rejected
            }
        }
    }

    private func requireVerification(_ id: UUID) throws {
        try lock.withLock {
            guard !closed, slots[id] != nil, v2Admissions.isVerifying(id, at: ContinuousClock.now) else {
                throw PairingSetupChannelError.rejected
            }
        }
    }

    private func completeVerification(_ id: UUID) throws {
        try lock.withLock {
            guard !closed, let slot = slots[id], v2Admissions.completeVerification(id, at: ContinuousClock.now) else {
                throw PairingSetupChannelError.rejected
            }
            slot.proofTimer?.cancel(); slot.proofTimer = nil
        }
    }

    private func expireProof(_ id: UUID) {
        let expired: Slot? = lock.withLock {
            guard v2Admissions.expire(id, at: ContinuousClock.now) else { return nil }
            return retireProof(id)
        }
        if let expired { cancel(expired) }
    }

    /// Called under the listener lock. Keep ownership until the handler and its disconnect callback return.
    @discardableResult
    private func retireProof(_ id: UUID) -> Slot? {
        guard let slot = slots.removeValue(forKey: id) else { return nil }
        slot.proofTimer?.cancel(); slot.proofTimer = nil
        retired[id] = slot
        return slot
    }

    private func cancel(_ slot: Slot) { slot.channel.abort(); slot.task?.cancel() }

    private func release(_ id: UUID) {
        lock.withLock {
            (slots[id] ?? retired[id])?.proofTimer?.cancel()
            slots[id] = nil; retired[id] = nil
            v2Admissions.remove(id)
        }
    }

    private func finish(_ result: DirectListenerEvent) {
        let owned = lock.withLock { () -> [Slot]? in
            guard !closed else { return nil }
            closed = true
            expiry?.cancel(); expiry = nil
            for (id, slot) in slots { retired[id] = slot }
            slots.removeAll(); v2Admissions.removeAll(); sources.removeAll()
            return Array(retired.values)
        }
        guard let owned else { return }
        listener.cancel()
        for slot in owned { cancel(slot) }
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
    static func candidatePoint(metadata: sec_protocol_metadata_t) -> Data? {
        var leaf: SecCertificate?
        let accessible = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
            if leaf == nil { leaf = sec_certificate_copy_ref(certificate).takeRetainedValue() }
        }
        guard accessible, let leaf else { return nil }
        return candidatePoint(certificate: SecCertificateCopyData(leaf) as Data)
    }
    private static func metadata(connection: NWConnection, applicationProtocol: String) -> sec_protocol_metadata_t? {
        guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else { return nil }
        let metadata = tls.securityProtocolMetadata
        guard let name = sec_protocol_metadata_copy_negotiated_protocol(metadata) else { return nil }
        defer { free(UnsafeMutableRawPointer(mutating: name)) }
        guard String(cString: name) == applicationProtocol,
              sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata) == .TLSv13,
              !sec_protocol_metadata_get_early_data_accepted(metadata) else { return nil }
        return metadata
    }

    private static func exporter(_ metadata: sec_protocol_metadata_t) throws -> Data {
        let label = PairingInvitationV2.exporterLabel
        guard let secret = sec_protocol_metadata_create_secret(metadata, label.utf8.count, label, 32) else {
            throw DirectListenerError.invalidIdentity
        }
        let bytes = DispatchData._unconditionallyBridgeFromObjectiveC(secret)
        guard bytes.count == 32 else { throw DirectListenerError.invalidIdentity }
        return Data(bytes)
    }
}
