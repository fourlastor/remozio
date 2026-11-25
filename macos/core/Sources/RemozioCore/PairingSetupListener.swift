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

    init(windowID: Data, lifetimeMilliseconds: UInt64, reserve: @escaping @Sendable (PairingSetupV2Proof) throws -> Void,
         disconnect: @escaping @Sendable (UUID) -> Void) {
        self.windowID = windowID; self.lifetimeMilliseconds = lifetimeMilliseconds
        localReserve = reserve; localDisconnect = disconnect; authority = nil
    }

    init(windowID: Data, lifetimeMilliseconds: UInt64, authority: AuthorityPairingProofClient) {
        self.windowID = windowID; self.lifetimeMilliseconds = lifetimeMilliseconds
        localReserve = nil; localDisconnect = nil; self.authority = authority
    }

    func register(connection: UUID, acceptedAt: UInt64, peerPoint: Data, exporter: Data,
                  deadline: ContinuousClock.Instant) async throws -> PairingSetupV2Connection {
        if let authority {
            let candidate = try await authority.register(connectionID: connection, acceptedAt: acceptedAt,
                peerPoint: peerPoint, exporter: exporter, deadline: deadline)
            return .init(connection: candidate.id, challenge: candidate.challenge, publicationDeadline: deadline,
                verify: { proposal, _, tag in
                    try await authority.verify(candidate: candidate.id, proposal: proposal.encode(), tag: tag, deadline: deadline)
                }, confirm: { try await authority.confirm(candidate: candidate.id, deadline: deadline) },
                invalidateLink: authority.close, retire: { await authority.retire(candidate: candidate.id, requiresAcknowledgement: $0) })
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
        let source: PairingSetupV2Source?
        var task: Task<Void, Never>?
        var proofTimer: Task<Void, Never>?
        init(_ channel: NetworkByteChannel, source: PairingSetupV2Source?) {
            self.channel = channel
            self.source = source
        }
    }
    private let listener: NWListener
    var requiredLocalEndpoint: NWEndpoint? { listener.parameters.requiredLocalEndpoint }
    private let queue = DispatchQueue(label: "dev.remozio.pairing-listener")
    private let lock = NSLock()
    private let invitation: PairingInvitation
    private let lanRoute: PairingLANRoute?
    private let lanBinding: PairingLANBinding?
    private let lanServiceName: String?
    private let advertisement: PairingLANAdvertisement?
    private let v2: PairingSetupV2Ingress?
    private let applicationProtocol: String
    struct IngressFixture: Sendable {
        let peerSubnet: PairingLANSubnet
        let now: @Sendable () throws -> AuthorityMoment
        let channelAllocated: @Sendable () -> Void
    }

    private let intakeNow: (@Sendable () throws -> AuthorityMoment)?
    private let peerSubnet: PairingLANSubnet?
    private let channelAllocated: (@Sendable () -> Void)?
    private let registrationLane: PairingSetupV2RegistrationLane
    private let sourceKey: @Sendable (NWEndpoint) -> PairingSetupV2Source?
    private var v2Admissions = PairingSetupV2Admissions()
    private var expiry: Task<Void, Never>?
    private let proofTime: @Sendable () -> ContinuousClock.Instant
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
         v2: PairingSetupV2Ingress?, lanRoute: PairingLANRoute? = nil, lanBinding: PairingLANBinding? = nil,
         proofTime: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now },
         registrationLane: PairingSetupV2RegistrationLane = PairingSetupV2RegistrationLane(),
         sourceKey: @escaping @Sendable (NWEndpoint) -> PairingSetupV2Source? = { PairingSetupV2Source($0) },
         ingressFixture: IngressFixture? = nil,
         event: @escaping @Sendable (DirectListenerEvent) -> Void,
         handler: @escaping @Sendable (PairingSetupNetworkSession) async throws -> Void) throws {
        guard (1...64).contains(maximumConnections), (1...60_000).contains(handshakeTimeoutMilliseconds),
              (1...300_000).contains(setupTimeoutMilliseconds) else { throw DirectListenerError.invalidConfiguration }
        guard (lanRoute == nil) == (lanBinding == nil),
              ingressFixture == nil || (lanRoute == nil && v2 != nil && binding == .loopback) else {
            throw DirectListenerError.invalidConfiguration
        }
        if let lanRoute {
            guard lanRoute.isCurrent, let subnet = lanRoute.liveSubnet else { throw TransportPairingControlError.unavailableInterface }
            peerSubnet = subnet
        } else {
            peerSubnet = ingressFixture?.peerSubnet
        }
        if let v2 {
            guard binding == (lanRoute == nil ? .loopback : .localNetwork), v2.windowID.count == 16,
                  (1...300_000).contains(v2.lifetimeMilliseconds),
                  lanBinding == nil || (lanBinding?.windowID == v2.windowID && lanBinding?.scope == lanRoute?.scope) else {
                throw DirectListenerError.invalidConfiguration
            }
        } else if lanRoute != nil { throw DirectListenerError.invalidConfiguration }
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
              Self.candidatePoint(certificate: SecCertificateCopyData(certificate) as Data) == invitation.transportPublicKey,
              let local = sec_identity_create(identity) else { throw DirectListenerError.invalidIdentity }
        self.invitation = invitation; self.maximumConnections = maximumConnections
        self.handshakeTimeoutMilliseconds = handshakeTimeoutMilliseconds; self.setupTimeoutMilliseconds = setupTimeoutMilliseconds
        self.handler = handler; self.event = event; self.v2 = v2; self.proofTime = proofTime; self.lanRoute = lanRoute
        self.lanBinding = lanBinding
        lanServiceName = try lanBinding.map { try Self.serviceName(invitation, windowID: $0.windowID) }
        advertisement = lanRoute == nil ? nil : PairingLANAdvertisement(queue: queue)
        self.registrationLane = registrationLane
        self.sourceKey = sourceKey
        if let ingressFixture {
            intakeNow = ingressFixture.now
        } else if v2 != nil {
            let clock = try AuthorityClock()
            intakeNow = clock.now
        } else {
            intakeNow = nil
        }
        channelAllocated = ingressFixture?.channelAllocated
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
        if let lanRoute {
            parameters.requiredInterface = lanRoute.interface
            parameters.requiredLocalEndpoint = .hostPort(host: lanRoute.address.host, port: .any)
        } else if binding == .loopback { parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any) }
        listener = try NWListener(using: parameters)
        if binding == .localNetwork && lanRoute == nil {
            var service = try NWListener.Service(name: Self.serviceName(invitation), type: "_remozio-pairing._tcp.")
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
            if let v2 {
                // Authority and Transport obtain milliseconds from the same host sleep-inclusive clock.
                let beforeSample = ContinuousClock.now
                let lifetime: UInt64
                if lanBinding != nil {
                    guard let remaining = lanRemainingLifetime() else { throw PairingSetupChannelError.closed }
                    lifetime = remaining
                } else { lifetime = v2.lifetimeMilliseconds }
                let deadline = beforeSample.advanced(by: .milliseconds(Int64(lifetime)))
                expiry = Task { [weak self] in
                    do { try await ContinuousClock().sleep(until: deadline) } catch { return }
                    self?.close()
                }
            }
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
        if let advertisement {
            await withCheckedContinuation { continuation in
                queue.async { advertisement.close(); continuation.resume() }
            }
        }
    }

    static func serviceName(_ invitation: PairingInvitation, windowID: Data? = nil) throws -> String {
        if let windowID { return try PairingInvitationV2.bonjourInstanceName(windowID: windowID) }
        func id(_ data: Data) -> String {
            data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        return "R-" + id(invitation.macID) + "-" + id(invitation.accountID)
    }

    private func lanRemainingLifetime() -> UInt64? {
        guard let lanBinding, let v2, let now = try? intakeNow?() else { return nil }
        return lanBinding.remainingMilliseconds(at: now.milliseconds, windowLifetime: v2.lifetimeMilliseconds)
    }

    private func publishReady(_ port: UInt16) {
        let announce = lock.withLock { () -> Bool in guard !closed && !ready else { return false }; ready = true; return true }
        if announce { event(.ready(port: port)) }
    }

    deinit { close() }
    private func changed(_ state: NWListener.State) {
        switch state {
        case .ready:
            guard let port = listener.port else { finish(.failed); return }
            if let lanRoute, let advertisement {
                guard lock.withLock({ !closed }) else { return }
                guard let lanServiceName else { finish(.failed); return }
                advertisement.start(name: lanServiceName, index: lanRoute.index, port: port.rawValue, address: lanRoute.address,
                                    isCurrent: { [weak self] in
                    guard let self, self.lanRemainingLifetime() != nil, lanRoute.isCurrent, let current = lanRoute.liveSubnet else { return false }
                    return current == self.peerSubnet
                }) { [weak self] event in
                    switch event {
                    case .ready(let port): self?.publishReady(port)
                    case .failed, .stopped: self?.finish(event)
                    }
                }
            } else { publishReady(port.rawValue) }
        case .failed: finish(.failed)
        case .cancelled: finish(.stopped)
        default: break
        }
    }
    private func accept(_ connection: NWConnection) {
        let id = UUID()
        let accepted = ContinuousClock.now
        let deadline = accepted.advanced(by: PairingSetupV2Admissions.proofTimeout)
        let acceptedAt: AuthorityMoment?
        do { acceptedAt = try intakeNow?() }
        catch { connection.cancel(); return }
        let source = v2 == nil ? nil : sourceKey(connection.endpoint)
        let peerIsOnLink = peerSubnet.map { subnet in source.map(subnet.contains) ?? false } ?? true
        let applicationProtocol = applicationProtocol
        let registrations = registrationLane
        var evicted: Slot?
        let slot = lock.withLock { () -> Slot? in
            guard started, !closed else { return nil }
            if let lanBinding {
                guard ready, let acceptedAt, acceptedAt.milliseconds < lanBinding.expiresAtMilliseconds else { return nil }
            }
            if self.v2 == nil {
                guard slots.count < maximumConnections else { return nil }
            } else {
                guard peerIsOnLink, let acceptedAt, let source else { return nil }
                switch v2Admissions.admit(id, source: source, accepted: accepted, clock: acceptedAt,
                                           draining: retired.values.compactMap(\.source),
                                           peerIsOnLink: peerIsOnLink) {
                case .rejected: return nil
                case .admitted(let victim):
                    if let victim { evicted = retireProof(victim) }
                }
            }
            let channel = NetworkByteChannel(connection: connection) {
                Self.metadata(connection: $0, applicationProtocol: applicationProtocol)
                    .flatMap { Self.candidatePoint(metadata: $0) } != nil
            }
            channelAllocated?()
            let value = Slot(channel, source: source)
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
                        guard let acceptedAt, ContinuousClock.now < deadline else { throw PairingSetupChannelError.rejected }
                        let exporter = try Self.exporter(metadata)
                        let candidate = try await registrations.withTurn(until: deadline) {
                            try await windowV2.register(connection: id, acceptedAt: acceptedAt.milliseconds, peerPoint: point,
                                                        exporter: exporter, deadline: deadline)
                        }
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
                    catch { session.retireVerifiedProof(); await session.closeAndWait(); throw error }
                    do { try await handler(session) }
                    catch { await session.closeAndWait(); throw error }
                    await session.closeAndWait()
                } catch {}
                await channel.close()
                await registeredProof?.retire(confirmed)
                if confirmed {
                    registeredProof?.invalidateLink()
                    self?.close()
                }
                self?.release(id)
            }
            return true
        }
        if !keep { channel.abort() }
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
            guard !closed, slots[id] != nil, v2Admissions.isVerifying(id, at: proofTime()) else {
                throw PairingSetupChannelError.rejected
            }
        }
    }

    private func completeVerification(_ id: UUID) throws {
        try lock.withLock {
            guard !closed, let slot = slots[id],
                  v2Admissions.completeVerification(id, at: proofTime(), closeAdmission: lanBinding != nil) else {
                throw PairingSetupChannelError.rejected
            }
            slot.proofTimer?.cancel(); slot.proofTimer = nil
        }
        // Keep the accepted candidate alive for confirmation and receipt delivery.
        if let advertisement { queue.async { advertisement.withdraw() } }
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
            slots.removeAll(); v2Admissions.removeAll()
            return Array(retired.values)
        }
        guard let owned else { return }
        listener.cancel()
        for slot in owned { cancel(slot) }
        queue.async { [advertisement, event] in
            advertisement?.close()
            event(result)
        }
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
