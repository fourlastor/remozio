import CPairingTLS
import Foundation
import RemozioProtocol

/// One accepted pairing connection from the C shim. Closing is the owner's job.
public final class TLSPairingStream: PairingByteStream {
    private var connection: OpaquePointer?
    public private(set) var bytesRead = 0

    init(connection: OpaquePointer) { self.connection = connection }

    deinit { close() }

    public func close() {
        if let connection { remozio_tls_connection_close(connection) }
        connection = nil
    }

    public func write(_ bytes: Data, deadline: Int64) throws {
        guard let connection else { throw PairingSessionError.stream("closed") }
        let status = bytes.withUnsafeBytes { buffer in
            remozio_tls_write(connection, buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count, -1, deadline)
        }
        try Self.check(status)
    }

    public func read(maximum: Int, deadline: Int64) throws -> Data {
        guard let connection else { throw PairingSessionError.stream("closed") }
        var buffer = [UInt8](repeating: 0, count: max(1, min(maximum, 16_384)))
        var count = 0
        let capacity = buffer.count
        let status = buffer.withUnsafeMutableBufferPointer { remozio_tls_read(connection, $0.baseAddress, capacity, -1, deadline, &count) }
        try Self.check(status)
        bytesRead += count
        return Data(buffer.prefix(count))
    }

    public func invitationExporter() throws -> Data {
        guard let connection else { throw PairingSessionError.stream("closed") }
        var material = Data(count: Int(REMOZIO_TLS_EXPORTER_LENGTH))
        let status = material.withUnsafeMutableBytes { buffer in
            remozio_tls_export_pairing_v2(connection, PairingInvitationV2.exporterLabel,
                                          buffer.bindMemory(to: UInt8.self).baseAddress)
        }
        try Self.check(status)
        return material
    }

    static func check(_ status: RemozioTLSStatus) throws {
        switch status {
        case REMOZIO_TLS_OK: return
        case REMOZIO_TLS_TIMEOUT: throw PairingSessionError.expired
        default: throw PairingSessionError.stream(Self.describe(status))
        }
    }

    static func describe(_ status: RemozioTLSStatus) -> String {
        switch status {
        case REMOZIO_TLS_TIMEOUT: return "timeout"
        case REMOZIO_TLS_CANCELLED: return "cancelled"
        case REMOZIO_TLS_HANDSHAKE_FAILED: return "handshake failed"
        case REMOZIO_TLS_PEER_CERTIFICATE: return "peer certificate refused"
        case REMOZIO_TLS_CLOSED: return "peer closed"
        case REMOZIO_TLS_IO: return "I/O error"
        case REMOZIO_TLS_PROTOCOL: return "TLS protocol error"
        default: return "TLS status \(status.rawValue)"
        }
    }
}

/// The server half of the setup TLS profile, built from the persisted transport key and a fresh certificate.
public final class TLSPairingServer {
    private let context: OpaquePointer

    public init(identity: PairingIdentity, nowUnixSeconds: Int64, lifetimeSeconds: Int64, version2: Bool = false) throws {
        let (certificate, key) = try identity.transportCertificate(nowUnixSeconds: nowUnixSeconds, lifetimeSeconds: lifetimeSeconds)
        let made = certificate.withUnsafeBytes { cert in
            key.withUnsafeBytes { key in
                let certificate = cert.bindMemory(to: UInt8.self).baseAddress
                let privateKey = key.bindMemory(to: UInt8.self).baseAddress
                return version2
                    ? remozio_tls_server_context_new_v2(certificate, cert.count, privateKey, key.count)
                    : remozio_tls_server_context_new(certificate, cert.count, privateKey, key.count)
            }
        }
        guard let made else { throw PairingSessionError.stream("server context") }
        context = made
    }

    deinit { remozio_tls_context_free(context) }

    /// Takes ownership of `fd`. Returns the stream and the client certificate's 65-byte P-256 point. A successful
    /// handshake proves key possession only; the first authenticated frame is the evidence the peer accepted us.
    public func accept(fd: Int32, deadline: Int64) throws -> (stream: TLSPairingStream, peerPoint: Data) {
        var connection: OpaquePointer?
        var point = [UInt8](repeating: 0, count: Int(REMOZIO_TLS_POINT_LENGTH))
        let handshake = min(deadline, remozio_tls_now_ms() + Int64(REMOZIO_TLS_DEFAULT_HANDSHAKE_MS))
        let status = point.withUnsafeMutableBufferPointer { buffer in
            remozio_tls_accept(context, fd, -1, handshake, &connection, buffer.baseAddress)
        }
        try TLSPairingStream.check(status)
        guard let connection else { throw PairingSessionError.stream("no connection") }
        return (TLSPairingStream(connection: connection), Data(point))
    }
}
