import CPairingTLS
import CPairingTLSTestSupport
import Dispatch
import Foundation
import Glibc
import XCTest

/// Holds C handles across the concurrent server and client halves of one test.
private final class Outcome: @unchecked Sendable {
    var status = REMOZIO_TLS_INTERNAL
    var connection: OpaquePointer?
    var point = [UInt8](repeating: 0, count: Int(REMOZIO_TLS_POINT_LENGTH))
    var firstRead = REMOZIO_TLS_INTERNAL // the client's first post-handshake read, or the raw peer's result
    var reused: Int32 = -1
}

private struct Identity {
    var cert: [UInt8]
    var key: [UInt8]
    static func make(curve: String = "P-256", before: Int64 = Int64(Date().timeIntervalSince1970) - 60,
                     after: Int64 = Int64(Date().timeIntervalSince1970) + 3600) -> Identity {
        var cert: UnsafeMutablePointer<UInt8>?, key: UnsafeMutablePointer<UInt8>?
        var certLength = 0, keyLength = 0
        precondition(remozio_tls_make_identity(curve, before, after, &cert, &certLength, &key, &keyLength) == REMOZIO_TLS_OK)
        defer { remozio_tls_free(cert); remozio_tls_free(key) }
        return Identity(cert: Array(UnsafeBufferPointer(start: cert, count: certLength)),
                        key: Array(UnsafeBufferPointer(start: key, count: keyLength)))
    }
    /// A P-256 leaf signed by another key; sameName makes it self-issued but still not self-signed.
    static func issued(sameName: Bool) -> Identity {
        var cert: UnsafeMutablePointer<UInt8>?, key: UnsafeMutablePointer<UInt8>?
        var certLength = 0, keyLength = 0
        precondition(remozio_test_make_issued_identity(sameName ? 1 : 0, &cert, &certLength, &key, &keyLength) == 1)
        defer { remozio_test_free(cert); remozio_test_free(key) }
        return Identity(cert: Array(UnsafeBufferPointer(start: cert, count: certLength)),
                        key: Array(UnsafeBufferPointer(start: key, count: keyLength)))
    }
    /// The public point derived from the private key, independently of any handshake.
    var point: [UInt8] {
        var point = [UInt8](repeating: 0, count: 65)
        precondition(remozio_test_public_point(key, key.count, &point) == 1)
        return point
    }
}

private func alpnWire(_ names: [String]) -> [UInt8] { names.flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } }

/// A plain OpenSSL peer from the test-support target, configured beyond what the adapter allows.
private func rawContext(server: Bool, _ identity: Identity, extra: Identity? = nil, alpn: [UInt8]? = nil,
                        tickets: Bool = false) -> UnsafeMutableRawPointer {
    let extraCert = extra?.cert ?? [], alpnBytes = alpn ?? []
    return identity.cert.withUnsafeBufferPointer { cert in
        identity.key.withUnsafeBufferPointer { key in
            extraCert.withUnsafeBufferPointer { extraBuffer in
                alpnBytes.withUnsafeBufferPointer { alpnBuffer in
                    var options = RemozioTestPeerOptions(
                        cert: cert.baseAddress, cert_length: cert.count, key: key.baseAddress, key_length: key.count,
                        extra: extra == nil ? nil : extraBuffer.baseAddress, extra_length: extraBuffer.count,
                        alpn_wire: alpn == nil ? nil : alpnBuffer.baseAddress, alpn_length: alpnBuffer.count,
                        issue_tickets: tickets ? 1 : 0)
                    return server ? remozio_test_server_context_new(&options)! : remozio_test_client_context_new(&options)!
                }
            }
        }
    }
}

private func socketPair() -> (Int32, Int32) {
    var fds: [Int32] = [0, 0]
    precondition(socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0)
    return (fds[0], fds[1])
}

private func openDescriptors() -> Int { (try? FileManager.default.contentsOfDirectory(atPath: "/proc/self/fd").count) ?? -1 }
private func deadline(_ ms: Int64) -> Int64 { remozio_tls_now_ms() + ms }

final class PairingTLSTests: XCTestCase {
    /// The raw test-support peers write through OpenSSL's ordinary socket BIO, so the test process (not the
    /// adapter) ignores SIGPIPE. The SIGPIPE test restores the default disposition while it checks the adapter.
    override class func setUp() {
        super.setUp()
        signal(SIGPIPE, SIG_IGN)
    }

    private func serverContext(_ identity: Identity) -> OpaquePointer {
        remozio_tls_server_context_new(identity.cert, identity.cert.count, identity.key, identity.key.count)!
    }

    private func clientContext(_ identity: Identity?, options: RemozioTLSClientOptions = RemozioTLSClientOptions()) -> OpaquePointer {
        var options = options
        if let identity { return remozio_tls_client_context_new(&options, identity.cert, identity.cert.count, identity.key, identity.key.count)! }
        return remozio_tls_client_context_new(&options, nil, 0, nil, 0)!
    }

    /// Runs the server half on a queue and the client half here; returns (server, client).
    private func handshake(server: OpaquePointer, client: OpaquePointer, serverMs: Int64 = 5000, clientMs: Int64 = 5000,
                           serverCancel: Int32 = -1, drainMs: Int64 = 300) -> (Outcome, Outcome) {
        let (serverFD, clientFD) = socketPair()
        let serverOutcome = Outcome(), clientOutcome = Outcome()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            serverOutcome.status = remozio_tls_accept(server, serverFD, serverCancel, deadline(serverMs),
                                                      &serverOutcome.connection, &serverOutcome.point)
            done.signal()
        }
        clientOutcome.status = remozio_tls_connect(client, clientFD, -1, deadline(clientMs),
                                                   &clientOutcome.connection, &clientOutcome.point)
        // A TLS 1.3 client finishes before the server has judged its certificate; drain one read so alerts surface.
        if clientOutcome.status == REMOZIO_TLS_OK, let connection = clientOutcome.connection {
            var byte: UInt8 = 0, count = 0
            clientOutcome.firstRead = remozio_tls_read(connection, &byte, 1, -1, deadline(drainMs), &count)
        }
        done.wait()
        return (serverOutcome, clientOutcome)
    }

    /// The adapter accepts on a queue while a raw client connects here, offering an optional saved session. The
    /// server sends one byte so the client's read completes, then reads until the client closes.
    private func rawClient(_ rawClient: UnsafeMutableRawPointer, against server: OpaquePointer,
                           offering session: UnsafeMutableRawPointer? = nil) -> (server: Outcome, client: Outcome,
                                                                                 session: UnsafeMutableRawPointer?) {
        let (serverFD, clientFD) = socketPair()
        let serverOutcome = Outcome(), clientOutcome = Outcome()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            serverOutcome.status = remozio_tls_accept(server, serverFD, -1, deadline(5000), &serverOutcome.connection,
                                                      &serverOutcome.point)
            if let connection = serverOutcome.connection {
                serverOutcome.reused = remozio_tls_session_was_reused(connection)
                var byte: UInt8 = 0x78, count = 0
                _ = remozio_tls_write(connection, &byte, 1, -1, deadline(5000))
                while remozio_tls_read(connection, &byte, 1, -1, deadline(5000), &count) == REMOZIO_TLS_OK {}
                remozio_tls_connection_close(connection)
                serverOutcome.connection = nil
            }
            done.signal()
        }
        var latest: UnsafeMutableRawPointer?
        let completed = remozio_test_connect_once(rawClient, clientFD, session, &clientOutcome.reused, &latest)
        clientOutcome.status = completed == 1 ? REMOZIO_TLS_OK : REMOZIO_TLS_HANDSHAKE_FAILED
        done.wait()
        return (serverOutcome, clientOutcome, latest)
    }

    /// Raw client against raw server, for controls that must hold without the adapter.
    private func rawClient(_ rawClient: UnsafeMutableRawPointer, againstRaw rawServer: UnsafeMutableRawPointer,
                           offering session: UnsafeMutableRawPointer? = nil) -> (server: Outcome, client: Outcome,
                                                                                 session: UnsafeMutableRawPointer?) {
        let (serverFD, clientFD) = socketPair()
        let serverOutcome = Outcome(), clientOutcome = Outcome()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            serverOutcome.status = remozio_test_serve_once(rawServer, serverFD) == 1 ? REMOZIO_TLS_OK : REMOZIO_TLS_HANDSHAKE_FAILED
            done.signal()
        }
        var latest: UnsafeMutableRawPointer?
        let completed = remozio_test_connect_once(rawClient, clientFD, session, &clientOutcome.reused, &latest)
        clientOutcome.status = completed == 1 ? REMOZIO_TLS_OK : REMOZIO_TLS_HANDSHAKE_FAILED
        done.wait()
        return (serverOutcome, clientOutcome, latest)
    }

    /// A raw server serves one connection on a queue while the adapter connects here and reads its one byte.
    private func adapterClient(_ client: OpaquePointer, against rawServer: UnsafeMutableRawPointer) -> (server: Outcome, client: Outcome) {
        let (serverFD, clientFD) = socketPair()
        let serverOutcome = Outcome(), clientOutcome = Outcome()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            serverOutcome.status = remozio_test_serve_once(rawServer, serverFD) == 1 ? REMOZIO_TLS_OK : REMOZIO_TLS_HANDSHAKE_FAILED
            done.signal()
        }
        clientOutcome.status = remozio_tls_connect(client, clientFD, -1, deadline(5000), &clientOutcome.connection,
                                                   &clientOutcome.point)
        if let connection = clientOutcome.connection {
            var byte: UInt8 = 0, count = 0
            clientOutcome.firstRead = remozio_tls_read(connection, &byte, 1, -1, deadline(5000), &count)
            remozio_tls_connection_close(connection)
            clientOutcome.connection = nil
        }
        done.wait()
        return (serverOutcome, clientOutcome)
    }

    func testPositiveHandshakeNegotiatesTLS13PairingALPNWithNoTicketsOrResumption() {
        let serverID = Identity.make(), clientID = Identity.make()
        let server = serverContext(serverID), client = clientContext(clientID)
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        XCTAssertEqual(s.status, REMOZIO_TLS_OK)
        XCTAssertEqual(c.status, REMOZIO_TLS_OK)
        let serverConnection = s.connection!, clientConnection = c.connection!
        defer { remozio_tls_connection_close(serverConnection); remozio_tls_connection_close(clientConnection) }
        XCTAssertEqual(remozio_tls_negotiated_version(serverConnection), 0x0304)
        XCTAssertEqual(String(cString: remozio_tls_negotiated_alpn(serverConnection)), "remozio-pairing/1")
        XCTAssertEqual(remozio_tls_session_was_reused(serverConnection), 0)
        XCTAssertEqual(remozio_tls_context_tickets_received(client), 0)
        // Each side exports exactly the other side's key, as derived from that side's private key.
        XCTAssertEqual(s.point, clientID.point)
        XCTAssertEqual(c.point, serverID.point)
        let again = handshake(server: server, client: client)
        XCTAssertEqual(remozio_tls_session_was_reused(again.0.connection!), 0)
        XCTAssertEqual(remozio_tls_context_tickets_received(client), 0)
        XCTAssertEqual(again.0.point, s.point)
        XCTAssertEqual(again.1.point, c.point)
        remozio_tls_connection_close(again.0.connection)
        remozio_tls_connection_close(again.1.connection)
    }

    func testDataRoundTripWithPartialReadsAndLargeWrites() {
        let serverID = Identity.make(), clientID = Identity.make()
        let server = serverContext(serverID), client = clientContext(clientID)
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        let serverConnection = s.connection!, clientConnection = c.connection!
        defer { remozio_tls_connection_close(serverConnection); remozio_tls_connection_close(clientConnection) }
        let payload = (0..<300_000).map { UInt8(truncatingIfNeeded: $0 &* 31) }
        let received = Outcome()
        let finished = DispatchSemaphore(value: 0)
        var collected: [UInt8] = []
        DispatchQueue.global().async {
            var chunk = [UInt8](repeating: 0, count: 7) // tiny buffer forces many partial reads
            while collected.count < payload.count {
                var count = 0
                guard remozio_tls_read(serverConnection, &chunk, chunk.count, -1, deadline(5000), &count) == REMOZIO_TLS_OK else { break }
                collected.append(contentsOf: chunk[0..<count])
            }
            received.status = REMOZIO_TLS_OK
            finished.signal()
        }
        XCTAssertEqual(remozio_tls_write(clientConnection, payload, payload.count, -1, deadline(10000)), REMOZIO_TLS_OK)
        finished.wait()
        XCTAssertEqual(collected, payload)
    }

    func testWrongALPNIsRejected() {
        let server = serverContext(.make())
        var options = RemozioTLSClientOptions()
        let client = "other/1".withCString { name -> OpaquePointer in
            options.alpn = name
            return clientContext(.make(), options: options)
        }
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        defer { remozio_tls_connection_close(s.connection); remozio_tls_connection_close(c.connection) }
        XCTAssertEqual(s.status, REMOZIO_TLS_HANDSHAKE_FAILED)
        XCTAssertNil(s.connection)
    }

    func testMissingALPNIsRejected() {
        let server = serverContext(.make())
        var options = RemozioTLSClientOptions()
        options.offer_no_alpn = 1
        let client = clientContext(.make(), options: options)
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        defer { remozio_tls_connection_close(s.connection); remozio_tls_connection_close(c.connection) }
        XCTAssertEqual(s.status, REMOZIO_TLS_HANDSHAKE_FAILED)
    }

    func testTLS12ClientIsRejected() {
        let server = serverContext(.make())
        var options = RemozioTLSClientOptions()
        options.min_version = 0x0303
        options.max_version = 0x0303
        let client = clientContext(.make(), options: options)
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        defer { remozio_tls_connection_close(s.connection); remozio_tls_connection_close(c.connection) }
        XCTAssertEqual(s.status, REMOZIO_TLS_HANDSHAKE_FAILED)
    }

    func testMissingClientCertificateIsRejected() {
        let server = serverContext(.make())
        let client = clientContext(nil)
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        defer { remozio_tls_connection_close(s.connection); remozio_tls_connection_close(c.connection) }
        XCTAssertEqual(s.status, REMOZIO_TLS_HANDSHAKE_FAILED)
    }

    func testNonP256ClientCertificateIsRejected() {
        let server = serverContext(.make())
        let client = clientContext(.make(curve: "P-384"))
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        defer { remozio_tls_connection_close(s.connection); remozio_tls_connection_close(c.connection) }
        XCTAssertEqual(s.status, REMOZIO_TLS_PEER_CERTIFICATE)
    }

    func testExpiredAndNotYetValidClientCertificatesAreRejected() {
        let now = Int64(Date().timeIntervalSince1970)
        for (before, after) in [(now - 7200, now - 3600), (now + 3600, now + 7200)] {
            let server = serverContext(.make())
            let client = clientContext(.make(before: before, after: after))
            defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
            let (s, c) = handshake(server: server, client: client)
            defer { remozio_tls_connection_close(s.connection); remozio_tls_connection_close(c.connection) }
            XCTAssertEqual(s.status, REMOZIO_TLS_PEER_CERTIFICATE)
        }
    }

    func testInvalidServerCertificatesAreRejected() {
        let now = Int64(Date().timeIntervalSince1970)
        let identities = [
            Identity.make(curve: "P-384"),
            Identity.make(before: now - 7200, after: now - 3600),
            Identity.make(before: now + 3600, after: now + 7200),
        ]
        for identity in identities {
            let server = serverContext(identity), client = clientContext(.make())
            defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
            let (s, c) = handshake(server: server, client: client)
            defer { remozio_tls_connection_close(s.connection); remozio_tls_connection_close(c.connection) }
            XCTAssertEqual(c.status, REMOZIO_TLS_PEER_CERTIFICATE)
            XCTAssertNil(c.connection)
        }
    }

    func testSilentPeerTimesOutAndClosesTheDescriptor() {
        let server = serverContext(.make())
        defer { remozio_tls_context_free(server) }
        let before = openDescriptors()
        let (serverFD, clientFD) = socketPair() // the client end stays open and silent
        var connection: OpaquePointer?
        var point = [UInt8](repeating: 0, count: 65)
        let started = remozio_tls_now_ms()
        XCTAssertEqual(remozio_tls_accept(server, serverFD, -1, deadline(300), &connection, &point), REMOZIO_TLS_TIMEOUT)
        XCTAssertGreaterThanOrEqual(remozio_tls_now_ms() - started, 290)
        XCTAssertLessThan(remozio_tls_now_ms() - started, 3000)
        XCTAssertEqual(fcntl(serverFD, F_GETFD), -1) // the shim closed it
        close(clientFD)
        XCTAssertEqual(openDescriptors(), before)
    }

    func testCancellationDuringHandshake() {
        let server = serverContext(.make())
        defer { remozio_tls_context_free(server) }
        var pipeFDs: [Int32] = [0, 0]
        XCTAssertEqual(pipe(&pipeFDs), 0); let writeFD = pipeFDs[1]
        let (serverFD, clientFD) = socketPair()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { _ = write(writeFD, "x", 1) }
        var connection: OpaquePointer?
        var point = [UInt8](repeating: 0, count: 65)
        XCTAssertEqual(remozio_tls_accept(server, serverFD, pipeFDs[0], deadline(10000), &connection, &point), REMOZIO_TLS_CANCELLED)
        close(clientFD); close(pipeFDs[0]); close(pipeFDs[1])
    }

    func testSilentHandshakeUsesAbsoluteBootTimeTimerAndReleasesItOnCancel() {
        let server = serverContext(.make())
        defer { remozio_tls_context_free(server) }
        let existing = Set((try? FileManager.default.contentsOfDirectory(atPath: "/proc/self/fdinfo")) ?? [])
        let (serverFD, clientFD) = socketPair()
        var pipeFDs: [Int32] = [0, 0]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        let cancelFD = pipeFDs[0]
        defer { close(clientFD); close(pipeFDs[0]); close(pipeFDs[1]) }
        let outcome = Outcome()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            outcome.status = remozio_tls_accept(server, serverFD, cancelFD, deadline(600_000),
                                                &outcome.connection, &outcome.point)
            done.signal()
        }

        var timerFD: Int32?
        var timerInfo: [String: String] = [:]
        let observeUntil = deadline(2000)
        while timerFD == nil && remozio_tls_now_ms() < observeUntil {
            for name in (try? FileManager.default.contentsOfDirectory(atPath: "/proc/self/fdinfo")) ?? [] {
                guard !existing.contains(name), let fd = Int32(name),
                      let info = try? String(contentsOfFile: "/proc/self/fdinfo/" + name, encoding: .utf8) else { continue }
                var fields: [String: String] = [:]
                for line in info.split(separator: "\n") {
                    let parts = line.split(separator: ":", maxSplits: 1)
                    if parts.count == 2 {
                        fields[String(parts[0]).trimmingCharacters(in: .whitespaces)] =
                            String(parts[1]).trimmingCharacters(in: .whitespaces)
                    }
                }
                if fields["clockid"] != nil { timerFD = fd; timerInfo = fields; break }
            }
            if timerFD == nil { Thread.sleep(forTimeInterval: 0.01) }
        }
        XCTAssertNotNil(timerFD)
        XCTAssertEqual(Int(timerInfo["clockid"] ?? ""), Int(CLOCK_BOOTTIME))
        XCTAssertEqual(Int(timerInfo["settime flags"] ?? "", radix: 8), 1)
        let remaining = (timerInfo["it_value"] ?? "").components(separatedBy: CharacterSet.decimalDigits.inverted)
            .compactMap { Int($0) }
        XCTAssertEqual(remaining.count, 2)
        if remaining.count == 2 {
            XCTAssertGreaterThan(remaining[0] + remaining[1], 0)
            XCTAssertLessThanOrEqual(remaining[0], 60)
        }
        if let timerFD {
            let flags = fcntl(timerFD, F_GETFD)
            XCTAssertGreaterThanOrEqual(flags, 0)
            XCTAssertEqual(flags & FD_CLOEXEC, FD_CLOEXEC)
        }

        _ = write(pipeFDs[1], "x", 1)
        done.wait()
        XCTAssertEqual(outcome.status, REMOZIO_TLS_CANCELLED)
        remozio_tls_connection_close(outcome.connection)
        if let timerFD { XCTAssertEqual(fcntl(timerFD, F_GETFD), -1) }
    }

    func testCancellationDuringReadAndStalledWriteTimesOut() {
        let serverID = Identity.make(), clientID = Identity.make()
        let server = serverContext(serverID), client = clientContext(clientID)
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        let serverConnection = s.connection!, clientConnection = c.connection!
        defer { remozio_tls_connection_close(serverConnection); remozio_tls_connection_close(clientConnection) }
        var pipeFDs: [Int32] = [0, 0]
        XCTAssertEqual(pipe(&pipeFDs), 0); let writeFD = pipeFDs[1]
        defer { close(pipeFDs[0]); close(pipeFDs[1]) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { _ = write(writeFD, "x", 1) }
        var byte: UInt8 = 0, count = 0
        XCTAssertEqual(remozio_tls_read(serverConnection, &byte, 1, pipeFDs[0], deadline(10000), &count), REMOZIO_TLS_CANCELLED)
        // The client never reads, so a payload larger than the socket buffers must stop at the deadline.
        let big = [UInt8](repeating: 7, count: 64 * 1024 * 1024)
        XCTAssertEqual(remozio_tls_write(serverConnection, big, big.count, -1, deadline(400)), REMOZIO_TLS_TIMEOUT)
    }

    func testExpiredDeadlineAndSignalledCancelWinBeforeAnyIO() {
        let serverID = Identity.make(), clientID = Identity.make()
        let server = serverContext(serverID), client = clientContext(clientID)
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        let serverConnection = s.connection!, clientConnection = c.connection!
        defer { remozio_tls_connection_close(serverConnection); remozio_tls_connection_close(clientConnection) }
        var byte: UInt8 = 1, count = 0
        XCTAssertEqual(remozio_tls_write(clientConnection, &byte, 1, -1, deadline(5000)), REMOZIO_TLS_OK) // data is now buffered
        XCTAssertEqual(remozio_tls_read(serverConnection, &byte, 1, -1, deadline(-1), &count), REMOZIO_TLS_TIMEOUT)
        var pipeFDs: [Int32] = [0, 0]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { close(pipeFDs[0]); close(pipeFDs[1]) }
        _ = write(pipeFDs[1], "x", 1)
        XCTAssertEqual(remozio_tls_read(serverConnection, &byte, 1, pipeFDs[0], deadline(5000), &count), REMOZIO_TLS_CANCELLED)
        let big = [UInt8](repeating: 7, count: 1024 * 1024)
        XCTAssertEqual(remozio_tls_write(serverConnection, big, big.count, pipeFDs[0], deadline(5000)), REMOZIO_TLS_CANCELLED)
    }

    func testInvalidReadAndWriteArgumentsAreRefused() {
        let serverID = Identity.make(), clientID = Identity.make()
        let server = serverContext(serverID), client = clientContext(clientID)
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        let connection = s.connection!
        defer { remozio_tls_connection_close(connection); remozio_tls_connection_close(c.connection) }
        var byte: UInt8 = 0, count = 0
        XCTAssertEqual(remozio_tls_read(connection, &byte, 0, -1, deadline(100), &count), REMOZIO_TLS_INVALID_ARGUMENT)
        XCTAssertEqual(remozio_tls_read(connection, nil, 1, -1, deadline(100), &count), REMOZIO_TLS_INVALID_ARGUMENT)
        XCTAssertEqual(remozio_tls_read(connection, &byte, 1, -1, deadline(100), nil), REMOZIO_TLS_INVALID_ARGUMENT)
        XCTAssertEqual(remozio_tls_write(connection, nil, 1, -1, deadline(100)), REMOZIO_TLS_INVALID_ARGUMENT)
        XCTAssertEqual(remozio_tls_write(connection, &byte, 0, -1, deadline(100)), REMOZIO_TLS_OK)
    }

    func testNullOutputPointersAreRefused() {
        var cert: UnsafeMutablePointer<UInt8>?
        var length = 0
        XCTAssertEqual(remozio_tls_make_identity("P-256", 1, 2, &cert, &length, nil, nil), REMOZIO_TLS_INVALID_ARGUMENT)
        let identity = Identity.make()
        let server = serverContext(identity)
        defer { remozio_tls_context_free(server) }
        let (fd, other) = socketPair()
        XCTAssertEqual(remozio_tls_accept(server, fd, -1, deadline(100), nil, nil), REMOZIO_TLS_INVALID_ARGUMENT)
        close(other)
    }

    func testPeerCloseReportsClosed() {
        let serverID = Identity.make(), clientID = Identity.make()
        let server = serverContext(serverID), client = clientContext(clientID)
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        remozio_tls_connection_close(c.connection)
        var byte: UInt8 = 0, count = 0
        XCTAssertEqual(remozio_tls_read(s.connection!, &byte, 1, -1, deadline(2000), &count), REMOZIO_TLS_CLOSED)
        remozio_tls_connection_close(s.connection)
    }

    func testRepeatedFailedHandshakesLeakNoDescriptors() {
        let server = serverContext(.make())
        let client = clientContext(nil)
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let before = openDescriptors()
        for _ in 0..<20 {
            let (s, c) = handshake(server: server, client: client)
            XCTAssertNil(s.connection)
            remozio_tls_connection_close(c.connection)
        }
        XCTAssertEqual(openDescriptors(), before)
    }

    func testTicketCounterCountsTicketsFromATicketIssuingServer() {
        // Positive control for the zero-ticket assertions: the same client counter sees a raw server's tickets.
        let rawServer = rawContext(server: true, .make(), tickets: true)
        let client = clientContext(.make())
        defer { remozio_test_context_free(rawServer); remozio_tls_context_free(client) }
        let (s, c) = adapterClient(client, against: rawServer)
        XCTAssertEqual(c.status, REMOZIO_TLS_OK)
        XCTAssertEqual(c.firstRead, REMOZIO_TLS_OK)
        XCTAssertEqual(s.status, REMOZIO_TLS_OK)
        XCTAssertEqual(remozio_tls_context_tickets_received(client), 2)
    }

    func testSavedSessionIsOfferedButNotResumed() {
        let clientID = Identity.make()
        let rawServer = rawContext(server: true, .make(), tickets: true)
        let rawClientContext = rawContext(server: false, clientID)
        let server = serverContext(.make())
        defer { remozio_test_context_free(rawServer); remozio_test_context_free(rawClientContext); remozio_tls_context_free(server) }

        // Positive control: this client resumes a raw ticket-issuing server with its saved session.
        let (_, first, saved) = rawClient(rawClientContext, againstRaw: rawServer)
        XCTAssertEqual(first.status, REMOZIO_TLS_OK)
        XCTAssertEqual(first.reused, 0)
        XCTAssertNotNil(saved)
        XCTAssertEqual(remozio_test_tickets_received(rawClientContext), 2)
        let (_, resumed, resumedSession) = rawClient(rawClientContext, againstRaw: rawServer, offering: saved)
        remozio_test_session_free(resumedSession)
        XCTAssertEqual(resumed.status, REMOZIO_TLS_OK)
        XCTAssertEqual(resumed.reused, 1)
        XCTAssertEqual(remozio_test_tickets_received(rawClientContext), 3) // OpenSSL sends one ticket on resumption

        // The adapter is offered that resumable session and performs a full handshake that authenticates the client.
        let (s, c, latest) = rawClient(rawClientContext, against: server, offering: saved)
        remozio_test_session_free(latest)
        remozio_test_session_free(saved)
        XCTAssertEqual(s.status, REMOZIO_TLS_OK)
        XCTAssertEqual(s.reused, 0)
        XCTAssertEqual(s.point, clientID.point)
        XCTAssertEqual(c.status, REMOZIO_TLS_OK)
        XCTAssertEqual(c.reused, 0)
        XCTAssertEqual(remozio_test_tickets_received(rawClientContext), 3) // the adapter issued none
    }

    func testNonSelfSignedLeavesAreRejectedAtBothEndpoints() {
        for sameName in [false, true] {
            let issued = Identity.issued(sameName: sameName)
            let server = serverContext(.make()), client = clientContext(issued)
            let (s, c) = handshake(server: server, client: client)
            XCTAssertEqual(s.status, REMOZIO_TLS_PEER_CERTIFICATE, "client leaf, sameName \(sameName)")
            XCTAssertNil(s.connection)
            remozio_tls_connection_close(c.connection)

            let issuedServer = serverContext(issued), plainClient = clientContext(.make())
            let (s2, c2) = handshake(server: issuedServer, client: plainClient)
            XCTAssertEqual(c2.status, REMOZIO_TLS_PEER_CERTIFICATE, "server leaf, sameName \(sameName)")
            XCTAssertNil(c2.connection)
            remozio_tls_connection_close(s2.connection)
            for context in [server, client, issuedServer, plainClient] { remozio_tls_context_free(context) }
        }
    }

    func testExtraChainCertificatesAreRejectedAtBothEndpoints() {
        let server = serverContext(.make()), client = clientContext(.make())
        let chainedClient = rawContext(server: false, .make(), extra: .make())
        let chainedServer = rawContext(server: true, .make(), extra: .make())
        defer {
            remozio_tls_context_free(server); remozio_tls_context_free(client)
            remozio_test_context_free(chainedClient); remozio_test_context_free(chainedServer)
        }
        let (s, _, session) = rawClient(chainedClient, against: server)
        remozio_test_session_free(session)
        XCTAssertEqual(s.status, REMOZIO_TLS_PEER_CERTIFICATE)
        let (_, c) = adapterClient(client, against: chainedServer)
        XCTAssertEqual(c.status, REMOZIO_TLS_PEER_CERTIFICATE)
    }

    func testALPNListsWithExtraProtocolsAreRejected() {
        let server = serverContext(.make())
        defer { remozio_tls_context_free(server) }
        let cases: [([String], RemozioTLSStatus)] = [
            (["remozio-pairing/1"], REMOZIO_TLS_OK), // control: the raw client's exact offer is accepted
            (["remozio-pairing/1", "h2"], REMOZIO_TLS_HANDSHAKE_FAILED),
            (["h2", "remozio-pairing/1"], REMOZIO_TLS_HANDSHAKE_FAILED),
            (["remozio-pairing/1", "remozio-pairing/1"], REMOZIO_TLS_HANDSHAKE_FAILED),
        ]
        for (names, expected) in cases {
            let rawClientContext = rawContext(server: false, .make(), alpn: alpnWire(names))
            let (s, c, session) = rawClient(rawClientContext, against: server)
            remozio_test_session_free(session)
            remozio_test_context_free(rawClientContext)
            XCTAssertEqual(s.status, expected, "\(names)")
            XCTAssertEqual(c.status == REMOZIO_TLS_OK, expected == REMOZIO_TLS_OK, "\(names)")
        }
    }

    func testPolicyRejectionAfterTheHandshakeReachesThePeerAsAClose() {
        // TLS 1.3 completes the client before the server judges its certificate, and the client finishes before it
        // judges the server's. Either rejection closes the transport without an alert, so the rejected side first
        // sees an accepted connection, then CLOSED. Accept/connect success is local acceptance only.
        let server = serverContext(.make()), wrongCurveClient = clientContext(.make(curve: "P-384"))
        let (s, c) = handshake(server: server, client: wrongCurveClient, drainMs: 5000)
        XCTAssertEqual(s.status, REMOZIO_TLS_PEER_CERTIFICATE)
        XCTAssertEqual(c.status, REMOZIO_TLS_OK)
        XCTAssertEqual(c.firstRead, REMOZIO_TLS_CLOSED)
        remozio_tls_connection_close(c.connection)

        let wrongCurveServer = serverContext(.make(curve: "P-384")), client = clientContext(.make())
        let (s2, c2) = handshake(server: wrongCurveServer, client: client)
        XCTAssertEqual(c2.status, REMOZIO_TLS_PEER_CERTIFICATE)
        XCTAssertEqual(s2.status, REMOZIO_TLS_OK)
        if let connection = s2.connection {
            var byte: UInt8 = 0, count = 0
            XCTAssertEqual(remozio_tls_read(connection, &byte, 1, -1, deadline(5000), &count), REMOZIO_TLS_CLOSED)
            remozio_tls_connection_close(connection)
        }
        for context in [server, wrongCurveClient, wrongCurveServer, client] { remozio_tls_context_free(context) }
    }

    func testAdapterLeavesSIGPIPEAloneAndAWriteToAClosedPeerReportsClosed() {
        // With the default disposition, a SIGPIPE would terminate the test process instead of failing an assertion.
        var defaultAction = sigaction(), previous = sigaction(), current = sigaction()
        defaultAction.__sigaction_handler.sa_handler = SIG_DFL
        XCTAssertEqual(sigaction(SIGPIPE, &defaultAction, &previous), 0)
        defer { _ = sigaction(SIGPIPE, &previous, nil) }
        let server = serverContext(.make()), client = clientContext(.make())
        defer { remozio_tls_context_free(server); remozio_tls_context_free(client) }
        let (s, c) = handshake(server: server, client: client)
        XCTAssertEqual(sigaction(SIGPIPE, nil, &current), 0)
        XCTAssertNil(current.__sigaction_handler.sa_handler) // still SIG_DFL after contexts and a handshake
        let serverConnection = s.connection!
        remozio_tls_connection_close(c.connection)
        let payload = [UInt8](repeating: 1, count: 1024 * 1024)
        XCTAssertEqual(remozio_tls_write(serverConnection, payload, payload.count, -1, deadline(5000)), REMOZIO_TLS_CLOSED)
        remozio_tls_connection_close(serverConnection)
    }
}
