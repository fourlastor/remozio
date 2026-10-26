import CPairingTLS
import Dispatch
import Foundation
import Glibc
import XCTest

/// Holds C handles across the concurrent server and client halves of one test.
private final class Outcome: @unchecked Sendable {
    var status = REMOZIO_TLS_INTERNAL
    var connection: OpaquePointer?
    var point = [UInt8](repeating: 0, count: Int(REMOZIO_TLS_POINT_LENGTH))
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
}

private func socketPair() -> (Int32, Int32) {
    var fds: [Int32] = [0, 0]
    precondition(socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0)
    return (fds[0], fds[1])
}

private func openDescriptors() -> Int { (try? FileManager.default.contentsOfDirectory(atPath: "/proc/self/fd").count) ?? -1 }
private func deadline(_ ms: Int64) -> Int64 { remozio_tls_now_ms() + ms }

final class PairingTLSTests: XCTestCase {
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
                           serverCancel: Int32 = -1) -> (Outcome, Outcome) {
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
            _ = remozio_tls_read(connection, &byte, 1, -1, deadline(300), &count)
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
        XCTAssertEqual(s.point[0], 0x04)
        XCTAssertEqual(c.point[0], 0x04)
        XCTAssertNotEqual(s.point, c.point)
        // The server saw the client's key, and the client saw the server's.
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
}
