import CPairingTLS
import Foundation
#if canImport(Glibc)
import Glibc
#endif

// Attended host suspend probe for the pairing TLS shim (issue 496). It completes one loopback handshake, then waits in
// a server read on a silent peer with an absolute deadline on CLOCK_BOOTTIME. The operator suspends the host before
// the deadline and resumes it after. A heartbeat thread finds the resume. The JSON evidence holds clock readings, the
// read status and the kernel release; no host name, address, key or certificate.

setvbuf(stdout, nil, _IOLBF, 0)
print("EXPERIMENT: attended host suspend probe. Software keys on loopback; not the protected host service.")

func usage() -> Never {
    FileHandle.standardError.write(Data("usage: remozio-tls-suspend-probe [--wait-seconds 30...1800] [--output FILE]\n".utf8))
    exit(2)
}

var waitSeconds: Int64 = 120
var outputPath: String?
var arguments = CommandLine.arguments.dropFirst()
while let argument = arguments.popFirst() {
    switch argument {
    case "--wait-seconds":
        guard let value = arguments.popFirst().flatMap({ Int64($0) }), (30...1800).contains(value) else { usage() }
        waitSeconds = value
    case "--output":
        guard let value = arguments.popFirst() else { usage() }
        outputPath = value
    default: usage()
    }
}

func now(_ clock: clockid_t) -> Int64 {
    var time = timespec()
    precondition(clock_gettime(clock, &time) == 0)
    return Int64(time.tv_sec) * 1000 + Int64(time.tv_nsec) / 1_000_000
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

struct Identity { let cert: [UInt8]; let key: [UInt8] }
func makeIdentity() -> Identity {
    var cert: UnsafeMutablePointer<UInt8>?, key: UnsafeMutablePointer<UInt8>?
    var certLength = 0, keyLength = 0
    let seconds = Int64(Date().timeIntervalSince1970)
    guard remozio_tls_make_identity("P-256", seconds - 60, seconds + 7200, &cert, &certLength, &key, &keyLength)
            == REMOZIO_TLS_OK else { fail("Could not create a loopback identity.") }
    defer { remozio_tls_free(cert); remozio_tls_free(key) }
    return Identity(cert: Array(UnsafeBufferPointer(start: cert, count: certLength)),
                    key: Array(UnsafeBufferPointer(start: key, count: keyLength)))
}

/// Shared between the client thread and the main thread.
final class ClientSide: @unchecked Sendable {
    var context: OpaquePointer?
    var status = REMOZIO_TLS_INTERNAL
    var connection: OpaquePointer?
    var point = [UInt8](repeating: 0, count: Int(REMOZIO_TLS_POINT_LENGTH))
    let connected = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let finished = DispatchSemaphore(value: 0)
}

/// Heartbeat samples of (boot - monotonic). A jump marks time the host spent suspended.
final class Heartbeat: @unchecked Sendable {
    private let lock = NSLock()
    private var running = true
    private var lastGap: Int64 = 0
    private(set) var largestJump: Int64 = 0
    private(set) var resumeBoot: Int64?
    func run() {
        lock.withLock { lastGap = now(CLOCK_BOOTTIME) - now(CLOCK_MONOTONIC) }
        while lock.withLock({ running }) {
            usleep(100_000)
            lock.withLock { if running { sample() } }
        }
    }
    /// Takes one last sample, so a read that ends before the first tick after resume still sees the jump.
    func stop() -> (jump: Int64, resumeBoot: Int64?) {
        lock.withLock { sample(); running = false; return (largestJump, resumeBoot) }
    }
    private func sample() {
        let boot = now(CLOCK_BOOTTIME), gap = boot - now(CLOCK_MONOTONIC)
        if gap - lastGap > largestJump { largestJump = gap - lastGap; resumeBoot = boot }
        lastGap = gap
    }
}

let serverIdentity = makeIdentity(), clientIdentity = makeIdentity()
guard let server = remozio_tls_server_context_new(serverIdentity.cert, serverIdentity.cert.count,
                                                  serverIdentity.key, serverIdentity.key.count) else { fail("No server context.") }
var options = RemozioTLSClientOptions()
guard let client = remozio_tls_client_context_new(&options, clientIdentity.cert, clientIdentity.cert.count,
                                                  clientIdentity.key, clientIdentity.key.count) else { fail("No client context.") }
var fds: [Int32] = [0, 0]
guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else { fail("No socket pair.") }

let side = ClientSide()
side.context = client
let clientFD = fds[1]
Thread.detachNewThread {
    side.status = remozio_tls_connect(side.context, clientFD, -1, remozio_tls_now_ms() + 15_000, &side.connection, &side.point)
    side.connected.signal()
    side.release.wait()  // stay silent until the server's read has ended
    remozio_tls_connection_close(side.connection)
    side.finished.signal()
}
var connection: OpaquePointer?
var peerPoint = [UInt8](repeating: 0, count: Int(REMOZIO_TLS_POINT_LENGTH))
let accepted = remozio_tls_accept(server, fds[0], -1, remozio_tls_now_ms() + 15_000, &connection, &peerPoint)
side.connected.wait()
guard accepted == REMOZIO_TLS_OK, side.status == REMOZIO_TLS_OK, let connection else {
    fail("Loopback handshake failed: server \(accepted.rawValue), client \(side.status.rawValue).")
}

let heartbeat = Heartbeat()
Thread.detachNewThread { heartbeat.run() }
let startBoot = now(CLOCK_BOOTTIME), startMonotonic = now(CLOCK_MONOTONIC), startReal = now(CLOCK_REALTIME)
let deadline = remozio_tls_now_ms() + waitSeconds * 1000
let suspendBy = Date(timeIntervalSinceNow: Double(waitSeconds) / 2)
let resumeAfter = Date(timeIntervalSinceNow: Double(waitSeconds) + 30)
let clockFormat = DateFormatter()
clockFormat.dateFormat = "HH:mm:ss"
print("Waiting in a TLS read for \(waitSeconds) s of CLOCK_BOOTTIME.")
print("1. Suspend this machine before \(clockFormat.string(from: suspendBy)) (for example: systemctl suspend).")
print("2. Resume it after \(clockFormat.string(from: resumeAfter)), so the deadline passes while it is suspended.")
print("The probe reports when the read ends. Ctrl-C abandons the run.")

var byte: UInt8 = 0, count = 0
let status = remozio_tls_read(connection, &byte, 1, -1, deadline, &count)
let endBoot = now(CLOCK_BOOTTIME), endMonotonic = now(CLOCK_MONOTONIC), endReal = now(CLOCK_REALTIME)
let (jump, resumeBoot) = heartbeat.stop()
remozio_tls_connection_close(connection)
side.release.signal()
side.finished.wait()
remozio_tls_context_free(server)
remozio_tls_context_free(client)

let bootElapsed = endBoot - startBoot, monotonicElapsed = endMonotonic - startMonotonic
let suspended = bootElapsed - monotonicElapsed
let deadlineMs = waitSeconds * 1000
// The heartbeat's largest jump is the suspension: it began at resumeBoot - jump and ended at resumeBoot. Whether it
// spanned the deadline depends only on those two points, not on awake time before the read returned, so a read that
// wrongly waits out its remaining awake time after resume is still spanned and fails the post-resume check below.
let suspendedAt = resumeBoot.map { $0 - jump }
let spanned = jump >= 10_000 && (suspendedAt.map { $0 < deadline } ?? false) && (resumeBoot.map { $0 >= deadline } ?? false)
let afterResume = resumeBoot.map { endBoot - $0 }
let verdict: String
if status != REMOZIO_TLS_TIMEOUT || bootElapsed < deadlineMs { verdict = "failed" }
else if !spanned { verdict = "inconclusive" }
else if let afterResume, afterResume <= 5000 { verdict = "passed" }
else { verdict = "failed" }

var system = utsname()
uname(&system)
let release = withUnsafeBytes(of: system.release) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
let statusName: String
switch status {
case REMOZIO_TLS_OK: statusName = "ok"
case REMOZIO_TLS_TIMEOUT: statusName = "timeout"
case REMOZIO_TLS_CANCELLED: statusName = "cancelled"
case REMOZIO_TLS_CLOSED: statusName = "closed"
default: statusName = "status-\(status.rawValue)"
}
let evidence: [String: Any] = [
    "experiment": "pairing-tls-read-deadline-across-host-suspend",
    "evidenceFormat": 1,
    "kernelRelease": release,
    "recordedAt": ISO8601DateFormatter().string(from: Date()),
    "waitSeconds": waitSeconds,
    "readStatus": statusName,
    "bootElapsedMs": bootElapsed,
    "monotonicElapsedMs": monotonicElapsed,
    "realtimeElapsedMs": endReal - startReal,
    "suspendedMs": suspended,
    "largestHeartbeatJumpMs": jump,
    "suspensionStartedBeforeDeadline": suspendedAt.map { $0 < deadline } as Any,
    "resumeAfterDeadline": resumeBoot.map { $0 >= deadline } as Any,
    "readEndedAfterResumeMs": afterResume as Any,
    "deadlineExpiredDuringSuspend": spanned,
    "verdict": verdict,
    "limits": ["Loopback socket pair in one process; no network interface or phone",
               "Read deadline only; the handshake shares the timer code but is capped at 60 s",
               "One suspend on this host and kernel; not a claim for other hardware or sleep states"],
]
let json = try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys])
print(String(decoding: json, as: UTF8.self))
if let outputPath {
    guard FileManager.default.createFile(atPath: outputPath, contents: json + Data("\n".utf8),
                                         attributes: [.posixPermissions: 0o644]) else { fail("Could not write \(outputPath).") }
}
exit(verdict == "passed" ? 0 : (verdict == "inconclusive" ? 3 : 1))
