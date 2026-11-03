#if os(Linux)
import Glibc
#endif
import CPairingTLS
import Foundation
import LinuxPairAuthority
import PairingCommitState
import RemozioProtocol

// A foreground software-key pairing experiment. Not the protected host service, and never installed as one.

let banner = "EXPERIMENT: software keys. Not the protected host service."
let usage = """
    usage: remozio-linux-pair [--state-dir DIR] <command>
      init [--label LABEL]   create the identity once
      invite                 print the invitation (and a QR code when qrencode is installed)
      pair [--listen ADDRESS:PORT] [--no-advertise]
                             accept one phone, compare codes, commit and send the receipt
      list                   show enrolled phones
    """

struct UsageError: Error { let message: String }

setvbuf(stdout, nil, _IOLBF, 0)
print(banner)
do {
    exit(try run(Array(CommandLine.arguments.dropFirst())))
} catch let error as UsageError {
    FileHandle.standardError.write(Data("\(error.message)\n\(usage)\n".utf8))
    exit(2)
} catch {
    FileHandle.standardError.write(Data("error: \(describe(error))\n".utf8))
    exit(1)
}

func run(_ arguments: [String]) throws -> Int32 {
    var arguments = arguments
    var stateDirectory: String?
    if arguments.first == "--state-dir" {
        guard arguments.count >= 2 else { throw UsageError(message: "--state-dir needs a path") }
        stateDirectory = arguments[1]
        arguments.removeFirst(2)
    }
    guard let command = arguments.first else { throw UsageError(message: "missing command") }
    let options = Array(arguments.dropFirst())
    let store = PairingCommitStore(directory: try stateURL(stateDirectory))
    switch command {
    case "init":
        var label = ProcessInfo.processInfo.hostName
        switch options.count {
        case 0: break
        case 2 where options[0] == "--label": label = options[1]
        default: throw UsageError(message: "init takes only --label LABEL")
        }
        let identity = try PairingIdentity.create(in: store, label: label)
        print("Created the identity for \"\(identity.label)\".")
        try printInvitation(identity)
        return 0
    case "invite":
        guard options.isEmpty else { throw UsageError(message: "invite takes no options") }
        try printInvitation(PairingIdentity.load(from: store))
        return 0
    case "list":
        guard options.isEmpty else { throw UsageError(message: "list takes no options") }
        _ = try PairingIdentity.load(from: store)
        let enrollments = try store.list()
        print("Enrolled phones: \(enrollments.count)")
        for item in enrollments {
            print("phone \(hex(item.phoneID)) epoch \(hex(item.epoch)) setup \(hex(item.setupID))")
        }
        return 0
    case "pair":
        var listen = "0.0.0.0:0"
        var advertise = true
        var rest = options[...]
        while let option = rest.popFirst() {
            switch option {
            case "--listen":
                guard let value = rest.popFirst() else { throw UsageError(message: "--listen needs ADDRESS:PORT") }
                listen = value
            case "--no-advertise": advertise = false
            default: throw UsageError(message: "unknown pair option \(option)")
            }
        }
        return try pair(identity: PairingIdentity.load(from: store), store: store, listen: listen, advertise: advertise)
    default:
        throw UsageError(message: "unknown command \(command)")
    }
}

/// `--state-dir`, else `$XDG_STATE_HOME/remozio-linux-pair`, else `~/.local/state/remozio-linux-pair`. Missing parents
/// are created private; the store itself refuses a directory that is not owned or not private.
func stateURL(_ explicit: String?) throws -> URL {
    let path: String
    if let explicit { path = explicit }
    else if let base = ProcessInfo.processInfo.environment["XDG_STATE_HOME"], base.hasPrefix("/") {
        path = base + "/remozio-linux-pair"
    } else {
        guard let home = ProcessInfo.processInfo.environment["HOME"], home.hasPrefix("/") else {
            throw UsageError(message: "set HOME, XDG_STATE_HOME or --state-dir")
        }
        path = home + "/.local/state/remozio-linux-pair"
    }
    let url = URL(fileURLWithPath: path).standardizedFileURL
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    return url
}

func printInvitation(_ identity: PairingIdentity) throws {
    let invitation = try identity.invitation()
    let text = try invitation.exportText()
    print("Label: \(invitation.label)")
    print("Fingerprint: \(try invitation.fingerprint())")
    print("Invitation:")
    print(text)
    if let qrencode = executable("qrencode") {
        let process = Process()
        process.executableURL = qrencode
        process.arguments = ["-t", "ANSIUTF8", text]
        try process.run()
        process.waitUntilExit()
    } else {
        print("(Install qrencode to show this invitation as a QR code.)")
    }
}

// MARK: pair

func pair(identity: PairingIdentity, store: PairingCommitStore, listen: String, advertise: Bool) throws -> Int32 {
    let (address, port) = try parseListen(listen)
    let listener = try Listener(address: address, port: port)
    defer { listener.close() }
    let loopback = address.s_addr == in_addr_t(0x7f00_0001).bigEndian
    print("Listening on \(listen.split(separator: ":").dropLast().joined(separator: ":")):\(listener.port)")
    var publisher: ServicePublisher?
    if loopback {
        print("Loopback address: not advertised.")
    } else if advertise {
        publisher = try ServicePublisher(name: identity.serviceName, port: listener.port)
        print("Advertised as \(identity.serviceName) (\(PairingIdentity.serviceType)).")
    } else {
        print("Not advertised: phones that rely on discovery will not find this address.")
    }
    defer { publisher?.stop() }
    let server = try TLSPairingServer(identity: identity, nowUnixSeconds: Int64(Date().timeIntervalSince1970),
                                      lifetimeSeconds: 86_400)
    let console = StandardInputConsole()
    print("Waiting for a phone. Press Ctrl-C to stop.")
    while true {
        let fd = try listener.accept()
        let accepted = remozio_tls_now_ms()
        let stream: TLSPairingStream, point: Data
        do {
            (stream, point) = try server.accept(fd: fd, deadline: accepted + PairingAuthoritySession.maximumLimitMilliseconds)
        } catch {
            print("Refused a connection: \(describe(error))")
            continue
        }
        defer { stream.close() }
        let session = PairingAuthoritySession(identity: identity, store: store, stream: stream, peerPoint: point,
                                              console: console, now: { remozio_tls_now_ms() })
        do {
            switch try session.run() {
            case .enrolled(let setupID, let phoneID):
                print("Enrolled phone \(hex(phoneID)) (setup \(hex(setupID))). Receipt sent.")
                return 0
            case .enrolledReceiptUndelivered(let setupID, let phoneID, let reason):
                print("Enrolled phone \(hex(phoneID)) (setup \(hex(setupID))), but the receipt was not delivered: \(reason).")
                print("Not retried. The phone keeps the setup pending; `list` shows the enrollment.")
                return 3
            case .enrolledStateUnknown(let setupID, let error):
                print("Enrolled state unknown for setup \(hex(setupID)): \(error). No receipt sent; not retried.")
                return 4
            }
        } catch {
            print("Setup failed: \(describe(error.error)).")
            // A candidate that never saw a transcript never reached the operator; keep waiting for the right phone.
            guard error.transcriptSent else { continue }
            print("Nothing was enrolled.")
            return 1
        }
    }
}

func parseListen(_ value: String) throws -> (in_addr, UInt16) {
    let parts = value.split(separator: ":", omittingEmptySubsequences: false)
    guard parts.count == 2, let port = UInt16(parts[1]) else { throw UsageError(message: "--listen takes IPV4:PORT") }
    var address = in_addr()
    guard inet_pton(AF_INET, String(parts[0]), &address) == 1 else { throw UsageError(message: "--listen takes IPV4:PORT") }
    return (address, port)
}

final class Listener {
    let fd: Int32
    let port: UInt16

    init(address: in_addr, port: UInt16) throws {
        let socketFD = socket(AF_INET, Int32(SOCK_STREAM.rawValue) | Int32(SOCK_CLOEXEC.rawValue), 0)
        guard socketFD >= 0 else { throw SystemError(operation: "socket", code: errno) }
        var reuse: Int32 = 1
        setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var socketAddress = sockaddr_in()
        socketAddress.sin_family = sa_family_t(AF_INET)
        socketAddress.sin_port = port.bigEndian
        socketAddress.sin_addr = address
        let bound = withUnsafePointer(to: &socketAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0, Glibc.listen(socketFD, 4) == 0 else {
            let code = errno; Glibc.close(socketFD); throw SystemError(operation: "bind", code: code)
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &socketAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(socketFD, $0, &length) }
        }
        guard named == 0 else { let code = errno; Glibc.close(socketFD); throw SystemError(operation: "getsockname", code: code) }
        fd = socketFD
        self.port = UInt16(bigEndian: socketAddress.sin_port)
    }

    func accept() throws -> Int32 {
        while true {
            let client = Glibc.accept(fd, nil, nil)
            if client >= 0 { _ = fcntl(client, F_SETFD, FD_CLOEXEC); return client }
            guard errno == EINTR || errno == ECONNABORTED else { throw SystemError(operation: "accept", code: errno) }
        }
    }

    func close() { Glibc.close(fd) }
}

/// Holds `avahi-publish` for the life of `pair`. avahi renames a service after a name collision; the Android client
/// looks for the exact name, so a rename withdraws the advertisement instead.
final class ServicePublisher {
    private let process = Process()

    init(name: String, port: UInt16) throws {
        guard let avahi = executable("avahi-publish") else {
            throw UsageError(message: "avahi-publish was not found. Install avahi-utils (with avahi-daemon running), "
                + "or pass --no-advertise and give the phone this address another way.")
        }
        let errors = Pipe()
        process.executableURL = avahi
        process.arguments = ["-s", name, PairingIdentity.serviceType, String(port)]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errors
        try process.run()
        let reader = errors.fileHandleForReading
        let deadline = remozio_tls_now_ms() + 10_000
        var text = ""
        while true {
            if text.contains("Established under name '\(name)'") { break }
            if text.lowercased().contains("collision") || text.contains("Failed") || !process.isRunning {
                stop()
                throw SystemError(operation: "avahi-publish: \(text.trimmingCharacters(in: .whitespacesAndNewlines))", code: 0)
            }
            var poller = pollfd(fd: reader.fileDescriptor, events: Int16(POLLIN), revents: 0)
            let remaining = deadline - remozio_tls_now_ms()
            guard remaining > 0 else { stop(); throw SystemError(operation: "avahi-publish did not confirm the service", code: ETIMEDOUT) }
            guard poll(&poller, 1, Int32(min(remaining, 1000))) >= 0 || errno == EINTR else {
                stop(); throw SystemError(operation: "poll", code: errno)
            }
            if poller.revents != 0 {
                let chunk = reader.availableData
                if chunk.isEmpty, !process.isRunning { continue }
                text += String(decoding: chunk, as: UTF8.self)
            }
        }
        let process = self.process
        Thread.detachNewThread {
            // A later collision would rename the service. Withdraw it and say so.
            while true {
                let chunk = reader.availableData
                if chunk.isEmpty { return }
                if String(decoding: chunk, as: UTF8.self).lowercased().contains("collision") {
                    process.terminate()
                    print("Advertisement withdrawn after a name collision. Restart pair to advertise again.")
                    return
                }
            }
        }
    }

    func stop() {
        if process.isRunning { process.terminate(); process.waitUntilExit() }
    }
}

/// Reads the operator's line from standard input with a `CLOCK_BOOTTIME` deadline.
final class StandardInputConsole: PairingOperatorConsole {
    func show(_ line: String) { print(line) }

    func discardPendingInput() {
        if isatty(0) == 1 { tcflush(0, TCIFLUSH); return }
        var poller = pollfd(fd: 0, events: Int16(POLLIN), revents: 0)
        var buffer = [UInt8](repeating: 0, count: 256)
        while poll(&poller, 1, 0) > 0, poller.revents & Int16(POLLIN) != 0 {
            if read(0, &buffer, buffer.count) <= 0 { return }
        }
    }

    func readLine(deadline: Int64) throws -> String? {
        var line = [UInt8]()
        var byte: UInt8 = 0
        while true {
            let remaining = deadline - remozio_tls_now_ms()
            guard remaining > 0 else { throw PairingSessionError.expired }
            var poller = pollfd(fd: 0, events: Int16(POLLIN), revents: 0)
            let ready = poll(&poller, 1, Int32(min(remaining, 1000)))
            if ready < 0, errno == EINTR { continue }
            guard ready >= 0 else { throw SystemError(operation: "poll", code: errno) }
            if ready == 0 { continue }
            let count = read(0, &byte, 1)
            if count < 0, errno == EINTR { continue }
            if count <= 0 { return line.isEmpty ? nil : String(decoding: line, as: UTF8.self) }
            if byte == 10 { return String(decoding: line, as: UTF8.self) }
            // A code is 20 symbols; a much longer line cannot match and is cut off here.
            if line.count < 256 { line.append(byte) }
        }
    }
}

struct SystemError: Error, CustomStringConvertible {
    let operation: String
    let code: Int32
    var description: String { code == 0 ? operation : "\(operation): \(String(cString: strerror(code)))" }
}

func executable(_ name: String) -> URL? {
    for directory in (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":") where directory.hasPrefix("/") {
        let path = "\(directory)/\(name)"
        if access(path, X_OK) == 0 { return URL(fileURLWithPath: path) }
    }
    return nil
}

func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

func describe(_ error: Error) -> String {
    switch error {
    case PairingIdentityError.notInitialized: return "no identity yet; run init first"
    case PairingCommitError.identityExists: return "an identity already exists; init never replaces it"
    case PairingCommitError.unsafeDirectory: return "the state directory is not a private directory owned by this user"
    case PairingIdentityError.invalidLabel: return "the label is not a valid invitation label"
    default: return String(describing: error)
    }
}
