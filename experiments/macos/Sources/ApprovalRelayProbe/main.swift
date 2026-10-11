import Darwin
import Foundation
import RemozioCore

/// Disposable loopback carrier probe. It does not load keys, register services, or authenticate a production request.
@main
struct ApprovalRelayProbe {
    static func main() async throws {
        guard [3, 5].contains(CommandLine.arguments.count), CommandLine.arguments[1] == "--target-port",
              let port = UInt16(CommandLine.arguments[2]), port > 0 else { exit(EX_USAGE) }
        let timeout: UInt64
        if CommandLine.arguments.count == 5 {
            guard CommandLine.arguments[3] == "--timeout-ms", let value = UInt64(CommandLine.arguments[4]),
                  (100...15_000).contains(value) else { exit(EX_USAGE) }
            timeout = value
        } else { timeout = 15_000 }
        let lifetime = Task { try await Task.sleep(for: .seconds(20)) }
        let relay = try ApprovalWebSocketRelay(listenPort: 0, targetPort: port, maximumConnections: 1, timeoutMilliseconds: timeout) { event in
            switch event {
            case .ready(let port):
                let bytes = try! JSONSerialization.data(withJSONObject: ["schemaVersion": 1, "port": Int(port)])
                FileHandle.standardOutput.write(bytes + Data([10]))
            case .failed: lifetime.cancel()
            case .stopped: break
            }
        }
        signal(SIGTERM, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        termination.setEventHandler { lifetime.cancel() }; termination.resume()
        defer { termination.cancel() }
        try relay.start()
        _ = try? await lifetime.value
        await relay.closeAndWait()
    }
}
