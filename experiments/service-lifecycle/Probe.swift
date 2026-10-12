import Darwin
import Foundation
import os

@main struct ServiceLifecycleHelper {
    static func main() {
        #if SESSION_PROBE
        let role = ServiceProbeContract.Role.session
        #elseif AUTHORITY_PROBE
        let role = ServiceProbeContract.Role.authority
        #elseif TRANSPORT_PROBE
        let role = ServiceProbeContract.Role.transport
        #else
        #error("Select a probe role")
        #endif
        let args = Array(CommandLine.arguments.dropFirst())
        if args == ["--describe"] {
            let values = ["role": role.rawValue, "capability": "service-lifecycle-only"]
            let data = try! JSONSerialization.data(withJSONObject: values, options: [.sortedKeys])
            FileHandle.standardOutput.write(data + Data([10])); return
        }
        guard args == ["--service-probe"] else { exit(EX_UNAVAILABLE) }
        guard getuid() == geteuid(), role == .authority ? getuid() == 0 : getuid() != 0 else { exit(EX_NOPERM) }
        do {
            if role == .transport {
                let account = try ServiceProbeTransportAccount.resolve()
                guard account.uid == getuid(), account.gid == getgid(), getgid() == getegid() else { throw ServiceProbeError.account }
            }
            var bytes = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            guard proc_pidpath(getpid(), &bytes, UInt32(bytes.count)) > 0 else { throw ServiceProbeError.placement }
            guard let end = bytes.firstIndex(of: 0),
                  let path = String(bytes: bytes[..<end].map { UInt8(bitPattern: $0) }, encoding: .utf8) else {
                throw ServiceProbeError.placement
            }
            let executable = URL(fileURLWithPath: path)
            let app = executable.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            let placement = try ServiceProbePlacement(app: app)
            try ServiceProbeContract.validateManifests(app)
            try ServiceProbeContract.validateSigning(app, notarized: true)
            try placement.validate()
            let logger = Logger(subsystem: ServiceProbeContract.appID, category: "lifecycle")
            logger.notice("Started disposable role=\(role.rawValue, privacy: .public) uid=\(getuid()) euid=\(geteuid())")
            signal(SIGTERM, SIG_IGN)
            let stop = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
            stop.setEventHandler {
                logger.notice("Terminating disposable role=\(role.rawValue, privacy: .public)")
                exit(EX_OK)
            }
            withExtendedLifetime(placement) { stop.resume(); dispatchMain() }
        } catch { exit(EX_CONFIG) }
    }
}
