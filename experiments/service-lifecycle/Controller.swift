import Darwin
import Foundation
import ServiceManagement

@main struct ServiceLifecycleController {
    @MainActor static func service(_ role: ServiceProbeContract.Role) -> SMAppService {
        if role == .session { return .agent(plistName: role.label + ".plist") }
        return .daemon(plistName: role.label + ".plist")
    }
    static func statusName(_ status: SMAppService.Status) -> String {
        switch status {
        case .notRegistered: "notRegistered"
        case .enabled: "eligibleNotVerifiedRunning"
        case .requiresApproval: "requiresSystemApproval"
        case .notFound: "notFound"
        @unknown default: "unknown"
        }
    }
    @MainActor static func main() async {
        do {
            let args = Array(CommandLine.arguments.dropFirst()), app = Bundle.main.bundleURL
            if args == ["--status"] {
                try emit(["experiment": "service-lifecycle", "operationsAttempted": false,
                    "session": statusName(service(.session).status), "authority": statusName(service(.authority).status), "transport": statusName(service(.transport).status)])
                return
            }
            if args == ["--validate-manifests"] {
                try ServiceProbeContract.validateManifests(app)
                try emit(["experiment": "service-lifecycle", "operationsAttempted": false, "manifest": "passed"])
                return
            }
            if args == ["--validate-publisher"] {
                try ServiceProbeContract.validateSigning(app, notarized: false)
                try emit(["experiment": "service-lifecycle", "operationsAttempted": false, "publisher": "passed"])
                return
            }
            if args == ["--validate-signing"] {
                try ServiceProbeContract.validateSigning(app, notarized: true)
                try emit(["experiment": "service-lifecycle", "operationsAttempted": false, "signing": "passed"])
                return
            }
            if args == ["--preflight"] {
                try validate(app)
                try emit(["experiment": "service-lifecycle", "operationsAttempted": false, "preflight": "passed"])
                return
            }
            guard args.count == 3, args[2] == "--confirm-disposable-service-test",
                  let role = ServiceProbeContract.Role(rawValue: args[1]), ["--register", "--unregister"].contains(args[0]),
                  getuid() != 0, getuid() == geteuid() else { throw ServiceProbeError.arguments }
            if args[0] == "--register" {
                let transport = role == .transport ? try ServiceProbeTransportAccount.resolve(invokingUID: getuid()) : nil
                let placement = try validate(app)
                defer { placement.close() }
                try placement.validate()
                try transport?.revalidate(invokingUID: getuid())
                try service(role).register()
            } else {
                // Removal remains reachable after the bundle moves. It still requires the approved test publisher.
                try ServiceProbeContract.validateSigning(app, notarized: false)
                try ServiceProbeContract.validateManifests(app)
                try await service(role).unregister()
            }
            try emit(["experiment": "service-lifecycle", "operationsAttempted": true, "role": role.rawValue,
                "operation": args[0], "status": statusName(service(role).status), "runningVerified": false])
        } catch {
            // Do not disclose signing data, account names or filesystem paths from system errors.
            fputs("Service lifecycle probe refused or failed. No success is claimed.\n", stderr)
            exit(EX_CONFIG)
        }
    }
    @discardableResult static func validate(_ app: URL) throws -> ServiceProbePlacement {
        guard getuid() != 0, getuid() == geteuid() else { throw ServiceProbeError.account }
        let placement = try ServiceProbePlacement(app: app)
        try ServiceProbeContract.validateManifests(app)
        try ServiceProbeContract.validateSigning(app, notarized: true)
        try placement.validate()
        return placement
    }
    static func emit(_ values: [String: Any]) throws {
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: values, options: [.sortedKeys]) + Data([10]))
    }
}
