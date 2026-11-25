import Darwin
import Foundation
import RemozioCore

@main
struct TransportMain {
    static func main() async {
        guard CommandLine.arguments.count == 3, ["--configuration", "--wake-configuration", "--remote-configuration", "--pairing-configuration", "--settings-host"].contains(CommandLine.arguments[1]) else {
            fail("Usage: RemozioTransport --configuration PATH or --wake-configuration PATH or --remote-configuration PATH or --pairing-configuration PATH or --settings-host PATH", code: EX_USAGE)
        }
        let termination: DaemonTermination
        do { termination = try DaemonTermination() }
        catch { fail("Transport could not install its termination handler.", code: EX_OSERR) }
        if CommandLine.arguments[1] == "--settings-host" {
            await settingsHost(path: CommandLine.arguments[2], termination: termination); return
        }
        let configuration: ApprovalTransportConfiguration
        let wake: TransportWakeStartupConfiguration?
        let relayPort: UInt16?
        let pairing: TransportPairingControlConfiguration?
        do {
            try termination.checkCancellation()
            if CommandLine.arguments[1] == "--pairing-configuration" {
                let value = try TransportPairingStartupConfiguration.load(path: CommandLine.arguments[2])
                configuration = value.transport; wake = value.wake; relayPort = value.relayPort; pairing = value.control
            } else if CommandLine.arguments[1] == "--remote-configuration" {
                let value = try TransportRemoteStartupConfiguration.load(path: CommandLine.arguments[2])
                configuration = value.transport; wake = value.wake; relayPort = value.relayPort; pairing = nil
            } else if CommandLine.arguments[1] == "--wake-configuration" {
                let value = try TransportWakeStartupConfiguration.load(path: CommandLine.arguments[2])
                configuration = value.transport; wake = value; relayPort = nil; pairing = nil
            } else {
                configuration = try ApprovalTransportConfiguration.load(path: CommandLine.arguments[2]); wake = nil; relayPort = nil; pairing = nil
            }
        }
        catch is CancellationError { exit(EX_OK) }
        catch { fail("Transport startup requires protected configuration and the configured service account.", code: EX_CONFIG) }
        let optionalWakePath = CommandLine.arguments[1] == "--pairing-configuration" && wake == nil ? CommandLine.arguments[2] : nil
        do {
            try await termination.run {
                try await run(configuration, wake: wake, relayPort: relayPort, pairing: pairing,
                              optionalWakePath: optionalWakePath, termination: termination)
            }
        } catch is CancellationError {
            exit(EX_OK)
        } catch ApprovalTransportStartupError.invalidIdentity {
            fail("Transport identity does not match its configured custody and installation pin.", code: EX_CONFIG)
        } catch {
            fail("Transport is unavailable. Restart requires fresh configuration and authority authentication.", code: EX_TEMPFAIL)
        }
    }

    private static func settingsHost(path: String, termination: DaemonTermination) async {
        let host: GatewaySettingsTransportHost
        do {
            try termination.checkCancellation()
            host = try .open(path: path, reportDirect: report, reportRelay: reportRelay, reportWake: reportWake)
        } catch is CancellationError { exit(EX_OK) }
        catch { fail("Transport control requires protected configuration, the dedicated account and the signed release.", code: EX_CONFIG) }
        var failed = false
        do {
            try await termination.run {
                try await host.start()
                while true {
                    try termination.checkCancellation()
                    try await host.poll()
                    try await Task.sleep(for: .milliseconds(250))
                }
            }
        } catch is CancellationError {} catch { failed = true }
        do { try await host.close() }
        catch { failed = true }
        if failed { fail("Transport control is unavailable. Restart requires fresh protected configuration and authority authentication.", code: EX_TEMPFAIL) }
        exit(EX_OK)
    }

    private static func run(_ configuration: ApprovalTransportConfiguration, wake: TransportWakeStartupConfiguration?, relayPort: UInt16?, pairing: TransportPairingControlConfiguration?, optionalWakePath: String?, termination: DaemonTermination) async throws {
        try termination.checkCancellation()
        let recovery: TransportWakeRunner?
        do {
            if let wake { recovery = try TransportWakeRunner(configuration: wake, report: reportWake) }
            else if let optionalWakePath { recovery = try TransportWakeRunner(pairingConfigurationPath: optionalWakePath, report: reportWake) }
            else { recovery = nil }
        } catch {
            log("Wake delivery is unavailable. Direct approvals remain available.")
            recovery = nil
        }
        let relay = try relayPort.map { port in
            try ApprovalRelayCoordinator(listenPort: port, maximumConnections: configuration.maximumConnections,
                timeoutMilliseconds: configuration.timeoutMilliseconds, report: reportRelay)
        }
        let identity = try ApprovalTransportIdentity.load(configuration: configuration)
        let pairingListener = try pairing.map {
            try TransportPairingXPCListener(configuration: $0, identity: identity, installedAuthority: configuration)
        }
        let service = try DirectApprovalTransportService(macID: configuration.macID, accountID: configuration.accountID,
            identity: identity, authorityServiceName: configuration.authorityServiceName, authorityPolicy: configuration.authorityPolicy,
            maximumConnections: configuration.maximumConnections, timeoutMilliseconds: configuration.timeoutMilliseconds,
            refreshMilliseconds: configuration.refreshMilliseconds, requestDeliveryTimeoutMilliseconds: configuration.timeoutMilliseconds,
            requestRefreshMilliseconds: configuration.refreshMilliseconds)
        do {
            try termination.checkCancellation()
            try await service.start()
            try termination.checkCancellation()
            try pairingListener?.start()
            try termination.checkCancellation()
            if let recovery {
                do { try await recovery.start() }
                catch is CancellationError { throw CancellationError() }
                catch {
                    await recovery.close()
                    log("Wake delivery is unavailable. Direct approvals remain available.")
                }
            }
            var previous: DirectHostState?
            while true {
                try termination.checkCancellation()
                let state = await service.state
                try termination.checkCancellation()
                if previous != state { report(state); previous = state }
                try await relay?.update(state)
                switch state {
                case .stopped, .authorityUnavailable, .failed: throw DirectHostError.authorityUnavailable
                case .noEligiblePhones, .starting, .ready: break
                }
                try await Task.sleep(for: .milliseconds(250))
            }
        } catch {
            await pairingListener?.closeAndWait()
            await relay?.close()
            await recovery?.close()
            await service.closeAndWait()
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }
    private static func reportRelay(_ status: ApprovalRelayCoordinator.Status) {
        switch status {
        case .ready: log("Local approval relay is ready.")
        case .failed: log("Local approval relay is unavailable. Retrying while direct approvals remain available.")
        default: break
        }
    }
    private static func reportWake(_ status: TransportWakeRunner.Status) {
        switch status {
        case .waiting(let milliseconds):
            log("Wake delivery is unavailable. Retrying in \(milliseconds) milliseconds. Direct approvals remain available.")
        case .failed:
            log("Wake delivery stopped. Direct approvals remain available.")
        default: break
        }
    }
    private static func report(_ state: DirectHostState) {
        switch state {
        case .noEligiblePhones: log("Transport is waiting for an eligible enrolled phone.")
        case .starting: log("Transport is starting.")
        case .ready: log("Transport is ready.")
        case .stopped, .authorityUnavailable, .failed: break
        }
    }
    private static func log(_ message: String) { FileHandle.standardError.write(Data((message + "\n").utf8)) }
    private static func fail(_ message: String, code: Int32) -> Never { log(message); exit(code) }
}
