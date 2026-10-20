import Darwin
import Foundation
import RemozioCore

@main
struct TransportMain {
    static func main() async {
        guard CommandLine.arguments.count == 3, ["--configuration", "--wake-configuration", "--remote-configuration", "--pairing-configuration", "--settings-host"].contains(CommandLine.arguments[1]) else {
            fail("Usage: RemozioTransport --configuration PATH or --wake-configuration PATH or --remote-configuration PATH or --pairing-configuration PATH or --settings-host PATH", code: EX_USAGE)
        }
        if CommandLine.arguments[1] == "--settings-host" {
            await settingsHost(path: CommandLine.arguments[2]); return
        }
        let configuration: ApprovalTransportConfiguration
        let wake: TransportWakeStartupConfiguration?
        let relayPort: UInt16?
        let pairing: TransportPairingControlConfiguration?
        do {
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
        catch { fail("Transport startup requires protected configuration and the configured service account.", code: EX_CONFIG) }
        let optionalWakePath = CommandLine.arguments[1] == "--pairing-configuration" && wake == nil ? CommandLine.arguments[2] : nil
        let task = Task { try await run(configuration, wake: wake, relayPort: relayPort, pairing: pairing, optionalWakePath: optionalWakePath) }
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        termination.setEventHandler { task.cancel() }; interruption.setEventHandler { task.cancel() }
        termination.resume(); interruption.resume()
        defer { termination.cancel(); interruption.cancel() }
        do {
            try await task.value
        } catch is CancellationError {
            exit(EX_OK)
        } catch ApprovalTransportStartupError.invalidIdentity {
            fail("Transport identity does not match its configured custody and installation pin.", code: EX_CONFIG)
        } catch {
            fail("Transport is unavailable. Restart requires fresh configuration and authority authentication.", code: EX_TEMPFAIL)
        }
    }

    private static func settingsHost(path: String) async {
        let host: GatewaySettingsTransportHost
        do { host = try .open(path: path, reportDirect: report, reportRelay: reportRelay, reportWake: reportWake) }
        catch { fail("Transport control requires protected configuration, the dedicated account and the signed release.", code: EX_CONFIG) }
        let task = Task {
            do {
                try await host.start()
                while true { try Task.checkCancellation(); try await host.poll(); try await Task.sleep(for: .milliseconds(250)) }
            } catch {
                let failure = error, cleanup = Task { try await host.close() }
                try await cleanup.value; throw failure
            }
        }
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        termination.setEventHandler { task.cancel() }; interruption.setEventHandler { task.cancel() }
        termination.resume(); interruption.resume()
        defer { termination.cancel(); interruption.cancel() }
        do { try await task.value }
        catch is CancellationError { exit(EX_OK) }
        catch { fail("Transport control is unavailable. Restart requires fresh protected configuration and authority authentication.", code: EX_TEMPFAIL) }
    }

    private static func run(_ configuration: ApprovalTransportConfiguration, wake: TransportWakeStartupConfiguration?, relayPort: UInt16?, pairing: TransportPairingControlConfiguration?, optionalWakePath: String?) async throws {
        try Task.checkCancellation()
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
        let pairingListener = try pairing.map { try TransportPairingXPCListener(configuration: $0, identity: identity) }
        let service = try DirectApprovalTransportService(macID: configuration.macID, accountID: configuration.accountID,
            identity: identity, authorityServiceName: configuration.authorityServiceName, authorityPolicy: configuration.authorityPolicy,
            maximumConnections: configuration.maximumConnections, timeoutMilliseconds: configuration.timeoutMilliseconds,
            refreshMilliseconds: configuration.refreshMilliseconds, requestDeliveryTimeoutMilliseconds: configuration.timeoutMilliseconds,
            requestRefreshMilliseconds: configuration.refreshMilliseconds)
        do {
            try await service.start()
            try pairingListener?.start()
            if let recovery {
                do { try await recovery.start() }
                catch {
                    await recovery.close()
                    log("Wake delivery is unavailable. Direct approvals remain available.")
                }
            }
            var previous: DirectHostState?
            while true {
                try Task.checkCancellation()
                let state = await service.state
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
