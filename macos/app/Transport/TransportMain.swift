import Darwin
import Foundation
import RemozioCore

@main
struct TransportMain {
    static func main() async {
        guard CommandLine.arguments.count == 3, ["--configuration", "--wake-configuration"].contains(CommandLine.arguments[1]) else {
            fail("Usage: RemozioTransport --configuration PATH or --wake-configuration PATH", code: EX_USAGE)
        }
        let configuration: ApprovalTransportConfiguration
        let wake: TransportWakeStartupConfiguration?
        do {
            if CommandLine.arguments[1] == "--wake-configuration" {
                let value = try TransportWakeStartupConfiguration.load(path: CommandLine.arguments[2])
                configuration = value.transport; wake = value
            } else {
                configuration = try ApprovalTransportConfiguration.load(path: CommandLine.arguments[2]); wake = nil
            }
        }
        catch { fail("Transport startup requires protected configuration and the configured service account.", code: EX_CONFIG) }
        let task = Task { try await run(configuration, wake: wake) }
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

    private static func run(_ configuration: ApprovalTransportConfiguration, wake: TransportWakeStartupConfiguration?) async throws {
        try Task.checkCancellation()
        let recovery: TransportWakeRunner?
        if let wake {
            do { recovery = try TransportWakeRunner(configuration: wake, report: reportWake) }
            catch {
                log("Wake delivery is unavailable. Direct approvals remain available.")
                recovery = nil
            }
        } else { recovery = nil }
        let identity = try ApprovalTransportIdentity.load(configuration: configuration)
        let service = try DirectApprovalTransportService(macID: configuration.macID, accountID: configuration.accountID,
            identity: identity, authorityServiceName: configuration.authorityServiceName, authorityPolicy: configuration.authorityPolicy,
            maximumConnections: configuration.maximumConnections, timeoutMilliseconds: configuration.timeoutMilliseconds,
            refreshMilliseconds: configuration.refreshMilliseconds, requestDeliveryTimeoutMilliseconds: configuration.timeoutMilliseconds,
            requestRefreshMilliseconds: configuration.refreshMilliseconds)
        do {
            try await service.start()
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
                switch state {
                case .stopped, .authorityUnavailable, .failed: throw DirectHostError.authorityUnavailable
                case .noEligiblePhones, .starting, .ready: break
                }
                try await Task.sleep(for: .milliseconds(250))
            }
        } catch {
            await recovery?.close()
            await service.close()
            if Task.isCancelled { throw CancellationError() }
            throw error
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
