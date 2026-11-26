import Darwin
import Foundation
import RemozioCore

@main
struct GatewayMain {
    static func main() async {
        guard CommandLine.arguments.count == 3,
              ["--configuration", "--journal-setup", "--settings-host"].contains(CommandLine.arguments[1]) else {
            fail("Usage: RemozioGateway --configuration /absolute/protected/gateway.cbor | --journal-setup /absolute/protected/setup-service.cbor | --settings-host /absolute/protected/settings-host.cbor", code: EX_USAGE)
        }
        let termination: DaemonTermination
        do { termination = try DaemonTermination() }
        catch { fail("Gateway could not install its termination handler.", code: EX_OSERR) }
        if CommandLine.arguments[1] == "--journal-setup" {
            await journalSetup(path: CommandLine.arguments[2], termination: termination)
        }
        if CommandLine.arguments[1] == "--settings-host" {
            await settingsHost(path: CommandLine.arguments[2], termination: termination)
        }
        let configuration: GatewayServiceConfiguration
        do {
            try termination.checkCancellation()
            configuration = try GatewayServiceConfiguration.load(path: CommandLine.arguments[2])
        } catch is CancellationError { exit(EX_OK) }
        catch { fail("Gateway startup requires protected configuration and the configured service account.", code: EX_CONFIG) }
        do { try await termination.run { try await run(configuration, termination: termination) } }
        catch is CancellationError { exit(EX_OK) }
        catch { fail("Gateway is unavailable. Restart requires fresh configuration and Root authentication.", code: EX_TEMPFAIL) }
    }
    private static func run(_ configuration: GatewayServiceConfiguration, termination: DaemonTermination) async throws {
        let service = try await GatewayService.open(configuration: configuration)
        do {
            try termination.checkCancellation()
            try service.start()
            FileHandle.standardError.write(Data("Gateway is waiting for authenticated Root state.\n".utf8))
            while !service.isRetired {
                try termination.checkCancellation()
                try await Task.sleep(for: .milliseconds(250))
            }
            throw GatewayServiceError.unavailable
        } catch {
            let failure = error
            try await service.close()
            if Task.isCancelled { throw CancellationError() }
            throw failure
        }
    }
    private static func settingsHost(path: String, termination: DaemonTermination) async -> Never {
        let host: GatewaySettingsGatewayHost
        do {
            try termination.checkCancellation()
            host = try .open(path: path)
        } catch is CancellationError { exit(EX_OK) }
        catch { fail("Gateway settings control requires protected bootstrap metadata and its dedicated account.", code: EX_CONFIG) }
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
        catch { fail("Gateway settings control could not drain. Check protected setup progress before restarting.", code: EX_TEMPFAIL) }
        if failed { fail("Gateway settings control is unavailable. Check protected bootstrap metadata before restarting.", code: EX_TEMPFAIL) }
        exit(EX_OK)
    }
    private static func journalSetup(path: String, termination: DaemonTermination) async -> Never {
        let service: GatewayJournalSetupService
        do {
            try termination.checkCancellation()
            service = try GatewayJournalSetupService.open(path: path)
        } catch is CancellationError { exit(EX_OK) }
        catch { fail("Gateway journal setup requires protected metadata and the configured service account.", code: EX_CONFIG) }
        var failed = false
        do {
            try await termination.run {
                try service.start()
                while !service.isRetired {
                    try termination.checkCancellation()
                    try await Task.sleep(for: .milliseconds(250))
                }
            }
        } catch is CancellationError {} catch { failed = true }
        // Drain from this uncancelled owner, after the listener task has stopped accepting work.
        do { try await service.close() }
        catch { fail("Gateway journal setup could not stop cleanly. Check protected setup progress before retrying.", code: EX_TEMPFAIL) }
        if failed { fail("Gateway journal setup is unavailable. Check protected setup progress before retrying.", code: EX_TEMPFAIL) }
        exit(EX_OK)
    }
    private static func fail(_ message: String, code: Int32) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8)); exit(code)
    }
}
