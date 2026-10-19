import Darwin
import Foundation
import RemozioCore

@main
struct GatewayMain {
    static func main() async {
        if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--journal-setup" {
            await journalSetup(path: CommandLine.arguments[2])
        }
        if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--settings-host" {
            await settingsHost(path: CommandLine.arguments[2])
        }
        guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--configuration" else {
            fail("Usage: RemozioGateway --configuration /absolute/protected/gateway.cbor | --journal-setup /absolute/protected/setup-service.cbor | --settings-host /absolute/protected/settings-host.cbor", code: EX_USAGE)
        }
        let configuration: GatewayServiceConfiguration
        do { configuration = try GatewayServiceConfiguration.load(path: CommandLine.arguments[2]) }
        catch { fail("Gateway startup requires protected configuration and the configured service account.", code: EX_CONFIG) }
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let task = Task { try await run(configuration) }
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        termination.setEventHandler { task.cancel() }; interruption.setEventHandler { task.cancel() }
        termination.resume(); interruption.resume()
        defer { termination.cancel(); interruption.cancel() }
        do { try await task.value }
        catch is CancellationError { exit(EX_OK) }
        catch { fail("Gateway is unavailable. Restart requires fresh configuration and Root authentication.", code: EX_TEMPFAIL) }
    }
    private static func run(_ configuration: GatewayServiceConfiguration) async throws {
        let service = try await GatewayService.open(configuration: configuration)
        do {
            try Task.checkCancellation()
            try service.start()
            FileHandle.standardError.write(Data("Gateway is waiting for authenticated Root state.\n".utf8))
            while !service.isRetired {
                try Task.checkCancellation()
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
    private static func settingsHost(path: String) async -> Never {
        let host: GatewaySettingsGatewayHost
        do { host = try .open(path: path) }
        catch { fail("Gateway settings control requires protected bootstrap metadata and its dedicated account.", code: EX_CONFIG) }
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let task = Task {
            try await host.start()
            while true {
                try Task.checkCancellation(); try await host.poll()
                try await Task.sleep(for: .milliseconds(250))
            }
        }
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        termination.setEventHandler { task.cancel() }; interruption.setEventHandler { task.cancel() }
        termination.resume(); interruption.resume()
        defer { termination.cancel(); interruption.cancel() }
        var failed = false
        do { try await task.value } catch is CancellationError {} catch { failed = true }
        do { try await host.close() }
        catch { fail("Gateway settings control could not drain. Check protected setup progress before restarting.", code: EX_TEMPFAIL) }
        if failed { fail("Gateway settings control is unavailable. Check protected bootstrap metadata before restarting.", code: EX_TEMPFAIL) }
        exit(EX_OK)
    }
    private static func journalSetup(path: String) async -> Never {
        let service: GatewayJournalSetupService
        do { service = try GatewayJournalSetupService.open(path: path) }
        catch { fail("Gateway journal setup requires protected metadata and the configured service account.", code: EX_CONFIG) }
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let task = Task {
            try service.start()
            while !service.isRetired {
                try Task.checkCancellation()
                try await Task.sleep(for: .milliseconds(250))
            }
        }
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        termination.setEventHandler { task.cancel() }; interruption.setEventHandler { task.cancel() }
        termination.resume(); interruption.resume()
        defer { termination.cancel(); interruption.cancel() }
        var failed = false
        do { try await task.value } catch is CancellationError {} catch { failed = true }
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
