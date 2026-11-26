import Darwin
import Foundation
import RemozioCore

@main
struct AuthorityMain {
    private enum RunFailure: Error { case startup(AuthorityStartupFailure), retired, shutdown }
    static func main() async {
        guard CommandLine.arguments.count == 3,
              ["--configuration", "--presence-configuration", "--command-configuration"].contains(CommandLine.arguments[1]) else {
            fail("Usage: RemozioAuthority --configuration|--presence-configuration|--command-configuration /absolute/protected/configuration.cbor", code: EX_USAGE)
        }
        guard getuid() == 0, geteuid() == 0 else { fail("Authority startup requires the Root account.", code: EX_NOPERM) }
        let requestMode = CommandLine.arguments[1] != "--configuration", commandMode = CommandLine.arguments[1] == "--command-configuration", path = CommandLine.arguments[2]
        let termination: DaemonTermination
        do { termination = try DaemonTermination() }
        catch { fail("Authority could not install its termination handler.", code: EX_OSERR) }
        do {
            try await termination.run {
                if requestMode { try await runRequests(path: path, command: commandMode, termination: termination) }
                else { try await runLegacy(path: path, termination: termination) }
            }
        }
        catch is CancellationError { exit(EX_OK) }
        catch RunFailure.retired { fail("Authority service stopped after a runtime failure.", code: EX_SOFTWARE) }
        catch RunFailure.shutdown { fail("Authority shutdown failed.", code: EX_SOFTWARE) }
        catch RunFailure.startup(let failure) {
            switch failure {
            case .historyRecoveryRequired: fail("Authority starting: history recovery is pending.", code: EX_TEMPFAIL)
            case .repairRequired: fail("Authority continuity requires repair.", code: EX_CONFIG)
            case .temporaryStorageFailure: fail("Authority starting: storage is temporarily unavailable.", code: EX_TEMPFAIL)
            case .configurationFailure: fail("Authority startup failed. Check protected provisioning and configuration.", code: EX_CONFIG)
            }
        } catch { fail("Authority startup failed. Check protected provisioning and configuration.", code: EX_CONFIG) }
    }
    private static func runRequests(path: String, command: Bool, termination: DaemonTermination) async throws {
        let runner = try command
            ? AuthorityRuntimeRunner(installedCommandConfigurationPath: path, report: reportRuntime)
            : AuthorityRuntimeRunner(presenceConfigurationPath: path, report: reportRuntime)
        do {
            try termination.checkCancellation()
            switch try await runner.runUntilExit() {
            case .failed(let failure): throw RunFailure.startup(failure)
            case .retired: throw RunFailure.retired
            case .shutdownFailed: throw RunFailure.shutdown
            case .closed: return
            default: throw RunFailure.shutdown
            }
        } catch {
            let failure = error
            do {
                if failure is CancellationError { try await runner.closeForTermination() } else { try await runner.close() }
            } catch { throw RunFailure.shutdown }
            throw failure
        }
    }
    private static func runLegacy(path: String, termination: DaemonTermination) async throws {
        let runner = try AuthorityServiceRunner(configurationPath: path, report: report)
        do {
            try termination.checkCancellation()
            try runner.start()
            while true { try termination.checkCancellation(); try await Task.sleep(for: .milliseconds(250)) }
        } catch {
            let failure = error
            do { try runner.close() } catch { throw RunFailure.shutdown }
            throw failure
        }
    }
    private static func reportRuntime(_ status: AuthorityRuntimeRunner.Status) {
        switch status {
        case .running: log("Authority request service started. Wake publication connects separately.")
        case .waiting(let milliseconds): log("Authority starting: storage is temporarily unavailable. Retrying in \(milliseconds) milliseconds.")
        default: break
        }
    }
    private static func report(_ status: AuthorityServiceRunner.Status) {
        // Startup inputs can contain private identifiers. Do not print them or storage paths.
        switch status {
        case .idle, .starting, .closed: break
        case .running:
            log("Authority trust service started.")
        case .retired:
            fail("Authority service stopped after a maintenance failure.", code: EX_SOFTWARE)
        case .waiting(let milliseconds):
            log("Authority starting: storage is temporarily unavailable. Retrying in \(milliseconds) milliseconds.")
        case .failed(.historyRecoveryRequired):
            fail("Authority starting: history recovery is pending.", code: EX_TEMPFAIL)
        case .failed(.repairRequired):
            fail("Authority continuity requires repair.", code: EX_CONFIG)
        case .failed(.temporaryStorageFailure):
            fail("Authority starting: storage is temporarily unavailable.", code: EX_TEMPFAIL)
        case .failed(.configurationFailure):
            fail("Authority startup failed. Check protected provisioning and configuration.", code: EX_CONFIG)
        }
    }
    private static func log(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
    private static func fail(_ message: String, code: Int32) -> Never {
        log(message)
        exit(code)
    }
}
