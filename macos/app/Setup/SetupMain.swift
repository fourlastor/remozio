import Darwin
import Foundation
import RemozioCore

@main
struct SetupMain {
    static func main() async {
        guard CommandLine.arguments.count == 3,
              ["--configuration", "--bootstrap-installation", "--prepare-package", "--inspect-package", "--ensure-app-entry"].contains(CommandLine.arguments[1]) else {
            fail("Usage: RemozioSetup --configuration /absolute/protected/setup.cbor | --bootstrap-installation PUBLISHER_TEAM_ID | --prepare-package|--inspect-package|--ensure-app-entry PINNED_PROFILE", code: EX_USAGE)
        }
        guard getuid() == 0, geteuid() == 0 else { fail("Setup startup requires the Root account.", code: EX_NOPERM) }
        if ["--prepare-package", "--inspect-package", "--ensure-app-entry"].contains(CommandLine.arguments[1]) {
            do {
                let profile = try PackageBootstrapProfile(argument: CommandLine.arguments[2])
                switch CommandLine.arguments[1] {
                case "--prepare-package": try PackageBootstrap.preparePayload(profile)
                case "--inspect-package": print(try PackageBootstrap.inspectInstalled(profile).rawValue)
                default: try PackageBootstrap.ensureApplicationEntry(profile)
                }
                return
            } catch { fail("Package preparation refused or failed. Existing code and setup state were not replaced.", code: EX_CONFIG) }
        }
        if CommandLine.arguments[1] == "--bootstrap-installation" {
            do {
                _ = try MachineBootstrap.run(teamID: CommandLine.arguments[2])
                FileHandle.standardError.write(Data("Machine bootstrap prepared. Account enrollment and service registration remain separate.\n".utf8))
                return
            } catch { fail("Machine bootstrap refused or failed. Retained installation state was not reset.", code: EX_CONFIG) }
        }
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let path = CommandLine.arguments[2]
        let worker = Task { try await run(path: path) }
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        termination.setEventHandler { worker.cancel() }; interruption.setEventHandler { worker.cancel() }
        termination.resume(); interruption.resume()
        defer { termination.cancel(); interruption.cancel() }
        do { try await worker.value }
        catch is CancellationError { exit(EX_OK) }
        catch { fail("Setup service could not start or remain available. Check protected installation and configuration.", code: EX_CONFIG) }
    }
    private static func run(path: String) async throws {
        let service = try AdministrativeSetupService.open(configurationPath: path)
        do {
            try Task.checkCancellation(); try service.start()
            FileHandle.standardError.write(Data("Local setup service started. This does not indicate approval service health.\n".utf8))
            while true { try Task.checkCancellation(); try await Task.sleep(for: .milliseconds(250)) }
        } catch {
            let failure = error
            try service.close()
            throw failure
        }
    }
    private static func fail(_ message: String, code: Int32) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8)); exit(code)
    }
}
