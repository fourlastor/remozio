import Darwin
import Foundation
import RemozioCore

@main
struct SetupMain {
    // Exit 0 reports successful one-shot setup or actual orderly service closure.
    static func main() async {
        // Exit 64 reports invalid command usage.
        guard CommandLine.arguments.count == 3,
              ["--configuration", "--bootstrap-installation", "--prepare-package", "--inspect-package", "--ensure-app-entry", "--disable-pairing-v2"].contains(CommandLine.arguments[1]) else {
            fail("Usage: RemozioSetup --configuration /absolute/protected/setup.cbor | --bootstrap-installation PUBLISHER_TEAM_ID | --prepare-package|--inspect-package|--ensure-app-entry PINNED_PROFILE | --disable-pairing-v2 ACCOUNT_ID", code: EX_USAGE)
        }
        // Exit 77 refuses a caller outside the Root account.
        guard getuid() == 0, geteuid() == 0 else { fail("Setup startup requires the Root account.", code: EX_NOPERM) }
        // Exit 78 reports configuration or startup failure.
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
        if CommandLine.arguments[1] == "--disable-pairing-v2" {
            do {
                let result = try PairingColdDisableSetup.run(accountIdentifier: CommandLine.arguments[2])
                if result == .retiredObsoleteIntent {
                    print("Retired an obsolete pairing disable record. The current pairing configuration remains active.")
                }
                return
            } catch PairingColdDisableSetup.RecoveryError.originalJobsRestored {
                fail("Pairing disable stopped before publication. Setup restored the original jobs. You can retry.", code: EX_TEMPFAIL)
            } catch PairingColdDisableSetup.RecoveryError.originalJobsRestorationFailed {
                fail("Pairing disable stopped before publication. Setup could not confirm restoration of both original jobs.", code: EX_CONFIG)
            } catch {
                fail("Pairing disable did not complete. Verify the installed account before retrying.", code: EX_CONFIG)
            }
        }
        if CommandLine.arguments[1] == "--bootstrap-installation" {
            do {
                _ = try MachineBootstrap.run(teamID: CommandLine.arguments[2])
                FileHandle.standardError.write(Data("Machine bootstrap prepared. Account enrollment and service registration remain separate.\n".utf8))
                return
            } catch { fail("Machine bootstrap refused or failed. Retained installation state was not reset.", code: EX_CONFIG) }
        }
        let path = CommandLine.arguments[2]
        let termination: DaemonTermination
        do { termination = try DaemonTermination() }
        catch { fail("Setup could not install its termination handler.", code: EX_OSERR) }
        do { try await termination.run { try await run(path: path, termination: termination) } }
        catch is CancellationError { exit(EX_OK) }
        catch { fail("Setup service could not start or remain available. Check protected installation and configuration.", code: EX_CONFIG) }
    }
    private static func run(path: String, termination: DaemonTermination) async throws {
        let service = try AdministrativeSetupService.open(configurationPath: path)
        do {
            try termination.checkCancellation()
            try service.start(terminate: { code in
                // Exit 75 is a recovery-deadline crash. It does not prove closure or release the durable drain.
                fail("Setup recovery did not join before its retirement deadline.", code: code)
            })
            try termination.checkCancellation()
            FileHandle.standardError.write(Data("Local setup status is available. Recovery can still keep normal requests pending.\n".utf8))
            await withTaskCancellationHandler {
                await service.waitUntilStopped()
            } onCancel: { service.requestRetirement() }
        } catch {
            let failure = error
            try await service.close()
            throw failure
        }
    }
    private static func fail(_ message: String, code: Int32) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8)); exit(code)
    }
}
