import Darwin
import Foundation

/// Reads the current protected window and closes the machine store before each native registration boundary.
enum RuntimeMaintenanceBootstrapGuard {
    static func requireNativeOpen(_ job: InstalledAccountJobManifest) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard job.declaration.role == .authority else { return }
        let configuration = try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath)
        try requireOpen(job, installationID: configuration.installationID,
            openMachine: { try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID) },
            verifyConfiguration: {
                guard try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath).canonicalBytes
                    == configuration.canonicalBytes else { throw RuntimePreparationError.changedScope }
            })
    }
    static func requireOpen(_ job: InstalledAccountJobManifest, installationID: Data,
        openMachine: () throws -> PreparationIntentStore, verifyConfiguration: () throws -> Void) throws {
        guard job.declaration.role == .authority else { return }
        let machine = try openMachine()
        do {
            try machine.requireRuntimeMaintenanceBootstrap(job, installationID: installationID)
            try machine.close(); try verifyConfiguration()
        } catch { try? machine.close(); throw error }
    }
}
