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
        _ = try captureOpen(job, installationID: installationID, openMachine: openMachine,
            verifyConfiguration: verifyConfiguration)
    }
    private static func captureOpen(_ job: InstalledAccountJobManifest, installationID: Data,
        openMachine: () throws -> PreparationIntentStore, verifyConfiguration: () throws -> Void) throws -> UpdateAdmissionRegistrationRecord.Account? {
        guard job.declaration.role == .authority else { return nil }
        let machine = try openMachine()
        do {
            let account = try machine.runtimeMaintenanceBootstrapAccount(job, installationID: installationID)
            try machine.close(); try verifyConfiguration(); return account
        } catch { try? machine.close(); throw error }
    }
    static func withNativeRegistration(_ job: InstalledAccountJobManifest,
        body: (_ verify: () throws -> Void) throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard job.declaration.role == .authority else { try body({}); return }
        let configuration = try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath)
        func capture() throws -> UpdateAdmissionRegistrationRecord.Account? {
            try captureOpen(job, installationID: configuration.installationID,
                openMachine: { try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID) },
                verifyConfiguration: {
                    guard try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath).canonicalBytes
                        == configuration.canonicalBytes else { throw RuntimePreparationError.changedScope }
                })
        }
        try withAccountAdmission(capture: capture, acquire: { account in
            try UpdateAdmissionBarrier.open(machineDirectory: configuration.machineDirectory,
                expected: account.identity, scope: .account(account.accountID)).acquireAdmission()
        }, body: body)
    }
    static func withOwnedRegistration(capture: () throws -> UpdateAdmissionRegistrationRecord.Account?,
        acquire: (UpdateAdmissionRegistrationRecord.Account) throws -> UpdateAdmissionToken,
        body: (_ verify: () throws -> Void) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        try withAccountAdmission(capture: capture, acquire: acquire, body: body)
    }
    private static func withAccountAdmission(capture: () throws -> UpdateAdmissionRegistrationRecord.Account?,
        acquire: (UpdateAdmissionRegistrationRecord.Account) throws -> UpdateAdmissionToken,
        body: (_ verify: () throws -> Void) throws -> Void) throws {
        try withoutActuallyEscaping(capture) { capture in
            let account = try capture()
            let token: UpdateAdmissionToken?
            do { token = try account.map(acquire) }
            catch UpdateAdmissionBarrierError.busy { throw RuntimeActivationError.maintenancePending }
            defer { token?.close() }
            func verify() throws {
                if let account { try token?.validateAccountScope(account) }
                guard try capture() == account else { throw RuntimePreparationError.changedScope }
                if let account { try token?.validateAccountScope(account) }
            }
            try verify(); try body(verify); try verify()
        }
    }
}
