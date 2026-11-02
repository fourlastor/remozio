import Darwin
import Foundation

/// Retains published source values before an audit upgrade. Registration and inventory remain unchanged.
enum RuntimeAuditUpgradeSourcePlan {
    static func retain(machine: PreparationIntentStore, account: AccountPreparationIntent,
                       installedRelease: SignedReleaseEvidence, rootActivity: ReleaseActivityToken,
                       verifyOwner: () throws -> Void) throws -> RuntimeActivationPlan {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        func verify() throws { try rootActivity.validateExclusive(); try verifyOwner() }
        try verify(); try machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory)
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        func directory(_ path: String, _ visibility: ProtectedSetupDirectory.Visibility) throws -> ProtectedSetupDirectory {
            try .init(anchor: "/", relativePath: String(path.dropFirst()), owner: 0, visibility: visibility, createIfMissing: false)
        }
        let runtime = try directory(paths.privateDirectory, .privateState); defer { runtime.close() }
        let services = try directory(paths.serviceDirectory, .sharedMetadata); defer { services.close() }
        let clients = try directory(RuntimePreparationPaths.sharedDirectory, .sharedMetadata); defer { clients.close() }
        return try retain(machine: machine, account: account, installedRelease: installedRelease, owner: 0,
            runtime: runtime, services: services, clientsDirectory: clients, verifyOwner: verify)
    }
    /// Ordinary-owner files and SQLite only. This entry point refuses a Root process.
    static func retainOwned(machine: PreparationIntentStore, account: AccountPreparationIntent,
                            installedRelease: SignedReleaseEvidence, owner: uid_t,
                            runtime: ProtectedSetupDirectory, services: ProtectedSetupDirectory,
                            clientsDirectory: ProtectedSetupDirectory,
                            verifyOwner: () throws -> Void = {}) throws -> RuntimeActivationPlan {
        guard owner > 0, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        return try retain(machine: machine, account: account, installedRelease: installedRelease, owner: owner,
            runtime: runtime, services: services, clientsDirectory: clientsDirectory, verifyOwner: verifyOwner)
    }
    private static func retain(machine: PreparationIntentStore, account: AccountPreparationIntent,
                               installedRelease: SignedReleaseEvidence, owner: uid_t,
                               runtime: ProtectedSetupDirectory, services: ProtectedSetupDirectory,
                               clientsDirectory: ProtectedSetupDirectory,
                               verifyOwner: () throws -> Void) throws -> RuntimeActivationPlan {
        func verify() throws {
            try verifyOwner(); try machine.validateStorageLease()
            try runtime.validate(); try services.validate(); try clientsDirectory.validate()
        }
        try verify()
        guard try machine.accountPreparation(ownerUID: account.ownerUID) == account,
              let initialization = try machine.initialization(accountID: account.accountID),
              let inventory = try machine.inventory() else { throw RuntimeActivationError.changedScope }
        try inventory.compareRelease(installedRelease)
        let state = try machine.runtimePreparation(accountID: account.accountID)
        guard state.configurationPublished, let reference = state.reference else { throw RuntimeActivationError.incomplete }
        let activation = try machine.runtimeActivation(accountID: account.accountID)
        if let plan = activation.plan {
            try plan.validate(account: account, reference: reference)
            try plan.host.validateRelease(installedRelease, bundlePath: inventory.bundlePath)
            return plan
        }
        guard !activation.jobsRegistered else { throw RuntimeActivationError.changedScope }
        func read(_ directory: ProtectedSetupDirectory, _ file: AdministrativeSetupPublication.File,
                  optional: Bool = false) throws -> Data? {
            try verify()
            let bytes: Data?
            do {
                bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
                    owner: owner, privateFile: file.mode == 0o600)
            } catch JournalLeaseError.system(let code) where optional && code == ENOENT {
                try directory.validate(); bytes = nil
            }
            if let bytes {
                try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory,
                    owner: owner, verify: verifyOwner)
            }
            try verify(); return bytes
        }
        let command = try read(runtime, .commandConfiguration)!
        let transport = try read(services, .transportConfiguration)!
        let host = try read(runtime, .commandHost, optional: true)
        let gateway = try read(services, .gatewaySettingsHost, optional: true)
        let clients = try RuntimeActivationClients.load(directory: clientsDirectory, owner: owner,
            ownerUID: account.ownerUID, verifyCurrent: verifyOwner)
        let plan = try RuntimeActivationPlan.retainingPublished(account: account, initialization: initialization,
            reference: reference, inventory: inventory, installedRelease: installedRelease,
            command: .decode(command), transport: .decode(transport),
            host: host.map { try .decode($0) }, gatewaySettingsHost: gateway.map { try .decode($0) }, clients: clients)
        func validateSource() throws {
            try verify()
            guard try read(runtime, .commandConfiguration) == command,
                  try read(services, .transportConfiguration) == transport,
                  try read(runtime, .commandHost, optional: true) == host,
                  try read(services, .gatewaySettingsHost, optional: true) == gateway,
                  try machine.accountPreparation(ownerUID: account.ownerUID) == account,
                  try machine.initialization(accountID: account.accountID) == initialization,
                  try machine.inventory() == inventory,
                  try machine.runtimePreparation(accountID: account.accountID) == state else { throw RuntimeActivationError.changedScope }
            try clients.validateRetained(directory: clientsDirectory, owner: owner, ownerUID: account.ownerUID,
                verifyCurrent: verifyOwner)
        }
        try validateSource()
        _ = try machine.retainRuntimeActivation(plan)
        try validateSource()
        let retained = try machine.runtimeActivation(accountID: account.accountID)
        guard try retained.plan?.encoded == plan.encoded, !retained.jobsRegistered else { throw RuntimeActivationError.changedScope }
        return plan
    }
}
