import Darwin
import Foundation

/// Native Root file preparation only. No job command runs while these callers hold a machine writer.
enum RuntimeActivationFiles {
    static func prepare(plan: RuntimeActivationPlan, account: AccountPreparationIntent,
                        initialization: AuthorityInitializationIntent, inventory: InstallationInventory,
                        verifyCurrent: () throws -> Void) throws {
        try access(plan: plan, account: account, initialization: initialization, inventory: inventory,
            publishNew: true, verifyCurrent: verifyCurrent)
    }
    static func validate(plan: RuntimeActivationPlan, account: AccountPreparationIntent,
                         initialization: AuthorityInitializationIntent, inventory: InstallationInventory,
                         verifyCurrent: () throws -> Void) throws {
        try access(plan: plan, account: account, initialization: initialization, inventory: inventory,
            publishNew: false, verifyCurrent: verifyCurrent)
    }
    private static func access(plan: RuntimeActivationPlan, account: AccountPreparationIntent,
                               initialization: AuthorityInitializationIntent, inventory: InstallationInventory,
                               publishNew: Bool, verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent(); try plan.validate(account: account, reference: plan.reference)
        let bundle = try plan.configurationBundle(account: account, initialization: initialization, inventory: inventory)
        guard bundle.command.canonicalBytes == plan.host.command.canonicalBytes,
              bundle.transport.canonicalBytes == plan.transport.canonicalBytes,
              let transport = plan.reference.services.claims.first(where: { $0.role == .transport }) else { throw RuntimeActivationError.changedScope }
        let native = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
        func verifyServices() throws {
            for claim in plan.reference.services.claims {
                try native.validateGroup(claim); try native.validateUser(claim, ownerUID: account.ownerUID)
            }
        }
        try verifyServices()
        _ = try AuthorityKeyProvisioning.restoreOrCreate(directoryPath: bundle.paths.authorityDirectory + "/Key",
            macID: account.macID, accountID: account.accountID, expectedPublicKey: plan.reference.services.authorityPublicKey)
        var directories: [ProtectedSetupDirectory] = []
        defer { for directory in directories.reversed() { directory.close() } }
        func existing(_ path: String, _ visibility: ProtectedSetupDirectory.Visibility) throws -> ProtectedSetupDirectory {
            try verifyCurrent()
            let value = try ProtectedSetupDirectory(anchor: "/", relativePath: String(path.dropFirst()), owner: 0,
                visibility: visibility, createIfMissing: false)
            directories.append(value); return value
        }
        let privateState = try existing(bundle.paths.privateDirectory, .privateState)
        let shared = try existing(bundle.paths.serviceDirectory, .sharedMetadata)
        let global = try existing(RuntimePreparationPaths.sharedDirectory, .sharedMetadata)
        let raw = try ProtectedServiceConfiguration.read(anchor: privateState.path, relativePath: "runtime-material.cbor", owner: 0)
        let material = try RuntimePreparationMaterial.decode(raw)
        guard try material.reference == plan.reference else { throw RuntimeActivationError.conflictingPlan }
        func retained(_ bytes: Data, _ file: AdministrativeSetupPublication.File, _ directory: ProtectedSetupDirectory) throws {
            try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: 0, verify: verifyCurrent)
        }
        try retained(raw, .runtimeRecord, privateState)
        try retained(account.policyBytes, .elevationPolicy, privateState)
        try retained(bundle.command.canonicalBytes, .commandConfiguration, privateState)
        try retained(material.transportIdentity, .transportIdentity(ownerUID: transport.number, groupID: transport.number), shared)
        try retained(bundle.transport.canonicalBytes, .transportConfiguration, shared)
        if let host = plan.gatewaySettingsHost { try retained(host.encoded, .gatewaySettingsHost, shared) }
        try retained(bundle.presenceClient.canonicalBytes, .presenceClient(ownerUID: account.ownerUID), global)
        try retained(bundle.pairingClient.canonicalBytes, .pairingClient(ownerUID: account.ownerUID), global)
        try retained(bundle.frontendClient.canonicalBytes, .frontendClient(ownerUID: account.ownerUID), global)
        let jobs: ProtectedSetupDirectory
        if publishNew {
            jobs = try ProtectedSetupDirectory.createOrOpen(path: InstalledAccountJobManifest.directory, visibility: .sharedMetadata)
            directories.append(jobs)
            try publish(plan: plan, privateState: privateState, jobs: jobs, owner: 0, verifyCurrent: verifyCurrent)
        } else { jobs = try existing(InstalledAccountJobManifest.directory, .sharedMetadata) }
        try retained(plan.host.canonicalBytes, .commandHost, privateState)
        for job in [plan.authorityJob, plan.transportJob] {
            try retained(job.bytes, .accountJob(accountID: plan.accountID, role: job.declaration.role), jobs)
        }
        try verifyServices(); try verifyCurrent()
        for directory in directories { try directory.validate() }
    }
    // Actual owned-file fixtures do not prove native service UID access, Root placement or registration.
    static func publish(plan: RuntimeActivationPlan, privateState: ProtectedSetupDirectory, jobs: ProtectedSetupDirectory,
                        owner: uid_t, verifyCurrent: () throws -> Void,
                        didPublish: (Int) throws -> Void = { _ in }) throws {
        try verifyCurrent()
        _ = try AdministrativeSetupPublication.publish(plan.host.canonicalBytes, file: .commandHost,
            directory: privateState, owner: owner, verify: verifyCurrent)
        try didPublish(0)
        for (index, job) in [plan.authorityJob, plan.transportJob].enumerated() {
            _ = try AdministrativeSetupPublication.publish(job.bytes, file: .accountJob(accountID: plan.accountID, role: job.declaration.role),
                directory: jobs, owner: owner, verify: verifyCurrent)
            try didPublish(index + 1)
        }
        try verifyCurrent(); try privateState.validate(); try jobs.validate()
    }
}

struct RuntimeActivationOperations {
    enum Stage { case intentRetained, filesPublished, inventoryEnrolled, authorityRegistered, transportRegistered, completed }
    let prepare: (RuntimeActivationPlan, AccountPreparationIntent, AuthorityInitializationIntent, InstallationInventory, () throws -> Void) throws -> Void
    let validate: (RuntimeActivationPlan, AccountPreparationIntent, AuthorityInitializationIntent, InstallationInventory, () throws -> Void) throws -> Void
    let register: (InstalledAccountJobManifest, () throws -> Void) throws -> Void
    let didStage: (Stage) throws -> Void
    static var native: Self {
        .init(prepare: { try RuntimeActivationFiles.prepare(plan: $0, account: $1, initialization: $2, inventory: $3, verifyCurrent: $4) },
            validate: { try RuntimeActivationFiles.validate(plan: $0, account: $1, initialization: $2, inventory: $3, verifyCurrent: $4) },
            register: { try RuntimeJobRegistration.ensure($0, verifyCurrent: $1) }, didStage: { _ in })
    }
}
