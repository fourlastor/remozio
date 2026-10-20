import Darwin
import Foundation
import RemozioProtocol

/// Initial setup only. The endpoint establishes administrator authorization and current signed host scope.
/// Publication does not register jobs, activate pairing, or grant command admission.
enum RuntimePublicationController {
    enum Stage { case materialRestored, referenceRetained, filesPublished, completed }

    static func prepare(machine: PreparationIntentStore, account: AccountPreparationIntent,
                        expected: RuntimePreparationState, fileCustodyAccepted: Bool,
                        serviceActivityEnabled: Bool = false,
                        verifyCurrent: () throws -> Void) throws -> RuntimePreparationState {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        return try withoutActuallyEscaping(verifyCurrent) { verify in
        try prepare(machine: machine, account: account, expected: expected, verifyCurrent: verify,
            verifyServices: { services in
                let directory = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
                for claim in services.claims {
                    try directory.validateGroup(claim); try directory.validateUser(claim, ownerUID: account.ownerUID)
                }
            }, verifyAuthority: { services in
                let authority = try AccountPreparationController.authorityDirectory(accountID: account.accountID)
                _ = try AuthorityKeyProvisioning.restoreOrCreate(directoryPath: authority + "/Key", macID: account.macID,
                    accountID: account.accountID, expectedPublicKey: services.authorityPublicKey)
            }, restoreMaterial: { services, reference, verify in
                try RuntimeMaterialPreparation.prepareFileIdentity(account: account, services: services, expected: reference,
                    fileCustodyAccepted: fileCustodyAccepted, serviceActivityEnabled: serviceActivityEnabled, verifyCurrent: verify)
            }, verifyActivity: { activity in
                try RuntimeMaterialPreparation.validateServiceActivity(account: account, activity: activity, verifyCurrent: verify)
            }, publish: { bundle, material, verify in
                try publishNative(bundle: bundle, material: material, verifyCurrent: verify)
            })
        }
    }

    // Logical composition fixtures do not prove native Root ownership, account isolation, signing, or service registration.
    static func prepare(machine: PreparationIntentStore, account: AccountPreparationIntent,
                        expected: RuntimePreparationState, importIntent: SharedSetupImportIntent? = nil, relayPlan: SharedSetupImportRelayPlan? = nil,
                        verifyCurrent: @escaping () throws -> Void,
                        verifyServices: @escaping (ServiceAccountPlan) throws -> Void,
                        verifyAuthority: (ServiceAccountPlan) throws -> Void,
                        restoreMaterial: (ServiceAccountPlan, RuntimeMaterialReference?, () throws -> Void) throws -> RuntimePreparationMaterial,
                        verifyActivity: @escaping (ServiceReleaseActivityReference) throws -> Void = { _ in throw RuntimePreparationError.incomplete },
                        publish: (RuntimeConfigurationBundle, RuntimePreparationMaterial, () throws -> Void) throws -> Void,
                        validatePublishedImport: (RuntimeConfigurationBundle, RuntimePreparationMaterial, () throws -> Void) throws -> Void = { _, _, _ in throw RuntimePreparationError.incomplete },
                        didStage: (Stage) throws -> Void = { _ in }) throws -> RuntimePreparationState {
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        guard let inventory = try machine.inventory(), let initialization = try machine.initialization(accountID: account.accountID),
              initialization.complete else { throw RuntimePreparationError.incomplete }
        if let importIntent {
            guard importIntent.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)) else {
                throw SharedSetupImportError.wrongScope
            }
        }
        if let importIntent, importIntent.recipe.cloudflare != nil {
            guard let relayPlan else { throw RuntimePreparationError.incomplete }
            try relayPlan.validate(expected: importIntent)
        } else { guard relayPlan == nil else { throw SharedSetupImportError.conflict } }
        let state = try machine.serviceAccountPlan(accountID: account.accountID)
        guard state.complete, let services = state.plan else { throw RuntimePreparationError.incomplete }
        try services.validate(account: account)
        guard try machine.runtimePreparation(accountID: account.accountID) == expected else { throw RuntimePreparationError.changedScope }
        var retainedReference = expected.reference
        func verify() throws {
            try verifyCurrent(); try machine.validateAccountPreparation(account); try services.validate(account: account)
            guard try machine.inventory() == inventory,
                  try machine.serviceAccountPlan(accountID: account.accountID) == state,
                  try machine.runtimePreparation(accountID: account.accountID).reference == retainedReference else {
                throw RuntimePreparationError.changedScope
            }
            try verifyServices(services)
            if let activity = retainedReference?.serviceActivity { try verifyActivity(activity) }
        }
        try verify(); try verifyAuthority(services); try verify()
        let material = try restoreMaterial(services, retainedReference, verify)
        try didStage(.materialRestored); try verify()
        let reference = try material.reference
        try reference.validate(account: account, services: services)
        if let retainedReference, retainedReference != reference { throw RuntimePreparationError.conflictingMaterial }
        if expected.configurationPublished {
            guard retainedReference != nil else { throw RuntimePreparationError.incomplete }
            if let importIntent {
                let bundle = try RuntimeConfigurationBundle.initial(account: account, initialization: initialization,
                    reference: reference, inventory: inventory, importIntent: importIntent, relayPlan: relayPlan)
                try validatePublishedImport(bundle, material, verify); try verify()
            }
            return expected
        }
        // Recheck the actual files after material recovery and immediately before retaining their identities.
        try verify()
        if let activity = reference.serviceActivity { try verifyActivity(activity) }
        try machine.retainRuntimeMaterial(reference)
        retainedReference = reference
        try didStage(.referenceRetained); try verify()
        let bundle = try RuntimeConfigurationBundle.initial(account: account, initialization: initialization,
            reference: reference, inventory: inventory, importIntent: importIntent, relayPlan: relayPlan)
        try publish(bundle, material, verify)
        try didStage(.filesPublished); try verify()
        if importIntent != nil { try validatePublishedImport(bundle, material, verify); try verify() }
        // Recheck the retained material after all outputs. An established reference never permits creation here.
        let confirmed = try restoreMaterial(services, reference, verify)
        guard try confirmed.reference == reference else { throw RuntimePreparationError.conflictingMaterial }
        try verify(); try machine.completeRuntimePublication(reference)
        try didStage(.completed)
        let result = try machine.runtimePreparation(accountID: account.accountID)
        guard result.reference == reference, result.configurationPublished else { throw RuntimePreparationError.incomplete }
        return result
    }

    private static func publishNative(bundle: RuntimeConfigurationBundle, material: RuntimePreparationMaterial,
                                      verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard let transport = material.services.claims.first(where: { $0.role == .transport }) else {
            throw RuntimePreparationError.incomplete
        }
        var directories: [ProtectedSetupDirectory] = []
        defer { for directory in directories.reversed() { directory.close() } }
        func open(_ path: String, _ visibility: ProtectedSetupDirectory.Visibility) throws -> ProtectedSetupDirectory {
            try verifyCurrent()
            let directory = try ProtectedSetupDirectory.createOrOpen(path: path, visibility: visibility)
            directories.append(directory); return directory
        }
        let global = try open(RuntimePreparationPaths.sharedDirectory, .sharedMetadata)
        let privateState = try open(bundle.paths.privateDirectory, .privateState)
        _ = try open(RuntimePreparationPaths.sharedDirectory + "/Services", .sharedMetadata)
        let shared = try open(bundle.paths.serviceDirectory, .sharedMetadata)
        func publish(_ bytes: Data, _ file: AdministrativeSetupPublication.File, _ directory: ProtectedSetupDirectory) throws {
            _ = try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: 0,
                verify: verifyCurrent)
        }
        try publish(bundle.elevationPolicy.canonicalBytes, .elevationPolicy, privateState)
        try publish(bundle.command.canonicalBytes, .commandConfiguration, privateState)
        try publish(material.transportIdentity, .transportIdentity(ownerUID: transport.number, groupID: transport.number), shared)
        try publish(bundle.transport.canonicalBytes, .transportConfiguration, shared)
        if let host = try bundle.gatewaySettingsHost { try publish(host.encoded, .gatewaySettingsHost, shared) }
        let owner = material.services.ownerUID
        try publish(bundle.presenceClient.canonicalBytes, .presenceClient(ownerUID: owner), global)
        try publish(bundle.pairingClient.canonicalBytes, .pairingClient(ownerUID: owner), global)
        try publish(bundle.frontendClient.canonicalBytes, .frontendClient(ownerUID: owner), global)
        for directory in directories { try directory.validate() }
        try verifyCurrent()
    }
}
