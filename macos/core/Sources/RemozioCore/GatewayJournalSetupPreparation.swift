import Darwin
import Foundation

/// Compose authorized file preparation and immutable setup retention. This operation does not start the initializer.
/// The administrator host must authenticate its caller and validate the signed release before using the native entry.
enum GatewayJournalSetupPreparation {
    enum Stage { case privateFilesPublished, journalFilesPrepared, intentRetained, completed }

    static func prepare(machine: PreparationIntentStore, account: AccountPreparationIntent, material: GatewayMaterialReference,
                        configuration: GatewayServiceConfiguration, expected: GatewayJournalPreparationState,
                        verifyCurrent: () throws -> Void) throws -> GatewayJournalPreparationState {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try withoutActuallyEscaping(verifyCurrent) { verify in
            try prepare(machine: machine, account: account, material: material, configuration: configuration, expected: expected,
                verifyCurrent: verify, verifyServices: {
                    let directory = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
                    for claim in material.runtime.services.claims {
                        try directory.validateGroup(claim); try directory.validateUser(claim, ownerUID: account.ownerUID)
                    }
                }, publishPrivate: { retained, verify in
                    _ = try GatewayPrivateArtifactPublication.publish(account: account, expected: material,
                        mode: retained ? .validateRetained : .prepareUnactivated, verifyCurrent: verify)
                }, provisionFiles: { retained, verify in
                    try GatewayJournalFileProvisioning.prepare(account: account, services: material.runtime.services,
                        mode: retained == nil ? .createIfAbsent : .requireExisting, expected: retained, verifyCurrent: verify).identity
                })
        }
    }

    // Owned fixtures exercise ordering and protected state. They do not prove Root authorization or native service isolation.
    static func prepare(machine: PreparationIntentStore, account: AccountPreparationIntent, material: GatewayMaterialReference,
                        configuration: GatewayServiceConfiguration, expected: GatewayJournalPreparationState,
                        verifyCurrent: @escaping () throws -> Void, verifyServices: @escaping () throws -> Void,
                        publishPrivate: (Bool, () throws -> Void) throws -> Void,
                        provisionFiles: (GatewayJournalFileIdentity?, () throws -> Void) throws -> GatewayJournalFileIdentity,
                        didStage: (Stage) throws -> Void = { _ in }) throws -> GatewayJournalPreparationState {
        try verifyCurrent(); try machine.validateAccountPreparation(account)
        let activation = try machine.runtimeActivation(accountID: account.accountID)
        guard activation.jobsRegistered, let foreground = activation.plan, let inventory = try machine.inventory(),
              try machine.gatewayPreparation(accountID: account.accountID).reference == material,
              material.runtime.services.accountID == account.accountID,
              let wake = configuration.wakeEndpoint else { throw GatewayPreparationError.incomplete }
        try material.runtime.validate(account: account, services: material.runtime.services)
        let proposal = try GatewayConfigurationBundle(foreground: foreground, material: material, inventory: inventory,
            settings: configuration.settings, wakeMaximumConnections: wake.maximumConnections,
            wakeMaximumOperations: wake.maximumOperations, wakeChallengeLifetimeMilliseconds: wake.challengeLifetimeMillis)
        guard proposal.gateway.canonicalBytes == configuration.canonicalBytes else { throw GatewayPreparationError.changedScope }
        var retained = expected
        func verify() throws {
            try verifyServices(); try verifyCurrent(); try machine.validateAccountPreparation(account)
            let current = try machine.runtimeActivation(accountID: account.accountID)
            guard try machine.inventory() == inventory, current.jobsRegistered,
                  try current.plan?.encoded == foreground.encoded,
                  try machine.gatewayPreparation(accountID: account.accountID).reference == material,
                  try machine.gatewayJournalPreparation(accountID: account.accountID) == retained else {
                throw GatewayPreparationError.changedScope
            }
        }
        try verify()
        if let intent = retained.intent {
            guard intent.material == material, intent.configuration.canonicalBytes == configuration.canonicalBytes else {
                throw GatewayPreparationError.changedScope
            }
            if retained.initialized { return retained }
        } else {
            guard !retained.initialized, !inventory.services.contains(where: {
                $0.accountID == account.accountID && $0.role == .notificationGateway
            }) else { throw GatewayPreparationError.changedScope }
        }
        try verify()
        try publishPrivate(retained.intent != nil, verify); try didStage(.privateFilesPublished); try verify()
        let files = try provisionFiles(retained.intent?.files, verify)
        if let pinned = retained.intent?.files { guard files == pinned else { throw JournalLeaseError.identityChanged } }
        try didStage(.journalFilesPrepared); try verify()
        let intent = try retained.intent ?? GatewayJournalSetupIntent(id: AccountPreparationIntent.randomID(), material: material,
            configuration: configuration, files: files)
        try intent.validate(foreground: foreground, inventory: inventory)
        try machine.retainGatewayJournalIntent(intent); retained = .init(intent: intent, initialized: false)
        try didStage(.intentRetained); try verify()
        try didStage(.completed); try verify()
        return retained
    }
}
