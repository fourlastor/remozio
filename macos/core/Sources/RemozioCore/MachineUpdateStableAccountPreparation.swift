import Darwin
import Foundation

/// Synchronous stable setup composition. The authenticated caller owns admission and verifies current administrator rights.
enum MachineUpdateStableAccountPreparation {
    enum Stage: CaseIterable { case keyProvisioned, keyPinned, initializationRetained, storesInitialized, completed }

    static func resumeNative(machine: PreparationIntentStore, expected: MachineUpdateStableAccountSetupSnapshot,
        candidate: SignedReleaseEvidence, currentCodePolicy: AuthorityCodePolicy,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyCurrent: @escaping (MachineUpdateStableAccountSetupSnapshot) throws -> Void) throws -> AccountPreparationIntent {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard expected.account?.origin == .currentRelease else { throw AccountPreparationError.conflict }
        let inventory = expected.source.actual.inventory
        guard inventory.bundlePath == MachineBootstrap.bundlePath,
              let app = currentCodePolicy.entries.first(where: { $0.role == .app && $0.active }),
              let setup = currentCodePolicy.entries.first(where: { $0.role == .setupController && $0.active }) else {
            throw AccountPreparationError.conflict
        }
        let bundle = URL(fileURLWithPath: inventory.bundlePath)
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        defer { placement.close() }
        _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
        let identity = try placement.preparationCopyIdentity(name: bundle.lastPathComponent)
        func verifyNative(_ actual: MachineUpdateStableAccountSetupSnapshot) throws {
            try placement.validate()
            guard try placement.preparationCopyIdentity(name: bundle.lastPathComponent) == identity else { throw JournalLeaseError.identityChanged }
            let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try actual.source.actual.inventory.compareRelease(release)
            guard try InstallationInventory.digest(release) == InstallationInventory.digest(candidate) else { throw AccountPreparationError.conflict }
            try MachineUpdateStableReleaseRecord.requireFormats(release)
            try ReleaseGenerationPreflight.validate(release, against: currentCodePolicy)
            for entry in [app, setup] {
                guard let component = release.manifest.components.first(where: { $0.role == entry.role }),
                      entry.installedGeneration == component.generation,
                      entry.codeDirectoryHash == release.codeDirectoryHashes[entry.role] else { throw AccountPreparationError.conflict }
            }
            let local = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
                approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
            try DynamicCodeValidation.validateSelf(requirement: local.requirement)
            guard try DynamicCodeValidation.selfPath() == inventory.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath else {
                throw AccountPreparationError.conflict
            }
            let owner = try LocalAccountDirectory.lookup(uid: actual.owner.uid)
            try actual.requireOwner(owner); try verifyCurrent(actual)
            try placement.validate()
            guard try placement.preparationCopyIdentity(name: bundle.lastPathComponent) == identity else { throw JournalLeaseError.identityChanged }
        }
        return try resume(machine: machine, expected: expected, candidate: candidate, directory: directory, admission: admission,
            verifyCurrent: verifyNative, initializationPaths: { preparation in
                let authority = try AccountPreparationController.authorityDirectory(accountID: preparation.accountID)
                return (authority + "/Journal/journal.sqlite", authority + "/Continuity/continuity.sqlite")
            }, provisionKey: { preparation, verify in
                let authority = try AccountPreparationController.authorityDirectory(accountID: preparation.accountID)
                let account = (authority as NSString).deletingLastPathComponent, key = authority + "/Key"
                var directories: [ProtectedSetupDirectory] = []
                defer { for directory in directories.reversed() { directory.close() } }
                for path in [AccountPreparationController.accountsDirectory, account, authority, key] {
                    try verify(); directories.append(try ProtectedSetupDirectory.createOrOpen(path: path))
                    for directory in directories { try directory.validate() }
                }
                let value = try AuthorityKeyProvisioning.restoreOrCreate(directoryPath: key, macID: preparation.macID,
                    accountID: preparation.accountID, expectedPublicKey: preparation.authorityPublicKey)
                for directory in directories { try directory.validate() }; try verify()
                return value.publicKey
            }, resumeInitialization: { initial, storage in
                try AuthorityAccountInitialization.resumeStable(machine: machine, expected: initial, storage: storage)
            })
    }

    /// Owned controls replace native factories. The same stable writers, admission checks, and callback lifetime remain mandatory.
    static func resume(machine: PreparationIntentStore, expected: MachineUpdateStableAccountSetupSnapshot,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyCurrent: @escaping (MachineUpdateStableAccountSetupSnapshot) throws -> Void,
        initializationPaths: (AccountPreparationIntent) throws -> (journal: String, continuity: String),
        provisionKey: (AccountPreparationIntent, () throws -> Void) throws -> Data,
        resumeInitialization: (AuthorityInitializationIntent, AuthorityAccountInitialization.Storage) throws -> AuthorityInitializationIntent,
        didStage: (Stage) throws -> Void = { _ in }) throws -> AccountPreparationIntent {
        guard expected.account?.origin == .currentRelease else { throw AccountPreparationError.conflict }
        let processID = getpid(), thread = pthread_self()
        var active = true, current = expected
        weak var writer = machine
        defer { active = false; writer = nil }
        func requireLifetime() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            guard active, writer != nil else { throw JournalLeaseError.invalidated }
        }
        func verifyBoundary(_ actual: MachineUpdateStableAccountSetupSnapshot) throws {
            try requireLifetime()
            guard actual.account?.origin == .currentRelease else { throw AccountPreparationError.conflict }
            try admission.validateMachineBoundary(directory: directory, expected: expected.source.actual.admission.machine)
            guard actual.source.actual.admission == expected.source.actual.admission else { throw MachineUpdateActivationError.wrongBoundary }
            try actual.requireOwner(expected.owner); try verifyCurrent(actual)
            try admission.validateMachineBoundary(directory: directory, expected: expected.source.actual.admission.machine)
        }
        func verify() throws {
            try requireLifetime(); guard let writer else { throw JournalLeaseError.invalidated }
            try current.requireCurrent(machine: writer, candidate: candidate); try verifyBoundary(current)
            try current.requireCurrent(machine: writer, candidate: candidate)
        }
        func adopt(preparation: AccountPreparationIntent, initialization: AuthorityInitializationIntent?) throws {
            try requireLifetime(); guard let writer else { throw JournalLeaseError.invalidated }
            let actual = try MachineUpdateStableAccountSetupSnapshot(source: writer.stableRuntimeSource(candidate: candidate), owner: expected.owner)
            guard actual.account?.origin == .currentRelease else { throw AccountPreparationError.conflict }
            try actual.requireAccountStorageState(preparation: preparation, initialization: initialization, from: current)
            current = actual; try verify()
        }
        func verifyStorage(_ initial: AuthorityInitializationIntent) throws {
            try verify()
            guard current.account?.initialization == initial else { throw AuthorityInitializationError.staleRevision }
        }
        try verify(); guard let original = current.preparation else { throw AccountPreparationError.missing }
        // Completion never authorizes key, journal, or continuity recreation.
        if original.storagePrepared { return original }
        let key = try provisionKey(original, verify)
        try didStage(.keyProvisioned); try verify()
        let pinned = try machine.pinStableAccountPreparation(publicKey: key, expected: current,
            candidate: candidate, directory: directory, admission: admission) { _, actual in try verifyBoundary(actual) }
        try adopt(preparation: pinned, initialization: current.account?.initialization)
        try didStage(.keyPinned); try verify()
        let paths = try initializationPaths(pinned)
        let initial = try machine.beginStableAccountInitialization(journalPath: paths.journal, continuityPath: paths.continuity,
            expected: current, candidate: candidate, directory: directory, admission: admission) { _, actual in try verifyBoundary(actual) }
        try adopt(preparation: pinned, initialization: initial)
        try didStage(.initializationRetained); try verify()
        let storage = AuthorityAccountInitialization.Storage(validate: verifyStorage, capture: { retained, declaration, journal in
            try verifyStorage(retained); guard let writer, let preparation = current.preparation,
                  try declaration.initializationBytes == preparation.initializationBytes else { throw AuthorityInitializationError.conflictingIntent }
            let value = try writer.captureStableAccountInitialization(journal: journal, expected: current,
                candidate: candidate, directory: directory, admission: admission) { _, actual in try verifyBoundary(actual) }
            try adopt(preparation: preparation, initialization: value); return value
        }, complete: { retained, journal, continuity in
            try verifyStorage(retained); guard let writer, let preparation = current.preparation else { throw JournalLeaseError.invalidated }
            let value = try writer.completeStableAccountInitialization(journal: journal, continuity: continuity, expected: current,
                candidate: candidate, directory: directory, admission: admission) { _, actual in try verifyBoundary(actual) }
            try adopt(preparation: preparation, initialization: value); return value
        })
        let result = try resumeInitialization(initial, storage)
        try verifyStorage(result)
        guard result.complete else { throw AuthorityInitializationError.invalidBoundary }
        try didStage(.storesInitialized); try verify()
        let completed = try machine.completeStableAccountPreparation(expected: current,
            candidate: candidate, directory: directory, admission: admission) { _, actual in try verifyBoundary(actual) }
        try adopt(preparation: completed, initialization: result)
        try didStage(.completed); try verify(); return completed
    }
}
