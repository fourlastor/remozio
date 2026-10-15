import Darwin
import Foundation
import RemozioProtocol
import Security

public enum MachineBootstrapError: Error, Equatable {
    case inconsistentState, existingStorage, wrongExecutable, randomFailure
}

/// One explicit installer operation. It creates no account, key, grant or service registration.
public enum MachineBootstrap {
    public static let bundlePath = "/Library/Application Support/Remozio/Applications/Remozio.app"
    public static let machineDirectory = "/Library/Application Support/Remozio/Machine"

    /// The package supplies its configured publisher identity. Never infer that identity from a candidate manifest.
    public static func run(teamID: String) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let bundle = URL(fileURLWithPath: bundlePath)
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        defer { placement.close() }
        func inspect() throws -> SignedReleaseEvidence {
            _ = try placement.inspectCopiedTree(name: bundle.lastPathComponent)
            let release = try SignedReleaseInspection.inspect(bundle, teamID: teamID, appIdentifier: "dev.remozio.mac")
            guard let host = release.manifest.components.first(where: { $0.role == .setupController }),
                  host.identifier == "dev.remozio.setup-controller", host.relativePath == AdministrativeSetupConfiguration.executablePath,
                  let hash = release.codeDirectoryHashes[.setupController] else { throw MachineBootstrapError.wrongExecutable }
            let requirement = try XPCPeerPolicy(teamID: teamID, componentIdentifier: host.identifier,
                approvedCodeDirectoryHashes: [hash], expectedUserID: 0).requirement
                + " and info[\"RemozioSecurityGeneration\"] = \"\(host.generation)\""
            try DynamicCodeValidation.validateSelf(requirement: requirement)
            guard try DynamicCodeValidation.selfPath() == bundlePath + "/" + host.relativePath else {
                throw MachineBootstrapError.wrongExecutable
            }
            try placement.validate()
            return release
        }
        _ = try inspect()
        let parent = URL(fileURLWithPath: AdministrativeSetupConfiguration.startupPath).deletingLastPathComponent().path
        let directory = try ProtectedSetupDirectory.createOrOpen(path: parent, visibility: .sharedMetadata)
        defer { directory.close() }
        return try run(directory: directory, owner: 0, fresh: {
            let release = try inspect(), mac = try randomID(), installation = try randomID()
            let inventory = try InstallationInventory.machineBootstrap(macID: mac, installationID: installation,
                revision: randomID(), bundlePath: bundlePath, releaseDigest: InstallationInventory.digest(release))
            let configuration = try AdministrativeSetupConfiguration(machineDirectory: machineDirectory, macID: mac,
                installationID: installation, releaseDigest: inventory.releaseDigest, codePolicy: policy(release, teamID: teamID))
            return try Seed(configuration: configuration, inventory: inventory)
        }, requireFreshStorage: {
            try directory.withDirectory { fd in
                var value = stat()
                if fstatat(fd, "Machine", &value, AT_SYMLINK_NOFOLLOW) == 0 { throw MachineBootstrapError.existingStorage }
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
            }
        }, prepareStore: {
            _ = try SetupDatabaseFileProvisioning.prepare(directoryPath: machineDirectory, kind: .installation)
        }, openStore: { initialize, mac in
            try PreparationIntentStore.open(directoryPath: machineDirectory, macID: mac, initialize: initialize)
        }, verify: { seed in
            let release = try inspect()
            guard seed.inventory.bundlePath == bundlePath, seed.configuration.machineDirectory == machineDirectory,
                  seed.configuration.codePolicy == (try policy(release, teamID: teamID)) else { throw MachineBootstrapError.inconsistentState }
            try seed.configuration.validate(inventory: seed.inventory, release: release)
        })
    }

    private static func policy(_ release: SignedReleaseEvidence, teamID: String) throws -> AuthorityCodePolicy {
        try AuthorityCodePolicy(entries: release.manifest.components.map { component in
            guard let hash = release.codeDirectoryHashes[component.role] else { throw MachineBootstrapError.inconsistentState }
            return try AuthorityCodeEntry(role: component.role, teamID: teamID, identifier: component.identifier,
                installedGeneration: component.generation, minimumGeneration: component.generation, codeDirectoryHash: hash, active: true)
        })
    }
    private static func randomID() throws -> Data {
        var bytes = Data(count: 16)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else {
            throw MachineBootstrapError.randomFailure
        }
        return bytes
    }

    struct Seed {
        let configuration: AdministrativeSetupConfiguration
        let inventory: InstallationInventory
        let bytes: Data
        init(configuration: AdministrativeSetupConfiguration, inventory: InstallationInventory) throws {
            guard inventory.formatVersion == 2, inventory.accounts.isEmpty,
                  inventory.macID == configuration.macID, inventory.installationID == configuration.installationID,
                  inventory.releaseDigest == configuration.releaseDigest else { throw MachineBootstrapError.inconsistentState }
            self.configuration = configuration; self.inventory = inventory
            bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(configuration.canonicalBytes),
                2: .bytes(inventory.canonicalBytes)]), limits: Self.limits)
        }
        static func decode(_ bytes: Data) throws -> Self {
            guard case .map(let values) = try DeterministicCBOR.decode(bytes, limits: limits), Set(values.keys) == [0, 1, 2],
                  values[0] == .unsigned(1), case .bytes(let config) = values[1], case .bytes(let record) = values[2] else {
                throw MachineBootstrapError.inconsistentState
            }
            let configuration = try AdministrativeSetupConfiguration.decode(config)
            let value = try Self(configuration: configuration,
                inventory: InstallationInventory.decode(record, expectedMacID: configuration.macID))
            guard value.bytes == bytes else { throw MachineBootstrapError.inconsistentState }; return value
        }
        private static var limits: CBORLimits { get throws { try .init(maxBytes: 65536, maxDepth: 2, maxItems: 8) } }
    }
    enum Stage: CaseIterable { case intentRetained, filesPrepared, storeOpened, inventoryRetained, completionPublished, configurationPublished }

    // Same-owner controls retain actual private files and SQLite stores. Product callers cannot inject these factories.
    static func run(directory: ProtectedSetupDirectory, owner: uid_t, fresh: () throws -> Seed,
                    requireFreshStorage: () throws -> Void, prepareStore: () throws -> Void,
                    openStore: (Bool, Data) throws -> PreparationIntentStore, verify: (Seed) throws -> Void,
                    didStage: (Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        let completion = try read(.bootstrapCompletion, directory: directory, owner: owner)
        let startup = try read(.startup, directory: directory, owner: owner)
        let seed: Seed
        if let bytes = try read(.bootstrapIntent, directory: directory, owner: owner) { seed = try Seed.decode(bytes) }
        else {
            guard completion == nil, startup == nil else { throw MachineBootstrapError.inconsistentState }
            try requireFreshStorage()
            seed = try fresh(); try verify(seed)
        }
        guard completion == nil || completion == seed.bytes,
              startup == nil || startup == seed.configuration.canonicalBytes,
              completion != nil || startup == nil else { throw MachineBootstrapError.inconsistentState }
        _ = try AdministrativeSetupPublication.publish(seed.bytes, file: .bootstrapIntent, directory: directory,
            owner: owner, verify: { try verify(seed) })
        var completed = completion != nil
        func verifyIntent() throws {
            try directory.validate()
            guard try read(.bootstrapIntent, directory: directory, owner: owner) == seed.bytes else {
                throw MachineBootstrapError.inconsistentState
            }
            let marker = try read(.bootstrapCompletion, directory: directory, owner: owner)
            guard marker == nil || marker == seed.bytes, !completed || marker != nil else {
                throw MachineBootstrapError.inconsistentState
            }
            if marker != nil { completed = true }
            try verify(seed)
        }
        try verifyIntent(); try didStage(.intentRetained); try verifyIntent()
        if !completed { try prepareStore(); try didStage(.filesPrepared); try verifyIntent() }
        let machine: PreparationIntentStore
        do { machine = try openStore(false, seed.configuration.macID) }
        catch PreparationStoreError.incompatibleStore {
            try verifyIntent()
            guard !completed else { throw MachineBootstrapError.inconsistentState }
            machine = try openStore(true, seed.configuration.macID)
        }
        defer { try? machine.close() }
        try didStage(.storeOpened); try verifyIntent()
        if !completed {
            guard try machine.records().isEmpty else { throw MachineBootstrapError.inconsistentState }
            try machine.upgradeInventoryStorage()
        }
        let inventory: InstallationInventory
        if let retained = try machine.inventory() { inventory = retained }
        else {
            guard !completed else { throw MachineBootstrapError.inconsistentState }
            inventory = try machine.writeInventory(seed.inventory, expectedRevision: nil)
        }
        guard inventory.formatVersion >= seed.inventory.formatVersion,
              inventory.macID == seed.inventory.macID, inventory.installationID == seed.inventory.installationID,
              inventory.bundlePath == seed.inventory.bundlePath, inventory.releaseDigest == seed.inventory.releaseDigest,
              inventory.services.contains(where: { $0 == seed.inventory.services[0] }),
              completed || (inventory.formatVersion == 2 && inventory.accounts.isEmpty && inventory.services == seed.inventory.services) else {
            throw MachineBootstrapError.inconsistentState
        }
        func verifyCurrent() throws {
            try verifyIntent()
            guard try machine.inventory() == inventory else { throw MachineBootstrapError.inconsistentState }
        }
        try verifyCurrent(); try didStage(.inventoryRetained)
        _ = try AdministrativeSetupPublication.publish(seed.bytes, file: .bootstrapCompletion, directory: directory,
            owner: owner, verify: verifyCurrent)
        completed = true
        try didStage(.completionPublished)
        let result = try AdministrativeSetupPublication.publish(seed.configuration, directory: directory,
            owner: owner, verify: verifyCurrent)
        try didStage(.configurationPublished)
        return result
    }

    private static func read(_ file: AdministrativeSetupPublication.File, directory: ProtectedSetupDirectory, owner: uid_t) throws -> Data? {
        try directory.validate()
        do {
            let result = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: owner)
            try directory.validate(); return result
        } catch JournalLeaseError.system(ENOENT) { try directory.validate(); return nil }
    }
}
