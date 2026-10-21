import Darwin
import Foundation

/// Initial private retention only. Existing material is restored without fetching another provider credential.
enum RelayRunCredentialPreparation {
    static func prepareNative(account: AccountPreparationIntent, inventory: InstallationInventory,
                              expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                              created: SharedSetupRelayProvisioningRecord, runtime: RuntimeMaterialReference,
                              reference: RelayRunCredentialReference?, fileCustodyAccepted: Bool,
                              verifyCurrent: () throws -> Void,
                              makeCredential: () throws -> CloudflareTunnelRunCredential) throws -> RelayRunCredentialMaterial {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.privateDirectory.dropFirst()),
            owner: 0, createIfMissing: false)
        defer { directory.close() }
        return try restoreOrCreate(directory: directory, owner: 0, account: account, inventory: inventory,
            expected: expected, plan: plan, created: created, runtime: runtime, reference: reference,
            verifyCurrent: verifyCurrent, makeCredential: {
                guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
                return try makeCredential()
            })
    }

    // Owned fixtures prove file behavior, not Root authorization, service isolation or administrator consent.
    static func restoreOrCreate(directory: ProtectedSetupDirectory, owner: uid_t, account: AccountPreparationIntent,
                                inventory: InstallationInventory, expected: SharedSetupImportIntent,
                                plan: SharedSetupImportRelayPlan, created: SharedSetupRelayProvisioningRecord,
                                runtime: RuntimeMaterialReference, reference: RelayRunCredentialReference?,
                                verifyCurrent: () throws -> Void, makeCredential: () throws -> CloudflareTunnelRunCredential,
                                didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RelayRunCredentialMaterial {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        _ = try RelayRunCredentialMaterial.validateScope(expected: expected, plan: plan, created: created,
            runtime: runtime, account: account, inventory: inventory)
        let file = AdministrativeSetupPublication.File.relayRunMaterial
        func verify(_ material: RelayRunCredentialMaterial) throws {
            try verifyCurrent(); try directory.validate()
            if let reference { guard try material.reference == reference else { throw RuntimePreparationError.conflictingMaterial } }
        }
        func read() throws -> RelayRunCredentialMaterial? {
            try directory.withPrivateDirectory { fd in
                var info = stat()
                if fstatat(fd, file.name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
                    guard errno == ENOENT else { throw JournalLeaseError.system(errno) }; return nil
                }
                return try RelayRunCredentialMaterial.decode(ProtectedServiceConfiguration.read(anchor: directory.path,
                    relativePath: file.name, owner: owner), expected: expected, plan: plan, created: created,
                    runtime: runtime, account: account, inventory: inventory)
            }
        }
        try verifyCurrent()
        if let material = try read() {
            try verify(material)
            _ = try AdministrativeSetupPublication.publish(material.encoded, file: file, directory: directory, owner: owner, verify: verifyCurrent)
            try verify(material); return material
        }
        guard reference == nil else { throw RuntimePreparationError.missingMaterial }
        guard expected.phase == .runtimePublished || expected.phase == .gatewayPrepared else { throw RuntimePreparationError.incomplete }
        let material = try RelayRunCredentialMaterial(expected: expected, plan: plan, created: created, runtime: runtime,
            account: account, inventory: inventory, credential: makeCredential())
        try verify(material)
        _ = try AdministrativeSetupPublication.publish(material.encoded, file: file, directory: directory,
            owner: owner, verify: verifyCurrent, didStage: didStage)
        guard let retained = try read(), try retained.reference == material.reference else { throw RuntimePreparationError.conflictingMaterial }
        try verify(retained); return retained
    }
}

/// Copies only the selected run token to the dedicated transport account. It does not start a connector.
enum RelayRunCredentialPublication {
    enum Mode { case prepareUnactivated, validateRetained }
    static func publishNative(account: AccountPreparationIntent, inventory: InstallationInventory,
                              expected: SharedSetupImportIntent, plan: SharedSetupImportRelayPlan,
                              created: SharedSetupRelayProvisioningRecord, runtime: RuntimeMaterialReference,
                              reference: RelayRunCredentialReference, mode: Mode,
                              verifyCurrent: () throws -> Void) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        _ = try RelayRunCredentialMaterial.validateScope(expected: expected, plan: plan, created: created,
            runtime: runtime, account: account, inventory: inventory)
        guard let transport = runtime.services.claims.first(where: { $0.role == .transport }) else { throw RuntimePreparationError.incomplete }
        let accounts = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        let root = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.privateDirectory.dropFirst()), owner: 0, createIfMissing: false)
        defer { root.close() }
        func load() throws -> RelayRunCredentialMaterial {
            try verifyCurrent(); try root.validate()
            try accounts.validateGroup(transport); try accounts.validateUser(transport, ownerUID: account.ownerUID)
            let retainedRuntime = try RuntimePreparationMaterial.decode(ProtectedServiceConfiguration.read(anchor: root.path,
                relativePath: AdministrativeSetupPublication.File.runtimeRecord.name, owner: 0))
            guard try retainedRuntime.reference == runtime else { throw RuntimePreparationError.changedScope }
            let material = try RelayRunCredentialMaterial.decode(ProtectedServiceConfiguration.read(anchor: root.path,
                relativePath: AdministrativeSetupPublication.File.relayRunMaterial.name, owner: 0), expected: expected,
                plan: plan, created: created, runtime: runtime, account: account, inventory: inventory)
            guard try material.reference == reference else { throw RuntimePreparationError.conflictingMaterial }
            try verifyCurrent(); return material
        }
        let material = try load()
        let shared = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { shared.close() }
        return try publish(material: material, reference: reference, expected: expected, directory: shared,
            owner: 0, transportUID: transport.number, transportGID: transport.number, mode: mode, verifyCurrent: { _ = try load() })
    }

    // Same-owner fixtures cannot prove the native service account or cross-user access controls.
    static func publish(material: RelayRunCredentialMaterial, reference: RelayRunCredentialReference,
                        expected: SharedSetupImportIntent, directory: ProtectedSetupDirectory, owner: uid_t,
                        transportUID: uid_t, transportGID: gid_t, mode: Mode,
                        verifyCurrent: () throws -> Void,
                        didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        guard try material.reference == reference else { throw RuntimePreparationError.conflictingMaterial }
        if mode == .prepareUnactivated {
            guard expected.phase == .runtimePublished || expected.phase == .gatewayPrepared else { throw RuntimePreparationError.incomplete }
        }
        let file = AdministrativeSetupPublication.File.transportTunnelToken(ownerUID: transportUID, groupID: transportGID)
        func verify() throws { try verifyCurrent(); try directory.validate() }
        return try material.withCredentialBytes { bytes in
            try verify()
            if mode == .prepareUnactivated {
                return try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: owner,
                    verify: verify, didStage: didStage)
            }
            try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
            try verify(); return .retained
        }
    }
}
