import CryptoKit
import Foundation
import RemozioProtocol

/// Canonical commitments to captured declarations. These bytes grant no rights or native custody.
struct RuntimeMaintenanceCommitments: Equatable {
    let scope: RuntimeMaintenanceWindowRecord.Scope
    private enum Domain: String {
        case operation, restoration, mutationFootprint, authorityPolicy, authorityGrant, targetConsent, administratorIntent
    }
    static func requireProfile(_ purpose: RuntimeMaintenanceWindowRecord.Purpose) throws {
        guard purpose == .retainedRuntime else { throw RuntimePreparationError.changedScope }
    }
    static func capture(binding: SetupRetainedCallerBinding, inputs: MachineUpdateRetainedSetupRuntimeInputs,
        candidate: SignedReleaseEvidence, purpose: RuntimeMaintenanceWindowRecord.Purpose) throws -> Self {
        let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(
            runtime: binding.entry.runtime, accountID: binding.authorityAccountID)
        guard try host.codePolicy.bytes == binding.publishedAuthorityPolicy.bytes else { throw RuntimePreparationError.changedScope }
        return try observing(entry: binding.entry, inputs: inputs, authorityAccountID: binding.authorityAccountID,
            authorityOwner: binding.authorityOwner, targetOwner: binding.targetOwner, candidate: candidate, purpose: purpose)
    }
    /// Recomputed declarations only. Recovery cannot mint a caller binding or authorize another body.
    static func observing(entry: MachineUpdateRetainedSetupInitialRuntimeEntry, inputs: MachineUpdateRetainedSetupRuntimeInputs,
        authorityAccountID: Data, authorityOwner: LocalAccountIdentity, targetOwner: LocalAccountIdentity,
        candidate: SignedReleaseEvidence, purpose: RuntimeMaintenanceWindowRecord.Purpose) throws -> Self {
        try requireProfile(purpose)
        let runtime = entry.runtime, inventory = runtime.setup.source.actual.inventory
        try inputs.requireSource(runtime); try runtime.setup.requireOwner(targetOwner)
        let (initial, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(runtime: runtime, accountID: authorityAccountID)
        guard let authorityPreparation = runtime.setup.source.preparations.first(where: { $0.accountID == authorityAccountID }),
              let targetInitial = runtime.setup.account?.initialization,
              let app = host.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw RuntimePreparationError.incomplete
        }
        try LocalAccountDirectory.validateOwnership(authorityOwner, uid: authorityPreparation.ownerUID, directoryID: authorityPreparation.directoryID)
        let authority = try account(authorityAccountID, owner: authorityOwner), target = try account(runtime.preparation.accountID, owner: targetOwner)
        let operation = try OperationManifest(purpose: purpose, entry: entry, initial: targetInitial, choices: stableImportChoices(inputs)).digest
        let restoration = try RestorationDeclarations(initial: initial, host: host, inventory: inventory).digest
        let footprint = try MutationFootprint(runtime: runtime, inputs: inputs).digest
        let candidateDigest = try InstallationInventory.digest(candidate)
        let grant = try digest(.authorityGrant, .array([.bytes(authority.accountID), identity(authorityOwner),
            .array([.text(app.teamID), .text(app.identifier), .bytes(app.codeDirectoryHash)])]))
        let consent = try digest(.targetConsent, .array([.bytes(target.accountID), identity(targetOwner), stableImportChoices(inputs)]))
        let intent = try administratorIntent(purpose: purpose, authority: authority, target: target,
            release: inventory.releaseDigest, candidate: candidateDigest, operation: operation)
        return try .init(scope: .init(macID: inventory.macID, installationID: inventory.installationID,
            authority: authority, target: target, releaseDigest: inventory.releaseDigest, candidateDigest: candidateDigest,
            authorityPolicyDigest: digest(.authorityPolicy, .bytes(host.codePolicy.bytes)), operationDigest: operation,
            restorationDigest: restoration, mutationFootprintDigest: footprint, authorityGrantDigest: grant,
            targetConsentDigest: consent, administratorIntentDigest: intent))
    }
    func requireImmutableScope(_ expected: RuntimeMaintenanceWindowRecord.Scope, purpose: RuntimeMaintenanceWindowRecord.Purpose) throws {
        let actual = scope
        guard actual.macID == expected.macID, actual.installationID == expected.installationID,
              actual.authority == expected.authority, actual.target == expected.target,
              actual.releaseDigest == expected.releaseDigest, actual.candidateDigest == expected.candidateDigest,
              actual.operationDigest == expected.operationDigest,
              actual.authorityPolicyDigest == expected.authorityPolicyDigest, actual.restorationDigest == expected.restorationDigest,
              actual.mutationFootprintDigest == expected.mutationFootprintDigest, actual.authorityGrantDigest == expected.authorityGrantDigest,
              actual.targetConsentDigest == expected.targetConsentDigest,
              try Self.administratorIntent(purpose: purpose, authority: expected.authority, target: expected.target,
                release: expected.releaseDigest, candidate: expected.candidateDigest, operation: expected.operationDigest) == expected.administratorIntentDigest else {
            throw RuntimePreparationError.changedScope
        }
    }
    private static func administratorIntent(purpose: RuntimeMaintenanceWindowRecord.Purpose,
        authority: RuntimeMaintenanceWindowRecord.Account, target: RuntimeMaintenanceWindowRecord.Account,
        release: Data, candidate: Data, operation: Data) throws -> Data {
        try digest(.administratorIntent, .array([.unsigned(purpose.rawValue), .bytes(authority.accountID),
            .bytes(target.accountID), .bytes(release), .bytes(candidate), .bytes(operation)]))
    }
    func requirePolicy(_ policy: AuthorityCodePolicy) throws {
        guard try Self.digest(.authorityPolicy, .bytes(policy.bytes)) == scope.authorityPolicyDigest else {
            throw RuntimePreparationError.changedScope
        }
    }
    private struct OperationManifest {
        let purpose: RuntimeMaintenanceWindowRecord.Purpose
        let entry: MachineUpdateRetainedSetupInitialRuntimeEntry
        let initial: AuthorityInitializationIntent
        let choices: CBORValue
        var digest: Data { get throws {
            let runtime = entry.runtime
            return try RuntimeMaintenanceCommitments.digest(.operation, .array([.unsigned(purpose.rawValue),
                .bytes(runtime.preparation.bytes), .bytes(initial.bytes), .bytes(runtime.plan.encoded), choices]))
        } }
    }
    /// Compares declarations only. A matching digest grants no startup custody.
    static func requireStartupRestoration(_ window: RuntimeMaintenanceWindowRecord,
        initial: AuthorityInitializationIntent, host: InstalledAuthorityCommandConfiguration,
        inventory: InstallationInventory, candidate: SignedReleaseEvidence) throws {
        try requireProfile(window.purpose)
        guard try RestorationDeclarations(initial: initial, host: host, inventory: inventory).digest == window.scope.restorationDigest,
              try digest(.authorityPolicy, .bytes(host.codePolicy.bytes)) == window.scope.authorityPolicyDigest,
              try InstallationInventory.digest(candidate) == window.scope.candidateDigest else {
            throw RuntimePreparationError.changedScope
        }
    }
    private struct RestorationDeclarations {
        let initial: AuthorityInitializationIntent
        let host: InstalledAuthorityCommandConfiguration
        let inventory: InstallationInventory
        var digest: Data { get throws {
            try RuntimeMaintenanceCommitments.digest(.restoration, .array([.bytes(initial.bytes),
                .bytes(host.canonicalBytes), .bytes(inventory.canonicalBytes)]))
        } }
    }
    /// Fixed declarations only. Matching one of these paths grants no write or native authority.
    struct MutationFootprint {
        struct Declaration: Equatable {
            let tables: [String], directories: [String], files: [String], staging: [String]
            func containsFile(_ relativePath: String) -> Bool {
                if files.contains(relativePath) { return true }
                return staging.contains { pattern in
                    let prefix = String(pattern.dropLast("{UUID}".count))
                    guard relativePath.hasPrefix(prefix) else { return false }
                    return UUID(uuidString: String(relativePath.dropFirst(prefix.count))) != nil
                }
            }
        }
        let runtime: MachineUpdateStableRuntimePreparationSnapshot
        let inputs: MachineUpdateRetainedSetupRuntimeInputs
        var digest: Data { get throws {
            let value = try declaration
            return try RuntimeMaintenanceCommitments.digest(.mutationFootprint, .array([
                .bytes(runtime.preparation.accountID), strings(value.tables), strings(value.directories),
                strings(value.files), strings(value.staging)]))
        } }
        var declaration: Declaration { get throws {
            let paths = try RuntimePreparationPaths(accountID: runtime.preparation.accountID)
            guard let transport = runtime.plan.claims.first(where: { $0.role == .transport }) else {
                throw RuntimePreparationError.incomplete
            }
            let shared = RuntimePreparationPaths.sharedDirectory, machine = MachineBootstrap.machineDirectory
            let uid = runtime.preparation.ownerUID
            let publications: [(String, AdministrativeSetupPublication.File)] = [
                (paths.privateDirectory, .elevationPolicy), (paths.privateDirectory, .commandConfiguration),
                (paths.serviceDirectory, .transportIdentity(ownerUID: transport.number, groupID: transport.number)),
                (paths.serviceDirectory, .transportConfiguration), (paths.serviceDirectory, .gatewaySettingsHost),
                (shared, .presenceClient(ownerUID: uid)), (shared, .pairingClient(ownerUID: uid)), (shared, .frontendClient(ownerUID: uid))]
            let directories = [shared, shared + "/Services", paths.serviceDirectory, paths.privateDirectory]
            var finalFiles = publications.map { $0.0 + "/" + $0.1.name }
            finalFiles.append(paths.privateDirectory + "/" + AdministrativeSetupPublication.File.runtimeRecord.name)
            finalFiles += ServiceAccountPlan.roles.map { paths.serviceDirectory + "/" + ServiceReleaseActivityBarrier.fileName($0) }
            let journal = paths.authorityDirectory + "/Journal/journal.sqlite"
            let continuity = paths.authorityDirectory + "/Continuity/continuity.sqlite"
            var databases = [machine + "/installation.sqlite", journal, continuity]
            var tables = ["machine/runtime_preparation_v1", "machine/" + MachineUpdateRetainedSetupPolicyStorage.tableName,
                "target-journal/authority_code_policy_v1", "target-continuity/continuity_v1"]
            if inputs.intent != nil {
                databases.append(machine + "/SharedSetupImport/setup-import.sqlite")
                tables.append("shared-import/shared_setup_import_v2")
            }
            finalFiles += databases.flatMap { [$0, $0 + "-journal"] }
            let staging = Set(publications.map { $0.0 } + [paths.privateDirectory]).map { $0 + "/.remozio-setup-{UUID}" }
                + [paths.serviceDirectory + "/.remozio-service-activity-{UUID}"]
            return try .init(tables: tables.sorted(), directories: directories.map(Self.relative).sorted(),
                files: finalFiles.map(Self.relative).sorted(), staging: staging.map(Self.relative).sorted())
        } }
        static func relative(_ path: String) throws -> String {
            guard path.hasPrefix(RuntimePreparationPaths.sharedDirectory + "/") || path == RuntimePreparationPaths.sharedDirectory,
                  !path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else {
                throw RuntimePreparationError.changedScope
            }
            return path == RuntimePreparationPaths.sharedDirectory ? "."
                : String(path.dropFirst(RuntimePreparationPaths.sharedDirectory.count + 1))
        }
    }
    private static func account(_ id: Data, owner: LocalAccountIdentity) throws -> RuntimeMaintenanceWindowRecord.Account {
        try .init(accountID: id, ownerUID: owner.uid, directoryID: uuid(owner.directoryID))
    }
    private static func identity(_ owner: LocalAccountIdentity) -> CBORValue {
        .array([.unsigned(UInt64(owner.uid)), .unsigned(UInt64(owner.primaryGroupID)), .bytes(uuid(owner.directoryID))])
    }
    private static func uuid(_ value: UUID) -> Data { var raw = value.uuid; return withUnsafeBytes(of: &raw) { Data($0) } }
    private static func optional(_ value: Data?) -> CBORValue { value.map(CBORValue.bytes) ?? .null }
    private static func strings(_ values: [String]) -> CBORValue { .array(values.map(CBORValue.text)) }
    private static func stableImportChoices(_ inputs: MachineUpdateRetainedSetupRuntimeInputs) throws -> CBORValue {
        let intent: CBORValue
        if let value = inputs.intent {
            let scope = value.scope
            intent = .array([.bytes(scope.macID), .bytes(scope.installationID), .bytes(scope.releaseDigest),
                .bytes(scope.accountID), .unsigned(UInt64(scope.ownerUID)), .bytes(scope.accountBinding),
                .bytes(value.operationID), .bytes(value.proposalDigest), .bytes(try value.recipe.bytes), .unsigned(value.originalPortableVersion)])
        } else { intent = .null }
        return .array([.unsigned(inputs.journalPresent ? 1 : 0), intent,
            optional(inputs.relay?.plan?.bytes), optional(inputs.relay?.snapshot?.digest)])
    }
    private static func digest(_ domain: Domain, _ value: CBORValue) throws -> Data {
        Data(SHA256.hash(data: try DeterministicCBOR.encode(
            .array([.text("remozio.maintenance." + domain.rawValue + (domain == .targetConsent || domain == .operation ? ".v2" : ".v1")), value]),
            limits: .init(maxBytes: 2 * 1024 * 1024, maxDepth: 8, maxItems: 4096))))
    }
}
