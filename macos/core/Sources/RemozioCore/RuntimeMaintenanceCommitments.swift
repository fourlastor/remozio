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
        try requireProfile(purpose)
        let entry = binding.entry, runtime = entry.runtime, inventory = runtime.setup.source.actual.inventory
        try inputs.requireSource(runtime)
        guard let targetInitial = runtime.setup.account?.initialization,
              let app = binding.publishedAuthorityPolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw RuntimePreparationError.incomplete
        }
        let (initial, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(
            runtime: runtime, accountID: binding.authorityAccountID)
        let authority = try account(binding.authorityAccountID, owner: binding.authorityOwner)
        let target = try account(runtime.preparation.accountID, owner: binding.targetOwner)
        let choices = try importChoices(inputs)
        let operation = try OperationManifest(purpose: purpose, entry: entry, initial: targetInitial, choices: choices).digest
        let restoration = try RestorationDeclarations(initial: initial, host: host, inventory: inventory).digest
        let footprint = try MutationFootprint(runtime: runtime, inputs: inputs).digest
        let candidateDigest = try InstallationInventory.digest(candidate)
        let grant = try digest(.authorityGrant, .array([.bytes(authority.accountID), identity(binding.authorityOwner),
            .array([.text(app.teamID), .text(app.identifier), .bytes(app.codeDirectoryHash)])]))
        let consent = try digest(.targetConsent, .array([.bytes(target.accountID), identity(binding.targetOwner), choices]))
        let intent = try digest(.administratorIntent, .array([.unsigned(purpose.rawValue), .bytes(authority.accountID),
            .bytes(target.accountID), .bytes(inventory.releaseDigest), .bytes(candidateDigest), .bytes(operation)]))
        return try .init(scope: .init(macID: inventory.macID, installationID: inventory.installationID,
            authority: authority, target: target, releaseDigest: inventory.releaseDigest, candidateDigest: candidateDigest,
            authorityPolicyDigest: digest(.authorityPolicy, .bytes(binding.publishedAuthorityPolicy.bytes)),
            operationDigest: operation, restorationDigest: restoration, mutationFootprintDigest: footprint,
            authorityGrantDigest: grant, targetConsentDigest: consent, administratorIntentDigest: intent))
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
                .bytes(runtime.preparation.bytes), .bytes(initial.bytes), .bytes(runtime.plan.encoded),
                optional(runtime.state.reference?.encoded), .unsigned(runtime.state.configurationPublished ? 1 : 0),
                optional(entry.intent?.encoded), choices]))
        } }
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
    private struct MutationFootprint {
        let runtime: MachineUpdateStableRuntimePreparationSnapshot
        let inputs: MachineUpdateRetainedSetupRuntimeInputs
        var digest: Data { get throws {
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
            return try RuntimeMaintenanceCommitments.digest(.mutationFootprint, .array([
                .bytes(runtime.preparation.accountID), strings(tables.sorted()),
                strings(try directories.map(relative).sorted()), strings(try finalFiles.map(relative).sorted()),
                strings(try staging.map(relative).sorted())]))
        } }
        private func relative(_ path: String) throws -> String {
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
    private static func importChoices(_ inputs: MachineUpdateRetainedSetupRuntimeInputs) throws -> CBORValue {
        .array([.unsigned(inputs.journalPresent ? 1 : 0), optional(try inputs.intent?.bytes),
            optional(inputs.relay?.plan?.bytes), optional(inputs.relay?.snapshot?.digest)])
    }
    private static func digest(_ domain: Domain, _ value: CBORValue) throws -> Data {
        Data(SHA256.hash(data: try DeterministicCBOR.encode(
            .array([.text("remozio.maintenance." + domain.rawValue + ".v1"), value]),
            limits: .init(maxBytes: 2 * 1024 * 1024, maxDepth: 8, maxItems: 4096))))
    }
}
