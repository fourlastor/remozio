import Darwin
import Foundation

/// Publishes a pending pause record and removes only its exact completed successor.
/// The authorized owner retains its machine/release scope; this helper never advances transition phases.
enum GatewayRuntimeSettingsFencePublication {
    typealias Removal = GatewaySettingsFenceRemoval.Result
    struct Scope {
        let plan: GatewayRuntimeSettingsPublicationPlan
        let machine: PreparationIntentStore
        let account: AccountPreparationIntent
        let foreground: RuntimeActivationPlan
        let inventory: InstallationInventory
        var fence: GatewayRuntimeSettingsFence { get throws { try .init(plan) } }
        func validateCommon() throws {
            try machine.validateAccountPreparation(account)
            let services = plan.pair.authority.material.runtime.services
            try services.validate(account: account)
            let activeForeground = try machine.runtimeActivation(accountID: account.accountID)
            guard activeForeground.jobsRegistered, try machine.inventory() == inventory,
                  inventory.macID == services.macID, inventory.installationID == services.installationID,
                  inventory.releaseDigest == services.releaseDigest,
                  try activeForeground.plan?.encoded == foreground.encoded else {
                throw GatewayPreparationError.changedScope
            }
            let runtime = try machine.gatewayRuntimeActivation(accountID: account.accountID)
            guard runtime.filesPublished, runtime.jobRegistered, try runtime.plan?.encoded == plan.activation.encoded else {
                throw GatewayPreparationError.changedScope
            }
        }
        func validatePending() throws {
            try validateCommon()
            let state = try machine.gatewaySettingsTransition(accountID: account.accountID)
            guard try state.pending?.encoded == plan.revision.encoded, state.phase != nil else { throw GatewayPreparationError.changedScope }
            let expected = try GatewayRuntimeSettingsPublicationPlan(revision: plan.revision, previous: state.active,
                activation: plan.activation, journal: machine.gatewayJournalPreparation(accountID: account.accountID),
                foreground: foreground, inventory: inventory)
            guard try GatewayRuntimeSettingsFence(expected).encoded == fence.encoded else { throw GatewayPreparationError.changedScope }
        }
        func validateComplete() throws {
            try validateCommon()
            let state = try machine.gatewaySettingsTransition(accountID: account.accountID)
            guard state.pending == nil, state.phase == nil, try state.active?.encoded == plan.revision.encoded else {
                throw GatewayPreparationError.changedScope
            }
        }
    }
    static func prepare(_ scope: Scope, release: SignedReleaseEvidence,
                        verifyCurrent: () throws -> Void) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        func verify() throws {
            try verifyCurrent(); try scope.validatePending()
            try scope.foreground.host.validateRelease(release, bundlePath: scope.inventory.bundlePath)
            try GatewayRuntimeSettingsFenceReleaseValidation.validate(release, policy: scope.foreground.host.codePolicy)
        }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: scope.account.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        return try publish(scope, directory: directory, owner: 0, verifyCurrent: verify)
    }
    static func removeCompleted(_ scope: Scope, release: SignedReleaseEvidence,
                                verifyCurrent: () throws -> Void) throws -> Removal {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        func verify() throws {
            try verifyCurrent(); try scope.validateComplete()
            try scope.foreground.host.validateRelease(release, bundlePath: scope.inventory.bundlePath)
            try GatewayRuntimeSettingsFenceReleaseValidation.validate(release, policy: scope.foreground.host.codePolicy)
        }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: scope.account.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        return try remove(scope, directory: directory, owner: 0, verifyCurrent: verify)
    }
    // Owned fixtures use real protected files and retained state. They do not prove native Root admission.
    static func publish(_ scope: Scope, directory: ProtectedSetupDirectory, owner: uid_t,
                        verifyCurrent: () throws -> Void,
                        didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        func verify() throws { try verifyCurrent(); try scope.validatePending(); try directory.validate() }
        try verify()
        return try AdministrativeSetupPublication.publish(scope.fence.encoded, file: .gatewaySettingsFence,
            directory: directory, owner: owner, verify: verify, didStage: didStage)
    }
    private static func validateSelected(_ scope: Scope, directory: ProtectedSetupDirectory, owner: uid_t,
                                         verify: () throws -> Void) throws {
        let fence = try scope.fence
        func read(_ file: AdministrativeSetupPublication.File) throws -> Data {
            try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: owner, privateFile: file.mode == 0o600)
        }
        for target in [GatewayRuntimeExtension.Target.authority, .transport] {
            guard let loaded = try GatewayRuntimeLoader.load(target: target, read: read, verifyCurrent: verify, validate: {
                if target == .authority { try $0.validate(authority: scope.foreground.host) }
                else { try $0.validate(transport: scope.foreground.transport) }
            }), try loaded.commit.encoded == fence.selected.encoded else { throw GatewayPreparationError.changedScope }
        }
    }
    static func remove(_ scope: Scope, directory: ProtectedSetupDirectory, owner: uid_t,
                       verifyCurrent: () throws -> Void, didValidate: () throws -> Void = {},
                       didRemove: () throws -> Void = {}) throws -> Removal {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        let bytes = try scope.fence.encoded
        func verify() throws { try verifyCurrent(); try scope.validateComplete(); try directory.validate() }
        try verify(); try validateSelected(scope, directory: directory, owner: owner, verify: verify)
        return try GatewaySettingsFenceRemoval.remove(bytes, directory: directory, owner: owner, verifyCurrent: {
            try verify(); try validateSelected(scope, directory: directory, owner: owner, verify: verify)
        }, didValidate: didValidate, didRemove: didRemove)
    }
}
