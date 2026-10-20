import Darwin
import Foundation

/// Publish recovery scope for completed settings. The native owner retains its machine writer across each file operation.
enum GatewayRuntimeSettingsRecoveryPublication {
    typealias Removal = GatewaySettingsFenceRemoval.Result
    struct Scope {
        let plan: GatewayRuntimeSettingsRecoveryPlan
        let activation: GatewayRuntimeActivationPlan
        let machine: PreparationIntentStore
        let account: AccountPreparationIntent
        let foreground: RuntimeActivationPlan
        let inventory: InstallationInventory

        func validate() throws {
            try machine.validateAccountPreparation(account)
            let services = plan.pair.authority.material.runtime.services
            try services.validate(account: account)
            let current = try machine.runtimeActivation(accountID: account.accountID)
            let runtime = try machine.gatewayRuntimeActivation(accountID: account.accountID)
            guard current.jobsRegistered, runtime.filesPublished, runtime.jobRegistered,
                  try machine.inventory() == inventory,
                  inventory.macID == services.macID, inventory.installationID == services.installationID,
                  inventory.releaseDigest == services.releaseDigest, try current.plan?.encoded == foreground.encoded,
                  try runtime.plan?.encoded == activation.encoded,
                  let attempt = plan.fence.recoveryAttemptID else { throw GatewayPreparationError.changedScope }
            let expected = try GatewayRuntimeSettingsRecoveryPlan(state: machine.gatewaySettingsTransition(accountID: account.accountID),
                activation: activation, journal: machine.gatewayJournalPreparation(accountID: account.accountID),
                foreground: foreground, inventory: inventory, attemptID: attempt)
            guard try expected.fence.encoded == plan.fence.encoded else { throw GatewayPreparationError.changedScope }
        }
        func validateFiles(directory: ProtectedSetupDirectory, owner: uid_t, verify: () throws -> Void) throws {
            let selected: [(AdministrativeSetupPublication.File, Data)] = try [
                (.gatewayConfiguration, plan.gateway.canonicalBytes), (.authorityGatewayRuntime, plan.pair.authority.encoded),
                (.transportGatewayRuntime, plan.pair.transport.encoded), (.gatewaySettingsRevision, plan.revision.encoded),
                (.gatewayRuntimeCommit, plan.commit.encoded)
            ]
            for (file, bytes) in selected {
                try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verify)
            }
        }
        func verifyNative(_ release: SignedReleaseEvidence, verifyCurrent: () throws -> Void) throws {
            try verifyCurrent(); try validate()
            try foreground.host.validateRelease(release, bundlePath: inventory.bundlePath)
            _ = try GatewaySettingsRecoveryNativePolicy(role: .gateway, services: plan.pair.authority.material.runtime.services,
                codePolicy: foreground.host.codePolicy, release: release)
            guard let authority = foreground.host.codePolicy.entries.first(where: { $0.role == .authority && $0.active }) else {
                throw GatewayPreparationError.changedScope
            }
            let policy = try XPCPeerPolicy(teamID: authority.teamID, componentIdentifier: authority.identifier,
                approvedCodeDirectoryHashes: [authority.codeDirectoryHash], expectedUserID: 0)
            try DynamicCodeValidation.validateSelf(requirement: policy.requirement)
            try verifyCurrent(); try validate()
        }
    }
    static func prepare(_ scope: Scope, release: SignedReleaseEvidence, verifyCurrent: () throws -> Void,
                        requireRootPaused: () throws -> Void) throws -> GatewayRuntimeSettingsFileResult {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        func verify() throws { try scope.verifyNative(release, verifyCurrent: verifyCurrent); try requireRootPaused() }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: scope.account.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        return try publish(scope, directory: directory, owner: 0, verifyCurrent: verify, requireRootPaused: requireRootPaused)
    }
    static func removeAccepted(_ scope: Scope, release: SignedReleaseEvidence, verifyCurrent: () throws -> Void,
                               requireFreshAcceptance: () throws -> Void) throws -> Removal {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        func verify() throws { try scope.verifyNative(release, verifyCurrent: verifyCurrent); try requireFreshAcceptance() }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: scope.account.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { directory.close() }
        return try remove(scope, directory: directory, owner: 0, verifyCurrent: verify, requireFreshAcceptance: requireFreshAcceptance)
    }
    // Owned fixtures prove file custody and retained-state checks. They do not grant native Root admission.
    static func publish(_ scope: Scope, directory: ProtectedSetupDirectory, owner: uid_t,
                        verifyCurrent: () throws -> Void, requireRootPaused: () throws -> Void,
                        didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> GatewayRuntimeSettingsFileResult {
        func verify() throws { try verifyCurrent(); try requireRootPaused(); try scope.validate(); try directory.validate() }
        func verifySelected() throws { try verify(); try scope.validateFiles(directory: directory, owner: owner, verify: verify) }
        try verifySelected()
        let previous = try ProtectedServiceConfiguration.readOptional(anchor: directory.path,
            relativePath: AdministrativeSetupPublication.File.gatewaySettingsFence.name, owner: owner)
        try verifySelected()
        return try AdministrativeSetupPublication.replaceRecoveryFence(scope.plan.fence.encoded, expected: previous,
            directory: directory, owner: owner, verify: verifySelected, didStage: didStage)
    }
    static func remove(_ scope: Scope, directory: ProtectedSetupDirectory, owner: uid_t,
                       verifyCurrent: () throws -> Void, requireFreshAcceptance: () throws -> Void,
                       didValidate: () throws -> Void = {}, didRemove: () throws -> Void = {}) throws -> Removal {
        func verify() throws { try verifyCurrent(); try requireFreshAcceptance(); try scope.validate(); try directory.validate() }
        func verifySelected() throws { try verify(); try scope.validateFiles(directory: directory, owner: owner, verify: verify) }
        try verifySelected()
        return try GatewaySettingsFenceRemoval.remove(scope.plan.fence.encoded, directory: directory, owner: owner,
            verifyCurrent: verifySelected, didValidate: didValidate, didRemove: didRemove)
    }
}
