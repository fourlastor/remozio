import Darwin
import Foundation

/// Pins the completed Authority host before registering its separate readiness listener.
struct MachineUpdateAuthorityReadinessScope: Sendable {
    let host: InstalledAuthorityCommandConfiguration
    let requirement: MachineUpdateRestartHealthPlan.Requirement
    let rootPolicy: XPCPeerPolicy
    private let verifySelection: @Sendable () throws -> Void
    let acquireActivity: @Sendable () throws -> any OwnedReleaseActivity

    init(host: InstalledAuthorityCommandConfiguration, requirement: MachineUpdateRestartHealthPlan.Requirement,
        release: SignedReleaseEvidence, verifySelection: @escaping @Sendable () throws -> Void,
        acquireActivity: @escaping @Sendable () throws -> any OwnedReleaseActivity) throws {
        guard host.installedReadinessEnabled, host.jobPlacement == .systemAccount, requirement.role == .authority,
              requirement.executionUID == 0, requirement.binding.formatVersion == 2,
              requirement.binding.macID == host.command.macID, requirement.binding.accountID == host.command.accountID,
              requirement.binding.installationID == host.installationID, requirement.binding.installedReleaseDigest == host.releaseDigest,
              requirement.publicKey == host.command.presence.wake.request.authorityPublicKey,
              requirement.code == host.codePolicy.entries.first(where: { $0.role == .authority && $0.active }) else {
            throw MachineUpdateRoleChallengeError.changedScope
        }
        try requirement.binding.requireCompletionPolicy(host.codePolicy)
        try host.validateRelease(release, bundlePath: MachineBootstrap.bundlePath)
        let code = requirement.code
        rootPolicy = try .init(teamID: code.teamID, componentIdentifier: code.identifier,
            approvedCodeDirectoryHashes: [code.codeDirectoryHash], expectedUserID: 0)
        self.host = host; self.requirement = requirement; self.verifySelection = verifySelection
        self.acquireActivity = acquireActivity
    }
    var serviceName: String { get throws {
        try MachineUpdateAuthorityReadinessDeclaration.serviceName(accountID: requirement.binding.accountID)
    } }
    func validate() throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try DynamicCodeValidation.validateSelf(requirement: AuthoritySelfValidation.requirement(for: requirement.code))
        try verifySelection()
    }
}
