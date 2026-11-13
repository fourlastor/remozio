import Foundation
import RemozioProtocol

/// Proposed initial files for a retained account. This value grants no publication, enrollment, registration or request authority.
struct RuntimeRetainedSetupInitialConfiguration: CustomStringConvertible, CustomDebugStringConvertible {
    let binding: RuntimeRetainedSetupReleaseBinding
    let bundle: RuntimeConfigurationBundle
    let host: InstalledAuthorityCommandConfiguration
    var description: String { "RuntimeRetainedSetupInitialConfiguration(redacted)" }
    var debugDescription: String { description }

    init(snapshot: MachineUpdateRetainedSetupPolicySnapshot, current: AuthorityJournal.MachineUpdatePolicyBoundary,
        candidate: SignedReleaseEvidence, currentCodePolicy: AuthorityCodePolicy,
        importIntent: SharedSetupImportIntent? = nil, presencePolicyOverride: PresenceConfiguration? = nil,
        relayPlan: SharedSetupImportRelayPlan? = nil, relayPortOverride: UInt16? = nil) throws {
        binding = try .init(snapshot: snapshot, current: current, candidate: candidate)
        try binding.requireStartupPolicy(currentCodePolicy)
        bundle = try .retainedSetupInitial(snapshot: snapshot, current: current, candidate: candidate,
            currentCodePolicy: currentCodePolicy, importIntent: importIntent, presencePolicyOverride: presencePolicyOverride,
            relayPlan: relayPlan, relayPortOverride: relayPortOverride)
        let runtime = snapshot.activation.runtime, inventory = runtime.setup.source.actual.inventory
        let label = bundle.paths.namespace + ".authority"
        let initial = try InstalledAuthorityCommandConfiguration(machineDirectory: MachineBootstrap.machineDirectory,
            installationID: inventory.installationID, releaseDigest: inventory.releaseDigest, codePolicy: currentCodePolicy,
            command: bundle.command, label: label, plistName: label + ".plist", jobPlacement: .systemAccount)
        host = try initial.enablingGatewaySettingsControl(release: candidate)
        try host.validateRelease(candidate, bundlePath: inventory.bundlePath)
        guard host.installationID == binding.installationID, host.releaseDigest == binding.installedReleaseDigest,
              let gateway = try bundle.gatewaySettingsHost, gateway.retainedSetupBinding == binding,
              let transport = bundle.transport.settingsHost, transport.retainedSetupBinding == binding else {
            throw RuntimeActivationError.changedScope
        }
        try gateway.requireConfigurationScope(account: runtime.preparation, inventory: inventory)
        try transport.requireConfigurationScope(account: runtime.preparation, inventory: inventory)
        try gateway.validateRelease(candidate); try transport.validateRelease(candidate)
    }
    /// The publication owner supplies fresh machine and journal reads and retains its admission and native file checks.
    func requireSourceForPublication(snapshot: MachineUpdateRetainedSetupPolicySnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy, importIntent: SharedSetupImportIntent? = nil,
        presencePolicyOverride: PresenceConfiguration? = nil, relayPlan: SharedSetupImportRelayPlan? = nil,
        relayPortOverride: UInt16? = nil) throws {
        try binding.requireSourceForPublication(snapshot, current: current, candidate: candidate)
        let actual = try Self(snapshot: snapshot, current: current, candidate: candidate, currentCodePolicy: currentCodePolicy,
            importIntent: importIntent, presencePolicyOverride: presencePolicyOverride,
            relayPlan: relayPlan, relayPortOverride: relayPortOverride)
        guard try actual.digest == digest else { throw RuntimeActivationError.changedScope }
    }
    var digest: Data { get throws {
        let limits = try CBORLimits(maxBytes: 1_048_576, maxDepth: 1, maxItems: 17)
        let bytes = try DeterministicCBOR.encode(.map([
            0: .text("remozio/retained-setup-initial-configuration/v1"), 1: .bytes(binding.encoded),
            2: .bytes(host.canonicalBytes), 3: .bytes(bundle.transport.canonicalBytes),
            4: .bytes(bundle.presenceClient.canonicalBytes), 5: .bytes(bundle.pairingClient.canonicalBytes),
            6: .bytes(bundle.frontendClient.canonicalBytes), 7: .bytes(bundle.elevationPolicy.canonicalBytes)
        ]), limits: limits)
        return MachineUpdateActivationRecord.digest(bytes)
    } }
}
