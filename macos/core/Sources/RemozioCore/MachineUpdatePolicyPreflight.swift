import Darwin
import Foundation
import RemozioProtocol

/// A live preflight only. It grants no exchange, publication, journal writer or floor authority.
struct MachineUpdatePolicyPreflight {
    let source: MachineUpdateRestartSource
    let policies: [MachineUpdatePolicyCapture]
    let digest: Data
    private let verify: () throws -> Void

    func validateExternal() throws { try verify() }

    static func captureNative(activation: MachineUpdateActivationRecord, configurationPath: String,
        machine: PreparationIntentStore, directory: ReleaseDestinationLease,
        quiescence: UpdateQuiescenceLease) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let host = try InstalledAuthorityCommandConfiguration.load(path: configurationPath)
        guard host.machineDirectory == MachineBootstrap.machineDirectory else { throw InstalledAuthorityCommandError.wrongInstallation }
        let source = try machine.machineUpdatePolicyPreflightSource(activation, directory: directory, quiescence: quiescence)
        let context = source.replacement, bundle = URL(fileURLWithPath: context.inventory.bundlePath)
        guard bundle.path == MachineBootstrap.bundlePath,
              host.command.macID == context.inventory.macID, host.installationID == context.inventory.installationID,
              let app = host.codePolicy.entries.first(where: { $0.role == .app && $0.active }),
              let root = host.codePolicy.entries.first(where: { $0.role == .authority && $0.active }) else {
            throw InstalledAuthorityCommandError.wrongInstallation
        }
        let installed = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        let prepared = try ReleaseDestinationLease.acquire(path: context.candidate.preparation.parent)
        let requirement = try AuthoritySelfValidation.requirement(for: root)
        func owner() throws {
            guard try DynamicCodeValidation.selfPath() == bundle.appendingPathComponent(InstalledAuthorityCommandConfiguration.executablePath).path,
                  try InstalledAuthorityCommandConfiguration.load(path: configurationPath).canonicalBytes == host.canonicalBytes else {
                throw InstalledAuthorityCommandError.wrongExecutable
            }
            try DynamicCodeValidation.validateSelf(requirement: requirement)
            _ = try installed.inspectInstalledApplication(name: bundle.lastPathComponent)
            let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            _ = try host.validate(inventory: context.inventory, release: release, bundlePath: bundle.path)
            try ReleaseCompatibilityPreflight.validate(release, policy: host.codePolicy,
                requirements: .init(formats: MachineUpdateActivationRecord.preflightRequirements, requests: []))
        }
        func candidate() throws -> SignedReleaseEvidence {
            try owner()
            guard try prepared.preparationAncestry() == context.candidate.preparation.ancestry,
                  try prepared.preparationCopyIdentity(name: context.candidate.preparation.bundleName) == context.candidate.preparation.copyIdentity else {
                throw MachineUpdateActivationError.changedScope
            }
            _ = try prepared.inspectCopiedTree(name: context.candidate.preparation.bundleName)
            return try SignedReleaseInspection.inspect(URL(fileURLWithPath: prepared.path).appendingPathComponent(context.candidate.preparation.bundleName),
                teamID: app.teamID, appIdentifier: app.identifier)
        }
        let value = try captureInLease(activation: activation, machine: machine, directory: directory, quiescence: quiescence,
            readPolicies: { try MachineUpdatePolicyRead.readNative(accounts: $0.accounts) }, inspectCandidate: candidate, verifyOwner: owner)
        guard value.policies.first(where: { $0.accountID == host.command.accountID })?.snapshot?.policy == host.codePolicy else {
            throw InstalledAuthorityCommandError.changedConfiguration
        }
        return value
    }

    /// Owned stores and injected code inspection only. The native factory separately authenticates the running Root and fixed placement.
    static func captureInLease(activation: MachineUpdateActivationRecord, machine: PreparationIntentStore,
        directory: ReleaseDestinationLease, quiescence: UpdateQuiescenceLease,
        readPolicies: @escaping (MachineUpdateRestartSource) throws -> [MachineUpdatePolicyCapture],
        inspectCandidate: @escaping () throws -> SignedReleaseEvidence,
        verifyOwner: @escaping () throws -> Void = {}) throws -> Self {
        let source = try machine.machineUpdatePolicyPreflightSource(activation, directory: directory, quiescence: quiescence)
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine)
        guard snapshot.inputs == source.replacement.runtime else { throw PreparationStoreError.staleRevision }
        try verifyOwner(); let candidate = try inspectCandidate()
        guard try DurableReleasePreparation.digest(candidate) == activation.updateID else { throw MachineUpdateActivationError.changedScope }
        try MachineUpdateActivationRecord.requirePreflightFormats(candidate)
        try verifyOwner(); let policies = try readPolicies(source)
        try requirePolicies(source: source, policies: policies, candidate: candidate, snapshot: snapshot)
        let digest = try policyDigest(source: source, policies: policies)
        let verify: () throws -> Void = {
            try quiescence.validateMachineBoundary(directory: directory, expected: source.replacement.admission.machine)
            try verifyOwner(); let current = try inspectCandidate()
            guard try DurableReleasePreparation.digest(current) == activation.updateID,
                  try InstallationInventory.digest(current) == InstallationInventory.digest(candidate) else {
                throw MachineUpdateActivationError.changedScope
            }
            let currentPolicies = try readPolicies(source)
            try requirePolicies(source: source, policies: currentPolicies, candidate: current, snapshot: snapshot)
            guard try policyDigest(source: source, policies: currentPolicies) == digest else { throw AuthorityCodePolicyError.staleRevision }
            try verifyOwner()
            try quiescence.validateMachineBoundary(directory: directory, expected: source.replacement.admission.machine)
        }
        try verify()
        guard try machine.machineUpdatePolicyPreflightSource(activation, directory: directory, quiescence: quiescence) == source else {
            throw PreparationStoreError.staleRevision
        }
        return .init(source: source, policies: policies, digest: digest, verify: verify)
    }
    private static func requirePolicies(source: MachineUpdateRestartSource,
        policies: [MachineUpdatePolicyCapture], candidate: SignedReleaseEvidence,
        snapshot: RuntimeReleaseCompatibilitySnapshot) throws {
        try validateCaptureSet(accounts: source.accounts, policies: policies)
        let declaresHistory = candidate.manifest.components.contains { component in
            component.formats.contains { $0.name == MachineUpdateProvisioningHistory.formatName }
        }
        if source.provisioningHistory != nil || declaresHistory {
            try MachineUpdatePreflightCompatibility.requireProvenanceFormats(candidate)
        }
        let declaresRetainedSetup = candidate.manifest.components.contains { component in
            component.formats.contains { $0.name == MachineUpdatePreflightCompatibility.retainedSetupFormatName }
        }
        if declaresRetainedSetup { try MachineUpdatePreflightCompatibility.requireRetainedSetupFormats(candidate) }
        for capture in policies {
            if let policy = capture.snapshot {
                _ = try MachineUpdatePolicyPlan(source: policy, candidate: candidate)
                try snapshot.validate(candidate, policy: policy.policy, verifyCurrent: {})
                try ReleaseCompatibilityPreflight.validate(candidate, policy: policy.policy,
                    requirements: .init(formats: MachineUpdateActivationRecord.preflightRequirements, requests: []))
            }
        }
    }
    private static func validateCaptureSet(accounts: [MachineUpdateRestartSource.Account],
                                           policies: [MachineUpdatePolicyCapture]) throws {
        guard accounts.count <= 128, Set(accounts.map(\.accountID)).count == accounts.count,
              Set(policies.map(\.accountID)).count == policies.count,
              Set(accounts.map(\.accountID)) == Set(policies.map(\.accountID)) else { throw MachineUpdateActivationError.changedScope }
        for account in accounts {
            let value = policies.first { $0.accountID == account.accountID }!
            if value.snapshot != nil {
                guard account.initialization != nil else { throw MachineUpdateActivationError.changedScope }
            } else if account.initialization?.complete == true { throw AuthoritySelfValidationError.unconfigured }
        }
    }

    static func policyDigest(source: MachineUpdateRestartSource,
                             policies: [MachineUpdatePolicyCapture]) throws -> Data {
        try validateCaptureSet(accounts: source.accounts, policies: policies)
        let accounts = try source.accounts.map { account in
            try PolicyDigestAccount(accountID: account.accountID, ownerUID: account.ownerUID,
                sourceDigest: source.accountDigest(accountID: account.accountID),
                policy: policies.first { $0.accountID == account.accountID }!.snapshot)
        }
        return try policyDigest(activation: source.replacement.activation, accounts: accounts)
    }
    typealias PolicyDigestAccount = MachineUpdatePolicyDigest.Account
    static func policyDigest(activation: MachineUpdateActivationRecord, accounts: [PolicyDigestAccount]) throws -> Data {
        try MachineUpdatePolicyDigest.make(activation: activation, accounts: accounts)
    }
    static func requireRetained(_ source: MachineUpdateRestartSource, policies: [MachineUpdatePolicyCapture]) throws {
        if let retained = source.replacement.activation.policyPreflightDigest {
            guard try policyDigest(source: source, policies: policies) == retained else { throw MachineUpdateActivationError.changedScope }
        }
    }
}

extension MachineUpdateRestartSource {
    func replacingActivation(_ activation: MachineUpdateActivationRecord) throws -> Self {
        let c = replacement, r = c.runtime
        let runtime = RuntimeReleaseCompatibilitySnapshot.Inputs(schemaVersion: r.schemaVersion, macID: r.macID,
            inventory: r.inventory, runtimes: r.runtimes, gateways: r.gateways, sharedImport: r.sharedImport,
            auditUpgrades: r.auditUpgrades, auditGraphs: r.auditGraphs, auditCutovers: r.auditCutovers,
            updateAdmissionRegistration: r.updateAdmissionRegistration, machineUpdateActivation: try activation.encoded)
        return .init(replacement: .init(activation: activation, inventory: c.inventory, candidate: c.candidate,
            admission: c.admission, replacement: c.replacement, runtime: runtime), accounts: accounts,
            provisioningHistory: provisioningHistory)
    }
}
