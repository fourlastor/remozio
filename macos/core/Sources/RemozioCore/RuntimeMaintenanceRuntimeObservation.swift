import Darwin
import Foundation

/// Read-only recovery evidence. A result grants no body replay, restoration, startup or gate release.
enum RuntimeMaintenanceRuntimeObservation {
    enum State: Equatable, Sendable { case old, new, partial, unknown }
    typealias Native = MachineUpdateRetainedSetupRuntimeNativeContext
    typealias Frame = Native.Frame
    typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    private struct Leaf { let path: String, access: RuntimePublishedArtifactValidation.Access }
    private struct Readers {
        let frame: () throws -> Frame
        let policy: () throws -> Boundary
        let material: (MachineUpdateStableRuntimePreparationSnapshot) throws -> RuntimePreparationMaterial?
        let leaf: (Leaf) throws -> Data?
        let lookup: (UInt32) throws -> LocalAccountIdentity
        let current: () throws -> Void
    }
    static func observeNative(window: RuntimeMaintenanceWindowRecord, expected: Frame,
        candidate: SignedReleaseEvidence, custody: Native.NativeCustody) -> State {
        guard getuid() == 0, geteuid() == 0 else { return .unknown }
        do {
            let runtime = expected.entry.runtime
            let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(
                runtime: runtime, accountID: window.scope.authority.accountID)
            let authorityHostPath = try RuntimePreparationPaths(accountID: window.scope.authority.accountID).privateDirectory
                + "/" + AdministrativeSetupPublication.File.commandHost.name
            func current() throws {
                try custody.requireActive()
                guard try ProtectedServiceConfiguration.read(path: authorityHostPath) == host.canonicalBytes else {
                    throw RuntimePreparationError.changedScope
                }
                guard let setup = host.codePolicy.entries.first(where: { $0.role == .setupController && $0.active }),
                      let app = host.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
                    throw RuntimePreparationError.changedScope
                }
                let policy = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
                    approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
                try DynamicCodeValidation.validateSelf(requirement: policy.requirement)
                guard try DynamicCodeValidation.selfPath() == MachineBootstrap.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath else {
                    throw RuntimePreparationError.changedScope
                }
                let release = try SignedReleaseInspection.inspect(URL(fileURLWithPath: MachineBootstrap.bundlePath),
                    teamID: app.teamID, appIdentifier: app.identifier)
                try MachineUpdateRetainedSetupPolicyNativeContext.requireRelease(release, approvedRuntime: runtime,
                    candidate: candidate, currentCodePolicy: host.codePolicy)
                try custody.requireActive()
            }
            try current()
            guard let initial = runtime.setup.account?.initialization else { throw RuntimePreparationError.incomplete }
            let paths = try MachineUpdateRetainedSetupPromotionNativeSupport.Paths(accountID: initial.accountID,
                journalPath: initial.journalPath, continuityPath: initial.continuityPath)
            return try MachineUpdateRetainedSetupPromotionNativeSupport.withReadOnlyPair(initial: initial, verifyCurrent: current,
                openStorage: {
                    try MachineUpdateRetainedSetupPromotionNativeSupport.openExistingStorage(initial: initial,
                        openJournalLease: { try ProtectedJournalLease.acquire(directoryPath: paths.journalDirectory) },
                        openContinuityLease: { try ProtectedContinuityLease.acquire(directoryPath: paths.continuityDirectory, excludingDirectory: $0) })
                }) { journal, paired in
                observe(window: window, candidate: candidate, readers: .init(frame: {
                    try current(); try paired()
                    return try Native.readCustodyFrame(expected: expected, candidate: candidate, openMachine: {
                        let machine = try PreparationIntentStore(lease: InstallationStorageLease.acquire(directoryPath: MachineBootstrap.machineDirectory),
                            macID: initial.macID, maximumRecords: 64, initialize: false, opening: .retainedPolicyVerification)
                        do {
                            try machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory)
                            try machine.requireRuntimeMaintenanceObservationWindow(window, candidate: candidate)
                            return machine
                        } catch { try? machine.close(); throw error }
                    }, lookupOwner: LocalAccountDirectory.lookup)
                }, policy: {
                    try current(); try paired()
                    return try journal.captureRetainedSetupPolicyBoundary(expected: initial)
                }, material: {
                    try MachineUpdateRetainedSetupRuntimeNativeFiles.readOptionalMaterial(runtime: $0, verifyCurrent: current)
                }, leaf: { leaf in
                    try current()
                    let value: Data?
                    switch leaf.access {
                    case .privateRoot: value = try ProtectedServiceConfiguration.readOptionalPrivate(path: leaf.path, kind: .root)
                    case .publicRoot: value = try ProtectedServiceConfiguration.readOptionalPublic(path: leaf.path)
                    case .servicePrivate(let uid): value = try ProtectedServiceConfiguration.readOptionalPrivate(path: leaf.path, kind: .service(uid))
                    }
                    try current(); return value
                }, lookup: LocalAccountDirectory.lookup, current: { try current(); try paired() }))
            }
        } catch { return .unknown }
    }
    /// Ordinary-owner readers exercise actual storage. Root cannot select their callbacks.
    static func observeOwned(window: RuntimeMaintenanceWindowRecord, candidate: SignedReleaseEvidence,
        readFrame: @escaping () throws -> Frame, readPolicy: @escaping () throws -> Boundary,
        readMaterial: @escaping (MachineUpdateStableRuntimePreparationSnapshot) throws -> RuntimePreparationMaterial?,
        readFile: @escaping (String, RuntimePublishedArtifactValidation.Access) throws -> Data?,
        lookup: @escaping (UInt32) throws -> LocalAccountIdentity, verifyCurrent: @escaping () throws -> Void) -> State {
        guard RuntimeMaintenanceOwnedControl.allows(realUID: getuid(), effectiveUID: geteuid()) else { return .unknown }
        return observe(window: window, candidate: candidate, readers: .init(frame: readFrame, policy: readPolicy,
            material: readMaterial, leaf: { try readFile($0.path, $0.access) }, lookup: lookup, current: verifyCurrent))
    }
    private static func observe(window: RuntimeMaintenanceWindowRecord, candidate: SignedReleaseEvidence, readers: Readers) -> State {
        do {
            try RuntimeMaintenanceCommitments.requireProfile(window.purpose)
            guard [.stopping, .stopped, .executing].contains(window.phase) else { return .unknown }
            let process = getpid(), thread = pthread_self()
            func current() throws {
                guard getpid() == process, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
                try readers.current()
            }
            try current(); let first = try readers.frame(), runtime = first.entry.runtime
            let a = try readers.lookup(window.scope.authority.ownerUID), b = try readers.lookup(window.scope.target.ownerUID)
            let observed = try RuntimeMaintenanceCommitments.observing(entry: first.entry, inputs: first.inputs,
                authorityAccountID: window.scope.authority.accountID, authorityOwner: a, targetOwner: b,
                candidate: candidate, purpose: window.purpose)
            try observed.requireImmutableScope(window.scope, purpose: window.purpose)
            let policy = try readers.policy(), material = try readers.material(runtime)
            if let reference = runtime.state.reference {
                guard let material, try material.reference == reference else { return .unknown }
            }
            if let material {
                try material.services.validate(account: runtime.preparation)
                guard try material.services.encoded == runtime.plan.encoded else { return .unknown }
                try material.reference.validate(account: runtime.preparation, services: runtime.plan)
            }
            let leaves = try publicationLeaves(runtime), values = try leaves.map { try readers.leaf($0) }
            let present = values.contains { $0 != nil }
            var recorded = false
            if let intent = first.entry.intent {
                _ = try intent.observeBoundary(policy)
                recorded = intent.phase == .recorded
            } else {
                guard let initial = runtime.setup.account?.initialization, policy.checkpoint == initial.checkpoint,
                      try policy.policy.policy.bytes == runtime.preparation.initialAuthority.codePolicy.bytes else { return .unknown }
            }
            if present {
                guard recorded, let material, let snapshot = first.entry.policy else { return .unknown }
                let bundle = try RuntimeConfigurationBundle.retainedSetupInitialObservation(snapshot: snapshot,
                    current: policy, candidate: candidate, inputs: first.inputs)
                let artifacts = try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: material)
                guard artifacts.count == leaves.count, Set(artifacts.map(\.path)) == Set(leaves.map(\.path)) else { return .unknown }
                for (leaf, actual) in zip(leaves, values) {
                    let expected = try artifacts.first(where: { $0.path == leaf.path }).unwrapMaintenanceArtifact()
                    guard leaf.access == expected.access, actual == nil || actual == expected.bytes else { return .unknown }
                }
            }
            let progressed = material != nil || runtime.state.reference != nil || first.entry.intent != nil
                || runtime.state.configurationPublished || present || first.inputs.intent?.phase == .runtimePublished
            let complete = recorded && runtime.state.configurationPublished && material?.serviceActivity != nil && values.allSatisfy { $0 != nil }
                && (first.inputs.intent == nil || first.inputs.intent?.phase == .runtimePublished)
            let second = try readers.frame(); try second.entry.requireSame(as: first.entry); try second.inputs.requireSame(as: first.inputs)
            guard try readers.policy() == policy, try readers.material(runtime)?.encoded == material?.encoded,
                  try leaves.map({ try readers.leaf($0) }) == values,
                  try readers.lookup(a.uid) == a, try readers.lookup(b.uid) == b else { return .unknown }
            try current()
            if complete { return .new }
            // Pre-existing valid partial files remain partial. Metadata equality never hides a mixed publication.
            if progressed { return .partial }
            return .old
        } catch { return .unknown }
    }
    private static func publicationLeaves(_ runtime: MachineUpdateStableRuntimePreparationSnapshot) throws -> [Leaf] {
        let paths = try RuntimePreparationPaths(accountID: runtime.preparation.accountID), shared = RuntimePreparationPaths.sharedDirectory
        guard let transport = runtime.plan.claims.first(where: { $0.role == .transport }) else { throw RuntimePreparationError.incomplete }
        return [
            .init(path: paths.policy, access: .privateRoot), .init(path: paths.commandConfiguration, access: .privateRoot),
            .init(path: paths.transportIdentity, access: .servicePrivate(transport.number)),
            .init(path: paths.transportConfiguration, access: .publicRoot),
            .init(path: paths.serviceDirectory + "/" + AdministrativeSetupPublication.File.gatewaySettingsHost.name, access: .publicRoot),
            .init(path: shared + "/" + AdministrativeSetupPublication.File.presenceClient(ownerUID: runtime.preparation.ownerUID).name, access: .publicRoot),
            .init(path: shared + "/" + AdministrativeSetupPublication.File.pairingClient(ownerUID: runtime.preparation.ownerUID).name, access: .publicRoot),
            .init(path: shared + "/" + AdministrativeSetupPublication.File.frontendClient(ownerUID: runtime.preparation.ownerUID).name, access: .publicRoot)]
    }
}

private extension Optional where Wrapped == RuntimePublishedArtifactValidation.Artifact {
    func unwrapMaintenanceArtifact() throws -> Wrapped {
        guard let value = self else { throw RuntimePreparationError.changedScope }; return value
    }
}
