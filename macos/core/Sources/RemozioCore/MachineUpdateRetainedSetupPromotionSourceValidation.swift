import Darwin
import Foundation

/// Checks the actual pair and source bytes. This value grants no publication, writer or native health authority.
enum MachineUpdateRetainedSetupPromotionSourceValidation {
    typealias Snapshot = MachineUpdateRetainedSetupCompletionSnapshot
    typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    typealias Verify = () throws -> Void
    enum PairKind: Equatable { case startup, receiptPending, recorded }

    static func kind(_ status: Snapshot.PairStatus) -> PairKind {
        switch status {
        case .startup: return .startup
        case .completionReceiptPending: return .receiptPending
        case .completionRecorded: return .recorded
        }
    }

    /// Pins the complete boundary and classification. A regenerated proposal revision is not a pair change.
    static func withPinnedPair<Value>(completion: Snapshot,
        readPolicyBoundary: () throws -> Boundary, verifyCurrent: Verify,
        perform: (Boundary, PairKind, @escaping Verify) throws -> Value) throws -> Value {
        try verifyCurrent()
        let expected = try readPolicyBoundary(), classification = try kind(completion.classifyPair(expected))
        try verifyCurrent()
        func verify() throws {
            try verifyCurrent()
            let actual = try readPolicyBoundary()
            guard actual == expected else { throw PreparationStoreError.staleRevision }
            guard try kind(completion.classifyPair(actual)) == classification else { throw PreparationStoreError.staleRevision }
            try verifyCurrent()
        }
        return try MachineUpdateRetainedSetupPromotionNativeSupport.withScopedVerification(verify) { current in
            try current()
            let result = try perform(expected, classification, current)
            try current(); return result
        }
    }

    /// Uses G4's native proof and G3's fixed read-only paths. Both paired stores close before this function returns.
    static func captureNative(expected: Snapshot, material: RuntimePreparationMaterial,
        candidate: SignedReleaseEvidence, native: MachineUpdateRetainedSetupPromotionNativeContext.NativeContext)
        throws -> RuntimeRetainedSetupCompletionPublication {
        try native.verify(expected)
        guard let initial = expected.activation.runtime.setup.account?.initialization else { throw RuntimeActivationError.incomplete }
        let paths = try MachineUpdateRetainedSetupPromotionNativeSupport.Paths(accountID: initial.accountID,
            journalPath: initial.journalPath, continuityPath: initial.continuityPath)
        return try MachineUpdateRetainedSetupPromotionNativeSupport.withReadOnlyPair(initial: initial,
            verifyCurrent: { try native.verify(expected) }, openStorage: {
                try MachineUpdateRetainedSetupPromotionNativeSupport.openExistingStorage(initial: initial,
                    openJournalLease: { try ProtectedJournalLease.acquire(directoryPath: paths.journalDirectory) },
                    openContinuityLease: { try ProtectedContinuityLease.acquire(directoryPath: paths.continuityDirectory,
                        excludingDirectory: $0) })
            }) { journal, current in
                try capture(expected: expected, material: material, candidate: candidate,
                    readPolicyBoundary: { try journal.captureRetainedSetupPolicyBoundary(expected: initial) },
                    verifyCurrent: current, read: { artifact in
                        if let plan = expected.activation.state.plan,
                           let job = [plan.authorityJob, plan.transportJob].first(where: { $0.path == artifact.path }) {
                            guard artifact.access == .publicRoot, artifact.bytes == job.bytes else { throw RuntimeActivationError.changedScope }
                            let directory = try ProtectedSetupDirectory(anchor: "/",
                                relativePath: String(InstalledAccountJobManifest.directory.dropFirst()), owner: 0,
                                visibility: .sharedMetadata, createIfMissing: false)
                            defer { directory.close() }
                            return try retainedJobBytes(job, directory: directory, owner: 0)
                        }
                        return try RuntimePublishedArtifactValidation.nativeRead(artifact)
                    })
            }
    }

    /// Owned controls check source values and ordering only. They cannot construct a native custody proof.
    static func capture(expected: Snapshot, material: RuntimePreparationMaterial, candidate: SignedReleaseEvidence,
        readPolicyBoundary: () throws -> Boundary, verifyCurrent: Verify, read: (Artifact) throws -> Data)
        throws -> RuntimeRetainedSetupCompletionPublication {
        try expected.requireSame(as: .init(activation: expected.activation, intent: expected.intent, candidate: candidate))
        guard expected.intent?.phase == .recorded,
              [Int64(26), 27].contains(expected.activation.runtime.setup.source.actual.schemaVersion),
              let plan = expected.activation.state.plan else { throw RuntimeActivationError.incomplete }
        return try withPinnedPair(completion: expected, readPolicyBoundary: readPolicyBoundary,
            verifyCurrent: verifyCurrent) { pair, classification, current in
                guard classification == .recorded else { throw RuntimeActivationError.incomplete }
                var captured: [String: Artifact] = [:]
                func pinnedRead(_ artifact: Artifact) throws -> Data {
                    try current(); let bytes = try read(artifact); try current()
                    guard !bytes.isEmpty, bytes.count <= ProtectedServiceConfiguration.maximumBytes else {
                        throw AdministrativeSetupPublicationError.conflictingConfiguration
                    }
                    if let previous = captured[artifact.path] {
                        guard previous.access == artifact.access, previous.bytes == bytes else {
                            throw AdministrativeSetupPublicationError.conflictingConfiguration
                        }
                    } else { captured[artifact.path] = .init(path: artifact.path, bytes: bytes, access: artifact.access) }
                    return bytes
                }
                let runtime = expected.activation.runtime, owner = runtime.preparation.ownerUID
                let paths = try RuntimePreparationPaths(accountID: runtime.preparation.accountID)
                let materialArtifact = try Artifact(path: paths.privateDirectory + "/" + AdministrativeSetupPublication.File.runtimeRecord.name,
                    bytes: material.encoded, access: .privateRoot)
                guard try pinnedRead(materialArtifact) == materialArtifact.bytes else { throw RuntimePreparationError.conflictingMaterial }
                func client(_ file: AdministrativeSetupPublication.File) throws -> Data {
                    try pinnedRead(.init(path: RuntimePreparationPaths.sharedDirectory + "/" + file.name, bytes: Data(), access: .publicRoot))
                }
                let clients = try RuntimeActivationClients(presence: .decode(client(.presenceClient(ownerUID: owner))),
                    pairing: .decode(client(.pairingClient(ownerUID: owner))), frontend: .decode(client(.frontendClient(ownerUID: owner))))
                let originals = try activationArtifacts(plan)
                for _ in 0..<2 {
                    try expected.activation.validateCompletionFiles(plan: plan, material: material, completion: expected,
                        candidate: candidate, verifyCurrent: current, read: pinnedRead)
                    for artifact in originals {
                        guard try pinnedRead(artifact) == artifact.bytes else {
                            throw AdministrativeSetupPublicationError.conflictingConfiguration
                        }
                    }
                }
                guard try pinnedRead(materialArtifact) == materialArtifact.bytes else { throw RuntimePreparationError.conflictingMaterial }
                try current()
                let configuration = try RuntimeRetainedSetupCompletionConfiguration(snapshot: expected,
                    current: pair, candidate: candidate, clients: clients)
                let publication = try RuntimeRetainedSetupCompletionPublication(configuration: configuration, sourceClients: clients)
                try current(); return publication
            }
    }

    /// Uses the existing per-file metadata and byte rules. It creates or repairs no retained job.
    static func retainedJobBytes(_ job: InstalledAccountJobManifest, directory: ProtectedSetupDirectory, owner: uid_t) throws -> Data {
        guard let account = job.declaration.accountID else { throw AdministrativeSetupPublicationError.invalidArtifact }
        try AdministrativeSetupPublication.validateRetained(job.bytes,
            file: .accountJob(accountID: account, role: job.declaration.role), directory: directory, owner: owner)
        return job.bytes
    }

    /// Retains the donor's complete three-file activation set without a startup or health dependency.
    static func activationArtifacts(_ plan: RuntimeRetainedSetupActivationPlan) throws -> [Artifact] {
        let paths = try RuntimePreparationPaths(accountID: plan.accountID)
        return [.init(path: paths.privateDirectory + "/" + AdministrativeSetupPublication.File.commandHost.name,
            bytes: plan.host.canonicalBytes, access: .privateRoot)] + [plan.authorityJob, plan.transportJob].map {
                .init(path: $0.path, bytes: $0.bytes, access: .publicRoot)
            }
    }
}
