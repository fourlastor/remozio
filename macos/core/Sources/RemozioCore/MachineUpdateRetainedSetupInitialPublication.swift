import Darwin
import Foundation

/// Publishes eight initial files. The native caller must prove identity, placement and file custody separately.
enum MachineUpdateRetainedSetupInitialPublication {
    typealias Selection = MachineUpdateRetainedSetupInitialSelection
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    struct Scope {
        fileprivate let checked: () throws -> Selection
        func read() throws -> Selection { try checked() }
        func verify() throws { _ = try read() }
    }
    /// A new invocation reads actual files. Callbacks must not change metadata or replay uncertain operations.
    static func prepare(selection: Selection, selectionScope: Selection.Scope,
        machine: PreparationIntentStore, expected: Snapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, fileCustodyAccepted: Bool,
        verifyCurrent: @escaping (Snapshot) throws -> Void, verifyServices: @escaping (ServiceAccountPlan) throws -> Void,
        readPolicyBoundary: @escaping () throws -> AuthorityJournal.MachineUpdatePolicyBoundary,
        readMaterial: @escaping (Scope) throws -> RuntimePreparationMaterial,
        verifyActivity: @escaping (ServiceReleaseActivityReference, Scope) throws -> Void,
        readArtifact: (RuntimePublishedArtifactValidation.Artifact, Scope) throws -> Data?,
        publish: (Selection, RuntimePreparationMaterial, Scope) throws -> Void,
        didStage: (RuntimePublicationController.Stage) throws -> Void = { _ in },
        inspectScope: (Scope) throws -> Void = { _ in }) throws -> Selection {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        guard let record = expected.intent, record.phase == .recorded,
              !expected.activation.runtime.state.configurationPublished,
              let reference = expected.activation.runtime.state.reference else { throw RuntimeActivationError.incomplete }
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        let processID = getpid(), thread = pthread_self(), digest = selection.digest
        var active = true, reading = false, checking = false, violated = false
        weak var writer = machine
        var currentVerification: ((Snapshot) throws -> Void)? = verifyCurrent
        var serviceVerification: ((ServiceAccountPlan) throws -> Void)? = verifyServices
        var boundaryReader: (() throws -> AuthorityJournal.MachineUpdatePolicyBoundary)? = readPolicyBoundary
        defer { active = false; writer = nil; currentVerification = nil; serviceVerification = nil; boundaryReader = nil }
        func lifetime() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0,
                  active, !violated, writer != nil else { throw JournalLeaseError.invalidated }
        }
        func read() throws -> Selection {
            try lifetime()
            guard !reading else { violated = true; throw PreparationStoreError.transactionActive }
            reading = true; defer { reading = false }
            guard let writer, let currentVerification, let serviceVerification, let boundaryReader else {
                throw JournalLeaseError.invalidated
            }
            let boundary = expected.activation.runtime.setup.source.actual.admission.machine
            try admission.validateMachineBoundary(directory: directory, expected: boundary)
            let actual = try writer.retainedSetupPolicySnapshot(owner: expected.activation.runtime.setup.owner, candidate: candidate)
            try actual.requireSame(as: expected); try currentVerification(actual); try lifetime()
            try serviceVerification(actual.activation.runtime.plan); try lifetime()
            let pair = try boundaryReader(); try record.requireRecorded(pair)
            try selection.configuration.binding.requireSourceForPublication(actual, current: pair, candidate: candidate)
            let selected = try selectionScope.read(); try selected.requireSame(as: selection)
            guard selected.digest == digest else { throw RuntimeActivationError.changedScope }
            try writer.retainedSetupPolicySnapshot(owner: expected.activation.runtime.setup.owner, candidate: candidate).requireSame(as: expected)
            try record.requireRecorded(boundaryReader())
            try admission.validateMachineBoundary(directory: directory, expected: boundary); try lifetime(); return selected
        }
        let sourceScope = Scope(checked: read)
        try sourceScope.verify(); try inspectScope(sourceScope); try sourceScope.verify()
        let material = try readMaterial(sourceScope); try sourceScope.verify()
        guard try material.reference == reference else { throw RuntimePreparationError.conflictingMaterial }
        guard let activity = material.serviceActivity else { throw RuntimePreparationError.incomplete }
        try reference.validate(account: expected.activation.runtime.preparation, services: expected.activation.runtime.plan)
        try sourceScope.verify(); try didStage(.materialRestored); try sourceScope.verify()
        func verify() throws -> Selection {
            try lifetime()
            guard !checking else { violated = true; throw PreparationStoreError.transactionActive }
            checking = true; defer { checking = false }
            let current = try sourceScope.read()
            let retained = try readMaterial(sourceScope)
            guard try retained.encoded == material.encoded else { throw RuntimePreparationError.conflictingMaterial }
            try sourceScope.verify(); try verifyActivity(activity, sourceScope); try sourceScope.verify(); return current
        }
        let scope = Scope(checked: verify)
        try scope.verify()
        let artifacts = try RuntimePublishedArtifactValidation.artifacts(bundle: selection.configuration.bundle, material: material)
        guard artifacts.count == 8, Set(artifacts.map(\.path)).count == 8 else { throw RuntimePreparationError.incomplete }
        for artifact in artifacts {
            try scope.verify(); let present = try readArtifact(artifact, scope); try scope.verify()
            if let present, present != artifact.bytes { throw AdministrativeSetupPublicationError.conflictingConfiguration }
        }
        try scope.verify(); try publish(selection, material, scope); try scope.verify()
        for artifact in artifacts {
            try scope.verify(); let actual = try readArtifact(artifact, scope); try scope.verify()
            guard actual == artifact.bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
        }
        try scope.verify(); try didStage(.filesPublished); try scope.verify(); return selection
    }
}
