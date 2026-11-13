import Darwin
import Foundation

/// Publishes eight initial files. The native caller proves identity, placement and file custody separately.
enum MachineUpdateRetainedSetupInitialPublication {
    typealias Selection = MachineUpdateRetainedSetupInitialSelection
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    /// Borrows checked values for one callback. It performs no snapshot, import, policy or material query.
    struct Scope: CustomStringConvertible, CustomDebugStringConvertible {
        fileprivate let check: (Bool) throws -> Void
        fileprivate let leave: () -> Void
        let selection: Selection
        let material: RuntimePreparationMaterial?
        let artifact: RuntimePublishedArtifactValidation.Artifact?
        var description: String { "RetainedSetupInitialPublicationScope(redacted)" }
        var debugDescription: String { description }
        func requireActive() throws { try check(false) }
        func withActive<Result>(_ body: () throws -> Result) throws -> Result {
            try check(true); defer { leave() }
            let result = try body(); try requireActive(); return result
        }
    }
    static func prepare(selection: Selection, selectionScope: Selection.Scope,
        machine: PreparationIntentStore, expected: Snapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, fileCustodyAccepted: Bool,
        verifyCurrent: (Snapshot) throws -> Void, verifyServices: (ServiceAccountPlan) throws -> Void,
        readMaterial: (Scope) throws -> RuntimePreparationMaterial,
        verifyActivity: (ServiceReleaseActivityReference, Scope) throws -> Void,
        readArtifact: (RuntimePublishedArtifactValidation.Artifact, Scope) throws -> Data?,
        publish: (Scope) throws -> Void,
        didStage: (RuntimePublicationController.Stage) throws -> Void = { _ in },
        inspectScope: (Scope) throws -> Void = { _ in }) throws -> Selection {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        guard let record = expected.intent, record.phase == .recorded,
              !expected.activation.runtime.state.configurationPublished,
              let reference = expected.activation.runtime.state.reference else { throw RuntimeActivationError.incomplete }
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        let processID = getpid(), thread = pthread_self(), digest = selection.digest
        let boundary = expected.activation.runtime.setup.source.actual.admission.machine
        var active = true, reading = false, violated = false
        weak var writer = machine
        defer { active = false; writer = nil }
        func lifetime() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0,
                  active, !violated, writer != nil else { throw JournalLeaseError.invalidated }
        }
        func loan<Result>(material: RuntimePreparationMaterial? = nil,
            artifact: RuntimePublishedArtifactValidation.Artifact? = nil, _ body: (Scope) throws -> Result) throws -> Result {
            var lent = true, checking = false, operating = false
            defer { lent = false }
            let scope = Scope(check: { enter in
                try lifetime(); guard lent else { throw JournalLeaseError.invalidated }
                guard !checking, !enter || !operating else { violated = true; throw PreparationStoreError.transactionActive }
                checking = true; defer { checking = false }
                if enter { operating = true }
                try admission.validateMachineBoundary(directory: directory, expected: boundary); try lifetime()
            }, leave: { operating = false }, selection: selection, material: material, artifact: artifact)
            try scope.requireActive(); try inspectScope(scope); try scope.requireActive()
            let result = try body(scope); try scope.requireActive(); return result
        }
        var retained: RuntimePreparationMaterial?
        func fullCheck() throws -> RuntimePreparationMaterial {
            try lifetime(); guard !reading else { violated = true; throw PreparationStoreError.transactionActive }
            reading = true; defer { reading = false }
            guard writer != nil else { throw JournalLeaseError.invalidated }
            try admission.validateMachineBoundary(directory: directory, expected: boundary)
            try verifyCurrent(expected); try lifetime()
            try verifyServices(expected.activation.runtime.plan); try lifetime()
            let material = try loan { try readMaterial($0) }
            guard try material.reference == reference else { throw RuntimePreparationError.conflictingMaterial }
            if let retained, try retained.encoded != material.encoded { throw RuntimePreparationError.conflictingMaterial }
            guard let activity = material.serviceActivity else { throw RuntimePreparationError.incomplete }
            try reference.validate(account: expected.activation.runtime.preparation, services: expected.activation.runtime.plan)
            try loan(material: material) { try verifyActivity(activity, $0) }
            let frame = try selectionScope.readFrame(); try frame.snapshot.requireSame(as: expected)
            try record.requireRecorded(frame.current)
            try selection.configuration.binding.requireSourceForPublication(frame.snapshot, current: frame.current, candidate: candidate)
            let selected = frame.selection; try selected.requireSame(as: selection)
            guard selected.digest == digest else { throw RuntimeActivationError.changedScope }
            try admission.validateMachineBoundary(directory: directory, expected: boundary); try lifetime(); return material
        }
        retained = try fullCheck(); guard let material = retained else { throw RuntimePreparationError.incomplete }
        try didStage(.materialRestored); try lifetime()
        let artifacts = try RuntimePublishedArtifactValidation.artifacts(bundle: selection.configuration.bundle, material: material)
        guard artifacts.count == 8, Set(artifacts.map(\.path)).count == 8 else { throw RuntimePreparationError.incomplete }
        for artifact in artifacts {
            let present = try loan(material: material, artifact: artifact) { try readArtifact(artifact, $0) }
            if let present, present != artifact.bytes { throw AdministrativeSetupPublicationError.conflictingConfiguration }
        }
        for artifact in artifacts {
            _ = try fullCheck()
            try loan(material: material, artifact: artifact, publish)
            let actual = try loan(material: material, artifact: artifact) { try readArtifact(artifact, $0) }
            guard actual == artifact.bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
            _ = try fullCheck()
        }
        try didStage(.filesPublished); try lifetime()
        for artifact in artifacts {
            let actual = try loan(material: material, artifact: artifact) { try readArtifact(artifact, $0) }
            guard actual == artifact.bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
        }
        _ = try fullCheck(); return selection
    }
}
