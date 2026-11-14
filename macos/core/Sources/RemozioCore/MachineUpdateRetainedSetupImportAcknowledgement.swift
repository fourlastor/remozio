import Foundation

/// Checks actual initial files around one import acknowledgement. Native callers prove custody and host identity separately.
enum MachineUpdateRetainedSetupImportAcknowledgement {
    typealias Entry = MachineUpdateRetainedSetupInitialRuntimeEntry
    typealias Inputs = MachineUpdateRetainedSetupRuntimeInputs
    typealias Frame = PreparationIntentStore.RetainedImportFrame
    typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    /// One callback loan. Repeated reads check the held transaction and admission without another query.
    struct Scope: CustomStringConvertible, CustomDebugStringConvertible {
        fileprivate let check: (Bool) throws -> Void
        fileprivate let leave: () -> Void
        fileprivate let frame: Frame
        let artifact: Artifact?
        var description: String { "RetainedSetupImportAcknowledgementScope(redacted)" }
        var debugDescription: String { description }
        func read() throws -> Frame { try check(false); return frame }
        func requireActive() throws { try check(false) }
        func withActive<Value>(_ body: () throws -> Value) throws -> Value {
            try check(true); defer { leave() }
            let result = try body(); try requireActive(); return result
        }
    }
    /// Requires a real retained or acknowledged intent. The outer sequence skips absent and empty input storage.
    static func acknowledge(machine: PreparationIntentStore, expected: Entry, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, fileCustodyAccepted: Bool,
        readPolicyBoundary: () throws -> AuthorityJournal.MachineUpdatePolicyBoundary,
        verifyCurrent: (Scope) throws -> Void, verifyServices: (ServiceAccountPlan) throws -> Void,
        readMaterial: (Scope) throws -> RuntimePreparationMaterial,
        verifyActivity: (ServiceReleaseActivityReference, Scope) throws -> Void,
        readArtifact: (Artifact, Scope) throws -> Data?) throws -> (frame: Frame, advanced: Bool) {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        guard expected.runtime.state.configurationPublished, let record = expected.intent, record.phase == .recorded,
              let reference = expected.runtime.state.reference, reference.serviceActivity != nil else {
            throw RuntimeActivationError.incomplete
        }
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        return try machine.withSharedImportJournal { journal in
            guard let journal else { throw RuntimePreparationError.incomplete }
            return try machine.withSharedImportSnapshot(journal: journal) { importDirectory, owner in
                let initial = try machine.retainedSetupInitialRuntimeEntry(owner: expected.runtime.setup.owner, candidate: candidate)
                try initial.requireSame(as: expected)
                let inputs = try Inputs.capture(expected: initial.runtime, journal: journal,
                    verifyCurrent: { try machine.validateStorageLease() },
                    readRelay: { try .read($0, directory: importDirectory, owner: owner) })
                guard inputs.intent != nil else { throw RuntimePreparationError.incomplete }
                var observations = 0, retainedMaterial: Data?, retainedPaths: [String]?, retainedBytes: [Data]?
                let result = try machine.acknowledgeRetainedSetupImport(expected: initial, expectedInputs: inputs,
                    journal: journal, candidate: candidate, directory: directory, admission: admission,
                    fileCustodyAccepted: fileCustodyAccepted, verifyScoped: { _, borrowed in
                        let actual = try borrowed.read()
                        guard observations < 2, let snapshot = actual.entry.policy else { throw RuntimePreparationError.changedScope }
                        observations += 1
                        func loan<Value>(artifact: Artifact? = nil, _ body: (Scope) throws -> Value) throws -> Value {
                            var active = true, operating = false, violated = false
                            defer { active = false }
                            let scope = Scope(check: { enter in
                                try borrowed.requireActive()
                                guard active, !violated else { throw JournalLeaseError.invalidated }
                                guard !enter || !operating else { violated = true; throw PreparationStoreError.transactionActive }
                                if enter { operating = true }
                            }, leave: { operating = false }, frame: actual, artifact: artifact)
                            try scope.requireActive(); let value = try body(scope); try scope.requireActive(); return value
                        }
                        try loan(verifyCurrent); try borrowed.requireActive()
                        try verifyServices(actual.entry.runtime.plan); try borrowed.requireActive()
                        let current = try readPolicyBoundary(); try borrowed.requireActive(); try record.requireRecorded(current)
                        let binding = try RuntimeRetainedSetupReleaseBinding(snapshot: snapshot, current: current, candidate: candidate)
                        let first = try loan(readMaterial), encoded = try first.encoded
                        guard try first.reference == reference, try first.services.encoded == actual.entry.runtime.plan.encoded,
                              let activity = first.serviceActivity else { throw RuntimePreparationError.conflictingMaterial }
                        if let retainedMaterial, encoded != retainedMaterial { throw RuntimePreparationError.conflictingMaterial }
                        try loan { try verifyActivity(activity, $0) }
                        let bundle = try RuntimeConfigurationBundle.retainedSetupInitialObservation(snapshot: snapshot,
                            current: current, candidate: candidate, inputs: actual.inputs)
                        let artifacts = try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: first)
                        guard artifacts.count == 8, Set(artifacts.map(\.path)).count == 8 else { throw RuntimePreparationError.incomplete }
                        if let retainedPaths, retainedPaths != artifacts.map(\.path) { throw RuntimePreparationError.changedScope }
                        if let retainedBytes, retainedBytes != artifacts.map(\.bytes) { throw RuntimePreparationError.changedScope }
                        for artifact in artifacts {
                            let bytes = try loan(artifact: artifact) { try readArtifact(artifact, $0) }
                            guard bytes == artifact.bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
                        }
                        let second = try loan(readMaterial)
                        guard try second.encoded == encoded else { throw RuntimePreparationError.conflictingMaterial }
                        try loan { try verifyActivity(activity, $0) }
                        try verifyServices(actual.entry.runtime.plan); try borrowed.requireActive()
                        let final = try readPolicyBoundary(); try borrowed.requireActive(); try record.requireRecorded(final)
                        try binding.requireSourceForPublication(snapshot, current: final, candidate: candidate)
                        try loan(verifyCurrent)
                        retainedMaterial = encoded; retainedPaths = artifacts.map(\.path); retainedBytes = artifacts.map(\.bytes)
                    })
                guard observations == 2 else { throw RuntimePreparationError.incomplete }
                return result
            }
        }
    }
}
