import Darwin
import Foundation

/// A verified filesystem result only. Service health, inventory changes and floor commits require separate authority.
struct MachineUpdateReplacementEvidence {
    let record: MachineUpdateReplacementRecord
    let release: SignedReleaseEvidence
    let recoveredAfterExchange: Bool
}

/// Current signed location only. A retained marker alone cannot prove the installed candidate or runtime health.
struct MachineUpdateReplacementObservation {
    enum Location: Equatable { case prepared, installed }
    let activation: MachineUpdateActivationRecord
    let record: MachineUpdateReplacementRecord
    let location: Location
    let release: SignedReleaseEvidence
}

enum ProtectedMachineUpdateReplacement {
    enum Stage { case bindingCommitted, immediatelyBeforeExchange, immediatelyAfterExchange }
    private enum Layout { case before, after }

    static func observe(activation: MachineUpdateActivationRecord, machineDirectory: ReleaseDestinationLease,
        installed: ReleaseDestinationLease, prepared: ReleaseDestinationLease, store: PreparationIntentStore,
        readPolicy: () throws -> AuthorityCodePolicy) throws -> MachineUpdateReplacementObservation {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try observeInLease(activation: activation, machineDirectory: machineDirectory,
            installed: installed, prepared: prepared, store: store, readPolicy: readPolicy)
    }

    /// Observes either exact layout without writing a phase or acquiring replacement authority.
    static func observeInLease(activation: MachineUpdateActivationRecord, machineDirectory: ReleaseDestinationLease,
        installed: ReleaseDestinationLease, prepared: ReleaseDestinationLease, store: PreparationIntentStore,
        readPolicy: () throws -> AuthorityCodePolicy,
        inspect: (URL, String, String) throws -> SignedReleaseEvidence = {
            try SignedReleaseInspection.inspect($0, teamID: $1, appIdentifier: $2)
        }) throws -> MachineUpdateReplacementObservation {
        try store.validateUpdateAdmissionDirectory(machineDirectory)
        let context = try store.machineUpdateReplacementContext(activation)
        guard let binding = context.replacement else { throw MachineUpdateReplacementError.changedBinding }
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: store)
        guard snapshot.inputs == context.runtime else { throw PreparationStoreError.staleRevision }
        return try store.withCurrentMachineUpdateReplacement(context, directory: machineDirectory) { validate in
            let current = try layout(binding, installed: installed, prepared: prepared)
            guard binding.phase != .observed || current == .after else { throw MachineUpdateReplacementError.unknownOutcome }
            let release = try verify(binding, layout: current, context: context, snapshot: snapshot,
                installed: installed, prepared: prepared, readPolicy: readPolicy, inspect: inspect, validate: validate)
            return .init(activation: activation, record: binding, location: current == .after ? .installed : .prepared, release: release)
        }
    }

    static func replaceOrRecover(activation: MachineUpdateActivationRecord, machineDirectory: ReleaseDestinationLease,
        installed: ReleaseDestinationLease, prepared: ReleaseDestinationLease, store: PreparationIntentStore,
        quiescence: UpdateQuiescenceLease, readPolicy: () throws -> AuthorityCodePolicy) throws -> MachineUpdateReplacementEvidence {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try replaceOrRecoverInLease(activation: activation, machineDirectory: machineDirectory,
            installed: installed, prepared: prepared, store: store, quiescence: quiescence, readPolicy: readPolicy)
    }

    // Owned trees and synthetic signature inspection exercise the operation without granting native Root authority.
    static func replaceOrRecoverInLease(activation: MachineUpdateActivationRecord, machineDirectory: ReleaseDestinationLease,
        installed: ReleaseDestinationLease, prepared: ReleaseDestinationLease, store: PreparationIntentStore,
        quiescence: UpdateQuiescenceLease, readPolicy: () throws -> AuthorityCodePolicy,
        inspect: (URL, String, String) throws -> SignedReleaseEvidence = {
            try SignedReleaseInspection.inspect($0, teamID: $1, appIdentifier: $2)
        }, didStage: (Stage) throws -> Void = { _ in }) throws -> MachineUpdateReplacementEvidence {
        try quiescence.withExclusiveActivity { _ in
            guard activation.phase == .activationStarted else { throw MachineUpdateReplacementError.wrongPhase }
            try store.validateUpdateAdmissionDirectory(machineDirectory)
            let context = try store.machineUpdateReplacementContext(activation)
            try quiescence.validateMachineBoundary(directory: machineDirectory, expected: context.admission.machine)
            var snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: store)
            guard snapshot.inputs == context.runtime else { throw PreparationStoreError.staleRevision }
            let policy = try readPolicy()
            let binding: MachineUpdateReplacementRecord
            if let retained = context.replacement { binding = retained }
            else {
                let installedName = URL(fileURLWithPath: context.inventory.bundlePath).lastPathComponent
                let proposed = try MachineUpdateReplacementRecord(activation: activation, inventory: context.inventory,
                    candidate: context.candidate, policy: policy, installed: installed, prepared: prepared,
                    previousIdentity: installed.preparationCopyIdentity(name: installedName))
                _ = try verify(proposed, layout: .before, context: context, snapshot: snapshot,
                    installed: installed, prepared: prepared, readPolicy: readPolicy, inspect: inspect,
                    validate: { try snapshot.requireCurrent(machine: store) })
                binding = try store.retainMachineUpdateReplacement(proposed, activation: activation, runtime: snapshot.inputs,
                    directory: machineDirectory, quiescence: quiescence, verify: {
                        _ = try verify(proposed, layout: .before, context: context, snapshot: snapshot,
                            installed: installed, prepared: prepared, readPolicy: readPolicy, inspect: inspect, validate: {})
                    })
                try didStage(.bindingCommitted)
                snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: store)
            }
            try binding.requireParents(installed: installed, prepared: prepared)
            guard try MachineUpdateActivationRecord.digest(policy.bytes) == binding.policyDigest else {
                throw MachineUpdateReplacementError.changedBinding
            }
            let initial = try layout(binding, installed: installed, prepared: prepared)
            guard binding.phase != .observed || initial == .after else { throw MachineUpdateReplacementError.unknownOutcome }
            let signature = try store.withBoundMachineUpdateReplacement(binding, activation: activation, runtime: snapshot.inputs,
                directory: machineDirectory, quiescence: quiescence) { validate in
                    var current = initial
                    _ = try verify(binding, layout: current, context: context, snapshot: snapshot,
                        installed: installed, prepared: prepared, readPolicy: readPolicy, inspect: inspect, validate: validate)
                    if current == .before {
                        try didStage(.immediatelyBeforeExchange)
                        _ = try verify(binding, layout: .before, context: context, snapshot: snapshot,
                            installed: installed, prepared: prepared, readPolicy: readPolicy, inspect: inspect, validate: validate)
                        try installed.exchangeMachineUpdateApplications(binding, prepared: prepared, validate: validate)
                        try didStage(.immediatelyAfterExchange)
                        current = .after
                    }
                    return try verify(binding, layout: current, context: context, snapshot: snapshot,
                        installed: installed, prepared: prepared, readPolicy: readPolicy, inspect: inspect, validate: validate)
                }
            let observed: MachineUpdateReplacementRecord
            if binding.phase == .observed { observed = binding }
            else {
                observed = try store.observeMachineUpdateReplacement(binding, activation: activation,
                    directory: machineDirectory, quiescence: quiescence, verify: {
                        _ = try verify(binding, layout: .after, context: context, snapshot: snapshot,
                            installed: installed, prepared: prepared, readPolicy: readPolicy, inspect: inspect, validate: {})
                    })
            }
            try quiescence.validateMachineBoundary(directory: machineDirectory, expected: context.admission.machine)
            return .init(record: observed, release: signature, recoveredAfterExchange: initial == .after)
        }
    }

    private static func layout(_ binding: MachineUpdateReplacementRecord, installed: ReleaseDestinationLease,
                               prepared: ReleaseDestinationLease) throws -> Layout {
        try binding.requireParents(installed: installed, prepared: prepared)
        let publicIdentity = try installed.preparationCopyIdentity(name: binding.installedName)
        let inactiveIdentity = try prepared.preparationCopyIdentity(name: binding.preparedName)
        if publicIdentity == binding.previousIdentity && inactiveIdentity == binding.preparedIdentity { return .before }
        if publicIdentity == binding.preparedIdentity && inactiveIdentity == binding.previousIdentity { return .after }
        throw MachineUpdateReplacementError.unknownOutcome
    }

    /// Uses only captured requirements and the scoped machine verifier. It never reenters the machine writer.
    private static func verify(_ binding: MachineUpdateReplacementRecord, layout expected: Layout,
        context: MachineUpdateReplacementContext, snapshot: RuntimeReleaseCompatibilitySnapshot,
        installed: ReleaseDestinationLease, prepared: ReleaseDestinationLease, readPolicy: () throws -> AuthorityCodePolicy,
        inspect: (URL, String, String) throws -> SignedReleaseEvidence, validate: () throws -> Void) throws -> SignedReleaseEvidence {
        try validate(); try binding.requireScope(activation: context.activation, inventory: context.inventory, candidate: context.candidate)
        guard try layout(binding, installed: installed, prepared: prepared) == expected else { throw MachineUpdateReplacementError.unknownOutcome }
        let policy = try readPolicy()
        guard try MachineUpdateActivationRecord.digest(policy.bytes) == binding.policyDigest,
              let app = policy.entries.first(where: { $0.role == .app && $0.active }) else { throw MachineUpdateReplacementError.changedBinding }
        let oldParent = expected == .before ? installed : prepared, oldName = expected == .before ? binding.installedName : binding.preparedName
        let newParent = expected == .before ? prepared : installed, newName = expected == .before ? binding.preparedName : binding.installedName
        let oldCounts = try oldParent.inspectInstalledApplication(name: oldName)
        let newCounts = try newParent.inspectCopiedTree(name: newName)
        let oldRelease = try inspect(URL(fileURLWithPath: oldParent.path).appendingPathComponent(oldName), app.teamID, app.identifier)
        let newRelease = try inspect(URL(fileURLWithPath: newParent.path).appendingPathComponent(newName), app.teamID, app.identifier)
        guard try InstallationInventory.digest(oldRelease) == context.inventory.releaseDigest,
              try DurableReleasePreparation.digest(newRelease) == context.candidate.updateID else { throw MachineUpdateReplacementError.changedBinding }
        try ReleaseGenerationPreflight.validate(oldRelease, against: policy)
        try snapshot.validate(newRelease, policy: policy, verifyCurrent: validate)
        guard try readPolicy() == policy,
              try oldParent.inspectInstalledApplication(name: oldName) == oldCounts,
              try newParent.inspectCopiedTree(name: newName) == newCounts,
              try layout(binding, installed: installed, prepared: prepared) == expected else { throw MachineUpdateReplacementError.changedBinding }
        try validate(); return newRelease
    }
}

extension ReleaseDestinationLease {
    /// Exchanges both existing names atomically. No old bundle is deleted, restored or adopted on failure.
    fileprivate func exchangeMachineUpdateApplications(_ binding: MachineUpdateReplacementRecord,
        prepared: ReleaseDestinationLease, validate: () throws -> Void) throws {
        try binding.requireParents(installed: self, prepared: prepared); try validate()
        try withDirectory { installedFD in
            try prepared.withDirectory { preparedFD in
                guard try preparationCopyIdentity(name: binding.installedName) == binding.previousIdentity,
                      try prepared.preparationCopyIdentity(name: binding.preparedName) == binding.preparedIdentity else {
                    throw MachineUpdateReplacementError.changedBinding
                }
                try validate()
                let result = renameatx_np(installedFD, binding.installedName, preparedFD, binding.preparedName, UInt32(RENAME_SWAP))
                guard result == 0 else { throw MachineUpdateReplacementError.system(errno) }
                guard fsync(installedFD) == 0, fsync(preparedFD) == 0 else { throw MachineUpdateReplacementError.system(errno) }
                try validate()
            }
        }
    }
}
