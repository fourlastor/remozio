import Darwin
import Foundation

/// Applies only the closed source/target bindings of a retained graph. Neither file state nor a saved phase proves quiescence.
enum RuntimeAuditUpgradeFiles {
    typealias Area = RuntimeAuditUpgradeArtifactPlan.Directory
    typealias Snapshot = RuntimeAuditUpgradeArtifactSnapshot
    enum Expectation { case sourceOnly, sourceOrTarget, targetOnly }
    enum State: Equatable { case absent, unchanged, source, target }

    static func validate(_ graph: RuntimeAuditUpgradeGraph, directories: [Area: ProtectedSetupDirectory], owner: uid_t,
                         missingImports: Snapshot.MissingImports? = nil, expectation: Expectation,
                         verifyOwnerAndBarrier: () throws -> Void) throws -> [String: State] {
        try graph.requireOwner(owner); try verifyOwnerAndBarrier()
        try parents(graph, directories: directories, owner: owner, missingImports: missingImports, verify: verifyOwnerAndBarrier)
        var result: [String: State] = [:]
        for leaf in graph.snapshot.leaves {
            let current = try state(leaf, graph: graph, directories: directories, owner: owner,
                missingImports: missingImports, verify: verifyOwnerAndBarrier)
            switch expectation {
            case .sourceOnly: guard current != .target else { throw RuntimePreparationError.changedScope }
            case .targetOnly: guard current != .source else { throw RuntimePreparationError.changedScope }
            case .sourceOrTarget: break
            }
            result[leaf.entry.key] = current
        }
        try parents(graph, directories: directories, owner: owner, missingImports: missingImports, verify: verifyOwnerAndBarrier)
        try verifyOwnerAndBarrier(); return result
    }
    private static func parents(_ graph: RuntimeAuditUpgradeGraph, directories: [Area: ProtectedSetupDirectory], owner: uid_t,
                                missingImports: Snapshot.MissingImports?, verify: () throws -> Void) throws {
        guard try Snapshot.captureParents(graph.snapshot.plan, directories: directories, missingImports: missingImports,
            owner: owner, ownership: graph.snapshot.ownership, verifyCurrent: verify) == graph.snapshot.retainedParents else {
            throw JournalLeaseError.identityChanged
        }
    }
    private static func state(_ leaf: Snapshot.Leaf, graph: RuntimeAuditUpgradeGraph,
                              directories: [Area: ProtectedSetupDirectory], owner: uid_t,
                              missingImports: Snapshot.MissingImports?, verify: () throws -> Void) throws -> State {
        let observed = try Snapshot.read(leaf.entry, directories: directories, owner: owner,
            ownership: graph.snapshot.ownership, missingImports: missingImports, verifyCurrent: verify)
        if leaf.source == leaf.target {
            guard observed.1 == leaf.source, observed.0 == leaf.metadata else { throw RuntimePreparationError.changedScope }
            return leaf.source == nil ? .absent : .unchanged
        }
        if observed.1 == leaf.source {
            guard observed.0 == leaf.metadata else { throw JournalLeaseError.identityChanged }; return .source
        }
        if observed.1 == leaf.target, leaf.target != nil, let current = observed.0 {
            if let old = leaf.metadata {
                guard current.device != old.device || current.inode != old.inode else { throw JournalLeaseError.identityChanged }
            }
            return .target
        }
        throw RuntimePreparationError.conflictingMaterial
    }
    static func apply(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeCutoverRecord,
                      graph: RuntimeAuditUpgradeGraph, installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                      rootActivity: ReleaseActivityToken, verifyOwnerAndBarrier: () throws -> Void) throws -> [String: State] {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory); try graph.requireOwner(0)
        return try withNativeDirectories(graph, verifyCurrent: verifyOwnerAndBarrier) { directories, missing in
            try applyCopy(machine: machine, expected: expected, graph: graph, installedRelease: installedRelease,
                currentPolicy: currentPolicy, directories: directories, owner: 0, missingImports: missing,
                rootActivity: rootActivity, verifyOwnerAndBarrier: verifyOwnerAndBarrier)
        }
    }
    static func validateNative(_ graph: RuntimeAuditUpgradeGraph, expectation: Expectation,
                               verifyOwnerAndBarrier: () throws -> Void) throws -> [String: State] {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try graph.requireOwner(0)
        return try withNativeDirectories(graph, verifyCurrent: verifyOwnerAndBarrier) { directories, missing in
            try validate(graph, directories: directories, owner: 0, missingImports: missing,
                expectation: expectation, verifyOwnerAndBarrier: verifyOwnerAndBarrier)
        }
    }
    private static func withNativeDirectories<Value>(_ graph: RuntimeAuditUpgradeGraph, verifyCurrent: () throws -> Void,
                                                     _ body: ([Area: ProtectedSetupDirectory], Snapshot.MissingImports?) throws -> Value) throws -> Value {
        try verifyCurrent()
        let paths = try RuntimePreparationPaths(accountID: graph.snapshot.plan.sourceAccount.accountID)
        let native: [Area: String] = [.runtime: paths.privateDirectory, .services: paths.serviceDirectory,
            .clients: RuntimePreparationPaths.sharedDirectory, .jobs: InstalledAccountJobManifest.directory,
            .imports: MachineBootstrap.machineDirectory + "/SharedSetupImport"]
        var directories: [Area: ProtectedSetupDirectory] = [:], held: [ProtectedSetupDirectory] = []
        defer { held.reversed().forEach { $0.close() } }
        for area in Area.allCases {
            guard let retained = graph.snapshot.retainedParents[area], let path = native[area], retained.path == path else {
                throw RuntimePreparationError.changedScope
            }
            if area == .imports && retained.missingChild { continue }
            let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(path.dropFirst()), owner: 0,
                visibility: area == .services || area == .clients || area == .jobs ? .sharedMetadata : .privateState, createIfMissing: false)
            directories[area] = directory; held.append(directory)
        }
        let missing: Snapshot.MissingImports?
        if directories[.imports] == nil {
            let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(MachineBootstrap.machineDirectory.dropFirst()),
                owner: 0, createIfMissing: false)
            held.append(directory)
            missing = try .observe(machine: directory, owner: 0, ownership: .native, verifyCurrent: verifyCurrent)
        } else { missing = nil }
        let result = try body(directories, missing); try verifyCurrent(); return result
    }
    static func applyOwned(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeCutoverRecord,
                           graph: RuntimeAuditUpgradeGraph, installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                           directories: [Area: ProtectedSetupDirectory], owner: uid_t, missingImports: Snapshot.MissingImports? = nil,
                           rootActivity: ReleaseActivityToken, verifyOwnerAndBarrier: () throws -> Void,
                           didStage: (String, AdministrativeSetupPublication.Stage) throws -> Void = { _, _ in }) throws -> [String: State] {
        guard owner > 0, getuid() == owner, geteuid() == owner, graph.snapshot.ownership == .ordinaryOwnerFixture else {
            throw JournalLeaseError.unsafeMetadata
        }
        return try applyCopy(machine: machine, expected: expected, graph: graph, installedRelease: installedRelease,
            currentPolicy: currentPolicy, directories: directories, owner: owner, missingImports: missingImports,
            rootActivity: rootActivity, verifyOwnerAndBarrier: verifyOwnerAndBarrier, didStage: didStage)
    }
    private static func applyCopy(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeCutoverRecord,
                                  graph: RuntimeAuditUpgradeGraph, installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                                  directories: [Area: ProtectedSetupDirectory], owner: uid_t, missingImports: Snapshot.MissingImports?,
                                  rootActivity: ReleaseActivityToken, verifyOwnerAndBarrier: () throws -> Void,
                                  didStage: (String, AdministrativeSetupPublication.Stage) throws -> Void = { _, _ in }) throws -> [String: State] {
        guard expected.phase == .filesChanging, let services = directories[.services] else { throw PreparationStoreError.invalidTransition }
        try graph.requireOwner(owner); try expected.graph.validate(graph)
        // This migration changes content or preserves absence. It never deletes an established artifact.
        guard graph.snapshot.leaves.allSatisfy({ $0.source == nil || $0.target != nil }) else { throw RuntimePreparationError.invalidRecord }
        let fence = try RuntimeAuditUpgradeStartupFence(expected).encoded
        func verify() throws {
            try rootActivity.validateExclusive(); try verifyOwnerAndBarrier(); try machine.validateStorageLease()
            try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(installedRelease, policy: currentPolicy)
            try RuntimeAuditUpgradeRecord.validatePreparation(graph.upgrade.intent, release: installedRelease, policy: currentPolicy)
            guard try machine.runtimeAuditCutover(accountID: graph.snapshot.plan.sourceAccount.accountID) == expected else {
                throw PreparationStoreError.staleRevision
            }
            try AdministrativeSetupPublication.validateRetained(fence, file: .auditUpgradeStartupFence, directory: services, owner: owner)
        }
        _ = try validate(graph, directories: directories, owner: owner, missingImports: missingImports,
            expectation: .sourceOrTarget, verifyOwnerAndBarrier: verify)
        for leaf in graph.snapshot.leaves where leaf.source != leaf.target {
            guard let directory = directories[leaf.entry.directory] else { throw RuntimePreparationError.incomplete }
            func checkLeaf() throws {
                try verify(); try parents(graph, directories: directories, owner: owner, missingImports: missingImports, verify: verify)
                _ = try state(leaf, graph: graph, directories: directories, owner: owner, missingImports: missingImports, verify: verify)
            }
            try checkLeaf()
            _ = try AdministrativeSetupPublication.replaceAuditUpgradeLeaf(graph, key: leaf.entry.key, directory: directory,
                owner: owner, verify: checkLeaf, didStage: { try didStage(leaf.entry.key, $0) })
            try checkLeaf()
        }
        return try validate(graph, directories: directories, owner: owner, missingImports: missingImports,
            expectation: .targetOnly, verifyOwnerAndBarrier: verify)
    }
}
