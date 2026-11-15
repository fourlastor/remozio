import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

/// Owns synthetic release metadata, real SQLite and ordinary admission. It grants no installed native authority.
struct RuntimeMaintenanceWriterFixture {
    let machine: () -> PreparationIntentStore
    let candidate: SignedReleaseEvidence
    let authority: RuntimeMaintenanceWindowRecord.Account
    let target: RuntimeMaintenanceWindowRecord.Account
    let directory: ReleaseDestinationLease
    let admission: UpdateOrdinaryAdmissionLease
    let databasePath: String
    let edit: ([String]) throws -> Void
    let reopen: ((() throws -> Void)?) throws -> Void
}

private typealias Window = RuntimeMaintenanceWindowRecord
private func maintenanceData(_ byte: UInt8, _ count: Int = 16) -> Data { Data(repeating: byte, count: count) }
private func maintenanceScope(mac: Data = maintenanceData(1), installation: Data = maintenanceData(2),
    authority: Window.Account? = nil, target: Window.Account? = nil, release: Data = maintenanceData(9, 32),
    operation: Data = maintenanceData(10, 32)) throws -> Window.Scope {
    try .init(macID: mac, installationID: installation,
        authority: authority ?? .init(accountID: maintenanceData(3), ownerUID: 501, directoryID: maintenanceData(4)),
        target: target ?? .init(accountID: maintenanceData(5), ownerUID: 1501, directoryID: maintenanceData(6)),
        releaseDigest: release, candidateDigest: maintenanceData(11, 32), authorityPolicyDigest: maintenanceData(12, 32),
        operationDigest: operation, restorationDigest: maintenanceData(13, 32), mutationFootprintDigest: maintenanceData(14, 32),
        authorityGrantDigest: maintenanceData(15, 32), targetConsentDigest: maintenanceData(16, 32), administratorIntentDigest: maintenanceData(17, 32))
}
private func maintenanceValue(_ phase: Window.Phase = .authorized, previous: Window? = nil,
    operation: Window.OperationOutcome? = nil, service: Window.ServiceOutcome? = nil, scope: Window.Scope? = nil,
    id: Data? = nil, revision: Data? = nil, gateIdentity: PreparationFileIdentity = .init(device: 1, inode: 1),
    requestRevision: Data? = nil) throws -> Window {
    let early = [Window.Phase.authorized, .draining, .stopping, .stopped].contains(phase)
    let outcome = operation ?? (phase == .executing ? .unknown : early ? .notStarted : previous?.operation ?? .unknown)
    let observedService: Window.ServiceOutcome
    switch phase {
    case .authorized, .draining, .stopping: observedService = .notStopped
    case .stopped, .executing, .workSettled: observedService = .stopped
    case .restoring: observedService = .restartPending
    case .reopenPending, .restored: observedService = .healthy
    case .needsOwnerRecovery: observedService = .unknown
    }
    let attempt = id ?? previous?.id ?? AccountPreparationIntent.randomID()
    let gate: Window.GateReadback? = try phase == .restored ? .init(attemptID: attempt,
        requestRevision: requestRevision ?? previous?.revision ?? maintenanceData(18), identity: gateIdentity,
        authorityIncarnation: maintenanceData(19), challenge: maintenanceData(20), responseDigest: maintenanceData(21, 32),
        hold: .released, admission: .available) : nil
    return try .init(id: attempt, revision: revision ?? AccountPreparationIntent.randomID(), purpose: .retainedRuntime,
        scope: scope ?? previous?.scope ?? maintenanceScope(), phase: phase, operation: outcome, service: service ?? observedService,
        failure: phase == .needsOwnerRecovery ? .healthFailed : nil, gate: gate)
}

final class RuntimeMaintenanceWindowTransitionTests: XCTestCase {
    func testTheFullLifecycleKeepsScopeAndUsesFreshRevisions() throws {
        var current = try maintenanceValue()
        try current.requireReplacing(nil)
        for phase in [Window.Phase.draining, .stopping, .stopped, .executing, .workSettled, .restoring, .reopenPending, .restored] {
            let next = try maintenanceValue(phase, previous: current,
                operation: phase == .workSettled ? .committed : nil)
            try next.requireReplacing(current)
            XCTAssertEqual(next.scope, current.scope); XCTAssertEqual(next.id, current.id)
            XCTAssertNotEqual(next.revision, current.revision)
            current = next
        }
        XCTAssertEqual(current.operation, .committed)
        try maintenanceValue().requireReplacing(current)
    }
    func testIllegalJumpsAndOperationReplayRefuse() throws {
        let forbidden: [(Window.Phase, Window.Phase)] = [(.authorized, .executing), (.draining, .stopped), (.stopped, .workSettled),
            (.executing, .stopped), (.needsOwnerRecovery, .executing), (.restored, .draining)]
        for (from, to) in forbidden {
            let previous = try maintenanceValue(from)
            XCTAssertThrowsError(try maintenanceValue(to, previous: previous).requireReplacing(previous))
        }
        for known in [Window.OperationOutcome.committed, .failed] {
            let previous = try maintenanceValue(.workSettled, operation: known)
            try maintenanceValue(.restoring, previous: previous).requireReplacing(previous)
            for changed in Window.OperationOutcome.allCases where changed != known {
                XCTAssertThrowsError(try maintenanceValue(.restoring, previous: previous, operation: changed).requireReplacing(previous))
            }
        }
        let uncertain = try maintenanceValue(.needsOwnerRecovery, operation: .unknown)
        XCTAssertThrowsError(try maintenanceValue(.restoring, previous: uncertain, operation: .notStarted).requireReplacing(uncertain))
        try maintenanceValue(.needsOwnerRecovery, previous: uncertain).requireReplacing(uncertain)
    }
    func testScopeGateAndInitialStateCannotBeReused() throws {
        let initial = try maintenanceValue()
        XCTAssertThrowsError(try maintenanceValue(.draining, previous: initial, revision: initial.revision).requireReplacing(initial))
        XCTAssertThrowsError(try maintenanceValue(.draining, previous: initial,
            scope: maintenanceScope(operation: maintenanceData(99, 32))).requireReplacing(initial)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
        XCTAssertThrowsError(try maintenanceValue().requireReplacing(initial))
        XCTAssertThrowsError(try maintenanceValue(.draining).requireReplacing(nil))
        let pending = try maintenanceValue(.reopenPending)
        try maintenanceValue(.restored, previous: pending).requireReplacing(pending)
        XCTAssertThrowsError(try maintenanceValue(.restored, previous: pending,
            requestRevision: maintenanceData(99)).requireReplacing(pending))
    }
    private func requireCancellation(draining: Bool) throws {
        let authorized = try maintenanceValue()
        var current = authorized
        if draining {
            let next = try maintenanceValue(.draining, previous: current)
            try next.requireReplacing(current); current = next
        }
        let pending = try maintenanceValue(.reopenPending, previous: current, service: .notStopped)
        try pending.requireReplacing(current)
        XCTAssertEqual(try Window.decode(pending.encoded), pending)
        XCTAssertThrowsError(try maintenanceValue(.reopenPending, previous: current, service: .healthy).requireReplacing(current))
        let restored = try maintenanceValue(.restored, previous: pending, service: .notStopped)
        try restored.requireReplacing(pending)
        XCTAssertEqual(restored.operation, .notStarted); XCTAssertEqual(restored.service, .notStopped)
        XCTAssertThrowsError(try maintenanceValue(.restored, previous: pending, service: .healthy).requireReplacing(pending))
        XCTAssertThrowsError(try maintenanceValue(.restored, previous: pending, service: .notStopped,
            requestRevision: maintenanceData(99)).requireReplacing(pending))
    }
    func testAuthorizedCancellationReopensWithoutStartingWorkOrStoppingServices() throws {
        try requireCancellation(draining: false)
    }
    func testDrainingCancellationReopensWithoutStartingWorkOrStoppingServices() throws {
        try requireCancellation(draining: true)
    }
    func testCancellationContinuityDoesNotPreventTheNormalServiceStop() throws {
        let draining = try maintenanceValue(.draining)
        let stopping = try maintenanceValue(.stopping, previous: draining)
        try stopping.requireReplacing(draining)
        let stopped = try maintenanceValue(.stopped, previous: stopping)
        try stopped.requireReplacing(stopping)
        XCTAssertEqual(stopped.service, .stopped)
        let pending = try maintenanceValue(.reopenPending, operation: .notStarted, service: .notStopped)
        try maintenanceValue(.needsOwnerRecovery, previous: pending, service: .notStopped).requireReplacing(pending)
        XCTAssertThrowsError(try maintenanceValue(.needsOwnerRecovery, previous: pending, service: .unknown).requireReplacing(pending))
    }
    func testAuthorityWriterDeclarationsCannotReplaceSetupDeclarations() throws {
        let required = try RuntimeMaintenanceWindowStorage.readerRequirements + MachineUpdateRetainedSetupPromotionReadyStorage.readerRequirements
            + MachineUpdateRetainedSetupPromotionStorage.readerRequirements + MachineUpdateRetainedSetupCompletionStorage.readerRequirements
        func candidate(setup: Bool = true, authority: Bool = false, migration: Bool = true) throws -> SignedReleaseEvidence {
            let components = try [AuthorityCodeRole.app, .authority, .setupController].map { role in
                let writes = role == .setupController ? setup : role == .authority && authority
                let names = Set(required.filter { $0.role == role }.map(\.name))
                let formats = try names.sorted().map { name -> ReleaseFormat in
                    let readers = Set(required.filter { $0.role == role && $0.name == name }.flatMap(\.readVersions))
                    let versions: Set<UInt64> = writes ? name == "authority.installation-preparation" ? [29]
                        : name == Window.formatName ? [1] : [] : []
                    return try .init(name: name, readers: readers, writers: versions,
                        migrations: writes && migration && role == .setupController && name == "authority.installation-preparation" ? [28: 29] : [:])
                }
                return try ReleaseComponent(role: role, identifier: "dev.sebastiano.remozio.test-\(role.rawValue)",
                    generation: 4, relativePath: "Contents/Helpers/role-\(role.rawValue)",
                    codeDirectoryHash: role == .app ? nil : maintenanceData(1, 20), build: "4", teamID: "ABCDEFGHIJ", formats: formats, requests: [])
            }
            return try .init(manifest: .init(release: "0.1.0", build: "4", components: components),
                codeDirectoryHashes: [.app: maintenanceData(1, 20), .authority: maintenanceData(1, 20), .setupController: maintenanceData(1, 20)])
        }
        let setup = try candidate()
        try RuntimeMaintenanceWindowStorage.requireWriteFormats(setup, sourceSchema: 28)
        XCTAssertFalse(try XCTUnwrap(setup.manifest.components.first { $0.role == .authority })
            .formats.contains { $0.writers.contains(29) || $0.name == Window.formatName && $0.writers.contains(1) })
        XCTAssertThrowsError(try RuntimeMaintenanceWindowStorage.requireWriteFormats(candidate(setup: false, authority: true), sourceSchema: 28))
        XCTAssertThrowsError(try RuntimeMaintenanceWindowStorage.requireWriteFormats(candidate(migration: false), sourceSchema: 28))
        try RuntimeMaintenanceWindowStorage.requireWriteFormats(candidate(migration: false), sourceSchema: 29)
        for schema in [Int64(27), 30] { XCTAssertThrowsError(try RuntimeMaintenanceWindowStorage.requireWriteFormats(setup, sourceSchema: schema)) }
    }
}

final class RuntimeMaintenanceWindowWriterTests: XCTestCase {
    private enum Fault: Error { case injected }
    private func fixture(_ body: (RuntimeMaintenanceWriterFixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture(body)
    }
    private func initial(_ f: RuntimeMaintenanceWriterFixture, authority: Window.Account? = nil,
        target: Window.Account? = nil, operation: Data = maintenanceData(10, 32)) throws -> Window {
        let source = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
        return try maintenanceValue(scope: maintenanceScope(mac: source.inventory.macID, installation: source.inventory.installationID,
            authority: authority ?? f.authority, target: target ?? f.target, release: source.inventory.releaseDigest, operation: operation))
    }
    @discardableResult private func write(_ value: Window, _ f: RuntimeMaintenanceWriterFixture, previous: Window? = nil,
        expected: MachineUpdateStableReleaseSnapshot? = nil,
        verify: (PreparationIntentStore.CompletionIntentStorageStage) throws -> Void = { _ in }) throws -> Window {
        let snapshot = try expected ?? f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
        let drain = try value.phase == .draining ? accountBarrier(f, expected: snapshot).beginDrain() : nil
        defer { drain?.close() }
        return try f.machine().writeRuntimeMaintenanceWindow(value, replacing: previous, expected: snapshot,
            candidate: f.candidate, directory: f.directory, admission: f.admission, accountDrain: drain, verifyScoped: verify)
    }
    private func accountBarrier(_ f: RuntimeMaintenanceWriterFixture, expected: MachineUpdateStableReleaseSnapshot) throws -> UpdateAdmissionBarrier {
        let account = try XCTUnwrap(expected.admission.accounts.first { $0.accountID == f.authority.accountID })
        let anchor = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent().deletingLastPathComponent().path
        return try .init(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()), owner: getuid(),
            expected: account.identity, scope: .account(account.accountID))
    }
    func testDrainingRequiresTheActualLiveAccountDrainAndPreservesRowsOnRefusal() throws {
        try fixture { f in
            let current = try initial(f); try write(current, f)
            let next = try maintenanceValue(.draining, previous: current)
            let expected = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let before = try runtimeMaintenanceFixtureRows(f.databasePath)
            let foreign = try UpdateAdmissionTestFixture(), machine = try foreign.open().beginDrain()
            let (other, _) = try foreign.provisionAccount(maintenanceData(99)), wrongAccount = try other.beginDrain()
            let closed = try accountBarrier(f, expected: expected).beginDrain(); closed.close()
            defer { machine.close(); wrongAccount.close() }
            for token in [nil, machine, wrongAccount, closed] as [UpdateDrainToken?] {
                var callbacks = 0
                XCTAssertThrowsError(try f.machine().writeRuntimeMaintenanceWindow(next, replacing: current, expected: expected,
                    candidate: f.candidate, directory: f.directory, admission: f.admission, accountDrain: token,
                    verifyScoped: { _ in callbacks += 1 }))
                XCTAssertEqual(callbacks, 0); XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), before)
            }
            let drain = try accountBarrier(f, expected: expected).beginDrain(); defer { drain.close() }
            XCTAssertEqual(try f.machine().writeRuntimeMaintenanceWindow(next, replacing: current, expected: expected,
                candidate: f.candidate, directory: f.directory, admission: f.admission, accountDrain: drain), next)
        }
    }
    func testClosingTheAccountDrainDuringMutationRollsBackTheDrainingRow() throws {
        try fixture { f in
            let current = try initial(f); try write(current, f)
            let expected = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let before = try runtimeMaintenanceFixtureRows(f.databasePath)
            let drain = try accountBarrier(f, expected: expected).beginDrain()
            XCTAssertThrowsError(try f.machine().writeRuntimeMaintenanceWindow(maintenanceValue(.draining, previous: current),
                replacing: current, expected: expected, candidate: f.candidate, directory: f.directory, admission: f.admission,
                accountDrain: drain, verifyScoped: { if $0 == .afterMutation { drain.close() } }))
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), before)
            let next = try accountBarrier(f, expected: expected).beginDrain(); next.close()
        }
    }
    func testClosingTheAccountDrainBeforeMutationRefusesTheDrainingRow() throws {
        try fixture { f in
            let current = try initial(f); try write(current, f)
            let expected = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let before = try runtimeMaintenanceFixtureRows(f.databasePath)
            for boundary in [PreparationIntentStore.CompletionIntentStorageStage.beforeTransaction, .inTransaction] {
                let drain = try accountBarrier(f, expected: expected).beginDrain()
                XCTAssertThrowsError(try f.machine().writeRuntimeMaintenanceWindow(maintenanceValue(.draining, previous: current),
                    replacing: current, expected: expected, candidate: f.candidate, directory: f.directory, admission: f.admission,
                    accountDrain: drain, verifyScoped: { if $0 == boundary { drain.close() } }))
                XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), before)
            }
        }
    }
    func testClosingTheAccountDrainAfterCommitRetiresTheWriterWithoutReplaying() throws {
        try fixture { f in
            let current = try initial(f); try write(current, f)
            let expected = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let next = try maintenanceValue(.draining, previous: current)
            let drain = try accountBarrier(f, expected: expected).beginDrain(); var mutations = 0
            XCTAssertThrowsError(try f.machine().writeRuntimeMaintenanceWindow(next, replacing: current, expected: expected,
                candidate: f.candidate, directory: f.directory, admission: f.admission, accountDrain: drain, verifyScoped: {
                    if $0 == .afterMutation { mutations += 1 }; if $0 == .afterCommit { drain.close() }
                }))
            XCTAssertEqual(mutations, 1)
            XCTAssertThrowsError(try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
            try f.reopen(nil)
            let projection = f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate)
            XCTAssertEqual(projection.revision, next.revision); XCTAssertTrue(projection.requiresLocalHold)
        }
    }
    func testFirstWindowMigratesAtomicallyAndPreservesAllOtherRows() throws {
        try fixture { f in
            let before = try runtimeMaintenanceFixtureRows(f.databasePath, omitMaintenance: true)
            let value = try initial(f)
            var stages: [PreparationIntentStore.CompletionIntentStorageStage] = []
            XCTAssertEqual(try write(value, f, verify: { stages.append($0) }), value)
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate).schemaVersion, 29)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath, omitMaintenance: true), before)
            try f.reopen(nil)
            let projection = f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate)
            XCTAssertTrue(projection.requiresLocalHold); XCTAssertEqual(projection.attemptID, value.id)
            XCTAssertEqual(projection.revision, value.revision)
        }
    }
    func testFailureAfterMigrationRollsBackTheSchemaAndExpiresTheOwner() throws {
        try fixture { f in
            let before = try runtimeMaintenanceFixtureRows(f.databasePath), value = try initial(f)
            XCTAssertThrowsError(try write(value, f, verify: { stage in
                if stage == .afterMutation {
                    XCTAssertThrowsError(try f.machine().close()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
                    throw Fault.injected
                }
            })) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate).schemaVersion, 28)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), before)
            XCTAssertEqual(try write(value, f), value)
        }
    }
    func testCASRejectsStaleOrChangedScopeAndKeepsOtherWindowsExact() throws {
        try fixture { f in
            let before = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let value = try initial(f); try write(value, f)
            let next = try maintenanceValue(.draining, previous: value)
            XCTAssertThrowsError(try write(next, f, previous: value, expected: before))
            XCTAssertThrowsError(try write(initial(f), f)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            XCTAssertThrowsError(try write(maintenanceValue(.draining, previous: value,
                scope: maintenanceScope(mac: value.scope.macID, installation: value.scope.installationID,
                    authority: f.authority, target: f.target, release: value.scope.releaseDigest,
                    operation: maintenanceData(99, 32))), f, previous: value)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            let other = try initial(f, authority: .init(accountID: maintenanceData(88), ownerUID: 65003, directoryID: maintenanceData(89)))
            func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
            try f.edit(["INSERT INTO runtime_maintenance_windows_v1 VALUES(X'\(hex(other.scope.authority.accountID))',X'\(hex(other.id))',X'\(hex(other.revision))',1,X'\(try hex(other.encoded))')"])
            let unchanged = try runtimeMaintenanceFixtureRows(f.databasePath, excludingAccount: f.authority.accountID)
            try write(next, f, previous: value)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath, excludingAccount: f.authority.accountID), unchanged)
            XCTAssertThrowsError(try write(maintenanceValue(.stopping, previous: value), f, previous: value))
        }
    }
    func testTheSQLLifecycleRequiresGateReadbackBeforeRestoredAndNeverReplaysWork() throws {
        try fixture { f in
            var current = try initial(f); try write(current, f)
            for phase in [Window.Phase.draining, .stopping, .stopped, .executing, .workSettled, .restoring, .reopenPending] {
                let next = try maintenanceValue(phase, previous: current, operation: phase == .workSettled ? .committed : nil)
                try write(next, f, previous: current); current = next
            }
            let source = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let gate = try XCTUnwrap(source.admission.accounts.first { $0.accountID == f.authority.accountID }).identity
            XCTAssertThrowsError(try write(maintenanceValue(.restored, previous: current, gateIdentity: gate,
                requestRevision: maintenanceData(99)), f, previous: current))
            let restored = try maintenanceValue(.restored, previous: current, gateIdentity: gate)
            try write(restored, f, previous: current)
            XCTAssertFalse(f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate).requiresLocalHold)
            XCTAssertThrowsError(try write(maintenanceValue(.executing, previous: restored), f, previous: restored))
            try write(initial(f), f, previous: restored)
        }
    }
    private func cancelWithoutStopping(_ f: RuntimeMaintenanceWriterFixture, draining: Bool) throws {
        let otherRows = try runtimeMaintenanceFixtureRows(f.databasePath, omitMaintenance: true)
        var current = try initial(f); try write(current, f)
        if draining {
            let next = try maintenanceValue(.draining, previous: current)
            try write(next, f, previous: current); current = next
        }
        let pending = try maintenanceValue(.reopenPending, previous: current, service: .notStopped)
        try write(pending, f, previous: current)
        try f.reopen(nil)
        XCTAssertTrue(f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate).requiresLocalHold)
        let source = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
        let gate = try XCTUnwrap(source.admission.accounts.first { $0.accountID == f.authority.accountID }).identity
        let beforeRejectedRestore = try runtimeMaintenanceFixtureRows(f.databasePath)
        XCTAssertThrowsError(try write(maintenanceValue(.restored, previous: pending, service: .notStopped,
            gateIdentity: gate, requestRevision: maintenanceData(99)), f, previous: pending))
        XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), beforeRejectedRestore)
        let restored = try maintenanceValue(.restored, previous: pending, service: .notStopped, gateIdentity: gate)
        XCTAssertEqual(try write(restored, f, previous: pending), restored)
        XCTAssertEqual(restored.operation, .notStarted); XCTAssertEqual(restored.service, .notStopped)
        try f.reopen(nil)
        XCTAssertFalse(f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate).requiresLocalHold)
        XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath, omitMaintenance: true), otherRows)
    }
    func testAuthorizedSQLCancellationRequiresGateReadbackWithoutStoppingServices() throws {
        try fixture { try cancelWithoutStopping($0, draining: false) }
    }
    func testDrainingSQLCancellationRequiresGateReadbackWithoutStoppingServices() throws {
        try fixture { try cancelWithoutStopping($0, draining: true) }
    }
    func testScopeProducerAndClosedAdmissionCannotCreateAWindow() throws {
        try fixture { f in
            let before = try runtimeMaintenanceFixtureRows(f.databasePath)
            let changed = try Window.Account(accountID: f.authority.accountID, ownerUID: f.authority.ownerUID + 1,
                directoryID: f.authority.directoryID)
            XCTAssertThrowsError(try write(initial(f, authority: changed), f)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            let components = try f.candidate.manifest.components.map { component in
                let formats = try component.formats.map { format -> ReleaseFormat in
                    guard component.role == .setupController else { return format }
                    return try .init(name: format.name, readers: format.readers, writers: [], migrations: [:])
                }
                return try ReleaseComponent(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: formats, requests: component.requests)
            }
            let missing = try SignedReleaseEvidence(manifest: .init(release: f.candidate.manifest.release, build: f.candidate.manifest.build,
                components: components, dependencies: f.candidate.manifest.dependencies), codeDirectoryHashes: f.candidate.codeDirectoryHashes,
                dependencyCodeDirectoryHashes: f.candidate.dependencyCodeDirectoryHashes)
            let value = try initial(f), expected = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            XCTAssertThrowsError(try f.machine().writeRuntimeMaintenanceWindow(value, replacing: nil, expected: expected,
                candidate: missing, directory: f.directory, admission: f.admission)) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            f.admission.close()
            XCTAssertThrowsError(try write(value, f))
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), before)
        }
    }
    func testCommitAndPostCommitFailuresRetireWithoutRepeatingTheMutation() throws {
        for hookFailure in [true, false] {
            try fixture { f in
                let value = try initial(f)
                if hookFailure { try f.reopen { throw Fault.injected } }
                var mutations = 0
                func attempt() throws {
                    try write(value, f, verify: { stage in
                        if stage == .afterMutation { mutations += 1 }
                        if !hookFailure && stage == .afterCommit { throw Fault.injected }
                    })
                }
                XCTAssertThrowsError(try attempt()) { XCTAssertTrue($0 is Fault) }
                XCTAssertEqual(mutations, 1)
                XCTAssertThrowsError(try attempt()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                XCTAssertEqual(mutations, 1)
                try f.reopen(nil)
                let projection = f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate)
                XCTAssertEqual(projection.attemptID, value.id); XCTAssertTrue(projection.requiresLocalHold)
                XCTAssertEqual(try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate).schemaVersion, 29)
            }
        }
    }
    func testObservationWindowReadbackRequiresTheExactRowAndNeverWrites() throws {
        try fixture { f in
            let row = try initial(f); try write(row, f)
            let before = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            var commits = 0; try f.reopen { commits += 1 }
            try f.machine().requireRuntimeMaintenanceObservationWindow(row, candidate: f.candidate)
            let changed = try Window(id: row.id, revision: AccountPreparationIntent.randomID(), purpose: row.purpose, scope: row.scope)
            XCTAssertThrowsError(try f.machine().requireRuntimeMaintenanceObservationWindow(changed, candidate: f.candidate)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate).requireSame(as: before)
            XCTAssertEqual(commits, 0)
        }
    }

}
