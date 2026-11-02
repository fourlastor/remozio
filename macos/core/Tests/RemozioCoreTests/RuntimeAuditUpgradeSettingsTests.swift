import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Candidate metadata and owned fixtures only. No native barriers, installed writes or service readiness are claimed.
final class RuntimeAuditUpgradeSettingsTests: XCTestCase {
    private struct Ready {
        let fixture: RuntimeActivationFixture
        let preparation: RuntimeAuditUpgradePreparation
        let inventory: InstallationInventory
        let journal: GatewayJournalPreparationState
        let activation: GatewayRuntimeActivationPlan
        let gateway: RuntimeAuditUpgradePreparation.Gateway
        init() throws {
            let helper = RuntimeAuditUpgradeDependenciesTests()
            (fixture, preparation, inventory) = try helper.fixture()
            let material = try helper.gateway(preparation)
            journal = try helper.journal(material, preparation, inventory)
            activation = try .init(journal: journal, foreground: preparation.source,
                inventory: inventory, wakePollMilliseconds: 777, wakeTimeoutMilliseconds: 8888)
            gateway = try preparation.gateway(material: material, expected: material.reference,
                journal: journal, activation: activation, inventory: inventory)
        }
        func selection(_ index: Int) throws -> GatewayRuntimeSettingsSelection {
            let old = try XCTUnwrap(journal.intent).configuration.settings
            let service = try GatewayServiceSettings(delivery: old.delivery, probe: old.probe, wake: old.wake,
                maximumOperations: 30 + index, handshakeTimeoutMillis: old.handshakeTimeoutMillis,
                authorityLeaseMillis: old.authorityLeaseMillis, providerTimeoutSeconds: old.providerTimeoutSeconds,
                schedulerRetryMillis: old.schedulerRetryMillis, maximumStoredControls: old.maximumStoredControls,
                maximumPendingPerEnrollment: old.maximumPendingPerEnrollment,
                maximumCandidateLifetimeMillis: old.maximumCandidateLifetimeMillis, databaseBusyMillis: old.databaseBusyMillis)
            return try .init(service: service, activation: .init(wakePollMilliseconds: UInt64(2000 + index * 100),
                wakeTimeoutMilliseconds: UInt64(6000 + index * 100)), maximumWakeConnections: 6 + index,
                maximumWakeOperations: 10 + index, wakeChallengeLifetimeMilliseconds: UInt64(7000 + index * 100))
        }
        func revision(_ index: UInt8, previous: GatewayRuntimeSettingsRevision? = nil) throws -> GatewayRuntimeSettingsRevision {
            try .init(id: Data(repeating: index, count: 16), selection: selection(Int(index)), activation: activation,
                previous: previous, journal: journal, foreground: preparation.source, inventory: inventory)
        }
        func prepare(_ state: GatewayRuntimeSettingsState) throws -> RuntimeAuditUpgradeSettingsPreparation {
            try .init(preparation, state: state, journal: journal, activation: activation, gateway: gateway, inventory: inventory)
        }
        func publication(_ revision: GatewayRuntimeSettingsRevision,
                         previous: GatewayRuntimeSettingsRevision? = nil) throws -> GatewayRuntimeSettingsPublicationPlan {
            try .init(revision: revision, previous: previous, activation: activation,
                journal: journal, foreground: preparation.source, inventory: inventory)
        }
    }
    private let limits = try! CBORLimits(maxBytes: 32768, maxDepth: 1, maxItems: 21)
    private func fields(_ revision: GatewayRuntimeSettingsRevision) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(revision.encoded, limits: limits) else {
            throw GatewayPreparationError.invalidRecord
        }
        return fields
    }
    private func changed(_ revision: GatewayRuntimeSettingsRevision, key: UInt64, value: CBORValue) throws -> GatewayRuntimeSettingsRevision {
        var values = try fields(revision); values[key] = value
        return try .decode(DeterministicCBOR.encode(.map(values), limits: limits))
    }
    private func assertPreserved(_ source: GatewayRuntimeSettingsRevision, _ target: GatewayRuntimeSettingsRevision,
                                 file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(source.id, target.id, file: file, line: line)
        XCTAssertEqual(source.sequence, target.sequence, file: file, line: line)
        XCTAssertEqual(try source.selection.bytes, try target.selection.bytes, file: file, line: line)
        var before = try fields(source), after = try fields(target)
        before.removeValue(forKey: 4); after.removeValue(forKey: 4)
        before.removeValue(forKey: 6); after.removeValue(forKey: 6)
        XCTAssertEqual(before, after, file: file, line: line)
    }
    func testEmptySettingsStayEmptyAndDoNotCreateARevision() throws {
        let r = try Ready(), result = try r.prepare(.empty)
        XCTAssertNil(result.target.active); XCTAssertNil(result.target.pending); XCTAssertNil(result.target.phase)
        XCTAssertNil(result.sourcePending); XCTAssertNil(result.targetPending)
        XCTAssertNil(result.targetActive.revision)
        XCTAssertEqual(result.sourceActive.gateway.canonicalBytes, result.targetActive.gateway.canonicalBytes)
        XCTAssertNil(result.targetActive.commit.settingsSequence)
        XCTAssertEqual(result.targetActive.pair.authority.material.runtime, r.preparation.intent.target)
        XCTAssertEqual(try r.fixture.machine.runtimePreparation(accountID: r.fixture.account.accountID).reference, r.preparation.intent.source)
    }
    func testFirstActiveRevisionKeepsItsIdentitySequenceAndSelectionWithTheNewAnchor() throws {
        let r = try Ready(), first = try r.revision(1), before = try first.encoded
        let result = try r.prepare(.init(active: first, pending: nil, phase: nil)), next = try XCTUnwrap(result.target.active)
        try assertPreserved(first, next)
        XCTAssertEqual(next.previousDigest, try r.gateway.activation.digest)
        try next.validateSuccessor(of: nil, activation: r.gateway.activation)
        XCTAssertEqual(result.targetActive.gateway.canonicalBytes, result.sourceActive.gateway.canonicalBytes)
        XCTAssertEqual(result.targetActive.pair.transport.wake?.canonicalBytes, result.sourceActive.pair.transport.wake?.canonicalBytes)
        XCTAssertEqual(result.targetActive.commit.settingsSequence, 1)
        XCTAssertNotEqual(try next.digest, try first.digest)
        XCTAssertNotEqual(try result.targetActive.commit.observationDigest, try result.sourceActive.commit.observationDigest)
        XCTAssertEqual(try result.source.active?.encoded, before); XCTAssertEqual(try first.encoded, before)
        XCTAssertEqual(try r.prepare(result.source).target.active?.encoded, try next.encoded)
        XCTAssertThrowsError(try first.proposal(activation: r.gateway.activation, journal: r.gateway.journal,
            foreground: r.preparation.target, inventory: r.inventory))
    }
    func testLaterActiveRevisionRetainsItsHistoricalPredecessorAndCounter() throws {
        let r = try Ready(), first = try r.revision(1), second = try r.revision(2, previous: first)
        let result = try r.prepare(.init(active: second, pending: nil, phase: nil)), next = try XCTUnwrap(result.target.active)
        try assertPreserved(second, next)
        XCTAssertEqual(next.previousDigest, try first.digest); XCTAssertEqual(next.previousDigest, second.previousDigest)
        let successor = try GatewayRuntimeSettingsRevision(id: Data(repeating: 8, count: 16), selection: r.selection(3),
            activation: r.gateway.activation, previous: next, journal: r.gateway.journal,
            foreground: r.preparation.target, inventory: r.inventory)
        try successor.validateSuccessor(of: next, activation: r.gateway.activation)
        XCTAssertEqual(successor.sequence, 3); XCTAssertEqual(successor.previousDigest, try next.digest)
        XCTAssertEqual(try result.source.active?.encoded, try second.encoded)
    }
    func testEveryPendingPhaseKeepsBothSelectionsAndUsesTheExactReboundPredecessor() throws {
        let r = try Ready(), first = try r.revision(1), active = try r.revision(2, previous: first)
        let pending = try r.revision(3, previous: active)
        for phase in GatewayRuntimeSettingsPhase.allCases {
            let result = try r.prepare(.init(active: active, pending: pending, phase: phase))
            let nextActive = try XCTUnwrap(result.target.active), nextPending = try XCTUnwrap(result.target.pending)
            try assertPreserved(active, nextActive); try assertPreserved(pending, nextPending)
            XCTAssertEqual(result.target.phase, phase); XCTAssertEqual(result.source.phase, phase)
            XCTAssertEqual(nextPending.previousDigest, try nextActive.digest)
            XCTAssertNotEqual(nextPending.previousDigest, try active.digest)
            try nextPending.validateSuccessor(of: nextActive, activation: r.gateway.activation)
            let oldPublication = try XCTUnwrap(result.sourcePending), newPublication = try XCTUnwrap(result.targetPending)
            XCTAssertEqual(newPublication.revision.id, oldPublication.revision.id)
            XCTAssertEqual(newPublication.commit.settingsSequence, 3)
            XCTAssertEqual(newPublication.pair.transport.wake?.canonicalBytes, oldPublication.pair.transport.wake?.canonicalBytes)
            XCTAssertEqual(newPublication.artifacts.first?.selected, oldPublication.artifacts.first?.selected)
            let oldFence = try GatewayRuntimeSettingsFence(oldPublication), binding = try result.preparingFence(oldFence)
            let newFence = binding.target
            XCTAssertEqual(try binding.source.encoded, try oldFence.encoded)
            XCTAssertEqual(try newFence.encoded, try GatewayRuntimeSettingsFence(newPublication).encoded)
            XCTAssertEqual(newFence.previous.settingsSequence, 2); XCTAssertEqual(newFence.selected.settingsSequence, 3)
            XCTAssertNil(newFence.recoveryAttemptID)
            XCTAssertThrowsError(try newFence.validate(commit: oldFence.previous))
            XCTAssertThrowsError(try newFence.validate(commit: oldFence.selected))
            try newFence.validate(commit: newPublication.commit)
        }
    }
    func testPendingFirstRevisionKeepsTheAbsentActiveSelection() throws {
        let r = try Ready(), first = try r.revision(1)
        let result = try r.prepare(.init(active: nil, pending: first, phase: .retained))
        XCTAssertNil(result.target.active)
        let next = try XCTUnwrap(result.target.pending)
        try assertPreserved(first, next); try next.validateSuccessor(of: nil, activation: r.gateway.activation)
        XCTAssertEqual(next.previousDigest, try r.gateway.activation.digest)
        XCTAssertNil(result.targetPending?.artifacts.first(where: { if case .gatewaySettingsRevision = $0.file { true } else { false } })?.previous)
    }
    func testRecoveryFenceKeepsItsAttemptAndRequiresTheNewCommit() throws {
        let r = try Ready(), first = try r.revision(1), state = GatewayRuntimeSettingsState(active: first, pending: nil, phase: nil)
        let result = try r.prepare(state), attempt = Data(repeating: 44, count: 16)
        let recovery = try GatewayRuntimeSettingsRecoveryPlan(state: state, activation: r.activation, journal: r.journal,
            foreground: r.preparation.source, inventory: r.inventory, attemptID: attempt)
        let binding = try result.preparingFence(recovery.fence), fence = binding.target
        XCTAssertEqual(try binding.source.encoded, try recovery.fence.encoded)
        let targetRecovery = try GatewayRuntimeSettingsRecoveryPlan(state: result.target, activation: r.gateway.activation,
            journal: r.gateway.journal, foreground: r.preparation.target, inventory: r.inventory, attemptID: attempt)
        XCTAssertEqual(try fence.encoded, try targetRecovery.fence.encoded)
        XCTAssertEqual(fence.recoveryAttemptID, attempt)
        XCTAssertEqual(try fence.previous.encoded, try result.targetActive.commit.encoded)
        XCTAssertEqual(try fence.selected.encoded, try result.targetActive.commit.encoded)
        XCTAssertEqual(fence.revision.sequence, first.sequence); XCTAssertEqual(fence.revision.id, first.id)
        XCTAssertThrowsError(try fence.validate(commit: recovery.commit))
        try fence.validate(commit: result.targetActive.commit)
    }
    func testCompletedTransitionFenceBecomesARecoveryPauseWithoutInventingItsHistoricalPredecessor() throws {
        let r = try Ready(), first = try r.revision(1), second = try r.revision(2, previous: first)
        let fence = try GatewayRuntimeSettingsFence(r.publication(second, previous: first)), before = try fence.encoded
        let result = try r.prepare(.init(active: second, pending: nil, phase: nil)), binding = try result.preparingFence(fence)
        let next = binding.target
        XCTAssertEqual(try binding.source.encoded, before)
        let targetRecovery = try GatewayRuntimeSettingsRecoveryPlan(state: result.target, activation: r.gateway.activation,
            journal: r.gateway.journal, foreground: r.preparation.target, inventory: r.inventory,
            attemptID: r.preparation.intent.id)
        XCTAssertEqual(try next.encoded, try targetRecovery.fence.encoded)
        XCTAssertEqual(next.recoveryAttemptID, r.preparation.intent.id)
        XCTAssertEqual(next.revision.id, second.id); XCTAssertEqual(next.revision.sequence, 2)
        XCTAssertEqual(try next.previous.encoded, try next.selected.encoded)
        XCTAssertEqual(try next.selected.encoded, try result.targetActive.commit.encoded)
        XCTAssertEqual(try fence.encoded, before)
        XCTAssertEqual(try result.preparingFence(fence).target.encoded, try next.encoded)
        XCTAssertThrowsError(try next.validate(commit: fence.selected))
    }
    func testMalformedProgressForeignRevisionAndChangedPendingPredecessorsRefuse() throws {
        let r = try Ready(), first = try r.revision(1), second = try r.revision(2, previous: first)
        XCTAssertThrowsError(try r.prepare(.init(active: first, pending: nil, phase: .quiesced)))
        XCTAssertThrowsError(try r.prepare(.init(active: nil, pending: first, phase: nil)))
        XCTAssertThrowsError(try r.prepare(.init(active: first, pending: first, phase: .retained)))
        let forged = try changed(second, key: 6, value: .bytes(Data(repeating: 0, count: 32)))
        XCTAssertThrowsError(try r.prepare(.init(active: first, pending: forged, phase: .retained)))
        let firstWithWrongAnchor = try changed(first, key: 6, value: .bytes(Data(repeating: 0, count: 32)))
        XCTAssertThrowsError(try r.prepare(.init(active: firstWithWrongAnchor, pending: nil, phase: nil)))
        let foreign = try Ready().revision(1)
        XCTAssertThrowsError(try r.prepare(.init(active: foreign, pending: nil, phase: nil)))
        let overflow = try changed(first, key: 5, value: .unsigned(UInt64(Int64.max) + 1))
        XCTAssertThrowsError(try r.prepare(.init(active: overflow, pending: nil, phase: nil))) {
            XCTAssertEqual($0 as? GatewayPreparationError, .exhausted)
        }
    }
    func testCrossedPreparationOrBaselineActivationCannotSupplyTargetSettings() throws {
        let r = try Ready(), newIntent = try RuntimeAuditUpgradeIntent(source: r.preparation.intent.source,
            target: r.preparation.intent.target, policy: r.preparation.source.host.codePolicy)
        let other = try RuntimeAuditUpgradePreparation(source: r.preparation.source, intent: newIntent,
            installedRelease: XCTUnwrap(r.fixture.nativeRelease), currentPolicy: r.preparation.source.host.codePolicy)
        XCTAssertThrowsError(try RuntimeAuditUpgradeSettingsPreparation(other, state: .empty, journal: r.journal,
            activation: r.activation, gateway: r.gateway, inventory: r.inventory))
        let changedActivation = try GatewayRuntimeActivationPlan(journal: r.journal, foreground: r.preparation.source,
            inventory: r.inventory, wakePollMilliseconds: 999, wakeTimeoutMilliseconds: 8888)
        XCTAssertThrowsError(try RuntimeAuditUpgradeSettingsPreparation(r.preparation, state: .empty, journal: r.journal,
            activation: changedActivation, gateway: r.gateway, inventory: r.inventory))
    }
    func testUnrelatedAndRecoveryFencesCannotReplaceAPendingTransitionFence() throws {
        let r = try Ready(), first = try r.revision(1), second = try r.revision(2, previous: first)
        let result = try r.prepare(.init(active: first, pending: second, phase: .filesPublished))
        let wrong = try GatewayRuntimeSettingsFence(r.publication(r.revision(3, previous: first), previous: first))
        XCTAssertThrowsError(try result.preparingFence(wrong))
        let recovery = try GatewayRuntimeSettingsRecoveryPlan(state: .init(active: first, pending: nil, phase: nil),
            activation: r.activation, journal: r.journal, foreground: r.preparation.source,
            inventory: r.inventory, attemptID: Data(repeating: 42, count: 16))
        XCTAssertThrowsError(try result.preparingFence(recovery.fence))
        let empty = try r.prepare(.empty)
        XCTAssertThrowsError(try empty.preparingFence(wrong))
    }
}
