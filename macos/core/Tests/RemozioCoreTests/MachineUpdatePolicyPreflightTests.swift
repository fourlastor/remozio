import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned files and SQLite. Candidate signature inspection is injected; this is not a native Root launch.
private final class PolicyPreflightFixture {
    let f: MachineUpdateActivationFixture
    let directory: ReleaseDestinationLease
    let drain: UpdateAdmissionDrain
    let record: MachineUpdateActivationRecord
    let quiet: UpdateQuiescenceLease
    init(candidate: SignedReleaseEvidence? = nil,
         beforeCandidateSelection: (UpdateCandidateStorageFixture) throws -> Void = { _ in },
         prepare: (MachineUpdateActivationFixture) throws -> Void = { _ in }) throws {
        f = try .init(candidateRelease: candidate, beforeCandidateSelection: beforeCandidateSelection); try prepare(f)
        directory = try f.files.directory(); drain = try f.admission().beginDrain()
        record = try f.begin(drain); quiet = try XCTUnwrap(drain.acquireQuiescence())
    }
    deinit { quiet.close(); drain.close(); directory.close() }
    func capture(policies: ((MachineUpdateRestartSource) throws -> [MachineUpdatePolicyCapture])? = nil,
                 inspect: (() throws -> SignedReleaseEvidence)? = nil, owner: @escaping () throws -> Void = {}) throws -> MachineUpdatePolicyPreflight {
        try .captureInLease(activation: record, machine: f.machine.store, directory: directory, quiescence: quiet,
            readPolicies: policies ?? f.machine.policyCaptures,
            inspectCandidate: inspect ?? { self.f.machine.release }, verifyOwner: owner)
    }
    func start(_ value: MachineUpdatePolicyPreflight) throws -> MachineUpdateActivationRecord {
        try f.machine.store.markMachineUpdateActivationStarted(record, preflight: value, directory: directory,
            quiescence: quiet, verifyCurrent: {})
    }
    func source() throws -> MachineUpdateRestartSource {
        try f.machine.store.machineUpdatePolicyPreflightSource(record, directory: directory, quiescence: quiet)
    }
}

final class MachineUpdatePolicyPreflightTests: XCTestCase {
    private enum Fault: Error { case expected }
    private func reserve(_ f: MachineUpdateActivationFixture, offset: UInt32 = 1000, complete: Bool = false) throws -> AccountPreparationIntent {
        let base = f.machine.f.f
        let value = try base.begin(f.machine.store, identity: .init(uid: getuid() + offset, primaryGroupID: getgid(), directoryID: UUID()))
        return try complete ? base.resume(f.machine.store, value) : value
    }
    func testAllAccountPolicyDigestIsDurableAtTheIrreversibleBoundary() throws {
        let f = try PolicyPreflightFixture(), proof = try f.capture(), value = try f.start(proof)
        XCTAssertEqual(value.phase, .activationStarted); XCTAssertEqual(value.formatVersion, 2)
        XCTAssertEqual(value.policyPreflightDigest, proof.digest); XCTAssertEqual(value.attemptID, f.record.attemptID)
        try f.f.machine.reopen(); XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), value)
        XCTAssertEqual(try MachineUpdateActivationRecord.decode(value.encoded), value)
        XCTAssertNoThrow(try MachineUpdatePolicyPreflight.requireRetained(proof.source.replacingActivation(value), policies: proof.policies))
    }
    /// A JSON value re-encoded with JSONEncoder, so its key order matches the record's canonical encoding.
    private enum JSONValue: Encodable {
        case string(String), number(Int64), bool(Bool), object([String: JSONValue])

        init(_ value: Any) throws {
            switch value {
            case let value as String: self = .string(value)
            case let value as NSNumber where CFGetTypeID(value) == CFBooleanGetTypeID(): self = .bool(value.boolValue)
            case let value as NSNumber: self = .number(value.int64Value)
            case let value as [String: Any]: self = .object(try value.mapValues(JSONValue.init))
            default: throw PreparationStoreError.corruptRecord
            }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .string(let value): try container.encode(value)
            case .number(let value): try container.encode(value)
            case .bool(let value): try container.encode(value)
            case .object(let value): try container.encode(value)
            }
        }
    }
    private static func canonicalJSON(_ object: [String: Any]) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(object.mapValues(JSONValue.init))
    }
    func testDrainingAndLegacyMarkersKeepTheirOriginalCodec() throws {
        let f = try PolicyPreflightFixture()
        XCTAssertEqual(f.record.formatVersion, 1); XCTAssertNil(f.record.policyPreflightDigest)
        // A new attempt cannot start without a preflight digest (#568), so the legacy started marker is decoded from
        // canonical version 1 bytes, as MachineUpdateActivationRecordTests does.
        let bytes = try f.record.encoded
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertEqual(try Self.canonicalJSON(object), bytes)
        object["phase"] = 2
        let legacy = try MachineUpdateActivationRecord.decode(Self.canonicalJSON(object))
        XCTAssertEqual(legacy.phase, .activationStarted)
        XCTAssertEqual(legacy.formatVersion, 1); XCTAssertNil(legacy.policyPreflightDigest)
        XCTAssertEqual(try MachineUpdateActivationRecord.decode(bytes).encoded, bytes)
        XCTAssertEqual(try MachineUpdateActivationRecord.decode(legacy.encoded), legacy)
    }
    func testMissingOrDuplicatePolicyCaptureCannotAdvanceTheMarker() throws {
        for duplicate in [false, true] {
            let f = try PolicyPreflightFixture()
            XCTAssertThrowsError(try f.capture(policies: { source in
                let values = try f.f.machine.policyCaptures(for: source)
                return duplicate ? values + values : []
            }))
            XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), f.record)
        }
    }
    func testEveryInitializedAccountRequiresItsProtectedPolicy() throws {
        let f = try PolicyPreflightFixture()
        XCTAssertThrowsError(try f.capture(policies: { source in source.accounts.map { .init(accountID: $0.accountID, snapshot: nil) } }))
        XCTAssertEqual(try f.f.machine.store.machineUpdateActivation()?.phase, .draining)
    }
    func testUnfinishedReservationsAreCapturedWithoutCreatingPolicyOrRuntime() throws {
        var pending: AccountPreparationIntent?
        let f = try PolicyPreflightFixture(prepare: { pending = try self.reserve($0) }), proof = try f.capture()
        XCTAssertEqual(proof.source.accounts.count, 2)
        XCTAssertNil(proof.policies.first { $0.accountID == pending!.accountID }?.snapshot)
        _ = try f.start(proof)
        XCTAssertEqual(try f.f.machine.store.accountPreparation(ownerUID: pending!.ownerUID), pending)
        XCTAssertNil(try f.f.machine.store.runtimePreparation(accountID: pending!.accountID).reference)
    }
    func testACheckpointedInitializationWithoutAPolicyCannotProduceADigest() throws {
        let f = try PolicyPreflightFixture(), source = try f.source()
        let index = try XCTUnwrap(source.accounts.firstIndex { $0.initialization?.checkpoint != nil })
        let account = source.accounts[index], initial = try XCTUnwrap(account.initialization)
        // Setup was interrupted after the checkpoint was captured, and the journal is now missing.
        let interrupted = try initial.advancing(checkpoint: XCTUnwrap(initial.checkpoint), complete: false)
        var accounts = source.accounts
        accounts[index] = .init(accountID: account.accountID, ownerUID: account.ownerUID, preparation: account.preparation,
            initialization: interrupted, services: account.services, servicesComplete: account.servicesComplete)
        let changed = MachineUpdateRestartSource(replacement: source.replacement, accounts: accounts, provisioningHistory: source.provisioningHistory)
        let policies = try f.f.machine.policyCaptures(for: source).map { value in
            value.accountID == account.accountID ? MachineUpdatePolicyCapture(accountID: value.accountID, snapshot: nil) : value
        }
        XCTAssertThrowsError(try MachineUpdatePolicyPreflight.policyDigest(source: changed, policies: policies)) {
            XCTAssertEqual($0 as? AuthoritySelfValidationError, .unconfigured)
        }
    }
    func testAnotherAccountsHigherInstalledGenerationBlocksBeforeAnyExchange() throws {
        var second: AccountPreparationIntent?
        let f = try PolicyPreflightFixture(prepare: { second = try self.reserve($0, complete: true) })
        XCTAssertThrowsError(try f.capture(policies: { source in
            try f.f.machine.policyCaptures(for: source).map { value in
                guard value.accountID == second!.accountID, let current = value.snapshot else { return value }
                let policy = try current.policy.retainingFormat(with: current.policy.entries.map { entry in
                    try .init(role: entry.role, teamID: entry.teamID, identifier: entry.identifier, installedGeneration: 2,
                        minimumGeneration: entry.minimumGeneration, codeDirectoryHash: entry.codeDirectoryHash, active: entry.active)
                })
                return .init(accountID: value.accountID, snapshot: .init(revision: current.revision, policy: policy, roleRevisions: current.roleRevisions))
            }
        }))
        XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), f.record)
    }
    func testGlobalRevisionAndRoleTokensAreRecheckedBeforeCommit() throws {
        for roleOnly in [false, true] {
            let f = try PolicyPreflightFixture(); var changed = false
            let proof = try f.capture(policies: { source in
                try f.f.machine.policyCaptures(for: source).map { value in
                    guard changed, let current = value.snapshot else { return value }
                    var roles = current.roleRevisions
                    if roleOnly { roles[.authority] = UUID() }
                    return .init(accountID: value.accountID, snapshot: .init(revision: roleOnly ? current.revision : UUID(), policy: current.policy, roleRevisions: roles))
                }
            })
            changed = true; XCTAssertThrowsError(try f.start(proof))
            XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), f.record)
        }
    }
    func testAChangedPolicyDuringTheWriteRollsBackTheIrreversibleMarker() throws {
        let f = try PolicyPreflightFixture(); var calls = 0, reject = false
        let proof = try f.capture(policies: { source in
            calls += 1
            let values = try f.f.machine.policyCaptures(for: source)
            guard reject && calls >= 4 else { return values }
            return values.map { .init(accountID: $0.accountID, snapshot: $0.snapshot.map { .init(revision: UUID(), policy: $0.policy, roleRevisions: $0.roleRevisions) }) }
        })
        reject = true; XCTAssertThrowsError(try f.start(proof))
        XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), f.record)
    }
    func testChangedCandidateEvidenceCannotAdvanceTheMarker() throws {
        let f = try PolicyPreflightFixture(); var changed = false
        let other = try f.f.machine.editedRelease { c in
            try .init(role: c.role, identifier: c.identifier, generation: c.generation + 1, relativePath: c.relativePath,
                codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: c.formats)
        }
        let proof = try f.capture(inspect: { changed ? other : f.f.machine.release })
        changed = true; XCTAssertThrowsError(try f.start(proof))
        XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), f.record)
    }
    func testForeignMachineProofCannotAuthorizeTheBoundary() throws {
        let f = try PolicyPreflightFixture(), other = try PolicyPreflightFixture(), proof = try other.capture()
        XCTAssertThrowsError(try f.start(proof)); XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), f.record)
    }
    func testAClosedQuiescenceLeaseInvalidatesTheProof() throws {
        let f = try PolicyPreflightFixture(), proof = try f.capture(); f.quiet.close()
        XCTAssertThrowsError(try f.start(proof)); XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), f.record)
    }
    func testUnknownCommitAcknowledgementReopensWithTheOriginalDigest() throws {
        let f = try PolicyPreflightFixture(), proof = try f.capture()
        try f.f.machine.reopen(hook: { throw Fault.expected }); XCTAssertThrowsError(try f.start(proof))
        try f.f.machine.reopen(); let committed = try XCTUnwrap(f.f.machine.store.machineUpdateActivation())
        XCTAssertEqual(committed.phase, .activationStarted); XCTAssertEqual(committed.policyPreflightDigest, proof.digest)
        XCTAssertNoThrow(try MachineUpdatePolicyPreflight.requireRetained(proof.source.replacingActivation(committed), policies: proof.policies))
        XCTAssertThrowsError(try f.start(proof))
    }
    func testDigestDoesNotDependOnPolicyReadOrder() throws {
        let f = try PolicyPreflightFixture(prepare: { _ = try self.reserve($0, complete: true) })
        let source = try f.source(), values = try f.f.machine.policyCaptures(for: source)
        XCTAssertEqual(try MachineUpdatePolicyPreflight.policyDigest(source: source, policies: values),
            try MachineUpdatePolicyPreflight.policyDigest(source: source, policies: Array(values.reversed())))
    }
    func testACommittedDigestRejectsChangedPolicyAtRecovery() throws {
        let f = try PolicyPreflightFixture(), proof = try f.capture(), committed = try f.start(proof)
        let changed = proof.policies.map { value in
            MachineUpdatePolicyCapture(accountID: value.accountID,
                snapshot: value.snapshot.map { .init(revision: UUID(), policy: $0.policy, roleRevisions: $0.roleRevisions) })
        }
        XCTAssertThrowsError(try MachineUpdatePolicyPreflight.requireRetained(proof.source.replacingActivation(committed), policies: changed))
    }
    // Restart checking needs an observed swap; MachineUpdateReplacementTests checks the digest through that transition.
    func testTheCommittedDigestStaysWhenRestartCheckingIsRefusedBeforeASwap() throws {
        let f = try PolicyPreflightFixture(), proof = try f.capture(), started = try f.start(proof)
        let restart = try f.quiet.releaseActivityForRestart(); defer { restart.close() }
        XCTAssertThrowsError(try f.f.machine.store.markMachineUpdateRestartChecking(started, directory: f.directory,
            restart: restart, verifyCurrent: {})) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
        let current = try XCTUnwrap(f.f.machine.store.machineUpdateActivation())
        XCTAssertEqual(current.phase, .activationStarted); XCTAssertEqual(current.policyPreflightDigest, proof.digest)
    }
    func testMalformedOrCancelledVersionTwoMarkersAreRejected() throws {
        let f = try PolicyPreflightFixture(), proof = try f.capture(), started = try f.start(proof)
        for mutation in 0...2 {
            var object = try XCTUnwrap(JSONSerialization.jsonObject(with: started.encoded) as? [String: Any])
            if mutation == 0 { object.removeValue(forKey: "policyPreflightDigest") }
            else if mutation == 1 { object["policyPreflightDigest"] = Data(repeating: 0, count: 31).base64EncodedString() }
            else { object["phase"] = 4 }
            XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])))
        }
    }
    func testCandidateMustDeclareTheNewMarkerReaderAndWriter() throws {
        let base = try MachineUpdateActivationFixture()
        for reader in [false, true] {
            let candidate = try base.machine.editedRelease { c in
                let formats = try c.formats.map { f -> ReleaseFormat in
                    guard c.role == .authority, f.name == MachineUpdateActivationRecord.formatName else { return f }
                    return try .init(name: f.name, readers: reader ? [1] : [1, 2], writers: [1])
                }
                return try .init(role: c.role, identifier: c.identifier, generation: c.generation, relativePath: c.relativePath,
                    codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: formats)
            }
            let f = try PolicyPreflightFixture(candidate: candidate)
            XCTAssertThrowsError(try f.capture(inspect: { candidate })); XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), f.record)
        }
    }
    func testRetainedMarkerMakesCompatibilityRequireVersionTwo() throws {
        let f = try PolicyPreflightFixture(), proof = try f.capture(); _ = try f.start(proof)
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.f.machine.store)
        for role in [AuthorityCodeRole.authority, .setupController] {
            let format = try XCTUnwrap(snapshot.requirements.formats.first { $0.role == role && $0.name == MachineUpdateActivationRecord.formatName })
            XCTAssertTrue(format.readVersions.contains(2)); XCTAssertTrue(format.writeVersions.contains(2))
        }
    }
    func testNativeFactoryRefusesOrdinaryUIDBeforeReadingAConfiguration() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("An ordinary process is required for the refusal control.") }
        let f = try PolicyPreflightFixture()
        XCTAssertThrowsError(try MachineUpdatePolicyPreflight.captureNative(activation: f.record, configurationPath: "/nonexistent/root.cbor",
            machine: f.f.machine.store, directory: f.directory, quiescence: f.quiet)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
    }

    private func healthCandidate(_ base: MachineUpdateActivationFixture,
                                 omitting role: AuthorityCodeRole? = nil) throws -> SignedReleaseEvidence {
        try base.machine.editedRelease { component in
            var formats = component.formats
            if component.role != role,
               let required = try MachineUpdateConsumerHealthReleaseValidation.formatRequirements.first(where: { $0.role == component.role }) {
                formats.append(try .init(name: required.name, readers: required.readVersions, writers: required.writeVersions))
            }
            return try .init(role: component.role, identifier: component.identifier, generation: component.generation + 1,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                build: component.build, teamID: component.teamID, formats: formats, requests: component.requests)
        }
    }

    private func assertHealthPreflightRefused(_ fixture: PolicyPreflightFixture, candidate: SignedReleaseEvidence,
                                              file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertThrowsError(try fixture.capture(inspect: { candidate }), file: file, line: line) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope, file: file, line: line)
        }
        XCTAssertEqual(try fixture.f.machine.store.machineUpdateActivation(), fixture.record, file: file, line: line)
        XCTAssertEqual(fixture.record.phase, .draining, file: file, line: line)
    }

    func testRegisteredForegroundRequiresAuthorityAndTransportHealthDeclarationsBeforeActivation() throws {
        let base = try MachineUpdateActivationFixture()
        for role in [AuthorityCodeRole.authority, .transport] {
            let candidate = try healthCandidate(base, omitting: role)
            let fixture = try PolicyPreflightFixture(candidate: candidate, beforeCandidateSelection: {
                try $0.store.markRuntimeJobsRegistered($0.f.plan)
            })
            try assertHealthPreflightRefused(fixture, candidate: candidate)
        }
    }

    func testRegisteredGatewayRequiresItsHealthDeclarationBeforeActivation() throws {
        let base = try MachineUpdateActivationFixture()
        for missing in [true, false] {
            let candidate = try healthCandidate(base, omitting: missing ? .notificationGateway : nil)
            let fixture = try PolicyPreflightFixture(candidate: candidate, beforeCandidateSelection: { machine in
                let store = machine.store
                let setup = try GatewayJournalSetupExchangeTests.Fixture(runtime: machine.f)
                try setup.retainCompletion(.decode(setup.initialize()))
                let plan = try GatewayRuntimeActivationPlan(journal: setup.state(), foreground: setup.runtime.plan,
                    inventory: XCTUnwrap(store.inventory()))
                try store.retainGatewayRuntimeActivation(plan)
                try store.markGatewayRuntimePublished(plan)
                _ = try store.enrollGatewayRuntimeActivation(plan)
                try store.markGatewayRuntimeRegistered(plan)
            })
            if missing {
                try assertHealthPreflightRefused(fixture, candidate: candidate)
            } else {
                let proof = try fixture.capture(inspect: { candidate })
                XCTAssertEqual(try fixture.start(proof).phase, .activationStarted)
            }
        }
    }

    func testUnregisteredGatewayDoesNotRequireItsHealthDeclarationBeforeActivation() throws {
        let base = try MachineUpdateActivationFixture()
        let candidate = try healthCandidate(base, omitting: .notificationGateway)
        let fixture = try PolicyPreflightFixture(candidate: candidate, beforeCandidateSelection: {
            try $0.store.markRuntimeJobsRegistered($0.f.plan)
        })
        let proof = try fixture.capture(inspect: { candidate })
        XCTAssertEqual(try fixture.start(proof).phase, .activationStarted)
    }

    private func provenanceCandidate(base: MachineUpdateActivationFixture,
        edit: (AuthorityCodeRole, ReleaseFormat) throws -> ReleaseFormat? = { _, value in value }) throws -> SignedReleaseEvidence {
        let requirements = try MachineUpdateProvisioningHistory.requirements +
            MachineUpdatePreflightCompatibility.configurationProvenanceRequirements + MachineUpdatePreflightCompatibility.installedProvenanceRequirements
        return try base.machine.editedRelease { component in
            var formats = component.formats
            for requirement in requirements where requirement.role == component.role {
                let previous = formats.first { $0.name == requirement.name }
                let value = try ReleaseFormat(name: requirement.name,
                    readers: (previous?.readers ?? []).union(requirement.readVersions),
                    writers: (previous?.writers ?? []).union(requirement.writeVersions))
                formats.removeAll { $0.name == requirement.name }
                if let edited = try edit(component.role, value) { formats.append(edited) }
            }
            return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                build: component.build, teamID: component.teamID, formats: formats, requests: component.requests)
        }
    }
    private func requireRejectedProvenanceCandidate(_ candidate: SignedReleaseEvidence,
        file: StaticString = #filePath, line: UInt = #line) throws {
        let value = try PolicyPreflightFixture(candidate: candidate)
        XCTAssertNil(try value.source().provisioningHistory, file: file, line: line)
        XCTAssertThrowsError(try value.capture(inspect: { candidate }), file: file, line: line) {
            XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore, file: file, line: line)
        }
        XCTAssertEqual(try value.f.machine.store.machineUpdateActivation(), value.record, file: file, line: line)
        XCTAssertEqual(value.record.phase, .draining, file: file, line: line)
        XCTAssertEqual(try value.f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 17, file: file, line: line)
    }
    func testFirstProvenanceUpdateRequiresEveryArchiveDeclarationBeforeActivationStarts() throws {
        let base = try MachineUpdateActivationFixture()
        for role in [AuthorityCodeRole.authority, .setupController] {
            for name in [MachineUpdatePreflightCompatibility.configurationFormatName, MachineUpdatePreflightCompatibility.installedFormatName] {
                let candidate = try provenanceCandidate(base: base) { currentRole, format in
                    currentRole == role && format.name == name ? nil : format
                }
                try requireRejectedProvenanceCandidate(candidate)
            }
        }
    }
    func testFirstProvenanceUpdateRequiresArchiveWritersBeforeActivationStarts() throws {
        let base = try MachineUpdateActivationFixture()
        for role in [AuthorityCodeRole.authority, .setupController] {
            for name in [MachineUpdatePreflightCompatibility.configurationFormatName, MachineUpdatePreflightCompatibility.installedFormatName] {
                let candidate = try provenanceCandidate(base: base) { currentRole, format in
                    guard currentRole == role, format.name == name else { return format }
                    return try .init(name: format.name, readers: format.readers, writers: [1])
                }
                try requireRejectedProvenanceCandidate(candidate)
            }
        }
    }
    func testFirstProvenanceUpdateRequiresHistoryReadersForBothHostsBeforeActivationStarts() throws {
        let base = try MachineUpdateActivationFixture()
        for role in [AuthorityCodeRole.authority, .setupController] {
            let candidate = try provenanceCandidate(base: base) { currentRole, format in
                guard currentRole == role, format.name == MachineUpdateProvisioningHistory.formatName else { return format }
                return try .init(name: format.name, readers: [2], writers: [2])
            }
            try requireRejectedProvenanceCandidate(candidate)
        }
    }
    func testFirstProvenanceUpdateRequiresHistoryWritersForBothHostsBeforeActivationStarts() throws {
        let base = try MachineUpdateActivationFixture()
        for role in [AuthorityCodeRole.authority, .setupController] {
            let candidate = try provenanceCandidate(base: base) { currentRole, format in
                guard currentRole == role, format.name == MachineUpdateProvisioningHistory.formatName else { return format }
                return try .init(name: format.name, readers: [1, 2], writers: [2])
            }
            try requireRejectedProvenanceCandidate(candidate)
        }
    }
    func testFirstProvenanceUpdateWithAllArchiveFormatsRetainsThePreflightAtActivationStart() throws {
        let base = try MachineUpdateActivationFixture(), candidate = try provenanceCandidate(base: base)
        let value = try PolicyPreflightFixture(candidate: candidate), proof = try value.capture(inspect: { candidate })
        XCTAssertNil(proof.source.provisioningHistory)
        let started = try value.start(proof)
        XCTAssertEqual(started.phase, .activationStarted)
        XCTAssertEqual(started.policyPreflightDigest, proof.digest)
        try value.f.machine.reopen()
        XCTAssertEqual(try value.f.machine.store.machineUpdateActivation(), started)
    }


    private func retainedSetupCandidate(_ base: MachineUpdateActivationFixture,
        missing: (AuthorityCodeRole, Bool)? = nil) throws -> SignedReleaseEvidence {
        try base.machine.editedRelease { component in
            var formats = component.formats
            for required in try MachineUpdatePreflightCompatibility.retainedSetupRequirements + MachineUpdatePreflightCompatibility.retainedSetupActivationRequirements
                where required.role == component.role {
                let index = formats.firstIndex { $0.name == required.name }
                let old = index.map { formats[$0] }
                var readers = (old?.readers ?? []).union(required.readVersions)
                var writers = (old?.writers ?? []).union(required.writeVersions)
                if required.name == RuntimeActivationPlan.formatName, missing?.0 == component.role {
                    if missing?.1 == true { writers.remove(6) }
                    else { readers.remove(6); writers.remove(6) }
                }
                let value = try ReleaseFormat(name: required.name, readers: readers, writers: writers,
                    migrations: old?.migrations ?? [:])
                if let index { formats[index] = value } else { formats.append(value) }
            }
            return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                build: component.build, teamID: component.teamID, formats: formats)
        }
    }
    func testRetainedSetupCandidateRequiresThePlanCodecBeforeTheIrreversibleMarker() throws {
        let base = try MachineUpdateActivationFixture()
        for missing in [(AuthorityCodeRole.authority, false), (.setupController, false), (.setupController, true)] {
            let candidate = try retainedSetupCandidate(base, missing: missing), f = try PolicyPreflightFixture(candidate: candidate)
            XCTAssertThrowsError(try f.capture(inspect: { candidate })) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), f.record)
            XCTAssertEqual(f.record.phase, .draining)
        }
    }
    func testRetainedSetupCandidateWithCompleteCodecSupportCanRetainThePreflightDigest() throws {
        let base = try MachineUpdateActivationFixture(), candidate = try retainedSetupCandidate(base)
        let f = try PolicyPreflightFixture(candidate: candidate), proof = try f.capture(inspect: { candidate })
        let started = try f.start(proof)
        XCTAssertEqual(started.phase, .activationStarted); XCTAssertEqual(started.policyPreflightDigest, proof.digest)
        try f.f.machine.reopen()
        XCTAssertEqual(try f.f.machine.store.machineUpdateActivation(), started)
    }

}
