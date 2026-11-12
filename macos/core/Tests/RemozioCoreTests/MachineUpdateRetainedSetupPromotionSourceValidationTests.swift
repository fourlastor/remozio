import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses an actual owned pair and injected source bytes. The machine still has no completed retained registration.
struct RetainedPromotionSourceValidationFixture {
    let completion: MachineUpdateRetainedSetupCompletionSnapshot
    let candidate: SignedReleaseEvidence
    let material: RuntimePreparationMaterial
    let plan: RuntimeRetainedSetupActivationPlan
    let publication: RuntimeRetainedSetupCompletionPublication
    let files: [String: RuntimePublishedArtifactValidation.Artifact]
    let boundary: () throws -> AuthorityJournal.MachineUpdatePolicyBoundary
    let verifyCurrent: () throws -> Void

    func read(_ artifact: RuntimePublishedArtifactValidation.Artifact) throws -> Data {
        guard let actual = files[artifact.path], actual.access == artifact.access else { throw RuntimePreparationError.invalidRecord }
        return actual.bytes
    }
    func withIntent(_ phase: MachineUpdateRetainedSetupCompletionIntentRecord.Phase?) throws -> MachineUpdateRetainedSetupCompletionSnapshot {
        let record: MachineUpdateRetainedSetupCompletionIntentRecord?
        if let phase {
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(completion.intent).encoded) as? [String: Any])
            fields["phase"] = phase.rawValue
            if phase != .recorded { fields["committedPolicy"] = nil; fields["committedCheckpoint"] = nil }
            record = try .decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
        } else { record = nil }
        return try .init(activation: completion.activation, intent: record, candidate: candidate)
    }
}

final class MachineUpdateRetainedSetupPromotionSourceValidationTests: XCTestCase {
    private typealias Source = MachineUpdateRetainedSetupPromotionSourceValidation
    private typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    private typealias Fixture = RetainedPromotionSourceValidationFixture
    private enum Failed: Error { case injected, expectedPending }

    private func fixture(_ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPromotionSourceValidationFixture(body)
    }
    private func pending(_ snapshot: MachineUpdateRetainedSetupCompletionSnapshot, _ pair: Boundary)
        throws -> MachineUpdateRetainedSetupCompletionIntentRecord {
        guard case .completionReceiptPending(let proposal) = try snapshot.classifyPair(pair) else { throw Failed.expectedPending }
        return proposal
    }
    private func capture(_ f: Fixture, read: (RuntimePublishedArtifactValidation.Artifact) throws -> Data)
        throws -> RuntimeRetainedSetupCompletionPublication {
        try Source.capture(expected: f.completion, material: f.material, candidate: f.candidate,
            readPolicyBoundary: f.boundary, verifyCurrent: f.verifyCurrent, read: read)
    }
    private func globalChange(_ pair: Boundary) -> Boundary {
        .init(macID: pair.macID, accountID: pair.accountID,
            policy: .init(revision: UUID(), policy: pair.policy.policy, roleRevisions: pair.policy.roleRevisions), checkpoint: pair.checkpoint)
    }
    private func originalPaths(_ f: Fixture) throws -> [String] {
        let paths = try RuntimePreparationPaths(accountID: f.plan.accountID)
        return [paths.privateDirectory + "/" + AdministrativeSetupPublication.File.commandHost.name,
            f.plan.authorityJob.path, f.plan.transportJob.path]
    }
    private func rejectLaterBytes(_ f: Fixture, paths: [String]) throws {
        for target in paths {
            var reads = 0
            XCTAssertThrowsError(try capture(f) { artifact in
                let bytes = try f.read(artifact)
                if artifact.path == target { reads += 1; if reads > 1 { return bytes + Data([0]) } }
                return bytes
            }) { XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration) }
            XCTAssertEqual(reads, 2, target)
        }
    }

    func testOwnedCapturePinsTheActualPairAndAllSourceBytes() throws {
        try fixture { f in
            let before = try f.boundary()
            var reads: [String: Int] = [:]
            let value = try capture(f) { artifact in reads[artifact.path, default: 0] += 1; return try f.read(artifact) }
            XCTAssertEqual(try value.encoded, try f.publication.encoded)
            XCTAssertEqual(try f.boundary(), before)
            XCTAssertEqual(reads.values.reduce(0, +), 33)
            XCTAssertEqual(Set(reads.keys), Set(f.files.keys))
            for path in try originalPaths(f) { XCTAssertEqual(reads[path], 2) }
        }
    }

    func testCompletionRuntimePinsAnotherValidRecoveredGlobalRevisionAtEveryRead() throws {
        try fixture { f in
            let writing = try f.withIntent(.writing), pair = try f.boundary(), changed = globalChange(pair)
            _ = try pending(writing, pair); _ = try pending(writing, changed)
            for changedAfter in 1...11 {
                var reads = 0
                XCTAssertThrowsError(try writing.activation.validateCompletionRuntime(plan: f.plan, material: f.material,
                    completion: writing, readPolicyBoundary: { reads >= changedAfter ? changed : pair }, candidate: f.candidate,
                    verifyCurrent: f.verifyCurrent, read: { reads += 1; return try f.read($0) })) {
                        XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                    }
                XCTAssertEqual(reads, changedAfter)
            }
        }
    }

    func testPairFenceRejectsRoleRevisionAndCheckpointChanges() throws {
        try fixture { f in
            let writing = try f.withIntent(.writing), pair = try f.boundary()
            let startup = try XCTUnwrap(writing.intent?.startupIntent.committedPolicy?.snapshot())
            let role = try XCTUnwrap(pair.policy.roleRevisions.keys.first { pair.policy.roleRevisions[$0] != startup.roleRevisions[$0] })
            var revisions = pair.policy.roleRevisions; revisions[role] = UUID()
            let roleChanged = Boundary(macID: pair.macID, accountID: pair.accountID,
                policy: .init(revision: pair.policy.revision, policy: pair.policy.policy, roleRevisions: revisions), checkpoint: pair.checkpoint)
            _ = try pending(writing, roleChanged)
            let cp = pair.checkpoint
            let checkpoint = try ContinuityCheckpoint(generation: cp.generation, authorityDigest: cp.authorityDigest,
                ledgerDigest: Data(repeating: 71, count: 32), journalEpoch: cp.journalEpoch,
                journalHead: cp.journalHead, authorityGeneration: cp.authorityGeneration)
            let checkpointChanged = Boundary(macID: pair.macID, accountID: pair.accountID, policy: pair.policy, checkpoint: checkpoint)
            XCTAssertEqual(try ContinuityCheckpoint.decode(checkpoint.bytes), checkpoint)
            for changed in [roleChanged, checkpointChanged] {
                var useChanged = false
                XCTAssertThrowsError(try Source.withPinnedPair(completion: writing,
                    readPolicyBoundary: { useChanged ? changed : pair }, verifyCurrent: f.verifyCurrent) { _, _, current in
                        try current(); useChanged = true; try current()
                    }) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            }
        }
    }

    func testWritingPairCannotChangeItsValidClassificationDuringTheScope() throws {
        try fixture { f in
            let writing = try f.withIntent(.writing), pair = try f.boundary()
            let intent = try XCTUnwrap(writing.intent), startupPolicy = try XCTUnwrap(intent.startupIntent.committedPolicy?.snapshot())
            let startup = Boundary(macID: pair.macID, accountID: pair.accountID, policy: startupPolicy,
                checkpoint: try .decode(XCTUnwrap(intent.startupIntent.committedCheckpoint)))
            XCTAssertEqual(Source.kind(try writing.classifyPair(pair)), .receiptPending)
            XCTAssertEqual(Source.kind(try writing.classifyPair(startup)), .startup)
            var switched = false
            XCTAssertThrowsError(try Source.withPinnedPair(completion: writing, readPolicyBoundary: { switched ? startup : pair },
                verifyCurrent: f.verifyCurrent) { _, _, current in switched = true; try current() }) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
        }
    }

    func testRegeneratedProposalRevisionsDoNotChangeThePinnedPairKind() throws {
        try fixture { f in
            let writing = try f.withIntent(.writing), pair = try f.boundary()
            let first = try pending(writing, pair), second = try pending(writing, pair)
            XCTAssertNotEqual(first.revision, second.revision)
            var escaped: (() throws -> Void)?
            try Source.withPinnedPair(completion: writing, readPolicyBoundary: f.boundary,
                verifyCurrent: f.verifyCurrent) { actual, kind, current in
                    XCTAssertEqual(actual, pair); XCTAssertEqual(kind, .receiptPending)
                    try current(); try current(); escaped = current
                }
            XCTAssertThrowsError(try XCTUnwrap(escaped)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testOriginalHostAndBothJobManifestsRejectChangesAfterAValidRead() throws {
        try fixture { f in
            _ = try capture(f, read: f.read)
            try rejectLaterBytes(f, paths: originalPaths(f))
        }
    }

    func testRuntimeClientsAndMaterialRejectChangesAfterAValidRead() throws {
        try fixture { f in
            let originals = Set(try originalPaths(f))
            _ = try capture(f, read: f.read)
            try rejectLaterBytes(f, paths: f.files.keys.filter { !originals.contains($0) }.sorted())
        }
    }

    func testMaterialMustMatchBeforeAnyClientRead() throws {
        try fixture { f in
            var reads = 0
            XCTAssertThrowsError(try capture(f) { artifact in reads += 1; return try f.read(artifact) + Data([0]) }) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertEqual(reads, 1)
        }
    }

    func testAValidChangedCompletionRowIsRejectedAfterEverySourceRead() throws {
        try fixture { f in
            var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(f.completion.intent).encoded) as? [String: Any])
            fields["revision"] = UUID().uuidString
            let intent = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(JSONSerialization.data(withJSONObject: fields,
                options: [.sortedKeys, .withoutEscapingSlashes]))
            let changed = try MachineUpdateRetainedSetupCompletionSnapshot(activation: f.completion.activation, intent: intent, candidate: f.candidate)
            try changed.requireSame(as: changed)
            for changedAfter in 1...33 {
                var reads = 0
                XCTAssertThrowsError(try Source.capture(expected: f.completion, material: f.material, candidate: f.candidate,
                    readPolicyBoundary: f.boundary, verifyCurrent: {
                        try f.verifyCurrent()
                        if reads >= changedAfter { try changed.requireSame(as: f.completion) }
                    }, read: { reads += 1; return try f.read($0) })) {
                        XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                    }
                XCTAssertEqual(reads, changedAfter)
            }
        }
    }

    func testUnrecordedCompletionIsRejectedBeforeReadingThePair() throws {
        try fixture { f in
            let phases: [MachineUpdateRetainedSetupCompletionIntentRecord.Phase?] = [nil, .prepared, .writing]
            for phase in phases {
                let snapshot = try f.withIntent(phase)
                var pairs = 0, files = 0
                XCTAssertThrowsError(try Source.capture(expected: snapshot, material: f.material, candidate: f.candidate,
                    readPolicyBoundary: { pairs += 1; return try f.boundary() }, verifyCurrent: f.verifyCurrent,
                    read: { files += 1; return try f.read($0) })) { XCTAssertEqual($0 as? RuntimeActivationError, .incomplete) }
                XCTAssertEqual(pairs, 0); XCTAssertEqual(files, 0)
            }
        }
    }

    func testPairReadFailureCannotReachTheFiles() throws {
        try fixture { f in
            var files = 0
            XCTAssertThrowsError(try Source.capture(expected: f.completion, material: f.material, candidate: f.candidate,
                readPolicyBoundary: { throw Failed.injected }, verifyCurrent: f.verifyCurrent,
                read: { files += 1; return try f.read($0) })) { XCTAssertTrue($0 is Failed) }
            XCTAssertEqual(files, 0)
        }
    }

    func testPairFailureAfterAReadCannotReturnPublication() throws {
        try fixture { f in
            var files = 0
            XCTAssertThrowsError(try Source.capture(expected: f.completion, material: f.material, candidate: f.candidate,
                readPolicyBoundary: { if files > 0 { throw Failed.injected }; return try f.boundary() }, verifyCurrent: f.verifyCurrent,
                read: { files += 1; return try f.read($0) })) { XCTAssertTrue($0 is Failed) }
            XCTAssertEqual(files, 1)
        }
    }

    func testActivationArtifactsKeepTheExactOriginalHostAndTwoCheckedJobs() throws {
        try fixture { f in
            let actual = try Source.activationArtifacts(f.plan), paths = try originalPaths(f)
            XCTAssertEqual(actual.map(\.path), paths)
            XCTAssertEqual(actual.map(\.access), [.privateRoot, .publicRoot, .publicRoot])
            for artifact in actual { XCTAssertEqual(artifact.bytes, try f.read(artifact)) }
            XCTAssertEqual(actual[0].bytes, f.plan.host.canonicalBytes)
            XCTAssertEqual(actual[1].bytes, f.plan.authorityJob.bytes)
            XCTAssertEqual(actual[2].bytes, f.plan.transportJob.bytes)
            let root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remozio-G5-job-retention-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: root)) }
            XCTAssertEqual(chmod(root.path, 0o755), 0)
            let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Jobs", owner: getuid(), visibility: .sharedMetadata)
            defer { directory.close() }
            for job in [f.plan.authorityJob, f.plan.transportJob] {
                let file = AdministrativeSetupPublication.File.accountJob(accountID: f.plan.accountID, role: job.declaration.role)
                _ = try AdministrativeSetupPublication.publish(job.bytes, file: file, directory: directory, owner: getuid())
                XCTAssertEqual(try Source.retainedJobBytes(job, directory: directory, owner: getuid()), job.bytes)
                let path = URL(fileURLWithPath: directory.path).appendingPathComponent(file.name)
                try (job.bytes + Data([0])).write(to: path)
                XCTAssertThrowsError(try Source.retainedJobBytes(job, directory: directory, owner: getuid()))
                try job.bytes.write(to: path)
                XCTAssertEqual(chmod(path.path, 0o600), 0)
                XCTAssertThrowsError(try Source.retainedJobBytes(job, directory: directory, owner: getuid())) {
                    XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
                }
                XCTAssertEqual(chmod(path.path, 0o644), 0)
                XCTAssertEqual(try Source.retainedJobBytes(job, directory: directory, owner: getuid()), job.bytes)
                try FileManager.default.removeItem(at: path)
                XCTAssertThrowsError(try Source.retainedJobBytes(job, directory: directory, owner: getuid()))
                XCTAssertFalse(FileManager.default.fileExists(atPath: path.path))
            }
        }
    }
}
