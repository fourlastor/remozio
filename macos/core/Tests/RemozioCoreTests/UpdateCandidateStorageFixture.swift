import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

/// Owned files and synthetic release evidence. This fixture grants no installed or live update authority.
final class UpdateCandidateStorageFixture {
    let f: RuntimeActivationFixture
    var store: PreparationIntentStore
    let release: SignedReleaseEvidence
    let destination: ReleaseDestinationLease
    var policy: AuthorityCodePolicy { f.plan.host.codePolicy }

    init(enable: Bool = true, enroll: Bool = true) throws {
        f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true, auditDelivery: true) { component in
            guard [.authority, .setupController].contains(component.role) else { return component }
            var formats = try component.formats.map { format in
                guard format.name == "authority.installation-preparation" else { return format }
                return try ReleaseFormat(name: format.name, readers: format.readers.union([15]), writers: format.writers.union([15]))
            }
            formats.append(try .init(name: UpdateSchedulingCandidateRecord.formatName, readers: [1], writers: [1]))
            return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                build: component.build, teamID: component.teamID, formats: formats)
        }
        store = f.machine
        release = try XCTUnwrap(f.nativeRelease)
        if enroll { try store.retainRuntimeActivation(f.plan); _ = try store.enrollRuntimeActivation(f.plan) }
        let path = f.f.root.appendingPathComponent("CandidateCopies")
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(path.path, 0o755), 0)
        destination = try .init(anchor: f.f.root.path, relativeDirectory: "CandidateCopies", owner: getuid())
        if enable { try self.enable() }
    }

    deinit { destination.close(); try? store.close() }
    func enable() throws {
        try UpdateSchedulingCurrentCandidate.enableStorageInLease(installedRelease: release, policy: policy, store: store)
    }
    func copy() throws -> PreparationIntentRecord {
        let intent = try store.begin(parent: destination.path, ancestry: destination.preparationAncestry())
        let path = URL(fileURLWithPath: destination.path).appendingPathComponent(intent.bundleName)
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(path.path, 0o755), 0)
        let payload = path.appendingPathComponent("fixture")
        try Data("synthetic candidate copy".utf8).write(to: payload)
        XCTAssertEqual(chmod(payload.path, 0o644), 0)
        return try store.recordCopy(id: intent.id, expectedRevision: intent.revision,
            identity: destination.preparationCopyIdentity(name: intent.bundleName), digest: DurableReleasePreparation.digest(release))
    }
    func select(_ copy: PreparationIntentRecord, replacing previous: UpdateSchedulingCandidateRecord? = nil) throws -> UpdateSchedulingCandidateRecord {
        try store.selectUpdateCandidate(preparation: copy, runtime: store.retainedRuntimeCompatibilityInputs(), replacing: previous)
    }
    func withCurrent<T>(_ record: UpdateSchedulingCandidateRecord, _ body: (_ validate: @escaping () throws -> Void) throws -> T) throws -> T {
        try store.withValidatedUpdateCandidate(record, runtime: store.retainedRuntimeCompatibilityInputs(), body)
    }
    func reopen(hook: (() throws -> Void)? = nil) throws {
        try store.close()
        store = try f.f.open(hook: hook)
    }
    func sql(_ statement: String) throws { XCTAssertEqual(try f.f.sql(statement), Int64(SQLITE_OK)) }
    func changedRelease(removing name: String) throws -> SignedReleaseEvidence {
        let components = try release.manifest.components.map { component in
            try ReleaseComponent(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                teamID: component.teamID, formats: component.formats.filter { $0.name != name })
        }
        return try .init(manifest: .init(release: release.manifest.release, build: release.manifest.build, components: components),
            codeDirectoryHashes: release.codeDirectoryHashes, dependencyCodeDirectoryHashes: release.dependencyCodeDirectoryHashes)
    }
}
