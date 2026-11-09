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
    private var inspectedCopies: [UUID: SignedReleaseEvidence] = [:]
    var policy: AuthorityCodePolicy { f.plan.host.codePolicy }
    var mac: Data { f.f.mac }
    var account: Data { f.account.accountID }

    init(enable: Bool = true, enroll: Bool = true, admission: Bool = false, activation: Bool = false, replacement: Bool = false, ownedInstalledBundle: Bool = false) throws {
        f = try RuntimeActivationFixture(nativeConsumerHosts: true, ownedInstalledBundle: ownedInstalledBundle, phoneAudit: true, auditDelivery: true) { component in
            guard [.authority, .setupController].contains(component.role) else { return component }
            let versions: Set<UInt64> = replacement ? [15, 16, 17, 18] : (activation ? [15, 16, 17] : (admission ? [15, 16] : [15]))
            var formats = try component.formats.map { format in
                guard format.name == "authority.installation-preparation" else { return format }
                return try ReleaseFormat(name: format.name, readers: format.readers.union(versions), writers: format.writers.union(versions))
            }
            formats.append(try .init(name: UpdateSchedulingCandidateRecord.formatName, readers: [1], writers: [1]))
            if admission { formats.append(try .init(name: UpdateAdmissionRegistrationRecord.formatName, readers: [1], writers: [1])) }
            if activation { formats.append(try .init(name: MachineUpdateActivationRecord.formatName, readers: [1, 2], writers: [1, 2])) }
            if replacement { formats.append(try .init(name: MachineUpdateReplacementRecord.formatName, readers: [1], writers: [1])) }
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
    func copy(release candidate: SignedReleaseEvidence? = nil) throws -> PreparationIntentRecord {
        let intent = try store.begin(parent: destination.path, ancestry: destination.preparationAncestry())
        let path = URL(fileURLWithPath: destination.path).appendingPathComponent(intent.bundleName)
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(path.path, 0o755), 0)
        let payload = path.appendingPathComponent("fixture")
        try Data("synthetic candidate copy".utf8).write(to: payload)
        XCTAssertEqual(chmod(payload.path, 0o644), 0)
        let signed = candidate ?? release
        let record = try store.recordCopy(id: intent.id, expectedRevision: intent.revision,
            identity: destination.preparationCopyIdentity(name: intent.bundleName), digest: DurableReleasePreparation.digest(signed))
        inspectedCopies[record.id] = signed
        return record
    }
    func select(_ copy: PreparationIntentRecord, replacing previous: UpdateSchedulingCandidateRecord? = nil) throws -> UpdateSchedulingCandidateRecord {
        try store.selectUpdateCandidate(preparation: copy, runtime: store.retainedRuntimeCompatibilityInputs(), replacing: previous)
    }
    func withCurrent<T>(_ record: UpdateSchedulingCandidateRecord, _ body: (_ validate: @escaping () throws -> Void) throws -> T) throws -> T {
        try store.withValidatedUpdateCandidate(record, runtime: store.retainedRuntimeCompatibilityInputs(), body)
    }
    func binding(_ record: PreparationIntentRecord) throws -> UpdateSchedulingPreparedRelease {
        try .captureInLease(attemptID: record.id, macID: mac, accountID: account, destination: destination,
            store: store, readPolicy: { self.policy }, inspect: { _, _, _ in self.evidence(record) })
    }
    func withLiveCandidate<Value: Sendable>(_ record: UpdateSchedulingCandidateRecord,
        _ body: (LiveUpdateSchedulingCandidate) throws -> Value) throws -> Value {
        try binding(record.preparation).withCurrentCandidateLeaseInLease(macID: mac, accountID: account,
            expected: record, destination: destination, store: store,
            readPolicy: { self.policy }, inspect: { _, _, _ in self.evidence(record.preparation) }, body)
    }
    func policyCaptures(for source: MachineUpdateRestartSource) throws -> [MachineUpdatePolicyCapture] {
        try source.accounts.map { account in
            guard let initial = account.initialization else { return .init(accountID: account.accountID, snapshot: nil) }
            let directory = (initial.journalPath as NSString).deletingLastPathComponent
            guard directory.hasPrefix(f.f.root.path + "/") else { throw PreparationStoreError.corruptRecord }
            let value: AuthorityCodePolicySnapshot?
            do {
                value = try MachineUpdatePolicyRead.readInLease(.init(anchor: f.f.root.path,
                    relativeDirectory: String(directory.dropFirst(f.f.root.path.count + 1)), owner: getuid()),
                    macID: initial.macID, accountID: initial.accountID)
            } catch JournalLeaseError.system(let code) where code == ENOENT && !initial.complete && initial.checkpoint == nil { value = nil }
            return .init(accountID: account.accountID, snapshot: value)
        }
    }
    func policyPreflight(_ activation: MachineUpdateActivationRecord, directory: ReleaseDestinationLease,
                         quiet: UpdateQuiescenceLease) throws -> MachineUpdatePolicyPreflight {
        let candidate = try XCTUnwrap(store.updateCandidate())
        return try .captureInLease(activation: activation, machine: store, directory: directory, quiescence: quiet,
            readPolicies: policyCaptures, inspectCandidate: {
                guard try self.destination.preparationAncestry() == candidate.preparation.ancestry,
                      try self.destination.preparationCopyIdentity(name: candidate.preparation.bundleName) == candidate.preparation.copyIdentity else {
                    throw MachineUpdateActivationError.changedScope
                }
                _ = try self.destination.inspectCopiedTree(name: candidate.preparation.bundleName)
                return self.evidence(candidate.preparation)
            })
    }
    private func evidence(_ record: PreparationIntentRecord) -> SignedReleaseEvidence { inspectedCopies[record.id] ?? release }
    func reopen(hook: (() throws -> Void)? = nil, inventoryRecordLimit: Int32 = 278_528) throws {
        try store.close()
        store = try f.f.open(hook: hook, inventoryRecordLimit: inventoryRecordLimit)
    }
    func sql(_ statement: String) throws { XCTAssertEqual(try f.f.sql(statement), Int64(SQLITE_OK)) }
    func editedRelease(_ edit: (ReleaseComponent) throws -> ReleaseComponent) throws -> SignedReleaseEvidence {
        try .init(manifest: .init(release: release.manifest.release, build: release.manifest.build,
            components: release.manifest.components.map(edit), dependencies: release.manifest.dependencies),
            codeDirectoryHashes: release.codeDirectoryHashes, dependencyCodeDirectoryHashes: release.dependencyCodeDirectoryHashes)
    }
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
