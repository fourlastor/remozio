import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Ordinary-owner files and SQLite only. No native custody, service barrier or installed cutover is qualified.
final class RuntimeAuditUpgradeGraphTests: XCTestCase {
    typealias Fixture = RuntimeAuditUpgradeCollectorTests.Fixture
    private struct Interrupted: Error {}
    private func staged(imported: RuntimeAuditUpgradeImportTests.Fixture? = nil) throws -> Fixture {
        let f = try Fixture(imported: imported), runtime = f.files.f
        f.record = try RuntimeAuditUpgradeStaging.stageOwned(machine: runtime.machine, account: runtime.account,
            expected: f.record, currentPolicy: f.files.preparation.source.host.codePolicy,
            installedRelease: XCTUnwrap(runtime.nativeRelease), directory: XCTUnwrap(f.files.directories[.runtime]), owner: getuid(),
            verifyCurrent: {}, verifyActivity: { XCTAssertEqual($0, f.record.intent.target.serviceActivity) })
        return f
    }
    private func graph(_ f: Fixture, journal: GatewayJournalFileIdentity? = nil) throws -> RuntimeAuditUpgradeGraph {
        let scope = try f.scope(); defer { scope.close() }
        return try .init(observation: f.collect(scope, journal: { journal }), upgrade: f.record,
            installedRelease: XCTUnwrap(f.files.f.nativeRelease), currentPolicy: f.files.preparation.source.host.codePolicy)
    }
    private func decode(_ bytes: Data, _ f: Fixture, digest: Data? = nil,
                        ownership: RuntimeAuditUpgradeArtifactSnapshot.Ownership = .ordinaryOwnerFixture) throws -> RuntimeAuditUpgradeGraph {
        try .decode(bytes, expectedDigest: digest ?? Data(SHA256.hash(data: bytes)), installedRelease: XCTUnwrap(f.files.f.nativeRelease),
            currentPolicy: f.files.preparation.source.host.codePolicy, ownership: ownership)
    }
    private func retain(_ value: RuntimeAuditUpgradeGraph, _ f: Fixture) throws -> RuntimeAuditUpgradeGraphRecord {
        try f.files.f.machine.retainRuntimeAuditGraph(value, installedRelease: XCTUnwrap(f.files.f.nativeRelease),
            currentPolicy: f.files.preparation.source.host.codePolicy)
    }
    private func restore(_ record: RuntimeAuditUpgradeGraphRecord, _ f: Fixture,
                         hook: (RuntimeAuditUpgradeGraphStorage.Stage) throws -> Void = { _ in },
                         publication: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RuntimeAuditUpgradeGraphRecord {
        try RuntimeAuditUpgradeGraphStorage.restoreOwned(machine: f.files.f.machine, expected: record,
            installedRelease: XCTUnwrap(f.files.f.nativeRelease), currentPolicy: f.files.preparation.source.host.codePolicy,
            directory: XCTUnwrap(f.files.directories[.runtime]), owner: getuid(), verifyOwner: {}, didStage: hook, publicationStage: publication)
    }
    private func path(_ value: RuntimeAuditUpgradeGraph, _ f: Fixture) throws -> String {
        try XCTUnwrap(f.files.directories[.runtime]).path + "/" + AdministrativeSetupPublication.File.auditUpgradeGraph(
            intentID: value.upgrade.intent.id, contentDigest: value.digest).name
    }
    private func fields(_ value: RuntimeAuditUpgradeGraph) throws -> [UInt64: CBORValue] {
        guard case .map(let f) = try DeterministicCBOR.decode(value.bytes, limits: RuntimeAuditUpgradeGraph.limits) else {
            throw RuntimePreparationError.invalidRecord
        }
        return f
    }
    func testRoundTripRestoresTheClosedGraphAndRedactsPrivateMaterial() throws {
        let f = try staged(), value = try graph(f), decoded = try decode(value.bytes, f)
        XCTAssertEqual(decoded.bytes, value.bytes); XCTAssertEqual(decoded.upgrade, f.record)
        XCTAssertEqual(decoded.snapshot.retainedParents, value.snapshot.retainedParents)
        XCTAssertEqual(decoded.snapshot.leaves.map(\.source), value.snapshot.leaves.map(\.source))
        XCTAssertEqual(decoded.snapshot.leaves.map(\.target), value.snapshot.leaves.map(\.target))
        XCTAssertEqual(decoded.snapshot.leaves.map(\.metadata), value.snapshot.leaves.map(\.metadata))
        XCTAssertNotNil(value.bytes.range(of: f.files.f.material.transportIdentity))
        XCTAssertEqual(String(reflecting: decoded), "RuntimeAuditUpgradeGraph(redacted)")
        XCTAssertEqual(Mirror(reflecting: decoded).children.count, 0)
        XCTAssertThrowsError(try decode(value.bytes, f, ownership: .native))
        XCTAssertThrowsError(try decode(value.bytes, f, digest: Data(repeating: 0, count: 32)))
    }
    func testPendingGatewayAndPrivateRelayRoundTripWithTheirExactSelections() throws {
        for imported in [false, true] {
            let importedFixture = try imported ? RuntimeAuditUpgradeImportTests.Fixture() : nil
            defer { withExtendedLifetime(importedFixture) {} }
            let f = try staged(imported: importedFixture)
            let gateway = imported ? nil : try f.gateway(pending: true)
            let value = try graph(f, journal: gateway?.journal.intent?.files), decoded = try decode(value.bytes, f)
            XCTAssertEqual(decoded.bytes, value.bytes)
            XCTAssertEqual(decoded.snapshot.plan.gateway.settings.phase, gateway?.settings.phase)
            XCTAssertEqual(decoded.snapshot.plan.gateway.settings.pending?.id, gateway?.settings.pending?.id)
            XCTAssertEqual(decoded.snapshot.plan.sourceImport?.intent, value.snapshot.plan.sourceImport?.intent)
            XCTAssertEqual(decoded.snapshot.plan.sourceImport?.targetReference, value.snapshot.plan.sourceImport?.targetReference)
        }
    }
    func testMalformedUnknownMissingDuplicateAndForgedTargetFieldsRefuseEvenWithMatchingDigest() throws {
        let f = try staged(), value = try graph(f), original = try fields(value)
        var variants: [[UInt64: CBORValue]] = []
        var changed = original; changed[0] = .unsigned(2); variants.append(changed)
        changed = original; changed[14] = .null; variants.append(changed)
        changed = original; changed.removeValue(forKey: 13); variants.append(changed)
        guard case .array(let leaves) = original[12] else { return XCTFail() }
        changed = original; changed[12] = .array(leaves + [leaves[0]]); variants.append(changed)
        changed = original; changed[12] = .array(Array(leaves.dropLast())); variants.append(changed)
        var forged = leaves
        guard case .array(var leaf) = forged[0] else { return XCTFail() }
        leaf[3] = .bytes(Data("forged target".utf8)); forged[0] = .array(leaf)
        changed = original; changed[12] = .array(forged); variants.append(changed)
        changed = original; changed[3] = .array([.unsigned(1), .unsigned(0), .unsigned(0)]); variants.append(changed)
        for fields in variants {
            let bytes = try DeterministicCBOR.encode(.map(fields), limits: RuntimeAuditUpgradeGraph.limits)
            XCTAssertThrowsError(try decode(bytes, f))
        }
        XCTAssertThrowsError(try decode(Data(repeating: 0, count: RuntimeAuditUpgradeGraph.maximumBytes + 1), f))
    }
    func testRetentionCommitsPrivateChunksAndPublicPointerWithoutPublishingOrChangingRuntime() throws {
        let f = try staged(), value = try graph(f), machine = f.files.f.machine
        let before = try machine.runtimePreparation(accountID: f.files.f.account.accountID), inventory = try machine.inventory()
        let record = try retain(value, f)
        XCTAssertEqual(record.phase, .retained); XCTAssertEqual(try f.files.f.f.sql("PRAGMA user_version"), 13)
        XCTAssertEqual(try f.files.f.f.sql("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"), 15)
        XCTAssertEqual(try f.files.f.f.sql("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('runtime_audit_upgrade_v1','runtime_audit_graph_v1','runtime_audit_graph_chunks_v1')"), 3)
        XCTAssertEqual(try machine.runtimeAuditGraphBytes(record), value.bytes)
        XCTAssertEqual(try retain(value, f), record)
        XCTAssertFalse(FileManager.default.fileExists(atPath: try path(value, f)))
        XCTAssertEqual(try machine.runtimePreparation(accountID: f.files.f.account.accountID), before)
        XCTAssertEqual(try machine.inventory(), inventory)
        let compatibility = try RuntimeReleaseCompatibilitySnapshot.capture(machine: machine)
        XCTAssertEqual(compatibility.inputs.auditGraphs, [record])
        for name in [RuntimeAuditUpgradeGraph.formatName, RuntimeAuditUpgradeGraphRecord.formatName] {
            XCTAssertTrue(compatibility.requirements.formats.contains { $0.role == .setupController && $0.name == name && $0.readVersions == [1] })
        }
        XCTAssertNil(try record.encoded.range(of: f.files.f.material.transportIdentity))
        try machine.close(); let reopened = try f.files.f.f.open(); defer { try? reopened.close() }
        XCTAssertEqual(try reopened.runtimeAuditGraphBytes(record), value.bytes)
    }
    func testPrivateLargeGraphReaderDoesNotExpandServiceConfigurationLimits() throws {
        let f = try staged(), gateway = try f.gateway(pending: true)
        let value = try graph(f, journal: gateway.journal.intent?.files), record = try retain(value, f)
        XCTAssertGreaterThan(value.bytes.count, ProtectedServiceConfiguration.maximumBytes)
        let stored = try restore(record, f), directory = try XCTUnwrap(f.files.directories[.runtime])
        XCTAssertEqual(stored.phase, .fileStored)
        XCTAssertThrowsError(try ProtectedServiceConfiguration.read(anchor: directory.path,
            relativePath: (try path(value, f) as NSString).lastPathComponent, owner: getuid()))
        XCTAssertEqual(try ProtectedServiceConfiguration.readAuditGraph(anchor: directory.path, intentID: value.upgrade.intent.id,
            contentDigest: value.digest, owner: getuid()), value.bytes)
        var info = stat(); XCTAssertEqual(lstat(try path(value, f), &info), 0); XCTAssertEqual(info.st_mode & 0o777, 0o600)
        XCTAssertEqual(try restore(record, f), stored)
        var again = stat(); XCTAssertEqual(lstat(try path(value, f), &again), 0); XCTAssertEqual(again.st_ino, info.st_ino)
    }
    func testEveryCoordinatorAndPublicationInterruptionRecoversTheSameCommittedCopy() throws {
        for stop in RuntimeAuditUpgradeGraphStorage.Stage.allCases {
            let f = try staged(), value = try graph(f), record = try retain(value, f)
            XCTAssertThrowsError(try restore(record, f, hook: { if $0 == stop { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertEqual(try restore(record, f).phase, .fileStored)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(value, f))), value.bytes)
        }
        for afterRename in [false, true] {
            let f = try staged(), value = try graph(f), record = try retain(value, f)
            XCTAssertThrowsError(try restore(record, f, publication: { if ($0 == .published) == afterRename { throw Interrupted() } }))
            XCTAssertEqual(try restore(record, f).phase, .fileStored)
        }
    }
    func testHistoricalCopyRecoversAfterSettingsChangeAndSourceFileRemovalWithoutClaimingCurrentness() throws {
        let f = try staged(), gateway = try f.gateway(pending: true)
        let value = try graph(f, journal: gateway.journal.intent?.files), record = try retain(value, f)
        try f.files.f.machine.markGatewaySettingsTransition(XCTUnwrap(gateway.settings.pending), phase: .filesPublished)
        let source = try f.files.entry("runtime-material.cbor", f.files.plan(gateway: gateway))
        XCTAssertEqual(unlink(try XCTUnwrap(f.files.directories[.runtime]).path + "/" + source.file.name), 0)
        XCTAssertEqual(try restore(record, f).phase, .fileStored)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(value, f))), value.bytes)
        let decoded = try decode(value.bytes, f)
        XCTAssertThrowsError(try decoded.snapshot.validate(directories: f.files.directories, owner: getuid(),
            ownership: .ordinaryOwnerFixture, verifyCurrent: {}))
        XCTAssertThrowsError(try retain(value, f))
    }
    func testMultipleImmutableGenerationsPreserveEarlierFilesAndRecords() throws {
        let f = try staged(), first = try graph(f), a = try retain(first, f); _ = try restore(a, f)
        let entry = try f.files.entry("runtime-material.cbor", f.files.plan())
        let bytes = try Data(contentsOf: URL(fileURLWithPath: XCTUnwrap(f.files.directories[.runtime]).path + "/" + entry.file.name))
        try f.files.write(bytes, entry)
        let second = try graph(f); XCTAssertNotEqual(first.digest, second.digest)
        let b = try retain(second, f); _ = try restore(b, f)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(first, f))), first.bytes)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(second, f))), second.bytes)
        XCTAssertEqual(try f.files.f.machine.retainedRuntimeCompatibilityInputs().auditGraphs.count, 2)
    }
    func testMissingCopyRebuildsButConflictsLinksAndUnsafeModesRemainUntouched() throws {
        for mode in 0...3 {
            let f = try staged(), value = try graph(f), record = try retain(value, f), name = try path(value, f)
            _ = try restore(record, f)
            if mode == 0 {
                XCTAssertEqual(unlink(name), 0); _ = try restore(record, f)
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: name)), value.bytes)
            } else if mode == 1 {
                let bad = Data("conflict".utf8); try bad.write(to: URL(fileURLWithPath: name))
                XCTAssertThrowsError(try restore(record, f)); XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: name)), bad)
            } else if mode == 2 {
                XCTAssertEqual(unlink(name), 0); XCTAssertEqual(symlink("runtime-material.cbor", name), 0)
                XCTAssertThrowsError(try restore(record, f)); var info = stat(); XCTAssertEqual(lstat(name, &info), 0)
                XCTAssertEqual(info.st_mode & S_IFMT, S_IFLNK)
            } else {
                XCTAssertEqual(chmod(name, 0o644), 0); XCTAssertThrowsError(try restore(record, f))
                var info = stat(); XCTAssertEqual(lstat(name, &info), 0); XCTAssertEqual(info.st_mode & 0o777, 0o644)
            }
        }
    }
    func testMissingCorruptAndNoncontiguousChunksRefuseBeforeFilePublication() throws {
        for statement in ["DELETE FROM runtime_audit_graph_chunks_v1 WHERE part=1",
                          "UPDATE runtime_audit_graph_chunks_v1 SET bytes=x'00' WHERE part=0",
                          "UPDATE runtime_audit_graph_chunks_v1 SET part=511 WHERE part=0"] {
            let f = try staged(), value = try graph(f), record = try retain(value, f)
            XCTAssertEqual(try f.files.f.f.sql(statement), 0)
            XCTAssertThrowsError(try restore(record, f)); XCTAssertFalse(FileManager.default.fileExists(atPath: try path(value, f)))
        }
    }
    func testMissingReaderWriterOrSchemaCapabilityFailsBeforeSchemaOrFileMutation() throws {
        let f = try staged(), value = try graph(f)
        for role in [AuthorityCodeRole.authority, .setupController] {
            for name in [RuntimeAuditUpgradeGraph.formatName, RuntimeAuditUpgradeGraphRecord.formatName, "authority.installation-preparation"] {
                let release = try NativeHostReleaseFixture.make(policy: f.files.preparation.source.host.codePolicy,
                    phoneAudit: true, auditDelivery: true, edit: { component in
                        guard component.role == role else { return component }
                        return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                            relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                            build: component.build, teamID: component.teamID, formats: component.formats.filter { $0.name != name })
                    })
                XCTAssertThrowsError(try f.files.f.machine.retainRuntimeAuditGraph(value, installedRelease: release,
                    currentPolicy: f.files.preparation.source.host.codePolicy))
                XCTAssertEqual(try f.files.f.f.sql("PRAGMA user_version"), 12)
                XCTAssertFalse(FileManager.default.fileExists(atPath: try path(value, f)))
            }
        }
    }
    func testLostMetadataAndStoredMarkerRepliesRecoverFromTheCommittedTransaction() throws {
        for markStored in [false, true] {
            let f = try staged(), value = try graph(f)
            let record = markStored ? try retain(value, f) : nil
            try f.files.f.machine.close(); var armed = false
            let writer = try f.files.f.f.open(hook: { if armed { throw Interrupted() } }); armed = true
            if markStored {
                XCTAssertThrowsError(try writer.markRuntimeAuditGraphStored(XCTUnwrap(record), graph: value,
                    installedRelease: XCTUnwrap(f.files.f.nativeRelease), currentPolicy: f.files.preparation.source.host.codePolicy))
            } else {
                XCTAssertThrowsError(try writer.retainRuntimeAuditGraph(value, installedRelease: XCTUnwrap(f.files.f.nativeRelease),
                    currentPolicy: f.files.preparation.source.host.codePolicy))
            }
            XCTAssertThrowsError(try writer.runtimeAuditGraph(accountID: f.files.f.account.accountID, contentDigest: value.digest))
            try writer.close(); let reopened = try f.files.f.f.open(); defer { try? reopened.close() }
            let recovered = try XCTUnwrap(reopened.runtimeAuditGraph(accountID: f.files.f.account.accountID, contentDigest: value.digest))
            XCTAssertEqual(recovered.phase, markStored ? .fileStored : .retained)
            XCTAssertEqual(try reopened.runtimeAuditGraphBytes(recovered), value.bytes)
            XCTAssertEqual(try decode(reopened.runtimeAuditGraphBytes(recovered), f).bytes, value.bytes)
        }
    }
    func testMissingImportDirectoryRoundTripDoesNotCreateIt() throws {
        let f = try staged(), unused = try XCTUnwrap(f.files.directories.removeValue(forKey: .imports))
        unused.close(); XCTAssertEqual(rmdir(unused.path), 0)
        let parent = try ProtectedSetupDirectory(anchor: f.files.f.f.root.path, relativePath: "machine", owner: getuid(), createIfMissing: false)
        defer { parent.close() }
        let scope = try f.scope(); defer { scope.close() }
        let missing = try RuntimeAuditUpgradeArtifactSnapshot.MissingImports.observe(machine: parent, owner: getuid(),
            ownership: .ordinaryOwnerFixture, verifyCurrent: scope.validateLifetime)
        let observation = try RuntimeAuditUpgradeCollector.captureOwned(scope: scope, directories: f.files.directories,
            owner: getuid(), missingImports: missing, observeJournal: { nil })
        let value = try RuntimeAuditUpgradeGraph(observation: observation, upgrade: f.record,
            installedRelease: XCTUnwrap(f.files.f.nativeRelease), currentPolicy: f.files.preparation.source.host.codePolicy)
        let decoded = try decode(value.bytes, f)
        XCTAssertEqual(decoded.snapshot.retainedParents[.imports]?.missingChild, true)
        let record = try retain(value, f); _ = try restore(record, f)
        XCTAssertFalse(FileManager.default.fileExists(atPath: parent.path + "/SharedSetupImport"))
    }
    func testChangedPointerAndRetiredOwnerCannotPublishAFile() throws {
        let f = try staged(), value = try graph(f), record = try retain(value, f)
        let stale = try RuntimeAuditUpgradeGraphRecord(upgrade: record.upgrade, contentDigest: record.contentDigest)
        XCTAssertThrowsError(try restore(stale, f))
        XCTAssertThrowsError(try RuntimeAuditUpgradeGraphStorage.restoreOwned(machine: f.files.f.machine, expected: record,
            installedRelease: XCTUnwrap(f.files.f.nativeRelease), currentPolicy: f.files.preparation.source.host.codePolicy,
            directory: XCTUnwrap(f.files.directories[.runtime]), owner: getuid(), verifyOwner: { throw Interrupted() }))
        XCTAssertFalse(FileManager.default.fileExists(atPath: try path(value, f)))
        XCTAssertEqual(try f.files.f.machine.runtimeAuditGraph(accountID: f.files.f.account.accountID, contentDigest: value.digest), record)
    }
    func testPublicPointerCodecRejectsUnknownVersionsPhasesAndFields() throws {
        let f = try staged(), record = try RuntimeAuditUpgradeGraphRecord(upgrade: f.record, contentDigest: Data(repeating: 3, count: 32))
        XCTAssertEqual(try RuntimeAuditUpgradeGraphRecord.decode(record.encoded), record)
        let limits = try CBORLimits(maxBytes: 28672, maxDepth: 1, maxItems: 17)
        guard case .map(let fields) = try DeterministicCBOR.decode(record.encoded, limits: limits) else { return XCTFail() }
        for (key, value) in [(UInt64(0), CBORValue.unsigned(2)), (4, .unsigned(2)), (5, .unsigned(3)), (7, .null)] {
            var edited = fields; edited[key] = value
            XCTAssertThrowsError(try RuntimeAuditUpgradeGraphRecord.decode(DeterministicCBOR.encode(.map(edited), limits: limits)))
        }
    }
    func testSetupWriterAndSchemaThirteenReaderAreRequiredBeforeRetention() throws {
        let f = try staged(), value = try graph(f)
        for missingWriter in [false, true] {
            let release = try NativeHostReleaseFixture.make(policy: f.files.preparation.source.host.codePolicy,
                phoneAudit: true, auditDelivery: true, edit: { component in
                    guard component.role == .setupController else { return component }
                    let formats = try component.formats.map { format -> ReleaseFormat in
                        guard format.name == (missingWriter ? RuntimeAuditUpgradeGraph.formatName : "authority.installation-preparation") else { return format }
                        return try .init(name: format.name, readers: missingWriter ? format.readers : format.readers.subtracting([13]),
                            writers: missingWriter ? [] : format.writers.subtracting([13]), migrations: format.migrations)
                    }
                    return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                        relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                        build: component.build, teamID: component.teamID, formats: formats)
                })
            XCTAssertThrowsError(try f.files.f.machine.retainRuntimeAuditGraph(value, installedRelease: release,
                currentPolicy: f.files.preparation.source.host.codePolicy))
            XCTAssertEqual(try f.files.f.f.sql("PRAGMA user_version"), 12)
        }
    }
    func testNativeRestoreRefusesBeforeOwnerCallback() throws {
        let f = try staged(), value = try graph(f), record = try retain(value, f); var calls = 0
        XCTAssertThrowsError(try RuntimeAuditUpgradeGraphStorage.restore(machine: f.files.f.machine, expected: record,
            installedRelease: XCTUnwrap(f.files.f.nativeRelease), currentPolicy: f.files.preparation.source.host.codePolicy,
            verifyOwner: { calls += 1 })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertEqual(calls, 0)
    }
}
