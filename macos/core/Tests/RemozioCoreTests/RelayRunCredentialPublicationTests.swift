import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned temporary files and disposable keys. These tests do not prove native service isolation.
final class RelayRunCredentialPublicationTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    private struct Fixture: Sendable {
        let host: RelayProvisioningFixture
        let plan: SharedSetupImportRelayPlan
        let created: SharedSetupRelayProvisioningRecord
        let expected: SharedSetupImportIntent
        let inventory: InstallationInventory
        let runtime: RuntimeMaterialReference
        let credential: CloudflareTunnelRunCredential
        var account: AccountPreparationIntent { host.f.account }
        func material() throws -> RelayRunCredentialMaterial {
            try .init(expected: expected, plan: plan, created: created, runtime: runtime, account: account,
                inventory: inventory, credential: credential)
        }
    }
    private func fixture() throws -> Fixture {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner fixture") }
        let h = try RelayProvisioningFixture(), plan = try h.prepare()
        let prepared = try h.directory { try SharedSetupRelayProvisioningStorage.begin(expected: h.intent, plan: plan,
            directory: $0, owner: getuid(), verifyCurrent: {}) }
        let created = try prepared.transition(to: .dispatched).transition(to: .created,
            tunnelID: "11111111-1111-4111-8111-111111111111")
        let runtime = try RuntimeMaterialReference(materialID: AccountPreparationIntent.randomID(), services: h.services,
            materialDigest: Data(repeating: 0x45, count: 32), transportPublicKeyInfo: P256.Signing.PrivateKey().publicKey.derRepresentation,
            gateway: .init(ownerID: AccountPreparationIntent.randomID(), macID: h.services.macID,
                accountID: h.services.accountID, gatewayID: AccountPreparationIntent.randomID(),
                lifecycleEpoch: AccountPreparationIntent.randomID(), rootPublicKey: h.services.authorityPublicKey))
        let tunnel = try created.createdTunnel(expected: h.intent, plan: plan)
        let token = try JSONSerialization.data(withJSONObject: ["a": tunnel.accountID, "t": tunnel.tunnelID,
            "s": Data(repeating: 0x71, count: 32).base64EncodedString()], options: [.sortedKeys, .withoutEscapingSlashes]).base64EncodedString()
        return try .init(host: h, plan: plan, created: created, expected: h.intent.advanced(to: .runtimePublished),
            inventory: h.machine { try XCTUnwrap($0.inventory()) }, runtime: runtime,
            credential: .restore(Data(token.utf8), tunnel: tunnel))
    }
    private func prepare(_ f: Fixture, _ directory: ProtectedSetupDirectory, reference: RelayRunCredentialReference? = nil,
                         intent: SharedSetupImportIntent? = nil, verify: () throws -> Void = {},
                         make: (() throws -> CloudflareTunnelRunCredential)? = nil,
                         stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RelayRunCredentialMaterial {
        try RelayRunCredentialPreparation.restoreOrCreate(directory: directory, owner: getuid(), account: f.account,
            inventory: f.inventory, expected: intent ?? f.expected, plan: f.plan, created: f.created, runtime: f.runtime,
            reference: reference, verifyCurrent: verify, makeCredential: make ?? { f.credential }, didStage: stage)
    }
    private func decode(_ bytes: Data, _ f: Fixture) throws -> RelayRunCredentialMaterial {
        try .decode(bytes, expected: f.expected, plan: f.plan, created: f.created, runtime: f.runtime,
            account: f.account, inventory: f.inventory)
    }
    private func path(_ directory: ProtectedSetupDirectory) -> String { directory.path + "/relay-run-material.cbor" }
    private func shared(_ body: (ProtectedSetupDirectory) throws -> Void) throws {
        let base = "/private/tmp/remozio-relay-publication-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(atPath: base) }
        XCTAssertEqual(chmod(base, 0o755), 0)
        let directory = try ProtectedSetupDirectory(anchor: base, relativePath: "Artifacts", owner: getuid(), visibility: .sharedMetadata)
        defer { directory.close() }; try body(directory)
    }
    private func publish(_ material: RelayRunCredentialMaterial, _ f: Fixture, _ directory: ProtectedSetupDirectory,
                         reference: RelayRunCredentialReference? = nil,
                         mode: RelayRunCredentialPublication.Mode = .prepareUnactivated,
                         intent: SharedSetupImportIntent? = nil, verify: () throws -> Void = {},
                         stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        try RelayRunCredentialPublication.publish(material: material, reference: reference ?? material.reference,
            expected: intent ?? f.expected, directory: directory, owner: getuid(), transportUID: getuid(),
            transportGID: getgid(), mode: mode, verifyCurrent: verify, didStage: stage)
    }

    func testCanonicalPrivateMaterialAndPublicReferenceHaveDistinctContents() throws {
        let f = try fixture(), material = try f.material(), reference = try material.reference
        XCTAssertEqual(try decode(material.encoded, f).reference, reference)
        XCTAssertEqual(try RelayRunCredentialReference.decode(reference.encoded, expected: f.expected, plan: f.plan,
            created: f.created, runtime: f.runtime, account: f.account, inventory: f.inventory), reference)
        try material.withCredentialBytes { token in
            XCTAssertNotNil(try material.encoded.range(of: token))
            XCTAssertNil(try reference.encoded.range(of: token))
            XCTAssertEqual(reference.credentialDigest, Data(SHA256.hash(data: token)))
        }
        var dumpText = ""; dump(material, to: &dumpText)
        XCTAssertLessThan(dumpText.count, 100)
        XCTAssertEqual(String(reflecting: material), "RelayRunCredentialMaterial(redacted)")
    }
    func testClosedSchemasAndCrossedRuntimeOrPlanAreRejected() throws {
        let f = try fixture(), material = try f.material()
        let limits = try CBORLimits(maxBytes: 32_768, maxDepth: 1, maxItems: 40)
        guard case let .map(fields) = try DeterministicCBOR.decode(material.encoded, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other-purpose")),
            (2, .bytes(Data())), (3, .bytes(Data())), (4, .bytes(Data(repeating: 0, count: 32))),
            (5, .bytes(Data())), (6, .bytes(Data("invalid-token".utf8))), (7, .null)] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try decode(DeterministicCBOR.encode(.map(changed), limits: limits), f))
        }
        let other = try fixture()
        XCTAssertThrowsError(try RelayRunCredentialMaterial.decode(material.encoded, expected: f.expected, plan: f.plan,
            created: f.created, runtime: other.runtime, account: f.account, inventory: f.inventory))
        XCTAssertThrowsError(try RelayRunCredentialMaterial.decode(material.encoded, expected: other.expected, plan: other.plan,
            created: other.created, runtime: other.runtime, account: other.account, inventory: other.inventory))
        let reference = try material.reference
        guard case let .map(publicFields) = try DeterministicCBOR.decode(reference.encoded, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (3, .bytes(Data())), (4, .bytes(Data())),
            (6, .text("wrong-account")), (9, .bytes(Data())), (11, .null)] {
            var changed = publicFields; changed[key] = value
            XCTAssertThrowsError(try RelayRunCredentialReference.decode(DeterministicCBOR.encode(.map(changed), limits: limits),
                expected: f.expected, plan: f.plan, created: f.created, runtime: f.runtime, account: f.account, inventory: f.inventory))
        }
    }
    func testRestoreRetainsTheCredentialAndInodeWithoutAnotherFetch() throws {
        let f = try fixture()
        try f.host.directory { directory in
            var fetches = 0
            let first = try prepare(f, directory, make: { fetches += 1; return f.credential })
            var before = stat(); XCTAssertEqual(lstat(path(directory), &before), 0)
            for intent in [f.expected, try f.expected.advanced(to: .gatewayPrepared).advanced(to: .relayPrepared)] {
                let restored = try prepare(f, directory, reference: first.reference, intent: intent,
                    make: { XCTFail("Retention fetched another credential"); throw Interrupted() })
                XCTAssertEqual(try first.reference, try restored.reference)
            }
            var after = stat(); XCTAssertEqual(lstat(path(directory), &after), 0)
            XCTAssertEqual(before.st_ino, after.st_ino); XCTAssertEqual(after.st_mode & 0o7777, 0o600)
            XCTAssertEqual(fetches, 1)
        }
    }
    func testLostPublicationReplyRestoresThePublishedMaterial() throws {
        let f = try fixture()
        try f.host.directory { directory in
            var fetches = 0
            XCTAssertThrowsError(try prepare(f, directory, make: { fetches += 1; return f.credential },
                stage: { if $0 == .published { throw Interrupted() } }))
            let bytes = try Data(contentsOf: URL(fileURLWithPath: path(directory)))
            let restored = try prepare(f, directory, make: { fetches += 1; throw Interrupted() })
            XCTAssertEqual(try restored.encoded, bytes); XCTAssertEqual(fetches, 1)
        }
    }
    func testMissingAcceptedMaterialAndInvalidPhaseNeverFetchOrCreate() throws {
        let f = try fixture()
        try f.host.directory { directory in
            let reference = try f.material().reference
            for (expected, intent) in [(reference as RelayRunCredentialReference?, f.expected),
                (nil, f.host.intent), (nil, try f.expected.advanced(to: .gatewayPrepared).advanced(to: .relayPrepared))] {
                XCTAssertThrowsError(try prepare(f, directory, reference: expected, intent: intent,
                    make: { XCTFail("Invalid state fetched a credential"); throw Interrupted() }))
                XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
            }
        }
    }
    func testUnsafePrivateFilesAreRefusedWithoutRepairOrFetch() throws {
        for kind in ["corrupt", "symlink", "readable", "hardlink"] {
            let f = try fixture()
            try f.host.directory { directory in
                let destination = path(directory), bytes = try f.material().encoded
                if kind == "symlink" { XCTAssertEqual(symlink("/dev/null", destination), 0) }
                else {
                    try (kind == "corrupt" ? Data("corrupt".utf8) : bytes).write(to: URL(fileURLWithPath: destination))
                    XCTAssertEqual(chmod(destination, kind == "readable" ? 0o644 : 0o600), 0)
                    if kind == "hardlink" { XCTAssertEqual(link(destination, destination + ".link"), 0) }
                }
                var before = stat(); XCTAssertEqual(lstat(destination, &before), 0)
                XCTAssertThrowsError(try prepare(f, directory, make: { XCTFail("Unsafe file triggered a fetch"); throw Interrupted() }))
                var after = stat(); XCTAssertEqual(lstat(destination, &after), 0)
                XCTAssertEqual(before.st_ino, after.st_ino); XCTAssertEqual(before.st_mode, after.st_mode)
            }
        }
    }
    func testPublicationCopiesOnlyTokenAndRetainsExactMetadata() throws {
        let f = try fixture(), material = try f.material()
        try shared { directory in
            XCTAssertEqual(try publish(material, f, directory), .created)
            let target = directory.path + "/transport-tunnel.token"
            try material.withCredentialBytes { XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: target)), $0) }
            var before = stat(); XCTAssertEqual(lstat(target, &before), 0)
            XCTAssertEqual(before.st_mode & 0o7777, 0o600); XCTAssertEqual(before.st_uid, getuid()); XCTAssertEqual(before.st_gid, getgid())
            for mode in [RelayRunCredentialPublication.Mode.prepareUnactivated, .validateRetained] {
                XCTAssertEqual(try publish(material, f, directory, mode: mode), .retained)
                var after = stat(); XCTAssertEqual(lstat(target, &after), 0); XCTAssertEqual(before.st_ino, after.st_ino)
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["transport-tunnel.token"])
        }
    }
    func testAcceptedOperationalTokenIsNeverRecreated() throws {
        let f = try fixture(), material = try f.material()
        try shared { directory in
            XCTAssertThrowsError(try publish(material, f, directory, mode: .validateRetained))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
            _ = try publish(material, f, directory)
            XCTAssertEqual(unlink(directory.path + "/transport-tunnel.token"), 0)
            XCTAssertThrowsError(try publish(material, f, directory, mode: .validateRetained))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
        }
    }
    func testStaleOrCrossedReferenceStopsBeforePublication() throws {
        let f = try fixture(), material = try f.material(), other = try f.material()
        try shared { directory in
            XCTAssertThrowsError(try publish(material, f, directory, reference: other.reference))
            XCTAssertThrowsError(try publish(material, f, directory, verify: { throw Interrupted() }))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
            XCTAssertThrowsError(try publish(material, f, directory, intent: f.host.intent))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
        }
        try f.host.directory { directory in
            XCTAssertThrowsError(try prepare(f, directory, verify: { throw Interrupted() },
                make: { XCTFail("Stale state fetched a credential"); throw Interrupted() }))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
        }
    }
    func testLostOperationalPublicationReplyRetainsTheSameToken() throws {
        let f = try fixture(), material = try f.material()
        try shared { directory in
            XCTAssertThrowsError(try publish(material, f, directory, stage: { if $0 == .published { throw Interrupted() } }))
            XCTAssertEqual(try publish(material, f, directory), .retained)
            XCTAssertEqual(try publish(material, f, directory, mode: .validateRetained), .retained)
        }
    }
    func testUnsafeOperationalTokenIsNotRepaired() throws {
        let f = try fixture(), material = try f.material()
        for kind in ["conflict", "readable", "symlink", "hardlink"] {
            try shared { directory in
                let target = directory.path + "/transport-tunnel.token"
                if kind == "symlink" { XCTAssertEqual(symlink("/dev/null", target), 0) }
                else {
                    _ = try publish(material, f, directory)
                    if kind == "conflict" { try Data("conflict".utf8).write(to: URL(fileURLWithPath: target)) }
                    if kind == "readable" { XCTAssertEqual(chmod(target, 0o644), 0) }
                    if kind == "hardlink" { XCTAssertEqual(link(target, target + ".link"), 0) }
                }
                var before = stat(); XCTAssertEqual(lstat(target, &before), 0)
                for mode in [RelayRunCredentialPublication.Mode.prepareUnactivated, .validateRetained] {
                    XCTAssertThrowsError(try publish(material, f, directory, mode: mode))
                }
                var after = stat(); XCTAssertEqual(lstat(target, &after), 0)
                XCTAssertEqual(before.st_ino, after.st_ino); XCTAssertEqual(before.st_mode, after.st_mode)
            }
        }
    }
    func testNativeEntryPointsRefuseOrdinaryIdentity() throws {
        let f = try fixture(), reference = try f.material().reference
        XCTAssertThrowsError(try RelayRunCredentialPreparation.prepareNative(account: f.account, inventory: f.inventory,
            expected: f.expected, plan: f.plan, created: f.created, runtime: f.runtime, reference: nil,
            fileCustodyAccepted: true, verifyCurrent: { XCTFail("Protected operation") },
            makeCredential: { XCTFail("Provider read"); throw Interrupted() })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try RelayRunCredentialPublication.publishNative(account: f.account, inventory: f.inventory,
            expected: f.expected, plan: f.plan, created: f.created, runtime: f.runtime, reference: reference,
            mode: .prepareUnactivated, verifyCurrent: { XCTFail("Protected operation") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
    }

    private func retainRuntimeAndTunnel(_ f: Fixture) throws -> SharedSetupImportIntent {
        try f.host.machine { machine in
            try machine.retainRuntimeMaterial(f.runtime); try machine.completeRuntimePublication(f.runtime)
        }
        let journal = try f.host.f.open()
        let current = try journal.advance(f.host.intent, to: .runtimePublished)
        try journal.close()
        try f.host.directory { directory in
            let old = try XCTUnwrap(SharedSetupRelayProvisioningStorage.read(expected: current, plan: f.plan,
                directory: directory, owner: getuid()))
            let sent = try old.transition(to: .dispatched)
            try SharedSetupRelayProvisioningStorage.replace(sent, previous: old, expected: current, plan: f.plan,
                directory: directory, owner: getuid(), verifyCurrent: {})
            try SharedSetupRelayProvisioningStorage.replace(f.created, previous: sent, expected: current, plan: f.plan,
                directory: directory, owner: getuid(), verifyCurrent: {})
        }
        return current
    }
    private func retainReference(_ reference: RelayRunCredentialReference, _ f: Fixture, _ directory: ProtectedSetupDirectory,
                                 expected: SharedSetupImportIntent, runtime: RuntimeMaterialReference? = nil,
                                 verify: () throws -> Void = {},
                                 stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RelayRunCredentialReference {
        try SharedSetupRelayRunReferenceStorage.retain(reference, expected: expected, plan: f.plan, created: f.created,
            runtime: runtime ?? f.runtime, directory: directory, owner: getuid(), verifyCurrent: verify, didStage: stage)
    }
    private func referencePath(_ f: Fixture, _ directory: ProtectedSetupDirectory) -> String {
        directory.path + "/" + AdministrativeSetupPublication.File.importRelayRunReference(accountID: f.account.accountID).name
    }
    func testAcceptedReferenceReopensWithoutCredentialBytesOrInodeReplacement() throws {
        let f = try fixture(), expected = try retainRuntimeAndTunnel(f), material = try f.material(), reference = try material.reference
        try f.host.directory { directory in
            _ = try retainReference(reference, f, directory, expected: expected)
            var before = stat(); XCTAssertEqual(lstat(referencePath(f, directory), &before), 0)
            _ = try retainReference(reference, f, directory, expected: expected)
            var after = stat(); XCTAssertEqual(lstat(referencePath(f, directory), &after), 0)
            XCTAssertEqual(before.st_ino, after.st_ino); XCTAssertEqual(after.st_mode & 0o7777, 0o600)
            try material.withCredentialBytes { token in
                XCTAssertNil(try Data(contentsOf: URL(fileURLWithPath: referencePath(f, directory))).range(of: token))
            }
        }
        try f.host.directory { directory in
            XCTAssertEqual(try SharedSetupRelayRunReferenceStorage.read(expected: expected, plan: f.plan, created: f.created,
                directory: directory, owner: getuid()), reference)
            let later = try expected.advanced(to: .gatewayPrepared).advanced(to: .relayPrepared)
            XCTAssertEqual(try retainReference(reference, f, directory, expected: later), reference)
        }
    }
    func testLostReferencePublicationReplyRetainsTheAcceptedIdentity() throws {
        let f = try fixture(), expected = try retainRuntimeAndTunnel(f), reference = try f.material().reference
        try f.host.directory { directory in
            XCTAssertThrowsError(try retainReference(reference, f, directory, expected: expected,
                stage: { if $0 == .published { throw Interrupted() } }))
            XCTAssertEqual(try retainReference(reference, f, directory, expected: expected), reference)
            let different = try f.material().reference
            XCTAssertThrowsError(try retainReference(different, f, directory, expected: expected)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertEqual(try SharedSetupRelayRunReferenceStorage.read(expected: expected, plan: f.plan, created: f.created,
                directory: directory, owner: getuid()), reference)
        }
    }
    func testMissingAcceptedReferenceCannotBeCreatedAfterRelayPreparation() throws {
        let f = try fixture(), expected = try retainRuntimeAndTunnel(f), reference = try f.material().reference
        try f.host.directory { directory in
            let later = try expected.advanced(to: .gatewayPrepared).advanced(to: .relayPrepared)
            XCTAssertThrowsError(try retainReference(reference, f, directory, expected: later))
            XCTAssertFalse(FileManager.default.fileExists(atPath: referencePath(f, directory)))
        }
    }
    func testReferenceRejectsStaleVerificationAndCrossedRuntimeBeforeWriting() throws {
        let f = try fixture(), expected = try retainRuntimeAndTunnel(f), reference = try f.material().reference
        let other = try fixture()
        try f.host.directory { directory in
            XCTAssertThrowsError(try retainReference(reference, f, directory, expected: expected, runtime: other.runtime))
            XCTAssertThrowsError(try retainReference(reference, f, directory, expected: expected, verify: { throw Interrupted() }))
            XCTAssertFalse(FileManager.default.fileExists(atPath: referencePath(f, directory)))
        }
    }
    func testReferenceRequiresTheExactRetainedTunnelAndPlan() throws {
        let f = try fixture(), reference = try f.material().reference
        try f.host.directory { directory in
            // The fixture has a prepared resource record until its explicit retention step.
            XCTAssertThrowsError(try retainReference(reference, f, directory, expected: f.expected))
            XCTAssertFalse(FileManager.default.fileExists(atPath: referencePath(f, directory)))
        }
    }
    func testReferencePublicationNeverRepairsUnsafeExistingFiles() throws {
        for kind in ["corrupt", "readable", "hardlink", "symlink"] {
            let f = try fixture(), expected = try retainRuntimeAndTunnel(f), reference = try f.material().reference
            try f.host.directory { directory in
                let target = referencePath(f, directory)
                if kind == "symlink" { XCTAssertEqual(symlink("/dev/null", target), 0) }
                else {
                    try (kind == "corrupt" ? Data("corrupt".utf8) : reference.encoded).write(to: URL(fileURLWithPath: target))
                    XCTAssertEqual(chmod(target, kind == "readable" ? 0o644 : 0o600), 0)
                    if kind == "hardlink" { XCTAssertEqual(link(target, target + ".link"), 0) }
                }
                var before = stat(); XCTAssertEqual(lstat(target, &before), 0)
                XCTAssertThrowsError(try retainReference(reference, f, directory, expected: expected))
                var after = stat(); XCTAssertEqual(lstat(target, &after), 0)
                XCTAssertEqual(before.st_ino, after.st_ino); XCTAssertEqual(before.st_mode, after.st_mode)
            }
        }
    }
    func testUpdateSnapshotIncludesReferenceAndPrivateMaterialCodecRequirements() throws {
        let f = try fixture(), expected = try retainRuntimeAndTunnel(f), reference = try f.material().reference
        let before = try f.host.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        XCTAssertFalse(before.requirements.formats.contains { $0.name == RelayRunCredentialReference.formatName })
        try f.host.directory { _ = try retainReference(reference, f, $0, expected: expected) }
        XCTAssertThrowsError(try f.host.machine { try before.requireCurrent(machine: $0) })
        let after = try f.host.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        XCTAssertNotNil(after.inputs.sharedImport?.records.first?.runCredential)
        for (role, format, writes): (AuthorityCodeRole, String, Set<UInt64>) in [
            (.setupController, RelayRunCredentialReference.formatName, [1]),
            (.setupController, RelayRunCredentialMaterial.formatName, [1])] {
            let requirement = try XCTUnwrap(after.requirements.formats.first { $0.role == role && $0.name == format })
            XCTAssertEqual(requirement.readVersions, [1]); XCTAssertEqual(requirement.writeVersions, writes)
        }
        try f.host.directory { directory in
            let target = referencePath(f, directory), replacement = target + ".replacement"
            try reference.encoded.write(to: URL(fileURLWithPath: replacement)); XCTAssertEqual(chmod(replacement, 0o600), 0)
            XCTAssertEqual(rename(replacement, target), 0)
        }
        XCTAssertThrowsError(try f.host.machine { try after.requireCurrent(machine: $0) })
    }
    func testUpdateSnapshotRejectsAReferenceForAnUnretainedRuntime() throws {
        let f = try fixture(), expected = try retainRuntimeAndTunnel(f)
        let other = try RuntimeMaterialReference(materialID: AccountPreparationIntent.randomID(), services: f.runtime.services,
            materialDigest: Data(repeating: 0x22, count: 32), transportPublicKeyInfo: f.runtime.transportPublicKeyInfo, gateway: f.runtime.gateway)
        let material = try RelayRunCredentialMaterial(expected: expected, plan: f.plan, created: f.created, runtime: other,
            account: f.account, inventory: f.inventory, credential: f.credential)
        try f.host.directory { _ = try retainReference(material.reference, f, $0, expected: expected, runtime: other) }
        XCTAssertThrowsError(try f.host.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }) {
            XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
        }
    }
    func testOrphanReferenceAndGenericReplacementAreRefused() throws {
        let f = try fixture(), expected = try retainRuntimeAndTunnel(f), reference = try f.material().reference
        try f.host.directory { directory in
            XCTAssertThrowsError(try AdministrativeSetupPublication.replaceSettings(reference.encoded, expected: nil,
                file: .importRelayRunReference(accountID: f.account.accountID), directory: directory, owner: getuid(), verify: {}))
            let orphan = directory.path + "/import-relay-run-" + String(repeating: "f", count: 32) + ".cbor"
            try reference.encoded.write(to: URL(fileURLWithPath: orphan)); XCTAssertEqual(chmod(orphan, 0o600), 0)
            XCTAssertThrowsError(try SharedSetupImportRelayStorage.validateTrackedFiles(records: [expected], directory: directory))
            XCTAssertThrowsError(try f.host.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) })
        }
    }

    private final class OwnerSharedDirectory: Sendable {
        let path: String
        init() throws {
            path = "/private/tmp/remozio-relay-owner-" + UUID().uuidString
            try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
            guard chmod(path, 0o755) == 0 else {
                let code = errno; try? FileManager.default.removeItem(atPath: path); throw JournalLeaseError.system(code)
            }
        }
        deinit { try? FileManager.default.removeItem(atPath: path) }
    }

    private struct OwnerFixture: Sendable {
        let base: Fixture
        let owner: SetupAccountOwner
        let expected: SetupPortableImportProgress
        let proposal: PortableSetup
        let operations: RelayRunCredentialSetupOperations
        let shared: OwnerSharedDirectory
        var privatePath: String { base.host.f.accountFixture.root.path + "/RelayRuntime/relay-run-material.cbor" }
    }
    private func ownerFixture() throws -> OwnerFixture {
        let f = try fixture(); _ = try retainRuntimeAndTunnel(f)
        let anchor = f.host.f.accountFixture.root.path, shared = try OwnerSharedDirectory()
        let operations = RelayRunCredentialSetupOperations(prepare: { context, credential, accepted, verify in
            let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: "RelayRuntime", owner: getuid())
            defer { directory.close() }
            return try RelayRunCredentialPreparation.restoreOrCreate(directory: directory, owner: getuid(),
                account: context.account, inventory: context.inventory, expected: context.expected, plan: context.plan,
                created: context.created, runtime: context.runtime, reference: context.reference, verifyCurrent: verify,
                makeCredential: {
                    guard accepted else { throw RuntimePreparationError.custodyNotAccepted }
                    guard let credential else { throw RelayRunCredentialSetupError.credentialRequired }
                    return credential
                }).reference
        }, publish: { context, reference, verify in
            let privateDirectory = try ProtectedSetupDirectory(anchor: anchor, relativePath: "RelayRuntime", owner: getuid(), createIfMissing: false)
            defer { privateDirectory.close() }
            let material = try RelayRunCredentialMaterial.decode(ProtectedServiceConfiguration.read(anchor: privateDirectory.path,
                relativePath: "relay-run-material.cbor", owner: getuid()), expected: context.expected, plan: context.plan,
                created: context.created, runtime: context.runtime, account: context.account, inventory: context.inventory)
            let sharedDirectory = try ProtectedSetupDirectory(anchor: shared.path, relativePath: "RelayService", owner: getuid(), visibility: .sharedMetadata)
            defer { sharedDirectory.close() }
            let mode: RelayRunCredentialPublication.Mode = [.runtimePublished, .gatewayPrepared].contains(context.expected.phase)
                ? .prepareUnactivated : .validateRetained
            _ = try RelayRunCredentialPublication.publish(material: material, reference: reference, expected: context.expected,
                directory: sharedDirectory, owner: getuid(), transportUID: getuid(), transportGID: getgid(), mode: mode, verifyCurrent: verify)
        })
        let owner = try f.host.owner()
        return try .init(base: f, owner: owner, expected: f.host.progress(owner), proposal: f.host.f.proposal(), operations: operations, shared: shared)
    }
    private func ownerReplies(_ f: OwnerFixture) throws -> [RelayIngressProbe.Step] {
        let configuration = try XCTUnwrap(f.proposal.cloudflare)
        let metadata = try RelayIngressProviderFixture.metadata(configuration: configuration, plan: f.base.plan)
        let token = f.base.credential.withFileBytes { String(decoding: $0, as: UTF8.self) }
        let reply = try JSONSerialization.data(withJSONObject: ["success": true, "errors": [], "result": token])
        return [RelayIngressProbe.reply(metadata), RelayIngressProbe.reply(reply), RelayIngressProbe.reply(metadata)]
    }
    private func prepareOwner(_ f: OwnerFixture, accepted: Bool = true, owner: SetupAccountOwner? = nil,
                              operations: RelayRunCredentialSetupOperations? = nil,
                              probe: RelayIngressProbe) async throws -> RelayRunCredentialReference {
        try await (owner ?? f.owner).prepareImportedRelayRunCredential(callerUID: getuid(), expected: f.expected,
            proposal: f.proposal, fileCustodyAccepted: accepted, operations: operations ?? f.operations,
            send: { try await probe.send($0) })
    }
    func testSetupOwnerReadsOnceWithoutHoldingTheMachineLeaseThenRestoresOffline() async throws {
        let f = try ownerFixture(); defer { try? f.owner.close() }
        let probe = try RelayIngressProbe(ownerReplies(f), hook: { _, _ in try f.base.host.machine { _ in } })
        let reference = try await prepareOwner(f, probe: probe)
        XCTAssertEqual(try f.base.host.progress(f.owner), f.expected)
        let requests = await probe.all(); XCTAssertEqual(requests.count, 3)
        let offline = RelayIngressProbe([])
        let restored = try await prepareOwner(f, accepted: false, probe: offline)
        XCTAssertEqual(restored, reference)
        try f.owner.close()
        let reopened = try f.base.host.owner(); defer { try? reopened.close() }
        let afterReopen = try await prepareOwner(f, accepted: false, owner: reopened, probe: offline)
        XCTAssertEqual(afterReopen, reference)
        let unexpected = await offline.all(); XCTAssertTrue(unexpected.isEmpty)
    }
    func testSetupOwnerMissingAcceptedMaterialNeverFetchesAReplacement() async throws {
        let f = try ownerFixture(); defer { try? f.owner.close() }
        _ = try await prepareOwner(f, probe: RelayIngressProbe(ownerReplies(f)))
        XCTAssertEqual(unlink(f.privatePath), 0)
        let probe = RelayIngressProbe([])
        do { _ = try await prepareOwner(f, probe: probe); XCTFail("Accepted material was recreated") }
        catch { XCTAssertEqual(error as? RuntimePreparationError, .missingMaterial) }
        let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.privatePath))
    }
    func testSetupOwnerCannotFetchWithoutCustodyConsentOrAcceptLateInventoryChanges() async throws {
        do {
            let f = try ownerFixture(); defer { try? f.owner.close() }; let probe = RelayIngressProbe([])
            do { _ = try await prepareOwner(f, accepted: false, probe: probe); XCTFail("Missing consent was accepted") }
            catch { XCTAssertEqual(error as? RuntimePreparationError, .custodyNotAccepted) }
            let requests = await probe.all(); XCTAssertTrue(requests.isEmpty)
        }
        for changedAt in 1...3 {
            let f = try ownerFixture(); defer { try? f.owner.close() }
            let probe = try RelayIngressProbe(ownerReplies(f), hook: { count, _ in
                if count == changedAt {
                    try f.base.host.machine { machine in
                        let current = try XCTUnwrap(machine.inventory())
                        _ = try machine.writeInventory(current, expectedRevision: current.revision)
                    }
                }
            })
            do { _ = try await prepareOwner(f, probe: probe); XCTFail("A stale operation retained a credential") }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
            let requests = await probe.all(); XCTAssertEqual(requests.count, changedAt)
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.privatePath))
        }
    }
    func testSetupOwnerRecoversAfterOperationalPublicationLosesItsReply() async throws {
        let f = try ownerFixture(); defer { try? f.owner.close() }
        let interrupted = RelayRunCredentialSetupOperations(prepare: f.operations.prepare, publish: { context, reference, verify in
            try f.operations.publish(context, reference, verify); throw Interrupted()
        })
        let probe = try RelayIngressProbe(ownerReplies(f))
        do { _ = try await prepareOwner(f, operations: interrupted, probe: probe); XCTFail("The simulated lost reply succeeded") }
        catch { XCTAssertTrue(error is Interrupted) }
        let before = try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), offline = RelayIngressProbe([])
        let restored = try await prepareOwner(f, probe: offline)
        XCTAssertEqual(restored, try RelayRunCredentialMaterial.decode(before, expected: f.base.expected, plan: f.base.plan,
            created: f.base.created, runtime: f.base.runtime, account: f.base.account, inventory: f.base.inventory).reference)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), before)
        let requests = await offline.all(); XCTAssertTrue(requests.isEmpty)
    }

    func testPrivateRetentionBeforeReferenceCommitStillProtectsUpdatesAndRestoresOffline() async throws {
        let f = try ownerFixture(); defer { try? f.owner.close() }
        let interrupted = RelayRunCredentialSetupOperations(prepare: { context, credential, accepted, verify in
            _ = try f.operations.prepare(context, credential, accepted, verify)
            throw Interrupted()
        }, publish: { _, _, _ in XCTFail("No reference was accepted") })
        do {
            _ = try await prepareOwner(f, operations: interrupted, probe: RelayIngressProbe(ownerReplies(f)))
            XCTFail("The simulated lost private-write reply succeeded")
        } catch { XCTAssertTrue(error is Interrupted) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.privatePath))
        let snapshot = try f.base.host.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        XCTAssertNil(snapshot.inputs.sharedImport?.records.first?.runCredential)
        let requirement = try XCTUnwrap(snapshot.requirements.formats.first {
            $0.role == .setupController && $0.name == RelayRunCredentialMaterial.formatName
        })
        XCTAssertEqual(requirement.readVersions, [1]); XCTAssertEqual(requirement.writeVersions, [1])
        let before = try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), offline = RelayIngressProbe([])
        _ = try await prepareOwner(f, probe: offline)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.privatePath)), before)
        let requests = await offline.all(); XCTAssertTrue(requests.isEmpty)
    }
}
