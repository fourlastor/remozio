import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned temporary files and disposable keys. These tests do not prove native service isolation.
final class RelayRunCredentialPublicationTests: XCTestCase {
    private struct Interrupted: Error {}
    private struct Fixture {
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
}
