import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class AuthorityKeyProvisioningTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private enum Injected: Error { case interrupted }
    private func record() throws -> AuthoritySigningKeyRecord {
        try .init(macID: mac, accountID: account, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            representation: Data(repeating: 7, count: 32))
    }
    private func fixture(_ body: (URL, URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-key-provisioning-" + UUID().uuidString)
        let state = root.appendingPathComponent("state")
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
        XCTAssertEqual(chmod(root.path, 0o700), 0); XCTAssertEqual(chmod(state.path, 0o700), 0)
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root, state)
    }
    private func open(_ root: URL) throws -> AuthorityKeyProvisioningStorage {
        try .init(anchor: root.path, relativeDirectory: "state", owner: getuid())
    }
    private func place(_ record: AuthoritySigningKeyRecord, state: URL, name: String) throws {
        let path = state.appendingPathComponent(name)
        try record.encode().write(to: path); XCTAssertEqual(chmod(path.path, 0o600), 0)
    }
    func testFirstPublicationAndRestartRetainTheExactRecord() throws {
        try fixture { root, state in
            let chosen = try record(); var created = 0
            let first = try open(root)
            let retained = try first.restoreOrCreate(macID: mac, accountID: account,
                create: { created += 1; return chosen }, verify: { _ in })
            XCTAssertEqual(try retained.encode(), try chosen.encode()); first.close()
            let second = try open(root); defer { second.close() }
            let restored = try second.restoreOrCreate(macID: mac, accountID: account, expectedPublicKey: chosen.publicKey,
                create: { created += 1; return try self.record() }, verify: { _ in })
            XCTAssertEqual(try restored.encode(), try chosen.encode()); XCTAssertEqual(created, 1)
            XCTAssertFalse(FileManager.default.fileExists(atPath: state.appendingPathComponent(AuthorityKeyProvisioningStorage.pendingName).path))
            let attrs = try FileManager.default.attributesOfItem(atPath: state.appendingPathComponent(AuthorityKeyProvisioningStorage.recordName).path)
            XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        }
    }
    func testInterruptedPreparedRecordRecoversWithoutCreatingAnotherKey() throws {
        try fixture { root, _ in
            let chosen = try record(); var created = 0
            let first = try open(root)
            XCTAssertThrowsError(try first.restoreOrCreate(macID: mac, accountID: account,
                create: { created += 1; return chosen }, verify: { _ in }, didStage: {
                    if $0 == .prepared { throw Injected.interrupted }
                }))
            first.close()
            let second = try open(root); defer { second.close() }
            let recovered = try second.restoreOrCreate(macID: mac, accountID: account, expectedPublicKey: chosen.publicKey,
                create: { created += 1; return try self.record() }, verify: { _ in })
            XCTAssertEqual(try recovered.encode(), try chosen.encode()); XCTAssertEqual(created, 1)
        }
    }
    func testInterruptedPublishedRecordRecoversWithoutCreatingAnotherKey() throws {
        try fixture { root, _ in
            let chosen = try record(); var created = 0
            let first = try open(root)
            XCTAssertThrowsError(try first.restoreOrCreate(macID: mac, accountID: account,
                create: { created += 1; return chosen }, verify: { _ in }, didStage: {
                    if $0 == .published { throw Injected.interrupted }
                }))
            first.close()
            let second = try open(root); defer { second.close() }
            XCTAssertEqual(try second.restoreOrCreate(macID: mac, accountID: account,
                create: { created += 1; return try self.record() }, verify: { _ in }).encode(), try chosen.encode())
            XCTAssertEqual(created, 1)
        }
    }
    func testMissingPinnedKeyNeverCreatesAReplacement() throws {
        try fixture { root, _ in
            let chosen = try record(), storage = try open(root); defer { storage.close() }; var created = false
            XCTAssertThrowsError(try storage.restoreOrCreate(macID: mac, accountID: account, expectedPublicKey: chosen.publicKey,
                create: { created = true; return chosen }, verify: { _ in })) {
                XCTAssertEqual($0 as? AuthorityKeyProvisioningError, .missingExistingKey)
            }
            XCTAssertFalse(created)
        }
    }
    func testWrongScopePinAndHardwareFailurePreserveRetainedBytes() throws {
        try fixture { root, state in
            let chosen = try record(); try place(chosen, state: state, name: AuthorityKeyProvisioningStorage.recordName)
            let storage = try open(root); defer { storage.close() }; var created = false
            for (expectedMac, expectedPin) in [(Data(repeating: 3, count: 16), chosen.publicKey), (mac, try record().publicKey)] {
                XCTAssertThrowsError(try storage.restoreOrCreate(macID: expectedMac, accountID: account, expectedPublicKey: expectedPin,
                    create: { created = true; return chosen }, verify: { _ in }))
            }
            XCTAssertThrowsError(try storage.restoreOrCreate(macID: mac, accountID: account,
                create: { created = true; return chosen }, verify: { _ in throw AuthorityRequestSignerError.unavailable }))
            XCTAssertFalse(created)
            XCTAssertEqual(try Data(contentsOf: state.appendingPathComponent(AuthorityKeyProvisioningStorage.recordName)), try chosen.encode())
        }
    }
    func testMalformedPreparedRecordAndConflictingStateNeverRotate() throws {
        try fixture { root, state in
            let pending = state.appendingPathComponent(AuthorityKeyProvisioningStorage.pendingName)
            try Data([0]).write(to: pending); XCTAssertEqual(chmod(pending.path, 0o600), 0)
            let storage = try open(root); defer { storage.close() }; var created = false
            let chosen = try record()
            XCTAssertThrowsError(try storage.restoreOrCreate(macID: mac, accountID: account,
                create: { created = true; return chosen }, verify: { _ in }))
            XCTAssertEqual(try Data(contentsOf: pending), Data([0])); XCTAssertFalse(created)
            try place(chosen, state: state, name: AuthorityKeyProvisioningStorage.recordName)
            try place(chosen, state: state, name: AuthorityKeyProvisioningStorage.pendingName)
            XCTAssertThrowsError(try storage.restoreOrCreate(macID: mac, accountID: account,
                create: { created = true; return chosen }, verify: { _ in })) {
                XCTAssertEqual($0 as? AuthorityKeyProvisioningError, .conflictingState)
            }
            XCTAssertFalse(created)
        }
    }
    func testLockExcludesAnotherOwnerAndDirectoryReplacementRetiresTheLease() throws {
        try fixture { root, state in
            let storage = try open(root); defer { storage.close() }
            XCTAssertThrowsError(try open(root)) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            try FileManager.default.moveItem(at: state, to: root.appendingPathComponent("moved"))
            try FileManager.default.createDirectory(at: state, withIntermediateDirectories: false)
            XCTAssertEqual(chmod(state.path, 0o700), 0)
            var created = false
            XCTAssertThrowsError(try storage.restoreOrCreate(macID: mac, accountID: account,
                create: { created = true; return try self.record() }, verify: { _ in }))
            XCTAssertFalse(created)
        }
    }
    func testPrivateRecordRejectsAliasesAndPermissiveMetadata() throws {
        try fixture { root, state in
            let chosen = try record(); try place(chosen, state: state, name: AuthorityKeyProvisioningStorage.recordName)
            let path = state.appendingPathComponent(AuthorityKeyProvisioningStorage.recordName)
            let storage = try open(root); defer { storage.close() }
            XCTAssertEqual(chmod(path.path, 0o640), 0)
            XCTAssertThrowsError(try storage.restoreOrCreate(macID: mac, accountID: account, create: { chosen }, verify: { _ in }))
            XCTAssertEqual(chmod(path.path, 0o600), 0)
            XCTAssertEqual(link(path.path, state.appendingPathComponent("alias").path), 0)
            XCTAssertThrowsError(try storage.restoreOrCreate(macID: mac, accountID: account, create: { chosen }, verify: { _ in }))
        }
    }
    func testChangedPreparedBytesAreNotPublished() throws {
        try fixture { root, state in
            let chosen = try record(), other = try record(), storage = try open(root); defer { storage.close() }
            XCTAssertThrowsError(try storage.restoreOrCreate(macID: mac, accountID: account, create: { chosen }, verify: { _ in },
                didStage: { if $0 == .prepared { try self.place(other, state: state, name: AuthorityKeyProvisioningStorage.pendingName) } }))
            XCTAssertFalse(FileManager.default.fileExists(atPath: state.appendingPathComponent(AuthorityKeyProvisioningStorage.recordName).path))
        }
    }
    func testPublicationCannotOverwriteAnExistingDestination() throws {
        try fixture { root, state in
            let chosen = try record(), other = try record(), storage = try open(root); defer { storage.close() }
            XCTAssertThrowsError(try storage.restoreOrCreate(macID: mac, accountID: account, create: { chosen }, verify: { _ in },
                didStage: { if $0 == .prepared { try self.place(other, state: state, name: AuthorityKeyProvisioningStorage.recordName) } }))
            XCTAssertEqual(try Data(contentsOf: state.appendingPathComponent(AuthorityKeyProvisioningStorage.recordName)), try other.encode())
        }
    }
    func testDirectoryBudgetIncludesTheRuntimeRecordPath() throws {
        try fixture { root, _ in
            var remaining = Int(PATH_MAX) - root.path.utf8.count - AuthorityKeyProvisioning.recordFileName.utf8.count - 3
            var parts: [String] = []
            while remaining > 255 { parts.append(String(repeating: "a", count: 255)); remaining -= 256 }
            parts.append(String(repeating: "b", count: remaining))
            XCTAssertThrowsError(try AuthorityKeyProvisioningStorage(anchor: root.path,
                relativeDirectory: parts.joined(separator: "/"), owner: getuid())) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidPath)
            }
        }
    }
    func testClosedHookAndOrdinaryProductionCallerCannotPublish() throws {
        try fixture { root, state in
            let chosen = try record(), storage = try open(root)
            XCTAssertThrowsError(try storage.restoreOrCreate(macID: mac, accountID: account, create: { chosen }, verify: { _ in },
                didStage: { if $0 == .prepared { storage.close() } })) {
                XCTAssertEqual($0 as? JournalLeaseError, .closed)
            }
            if getuid() != 0 {
                XCTAssertThrowsError(try AuthorityKeyProvisioning.restoreOrCreate(directoryPath: state.path, macID: mac, accountID: account)) {
                    XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                }
            }
        }
    }
}
