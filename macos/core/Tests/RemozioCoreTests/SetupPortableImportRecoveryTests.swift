import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Metadata codecs and owned files only. This does not authenticate a native Root channel or administrator authorization.
final class SetupPortableImportRecoveryTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 4096, maxDepth: 3, maxItems: 96)
    private func rejected(_ f: DNSRecordFixture) throws -> SharedSetupDNSRecord {
        let first = try f.begin(), sent = try first.transition(to: .dispatched), rejected = try sent.transition(to: .rejected, refusal: .unauthorized)
        try f.replace(sent, previous: first); try f.replace(rejected, previous: sent); return rejected
    }
    private func fields(_ value: SetupPortableImportRecovery) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(value.bytes, limits: limits) else { throw AdministrativeSetupChannelError.invalidMessage }
        return fields
    }
    private func row(_ fields: [UInt64: CBORValue], index: Int) throws -> [UInt64: CBORValue] {
        guard case .array(let records) = fields[5], case .map(let entry) = records[index] else { throw AdministrativeSetupChannelError.invalidMessage }
        return entry
    }
    private func replacing(_ fields: [UInt64: CBORValue], row index: Int, key: UInt64, value: CBORValue) throws -> Data {
        var changed = fields
        guard case .array(var records) = fields[5] else { throw AdministrativeSetupChannelError.invalidMessage }
        var entry = try row(fields, index: index); entry[key] = value; records[index] = .map(entry); changed[5] = .array(records)
        return try DeterministicCBOR.encode(.map(changed), limits: limits)
    }
    func testCanonicalProjectionBindsPublicProgressAndExactRejectedRecordWithoutCredentials() throws {
        let f = try DNSRecordFixture(), retained = try rejected(f), owner = try f.base.h.owner(); defer { try? owner.close() }
        let value = try XCTUnwrap(owner.portableImportRecovery(callerUID: getuid()))
        XCTAssertEqual(value.progress, try f.base.h.progress(owner)); XCTAssertTrue(value.relayConfigured)
        XCTAssertEqual(value.relayScope?.hostname, f.base.plan.hostname); XCTAssertEqual(value.relayScope?.tunnelName, f.base.plan.tunnelName)
        XCTAssertEqual(value.records.map(\.resource), [.tunnel, .accessApplication, .dnsRecord])
        let dns = try XCTUnwrap(value.rejectedRecord(for: .dnsRecord))
        XCTAssertEqual(dns.phase, .rejected); XCTAssertEqual(dns.refusal, .unauthorized); XCTAssertNil(dns.providerID)
        XCTAssertEqual(dns.recordDigest, Data(SHA256.hash(data: retained.bytes))); XCTAssertEqual(dns.attemptNumber, retained.attemptNumber)
        XCTAssertNil(value.rejectedRecord(for: .tunnel)); XCTAssertNil(value.rejectedRecord(for: .accessApplication))
        XCTAssertEqual(value.records[0].providerID, f.base.tunnel.tunnelID); XCTAssertEqual(value.records[1].providerID, f.access.applicationID)
        let bytes = try value.bytes
        XCTAssertLessThanOrEqual(bytes.count, SetupPortableImportRecovery.maximumByteCount)
        XCTAssertNil(bytes.range(of: Data("synthetic-provider-token-only".utf8)))
        XCTAssertEqual(try SetupPortableImportRecovery.decode(bytes), value)
        XCTAssertEqual(String(reflecting: value), "SetupPortableImportRecovery(redacted)")
        XCTAssertEqual(String(reflecting: dns), "SetupPortableImportRecovery.Record(redacted)")
        XCTAssertTrue(Mirror(reflecting: value).children.isEmpty); XCTAssertTrue(Mirror(reflecting: dns).children.isEmpty)
    }
    func testClosedEnvelopeAndScopeFieldsRejectCrossedOrUnsupportedValues() throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }; _ = try rejected(f)
        let value = try XCTUnwrap(owner.portableImportRecovery(callerUID: getuid())), original = try fields(value)
        for (key, field): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other-purpose")), (3, .null), (4, .null), (6, .null)] {
            var changed = original; changed[key] = field
            XCTAssertThrowsError(try SetupPortableImportRecovery.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        guard case .map(let scope) = original[4] else { return XCTFail() }
        for (key, field): (UInt64, CBORValue) in [(0, .text("wrong-account")), (1, .text("wrong-zone")),
            (2, .text("m-" + String(repeating: "0", count: 32) + ".example.invalid")),
            (3, .text("remozio-" + String(repeating: "0", count: 32))), (4, .null)] {
            var changed = original, crossed = scope; crossed[key] = field; changed[4] = .map(crossed)
            XCTAssertThrowsError(try SetupPortableImportRecovery.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        for bytes in [Data(), Data(repeating: 0, count: SetupPortableImportRecovery.maximumByteCount + 1)] {
            XCTAssertThrowsError(try SetupPortableImportRecovery.decode(bytes))
        }
    }
    func testEntriesRejectUnknownKindsBadDigestsAndCrossedStateOrIdentity() throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }; _ = try rejected(f)
        let original = try fields(XCTUnwrap(owner.portableImportRecovery(callerUID: getuid())))
        for (key, field): (UInt64, CBORValue) in [(0, .unsigned(4)), (1, .unsigned(9)), (2, .bytes(Data(repeating: 0, count: 31))),
            (3, .unsigned(0)), (4, .text("not-a-provider-id")), (5, .unsigned(1)), (6, .null)] {
            XCTAssertThrowsError(try SetupPortableImportRecovery.decode(replacing(original, row: 0, key: key, value: field)))
        }
        for field: CBORValue in [.null, .unsigned(0), .unsigned(4)] {
            XCTAssertThrowsError(try SetupPortableImportRecovery.decode(replacing(original, row: 2, key: 5, value: field)))
        }
        XCTAssertThrowsError(try SetupPortableImportRecovery.decode(replacing(original, row: 2, key: 4, value: .text(String(repeating: "d", count: 32)))))
        var createdDNS = original
        guard case .array(var records) = original[5] else { return XCTFail() }
        var entry = try row(original, index: 2); entry[1] = .unsigned(3); entry[4] = .text(String(repeating: "D", count: 32)); entry[5] = .null
        records[2] = .map(entry); createdDNS[5] = .array(records)
        XCTAssertThrowsError(try SetupPortableImportRecovery.decode(DeterministicCBOR.encode(.map(createdDNS), limits: limits)))
    }
    func testDuplicateUnorderedAndMissingParentEntriesCannotDecode() throws {
        let f = try DNSRecordFixture(), owner = try f.base.h.owner(); defer { try? owner.close() }; _ = try rejected(f)
        let original = try fields(XCTUnwrap(owner.portableImportRecovery(callerUID: getuid())))
        guard case .array(let records) = original[5] else { return XCTFail() }
        for changedRows in [[records[1], records[0], records[2]], [records[0], records[0]], [records[1], records[2]], [records[0], records[2]]] {
            var changed = original; changed[5] = .array(changedRows)
            XCTAssertThrowsError(try SetupPortableImportRecovery.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        var changed = original; changed[3] = .boolean(false)
        XCTAssertThrowsError(try SetupPortableImportRecovery.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
    }
}

final class SetupPortableImportRecoveryOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Refused: Error {}
    private func fileHashes(_ h: RelayProvisioningFixture) throws -> [String: Data] {
        let path = URL(fileURLWithPath: h.path).deletingLastPathComponent()
        return try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(atPath: path.path).map { name in
            (name, Data(SHA256.hash(data: try Data(contentsOf: path.appendingPathComponent(name)))))
        })
    }
    private func replace(_ path: String, bytes: Data) throws {
        let replacement = path + ".replacement"; try bytes.write(to: URL(fileURLWithPath: replacement))
        guard chmod(replacement, 0o600) == 0, rename(replacement, path) == 0 else { throw Refused() }
    }
    func testBeforeImportReadDoesNotCreateStorageAndWaitsForServicePreparation() throws {
        for complete in [false, true] {
            let f = try AccountPreparationFixture(), machine = try f.open(initialize: true)
            let account = try f.resume(machine, f.begin(machine))
            let services = try ServiceAccountPlan(account: account, planID: AccountPreparationIntent.randomID(), claims: [
                .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
                .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
            try machine.retainServiceAccountPlan(services)
            if complete { try machine.completeServiceAccountPlan(services) }
            try machine.close()
            let owner = try SetupAccountOwner(openMachine: { try f.open() }, expectedReleaseDigest: f.release,
                resume: { _, _ in throw Refused() }, accountCodePolicy: f.policy,
                lookupAccount: { uid in guard uid == f.identity.uid else { throw Refused() }; return f.identity })
            defer { try? owner.close() }
            let path = f.root.appendingPathComponent("machine/SharedSetupImport").path
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            let value = try owner.portableImportRecovery(callerUID: getuid())
            if complete {
                let result = try XCTUnwrap(value)
                XCTAssertNil(result.progress.operationID); XCTAssertFalse(result.relayConfigured)
                XCTAssertNil(result.relayScope); XCTAssertTrue(result.records.isEmpty)
            } else { XCTAssertNil(value) }
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }
    func testAReadCannotPrepareAMissingPlanOrAlterAnyRetainedFile() throws {
        let h = try RelayProvisioningFixture(), owner = try h.owner(); defer { try? owner.close() }
        let before = try fileHashes(h), result = try XCTUnwrap(owner.portableImportRecovery(callerUID: getuid()))
        XCTAssertEqual(result.progress, try h.progress(owner)); XCTAssertTrue(result.relayConfigured)
        XCTAssertNil(result.relayScope); XCTAssertTrue(result.records.isEmpty); XCTAssertNil(try h.readPlan())
        XCTAssertEqual(try fileHashes(h), before)
    }
    func testPreparedDispatchedUnknownAndCreatedHistoryNeverBecomesARetryPermission() throws {
        for phase in [SharedSetupDNSRecord.Phase.prepared, .dispatched, .unknown, .created] {
            let f = try DNSRecordFixture(), first = try f.begin()
            if phase != .prepared {
                let sent = try first.transition(to: .dispatched); try f.replace(sent, previous: first)
                if phase == .unknown { try f.replace(sent.transition(to: .unknown), previous: sent) }
                if phase == .created { try f.replace(sent.transition(to: .created, dnsRecordID: DNSRecordFixture.providerID), previous: sent) }
            }
            let owner = try f.base.h.owner(); defer { try? owner.close() }; let before = try fileHashes(f.base.h)
            let result = try XCTUnwrap(owner.portableImportRecovery(callerUID: getuid()))
            XCTAssertEqual(result.records.last?.phase.rawValue, phase.rawValue); XCTAssertNil(result.rejectedRecord(for: .dnsRecord))
            XCTAssertEqual(try fileHashes(f.base.h), before)
        }
    }
    func testReadbackMatchesTheNewPreparedAttemptAfterExplicitRefusalRecovery() async throws {
        let f = try DNSRecordFixture(), first = try f.begin(), sent = try first.transition(to: .dispatched)
        let rejected = try sent.transition(to: .rejected, refusal: .unauthorized)
        try f.replace(sent, previous: first); try f.replace(rejected, previous: sent)
        let owner = try f.base.h.owner(); defer { try? owner.close() }
        let before = try XCTUnwrap(owner.portableImportRecovery(callerUID: getuid())), probe = try RelayIngressProbe(RelayPublicationReplies.ownerSteps(f))
        let prepared = try await owner.prepareRefusedImportedDNSRecordRetry(callerUID: getuid(), expected: before.progress,
            proposal: f.base.h.f.proposal(), expectedRecordDigest: XCTUnwrap(before.rejectedRecord(for: .dnsRecord)).recordDigest,
            send: { try await probe.send($0) })
        let after = try XCTUnwrap(owner.portableImportRecovery(callerUID: getuid()))
        XCTAssertEqual(after.progress, before.progress); XCTAssertNil(after.rejectedRecord(for: .dnsRecord))
        XCTAssertEqual(after.records.last?.phase, .prepared); XCTAssertEqual(after.records.last?.recordDigest, Data(SHA256.hash(data: prepared.bytes)))
        XCTAssertNotEqual(after.records.last?.recordDigest, before.records.last?.recordDigest); XCTAssertEqual(after.records.last?.attemptNumber, 2)
    }
    func testCapturedProjectionRejectsIdenticalReplacementOfEveryFile() throws {
        for index in 0..<4 {
            let f = try DNSRecordFixture(); _ = try f.retainCreated()
            let h = f.base.h
            let paths = [h.path, URL(fileURLWithPath: h.path).deletingLastPathComponent().appendingPathComponent(AdministrativeSetupPublication.File.importRelayProvisioning(accountID: h.intent.scope.accountID).name).path,
                f.base.path, f.path]
            try h.directory { directory in
                let captured = try SharedSetupImportRecoveryProjection.capture(expected: h.intent, directory: directory, owner: getuid())
                try self.replace(paths[index], bytes: Data(contentsOf: URL(fileURLWithPath: paths[index])))
                XCTAssertThrowsError(try captured.requireCurrent(expected: h.intent, directory: directory, owner: getuid()))
            }
        }
    }
    func testCapturedProjectionRejectsANewRecordAfterAnAbsentObservation() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare()
        try h.directory { directory in
            let captured = try SharedSetupImportRecoveryProjection.capture(expected: h.intent, directory: directory, owner: getuid())
            _ = try SharedSetupRelayProvisioningStorage.begin(expected: h.intent, plan: plan, directory: directory, owner: getuid(), verifyCurrent: {})
            XCTAssertThrowsError(try captured.requireCurrent(expected: h.intent, directory: directory, owner: getuid()))
        }
    }
    func testCorruptOrOrphanResourceFilesAreRefusedWithoutRepair() throws {
        for orphan in [false, true] {
            let h = try RelayProvisioningFixture(), owner = try h.owner(); defer { try? owner.close() }
            let path: String
            if orphan {
                path = URL(fileURLWithPath: h.path).deletingLastPathComponent().appendingPathComponent("import-relay-state-" + String(repeating: "e", count: 32) + ".cbor").path
            } else { path = h.path }
            try Data("malformed-metadata".utf8).write(to: URL(fileURLWithPath: path)); XCTAssertEqual(chmod(path, 0o600), 0)
            let before = try fileHashes(h)
            XCTAssertThrowsError(try owner.portableImportRecovery(callerUID: getuid()))
            XCTAssertEqual(try fileHashes(h), before)
        }
    }
    func testWrongCallerAndClosedOwnerCannotReturnAnotherAccountsMetadata() throws {
        let h = try RelayProvisioningFixture(), owner = try h.owner()
        XCTAssertNil(try owner.portableImportRecovery(callerUID: getuid() + 1))
        try owner.close(); XCTAssertThrowsError(try owner.portableImportRecovery(callerUID: getuid()))
    }
}
