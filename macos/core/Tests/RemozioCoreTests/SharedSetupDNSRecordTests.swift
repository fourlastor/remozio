import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class DNSRecordFixture: @unchecked Sendable {
    let base: AccessApplicationFixture
    let access: SharedSetupAccessApplicationRecord
    static let providerID = String(repeating: "d", count: 32)
    init() throws { let value = try AccessApplicationFixture(); base = value; access = try value.retainCreated() }
    var path: String { URL(fileURLWithPath: base.path).deletingLastPathComponent().appendingPathComponent(AdministrativeSetupPublication.File.importDNSRecord(accountID: base.h.intent.scope.accountID).name).path }
    func begin() throws -> SharedSetupDNSRecord {
        try base.h.directory { try SharedSetupDNSStorage.begin(expected: base.h.intent, plan: base.plan, createdTunnel: base.tunnel,
            application: access, directory: $0, owner: getuid(), verifyCurrent: {}) }
    }
    func read() throws -> SharedSetupDNSRecord? {
        try base.h.directory { try SharedSetupDNSStorage.read(expected: base.h.intent, plan: base.plan, createdTunnel: base.tunnel,
            application: access, directory: $0, owner: getuid()) }
    }
    func replace(_ next: SharedSetupDNSRecord, previous: SharedSetupDNSRecord,
                 stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws {
        try base.h.directory { try SharedSetupDNSStorage.replace(next, previous: previous, expected: base.h.intent, plan: base.plan,
            createdTunnel: base.tunnel, application: access, directory: $0, owner: getuid(), verifyCurrent: {}, didStage: stage) }
    }
    func retainCreated() throws -> SharedSetupDNSRecord {
        let prepared = try begin(), sent = try prepared.transition(to: .dispatched), created = try sent.transition(to: .created, dnsRecordID: Self.providerID)
        try replace(sent, previous: prepared); try replace(created, previous: sent); return created
    }
    func dnsReply(changes: [String: Any] = [:], envelope extra: [String: Any] = [:], omitting fields: [String] = []) throws -> Data {
        var record: [String: Any] = ["id": Self.providerID, "name": base.plan.hostname, "type": "CNAME",
            "content": base.tunnel.tunnelID! + ".cfargotunnel.com", "proxied": true, "proxiable": true, "ttl": 1,
            "zone_id": try XCTUnwrap(base.h.f.proposal().cloudflare).zoneID, "meta": [:]]
        for (key, value) in changes { record[key] = value }
        for key in fields { record.removeValue(forKey: key) }
        var result: [String: Any] = ["success": true, "errors": [], "result": record]
        for (key, value) in extra { result[key] = value }; return try JSONSerialization.data(withJSONObject: result)
    }
}

/// Owned fixture files only. Provider authorization and DNS publication are not exercised.
final class SharedSetupDNSRecordTests: XCTestCase {
    private struct Interrupted: Error {}
    func testCanonicalRecordBindsThePlanCreatedTunnelAndExactAccessRecord() throws {
        let f = try DNSRecordFixture(), record = try f.begin()
        XCTAssertEqual(record, try SharedSetupDNSRecord.decode(record.bytes, expected: f.base.h.intent, plan: f.base.plan,
            createdTunnel: f.base.tunnel, application: f.access))
        XCTAssertEqual(record.accessApplicationID, f.access.applicationID)
        XCTAssertEqual(record.accessRecordDigest, Data(SHA256.hash(data: f.access.bytes)))
        XCTAssertEqual(record.tunnelID, f.base.tunnel.tunnelID); XCTAssertEqual(record.phase, .prepared)
        XCTAssertEqual(String(reflecting: record), "SharedSetupDNSRecord(redacted)")
        XCTAssertNil(record.bytes.range(of: Data("synthetic-only-provider-token".utf8)))
    }
    func testUnresolvedTunnelOrAccessCreationCannotPrepareDNS() throws {
        let f = try DNSRecordFixture(), unresolved = try SharedSetupAccessApplicationRecord(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel)
        XCTAssertThrowsError(try SharedSetupDNSRecord(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: unresolved))
        let tunnel = try SharedSetupRelayProvisioningRecord(expected: f.base.h.intent, plan: f.base.plan)
        XCTAssertThrowsError(try SharedSetupDNSRecord(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: tunnel, application: f.access))
    }
    func testOnlyDispatchedAttemptsCanRetainACanonicalDNSIdentifier() throws {
        let f = try DNSRecordFixture(), prepared = try f.begin(), sent = try prepared.transition(to: .dispatched)
        XCTAssertThrowsError(try prepared.transition(to: .created, dnsRecordID: DNSRecordFixture.providerID))
        for id in ["", "not-an-id", String(repeating: "d", count: 31), String(repeating: "d", count: 33), String(repeating: "D", count: 32),
            "11111111-1111-4111-8111-111111111111", String(repeating: "g", count: 32)] {
            XCTAssertThrowsError(try sent.transition(to: .created, dnsRecordID: id))
        }
        XCTAssertThrowsError(try sent.transition(to: .unknown, dnsRecordID: DNSRecordFixture.providerID))
    }
    func testUnknownAndCreatedStatesCannotRetryOrDiscardTheirHistory() throws {
        let f = try DNSRecordFixture(), sent = try f.begin().transition(to: .dispatched)
        let unknown = try sent.transition(to: .unknown), created = try sent.transition(to: .created, dnsRecordID: DNSRecordFixture.providerID)
        for record in [unknown, created] {
            XCTAssertThrowsError(try record.retryAfterRefusal()); XCTAssertThrowsError(try record.transition(to: .prepared))
            XCTAssertThrowsError(try record.transition(to: .dispatched))
        }
    }
    func testExplicitRefusalRetryUsesANewAttemptAndPreservesEveryResourceBinding() throws {
        let f = try DNSRecordFixture(), sent = try f.begin().transition(to: .dispatched)
        let rejected = try sent.transition(to: .rejected, refusal: .unauthorized), retried = try rejected.retryAfterRefusal()
        XCTAssertEqual(retried.recordID, rejected.recordID); XCTAssertEqual(retried.accessRecordDigest, rejected.accessRecordDigest)
        XCTAssertEqual(retried.tunnelID, rejected.tunnelID); XCTAssertEqual(retried.requestDigest, rejected.requestDigest)
        XCTAssertEqual(retried.attemptNumber, 2); XCTAssertNotEqual(retried.attemptID, rejected.attemptID)
    }
    func testVersionsPurposeAdditionalFieldsAndResourceDigestsAreValidated() throws {
        let f = try DNSRecordFixture(), record = try f.begin(), limits = try CBORLimits(maxBytes: 8192, maxDepth: 1, maxItems: 40)
        guard case let .map(fields) = try DeterministicCBOR.decode(record.bytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("wrong-purpose")), (6, .unsigned(0)),
            (11, .bytes(Data(repeating: 0, count: 32))), (13, .bytes(Data(repeating: 0, count: 32))),
            (14, .text("33333333-3333-4333-8333-333333333333")), (15, .null)] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try SharedSetupDNSRecord.decode(DeterministicCBOR.encode(.map(changed), limits: limits), expected: f.base.h.intent,
                plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access))
        }
    }
    func testAccessIdentityAloneCannotRebindAnotherCreationRecord() throws {
        let f = try DNSRecordFixture(), record = try f.begin()
        let other = try SharedSetupAccessApplicationRecord(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel)
            .transition(to: .dispatched).transition(to: .created, applicationID: XCTUnwrap(f.access.applicationID), audience: XCTUnwrap(f.access.audience))
        XCTAssertThrowsError(try record.validate(expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: other))
    }
    func testDispatchedAndUnknownStatesSurviveBeginWithoutCreatingANewAttempt() throws {
        let f = try DNSRecordFixture(), prepared = try f.begin(), sent = try prepared.transition(to: .dispatched)
        try f.replace(sent, previous: prepared); XCTAssertEqual(try f.begin(), sent)
        let unknown = try sent.transition(to: .unknown); try f.replace(unknown, previous: sent)
        XCTAssertEqual(try f.read(), unknown); XCTAssertEqual(try f.begin(), unknown)
        var info = stat(); XCTAssertEqual(lstat(f.path, &info), 0); XCTAssertEqual(info.st_mode & 0o777, 0o600)
    }
    func testStaleCompareAndSwapCannotOverwriteDispatchedState() throws {
        let f = try DNSRecordFixture(), prepared = try f.begin(), sent = try prepared.transition(to: .dispatched)
        try f.replace(sent, previous: prepared)
        XCTAssertThrowsError(try f.replace(prepared.transition(to: .dispatched), previous: prepared)); XCTAssertEqual(try f.read(), sent)
    }
    func testLostPublicationReplyRetainsDispatchWithoutRetryPermission() throws {
        let f = try DNSRecordFixture(), prepared = try f.begin(), sent = try prepared.transition(to: .dispatched)
        XCTAssertThrowsError(try f.replace(sent, previous: prepared, stage: { if $0 == .published { throw Interrupted() } }))
        XCTAssertEqual(try f.read(), sent); XCTAssertEqual(try f.begin(), sent)
    }
    func testUpdateSnapshotIncludesDNSAndRequiresItsSetupReaderAndWriter() throws {
        let f = try DNSRecordFixture(), prepared = try f.begin()
        let snapshot = try f.base.h.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        XCTAssertNotNil(snapshot.inputs.sharedImport?.records.first?.dnsRecord)
        let requirement = try XCTUnwrap(snapshot.requirements.formats.first { $0.name == SharedSetupDNSRecord.formatName })
        XCTAssertEqual(requirement.role, .setupController); XCTAssertEqual(requirement.readVersions, [1]); XCTAssertEqual(requirement.writeVersions, [1])
        try f.replace(prepared.transition(to: .dispatched), previous: prepared)
        XCTAssertThrowsError(try f.base.h.machine { try snapshot.requireCurrent(machine: $0) })
    }
    func testIdenticalDNSBytesWithANewInodeInvalidateTheUpdateSnapshot() throws {
        let f = try DNSRecordFixture(), prepared = try f.begin(), snapshot = try f.base.h.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        let temp = f.path + ".replacement"; try prepared.bytes.write(to: URL(fileURLWithPath: temp))
        XCTAssertEqual(chmod(temp, 0o600), 0); XCTAssertEqual(rename(temp, f.path), 0)
        XCTAssertThrowsError(try f.base.h.machine { try snapshot.requireCurrent(machine: $0) })
    }
    func testMissingDependenciesCannotReselectTheRelayUnderARetainedDNSRecord() throws {
        for selected in 0..<3 {
            let f = try DNSRecordFixture(); _ = try f.begin()
            let parent = URL(fileURLWithPath: f.path).deletingLastPathComponent()
            let path = selected == 0 ? f.base.h.path : selected == 1 ? parent.appendingPathComponent(AdministrativeSetupPublication.File.importRelayProvisioning(accountID: f.base.h.intent.scope.accountID).name).path : f.base.path
            XCTAssertEqual(unlink(path), 0)
            XCTAssertThrowsError(try f.base.h.prepare(select: { _ in XCTFail("No reselection"); return 51002 }))
            XCTAssertThrowsError(try f.base.h.machine { try $0.retainedRuntimeCompatibilityInputs() })
        }
    }
    func testMalformedAndSymlinkedDNSStateIsNotReplaced() throws {
        let f = try DNSRecordFixture(); _ = try f.begin(); let bytes = Data("malformed".utf8)
        try bytes.write(to: URL(fileURLWithPath: f.path)); XCTAssertThrowsError(try f.begin())
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path)), bytes)
        XCTAssertEqual(unlink(f.path), 0); XCTAssertEqual(symlink(f.base.path, f.path), 0); XCTAssertThrowsError(try f.begin())
    }
    func testUntrackedDNSRecordCannotDisappearFromCompatibilityChecks() throws {
        let f = try DNSRecordFixture(), record = try f.begin(), path = URL(fileURLWithPath: f.path).deletingLastPathComponent()
            .appendingPathComponent("import-relay-dns-" + String(repeating: "e", count: 32) + ".cbor")
        try record.bytes.write(to: path); XCTAssertEqual(chmod(path.path, 0o600), 0)
        XCTAssertThrowsError(try f.base.h.machine { try $0.retainedRuntimeCompatibilityInputs() })
    }
    func testGenericPublisherAndInitialDispatchedPublicationAreRejected() throws {
        let f = try DNSRecordFixture(), prepared = try f.begin(), sent = try prepared.transition(to: .dispatched)
        XCTAssertThrowsError(try f.base.h.directory { try AdministrativeSetupPublication.replaceSettings(sent.bytes, expected: prepared.bytes,
            file: .importDNSRecord(accountID: f.base.h.intent.scope.accountID), directory: $0, owner: getuid(), verify: {}) })
        XCTAssertThrowsError(try f.base.h.directory { try AdministrativeSetupPublication.replaceDNSRecord(sent.bytes, previous: nil,
            expected: f.base.h.intent, plan: f.base.plan, createdTunnel: f.base.tunnel, application: f.access, directory: $0, owner: getuid(), verify: {}) })
        XCTAssertEqual(try f.read(), prepared)
    }
}
