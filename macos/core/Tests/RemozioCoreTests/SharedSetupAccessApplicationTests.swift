import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AccessApplicationFixture: @unchecked Sendable {
    let h: RelayProvisioningFixture
    let plan: SharedSetupImportRelayPlan
    let tunnel: SharedSetupRelayProvisioningRecord
    init() throws {
        let ownerFixture = try RelayProvisioningFixture(), localPlan = try ownerFixture.prepare()
        let retainedTunnel = try ownerFixture.directory { directory in
            let prepared = try SharedSetupRelayProvisioningStorage.begin(expected: ownerFixture.intent, plan: localPlan, directory: directory, owner: getuid(), verifyCurrent: {})
            let sent = try prepared.transition(to: .dispatched), created = try sent.transition(to: .created, tunnelID: "11111111-1111-4111-8111-111111111111")
            for (next, old) in [(sent, prepared), (created, sent)] {
                try SharedSetupRelayProvisioningStorage.replace(next, previous: old, expected: ownerFixture.intent, plan: localPlan, directory: directory, owner: getuid(), verifyCurrent: {})
            }
            return created
        }
        h = ownerFixture; plan = localPlan; tunnel = retainedTunnel
    }
    var path: String { URL(fileURLWithPath: h.path).deletingLastPathComponent().path + "/" + AdministrativeSetupPublication.File.importAccessApplication(accountID: h.intent.scope.accountID).name }
    func begin() throws -> SharedSetupAccessApplicationRecord {
        try h.directory { try SharedSetupAccessApplicationStorage.begin(expected: h.intent, plan: plan, createdTunnel: tunnel,
            directory: $0, owner: getuid(), verifyCurrent: {}) }
    }
    func read() throws -> SharedSetupAccessApplicationRecord? {
        try h.directory { try SharedSetupAccessApplicationStorage.read(expected: h.intent, plan: plan, createdTunnel: tunnel, directory: $0, owner: getuid()) }
    }
    func replace(_ next: SharedSetupAccessApplicationRecord, _ previous: SharedSetupAccessApplicationRecord,
                 stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws {
        try h.directory { try SharedSetupAccessApplicationStorage.replace(next, previous: previous, expected: h.intent, plan: plan,
            createdTunnel: tunnel, directory: $0, owner: getuid(), verifyCurrent: {}, didStage: stage) }
    }
    func retainCreated() throws -> SharedSetupAccessApplicationRecord {
        let prepared = try begin(), sent = try prepared.transition(to: .dispatched)
        let created = try sent.transition(to: .created, applicationID: "22222222-2222-4222-8222-222222222222", audience: String(repeating: "a", count: 64))
        try replace(sent, prepared); try replace(created, sent); return created
    }
    func applicationReply(changes: [String: Any] = [:], envelope extra: [String: Any] = [:]) throws -> Data {
        var app: [String: Any] = ["id": "22222222-2222-4222-8222-222222222222", "name": plan.accessApplicationName,
            "domain": plan.hostname, "type": "self_hosted", "aud": String(repeating: "a", count: 64),
            "service_auth_401_redirect": true, "auto_redirect_to_identity": false, "app_launcher_visible": false,
            "allow_authenticate_via_warp": false, "destinations": [["type": "public", "uri": plan.hostname]]]
        for (key, value) in changes { app[key] = value }
        var result: [String: Any] = ["success": true, "errors": [], "result": app]
        for (key, value) in extra { result[key] = value }
        return try JSONSerialization.data(withJSONObject: result)
    }
}

/// Owned protected files only. There is no provider or installed-service activity.
final class SharedSetupAccessApplicationTests: XCTestCase {
    private struct Interrupted: Error {}
    func testCanonicalRecordBindsTheCreatedTunnelAndContainsNoCredential() throws {
        let f = try AccessApplicationFixture(), record = try f.begin()
        XCTAssertEqual(record, try SharedSetupAccessApplicationRecord.decode(record.bytes, expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel))
        XCTAssertEqual(record.phase, .prepared); XCTAssertEqual(record.tunnelID, f.tunnel.tunnelID)
        XCTAssertEqual(String(reflecting: record), "SharedSetupAccessApplicationRecord(redacted)")
        XCTAssertNil(record.bytes.range(of: Data("synthetic-only-provider-token".utf8)))
    }
    func testRecordRequiresSuccessfulTunnelCreation() throws {
        let f = try AccessApplicationFixture(), unresolved = try SharedSetupRelayProvisioningRecord(expected: f.h.intent, plan: f.plan)
        XCTAssertThrowsError(try SharedSetupAccessApplicationRecord(expected: f.h.intent, plan: f.plan, createdTunnel: unresolved))
        let otherTunnel = try unresolved.transition(to: .dispatched).transition(to: .created, tunnelID: "33333333-3333-4333-8333-333333333333")
        let record = try f.begin()
        XCTAssertThrowsError(try SharedSetupAccessApplicationRecord.decode(record.bytes, expected: f.h.intent, plan: f.plan, createdTunnel: otherTunnel))
    }
    func testOnlyDispatchedAttemptsCanRetainACanonicalIdentityAndAudience() throws {
        let f = try AccessApplicationFixture(), prepared = try f.begin()
        XCTAssertThrowsError(try prepared.transition(to: .created, applicationID: "22222222-2222-4222-8222-222222222222", audience: "audience"))
        let sent = try prepared.transition(to: .dispatched)
        for audience in ["", "with space", String(repeating: "a", count: 257)] {
            XCTAssertThrowsError(try sent.transition(to: .created, applicationID: "22222222-2222-4222-8222-222222222222", audience: audience))
        }
        XCTAssertThrowsError(try sent.transition(to: .created, applicationID: "not-a-uuid", audience: "audience"))
        XCTAssertThrowsError(try sent.transition(to: .unknown, audience: "audience"))
    }
    func testUnknownAndCreatedOutcomesCannotRestart() throws {
        let f = try AccessApplicationFixture(), sent = try f.begin().transition(to: .dispatched)
        let unknown = try sent.transition(to: .unknown)
        XCTAssertThrowsError(try unknown.retryAfterRefusal()); XCTAssertThrowsError(try unknown.transition(to: .prepared))
        let created = try sent.transition(to: .created, applicationID: "22222222-2222-4222-8222-222222222222", audience: "audience")
        XCTAssertThrowsError(try created.retryAfterRefusal()); XCTAssertThrowsError(try created.transition(to: .dispatched))
    }
    func testExplicitRefusalRetryUsesANewAttemptAndRetainsTheTunnelBinding() throws {
        let f = try AccessApplicationFixture(), sent = try f.begin().transition(to: .dispatched)
        let refused = try sent.transition(to: .rejected, refusal: .unauthorized), next = try refused.retryAfterRefusal()
        XCTAssertEqual(next.tunnelID, refused.tunnelID); XCTAssertEqual(next.recordID, refused.recordID)
        XCTAssertNotEqual(next.attemptID, refused.attemptID); XCTAssertEqual(next.attemptNumber, 2)
        XCTAssertNoThrow(try next.validateTransition(from: refused))
    }
    func testMalformedVersionsPurposeFieldsAndRequestDigestAreRejected() throws {
        let f = try AccessApplicationFixture(), record = try f.begin(), limits = try CBORLimits(maxBytes: 8192, maxDepth: 1, maxItems: 40)
        guard case let .map(fields) = try DeterministicCBOR.decode(record.bytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other-purpose")), (6, .unsigned(0)),
            (11, .bytes(Data(repeating: 0, count: 32))), (12, .text("33333333-3333-4333-8333-333333333333")), (14, .null)] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try SharedSetupAccessApplicationRecord.decode(DeterministicCBOR.encode(.map(changed), limits: limits),
                expected: f.h.intent, plan: f.plan, createdTunnel: f.tunnel))
        }
    }
    func testExistingBeginPreservesDispatchAndUnknownAcrossReopen() throws {
        let f = try AccessApplicationFixture(), prepared = try f.begin(), sent = try prepared.transition(to: .dispatched)
        try f.replace(sent, prepared); XCTAssertEqual(try f.begin(), sent)
        let unknown = try sent.transition(to: .unknown); try f.replace(unknown, sent)
        XCTAssertEqual(try f.read(), unknown); XCTAssertEqual(try f.begin(), unknown)
        var info = stat(); XCTAssertEqual(lstat(f.path, &info), 0); XCTAssertEqual(info.st_mode & 0o777, 0o600)
    }
    func testStaleCompareAndSwapCannotUndoAnAccessDispatch() throws {
        let f = try AccessApplicationFixture(), prepared = try f.begin(), sent = try prepared.transition(to: .dispatched)
        try f.replace(sent, prepared)
        XCTAssertThrowsError(try f.replace(prepared.transition(to: .dispatched), prepared)); XCTAssertEqual(try f.read(), sent)
    }
    func testLostPublicationReplyRetainsTheUnresolvedDispatch() throws {
        let f = try AccessApplicationFixture(), prepared = try f.begin(), sent = try prepared.transition(to: .dispatched)
        XCTAssertThrowsError(try f.replace(sent, prepared, stage: { if $0 == .published { throw Interrupted() } }))
        XCTAssertEqual(try f.read(), sent); XCTAssertEqual(try f.begin(), sent)
    }
    func testUpdateSnapshotPinsAccessStateAndRequiresItsSetupReaderAndWriter() throws {
        let f = try AccessApplicationFixture(), prepared = try f.begin()
        let snapshot = try f.h.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        XCTAssertNotNil(snapshot.inputs.sharedImport?.records.first?.accessApplication)
        let requirement = try XCTUnwrap(snapshot.requirements.formats.first { $0.name == SharedSetupAccessApplicationRecord.formatName })
        XCTAssertEqual(requirement.role, .setupController); XCTAssertEqual(requirement.readVersions, [1]); XCTAssertEqual(requirement.writeVersions, [1])
        try f.replace(prepared.transition(to: .dispatched), prepared)
        XCTAssertThrowsError(try f.h.machine { try snapshot.requireCurrent(machine: $0) })
    }
    func testIdenticalBytesWithANewInodeInvalidateTheUpdateSnapshot() throws {
        let f = try AccessApplicationFixture(), prepared = try f.begin()
        let snapshot = try f.h.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        let temp = f.path + ".replacement"; try prepared.bytes.write(to: URL(fileURLWithPath: temp))
        XCTAssertEqual(chmod(temp, 0o600), 0); XCTAssertEqual(rename(temp, f.path), 0)
        XCTAssertThrowsError(try f.h.machine { try snapshot.requireCurrent(machine: $0) })
    }
    func testMissingPlanOrTunnelCannotBeReselectedUnderAnAccessRecord() throws {
        for removePlan in [false, true] {
            let f = try AccessApplicationFixture(); _ = try f.begin()
            let path = removePlan ? f.h.path : URL(fileURLWithPath: f.path).deletingLastPathComponent().path + "/" + AdministrativeSetupPublication.File.importRelayProvisioning(accountID: f.h.intent.scope.accountID).name
            XCTAssertEqual(unlink(path), 0)
            XCTAssertThrowsError(try f.h.prepare(select: { _ in XCTFail("No port reselection"); return 51002 }))
            XCTAssertThrowsError(try f.h.machine { try $0.retainedRuntimeCompatibilityInputs() })
        }
    }
    func testMalformedAndSymlinkedAccessRecordsAreNotOverwritten() throws {
        let f = try AccessApplicationFixture(); _ = try f.begin(); let bytes = Data("malformed".utf8)
        try bytes.write(to: URL(fileURLWithPath: f.path)); XCTAssertThrowsError(try f.begin())
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path)), bytes)
        XCTAssertEqual(unlink(f.path), 0); XCTAssertEqual(symlink(f.h.path, f.path), 0); XCTAssertThrowsError(try f.begin())
    }
    func testGenericSettingsPublisherCannotWriteAccessState() throws {
        let f = try AccessApplicationFixture(), record = try f.begin()
        XCTAssertThrowsError(try f.h.directory { try AdministrativeSetupPublication.replaceSettings(record.bytes, expected: record.bytes,
            file: .importAccessApplication(accountID: f.h.intent.scope.accountID), directory: $0, owner: getuid(), verify: {}) })
    }
}
