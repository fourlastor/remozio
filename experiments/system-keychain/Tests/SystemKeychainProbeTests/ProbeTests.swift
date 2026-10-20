import Foundation
import Security
import XCTest
@testable import SystemKeychainProbe

final class ProbeTests: XCTestCase {
    final class Fake: KeychainBackend {
        var calls: [String] = []
        var error: ProbeError?
        var digest = String(repeating: "a", count: 64)
        func create(id: UUID, reader: String) throws -> String { calls.append("create"); if let error { throw error }; return digest }
        func read(id: UUID) throws -> String { calls.append("read"); if let error { throw error }; return digest }
        func remove(id: UUID) throws { calls.append("delete"); if let error { throw error } }
    }
    let id = UUID(uuidString: "12345678-1234-4234-8234-123456789abc")!
    func testDefaultAndPlanDoNotTouchAnyKeychain() throws {
        for args: [String] in [[], ["--plan"]] {
            let fake = Fake(), operation = try Operation.parse(args)
            let report = try Controller(backend: fake, uid: 501, effectiveUID: 501).run(operation)
            XCTAssertEqual(report.outcome, "not-run"); XCTAssertFalse(report.keychainOperationRequested); XCTAssertTrue(fake.calls.isEmpty)
        }
    }
    func testCreationAndDeletionRequireRealAndEffectiveRootBeforeBackendAccess() {
        for (uid, euid): (UInt32, UInt32) in [(501, 501), (501, 0), (0, 501)] {
            for operation in [Operation.create(id, reader: "/protected/reader"), .remove(id)] {
                let fake = Fake()
                XCTAssertThrowsError(try Controller(backend: fake, uid: uid, effectiveUID: euid).run(operation)) {
                    XCTAssertEqual($0 as? ProbeError, .rootRequired)
                }
                XCTAssertTrue(fake.calls.isEmpty)
            }
        }
    }
    func testReadRunsAsTheActualSelectedAccountAndReportsOnlyAMatch() throws {
        let fake = Fake(), report = try Controller(backend: fake, uid: 233, effectiveUID: 233).run(.read(id, digest: fake.digest))
        XCTAssertEqual(fake.calls, ["read"]); XCTAssertEqual(report.actualUID, 233); XCTAssertEqual(report.outcome, "matched")
        XCTAssertNil(report.secretSHA256); XCTAssertFalse(report.lifecycleProven); XCTAssertFalse(report.readerIsolationProven)
    }
    func testMismatchedReadDoesNotProduceSuccessOrRetry() {
        let fake = Fake()
        XCTAssertThrowsError(try Controller(backend: fake, uid: 233, effectiveUID: 233).run(.read(id, digest: String(repeating: "b", count: 64)))) {
            XCTAssertEqual($0 as? ProbeError, .invalidResponse)
        }
        XCTAssertEqual(fake.calls, ["read"])
    }
    func testDuplicateCreationNeverAdoptsOrReplacesAnItem() {
        let fake = Fake(); fake.error = .status(errSecDuplicateItem)
        XCTAssertThrowsError(try Controller(backend: fake, uid: 0, effectiveUID: 0).run(.create(id, reader: "/protected/reader"))) {
            XCTAssertEqual($0 as? ProbeError, .status(errSecDuplicateItem))
        }
        XCTAssertEqual(fake.calls, ["create"])
    }
    func testDeniedReadPreservesTheNumericStatusWithoutAnAutomaticRetry() {
        let fake = Fake(); fake.error = .status(errSecInteractionNotAllowed)
        XCTAssertThrowsError(try Controller(backend: fake, uid: 233, effectiveUID: 233).run(.read(id, digest: fake.digest))) {
            XCTAssertEqual($0 as? ProbeError, .status(errSecInteractionNotAllowed))
        }
        XCTAssertEqual(fake.calls, ["read"])
    }
    func testDeletionTargetsOneSelectedExperimentOnly() throws {
        let fake = Fake(), report = try Controller(backend: fake, uid: 0, effectiveUID: 0).run(.remove(id))
        XCTAssertEqual(fake.calls, ["delete"]); XCTAssertEqual(report.experimentID, id.uuidString.lowercased())
        XCTAssertEqual(report.outcome, "removed"); XCTAssertFalse(report.lifecycleProven)
    }
    func testCreationReturnsADigestButDoesNotClaimServiceOrLifecycleEvidence() throws {
        let fake = Fake(), report = try Controller(backend: fake, uid: 0, effectiveUID: 0).run(.create(id, reader: "/protected/reader"))
        XCTAssertEqual(report.secretSHA256, fake.digest); XCTAssertFalse(report.lifecycleProven); XCTAssertFalse(report.readerIsolationProven)
    }
    func testQueriesUseOnlyTheFixedProbeNamespaceAndExactCanonicalUUID() {
        let query = SystemKeychain.selection(id: id)
        XCTAssertEqual(Set(query.keys), [kSecClass as String, kSecAttrService as String, kSecAttrAccount as String, kSecUseDataProtectionKeychain as String])
        XCTAssertEqual(query[kSecAttrService as String] as? String, "dev.remozio.experiment.system-keychain.v1")
        XCTAssertEqual(query[kSecAttrAccount as String] as? String, id.uuidString.lowercased())
        XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, false)
    }
    func testParserAcceptsOnlyExplicitSupportedModes() throws {
        let nonce = id.uuidString.lowercased(), digest = String(repeating: "a", count: 64)
        XCTAssertEqual(try Operation.parse(["--create", nonce, "--reader", "/protected/reader"]), .create(id, reader: "/protected/reader"))
        XCTAssertEqual(try Operation.parse(["--read", nonce, "--sha256", digest]), .read(id, digest: digest))
        XCTAssertEqual(try Operation.parse(["--delete", nonce]), .remove(id))
    }
    func testParserRejectsBroadSelectorsExtraArgumentsAndAmbiguousPaths() {
        let nonce = id.uuidString.lowercased()
        for args in [["--delete", "*"], ["--delete", nonce, "extra"], ["--create", nonce, "--reader", "relative"],
                     ["--create", nonce, "--reader", "/protected/../reader"], ["--create", nonce, "--reader", "/protected//reader"],
                     ["--read", nonce, "--sha256", "not-a-digest"], ["--read", nonce.uppercased(), "--sha256", String(repeating: "a", count: 64)]] {
            XCTAssertThrowsError(try Operation.parse(args)) { XCTAssertEqual($0 as? ProbeError, .arguments) }
        }
    }
    func testNativeFailureRecordsOnlyTheTypedStageAndNumericStatus() throws {
        let report = Report.failure(ProbeError.native(.readItem, errSecInteractionNotAllowed), requested: true, uid: 233)
        XCTAssertEqual(report.nativeStage, .readItem); XCTAssertEqual(report.status, errSecInteractionNotAllowed)
        XCTAssertEqual(report.outcome, "not-proven"); XCTAssertTrue(report.keychainOperationRequested)
        XCTAssertFalse(report.lifecycleProven); XCTAssertFalse(report.readerIsolationProven); XCTAssertNil(report.secretSHA256)
    }
    func testUnknownErrorDescriptionsCannotLeakIntoTheReport() throws {
        struct Sensitive: Error, CustomStringConvertible { var description: String { "synthetic-sensitive-fixture-description" } }
        let report = Report.failure(Sensitive(), requested: false, uid: 501)
        let bytes = try JSONEncoder().encode(report)
        XCTAssertFalse(String(decoding: bytes, as: UTF8.self).contains("synthetic-sensitive-fixture-description"))
        XCTAssertNil(report.status); XCTAssertNil(report.nativeStage); XCTAssertFalse(report.keychainOperationRequested)
    }
}
