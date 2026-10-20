import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SharedSetupImportRelayPlanValueTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 2048, maxDepth: 1, maxItems: 32)
    func testCanonicalPlanUsesLocalOperationNamesAndExcludesProviderCredentials() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent()
        let plan = try SharedSetupImportRelayPlan(expected: intent, port: 51001)
        let suffix = intent.operationID.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(plan.hostname, "m-" + suffix + ".remozio.example.invalid")
        XCTAssertEqual(plan.tunnelName, "remozio-" + suffix)
        XCTAssertEqual(plan.accessApplicationName, plan.tunnelName + "-approval")
        XCTAssertEqual(try SharedSetupImportRelayPlan.decode(plan.bytes, expected: intent), plan)
        XCTAssertNil(plan.bytes.range(of: Data("synthetic-provider-token-only".utf8)))
        XCTAssertEqual(plan.description, "SharedSetupImportRelayPlan(redacted)")
        XCTAssertEqual(plan.debugDescription, plan.description)
    }
    func testPhaseChangesKeepTheSameLocalPlan() throws {
        let f = try SharedSetupImportFixture(); var current = try f.intent()
        let plan = try SharedSetupImportRelayPlan(expected: current, port: 51001)
        for phase in [SharedSetupImportIntent.Phase.runtimePublished, .gatewayPrepared, .relayPrepared, .rootComplete] {
            current = try current.advanced(to: phase)
            XCTAssertEqual(try SharedSetupImportRelayPlan.decode(plan.bytes, expected: current), plan)
        }
    }
    func testDifferentOperationAccountOrCredentialDigestCannotAdoptThePlan() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent(), proposal = try f.proposal()
        let plan = try SharedSetupImportRelayPlan(expected: intent, port: 51001)
        XCTAssertThrowsError(try plan.validate(expected: f.intent()))
        XCTAssertThrowsError(try plan.validate(expected: f.another(intent, account: 0x72)))
        let changed = try PortableSetup(defaults: proposal.defaults,
            cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                dnsSuffix: "remozio.example.invalid", apiToken: "different-synthetic-token"), appPreferences: proposal.appPreferences)
        let other = try SharedSetupImportIntent(scope: f.scope, proposal: changed, operationID: intent.operationID)
        XCTAssertThrowsError(try SharedSetupImportRelayPlan.decode(plan.bytes, expected: other))
    }
    func testUnknownFieldsVersionsPurposesPortsAndTrailingDataAreRejected() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent()
        let plan = try SharedSetupImportRelayPlan(expected: intent, port: 51001)
        guard case .map(let fields) = try DeterministicCBOR.decode(plan.bytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [
            (0, .unsigned(2)), (1, .text("another-purpose")), (10, .unsigned(1023)),
            (10, .unsigned(65536)), (14, .text("foreign-tunnel")),
        ] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try SharedSetupImportRelayPlan.decode(DeterministicCBOR.encode(.map(changed), limits: limits), expected: intent))
        }
        var missing = fields; missing.removeValue(forKey: 9)
        XCTAssertThrowsError(try SharedSetupImportRelayPlan.decode(DeterministicCBOR.encode(.map(missing), limits: limits), expected: intent))
        XCTAssertThrowsError(try SharedSetupImportRelayPlan.decode(plan.bytes + Data([0]), expected: intent))
        XCTAssertThrowsError(try SharedSetupImportRelayPlan.decode(Data(repeating: 0, count: 2049), expected: intent))
    }
    func testProviderFreeImportsCannotInventRelayResources() throws {
        let f = try SharedSetupImportFixture(), proposal = try f.proposal()
        let plain = PortableSetup(defaults: proposal.defaults, appPreferences: proposal.appPreferences)
        let intent = try SharedSetupImportIntent(scope: f.scope, proposal: plain)
        XCTAssertThrowsError(try SharedSetupImportRelayPlan(expected: intent, port: 51001))
    }
    func testDerivedHostnameMustFitTheDnsLimitBeforeAnyResourceIsCreated() throws {
        let f = try SharedSetupImportFixture(), proposal = try f.proposal()
        let suffix = [String(repeating: "a", count: 63), String(repeating: "b", count: 63),
            String(repeating: "c", count: 63), String(repeating: "d", count: 40)].joined(separator: ".")
        let selected = try PortableSetup(defaults: proposal.defaults,
            cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                dnsSuffix: suffix, apiToken: "synthetic-token"))
        let intent = try SharedSetupImportIntent(scope: f.scope, proposal: selected)
        XCTAssertThrowsError(try SharedSetupImportRelayPlan(expected: intent, port: 51001))
    }
}
