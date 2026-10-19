import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayRuntimeActivationPlanTests: XCTestCase {
    private func ready() throws -> GatewayJournalSetupExchangeTests.Fixture {
        let f = try GatewayJournalSetupExchangeTests.Fixture()
        try f.retainCompletion(.decode(f.initialize())); return f
    }
    private func plan(_ f: GatewayJournalSetupExchangeTests.Fixture, poll: UInt64 = 1000, timeout: UInt64 = 5000) throws -> GatewayRuntimeActivationPlan {
        try .init(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()),
            wakePollMilliseconds: poll, wakeTimeoutMilliseconds: timeout)
    }
    private func changed(_ bytes: Data, _ edit: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        let limits = try CBORLimits(maxBytes: 524288, maxDepth: 2, maxItems: 64)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        edit(&fields); return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testCompletedJournalBindsTheFixedGatewayJobWithoutChangingForegroundState() throws {
        let f = try ready(), inventory = try XCTUnwrap(f.runtime.machine.inventory()), before = try f.runtime.plan.encoded
        let journal = try f.state(), value = try plan(f), proposal = try value.proposal(journal: journal, foreground: f.runtime.plan, inventory: inventory)
        XCTAssertEqual(value.accountID, f.intent.accountID); XCTAssertEqual(value.journalIntentID, f.intent.id)
        XCTAssertEqual(value.journalIntentDigest, try f.intent.digest)
        XCTAssertEqual(try value.gatewayJob.bytes, proposal.gatewayJob.bytes)
        XCTAssertEqual(try value.gatewayJob.declaration.executionUID, f.intent.configuration.serviceUID)
        XCTAssertEqual(try value.gatewayJob.arguments, [value.bundlePath + "/Contents/Library/LaunchServices/RemozioGateway", "--configuration", f.intent.configuration.providerPath.replacingOccurrences(of: "gateway-provider.json", with: "gateway-host.cbor")])
        XCTAssertEqual(try f.runtime.machine.inventory(), inventory)
        XCTAssertEqual(try f.runtime.machine.runtimeActivation(accountID: f.intent.accountID).plan?.encoded, before)
        XCTAssertEqual(try f.state(), journal)
        XCTAssertNil(try value.encoded.range(of: f.runtime.material.transportIdentity))
        XCTAssertEqual(String(reflecting: value), "GatewayRuntimeActivationPlan(redacted)")
    }
    func testPendingJournalCannotCreateAnActivationPlan() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture()
        XCTAssertThrowsError(try plan(f)) { XCTAssertEqual($0 as? GatewayPreparationError, .incomplete) }
    }
    func testRoundTripRetainsSelectedTimingAndAllConfigurationBindings() throws {
        let f = try ready(), value = try plan(f, poll: 2000, timeout: 6000), bytes = try value.encoded
        let restored = try GatewayRuntimeActivationPlan.decode(bytes)
        XCTAssertEqual(try restored.encoded, bytes); XCTAssertEqual(try restored.digest, Data(SHA256.hash(data: bytes)))
        XCTAssertEqual(restored.extensions.transport.wake?.pollMilliseconds, 2000)
        XCTAssertEqual(restored.extensions.transport.wake?.wake.timeoutMilliseconds, 6000)
        _ = try restored.proposal(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()))
        let original = try plan(f)
        XCTAssertNotEqual(try original.digest, try value.digest)
        XCTAssertEqual(original.extensions.authority.material, value.extensions.authority.material)
        XCTAssertEqual(try original.gatewayJob.bytes, try value.gatewayJob.bytes)
    }
    func testAPlanCannotBindAnotherAccountOrAnotherBundlePlacement() throws {
        let first = try ready(), second = try ready(), value = try plan(first)
        XCTAssertThrowsError(try value.proposal(journal: second.state(), foreground: second.runtime.plan, inventory: XCTUnwrap(second.runtime.machine.inventory())))
        let relocated = try GatewayRuntimeActivationPlan.decode(changed(value.encoded) { $0[3] = .text("/Library/Other.app") })
        XCTAssertNotEqual(try relocated.digest, try value.digest)
        XCTAssertThrowsError(try relocated.proposal(journal: first.state(), foreground: first.runtime.plan, inventory: XCTUnwrap(first.runtime.machine.inventory())))
    }
    func testUnknownVersionsPurposesFieldsAndUnsafeJobPathsAreRejected() throws {
        let f = try ready(), value = try plan(f), bytes = try value.encoded
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("foreign") }, { $0[4] = .null },
            { $0[2] = .bytes(Data()) }, { $0[3] = .text("relative.app") }, { $0[3] = .text("/Library/../Other.app") }
        ] { XCTAssertThrowsError(try GatewayRuntimeActivationPlan.decode(changed(bytes, edit))) }
        XCTAssertThrowsError(try GatewayRuntimeActivationPlan.decode(Data(repeating: 0, count: GatewayRuntimeActivationPlan.maximumBytes + 1)))
    }
}
