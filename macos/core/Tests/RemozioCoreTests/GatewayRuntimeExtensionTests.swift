import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayRuntimeExtensionTests: XCTestCase {
    private func ready() throws -> GatewayJournalSetupExchangeTests.Fixture {
        let f = try GatewayJournalSetupExchangeTests.Fixture()
        try f.retainCompletion(.decode(f.initialize())); return f
    }
    private func plan(_ f: GatewayJournalSetupExchangeTests.Fixture, poll: UInt64 = 1000, timeout: UInt64 = 5000) throws -> GatewayRuntimeExtensions {
        try .init(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()),
            wakePollMilliseconds: poll, wakeTimeoutMilliseconds: timeout)
    }
    private let limits = try! CBORLimits(maxBytes: 524288, maxDepth: 4, maxItems: 128)
    private func changed(_ bytes: Data, _ edit: (inout [UInt64: CBORValue]) throws -> Void) throws -> Data {
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        try edit(&fields); return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testRequiresCompletedInitializationAndBindsBothRolesToTheOriginalRuntime() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture()
        XCTAssertThrowsError(try plan(f)) { XCTAssertEqual($0 as? GatewayPreparationError, .incomplete) }
        try f.retainCompletion(.decode(f.initialize()))
        let value = try plan(f)
        try value.validate(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory()))
        try value.authority.validate(authority: f.runtime.plan.host)
        try value.transport.validate(transport: f.runtime.plan.transport)
        XCTAssertNil(value.authority.wake); XCTAssertNotNil(value.transport.wake)
        XCTAssertEqual(value.authority.setupCode, f.runtime.plan.host.codePolicy.entries.first { $0.role == .setupController })
        XCTAssertEqual(value.authority.intentDigest, try f.intent.digest)
        XCTAssertNil(try value.encoded.range(of: f.runtime.material.transportIdentity))
        XCTAssertEqual(String(reflecting: value.authority), "GatewayRuntimeExtension(redacted)")
    }
    func testRecordsAndPairRoundTripAndRejectCrossRoleUse() throws {
        let f = try ready(), value = try plan(f), bytes = try value.encoded
        XCTAssertEqual(try GatewayRuntimeExtensions.decode(bytes).encoded, bytes)
        XCTAssertEqual(try GatewayRuntimeExtension.decode(value.authority.encoded).encoded, try value.authority.encoded)
        XCTAssertEqual(try GatewayRuntimeExtension.decode(value.transport.encoded).encoded, try value.transport.encoded)
        XCTAssertThrowsError(try value.authority.validate(transport: f.runtime.plan.transport))
        XCTAssertThrowsError(try value.transport.validate(authority: f.runtime.plan.host))
        XCTAssertThrowsError(try GatewayRuntimeExtensions.decode(changed(bytes) { let authority = $0[2]; $0[2] = $0[3]; $0[3] = authority }))
    }
    func testForeignStartupFilesOrMixedPairsCannotValidate() throws {
        let first = try ready(), second = try ready(), value = try plan(first), other = try plan(second)
        XCTAssertThrowsError(try value.authority.validate(authority: second.runtime.plan.host))
        XCTAssertThrowsError(try value.transport.validate(transport: second.runtime.plan.transport))
        XCTAssertThrowsError(try value.validate(journal: second.state(), foreground: second.runtime.plan, inventory: XCTUnwrap(second.runtime.machine.inventory())))
        let transport = try other.transport.encoded
        XCTAssertThrowsError(try GatewayRuntimeExtensions.decode(changed(value.encoded) { $0[3] = .bytes(transport) }))
    }
    func testPairDigestBindsTransportTimingWithoutReplacingMaterial() throws {
        let f = try ready(), first = try plan(f), second = try plan(f, poll: 2000, timeout: 6000)
        XCTAssertNotEqual(try first.digest, try second.digest)
        XCTAssertEqual(try first.authority.encoded, try second.authority.encoded)
        XCTAssertEqual(first.transport.material, second.transport.material)
        XCTAssertEqual(first.transport.wake?.transport.identityPublicKeyInfo, f.runtime.plan.transport.transport.identityPublicKeyInfo)
        XCTAssertEqual(second.transport.wake?.pollMilliseconds, 2000)
        XCTAssertThrowsError(try plan(f, poll: 0)); XCTAssertThrowsError(try plan(f, timeout: 0))
    }
    func testUnknownVersionsPurposesFieldsRolesAndOversizedRecordsAreRejected() throws {
        let f = try ready(), value = try plan(f), bytes = try value.authority.encoded
        for edit: (inout [UInt64: CBORValue]) throws -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("foreign") }, { $0[2] = .unsigned(99) }, { $0[10] = .null },
            { $0[3] = .bytes(Data([1])) }, { $0[4] = .bytes(Data([1])) }, { $0[5] = .bytes(Data([1])) },
            { $0[6] = .bytes(Data([1])) }, { $0[9] = .bytes(Data()) }
        ] { XCTAssertThrowsError(try GatewayRuntimeExtension.decode(changed(bytes, edit))) }
        XCTAssertThrowsError(try GatewayRuntimeExtension.decode(Data(repeating: 0, count: ProtectedServiceConfiguration.maximumBytes + 1)))
        XCTAssertThrowsError(try GatewayRuntimeExtensions.decode(changed(value.encoded) { $0[0] = .unsigned(2) }))
        XCTAssertThrowsError(try GatewayRuntimeExtensions.decode(Data(repeating: 0, count: 262145)))
    }
    func testInactiveSetupCodeAndAlteredScopeCannotBecomeAValidExtension() throws {
        let f = try ready(), value = try plan(f), policy = value.authority.codePolicy
        let inactive = try AuthorityCodePolicy(entries: policy.entries.map { entry in
            try AuthorityCodeEntry(role: entry.role, teamID: entry.teamID, identifier: entry.identifier, installedGeneration: entry.installedGeneration,
                minimumGeneration: entry.minimumGeneration, codeDirectoryHash: entry.codeDirectoryHash,
                active: entry.role == .setupController ? false : entry.active)
        })
        let encoded = try inactive.bytes
        XCTAssertThrowsError(try GatewayRuntimeExtension.decode(changed(value.authority.encoded) { $0[8] = .bytes(encoded) }))
        let authority = try changed(value.authority.encoded) { $0[5] = .bytes(Data(repeating: 0, count: 32)) }
        let transport = try changed(value.transport.encoded) { $0[5] = .bytes(Data(repeating: 0, count: 32)) }
        let mixed = try GatewayRuntimeExtensions.decode(changed(value.encoded) { $0[2] = .bytes(authority); $0[3] = .bytes(transport) })
        XCTAssertThrowsError(try mixed.validate(journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory())))
    }
}
