import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayRuntimeSettingsFenceTests: XCTestCase {
    private typealias Ready = GatewayRuntimeSettingsStoreTests.Ready
    private func publication(_ r: Ready, revision: GatewayRuntimeSettingsRevision? = nil,
                             previous: GatewayRuntimeSettingsRevision? = nil) throws -> GatewayRuntimeSettingsPublicationPlan {
        try .init(revision: revision ?? r.revision(), previous: previous, activation: r.activation,
            journal: r.fixture.state(), foreground: r.fixture.runtime.plan, inventory: XCTUnwrap(r.fixture.runtime.machine.inventory()))
    }
    private func changed(_ bytes: Data, edit: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        let limits = try CBORLimits(maxBytes: 131072, maxDepth: 2, maxItems: 64)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        edit(&fields); return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testRoundTripPinsBothExactCommitsAndGatewayBytesWithoutMutationAuthority() throws {
        let r = try Ready(), plan = try publication(r), value = try GatewayRuntimeSettingsFence(plan)
        let restored = try GatewayRuntimeSettingsFence.decode(value.encoded)
        XCTAssertEqual(try restored.encoded, try value.encoded); XCTAssertEqual(try restored.revision.encoded, try plan.revision.encoded)
        XCTAssertNil(restored.previous.settingsSequence); XCTAssertEqual(restored.selected.settingsSequence, 1)
        try restored.validate(services: plan.pair.authority.material.runtime.services)
        try restored.validate(commit: restored.previous); try restored.validate(commit: restored.selected)
        let oldGateway = try GatewayServiceConfiguration.decode(XCTUnwrap(plan.artifacts.first?.previous))
        let newGateway = try GatewayServiceConfiguration.decode(XCTUnwrap(plan.artifacts.first?.selected))
        try restored.validate(gateway: oldGateway, commit: restored.previous)
        try restored.validate(gateway: newGateway, commit: restored.selected)
        XCTAssertEqual(String(describing: restored), "GatewayRuntimeSettingsFence(redacted)")
        XCTAssertEqual(String(reflecting: restored), "GatewayRuntimeSettingsFence(redacted)")
    }
    func testARevisionSuccessorBindsItsExactPredecessorWithoutAcceptingAnotherCommit() throws {
        let r = try Ready(), first = try r.revision(), second = try r.revision(2, previous: first)
        let plan = try publication(r, revision: second, previous: first), fence = try GatewayRuntimeSettingsFence(plan)
        XCTAssertEqual(fence.previous.settingsSequence, 1); XCTAssertEqual(fence.selected.settingsSequence, 2)
        try fence.validate(commit: fence.previous); try fence.validate(commit: fence.selected)
        let initial = try GatewayRuntimeCommit(r.activation.extensions)
        XCTAssertThrowsError(try fence.validate(commit: initial))
        let competing = try GatewayRuntimeSettingsFence(publication(r, revision: r.revision(3, previous: first), previous: first))
        XCTAssertThrowsError(try fence.validate(commit: competing.selected))
    }
    func testSuccessorRejectsASubstitutedDigestForValidGatewayBytesInTheSameScope() throws {
        let r = try Ready(), first = try r.revision(), second = try r.revision(2, previous: first)
        let plan = try publication(r, revision: second, previous: first), fence = try GatewayRuntimeSettingsFence(plan)
        let gateway = try GatewayServiceConfiguration.decode(XCTUnwrap(plan.artifacts.first?.previous))
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 4, maxItems: 128)
        guard case .map(var fields) = try DeterministicCBOR.decode(gateway.canonicalBytes, limits: limits) else {
            throw GatewayPreparationError.invalidRecord
        }
        fields[11] = .text("alternate-project")
        let substituted = try GatewayServiceConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: limits))
        XCTAssertEqual(substituted.registration.macID, gateway.registration.macID)
        XCTAssertEqual(substituted.registration.accountID, gateway.registration.accountID)
        let digest = Data(SHA256.hash(data: substituted.canonicalBytes))
        XCTAssertNotEqual(digest, fence.previous.gatewayConfigurationDigest)
        let crossed = try changed(fence.encoded) { $0[9] = .bytes(digest) }
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(crossed))
        try fence.validate(gateway: gateway, commit: fence.previous)
    }
    func testForeignScopeAndSubstitutedGatewayBytesCannotMatchARecognizedCommit() throws {
        let r = try Ready(), other = try Ready(), plan = try publication(r), fence = try GatewayRuntimeSettingsFence(plan)
        XCTAssertThrowsError(try fence.validate(services: other.activation.extensions.authority.material.runtime.services))
        XCTAssertThrowsError(try fence.validate(gateway: other.fixture.intent.configuration, commit: fence.previous))
        for key in [UInt64(2), 4, 5] {
            let mutated = try GatewayRuntimeSettingsFence.decode(changed(fence.encoded) { $0[key] = .bytes(Data(repeating: 91, count: key == 5 ? 32 : 16)) })
            XCTAssertThrowsError(try mutated.validate(services: plan.pair.authority.material.runtime.services))
        }
        let corrupt = try GatewayRuntimeSettingsFence.decode(changed(fence.encoded) { $0[9] = .bytes(Data(repeating: 81, count: 32)) })
        XCTAssertThrowsError(try corrupt.validate(gateway: r.fixture.intent.configuration, commit: fence.previous))
    }
    func testUnknownVersionsPurposesFieldsAndMalformedLengthsAreRejected() throws {
        let bytes = try GatewayRuntimeSettingsFence(publication(Ready())).encoded
        for version: UInt64 in [0, 2, UInt64.max] {
            XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[0] = .unsigned(version) }))
        }
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[1] = .text("other") }))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[10] = .null }))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0.removeValue(forKey: 9) }))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(Data(repeating: 0, count: 65537)))
        for key: UInt64 in [2, 3, 4, 5, 9] {
            for length in [0, 15, 17, 31, 33] {
                XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[key] = .bytes(Data(repeating: 1, count: length)) }))
            }
        }
    }
    func testCrossedRecordsAndChangesToTheForegroundOrAuthorityScopeAreRejected() throws {
        let r = try Ready(), plan = try publication(r), value = try GatewayRuntimeSettingsFence(plan), bytes = try value.encoded
        let foreign = try GatewayRuntimeSettingsFence(publication(Ready()))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[6] = .bytes(try! foreign.revision.encoded) }))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[8] = .bytes(try! value.previous.encoded) }))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[7] = .bytes(try! value.selected.encoded) }))
        for key: UInt64 in [2, 3, 4, 6] {
            let crossed = try changed(value.previous.encoded) { $0[key] = .bytes(Data(repeating: 41, count: key == 2 ? 16 : 32)) }
            XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(bytes) { $0[7] = .bytes(crossed) }))
        }
    }
    func testTheRetainedCounterCannotExceedTheDurableStoreRange() throws {
        let r = try Ready(), first = try r.revision(), second = try r.revision(2, previous: first)
        let value = try GatewayRuntimeSettingsFence(publication(r, revision: second, previous: first)), sequence = UInt64(Int64.max) + 1
        let revision = try changed(value.revision.encoded) { $0[5] = .unsigned(sequence) }
        let previous = try changed(value.previous.encoded) { $0[8] = .unsigned(sequence - 1) }
        let selected = try changed(value.selected.encoded) {
            $0[8] = .unsigned(sequence); $0[9] = .bytes(Data(SHA256.hash(data: revision)))
        }
        let encoded = try changed(value.encoded) { $0[6] = .bytes(revision); $0[7] = .bytes(previous); $0[8] = .bytes(selected) }
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(encoded))
    }
    func testASequenceJumpOrChangedPredecessorCannotBeDecodedAsTheSameFence() throws {
        let r = try Ready(), first = try r.revision(), second = try r.revision(2, previous: first)
        let value = try GatewayRuntimeSettingsFence(publication(r, revision: second, previous: first))
        let jumped = try changed(value.previous.encoded) { $0[8] = .unsigned(3) }
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(value.encoded) { $0[7] = .bytes(jumped) }))
        let replaced = try changed(value.previous.encoded) { $0[9] = .bytes(Data(repeating: 9, count: 32)) }
        XCTAssertThrowsError(try GatewayRuntimeSettingsFence.decode(changed(value.encoded) { $0[7] = .bytes(replaced) }))
    }
}
