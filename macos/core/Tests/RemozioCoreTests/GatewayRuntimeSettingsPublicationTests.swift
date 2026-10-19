import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayRuntimeSettingsPublicationTests: XCTestCase {
    private struct Ready {
        let f: GatewayJournalSetupExchangeTests.Fixture
        let activation: GatewayRuntimeActivationPlan
        let inventory: InstallationInventory
        init() throws {
            f = try .init(); try f.retainCompletion(.decode(f.initialize()))
            inventory = try XCTUnwrap(f.runtime.machine.inventory())
            activation = try .init(journal: f.state(), foreground: f.runtime.plan, inventory: inventory)
        }
        func revision(_ number: UInt8 = 3, previous: GatewayRuntimeSettingsRevision? = nil,
                      poll: UInt64 = 2000, serviceOnly: Bool = false) throws -> GatewayRuntimeSettingsRevision {
            let old = f.intent.configuration.settings
            let service = try GatewayServiceSettings(delivery: old.delivery, probe: old.probe, wake: old.wake,
                maximumOperations: old.maximumOperations == 64 ? 63 : old.maximumOperations + 1,
                authorityLeaseMillis: old.authorityLeaseMillis, maximumStoredControls: old.maximumStoredControls,
                maximumCandidateLifetimeMillis: old.maximumCandidateLifetimeMillis)
            return try .init(id: Data(repeating: number, count: 16), selection: .init(service: service,
                activation: .init(wakePollMilliseconds: serviceOnly ? 1000 : poll, wakeTimeoutMilliseconds: serviceOnly ? 5000 : 6000)),
                activation: activation, previous: previous, journal: f.state(), foreground: f.runtime.plan, inventory: inventory)
        }
        func plan(_ revision: GatewayRuntimeSettingsRevision, previous: GatewayRuntimeSettingsRevision? = nil) throws -> GatewayRuntimeSettingsPublicationPlan {
            try .init(revision: revision, previous: previous, activation: activation, journal: f.state(), foreground: f.runtime.plan, inventory: inventory)
        }
    }
    private func load(_ plan: GatewayRuntimeSettingsPublicationPlan, _ r: Ready,
                      target: GatewayRuntimeExtension.Target, change: (AdministrativeSetupPublication.File, Data) throws -> Data = { _, bytes in bytes }) throws -> GatewayRuntimeLoader.Loaded? {
        try GatewayRuntimeLoader.load(target: target, read: { file in
            let bytes = try XCTUnwrap(plan.artifacts.first { $0.file.name == file.name }?.selected)
            return try change(file, bytes)
        }, verifyCurrent: {}, validate: { role in
            if target == .authority { try role.validate(authority: r.f.runtime.plan.host) }
            else { try role.validate(transport: r.f.runtime.plan.transport) }
        })
    }
    private func changed(_ bytes: Data, _ edit: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 64)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        edit(&fields); return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testLegacyCommitBytesAndObservationKeyRemainUnchanged() throws {
        let r = try Ready(), pair = r.activation.extensions, commit = try GatewayRuntimeCommit(pair)
        let legacy = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-runtime-commit"),
            2: .bytes(pair.authority.intentID), 3: .bytes(pair.authority.intentDigest), 4: .bytes(pair.authority.foregroundDigest),
            5: .bytes(pair.digest), 6: .bytes(Data(SHA256.hash(data: pair.authority.encoded))),
            7: .bytes(Data(SHA256.hash(data: pair.transport.encoded)))]), limits: .init(maxBytes: 1024, maxDepth: 1, maxItems: 17))
        XCTAssertEqual(try commit.encoded, legacy); XCTAssertNil(try GatewayRuntimeCommit.decode(legacy).settingsSequence)
        XCTAssertEqual(try commit.observationDigest, try pair.digest)
    }
    func testRevisionPlanListsExactPredecessorBytesAndCommitsLast() throws {
        let r = try Ready(), first = try r.revision(), plan = try r.plan(first)
        XCTAssertEqual(plan.artifacts.map { $0.file.name }, ["gateway-host.cbor", "authority-gateway-runtime.cbor", "transport-gateway-runtime.cbor", "gateway-settings-revision.cbor", "gateway-runtime-commit.cbor"])
        XCTAssertNil(plan.artifacts[3].previous)
        XCTAssertEqual(plan.artifacts[1].previous, plan.artifacts[1].selected)
        let second = try r.revision(4, previous: first, poll: 3000), successor = try r.plan(second, previous: first)
        XCTAssertEqual(successor.artifacts.map(\.previous), plan.artifacts.map { Optional($0.selected) })
        XCTAssertThrowsError(try r.plan(second)); XCTAssertThrowsError(try r.plan(first, previous: second))
        XCTAssertEqual(try r.f.state().intent, r.f.intent)
    }
    func testBothRuntimeRolesVerifyTheVersionTwoCommitAndSelectedSettings() throws {
        let r = try Ready(), revision = try r.revision(), plan = try r.plan(revision)
        XCTAssertEqual(plan.commit.settingsSequence, 1)
        XCTAssertEqual(try GatewayRuntimeCommit.decode(plan.commit.encoded).encoded, try plan.commit.encoded)
        try plan.commit.validate(plan.pair)
        for role in [GatewayRuntimeExtension.Target.authority, .transport] {
            let loaded = try XCTUnwrap(load(plan, r, target: role))
            XCTAssertEqual(try loaded.commit.observationDigest, try plan.commit.observationDigest)
        }
    }
    func testAServiceOnlyChangeStillChangesTheObservationKey() throws {
        let r = try Ready(), revision = try r.revision(serviceOnly: true), plan = try r.plan(revision)
        XCTAssertEqual(try plan.pair.encoded, try r.activation.extensions.encoded)
        XCTAssertEqual(plan.commit.pairDigest, try r.activation.extensions.digest)
        XCTAssertNotEqual(try plan.commit.observationDigest, try GatewayRuntimeCommit(r.activation.extensions).observationDigest)
    }
    func testMissingOrMismatchedRevisionAndConfigurationRefuseForBothRoles() throws {
        let r = try Ready(), plan = try r.plan(r.revision())
        for role in [GatewayRuntimeExtension.Target.authority, .transport] {
            for file in [AdministrativeSetupPublication.File.gatewaySettingsRevision, .gatewayConfiguration] {
                XCTAssertThrowsError(try load(plan, r, target: role, change: { current, bytes in
                    if current.name == file.name { throw JournalLeaseError.system(2) }; return bytes
                }))
                XCTAssertThrowsError(try load(plan, r, target: role, change: { current, bytes in
                    current.name == file.name ? Data("changed".utf8) : bytes
                }))
            }
            XCTAssertThrowsError(try load(plan, r, target: role, change: { current, bytes in
                if case .gatewaySettingsRevision = current { return try changed(bytes) { $0[5] = .unsigned(2) } }; return bytes
            }))
        }
    }
    func testUnknownCommitVersionsExtraFieldsAndMalformedRevisionBindingsRefuse() throws {
        let r = try Ready(), plan = try r.plan(r.revision()), bytes = try plan.commit.encoded
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(3) }, { $0[0] = .unsigned(1) }, { $0[12] = .null },
            { $0[8] = .unsigned(0) }, { $0[9] = .bytes(Data()) }, { $0[10] = .bytes(Data(repeating: 0, count: 31)) }, { $0[11] = .null }
        ] { XCTAssertThrowsError(try GatewayRuntimeCommit.decode(changed(bytes, edit))) }
    }
}
