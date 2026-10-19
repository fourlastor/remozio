import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayRuntimeSettingsRevisionTests: XCTestCase {
    private struct Ready {
        let fixture: GatewayJournalSetupExchangeTests.Fixture
        let activation: GatewayRuntimeActivationPlan
        let inventory: InstallationInventory
        init() throws {
            fixture = try .init(); try fixture.retainCompletion(.decode(fixture.initialize()))
            inventory = try XCTUnwrap(fixture.runtime.machine.inventory())
            activation = try .init(journal: fixture.state(), foreground: fixture.runtime.plan, inventory: inventory)
            try fixture.runtime.machine.retainGatewayRuntimeActivation(activation)
        }
        func selection(poll: UInt64 = 2000) throws -> GatewayRuntimeSettingsSelection {
            let old = fixture.intent.configuration.settings
            let service = try GatewayServiceSettings(delivery: old.delivery, probe: old.probe, wake: old.wake,
                maximumOperations: old.maximumOperations == 64 ? 63 : old.maximumOperations + 1,
                handshakeTimeoutMillis: old.handshakeTimeoutMillis, authorityLeaseMillis: old.authorityLeaseMillis,
                providerTimeoutSeconds: old.providerTimeoutSeconds, schedulerRetryMillis: old.schedulerRetryMillis,
                maximumStoredControls: old.maximumStoredControls, maximumPendingPerEnrollment: old.maximumPendingPerEnrollment,
                maximumCandidateLifetimeMillis: old.maximumCandidateLifetimeMillis, databaseBusyMillis: old.databaseBusyMillis)
            return try .init(service: service, activation: .init(wakePollMilliseconds: poll, wakeTimeoutMilliseconds: 6000),
                maximumWakeConnections: 6, maximumWakeOperations: 9, wakeChallengeLifetimeMilliseconds: 7000)
        }
        func revision(_ number: UInt8 = 3, previous: GatewayRuntimeSettingsRevision? = nil,
                      poll: UInt64 = 2000) throws -> GatewayRuntimeSettingsRevision {
            try .init(id: Data(repeating: number, count: 16), selection: selection(poll: poll), activation: activation,
                previous: previous, journal: fixture.state(), foreground: fixture.runtime.plan, inventory: inventory)
        }
    }
    private func changed(_ bytes: Data, _ edit: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 64)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        edit(&fields); return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testChangedSettingsPreserveTheJournalAndAllServiceAndPhoneIdentities() throws {
        let r = try Ready(), f = r.fixture, before = try f.state(), foreground = try f.runtime.plan.encoded
        let retained = try f.runtime.machine.gatewayRuntimeActivation(accountID: f.intent.accountID).plan?.encoded
        let revision = try r.revision(), restored = try GatewayRuntimeSettingsRevision.decode(revision.encoded)
        let proposal = try restored.proposal(activation: r.activation, journal: f.state(), foreground: f.runtime.plan, inventory: r.inventory)
        XCTAssertEqual(try restored.encoded, try revision.encoded); XCTAssertEqual(try restored.digest, try revision.digest)
        XCTAssertEqual(proposal.gateway.registration, f.intent.configuration.registration)
        XCTAssertEqual(proposal.gateway.receiptPublicKey, f.intent.configuration.receiptPublicKey)
        XCTAssertEqual(proposal.gateway.providerPath, f.intent.configuration.providerPath)
        XCTAssertEqual(proposal.transport.wake?.wake.credentialID, r.activation.extensions.transport.wake?.wake.credentialID)
        XCTAssertEqual(proposal.transport.wake?.wake.publicKey, r.activation.extensions.transport.wake?.wake.publicKey)
        XCTAssertEqual(try proposal.gatewayJob.bytes, try r.activation.gatewayJob.bytes)
        XCTAssertEqual(try f.state(), before); XCTAssertEqual(try f.runtime.plan.encoded, foreground)
        XCTAssertEqual(try f.runtime.machine.inventory(), r.inventory)
        XCTAssertEqual(try f.runtime.machine.gatewayRuntimeActivation(accountID: f.intent.accountID).plan?.encoded, retained)
        XCTAssertNotEqual(proposal.gateway.canonicalBytes, f.intent.configuration.canonicalBytes)
        XCTAssertEqual(proposal.transport.wake?.pollMilliseconds, 2000)
        XCTAssertEqual(proposal.gateway.wakeEndpoint?.maximumConnections, 6)
        XCTAssertEqual(proposal.gateway.wakeEndpoint?.maximumOperations, 9)
        XCTAssertEqual(proposal.gateway.wakeEndpoint?.challengeLifetimeMillis, 7000)
        XCTAssertEqual(String(reflecting: revision), "GatewayRuntimeSettingsRevision(redacted)")
    }
    func testSuccessorsRequireTheExactCurrentRevisionAndCannotReplayAnEarlierRevision() throws {
        let r = try Ready(), first = try r.revision(), second = try r.revision(4, previous: first, poll: 3000)
        try first.validateSuccessor(of: nil, activation: r.activation)
        try second.validateSuccessor(of: first, activation: r.activation)
        XCTAssertEqual(first.sequence, 1); XCTAssertEqual(second.sequence, 2)
        XCTAssertEqual(second.previousDigest, try first.digest)
        XCTAssertThrowsError(try first.validateSuccessor(of: second, activation: r.activation))
        XCTAssertThrowsError(try second.validateSuccessor(of: nil, activation: r.activation))
        let competing = try r.revision(5, poll: 4000)
        XCTAssertThrowsError(try second.validateSuccessor(of: competing, activation: r.activation))
        XCTAssertThrowsError(try r.revision(3, previous: first))
    }
    func testSequenceOverflowAndMalformedRevisionIdentityRefuse() throws {
        let r = try Ready(), first = try r.revision()
        let last = try GatewayRuntimeSettingsRevision.decode(changed(first.encoded) { $0[5] = .unsigned(UInt64.max) })
        XCTAssertThrowsError(try r.revision(4, previous: last))
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[2] = .bytes(Data()) }, { $0[3] = .bytes(Data(repeating: 1, count: 15)) },
            { $0[5] = .unsigned(0) }, { $0[6] = .bytes(Data(repeating: 1, count: 31)) }
        ] { XCTAssertThrowsError(try GatewayRuntimeSettingsRevision.decode(changed(first.encoded, edit))) }
    }
    func testForeignScopeAndChangedOperationalDigestsCannotProduceAProposal() throws {
        let r = try Ready(), other = try Ready(), revision = try r.revision()
        XCTAssertThrowsError(try revision.proposal(activation: other.activation, journal: other.fixture.state(), foreground: other.fixture.runtime.plan, inventory: other.inventory))
        XCTAssertThrowsError(try revision.proposal(activation: r.activation, journal: other.fixture.state(), foreground: r.fixture.runtime.plan, inventory: r.inventory))
        for key: UInt64 in [4, 8, 9] {
            let forged = try GatewayRuntimeSettingsRevision.decode(changed(revision.encoded) { $0[key] = .bytes(Data(repeating: 0, count: 32)) })
            XCTAssertThrowsError(try forged.proposal(activation: r.activation, journal: r.fixture.state(), foreground: r.fixture.runtime.plan, inventory: r.inventory))
        }
        let wrongParent = try GatewayRuntimeSettingsRevision.decode(changed(revision.encoded) { $0[6] = .bytes(Data(repeating: 0, count: 32)) })
        XCTAssertThrowsError(try wrongParent.validateSuccessor(of: nil, activation: r.activation))
    }
    func testUnknownWireVersionsPurposesFieldsAndOversizeInputsRefuse() throws {
        let r = try Ready(), revision = try r.revision(), bytes = try revision.encoded
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("foreign") }, { $0[10] = .null }, { $0[7] = .bytes(Data()) }
        ] { XCTAssertThrowsError(try GatewayRuntimeSettingsRevision.decode(changed(bytes, edit))) }
        XCTAssertThrowsError(try GatewayRuntimeSettingsRevision.decode(Data(repeating: 0, count: 32769)))
        let selected = try r.selection(), selectionBytes = try selected.bytes
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("foreign") }, { $0[7] = .null },
            { $0[4] = .unsigned(65) }, { $0[5] = .unsigned(0) }, { $0[6] = .unsigned(60001) }
        ] { XCTAssertThrowsError(try GatewayRuntimeSettingsSelection.decode(changed(selectionBytes, edit))) }
        XCTAssertEqual(try GatewayRuntimeSettingsSelection.decode(selectionBytes).bytes, selectionBytes)
    }
    func testASettingsProposalCannotInitializeTheJournalOrReplaceTheOriginalActivation() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(), r = try Ready()
        XCTAssertThrowsError(try GatewayRuntimeSettingsRevision(id: Data(repeating: 1, count: 16), selection: r.selection(), activation: r.activation,
            journal: f.state(), foreground: f.runtime.plan, inventory: XCTUnwrap(f.runtime.machine.inventory())))
        let old = try GatewayRuntimeActivationPlan.decode(r.activation.encoded)
        XCTAssertEqual(try old.encoded, try r.activation.encoded)
        XCTAssertNotEqual(try r.revision().encoded, try old.encoded)
    }
}
