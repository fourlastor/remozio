import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewaySettingsConsumerMessageTests: XCTestCase {
    private typealias Binding = GatewaySettingsConsumerBinding
    private typealias Request = GatewaySettingsConsumerRequest
    private typealias Response = GatewaySettingsConsumerResponse
    private func fence(_ r: GatewayRuntimeSettingsStoreTests.Ready, number: UInt8 = 1) throws -> GatewayRuntimeSettingsFence {
        try .init(.init(revision: r.revision(number), previous: nil, activation: r.activation,
            journal: r.fixture.state(), foreground: r.fixture.runtime.plan, inventory: XCTUnwrap(r.fixture.runtime.machine.inventory())))
    }
    private func binding(_ value: GatewayRuntimeSettingsFence, role: GatewaySettingsConsumerRole = .gateway) throws -> Binding {
        try .init(role: role, macID: value.macID, accountID: value.accountID)
    }
    private func changed(_ bytes: Data, edit: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        let limits = try CBORLimits(maxBytes: 131072, maxDepth: 2, maxItems: 64)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        edit(&fields); return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testEachCompanionRoleRoundTripsAllActionsWithoutGrantingAuthority() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), value = try fence(r)
        for role in GatewaySettingsConsumerRole.allCases {
            let scope = try binding(value, role: role)
            XCTAssertEqual(try Binding.decode(scope.encoded), scope)
            for action in [GatewaySettingsControlAction.observe, .quiesce, .accept] {
                let request = try Request(binding: scope, fence: value, action: action, challenge: Data(repeating: 7, count: 32))
                let restored = try Request.decode(request.encoded); try restored.validate(binding: scope, fence: value)
                XCTAssertEqual(try restored.encoded, try request.encoded)
            }
        }
    }
    func testRestartRoleAndAccountChangesInvalidateThePreviousGenerationRequest() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), value = try fence(r), current = try binding(value)
        let request = try Request(binding: current, fence: value, action: .observe, challenge: Data(repeating: 1, count: 32))
        let restarted = try binding(value); XCTAssertNotEqual(restarted.generation, current.generation)
        let variants = [restarted,
            try Binding(role: .transport, macID: current.macID, accountID: current.accountID, generation: current.generation),
            try Binding(role: .gateway, macID: Data(repeating: 0, count: 16), accountID: current.accountID, generation: current.generation),
            try Binding(role: .gateway, macID: current.macID, accountID: Data(repeating: 0, count: 16), generation: current.generation)]
        for scope in variants { XCTAssertThrowsError(try request.validate(binding: scope, fence: value)) }
        XCTAssertThrowsError(try request.validate(binding: current, fence: fence(r, number: 2)))
    }
    func testTheWholeFenceDigestAlsoBindsThePreviousGatewayConfiguration() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), value = try fence(r), scope = try binding(value)
        let request = try Request(binding: scope, fence: value, action: .quiesce, challenge: Data(repeating: 1, count: 32))
        let replacement = try GatewayRuntimeSettingsFence.decode(changed(value.encoded) { $0[9] = .bytes(Data(repeating: 83, count: 32)) })
        XCTAssertEqual(try replacement.revision.digest, try value.revision.digest)
        XCTAssertThrowsError(try request.validate(binding: scope, fence: replacement))
    }
    func testReceiptsCannotCrossAnActionChallengeRoleOrGeneration() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), value = try fence(r), scope = try binding(value)
        let request = try Request(binding: scope, fence: value, action: .observe, challenge: Data(repeating: 1, count: 32))
        let bytes = try Response(request: request, observation: .unknown).encoded
        let variants = [try Request(binding: scope, fence: value, action: .accept, challenge: request.challenge),
            try Request(binding: scope, fence: value, action: .observe, challenge: Data(repeating: 2, count: 32)),
            try Request(binding: .init(role: .transport, macID: scope.macID, accountID: scope.accountID, generation: scope.generation),
                fence: value, action: .observe, challenge: request.challenge),
            try Request(binding: binding(value), fence: value, action: .observe, challenge: request.challenge)]
        for expected in variants { XCTAssertThrowsError(try Response.decode(bytes, expected: expected)) }
        XCTAssertEqual(try Response.decode(bytes, expected: request).encoded, bytes)
    }
    func testOnlySettledQuiescenceAndExplicitAcceptanceCanAcknowledgeTheirActions() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), value = try fence(r), scope = try binding(value)
        for action in [GatewaySettingsControlAction.observe, .quiesce, .accept] {
            let request = try Request(binding: scope, fence: value, action: action, challenge: Data(repeating: 1, count: 32))
            for observation in GatewaySettingsConsumerObservation.allCases {
                let permitted = action == .observe || (action == .quiesce && observation == .paused) ||
                    (action == .accept && (observation == .accepted || observation == .runtimeStarted))
                if permitted {
                    let reply = try Response(request: request, observation: observation)
                    XCTAssertEqual(try Response.decode(reply.encoded, expected: request).observation, observation)
                } else { XCTAssertThrowsError(try Response(request: request, observation: observation)) }
            }
        }
    }
    func testUnknownFormatsFieldsRolesActionsAndMalformedDigestsAreRejected() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), value = try fence(r), scope = try binding(value)
        let request = try Request(binding: scope, fence: value, action: .observe, challenge: Data(repeating: 1, count: 32))
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("other") }, { $0[9] = .null }, { $0.removeValue(forKey: 3) },
            { $0[7] = .unsigned(0) }, { $0[8] = .bytes(Data()) }, { $0[3] = .bytes(Data(repeating: 1, count: 31)) },
            { $0[4] = .bytes(Data()) }, { $0[5] = .bytes(Data()) }, { $0[6] = $0[5] }
        ] { XCTAssertThrowsError(try Request.decode(changed(request.encoded, edit: edit))) }
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(0) }, { $0[1] = .text("other") }, { $0[2] = .unsigned(0) }, { $0[2] = .unsigned(3) },
            { $0[6] = .null }, { $0[3] = .bytes(Data()) }, { $0[4] = .bytes(Data()) }, { $0[5] = .bytes(Data()) }
        ] { XCTAssertThrowsError(try Binding.decode(changed(scope.encoded, edit: edit))) }
        let reply = try Response(request: request, observation: .unknown)
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("other") }, { $0[4] = .null }, { $0[3] = .unsigned(5) }
        ] { XCTAssertThrowsError(try Response.decode(changed(reply.encoded, edit: edit), expected: request)) }
    }
    func testBoundedPayloadsAndChallengeSizesCannotBeExpandedByTheCaller() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), value = try fence(r), scope = try binding(value)
        let request = try Request(binding: scope, fence: value, action: .observe, challenge: Data(repeating: 1, count: 32))
        for size in [0, 31, 33] { XCTAssertThrowsError(try Request(binding: scope, fence: value, action: .observe, challenge: Data(repeating: 1, count: size))) }
        XCTAssertThrowsError(try Binding.decode(Data(repeating: 0, count: 257)))
        XCTAssertThrowsError(try Request.decode(Data(repeating: 0, count: 769)))
        XCTAssertThrowsError(try Response.decode(Data(repeating: 0, count: 1025), expected: request))
    }
    func testFixedRoleAddressesAreSeparateFromRootAndOtherAccounts() throws {
        let account = Data(repeating: 4, count: 16), other = Data(repeating: 5, count: 16)
        let root = try GatewaySettingsControlAddress.serviceName(accountID: account)
        let gateway = try GatewaySettingsConsumerRole.gateway.serviceName(accountID: account)
        let transport = try GatewaySettingsConsumerRole.transport.serviceName(accountID: account)
        XCTAssertEqual(Set([root, gateway, transport]).count, 3)
        XCTAssertNotEqual(gateway, try GatewaySettingsConsumerRole.gateway.serviceName(accountID: other))
        XCTAssertThrowsError(try GatewaySettingsConsumerRole.transport.serviceName(accountID: Data()))
        XCTAssertEqual(GatewaySettingsConsumerRole.gateway.codeRole, .notificationGateway)
        XCTAssertEqual(GatewaySettingsConsumerRole.transport.codeRole, .transport)
    }
    func testRootControlOneBytesRemainExactAndPurposesCannotCrossDecode() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), value = try fence(r), companion = try binding(value)
        let peer = try GatewaySettingsControlBinding(accountID: value.accountID, rootEpoch: UUID())
        let change = try AuthorityPhonePushSettingsChange(revisionDigest: value.revision.digest,
            previousCommitDigest: value.previous.observationDigest, selectedCommitDigest: value.selected.observationDigest)
        let root = try GatewaySettingsControlRequest(binding: peer, change: change, action: .observe, challenge: Data(repeating: 1, count: 32))
        let expected = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-root-gateway-settings-request"),
            2: .bytes(peer.encoded), 3: .bytes(change.revisionDigest), 4: .bytes(change.previousCommitDigest),
            5: .bytes(change.selectedCommitDigest), 6: .unsigned(1), 7: .bytes(root.challenge)]), limits: .init(maxBytes: 512, maxDepth: 1, maxItems: 17))
        XCTAssertEqual(try root.encoded, expected)
        let request = try Request(binding: companion, fence: value, action: .observe, challenge: root.challenge)
        XCTAssertThrowsError(try GatewaySettingsControlRequest.decode(request.encoded)); XCTAssertThrowsError(try Request.decode(root.encoded))
        XCTAssertThrowsError(try GatewaySettingsControlBinding.decode(companion.encoded)); XCTAssertThrowsError(try Binding.decode(peer.encoded))
        let rootReply = try GatewaySettingsControlResponse(request: root, observation: .unknown)
        let companionReply = try Response(request: request, observation: .unknown)
        XCTAssertThrowsError(try Response.decode(rootReply.encoded, expected: request))
        XCTAssertThrowsError(try GatewaySettingsControlResponse.decode(companionReply.encoded, expected: root))
    }
}
