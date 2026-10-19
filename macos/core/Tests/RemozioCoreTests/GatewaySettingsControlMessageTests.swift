import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewaySettingsControlMessageTests: XCTestCase {
    private func request(action: GatewaySettingsControlAction = .observe, epoch: UUID = UUID(),
                         account: UInt8 = 1, revision: UInt8 = 2, challenge: UInt8 = 5) throws -> GatewaySettingsControlRequest {
        try .init(binding: .init(accountID: Data(repeating: account, count: 16), rootEpoch: epoch),
            change: .init(revisionDigest: Data(repeating: revision, count: 32),
                previousCommitDigest: Data(repeating: 3, count: 32), selectedCommitDigest: Data(repeating: 4, count: 32)),
            action: action, challenge: Data(repeating: challenge, count: 32))
    }
    private func changed(_ bytes: Data, _ edit: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        let limits = try CBORLimits(maxBytes: 2048, maxDepth: 2, maxItems: 128)
        guard case .map(var f) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        edit(&f); return try DeterministicCBOR.encode(.map(f), limits: limits)
    }
    func testEveryActionRoundTripsWithTheExactAccountEpochRevisionAndChallenge() throws {
        XCTAssertEqual(GatewaySettingsControlInterface.supportedVersions, [1])
        for action in [GatewaySettingsControlAction.observe, .quiesce, .accept] {
            let v = try request(action: action), bytes = try v.encoded, decoded = try GatewaySettingsControlRequest.decode(bytes)
            XCTAssertEqual(try decoded.encoded, bytes); XCTAssertEqual(decoded.binding, v.binding)
            XCTAssertEqual(decoded.change, v.change); XCTAssertEqual(decoded.action, action); XCTAssertEqual(decoded.challenge, v.challenge)
            XCTAssertLessThanOrEqual(bytes.count, 512)
        }
    }
    func testRequestRefusesUnknownVersionsFieldsPurposesActionsAndMalformedLengths() throws {
        let v = try request(), bytes = try v.encoded
        let edits: [(inout [UInt64: CBORValue]) -> Void] = [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("other") }, { $0[8] = .null }, { $0.removeValue(forKey: 7) },
            { $0[6] = .unsigned(0) }, { $0[6] = .unsigned(4) }, { $0[2] = .bytes(Data()) },
            { $0[3] = .bytes(Data(repeating: 2, count: 31)) }, { $0[4] = $0[5] }, { $0[7] = .bytes(Data(repeating: 5, count: 33)) }
        ]
        for edit in edits { XCTAssertThrowsError(try GatewaySettingsControlRequest.decode(changed(bytes, edit))) }
        XCTAssertThrowsError(try GatewaySettingsControlRequest.decode(bytes + Data([0])))
        XCTAssertThrowsError(try GatewaySettingsControlRequest.decode(Data(repeating: 0, count: 513)))
    }
    func testBindingRefusesMalformedAccountsEpochsAndFutureFormats() throws {
        let binding = try request().binding, bytes = try binding.encoded
        XCTAssertEqual(try GatewaySettingsControlBinding.decode(bytes), binding)
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("other") }, { $0[4] = .null },
            { $0[2] = .bytes(Data(repeating: 1, count: 15)) }, { $0[3] = .bytes(Data(repeating: 1, count: 17)) }
        ] { XCTAssertThrowsError(try GatewaySettingsControlBinding.decode(changed(bytes, edit))) }
    }
    func testAReplyCannotBeReusedForAnotherProcessAccountRevisionActionOrChallenge() throws {
        let epoch = UUID(), original = try request(epoch: epoch), reply = try GatewaySettingsControlResponse(request: original, observation: .unknown).encoded
        XCTAssertEqual(try GatewaySettingsControlResponse.decode(reply, expected: original).observation, .unknown)
        for other in [try request(epoch: UUID()), try request(epoch: epoch, account: 2), try request(epoch: epoch, revision: 3),
                      try request(action: .quiesce, epoch: epoch), try request(epoch: epoch, challenge: 6)] {
            XCTAssertThrowsError(try GatewaySettingsControlResponse.decode(reply, expected: other))
        }
        for edit: (inout [UInt64: CBORValue]) -> Void in [
            { $0[0] = .unsigned(2) }, { $0[1] = .text("other") }, { $0[4] = .null }, { $0[3] = .unsigned(5) }
        ] { XCTAssertThrowsError(try GatewaySettingsControlResponse.decode(changed(reply, edit), expected: original)) }
    }
    func testMutationRepliesCannotClaimAnEarlierOrUnrelatedStage() throws {
        for action in [GatewaySettingsControlAction.observe, .quiesce, .accept] {
            let request = try request(action: action)
            for observation in [GatewaySettingsControlObservation.unknown, .quiescing, .suspended, .accepted, .providerInstalled] {
                let valid = action == .observe || (action == .quiesce && observation == .suspended) ||
                    (action == .accept && (observation == .accepted || observation == .providerInstalled))
                if valid {
                    let bytes = try GatewaySettingsControlResponse(request: request, observation: observation).encoded
                    XCTAssertEqual(try GatewaySettingsControlResponse.decode(bytes, expected: request).observation, observation)
                    XCTAssertLessThanOrEqual(bytes.count, 640)
                } else { XCTAssertThrowsError(try GatewaySettingsControlResponse(request: request, observation: observation)) }
            }
        }
    }
}
