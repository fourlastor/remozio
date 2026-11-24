import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandStreamFrameTests: XCTestCase {
    private func binding(wire: UInt64 = 4) -> CommandStreamBinding {
        .init(profile: .init(wireVersion: wire, submissionSchemaVersion: 1, inputCarrierVersion: 4,
            callerBinding: Data(repeating: 1, count: 16), macID: Data(repeating: 2, count: 16), accountID: Data(repeating: 3, count: 16)),
            submission: .init(id: Data(repeating: 4, count: 16), nonce: Data(repeating: 5, count: 32), callerBinding: Data(repeating: 1, count: 16)),
            submissionDigest: Data(repeating: 6, count: 32),
            request: .init(requestID: Data(repeating: 7, count: 16), requestToken: Data(repeating: 8, count: 32), challenge: Data(repeating: 9, count: 32)))
    }
    func testEveryBodyRoundTripsWithExactBinaryBytesAndDirection() throws {
        let bodies: [CommandStreamFrame.Body] = [.opened, .output(Data((0..<4096).map { UInt8($0 % 251) })), .outputEnd,
            .inputCredit(32768), .input(Data([0, 10, 13, 255])), .inputEnd, .signal(UInt32(SIGINT)), .resize(0, 65535, 53, 143), .cancel, .outputDrained]
        for body in bodies {
            let frame = CommandStreamFrame(sequence: 3, body: body), bytes = try frame.encode(binding: binding())
            XCTAssertEqual(try CommandStreamFrame.decode(bytes, binding: binding(), direction: frame.direction), frame)
            XCTAssertThrowsError(try CommandStreamFrame.decode(bytes, binding: binding(), direction: frame.direction == .toFrontend ? .toAuthority : .toFrontend))
        }
    }
    func testLegacyWireAndMutatedRequestScopeOrSubmissionCannotAcquireStreamMeaning() throws {
        let frame = CommandStreamFrame(sequence: 0, body: .opened), bytes = try frame.encode(binding: binding())
        XCTAssertThrowsError(try frame.encode(binding: binding(wire: 3)))
        var fields = try XCTUnwrap(try DeterministicCBOR.decode(bytes, limits: CommandStreamFrame.limits()).mapValue)
        let original = try XCTUnwrap(fields[1]?.mapValue)
        for field: UInt64 in 0...3 {
            var wrong = original; wrong[field] = .bytes(Data(repeating: 99, count: 32)); fields[1] = .map(wrong)
            XCTAssertThrowsError(try CommandStreamFrame.decode(DeterministicCBOR.encode(.map(fields), limits: CommandStreamFrame.limits()),
                binding: binding(), direction: .toFrontend))
        }
    }
    func testLimitsUnknownFieldsVersionsTagsAndCounterOverflowFail() throws {
        for body: CommandStreamFrame.Body in [.input(Data()), .output(Data(count: 4097)), .inputCredit(0), .inputCredit(32769), .signal(0), .signal(UInt32(NSIG))] {
            XCTAssertThrowsError(try CommandStreamFrame(sequence: 0, body: body).encode(binding: binding()))
        }
        XCTAssertThrowsError(try CommandStreamFrame(sequence: UInt64.max, body: .cancel).encode(binding: binding()))
        let bytes = try CommandStreamFrame(sequence: 0, body: .opened).encode(binding: binding())
        let original = try XCTUnwrap(try DeterministicCBOR.decode(bytes, limits: CommandStreamFrame.limits()).mapValue)
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (3, .unsigned(99)), (4, .null), (5, .null)] {
            var wrong = original; wrong[key] = value
            XCTAssertThrowsError(try CommandStreamFrame.decode(DeterministicCBOR.encode(.map(wrong), limits: CommandStreamFrame.limits()), binding: binding(), direction: .toFrontend))
        }
        XCTAssertThrowsError(try CommandStreamFrame.decode(Data(count: 8193), binding: binding(), direction: .toFrontend))
    }
    func testSequenceRejectsReplayGapsEarlyOutputAndPostEOFBytesWithoutAdvancing() throws {
        var down = CommandStreamReceiveSequence(direction: .toFrontend)
        XCTAssertThrowsError(try down.accept(.init(sequence: 0, body: .output(Data([1])))))
        XCTAssertEqual(down.next, 0)
        try down.accept(.init(sequence: 0, body: .opened))
        for frame in [CommandStreamFrame(sequence: 0, body: .opened), .init(sequence: 2, body: .outputEnd)] { XCTAssertThrowsError(try down.accept(frame)) }
        XCTAssertEqual(down.next, 1)
        try down.accept(.init(sequence: 1, body: .outputEnd))
        XCTAssertThrowsError(try down.accept(.init(sequence: 2, body: .output(Data([1])))))
        var up = CommandStreamReceiveSequence(direction: .toAuthority)
        try up.accept(.init(sequence: 0, body: .inputEnd))
        XCTAssertThrowsError(try up.accept(.init(sequence: 1, body: .input(Data([1])))))
        try up.accept(.init(sequence: 1, body: .signal(UInt32(SIGINT))))
        try up.accept(.init(sequence: 2, body: .outputDrained))
    }
    func testPipeControlsRequireTheirOwnOfferWithoutChangingLegacyProfiles() throws {
        let selected = binding(wire: 5).profile, nonce = Data(repeating: 10, count: 32)
        let bytes = try CommandHandshakeReply(nonce: nonce, profile: selected).bytes
        XCTAssertEqual(try CommandHandshakeReply.decode(bytes, offer: CommandHandshakeOffer(nonce: nonce, capabilities: .pipeExecutionControls),
            macID: selected.macID, accountID: selected.accountID), selected)
        for capabilities: CommandHandshakeCapabilities in [.executionChannels, .streamingExecution, .admissionResults, .current] {
            XCTAssertThrowsError(try CommandHandshakeReply.decode(bytes, offer: CommandHandshakeOffer(nonce: nonce, capabilities: capabilities),
                macID: selected.macID, accountID: selected.accountID))
        }
        XCTAssertEqual(CommandHandshakeCapabilities.pipeExecutionControls.wireVersions, [5])
        XCTAssertEqual(CommandHandshakeCapabilities.streamingExecution.wireVersions, [4])
        XCTAssertTrue(selected.supportsExecutionControls); XCTAssertFalse(selected.supportsStreamingExecution)
    }
    func testPipeOpenedGrantsNoInputCreditAndOnlySignalsAndCancellationRoundTrip() throws {
        for (wire, value): (UInt64, CBORValue) in [(4, .unsigned(32768)), (5, .null)] {
            let bytes = try CommandStreamFrame(sequence: 0, body: .opened).encode(binding: binding(wire: wire))
            XCTAssertEqual(try DeterministicCBOR.decode(bytes, limits: CommandStreamFrame.limits()).mapValue?[4], value)
            XCTAssertEqual(try CommandStreamFrame.decode(bytes, binding: binding(wire: wire), direction: .toFrontend).body, .opened)
        }
        for body: CommandStreamFrame.Body in [.signal(UInt32(SIGTERM)), .cancel] {
            let frame = CommandStreamFrame(sequence: 3, body: body), bytes = try frame.encode(binding: binding(wire: 5))
            XCTAssertEqual(try CommandStreamFrame.decode(bytes, binding: binding(wire: 5), direction: .toAuthority), frame)
        }
        for body: CommandStreamFrame.Body in [.input(Data([1])), .inputEnd, .output(Data([2])), .outputEnd,
                                             .inputCredit(1), .resize(24, 80, 0, 0), .outputDrained] {
            XCTAssertThrowsError(try CommandStreamFrame(sequence: 1, body: body).encode(binding: binding(wire: 5)))
        }
    }
    func testPipeProfileCannotAcquirePTYFramesByChangingOnlyTheBinding() throws {
        for body: CommandStreamFrame.Body in [.opened, .input(Data([1])), .inputEnd, .output(Data([2])), .outputEnd,
                                             .inputCredit(1), .resize(24, 80, 0, 0), .outputDrained] {
            let bytes = try CommandStreamFrame(sequence: 0, body: body).encode(binding: binding())
            var fields = try XCTUnwrap(try DeterministicCBOR.decode(bytes, limits: CommandStreamFrame.limits()).mapValue)
            fields[1] = binding(wire: 5).fields
            XCTAssertThrowsError(try CommandStreamFrame.decode(DeterministicCBOR.encode(.map(fields), limits: CommandStreamFrame.limits()),
                binding: binding(wire: 5), direction: CommandStreamFrame(sequence: 0, body: body).direction))
        }
        let bytes = try CommandStreamFrame(sequence: 0, body: .opened).encode(binding: binding(wire: 5))
        XCTAssertThrowsError(try CommandStreamFrame.decode(bytes, binding: binding(), direction: .toFrontend))
    }
    func testWireFourRequiresAnExplicitOfferAndLeavesLegacyDeclarationsUnchanged() throws {
        let nonce = Data(repeating: 10, count: 32), selected = binding().profile
        let bytes = try CommandHandshakeReply(nonce: nonce, profile: selected).bytes
        XCTAssertEqual(try CommandHandshakeReply.decode(bytes, offer: CommandHandshakeOffer(nonce: nonce, capabilities: .streamingExecution),
            macID: selected.macID, accountID: selected.accountID), selected)
        XCTAssertThrowsError(try CommandHandshakeReply.decode(bytes, offer: CommandHandshakeOffer(nonce: nonce, capabilities: .executionChannels),
            macID: selected.macID, accountID: selected.accountID))
        XCTAssertEqual(CommandHandshakeCapabilities.executionChannels.wireVersions, [3])
        XCTAssertEqual(CommandHandshakeCapabilities.current.wireVersions, [1])
    }
}

private extension CBORValue {
    var mapValue: [UInt64: CBORValue]? { if case .map(let value) = self { value } else { nil } }
}
