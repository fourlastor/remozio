import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandCurrentJobTests: XCTestCase {
    private func binding(_ wire: UInt64) -> CommandStreamBinding {
        .init(profile: .init(wireVersion: wire, submissionSchemaVersion: 1, inputCarrierVersion: 5,
            callerBinding: Data(repeating: 1, count: 16), macID: Data(repeating: 2, count: 16), accountID: Data(repeating: 3, count: 16)),
            submission: .init(id: Data(repeating: 4, count: 16), nonce: Data(repeating: 5, count: 32), callerBinding: Data(repeating: 1, count: 16)),
            submissionDigest: Data(repeating: 6, count: 32),
            request: .init(requestID: Data(repeating: 7, count: 16), requestToken: Data(repeating: 8, count: 32), challenge: Data(repeating: 9, count: 32)))
    }
    func testFreshQueriesRequireExplicitNewProfilesAndPreserveHistoricalOffers() throws {
        let nonce = Data(repeating: 1, count: 32)
        for (wire, capabilities): (UInt64, CommandHandshakeCapabilities) in [(10, .mappedTerminalCurrentJobExecution), (11, .mappedPipeCurrentJobExecutionControls)] {
            let profile = binding(wire).profile, reply = try CommandHandshakeReply(nonce: nonce, profile: profile).bytes
            XCTAssertEqual(try CommandHandshakeReply.decode(reply, offer: CommandHandshakeOffer(nonce: nonce, capabilities: capabilities),
                macID: profile.macID, accountID: profile.accountID), profile)
            XCTAssertTrue(profile.supportsMappedLayout); XCTAssertTrue(profile.supportsCurrentJob)
            XCTAssertEqual(profile.supportsStreamingExecution, wire == 10)
            XCTAssertEqual(profile.supportsPipeExecutionControls, wire == 11)
            for old: CommandHandshakeCapabilities in [.mappedTerminalJobExecution, .mappedPipeJobExecutionControls, .streamingJobExecution, .pipeJobExecutionControls] {
                XCTAssertThrowsError(try CommandHandshakeReply.decode(reply, offer: CommandHandshakeOffer(nonce: nonce, capabilities: old),
                    macID: profile.macID, accountID: profile.accountID))
            }
        }
        XCTAssertEqual(CommandHandshakeCapabilities.mappedTerminalJobExecution.wireVersions, [8])
        XCTAssertEqual(CommandHandshakeCapabilities.mappedPipeJobExecutionControls.wireVersions, [9])
    }
    func testQueryAndResponseRequireExactBindingDirectionAndCanonicalState() throws {
        let nonce = Data(repeating: 2, count: 32)
        for wire: UInt64 in [10, 11] {
            for body: CommandStreamFrame.Body in [.queryCurrentJob(nonce), .currentJob(.init(nonce: nonce, state: .unknown)),
                .currentJob(.init(nonce: nonce, state: .running)), .currentJob(.init(nonce: nonce, state: .stopped(signal: UInt32(SIGSTOP), revision: 4)))] {
                let frame = CommandStreamFrame(sequence: 2, body: body), bytes = try frame.encode(binding: binding(wire))
                XCTAssertEqual(try CommandStreamFrame.decode(bytes, binding: binding(wire), direction: frame.direction), frame)
                XCTAssertThrowsError(try CommandStreamFrame.decode(bytes, binding: binding(wire), direction: frame.direction == .toFrontend ? .toAuthority : .toFrontend))
                XCTAssertThrowsError(try CommandStreamFrame.decode(bytes, binding: binding(wire == 10 ? 11 : 10), direction: frame.direction))
                for old: UInt64 in [8, 9] { XCTAssertThrowsError(try frame.encode(binding: binding(old))) }
            }
        }
        for state: CommandCurrentJobState in [.stopped(signal: 0, revision: 1), .stopped(signal: UInt32(NSIG), revision: 1), .stopped(signal: 1, revision: 0)] {
            XCTAssertThrowsError(try CommandCurrentJobPayload(nonce: nonce, state: state).fields)
        }
        XCTAssertThrowsError(try CommandCurrentJobPayload(nonce: Data(count: 31), state: .unknown).fields)
        XCTAssertThrowsError(try CommandCurrentJobPayload.decode(.map([0: .bytes(nonce), 1: .unsigned(0), 2: .unsigned(1)])))
        XCTAssertThrowsError(try CommandCurrentJobPayload.decode(.map([0: .bytes(nonce), 1: .unsigned(3)])))
    }
    func testReadOnlyReplyAfterOutputEOFDoesNotReopenStreams() throws {
        var sequence = CommandStreamReceiveSequence(direction: .toFrontend)
        try sequence.accept(.init(sequence: 0, body: .opened))
        try sequence.accept(.init(sequence: 1, body: .outputEnd))
        try sequence.accept(.init(sequence: 2, body: .currentJob(.init(nonce: Data(count: 32), state: .unknown))))
        XCTAssertTrue(sequence.ended)
        XCTAssertThrowsError(try sequence.accept(.init(sequence: 3, body: .output(Data([1])))))
        XCTAssertThrowsError(try sequence.accept(.init(sequence: 2, body: .currentJob(.init(nonce: Data(count: 32), state: .unknown)))))
    }
}
