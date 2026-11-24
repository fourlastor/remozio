import Darwin
import Foundation
import RemozioMach
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandJobStateTests: XCTestCase {
    private func binding(_ wire: UInt64, token: UInt8 = 8) -> CommandStreamBinding {
        .init(profile: .init(wireVersion: wire, submissionSchemaVersion: 1, inputCarrierVersion: wire >= 8 ? 5 : 4,
            callerBinding: Data(repeating: 1, count: 16), macID: Data(repeating: 2, count: 16), accountID: Data(repeating: 3, count: 16)),
            submission: .init(id: Data(repeating: 4, count: 16), nonce: Data(repeating: 5, count: 32), callerBinding: Data(repeating: 1, count: 16)),
            submissionDigest: Data(repeating: 6, count: 32),
            request: .init(requestID: Data(repeating: 7, count: 16), requestToken: Data(repeating: token, count: 32), challenge: Data(repeating: 9, count: 32)))
    }
    private func stopped(revision: UInt64 = 1, tracing: CommandStopTracing = .unknown) -> CommandJobStatePayload {
        .init(revision: revision, state: .stopped(signal: UInt32(SIGTSTP), rawStopCode: UInt32(CLD_STOPPED), tracing: tracing))
    }
    func testEachJobProfileRequiresAnExplicitOfferWithoutChangingLegacyDefaults() throws {
        let nonce = Data(repeating: 10, count: 32)
        for (wire, capabilities): (UInt64, CommandHandshakeCapabilities) in [(6, .streamingJobExecution), (7, .pipeJobExecutionControls), (8, .mappedTerminalJobExecution), (9, .mappedPipeJobExecutionControls)] {
            let profile = binding(wire).profile, bytes = try CommandHandshakeReply(nonce: nonce, profile: profile).bytes
            XCTAssertEqual(try CommandHandshakeReply.decode(bytes, offer: CommandHandshakeOffer(nonce: nonce, capabilities: capabilities),
                macID: profile.macID, accountID: profile.accountID), profile)
            for old: CommandHandshakeCapabilities in [.current, .executionChannels, .streamingExecution, .pipeExecutionControls] {
                XCTAssertThrowsError(try CommandHandshakeReply.decode(bytes, offer: CommandHandshakeOffer(nonce: nonce, capabilities: old),
                    macID: profile.macID, accountID: profile.accountID))
            }
            XCTAssertTrue(profile.supportsJobState)
            XCTAssertEqual(profile.supportsStreamingExecution, [6, 8].contains(wire))
            XCTAssertEqual(profile.supportsPipeExecutionControls, [7, 9].contains(wire))
        }
        XCTAssertEqual(CommandHandshakeCapabilities.streamingExecution.wireVersions, [4])
        XCTAssertEqual(CommandHandshakeCapabilities.pipeExecutionControls.wireVersions, [5])
        XCTAssertEqual(CommandHandshakeCapabilities.executionChannels.wireVersions, [3])
    }
    func testJobFramesPreserveUnknownTracingRawStopCodesAndExactBinding() throws {
        for wire: UInt64 in [6, 7, 8, 9] {
            for tracing: CommandStopTracing in [.unknown, .untraced, .traced] {
                for code in [CLD_STOPPED, CLD_TRAPPED] {
                    let payload = CommandJobStatePayload(revision: 3, state: .stopped(signal: UInt32(SIGTRAP), rawStopCode: UInt32(code), tracing: tracing))
                    let frame = CommandStreamFrame(sequence: 2, body: .jobState(payload)), bytes = try frame.encode(binding: binding(wire))
                    XCTAssertEqual(try CommandStreamFrame.decode(bytes, binding: binding(wire), direction: .toFrontend), frame)
                    XCTAssertThrowsError(try CommandStreamFrame.decode(bytes, binding: binding(wire), direction: .toAuthority))
                    XCTAssertThrowsError(try CommandStreamFrame.decode(bytes, binding: binding(wire == 6 ? 7 : 6), direction: .toFrontend))
                }
            }
            let frame = CommandStreamFrame(sequence: 3, body: .jobState(.init(revision: 4, state: .continued)))
            XCTAssertEqual(try CommandStreamFrame.decode(frame.encode(binding: binding(wire)), binding: binding(wire), direction: .toFrontend), frame)
        }
        for wire: UInt64 in [3, 4, 5] {
            XCTAssertThrowsError(try CommandStreamFrame(sequence: 1, body: .jobState(stopped())).encode(binding: binding(wire)))
        }
    }
    func testStreamRejectsAChangedRequestTokenInBothDirections() throws {
        for wire: UInt64 in 4...9 {
            let original = binding(wire), crossed = binding(wire, token: 10)
            for (body, direction): (CommandStreamFrame.Body, CommandStreamFrame.Direction) in [(.opened, .toFrontend), (.cancel, .toAuthority)] {
                let frame = CommandStreamFrame(sequence: 0, body: body)
                let bytes = try frame.encode(binding: original)
                XCTAssertEqual(try CommandStreamFrame.decode(bytes, binding: original, direction: direction), frame)
                XCTAssertThrowsError(try CommandStreamFrame.decode(bytes, binding: crossed, direction: direction)) {
                    XCTAssertEqual($0 as? CommandStreamError, .binding)
                }
            }
        }
    }
    func testMalformedJobMetadataAndUnknownFieldsFail() throws {
        let valid = try stopped().fields
        guard case .map(let fields) = valid else { return XCTFail("A job observation must have exact fields") }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(0)), (1, .unsigned(3)), (2, .unsigned(0)),
                                               (2, .unsigned(UInt64(NSIG))), (2, .unsigned(UInt64.max)),
                                               (3, .unsigned(UInt64(CLD_CONTINUED))), (4, .unsigned(3)), (5, .null)] {
            var wrong = fields; wrong[key] = value
            XCTAssertThrowsError(try CommandJobStatePayload.decode(.map(wrong)))
        }
        XCTAssertThrowsError(try CommandJobStatePayload.decode(.map([0: .unsigned(1), 1: .unsigned(2), 2: .unsigned(0)])))
        XCTAssertThrowsError(try CommandJobStatePayload(revision: 0, state: .continued).fields)
    }
    func testOutputEOFStillPermitsJobObservationsWithoutReopeningPTYBytes() throws {
        var sequence = CommandStreamReceiveSequence(direction: .toFrontend)
        XCTAssertThrowsError(try sequence.accept(.init(sequence: 0, body: .jobState(stopped()))))
        try sequence.accept(.init(sequence: 0, body: .opened))
        try sequence.accept(.init(sequence: 1, body: .outputEnd))
        try sequence.accept(.init(sequence: 2, body: .jobState(stopped())))
        try sequence.accept(.init(sequence: 3, body: .jobState(.init(revision: 2, state: .continued))))
        XCTAssertTrue(sequence.ended); XCTAssertEqual(sequence.next, 4)
        for body: CommandStreamFrame.Body in [.output(Data([1])), .inputCredit(1), .opened, .outputEnd] {
            XCTAssertThrowsError(try sequence.accept(.init(sequence: 4, body: body)))
        }
        XCTAssertEqual(sequence.next, 4)
        for body: CommandStreamFrame.Body in [.input(Data([1])), .output(Data([1])), .outputEnd, .inputCredit(1), .resize(24, 80, 0, 0), .outputDrained] {
            XCTAssertThrowsError(try CommandStreamFrame(sequence: 1, body: body).encode(binding: binding(7)))
        }
    }
    func testNativeRecordConversionRetainsSnapshotKnowledgeWithoutInferringCause() throws {
        var record = remozio_monitor_record_t()
        record.tag = UInt32(REMOZIO_MONITOR_JOB_STATE.rawValue); record.target_pid = 42; record.sequence = 2; record.job_revision = 1
        record.flags = UInt32(REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED.rawValue | REMOZIO_MONITOR_STOPPED.rawValue)
        record.detail = UInt32(SIGTRAP); record.stop_code = UInt32(CLD_STOPPED)
        XCTAssertEqual(try CommandJobStatePayload(nativeRecord: record),
                       .init(revision: 1, state: .stopped(signal: UInt32(SIGTRAP), rawStopCode: UInt32(CLD_STOPPED), tracing: .unknown)))
        record.flags |= UInt32(REMOZIO_MONITOR_TRACING_KNOWN.rawValue)
        XCTAssertEqual(try CommandJobStatePayload(nativeRecord: record).state,
                       .stopped(signal: UInt32(SIGTRAP), rawStopCode: UInt32(CLD_STOPPED), tracing: .untraced))
        record.flags |= UInt32(REMOZIO_MONITOR_TRACED.rawValue)
        XCTAssertEqual(try CommandJobStatePayload(nativeRecord: record).state,
                       .stopped(signal: UInt32(SIGTRAP), rawStopCode: UInt32(CLD_STOPPED), tracing: .traced))
        record.flags = UInt32(REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED.rawValue); record.detail = 0; record.stop_code = 0
        XCTAssertEqual(try CommandJobStatePayload(nativeRecord: record).state, .continued)
        for tag in [REMOZIO_MONITOR_PREPARED, REMOZIO_MONITOR_TARGET_REAPED, REMOZIO_MONITOR_FAILURE] {
            record.tag = UInt32(tag.rawValue); XCTAssertThrowsError(try CommandJobStatePayload(nativeRecord: record))
        }
    }
}
