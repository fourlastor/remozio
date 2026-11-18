import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class SetupRestartRecoveryWireTests: XCTestCase {
    private typealias W = SetupRestartRecoveryWire
    private let id = Data(repeating: 7, count: 16)
    private struct Golden: Decodable { let vectors: [String: String] }
    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    private func map(_ fields: [UInt64: CBORValue]) throws -> Data {
        try DeterministicCBOR.encode(.map(fields), limits: .init(maxBytes: 2048, maxDepth: 4, maxItems: 30))
    }
    func testEveryActionAndResultMatchesTheIndependentGoldenBytes() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "setup-restart-wire-v1", withExtension: "json", subdirectory: "Fixtures"))
        let expected = try JSONDecoder().decode(Golden.self, from: Data(contentsOf: url)).vectors
        var actual = ["progress": hex(try W.Progress(requestID: id).bytes)]
        for action in W.Action.allCases { actual["action-\(action.rawValue)"] = hex(try W.Request(requestID: id, action: action).bytes) }
        for code in W.Code.allCases { actual["reply-\(code.rawValue)"] = hex(try W.Reply(requestID: id, code: code).bytes) }
        XCTAssertEqual(actual, expected); XCTAssertEqual(actual.count, 14)
    }
    func testCanonicalMessagesRoundTripWithoutPrivateScopeFields() throws {
        for action in W.Action.allCases {
            let request = try W.Request(requestID: id, action: action)
            XCTAssertEqual(try W.Request.decode(request.bytes), request)
        }
        for code in W.Code.allCases {
            let reply = try W.Reply(requestID: id, code: code)
            XCTAssertEqual(try W.Reply.decode(reply.bytes), reply)
        }
        let progress = try W.Progress(requestID: id)
        XCTAssertEqual(try W.Progress.decode(progress.bytes), progress)
    }
    func testMalformedRequestIDsAreRefusedForEveryMessageType() {
        for size in [0, 15, 17, 1024] {
            let bytes = Data(repeating: 7, count: size)
            XCTAssertThrowsError(try W.Request(requestID: bytes, action: .restore))
            XCTAssertThrowsError(try W.Progress(requestID: bytes))
            XCTAssertThrowsError(try W.Reply(requestID: bytes, code: .pending))
        }
    }
    func testUnknownActionsAndResultCodesAreClosed() throws {
        for value in [UInt64(0), 4, 100] {
            XCTAssertThrowsError(try W.Request.decode(map([0: .unsigned(1), 1: .text(W.requestName), 2: .bytes(id), 3: .unsigned(value)])))
        }
        for value in [UInt64(10), 11, 100] {
            XCTAssertThrowsError(try W.Reply.decode(map([0: .unsigned(1), 1: .text(W.replyName), 2: .bytes(id), 3: .unsigned(value)])))
        }
        XCTAssertEqual(W.Code.failedOperation.rawValue, 9)
    }
    func testOrphanMessagesAndClientScopeInputsCannotSelectRestart() throws {
        XCTAssertThrowsError(try W.Request.decode(SetupOrphanRecoveryWire.Request(requestID: id, action: .restore).bytes))
        let request = try map([0: .unsigned(1), 1: .text(W.requestName), 2: .bytes(id), 3: .unsigned(1), 4: .bytes(Data(repeating: 9, count: 16))])
        XCTAssertThrowsError(try W.Request.decode(request))
        XCTAssertThrowsError(try SetupOrphanRecoveryWire.Request.decode(W.Request(requestID: id, action: .restore).bytes))
    }
    func testNoncanonicalVersionAndOversizedPayloadsAreRefused() throws {
        let request = try W.Request(requestID: id, action: .restore).bytes
        var noncanonical = request; noncanonical.replaceSubrange(2...2, with: [0x18, 0x01])
        XCTAssertThrowsError(try W.Request.decode(noncanonical))
        XCTAssertThrowsError(try W.Request.decode(Data(repeating: 0, count: 1025)))
        XCTAssertThrowsError(try W.Progress.decode(Data(repeating: 0, count: 1025)))
        XCTAssertThrowsError(try W.Reply.decode(Data(repeating: 0, count: 1025)))
    }
    func testMessageNamesAndVersionsCannotBeSubstituted() throws {
        for version in [UInt64(0), 2] {
            XCTAssertThrowsError(try W.Request.decode(map([0: .unsigned(version), 1: .text(W.requestName), 2: .bytes(id), 3: .unsigned(1)])))
        }
        XCTAssertThrowsError(try W.Progress.decode(W.Request(requestID: id, action: .restore).bytes))
        XCTAssertThrowsError(try W.Reply.decode(W.Progress(requestID: id).bytes))
    }
}
