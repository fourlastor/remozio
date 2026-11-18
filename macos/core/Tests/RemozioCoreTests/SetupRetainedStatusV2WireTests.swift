import Darwin
import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class SetupRetainedStatusV2WireTests: XCTestCase {
    private typealias W = SetupRetainedStatusV2Wire
    private let id = Data(repeating: 7, count: 16)
    private struct Golden: Decodable {
        struct Entry: Decodable { let name: String; let tuple: [UInt64?]; let hex: String }
        let request: String, unavailable: String
        struct Shape: Decodable { let name: String; let hex: String }
        let cases: [Entry]
        let shapes: [Shape]
    }
    private func fixture() throws -> Golden {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "setup-retained-status-v2", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(Golden.self, from: Data(contentsOf: url))
    }
    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    func testEveryRestartFactMatchesTheIndependentGoldenBytes() throws {
        let golden = try fixture(), request = try W.Request(requestID: id)
        for entry in golden.cases {
            let v = entry.tuple
            let snapshot = SetupRestartStatus.Snapshot(revision: 71,
                slot: try XCTUnwrap(v[0].flatMap(SetupRestartStatus.Slot.init(rawValue:))),
                claim: try XCTUnwrap(v[1].flatMap(SetupRestartStatus.Claim.init(rawValue:))),
                task: try XCTUnwrap(v[2].flatMap(SetupRestartStatus.Task.init(rawValue:))),
                custody: v[3].flatMap(SetupRestartStatus.Custody.init(rawValue:)),
                writer: v[4].flatMap(SetupRestartStatus.Writer.init(rawValue:)), row: nil)
            let bytes = try W.reply(request, .init(retained: .unavailable, restart: snapshot))
            XCTAssertEqual(hex(bytes), entry.hex, entry.name)
            let fields = try W.decodeReply(bytes)
            XCTAssertEqual(fields[3], .unsigned(2))
            for key in [UInt64(4), 5, 6, 7, 8, 9, 10, 11] { XCTAssertEqual(fields[key], .null) }
        }
        XCTAssertEqual(golden.cases.count, 12)
        XCTAssertEqual(Set(golden.cases.map(\.hex)).count, 12)
    }
    func testUnavailableFactsAndTheRequestHaveFrozenBytes() throws {
        let golden = try fixture(), request = try W.Request(requestID: id)
        XCTAssertEqual(hex(try request.bytes), golden.request)
        XCTAssertEqual(try W.Request.decode(request.bytes), request)
        let bytes = try W.reply(request, .unavailable)
        XCTAssertEqual(hex(bytes), golden.unavailable)
        let fields = try W.decodeReply(bytes)
        for key in UInt64(3)...12 { XCTAssertEqual(fields[key], .null) }
    }
    func testStatusVersionsRemainSeparateAndMalformedIDsAreRefused() throws {
        let request = try W.Request(requestID: id)
        XCTAssertThrowsError(try SetupRetainedStatusWire.Request.decode(request.bytes))
        XCTAssertThrowsError(try W.Request.decode(SetupRetainedStatusWire.Request(requestID: id).bytes))
        for size in [0, 15, 17] { XCTAssertThrowsError(try W.Request(requestID: Data(repeating: 0, count: size))) }
        XCTAssertThrowsError(try W.Request.decode(Data(repeating: 0, count: 1025)))
        XCTAssertThrowsError(try W.decodeReply(Data(repeating: 0, count: 16385)))
    }
    func testUnknownReplyCodesFieldsAndOpenCustodySafetyClaimsAreRefused() throws {
        let value = SetupRestartStatus.Snapshot(revision: 0, slot: .held, claim: .present, task: .running,
            custody: .open, writer: nil, row: nil)
        let request = try W.Request(requestID: id)
        let good = try W.decodeReply(W.reply(request, .init(retained: .unavailable, restart: value)))
        var mutations: [[UInt64: CBORValue]] = []
        var fields = good; fields[13] = .null; mutations.append(fields)
        fields = good; fields[3] = .unsigned(4); mutations.append(fields)
        fields = good; fields[12] = .array([.unsigned(3), .unsigned(1), .unsigned(2), .unsigned(2), .null]); mutations.append(fields)
        fields = good; fields[12] = .array([.unsigned(1), .unsigned(1), .unsigned(7), .unsigned(2), .null]); mutations.append(fields)
        fields = good; fields[12] = .array([.unsigned(1), .unsigned(1), .unsigned(2), .unsigned(2), .unsigned(1)]); mutations.append(fields)
        fields = good; fields[12] = .array([.unsigned(1), .unsigned(1), .unsigned(2), .null, .unsigned(1)]); mutations.append(fields)
        fields = good; fields[12] = .array([.unsigned(1), .unsigned(1), .unsigned(2), .null, .unsigned(2)]); mutations.append(fields)
        fields = good; fields[11] = .array([.unsigned(3)]); mutations.append(fields)
        fields = good; fields[2] = .bytes(Data(repeating: 7, count: 15)); mutations.append(fields)
        fields = good; fields[8] = .array([.unsigned(11), .unsigned(1), .null]); mutations.append(fields)
        for bad in mutations {
            let bytes = try DeterministicCBOR.encode(.map(bad), limits: .init(maxBytes: 16384, maxDepth: 4, maxItems: 96))
            XCTAssertThrowsError(try W.decodeReply(bytes))
        }
    }
    private func fixedProjection(_ name: String) throws -> SetupRetainedStatusProjection {
        typealias Row = RuntimeMaintenanceWindowRecord
        let uid = getuid(), digest = Data(repeating: 9, count: 32)
        let authority = try Row.Account(accountID: Data(repeating: 1, count: 16), ownerUID: uid, directoryID: Data(repeating: 0x11, count: 16))
        let target = try Row.Account(accountID: Data(repeating: 2, count: 16), ownerUID: uid + 1, directoryID: Data(repeating: 0x22, count: 16))
        let scope = try Row.Scope(macID: Data(repeating: 3, count: 16), installationID: Data(repeating: 4, count: 16),
            authority: authority, target: target, releaseDigest: digest, candidateDigest: digest, authorityPolicyDigest: digest,
            operationDigest: digest, restorationDigest: digest, mutationFootprintDigest: digest,
            authorityGrantDigest: digest, targetConsentDigest: digest, administratorIntentDigest: digest)
        let withoutFailure = name == "restart-row-no-failure"
        let row = try Row(id: Data(repeating: 0xab, count: 16), revision: Data(repeating: 0xcd, count: 16), purpose: .retainedRuntime,
            scope: scope, phase: withoutFailure ? .restoring : .needsOwnerRecovery, operation: .committed,
            service: withoutFailure ? .restartPending : .unknown, failure: withoutFailure ? nil : .cleanupPending)
        if name.hasPrefix("restart-") {
            return .init(retained: .unavailable, restart: .init(revision: 0, slot: .held, claim: .present, task: .running,
                custody: .open, writer: nil, row: .init(row)))
        }
        let reader = SetupRetainedInvocationStatus.Reader(); defer { reader.close() }
        reader.publishRecovery(row)
        let peer = XPCPeerCredentials(processID: getpid(), userID: uid, auditSessionID: 1)
        let owner = LocalAccountIdentity(uid: uid, primaryGroupID: getgid(), directoryID: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!)
        let observed = reader.read(authenticatedPeer: peer, currentOwner: owner)
        if name == "supervisor-row" { return .init(retained: observed.observing(supervisor: .phase(.needsOwnerRecovery)), restart: nil) }
        guard case .observed(let binding) = observed.binding else { throw AdministrativeSetupError.unavailable }
        let identity = SetupRetainedInvocationStatus.Identity(reservationID: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            incarnation: UUID(uuidString: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")!)
        let captured = SetupRetainedInvocationStatus.reservation(.attached, identity: identity, binding: binding, expectedWindow: .init(row),
            worker: .observed(.idle), cleanup: .observed(.noneRegistered)).observing(row).observing(supervisor: .busy)
        return .init(retained: captured, restart: nil)
    }
    func testAllOriginsAndRestartRowsMatchFrozenBytes() throws {
        let golden = try fixture(), request = try W.Request(requestID: id)
        XCTAssertEqual(Set(golden.shapes.map(\.name)), ["restart-row-failure", "restart-row-no-failure", "in-process-row-supervisor", "supervisor-row"])
        for shape in golden.shapes {
            let bytes = try W.reply(request, fixedProjection(shape.name))
            XCTAssertEqual(hex(bytes), shape.hex, shape.name)
            let fields = try W.decodeReply(bytes)
            XCTAssertNotEqual(fields[6], .null); XCTAssertNotEqual(fields[7], .null); XCTAssertNotEqual(fields[8], .null)
        }
    }
}
