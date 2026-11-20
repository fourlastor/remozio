import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceUnboundMessageTests: XCTestCase {
    private func bytes(_ value: UInt8, _ count: Int = 16) -> Data { Data(repeating: value, count: count) }
    private func request(kind: AuthorityMaintenanceUnboundRequest.Kind = .gate) throws -> AuthorityMaintenanceUnboundRequest {
        try .init(kind: kind, installationID: bytes(1), accountID: bytes(2), attemptID: bytes(3), revision: bytes(4),
            rowDigest: bytes(5, 32), pendingRevision: bytes(6), intentID: bytes(7), gate: .init(device: 1, inode: 2),
            authorityIncarnation: bytes(8), challenge: bytes(9))
    }
    func testRequestsRoundTripWithExactKeysAndRefuseUnknownFields() throws {
        let limits = try CBORLimits(maxBytes: 2048, maxDepth: 3, maxItems: 64)
        for kind in [AuthorityMaintenanceUnboundRequest.Kind.release, .gate] {
            let request = try request(kind: kind)
            XCTAssertEqual(try AuthorityMaintenanceUnboundRequest.decode(request.encoded), request)
            guard case .map(var fields) = try DeterministicCBOR.decode(request.encoded, limits: limits) else { return XCTFail() }
            fields[12] = .null
            XCTAssertThrowsError(try AuthorityMaintenanceUnboundRequest.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
    }
    func testNeverHeldIsAnObservationAndOnlyAvailableAdmissionCanComplete() throws {
        for hold in [AuthorityMaintenanceUnboundGateResponse.Hold.held, .released, .neverHeld, .unknown] {
            for admission in RuntimeMaintenanceWindowRecord.GateReadback.Admission.allCases {
                let response = try AuthorityMaintenanceUnboundGateResponse(request: request(), hold: hold, admission: admission)
                XCTAssertEqual(try AuthorityMaintenanceUnboundGateResponse.decode(response.encoded), response)
                if admission == .available && (hold == .released || hold == .neverHeld) {
                    let gate = try response.completedGateReadback()
                    XCTAssertEqual(gate.hold, .released)
                    XCTAssertEqual(gate.requestRevision, response.request.pendingRevision)
                    XCTAssertEqual(gate.authorityIncarnation, response.request.authorityIncarnation)
                } else { XCTAssertThrowsError(try response.completedGateReadback()) }
            }
        }
    }
    func testReleaseRequestCannotMasqueradeAsAGateObservation() throws {
        XCTAssertThrowsError(try AuthorityMaintenanceUnboundGateResponse(request: request(kind: .release),
            hold: .neverHeld, admission: .available))
        XCTAssertThrowsError(try AuthorityMaintenanceUnboundRequest(kind: .gate, installationID: bytes(1), accountID: bytes(2),
            attemptID: bytes(3), revision: bytes(4), rowDigest: bytes(5, 31), pendingRevision: bytes(6), intentID: bytes(7),
            gate: .init(device: 1, inode: 2), authorityIncarnation: bytes(8), challenge: bytes(9)))
    }
    func testOversizedUntrustedMessagesRefuseBeforeUse() throws {
        let limits = try CBORLimits(maxBytes: 2048, maxDepth: 2, maxItems: 8)
        let oversized = try DeterministicCBOR.encode(.map([0: .bytes(Data(repeating: 0, count: 1020))]), limits: limits)
        XCTAssertEqual(oversized.count, 1025)
        XCTAssertThrowsError(try AuthorityMaintenanceUnboundRequest.decode(oversized)) { XCTAssertEqual($0 as? CBORError, .limitExceeded(.bytes)) }
        XCTAssertThrowsError(try AuthorityMaintenanceUnboundGateResponse.decode(oversized)) { XCTAssertEqual($0 as? CBORError, .limitExceeded(.bytes)) }
    }
    func testCommandIdleRefusesEachOutstandingPairingOwner() throws {
        let admission = try AuthorityMaintenancePairingAdmission(accountID: bytes(2), incarnation: bytes(8))
        try admission.withUnboundCommandIdle {}
        func refuses(_ expected: AuthorityMaintenancePairingAdmission.UnboundCommandError = .busy) {
            XCTAssertThrowsError(try admission.withUnboundCommandIdle {}) { XCTAssertEqual($0 as? AuthorityMaintenancePairingAdmission.UnboundCommandError, expected) }
        }
        let stage = try admission.reserveStage()
        refuses(); stage.close(); try admission.withUnboundCommandIdle {}
        let connection = try admission.openConnection(attemptID: bytes(3), revision: bytes(4))
        refuses()
        _ = try connection.blockNewStages(matching: connection.binding)
        refuses()
        let shutdown = try connection.transferToShutdown(matching: connection.binding)
        refuses()
        let marker = try AuthorityMaintenanceCloseMarker(binding: shutdown.binding, macID: bytes(10),
            installationID: bytes(1), releaseDigest: bytes(11, 32), codeHash: bytes(12, 32),
            directoryID: bytes(13), ownerUID: 501, gate: .init(device: 1, inode: 2))
        try shutdown.retainCloseMarker(marker)
        XCTAssertEqual(try admission.claimCloseMarker(), marker)
        refuses(.stopping); admission.close(); refuses(.stopping)
    }
}
