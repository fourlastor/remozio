import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityMaintenancePairingAdmissionTests: XCTestCase {
    private final class Box<Value: Sendable>: Sendable {
        private let state: Mutex<Value>
        init(_ value: Value) { state = Mutex(value) }
        var value: Value { get { state.withLock { $0 } } set { state.withLock { $0 = newValue } } }
    }
    private let wide = try! CBORLimits(maxBytes: 4096, maxDepth: 4, maxItems: 128)
    private func bytes(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private func gate(_ incarnation: UInt8 = 4) throws -> AuthorityMaintenancePairingAdmission {
        try .init(accountID: bytes(1), incarnation: bytes(incarnation))
    }
    private func connection(_ gate: AuthorityMaintenancePairingAdmission) throws -> AuthorityMaintenancePairingAdmission.Connection {
        try gate.openConnection(attemptID: bytes(2), revision: bytes(3))
    }
    private func changed(_ b: AuthorityMaintenanceBinding, field: Int) throws -> AuthorityMaintenanceBinding {
        var values = [b.accountID, b.attemptID, b.revision, b.incarnation, b.connectionID]; values[field] = bytes(99)
        return try .init(accountID: values[0], attemptID: values[1], revision: values[2], incarnation: values[3], connectionID: values[4])
    }
    func testBindingRoundTripAndEveryIdentifierBound() throws {
        let b = try connection(gate()).binding
        XCTAssertEqual(try AuthorityMaintenanceBinding.decode(b.encoded), b)
        for field in 0..<5 {
            for count in [0, 15, 17, 257] {
                var v = [b.accountID, b.attemptID, b.revision, b.incarnation, b.connectionID]; v[field] = Data(repeating: 1, count: count)
                XCTAssertThrowsError(try AuthorityMaintenanceBinding(accountID: v[0], attemptID: v[1], revision: v[2], incarnation: v[3], connectionID: v[4]))
            }
        }
    }
    func testBindingRejectsUnknownMissingNoncanonicalAndOversizedInput() throws {
        let b = try connection(gate()).binding, encoded = try b.encoded
        guard case .map(let original) = try DeterministicCBOR.decode(encoded, limits: wide) else { return XCTFail() }
        var unknown = original; unknown[6] = .null
        var missing = original; missing.removeValue(forKey: 5)
        var wrongVersion = original; wrongVersion[0] = .unsigned(2)
        for fields in [unknown, missing, wrongVersion] {
            XCTAssertThrowsError(try AuthorityMaintenanceBinding.decode(DeterministicCBOR.encode(.map(fields), limits: wide)))
        }
        for key in UInt64(1)...5 {
            var wrongType = original; wrongType[key] = .unsigned(1)
            XCTAssertThrowsError(try AuthorityMaintenanceBinding.decode(DeterministicCBOR.encode(.map(wrongType), limits: wide)))
        }
        var noncanonical = encoded; noncanonical.replaceSubrange(2..<3, with: [0x18, 0x01])
        for bytes in [noncanonical, Data(encoded.dropLast()), encoded + Data([0]), Data(repeating: 0, count: 257)] {
            XCTAssertThrowsError(try AuthorityMaintenanceBinding.decode(bytes))
        }
    }
    func testBlockPreservesExistingStagesAndRepeatedObservationCannotReplaceBinding() throws {
        let g = try gate(), a = try g.reserveStage(), b = try g.reserveStage(), c = try connection(g)
        XCTAssertEqual(try c.blockNewStages(matching: c.binding), 2)
        XCTAssertThrowsError(try g.reserveStage())
        a.close(); a.close()
        XCTAssertEqual(try c.blockNewStages(matching: c.binding), 1)
        for field in 0..<5 { XCTAssertThrowsError(try c.blockNewStages(matching: changed(c.binding, field: field))) }
        XCTAssertEqual(try g.stagedReservations(), 1)
        b.close(); XCTAssertEqual(try c.blockNewStages(matching: c.binding), 0)
        XCTAssertThrowsError(try g.reserveStage()); c.close()
    }
    func testCancelAndReopenReleaseOnlyTheirExactOwnerWithoutClearingStages() throws {
        let g = try gate(), stage = try g.reserveStage(), c = try connection(g)
        XCTAssertEqual(try c.blockNewStages(matching: c.binding), 1)
        for field in 0..<5 { XCTAssertThrowsError(try c.release(matching: changed(c.binding, field: field))) }
        XCTAssertThrowsError(try g.reserveStage())
        try c.release(matching: c.binding)
        XCTAssertEqual(try g.stagedReservations(), 1)
        let next = try g.reserveStage(); XCTAssertEqual(try g.stagedReservations(), 2)
        XCTAssertThrowsError(try c.blockNewStages(matching: c.binding))
        stage.close(); XCTAssertEqual(try g.stagedReservations(), 1); next.close()
    }
    func testLateDisconnectCannotReleaseANewerBinding() throws {
        let g = try gate(), old = try connection(g), replacement = try connection(g)
        XCTAssertNotEqual(old.binding.connectionID, replacement.binding.connectionID)
        XCTAssertEqual(try old.blockNewStages(matching: old.binding), 0)
        XCTAssertThrowsError(try replacement.blockNewStages(matching: replacement.binding))
        old.close(); XCTAssertEqual(try replacement.blockNewStages(matching: replacement.binding), 0)
        old.close(); try old.release(matching: old.binding)
        XCTAssertThrowsError(try g.reserveStage())
        replacement.close(); let stage = try g.reserveStage(); stage.close()
    }
    func testDecodedForeignAndRestartBindingsCannotMoveAnOwnedRestriction() throws {
        let g = try gate(), c = try connection(g), restarted = try gate(5), next = try connection(restarted)
        let decoded = try AuthorityMaintenanceBinding.decode(c.binding.encoded)
        XCTAssertThrowsError(try next.blockNewStages(matching: decoded))
        XCTAssertEqual(try next.blockNewStages(matching: next.binding), 0)
        c.close(); XCTAssertThrowsError(try restarted.reserveStage())
        next.close(); let stage = try restarted.reserveStage(); stage.close()
    }
    func testClosedAdmissionCannotLookEmptyOrReopenAfterLateCleanup() throws {
        let g = try gate(), stage = try g.reserveStage(), c = try connection(g)
        XCTAssertEqual(try c.blockNewStages(matching: c.binding), 1); g.close()
        stage.close(); c.close(); try c.release(matching: c.binding)
        XCTAssertThrowsError(try g.stagedReservations()); XCTAssertThrowsError(try g.reserveStage())
        XCTAssertThrowsError(try connection(g)); XCTAssertThrowsError(try c.blockNewStages(matching: c.binding))
    }
    func testOwnerAndStageDestructionReleaseOnlyTheirOwnReservations() throws {
        let g = try gate(), retained = try g.reserveStage()
        do { let temporary = try g.reserveStage(); XCTAssertEqual(try g.stagedReservations(), 2); withExtendedLifetime(temporary) {} }
        XCTAssertEqual(try g.stagedReservations(), 1)
        do { let c = try connection(g); XCTAssertEqual(try c.blockNewStages(matching: c.binding), 1); XCTAssertThrowsError(try g.reserveStage()) }
        let next = try g.reserveStage(); retained.close(); XCTAssertEqual(try g.stagedReservations(), 1); next.close()
    }
    func testCrossThreadStageRemainsOwnedThroughBlockAndExplicitReopen() throws {
        let g = try gate(), c = try connection(g), entered = DispatchSemaphore(value: 0)
        let resume = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0), failed = Box(false)
        defer { resume.signal(); c.close() }
        DispatchQueue.global().async {
            do {
                let stage = try g.reserveStage(); entered.signal()
                if resume.wait(timeout: .now() + 3) != .success { failed.value = true }
                stage.close()
            } catch { failed.value = true; entered.signal() }
            completed.signal()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(try c.blockNewStages(matching: c.binding), 1); XCTAssertThrowsError(try g.reserveStage())
        try c.release(matching: c.binding); let newStage = try g.reserveStage()
        XCTAssertEqual(try g.stagedReservations(), 2)
        resume.signal(); XCTAssertEqual(completed.wait(timeout: .now() + 3), .success); XCTAssertFalse(failed.value)
        XCTAssertEqual(try g.stagedReservations(), 1); newStage.close()
    }
    func testConcurrentStageAndBlockHaveNoUncountedAdmissionGap() throws {
        for _ in 0..<40 {
            let g = try gate(), c = try connection(g), start = DispatchSemaphore(value: 0), done = DispatchGroup()
            let stage = Box<AuthorityMaintenancePairingAdmission.Stage?>(nil), count = Box(-1)
            done.enter(); DispatchQueue.global().async { start.wait(); stage.value = try? g.reserveStage(); done.leave() }
            done.enter(); DispatchQueue.global().async {
                start.wait(); count.value = (try? c.blockNewStages(matching: c.binding)) ?? -1; done.leave()
            }
            start.signal(); start.signal(); XCTAssertEqual(done.wait(timeout: .now() + 3), .success)
            XCTAssertEqual(count.value, stage.value == nil ? 0 : 1)
            XCTAssertEqual(try g.stagedReservations(), count.value); XCTAssertThrowsError(try g.reserveStage())
            stage.value?.close(); c.close()
        }
    }
}
