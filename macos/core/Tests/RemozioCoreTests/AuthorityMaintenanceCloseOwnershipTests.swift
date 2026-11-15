import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceCloseOwnershipTests: XCTestCase {
    private func armed() throws -> (AuthorityMaintenancePairingAdmission, AuthorityMaintenancePairingAdmission.Connection,
        AuthorityMaintenancePairingAdmission.Shutdown, AuthorityMaintenanceCloseMarker) {
        let g = try AuthorityMaintenancePairingAdmission(accountID: maintenanceCloseBytes(1), incarnation: maintenanceCloseBytes(4))
        let c = try g.openConnection(attemptID: maintenanceCloseBytes(2), revision: maintenanceCloseBytes(3))
        _ = try c.blockNewStages(matching: c.binding); let shutdown = try c.transferToShutdown(matching: c.binding)
        return (g, c, shutdown, try maintenanceCloseMarker(binding: c.binding))
    }
    func testUnarmedAndMetadataOnlyCannotCreateACloseClaim() throws {
        let g = try AuthorityMaintenancePairingAdmission(accountID: maintenanceCloseBytes(1), incarnation: maintenanceCloseBytes(4))
        XCTAssertNil(try g.claimCloseMarker())
        let (armed, _, _, _) = try self.armed(); XCTAssertThrowsError(try armed.claimCloseMarker())
    }
    func testExactClaimSurvivesExpectedTeardownAndRefusesCancelReopenAndReplacement() throws {
        let (g, c, shutdown, marker) = try armed(); try shutdown.retainCloseMarker(marker)
        XCTAssertEqual(try g.claimCloseMarker(), marker); c.close(); g.close()
        try g.requireCloseMarker(marker)
        XCTAssertThrowsError(try shutdown.cancel(matching: marker.binding))
        XCTAssertThrowsError(try shutdown.reopen(matching: marker.binding))
        XCTAssertThrowsError(try g.claimCloseMarker()); XCTAssertThrowsError(try g.reserveStage())
        XCTAssertThrowsError(try shutdown.retainCloseMarker(maintenanceCloseMarker(binding: marker.binding, installation: 99)))
    }
    func testCancelBeforeClaimAndUnboundCloseRetireTheMarker() throws {
        let (g, _, shutdown, marker) = try armed(); try shutdown.retainCloseMarker(marker)
        try shutdown.cancel(matching: marker.binding); XCTAssertNil(try g.claimCloseMarker())
        XCTAssertThrowsError(try g.requireCloseMarker(marker))
        let (other, _, owner, value) = try armed(); try owner.retainCloseMarker(value); other.close()
        XCTAssertThrowsError(try other.claimCloseMarker()); XCTAssertThrowsError(try other.requireCloseMarker(value))
    }
    func testForeignBindingAndChangedMetadataCannotReplaceAnArmedMarker() throws {
        let (g, _, shutdown, marker) = try armed()
        XCTAssertThrowsError(try shutdown.retainCloseMarker(maintenanceCloseMarker()))
        try shutdown.retainCloseMarker(marker)
        XCTAssertThrowsError(try shutdown.retainCloseMarker(maintenanceCloseMarker(binding: marker.binding, installation: 99)))
        XCTAssertEqual(try g.claimCloseMarker(), marker)
    }
    func testConcurrentCancelAndClaimHaveOnlyOneWinner() throws {
        for _ in 0..<24 {
            let (g, _, shutdown, marker) = try armed(); try shutdown.retainCloseMarker(marker)
            let wins = Mutex((claim: false, cancel: false)), group = DispatchGroup(), start = DispatchSemaphore(value: 0)
            group.enter(); DispatchQueue.global().async {
                start.wait(); if (try? g.claimCloseMarker()) != nil { wins.withLock { $0.claim = true } }; group.leave()
            }
            group.enter(); DispatchQueue.global().async {
                start.wait(); do { try shutdown.cancel(matching: marker.binding); wins.withLock { $0.cancel = true } } catch {}; group.leave()
            }
            start.signal(); start.signal(); XCTAssertEqual(group.wait(timeout: .now() + 2), .success)
            let result = wins.withLock { $0 }; XCTAssertNotEqual(result.claim, result.cancel)
            if result.claim { try g.requireCloseMarker(marker) } else { XCTAssertThrowsError(try g.requireCloseMarker(marker)) }
        }
    }
}
