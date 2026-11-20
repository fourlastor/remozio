import Foundation
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceUnboundHoldTests: XCTestCase {
    func testNeverHeldDoesNotManufactureAReleaseAcknowledgement() throws {
        let records = try UnboundAuthorityRecords(), pairing = try AuthorityMaintenancePairingAdmission(
            accountID: records.authorized.scope.authority.accountID, incarnation: unboundAuthorityBytes(41))
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(nil))
        try hold.bindUnboundAuthority(unboundAuthorityBytes(41))
        XCTAssertEqual(try hold.unboundObservation(records.pending, incarnation: unboundAuthorityBytes(41)), .neverHeld)
        XCTAssertThrowsError(try hold.releaseUnbound(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing))
        try hold.requireOpen()
    }
    func testExactStartupOriginReleasesOnceAndDuplicateKeepsTheSameIntent() throws {
        let records = try UnboundAuthorityRecords(), pairing = try AuthorityMaintenancePairingAdmission(
            accountID: records.authorized.scope.authority.accountID, incarnation: unboundAuthorityBytes(41))
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(records.authorized))
        try hold.bindUnboundAuthority(unboundAuthorityBytes(41))
        XCTAssertEqual(try hold.unboundObservation(records.pending, incarnation: unboundAuthorityBytes(41)), .held)
        XCTAssertEqual(try hold.releaseUnbound(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing), .released)
        XCTAssertEqual(try hold.releaseUnbound(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing), .alreadyReleased)
        XCTAssertEqual(try hold.unboundObservation(records.pending, incarnation: unboundAuthorityBytes(41)), .released)
        try hold.requireOpen()
    }
    func testPendingStartupOriginMatchesTheWholeDescriptorAndScope() throws {
        let records = try UnboundAuthorityRecords(), pairing = try AuthorityMaintenancePairingAdmission(
            accountID: records.authorized.scope.authority.accountID, incarnation: unboundAuthorityBytes(41))
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(records.pending))
        try hold.bindUnboundAuthority(unboundAuthorityBytes(41))
        XCTAssertEqual(try hold.releaseUnbound(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing), .released)
        XCTAssertThrowsError(try hold.bindUnboundAuthority(unboundAuthorityBytes(43)))
    }
    func testCommandCreatedHoldCannotBecomeAnUnboundStartupHold() throws {
        let records = try UnboundAuthorityRecords(), pairing = try AuthorityMaintenancePairingAdmission(
            accountID: records.authorized.scope.authority.accountID, incarnation: unboundAuthorityBytes(41))
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(nil))
        try hold.bindUnboundAuthority(unboundAuthorityBytes(41))
        let draining = try RuntimeMaintenanceWindowRecord(id: records.authorized.id, revision: unboundAuthorityBytes(50),
            purpose: .retainedRuntime, scope: records.authorized.scope, phase: .draining, service: .notStopped)
        try hold.retain(draining)
        XCTAssertThrowsError(try hold.releaseUnbound(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing))
        XCTAssertThrowsError(try hold.requireOpen())
    }
    func testStagedAndArmedPairingOwnersPreventTheLocalRelease() throws {
        let records = try UnboundAuthorityRecords(), pairing = try AuthorityMaintenancePairingAdmission(
            accountID: records.authorized.scope.authority.accountID, incarnation: unboundAuthorityBytes(41))
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(records.authorized))
        try hold.bindUnboundAuthority(unboundAuthorityBytes(41))
        let stage = try pairing.reserveStage()
        XCTAssertThrowsError(try hold.releaseUnbound(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing)); stage.close()
        let owner = try pairing.openConnection(attemptID: unboundAuthorityBytes(44), revision: unboundAuthorityBytes(45))
        _ = try owner.blockNewStages(matching: owner.binding)
        let shutdown = try owner.transferToShutdown(matching: owner.binding)
        XCTAssertThrowsError(try hold.releaseUnbound(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing))
        XCTAssertThrowsError(try hold.requireOpen()); withExtendedLifetime(shutdown) {}
    }
    func testUnknownStartupRemainsClosed() throws {
        let records = try UnboundAuthorityRecords(), pairing = try AuthorityMaintenancePairingAdmission(
            accountID: records.authorized.scope.authority.accountID, incarnation: unboundAuthorityBytes(41))
        let hold = AuthorityMaintenanceAdmissionHold(projection: .startup { throw RuntimePreparationError.changedScope })
        try hold.bindUnboundAuthority(unboundAuthorityBytes(41))
        XCTAssertThrowsError(try hold.releaseUnbound(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing))
        XCTAssertEqual(try hold.unboundObservation(records.pending, incarnation: unboundAuthorityBytes(41)), .unknown)
        let files = try UpdateAdmissionTestFixture()
        let response = try AuthorityMaintenanceGateObservation.captureUnbound(request: records.request(.gate),
            incarnation: unboundAuthorityBytes(41), hold: hold, boundary: .init(machine: files.open()),
            gateIdentity: records.gate, read: { records.pending })
        XCTAssertEqual(try AuthorityMaintenanceUnboundGateResponse.decode(response.encoded).hold.rawValue, 4)
        XCTAssertThrowsError(try hold.requireOpen())
    }
    func testOpenPreviousAttemptIsNeverHeldButAForeignHeldAttemptRefuses() throws {
        let old = try UnboundAuthorityRecords(), next = try UnboundAuthorityRecords(windowID: unboundAuthorityBytes(71))
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: old.authorized.scope.authority.accountID,
            incarnation: unboundAuthorityBytes(41))
        let hold = AuthorityMaintenanceAdmissionHold(projection: try old.projection(old.authorized))
        try hold.bindUnboundAuthority(unboundAuthorityBytes(41))
        XCTAssertThrowsError(try hold.unboundObservation(next.pending, incarnation: unboundAuthorityBytes(41)))
        let binding = try AuthorityMaintenanceBinding(accountID: old.authorized.scope.authority.accountID,
            attemptID: old.authorized.id, revision: old.authorized.revision,
            incarnation: unboundAuthorityBytes(41), connectionID: unboundAuthorityBytes(72))
        let pending = try RuntimeMaintenanceWindowRecord(id: old.authorized.id, revision: unboundAuthorityBytes(73),
            purpose: .retainedRuntime, scope: old.authorized.scope, phase: .reopenPending,
            service: .notStopped, shutdownBinding: binding)
        try hold.reopen(pending, binding: binding, incarnation: unboundAuthorityBytes(41), releaseBinding: {})
        XCTAssertEqual(try hold.unboundObservation(next.pending, incarnation: unboundAuthorityBytes(41)), .neverHeld)
    }
    func testPendingStartupRejectsAnotherDescriptorAndFullScope() throws {
        let records = try UnboundAuthorityRecords(), source = records.pending
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: source.scope.authority.accountID, incarnation: unboundAuthorityBytes(41))
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(source))
        try hold.bindUnboundAuthority(unboundAuthorityBytes(41))
        let descriptor = try RuntimeMaintenanceUnboundRelease(authorized: records.authorized, previous: records.authorized,
            pendingRevision: unboundAuthorityBytes(80), intentID: unboundAuthorityBytes(81))
        let different = try RuntimeMaintenanceWindowRecord(id: source.id, revision: descriptor.pendingRevision,
            purpose: source.purpose, scope: source.scope, phase: .reopenPending, unboundRelease: descriptor)
        XCTAssertThrowsError(try hold.releaseUnbound(different, incarnation: unboundAuthorityBytes(41), pairing: pairing))
        let scope = source.scope
        let changed = try RuntimeMaintenanceWindowRecord.Scope(macID: scope.macID, installationID: scope.installationID,
            authority: scope.authority, target: scope.target, releaseDigest: scope.releaseDigest,
            candidateDigest: unboundAuthorityBytes(82, 32), authorityPolicyDigest: scope.authorityPolicyDigest,
            operationDigest: scope.operationDigest, restorationDigest: scope.restorationDigest,
            mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
            targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
        let foreign = try RuntimeMaintenanceWindowRecord(id: source.id, revision: source.revision,
            purpose: source.purpose, scope: changed, phase: .reopenPending, unboundRelease: source.unboundRelease)
        XCTAssertThrowsError(try hold.releaseUnbound(foreign, incarnation: unboundAuthorityBytes(41), pairing: pairing))
        XCTAssertThrowsError(try hold.requireOpen())
        XCTAssertEqual(try hold.releaseUnbound(source, incarnation: unboundAuthorityBytes(41), pairing: pairing), .released)
    }

}
