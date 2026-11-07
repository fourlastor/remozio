import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class DesignatedUpdateOwnerTests: XCTestCase {
    private func rejectsOwner<Value>(_ body: () throws -> Value, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? UpdateSchedulingCandidateLeaseError, .notDesignatedUpdateOwner, file: file, line: line)
        }
    }
    private func control(_ reply: RootUpdateSchedulingReply, _ f: RootUpdateSchedulingFixture) throws -> UpdateSchedulingControl {
        try .decode(RootUpdateSchedulingChallenge.decode(reply.canonicalChallenge, limits: f.data.limits).canonicalControl,
            limits: f.data.limits)
    }
    private func replaceOwnerForFault(_ f: UpdateCandidateStorageFixture, owner: Data?) throws {
        let previous = try XCTUnwrap(f.store.updateAdmissionRegistration())
        let value = try UpdateAdmissionRegistrationRecord(macID: previous.macID, installationID: previous.installationID,
            machine: previous.machine, accounts: previous.accounts, designatedOwner: owner, revision: previous.revision)
        let hex = try value.encoded.map { String(format: "%02x", $0) }.joined()
        try f.sql("UPDATE update_admission_registration_v1 SET record=x'\(hex)' WHERE id=1")
    }
    func testDesignatedOwnerDeferralSurvivesMachineReopen() throws {
        let f = try RootUpdateSchedulingFixture()
        XCTAssertEqual(try f.data.machine.store.updateAdmissionRegistration()?.designatedOwner, f.data.accountID)
        try f.data.machine.reopen()
        let accepted = try f.consume(control(f.issue(.deferUpdate), f))
        XCTAssertEqual(accepted.requestedAction, .deferUpdate)
        XCTAssertEqual(try f.status(), accepted)
    }
    func testAnotherAccountCannotObtainARootDeferralChallenge() throws {
        let f = try RootUpdateSchedulingFixture(updateOwner: .otherAccount), before = try f.data.store.read()
        let offered = try f.status(); var signed = false
        rejectsOwner { try f.issue(.deferUpdate, sign: { _ in signed = true; return Data() }) }
        XCTAssertFalse(signed); XCTAssertFalse(f.owner.retired)
        XCTAssertEqual(try f.data.store.read(), before); XCTAssertEqual(try f.status(), offered)
    }
    func testMissingDesignationCannotBeInferredFromTheCurrentAccount() throws {
        for selection in [UpdateSchedulingAccountFixture.UpdateOwner.undesignated, .absentRegistration] {
            let f = try RootUpdateSchedulingFixture(updateOwner: selection)
            let machine = try f.data.machine.store.retainedRuntimeCompatibilityInputs(), account = try f.data.store.read()
            rejectsOwner { try f.issue(.deferUpdate) }
            XCTAssertEqual(try f.data.machine.store.retainedRuntimeCompatibilityInputs(), machine)
            XCTAssertEqual(try f.data.store.read(), account)
            XCTAssertNil(try f.data.machine.store.updateAdmissionRegistration()?.designatedOwner)
        }
    }
    func testOwnerLossRefusesAnExistingRootChallengeWithoutConsumingIt() throws {
        let f = try RootUpdateSchedulingFixture(), pending = try control(f.issue(.deferUpdate), f)
        try replaceOwnerForFault(f.data.machine, owner: nil)
        let before = try f.data.store.read()
        rejectsOwner { try f.consume(pending) }
        XCTAssertEqual(try f.data.store.read(), before)
        XCTAssertNil(try f.data.db.read { try $0.consumedUpdateSchedulingRevision(operationID: pending.operationID) })
        try replaceOwnerForFault(f.data.machine, owner: f.data.accountID)
        XCTAssertEqual(try f.consume(pending).requestedAction, .deferUpdate)
    }
    func testJournalConsumptionAlsoChecksTheDesignatedOwner() throws {
        let f = try UpdateSchedulingAccountFixture(); try f.install(); let offered = try f.offer()
        let pending = try f.issue(.deferUpdate)
        try replaceOwnerForFault(f.machine, owner: nil)
        let before = try f.store.read()
        rejectsOwner { try f.consume(pending) }
        XCTAssertEqual(try f.store.read(), before)
        XCTAssertEqual(try f.commits.read { try $0.updateSchedulingIntent() }, offered)
        XCTAssertNil(try f.commits.read { try $0.consumedUpdateSchedulingRevision(operationID: pending.operationID) })
    }
    func testNonOwnerDrainAndCancelControlsRemainAvailableForItsAccount() throws {
        let f = try RootUpdateSchedulingFixture(updateOwner: .otherAccount)
        for action in [UpdateSchedulingAction.installWhenCurrentWorkFinishes, .cancelDrain] {
            let accepted = try f.consume(control(f.issue(action), f))
            XCTAssertEqual(accepted.requestedAction, action)
            XCTAssertEqual(try f.status(), accepted)
        }
    }
    func testEscapedCandidateCannotReuseTheOwnerDesignation() throws {
        let f = try UpdateSchedulingAccountFixture(); try f.install(); _ = try f.offer()
        var escaped: LiveUpdateSchedulingCandidate?
        try f.withCandidate { candidate in
            try candidate.requireAction(.deferUpdate, macID: f.macID, accountID: f.accountID)
            escaped = candidate
        }
        XCTAssertThrowsError(try XCTUnwrap(escaped).requireAction(.deferUpdate, macID: f.macID, accountID: f.accountID)) {
            XCTAssertEqual($0 as? UpdateSchedulingCandidateLeaseError, .expired)
        }
    }
    func testAnOwnerLeaseStillRejectsAForeignMacOrAccount() throws {
        let f = try UpdateSchedulingAccountFixture(); try f.install(); _ = try f.offer()
        try f.withCandidate { candidate in
            for (mac, account) in [(f.id(99), f.accountID), (f.macID, f.id(99))] {
                XCTAssertThrowsError(try candidate.requireAction(.deferUpdate, macID: mac, accountID: account)) {
                    XCTAssertEqual($0 as? UpdateSchedulingCandidateLeaseError, .wrongScope)
                }
            }
        }
    }
}
