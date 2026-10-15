import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeJobRegistrationTests: XCTestCase {
    private struct LostReply: Error {}
    private func job() throws -> InstalledAccountJobManifest {
        try .init(accountID: Data(repeating: 1, count: 16), role: .authority, executionUID: 0,
            userName: "root", bundlePath: MachineBootstrap.bundlePath)
    }
    private func output(_ job: InstalledAccountJobManifest) -> String {
        "system/\(job.declaration.label) = {\n\tpath = \(job.path)\n\ttype = LaunchDaemon\n\tstate = waiting\n\tprogram = \(job.executablePath)\n\targuments = {\n"
            + job.arguments.map { "\t\t" + $0 + "\n" }.joined() + "\t}\n\tusername = \(job.userName)\n\tgroup = \(job.groupName)\n\tproperties = runatload | keepalive | inferred program\n\tendpoints = {\n"
            + job.machServices.sorted().map { "\t\t\"" + $0 + "\" = {\n\t\t\tmanaged = 1\n\t\t\treset = 0\n\t\t\thide = 0\n\t\t}\n" }.joined()
            + "\t}\n\tenvironment = {\n\t\tEXAMPLE => synthetic\n\t}\n}\n"
    }
    func testOperationalObservationMatchesOnlyTheExactLoadedProgramArgumentsAndSourcePath() throws {
        let job = try job(), original = output(job), target = "system/" + job.declaration.label
        XCTAssertTrue(try LaunchdJobObservation.decode(Data(original.utf8), target: target).matches(job))
        for changed in [original.replacingOccurrences(of: "\tpath = " + job.path, with: "\tpath = /private/other.plist"),
                        original.replacingOccurrences(of: "\tprogram = " + job.executablePath, with: "\tprogram = /usr/bin/true"),
                        original.replacingOccurrences(of: "\t\t--command-configuration", with: "\t\t--configuration"),
                        original.replacingOccurrences(of: "\ttype = LaunchDaemon", with: "\ttype = LaunchAgent")] {
            XCTAssertFalse(try LaunchdJobObservation.decode(Data(changed.utf8), target: target).matches(job))
        }
    }
    func testUnknownTruncatedDuplicateAndMisScopedOutputNeverLooksAbsentOrMatching() throws {
        let job = try job(), original = output(job), target = "system/" + job.declaration.label
        for changed in [original.replacingOccurrences(of: target, with: "system/dev.remozio.other"), String(original.dropLast(2)),
                        original.replacingOccurrences(of: "\tpath = ", with: "\tother-path = "),
                        original.replacingOccurrences(of: "\tstate = waiting", with: "\tprogram = /usr/bin/true"),
                        original.replacingOccurrences(of: "\targuments = {", with: "\tunknown-arguments = {")] {
            XCTAssertThrowsError(try LaunchdJobObservation.decode(Data(changed.utf8), target: target))
        }
        XCTAssertThrowsError(try LaunchdJobObservation.decode(Data(repeating: 65, count: 65537), target: target))
        XCTAssertThrowsError(try LaunchdJobObservation.decode(Data([0xff]), target: target))
    }
    func testRetainedJobRejectsDifferentLoadedCredentialsEndpointsAndLaunchProperties() throws {
        let job = try job(), original = output(job), target = "system/" + job.declaration.label
        for changed in [original.replacingOccurrences(of: "username = root", with: "username = nobody"),
                        original.replacingOccurrences(of: "group = wheel", with: "group = staff"),
                        original.replacingOccurrences(of: "\t\t\"" + job.machServices.sorted()[0] + "\" = {", with: "\t\t\"dev.remozio.wrong\" = {"),
                        original.replacingOccurrences(of: "runatload | keepalive", with: "runatload"),
                        original.replacingOccurrences(of: "runatload | keepalive", with: "keepalive")] {
            XCTAssertFalse(try LaunchdJobObservation.decode(Data(changed.utf8), target: target).matches(job))
        }
        for changed in [original.replacingOccurrences(of: "managed = 1", with: "managed = 0"),
                        original.replacingOccurrences(of: "reset = 0", with: "reset = 1"),
                        original.replacingOccurrences(of: "hide = 0", with: "hide = 1"),
                        original.replacingOccurrences(of: "\tendpoints = {", with: "\tunknown-endpoints = {"),
                        original.replacingOccurrences(of: "\tgroup = wheel", with: "\tusername = nobody")] {
            XCTAssertThrowsError(try LaunchdJobObservation.decode(Data(changed.utf8), target: target))
        }
        let defaults = original.replacingOccurrences(of: "\tusername = root\n", with: "").replacingOccurrences(of: "\tgroup = wheel\n", with: "")
        XCTAssertTrue(try LaunchdJobObservation.decode(Data(defaults.utf8), target: target).matches(job))
    }
    func testTransportRequiresItsExplicitLoadedUserAndGroup() throws {
        let account = Data(repeating: 2, count: 16)
        let job = try InstalledAccountJobManifest(accountID: account, role: .transport, executionUID: 450,
            userName: ServiceAccountClaim.recordName(accountID: account, role: .transport), bundlePath: MachineBootstrap.bundlePath)
        let original = output(job), target = "system/" + job.declaration.label
        XCTAssertTrue(try LaunchdJobObservation.decode(Data(original.utf8), target: target).matches(job))
        for changed in [original.replacingOccurrences(of: "\tusername = " + job.userName + "\n", with: ""),
                        original.replacingOccurrences(of: "\tgroup = " + job.groupName + "\n", with: ""),
                        original.replacingOccurrences(of: "username = " + job.userName, with: "username = root")] {
            XCTAssertFalse(try LaunchdJobObservation.decode(Data(changed.utf8), target: target).matches(job))
        }
    }
    func testMatchingRegistrationDoesNotBootstrapOrMutateTheExistingJob() throws {
        var checks = 0
        try RuntimeJobRegistration.reconcile(verifyCurrent: { checks += 1 }, inspect: { .matching },
            bootstrap: { XCTFail("A matching job must be retained") })
        XCTAssertEqual(checks, 2)
    }
    func testConflictingOrUnknownRegistrationCannotBeReplaced() throws {
        XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(verifyCurrent: {}, inspect: { .conflicting },
            bootstrap: { XCTFail("Never replace an unclaimed job") })) { XCTAssertEqual($0 as? RuntimeActivationError, .conflictingPlan) }
        XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(verifyCurrent: {}, inspect: { throw LostReply() },
            bootstrap: { XCTFail("Unknown is not absent") }))
    }
    func testLostBootstrapAcknowledgmentReconcilesTheExactJobWithoutASecondMutation() throws {
        var reads = 0, starts = 0
        try RuntimeJobRegistration.reconcile(verifyCurrent: {}, inspect: { reads += 1; return reads == 1 ? .absent : .matching }, bootstrap: {
            starts += 1; throw LostReply()
        })
        XCTAssertEqual(reads, 2); XCTAssertEqual(starts, 1)
    }
    func testFailedAndConflictingBootstrapOutcomesRemainRecoverableWithoutDeletion() throws {
        for conflict in [false, true] {
            var reads = 0, starts = 0
            XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(verifyCurrent: {}, inspect: {
                reads += 1; return reads == 1 || !conflict ? .absent : .conflicting
            }, bootstrap: { starts += 1 })) {
                XCTAssertEqual($0 as? RuntimeActivationError, conflict ? .conflictingPlan : .unavailable)
            }
            XCTAssertEqual(starts, 1)
        }
    }
    func testAChangedScopeStopsBeforeAnyNativeMutation() throws {
        var checks = 0
        XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(verifyCurrent: { checks += 1; if checks == 2 { throw LostReply() } },
            inspect: { .absent }, bootstrap: { XCTFail("Scope changed before bootstrap") }))
    }
    func testNativeSystemRegistrationRefusesOrdinaryUsersBeforeValidationOrLaunchctl() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner Root guard") }
        XCTAssertThrowsError(try RuntimeJobRegistration.ensure(job(), verifyCurrent: { XCTFail("Root guard must run first") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
