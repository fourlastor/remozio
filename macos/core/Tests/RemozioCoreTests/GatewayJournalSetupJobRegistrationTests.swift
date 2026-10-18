import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayJournalSetupJobRegistrationTests: XCTestCase {
    private struct LostReply: Error {}
    private typealias Registration = GatewayJournalSetupJobRegistration
    private func fixture(_ body: (GatewayJournalSetupJobManifest) throws -> Void) throws {
        try GatewayJournalSetupNativeModelTests.fixture { _, _, configuration in
            try body(GatewayJournalSetupJobManifest(configuration: configuration))
        }
    }
    private func output(_ job: GatewayJournalSetupJobManifest, state: String = "not running", active: UInt64 = 0, pid: Int32? = nil) -> String {
        "system/\(job.label) = {\n\tpath = \(job.path)\n\ttype = LaunchDaemon\n\tstate = \(state)\n\tactive count = \(active)\n"
            + (pid.map { "\tpid = \($0)\n" } ?? "")
            + "\tprogram = \(job.executablePath)\n\targuments = {\n" + job.arguments.map { "\t\t" + $0 + "\n" }.joined()
            + "\t}\n\tusername = \(job.userName)\n\tgroup = \(job.userName)\n\tproperties = inferred program\n\tendpoints = {\n"
            + "\t\t\"\(job.label)\" = {\n\t\t\tmanaged = 1\n\t\t\treset = 0\n\t\t\thide = 0\n\t\t}\n\t}\n}\n"
    }
    func testOnlyAnExactStoppedJobWithNoPIDOrActiveCountCanBeRemoved() throws {
        try fixture { job in
            func observe(_ text: String) throws -> Registration.Observation {
                try GatewayJournalSetupJobObservation.decode(Data(text.utf8), target: "system/" + job.label).classify(job)
            }
            XCTAssertEqual(try observe(output(job)), .matchingStopped)
            XCTAssertEqual(try observe(output(job, state: "running", active: 1, pid: 123)), .matchingActive)
            XCTAssertEqual(try observe(output(job, pid: 123)), .matchingActive)
            XCTAssertEqual(try observe(output(job, active: 1)), .matchingActive)
            XCTAssertEqual(try observe(output(job, state: "waiting")), .matchingActive)
            let changed = output(job).replacingOccurrences(of: "\tusername = " + job.userName, with: "\tusername = root")
            XCTAssertEqual(try observe(changed), .conflicting)
        }
    }
    func testMissingDuplicateAndMalformedProcessFieldsNeverLookStopped() throws {
        try fixture { job in
            let original = output(job), target = "system/" + job.label
            for text in [original.replacingOccurrences(of: "\tstate = not running\n", with: ""),
                         original.replacingOccurrences(of: "\tactive count = 0\n", with: ""),
                         original.replacingOccurrences(of: "\tactive count = 0", with: "\tactive count = -1"),
                         original.replacingOccurrences(of: "\tactive count = 0", with: "\tactive count = 00"),
                         original.replacingOccurrences(of: "\tstate = not running", with: "\tstate = not running\n\tstate = running"),
                         original.replacingOccurrences(of: "\tstate = not running", with: "\tstate = not running\n\tpid = 0"),
                         original.replacingOccurrences(of: "\tstate = not running", with: "\tstate = not running\n\tpid = 2147483648"),
                         original.replacingOccurrences(of: "\tstate = not running", with: "\tstate = not running\n\tpid = 123\n\tpid = 123")] {
                XCTAssertThrowsError(try GatewayJournalSetupJobObservation.decode(Data(text.utf8), target: target))
            }
        }
    }
    func testMatchingJobIsRetainedAndLostBootstrapReplyIsReconciledOnce() throws {
        for existing in [Registration.Observation.matchingStopped, .matchingActive] {
            try Registration.reconcileRegistration(verifyCurrent: {}, inspect: { existing }, bootstrap: { XCTFail("Never replace an exact retained job") })
        }
        var reads = 0, starts = 0
        try Registration.reconcileRegistration(verifyCurrent: {}, inspect: { reads += 1; return reads == 1 ? .absent : .matchingStopped },
            bootstrap: { starts += 1; throw LostReply() })
        XCTAssertEqual(reads, 2); XCTAssertEqual(starts, 1)
    }
    func testConflictingAndUnknownRegistrationNeverMutateTheJob() throws {
        XCTAssertThrowsError(try Registration.reconcileRegistration(verifyCurrent: {}, inspect: { .conflicting }, bootstrap: { XCTFail() }))
        XCTAssertThrowsError(try Registration.reconcileRegistration(verifyCurrent: {}, inspect: { throw LostReply() }, bootstrap: { XCTFail() }))
    }
    func testActiveOrNewlyStartedJobKeepsCleanupPendingWithoutRemoval() throws {
        XCTAssertFalse(try Registration.reconcileCleanup(verifyCurrent: {}, inspect: { .matchingActive }, bootout: { XCTFail("Active work must remain owned") }))
        var reads = 0
        XCTAssertFalse(try Registration.reconcileCleanup(verifyCurrent: {}, inspect: { reads += 1; return reads == 1 ? .matchingStopped : .matchingActive }, bootout: { XCTFail("A new process appeared") }))
    }
    func testExactStoppedJobReconcilesALostBootoutReplyAndAbsentCleanupIsIdempotent() throws {
        var reads = 0, removals = 0
        XCTAssertTrue(try Registration.reconcileCleanup(verifyCurrent: {}, inspect: { reads += 1; return reads < 3 ? .matchingStopped : .absent },
            bootout: { removals += 1; throw LostReply() }))
        XCTAssertEqual(reads, 3); XCTAssertEqual(removals, 1)
        XCTAssertTrue(try Registration.reconcileCleanup(verifyCurrent: {}, inspect: { .absent }, bootout: { XCTFail() }))
    }
    func testUnknownAndConflictingCleanupOutcomesCannotReportCompletion() throws {
        for conflict in [false, true] {
            var reads = 0, removals = 0
            XCTAssertThrowsError(try Registration.reconcileCleanup(verifyCurrent: {}, inspect: {
                reads += 1
                if reads < 3 { return .matchingStopped }
                if conflict { return .conflicting }; throw LostReply()
            }, bootout: { removals += 1 }))
            XCTAssertEqual(removals, 1)
        }
    }
    func testChangedScopeStopsCleanupBeforeRemoval() throws {
        var checks = 0
        XCTAssertThrowsError(try Registration.reconcileCleanup(verifyCurrent: { checks += 1; if checks == 2 { throw LostReply() } },
            inspect: { .matchingStopped }, bootout: { XCTFail("Scope changed") }))
    }
    func testNativeOperationsRefuseOrdinaryUsersBeforeAnyCallbackOrCommand() throws {
        try fixture { job in
            XCTAssertThrowsError(try Registration.ensure(job, verifyCurrent: { XCTFail() })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
            XCTAssertThrowsError(try Registration.cleanupStopped(job, verifyCurrent: { XCTFail() })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        }
    }
}
