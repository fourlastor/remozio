import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeJobStopSessionTests: XCTestCase {
    private enum Failure: Error { case expected }
    private final class Witness: RuntimeJobExitWitness {
        let processID: pid_t
        var exited = false
        var unavailable = false
        init(_ pid: pid_t) { processID = pid }
        func hasExited() throws -> Bool { if unavailable { throw Failure.expected }; return exited }
    }
    private func job() throws -> InstalledAccountJobManifest {
        try .init(accountID: Data(repeating: 1, count: 16), role: .authority, executionUID: 0,
            userName: "root", bundlePath: MachineBootstrap.bundlePath)
    }
    func testReadOnlyRemovalValidationNeverBootsOutOrCapturesAProcess() throws {
        var observation = RuntimeJobStopSession.Observation.absent
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { observation },
            capture: { _ in XCTFail("Read-only check captured a process"); throw Failure.expected },
            bootout: { XCTFail("Read-only check removed a job") })
        try session.requireRemoved()
        observation = .matching(100); XCTAssertThrowsError(try session.requireRemoved())
        observation = .matching(nil); XCTAssertThrowsError(try session.requireRemoved())
        observation = .conflicting
        XCTAssertThrowsError(try session.requireRemoved()) { XCTAssertEqual($0 as? RuntimeActivationError, .conflictingPlan) }
    }
    func testReadOnlyRemovalValidationRetainsAndRechecksTheOriginalWitness() throws {
        let witness = Witness(100); var removed = false, captures = 0, stops = 0
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { removed ? .absent : .matching(100) },
            capture: { _ in captures += 1; return witness }, bootout: { stops += 1; removed = true })
        XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
        XCTAssertThrowsError(try session.requireRemoved())
        witness.unavailable = true; XCTAssertThrowsError(try session.requireRemoved())
        witness.unavailable = false; witness.exited = true; try session.requireRemoved()
        XCTAssertEqual(captures, 1); XCTAssertEqual(stops, 1)
    }
    func testAbsentRegistrationDoesNotMutateOrInventAProcess() throws {
        var checks = 0
        let session = RuntimeJobStopSession(verifyCurrent: { checks += 1 }, inspect: { .absent },
            capture: { _ in XCTFail("No process was observed"); throw Failure.expected }, bootout: { XCTFail("Already absent") })
        XCTAssertEqual(try session.poll(), .registrationRemoved)
        XCTAssertGreaterThanOrEqual(checks, 3)
    }
    func testMissingRegistrationStillWaitsForTheOriginalObservedProcess() throws {
        let witness = Witness(100)
        var registered = true, stops = 0, captures = 0
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { registered ? .matching(100) : .absent },
            capture: { pid in XCTAssertEqual(pid, 100); captures += 1; return witness }, bootout: { stops += 1; registered = false })
        XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
        XCTAssertEqual(captures, 1); XCTAssertEqual(stops, 1)
        XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
        XCTAssertEqual(stops, 1)
        witness.exited = true
        XCTAssertEqual(try session.poll(), .registrationRemoved)
    }
    func testLostBootoutReplyReconcilesWithoutASecondRemoval() throws {
        var registered = true, stops = 0
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { registered ? .matching(nil) : .absent },
            capture: { _ in XCTFail("No observed PID"); throw Failure.expected }, bootout: {
                stops += 1; registered = false; throw Failure.expected
            })
        XCTAssertEqual(try session.poll(), .registrationRemoved)
        XCTAssertEqual(try session.poll(), .registrationRemoved)
        XCTAssertEqual(stops, 1)
    }
    func testUnremovedRegistrationStaysPendingAndRetryChecksItAgain() throws {
        var registered = true, stops = 0
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { registered ? .matching(nil) : .absent },
            capture: { _ in throw Failure.expected }, bootout: { stops += 1; if stops == 1 { throw Failure.expected }; registered = false })
        XCTAssertEqual(try session.poll(), .removingRegistration)
        XCTAssertEqual(try session.poll(), .registrationRemoved)
        XCTAssertEqual(stops, 2)
    }
    func testSecondObservationCapturesAReplacementBeforeRemovingTheJob() throws {
        let first = Witness(100), next = Witness(101)
        var reads = 0, removed = false
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: {
            reads += 1; return removed ? .absent : .matching(reads == 1 ? 100 : 101)
        }, capture: { $0 == 100 ? first : next }, bootout: { removed = true })
        XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
        next.exited = true
        XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
        first.exited = true
        XCTAssertEqual(try session.poll(), .registrationRemoved)
    }
    func testProcessSeenAfterRemovalRequestIsRetainedForLaterReconciliation() throws {
        let first = Witness(100), next = Witness(101)
        var reads = 0, absent = false, captures = [pid_t]()
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: {
            reads += 1; return absent ? .absent : .matching(reads <= 2 ? 100 : 101)
        }, capture: { captures.append($0); return $0 == 100 ? first : next }, bootout: {})
        XCTAssertEqual(try session.poll(), .removingRegistration)
        XCTAssertEqual(captures, [100, 101])
        absent = true; first.exited = true
        XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
        next.exited = true
        XCTAssertEqual(try session.poll(), .registrationRemoved)
    }
    func testReusedPIDRequiresAnotherWitnessEvenAfterTheOldProcessExited() throws {
        let first = Witness(100), reused = Witness(100)
        var captures = 0, removed = false
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { removed ? .absent : .matching(100) }, capture: { _ in
            captures += 1; return captures == 1 ? first : reused
        }, bootout: {})
        XCTAssertEqual(try session.poll(), .removingRegistration); XCTAssertEqual(captures, 1)
        first.exited = true
        XCTAssertEqual(try session.poll(), .removingRegistration); XCTAssertEqual(captures, 2)
        removed = true
        XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
        reused.exited = true
        XCTAssertEqual(try session.poll(), .registrationRemoved)
    }
    func testUnknownProcessStateNeverBecomesExitOrDropsItsWitness() throws {
        let witness = Witness(100)
        var removed = false
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { removed ? .absent : .matching(100) },
            capture: { _ in witness }, bootout: { removed = true })
        XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
        witness.unavailable = true
        XCTAssertThrowsError(try session.poll())
        witness.unavailable = false; witness.exited = true
        XCTAssertEqual(try session.poll(), .registrationRemoved)
    }
    func testConflictBeforeOrImmediatelyBeforeRemovalCannotMutate() throws {
        for secondRead in [false, true] {
            var reads = 0
            let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: {
                reads += 1; return secondRead && reads == 1 ? .matching(nil) : .conflicting
            }, capture: { _ in throw Failure.expected }, bootout: { XCTFail("Conflicting job") })
            XCTAssertThrowsError(try session.poll()) { XCTAssertEqual($0 as? RuntimeActivationError, .conflictingPlan) }
        }
    }
    func testConflictAfterRemovalRequestIsNotSuccess() throws {
        var removed = false
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { removed ? .conflicting : .matching(nil) },
            capture: { _ in throw Failure.expected }, bootout: { removed = true })
        XCTAssertThrowsError(try session.poll()) { XCTAssertEqual($0 as? RuntimeActivationError, .conflictingPlan) }
    }
    func testScopeFailureAtEveryPreMutationBoundaryStopsRemoval() throws {
        for failAt in 1...5 {
            var checks = 0, mutations = 0
            let session = RuntimeJobStopSession(verifyCurrent: { checks += 1; if checks == failAt { throw Failure.expected } },
                inspect: { .matching(nil) }, capture: { _ in throw Failure.expected }, bootout: { mutations += 1 })
            XCTAssertThrowsError(try session.poll()); XCTAssertEqual(mutations, 0)
        }
    }
    func testScopeFailureAfterRemovalDoesNotLoseTheKnownProcess() throws {
        let witness = Witness(100)
        var removed = false, fail = true
        let session = RuntimeJobStopSession(verifyCurrent: { if removed && fail { throw Failure.expected } },
            inspect: { removed ? .absent : .matching(100) }, capture: { _ in witness }, bootout: { removed = true })
        XCTAssertThrowsError(try session.poll())
        fail = false
        XCTAssertEqual(try session.poll(), .waitingForObservedProcesses)
        witness.exited = true
        XCTAssertEqual(try session.poll(), .registrationRemoved)
    }
    func testUnknownCaptureAndWrongWitnessCannotIssueRemoval() throws {
        for wrong in [false, true] {
            let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { .matching(100) }, capture: { _ in
                if wrong { return Witness(101) }; throw Failure.expected
            }, bootout: { XCTFail("Unbound process") })
            XCTAssertThrowsError(try session.poll())
        }
    }
    func testWitnessCapacityFailsBeforeAnotherRemovalAndPreservesEarlierProcesses() throws {
        var nextPID: pid_t = 100, captures = 0, stops = 0
        let session = RuntimeJobStopSession(verifyCurrent: {}, inspect: { .matching(nextPID) }, capture: { pid in
            captures += 1; return Witness(pid)
        }, bootout: { stops += 1 })
        for _ in 0..<RuntimeJobStopSession.maximumWitnesses {
            XCTAssertEqual(try session.poll(), .removingRegistration); nextPID += 1
        }
        XCTAssertEqual(stops, RuntimeJobStopSession.maximumWitnesses)
        XCTAssertThrowsError(try session.poll())
        XCTAssertEqual(captures, RuntimeJobStopSession.maximumWitnesses)
        XCTAssertEqual(stops, RuntimeJobStopSession.maximumWitnesses)
    }
    func testOnlyExactAbsentOutputCanBeClassifiedAsMissing() throws {
        let job = try job(), message = Data(("Bad request.\nCould not find service \"" + job.declaration.label + "\" in domain for system\n").utf8)
        XCTAssertEqual(try RuntimeJobStopSession.classify(.init(exitCode: 113, output: Data(), errorOutput: message), job: job), .absent)
        for result in [BoundedNativeCommand.Result(exitCode: 113, output: Data([1]), errorOutput: message),
                       .init(exitCode: 1, output: Data(), errorOutput: message),
                       .init(exitCode: 113, output: Data(), errorOutput: Data("Could not find service \"other\"".utf8)),
                       .init(exitCode: 0, output: Data(), errorOutput: message),
                       .init(exitCode: 113, output: Data(), errorOutput: Data("extra\n".utf8) + message)] {
            XCTAssertThrowsError(try RuntimeJobStopSession.classify(result, job: job))
        }
    }
    func testNativeRemovalRefusesOrdinaryIdentityBeforeOwnerChecks() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary owner") }
        let fixture = try ReleaseActivityFixture(), barrier = try fixture.open(), token = try barrier.acquireExclusive()
        defer { token.close() }
        let policy = try AuthorityCodePolicy(entries: [.init(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 1, count: 20), active: true)])
        XCTAssertThrowsError(try RuntimeJobStopSession.open(job: job(), policy: policy, rootActivity: token,
            verifyOwnerAndFence: { XCTFail("Root guard must precede owner and launchctl") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
    }
}
