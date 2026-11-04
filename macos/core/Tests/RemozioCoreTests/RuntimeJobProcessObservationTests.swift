import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeJobProcessObservationTests: XCTestCase {
    private enum Failure: Error { case expected }
    private func withChild(_ body: (Process, CommandAncestryObservation.Process) throws -> Void) throws {
        let child = Process(); child.executableURL = URL(fileURLWithPath: "/bin/sleep"); child.arguments = ["30"]
        try child.run()
        defer { if child.isRunning { child.terminate() }; child.waitUntilExit() }
        try body(child, CommandAncestryObservation.sample(child.processIdentifier))
    }
    func testKernelExitIsObservedAfterOwnedChildTerminationWithoutTakingItsWait() throws {
        try withChild { child, sample in
            let observer = try RuntimeJobProcessObservation(processID: child.processIdentifier, expectedUID: getuid(),
                expectedParent: getpid(), expectedPath: XCTUnwrap(sample.path), validateCode: { _ in })
            XCTAssertFalse(try observer.hasExited())
            child.terminate(); child.waitUntilExit()
            let deadline = Date().addingTimeInterval(3)
            var exited = false
            repeat {
                do { exited = try observer.hasExited() } catch { }
                if !exited { usleep(1000) }
            } while !exited && Date() < deadline
            XCTAssertTrue(exited); XCTAssertTrue(try observer.hasExited())
        }
    }
    func testWrongUIDParentPathAndRejectedCodeCannotCreateAnObserver() throws {
        try withChild { child, sample in
            let path = try XCTUnwrap(sample.path)
            for (uid, parent, expectedPath) in [(getuid() + 1, getpid(), path), (getuid(), getpid() + 1, path),
                                               (getuid(), getpid(), Data("/not-the-program".utf8))] {
                XCTAssertThrowsError(try RuntimeJobProcessObservation(processID: child.processIdentifier, expectedUID: uid,
                    expectedParent: parent, expectedPath: expectedPath, validateCode: { _ in })) {
                        XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
                    }
            }
            XCTAssertThrowsError(try RuntimeJobProcessObservation(processID: child.processIdentifier, expectedUID: getuid(),
                expectedParent: getpid(), expectedPath: path, validateCode: { _ in throw Failure.expected }))
        }
    }
    func testCodeFailureAfterKernelRegistrationClosesWithoutAffectingTheChild() throws {
        try withChild { child, sample in
            var checks = 0
            XCTAssertThrowsError(try RuntimeJobProcessObservation(processID: child.processIdentifier, expectedUID: getuid(),
                expectedParent: getpid(), expectedPath: XCTUnwrap(sample.path), validateCode: { _ in
                    checks += 1; if checks == 2 { throw Failure.expected }
                }))
            XCTAssertEqual(checks, 2); XCTAssertTrue(child.isRunning)
        }
    }
    func testAnAlreadyReapedProcessDoesNotInventARegisteredExitWitness() throws {
        let child = Process(); child.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try child.run(); child.waitUntilExit()
        XCTAssertThrowsError(try RuntimeJobProcessObservation(processID: child.processIdentifier, expectedUID: getuid(),
            expectedParent: getpid(), expectedPath: Data("/usr/bin/true".utf8), validateCode: { _ in }))
    }
    func testExecCannotBeTreatedAsTheOriginalProcessExit() throws {
        let child = Process(), input = Pipe(), output = Pipe()
        child.executableURL = URL(fileURLWithPath: "/bin/sh")
        child.arguments = ["-c", "printf ready; read token; exec /bin/sleep 30"]
        child.standardInput = input; child.standardOutput = output
        try child.run()
        defer { if child.isRunning { child.terminate() }; child.waitUntilExit() }
        XCTAssertEqual(output.fileHandleForReading.readData(ofLength: 5), Data("ready".utf8))
        let sample = try CommandAncestryObservation.sample(child.processIdentifier)
        let observer = try RuntimeJobProcessObservation(processID: child.processIdentifier, expectedUID: getuid(),
            expectedParent: getpid(), expectedPath: XCTUnwrap(sample.path), validateCode: { _ in })
        try input.fileHandleForWriting.write(contentsOf: Data("go\n".utf8))
        let deadline = Date().addingTimeInterval(3)
        var rejected = false
        repeat {
            do { let exited = try observer.hasExited(); XCTAssertFalse(exited) } catch { rejected = true }
            if !rejected { usleep(1000) }
        } while !rejected && Date() < deadline
        XCTAssertTrue(rejected)
        child.terminate(); child.waitUntilExit()
        XCTAssertThrowsError(try observer.hasExited())
    }
    func testNativeObservationRefusesOrdinaryIdentityBeforeProcessAccess() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary owner") }
        let job = try InstalledAccountJobManifest(accountID: Data(repeating: 1, count: 16), role: .authority, executionUID: 0,
            userName: "root", bundlePath: MachineBootstrap.bundlePath)
        let code = try AuthorityCodeEntry(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 1, count: 20), active: true)
        XCTAssertThrowsError(try RuntimeJobProcessObservation.open(job: job, code: code, processID: -1)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
