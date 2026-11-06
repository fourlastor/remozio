import Darwin
import XCTest
@testable import RemozioCore

final class CommandFrontendReadinessPresentationTests: XCTestCase {
    private let busy: [(CommandAdmissionRejectionReason, Int32, String)] = [
        (.updateInstalling, 80, "Update installing"), (.authorityStarting, 81, "Mac authority starting"),
        (.updateWaiting, 82, "Update waiting"), (.storageUnavailable, 83, "Storage unavailable")]

    private func status(_ result: CommandFrontendExit, file: StaticString = #filePath, line: UInt = #line) -> Int32 {
        guard case .status(let value) = result else { XCTFail("Expected a CLI exit status.", file: file, line: line); return -1 }
        return value
    }

    func testWaitingNamesEachAuthenticatedBusyState() {
        for (reason, _, label) in busy {
            XCTAssertEqual(CommandFrontendMain.readinessStatusMessage(.waiting(reason)),
                label + ". Waiting before a fresh submission.")
        }
    }

    func testBusyDeadlineResultsHaveDistinctNonzeroStatusesAndTheLastState() {
        var statuses: [Int32] = []
        for (reason, expected, label) in busy {
            var messages: [String] = []
            let result = CommandFrontendMain.readinessExit(.deadlineExceeded(lastBusyReason: reason)) { messages.append($0) }
            let code = status(result); statuses.append(code)
            XCTAssertEqual(code, expected); XCTAssertNotEqual(code, 0)
            XCTAssertEqual(messages, ["Last state: " + label + ". The configured wait ended before admission."])
        }
        XCTAssertEqual(Set(statuses).count, busy.count)
    }

    func testLookupDeadlineDoesNotInventAnAuthenticatedBusyState() {
        var messages: [String] = []
        XCTAssertEqual(status(CommandFrontendMain.readinessExit(.deadlineExceeded(lastBusyReason: nil)) { messages.append($0) }), EX_TEMPFAIL)
        XCTAssertEqual(messages, ["The authority did not become ready within the configured wait."])
        XCTAssertEqual(CommandFrontendMain.readinessStatusMessage(.connecting), "Waiting for the command authority.")
    }

    func testPermanentRejectionsCannotAcquireABusyExitStatus() {
        let reasons: [CommandAdmissionRejectionReason] = [.invalidRequest, .policyRejected, .capacityExceeded, .unsupported, .requesterExited]
        for reason in reasons {
            var messages: [String] = []
            XCTAssertEqual(status(CommandFrontendMain.readinessExit(.deadlineExceeded(lastBusyReason: reason)) { messages.append($0) }), EX_TEMPFAIL)
            XCTAssertEqual(messages, ["The authority did not become ready within the configured wait."])
        }
    }

    func testConfigurationAndClockErrorsKeepTheirExistingResults() {
        for (error, expected, text): (CommandCallerReadinessError, Int32, String) in [
            (.invalidConfiguration, EX_CONFIG, "Invalid command readiness settings."),
            (.clockMovedBackwards, EX_OSERR, "The command caller clock failed.")] {
            var messages: [String] = []
            XCTAssertEqual(status(CommandFrontendMain.readinessExit(error) { messages.append($0) }), expected)
            XCTAssertEqual(messages, [text])
        }
    }
}
