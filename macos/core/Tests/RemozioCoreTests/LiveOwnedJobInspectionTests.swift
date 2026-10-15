import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class LiveOwnedJobInspectionTests: XCTestCase {
    func testOwnedGUIJobReconciliation() throws {
        guard ProcessInfo.processInfo.environment["REMOZIO_OWNED_JOB_PROBE"] == "1" else {
            throw XCTSkip("Explicit ordinary GUI-session experiment only")
        }
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("No Root or system-domain fixture") }
        let domain = "gui/\(getuid())", label = "dev.remozio.experiments.job-inspection." + UUID().uuidString.lowercased()
        let target = domain + "/" + label
        let directory = URL(fileURLWithPath: "/private/tmp/remozio job inspection " + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let first = directory.appendingPathComponent("original.plist"), other = directory.appendingPathComponent("conflicting.plist")
        var facts: [String: Bool] = [:]
        defer {
            let payload = try? JSONSerialization.data(withJSONObject: facts, options: [.sortedKeys])
            if let payload, let text = String(data: payload, encoding: .utf8) { print("REMOZIO_JOB_INSPECTION_EVIDENCE " + text) }
        }
        func run(_ arguments: [String]) throws -> BoundedNativeCommand.Result {
            try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: arguments)
        }
        var attempted = false
        defer {
            if attempted {
                do {
                    _ = try run(["bootout", target])
                    var absent = false
                    for _ in 0..<50 {
                        let value = try run(["print", target])
                        absent = value.exitCode == 113 && String(data: value.errorOutput, encoding: .utf8)?.contains("Could not find service \"" + label + "\"") == true
                        if absent { break }
                        usleep(100_000)
                    }
                    facts["temporaryJobRemoved"] = absent
                    XCTAssertTrue(absent, "Remove only the reported owned experiment target if cleanup fails: \(target)")
                    if absent { try FileManager.default.removeItem(at: directory) }
                } catch { facts["temporaryJobRemoved"] = false; XCTFail("Owned cleanup failed for \(target)") }
            } else { try? FileManager.default.removeItem(at: directory) }
        }
        func write(_ url: URL, program: String, arguments: [String], suffix: String = ".original") throws {
            let values: [String: Any] = ["Label": label, "Program": program, "ProgramArguments": arguments,
                                         "RunAtLoad": true, "KeepAlive": true, "MachServices": [label + suffix: true]]
            try PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0).write(to: url)
        }
        try write(first, program: "/bin/sleep", arguments: ["/bin/sleep", "60"])
        try write(other, program: "/usr/bin/true", arguments: ["/usr/bin/true"])
        let absent = try run(["print", target])
        facts["unknownOwnedLabelAbsent"] = absent.exitCode == 113
        XCTAssertTrue(facts["unknownOwnedLabelAbsent"] == true)
        print("REMOZIO_JOB_INSPECTION_TARGET " + target)
        attempted = true
        XCTAssertEqual(try run(["bootstrap", domain, first.path]).exitCode, 0)
        let loaded = try run(["print", target]); XCTAssertEqual(loaded.exitCode, 0)
        let observation = try LaunchdJobObservation.decode(loaded.output, target: target)
        facts["loadedFieldsMatchOriginal"] = observation.kind == "LaunchAgent" && observation.path == first.path
            && observation.program == "/bin/sleep" && observation.arguments == ["/bin/sleep", "60"]
        XCTAssertTrue(facts["loadedFieldsMatchOriginal"] == true)
        facts["loadedEndpointSettingsMatch"] = observation.endpoints == [label + ".original"]
        facts["loadedPropertiesMatch"] = observation.properties.isSuperset(of: ["runatload", "keepalive"])
        XCTAssertTrue(facts["loadedEndpointSettingsMatch"] == true)
        XCTAssertTrue(facts["loadedPropertiesMatch"] == true)
        let conflict = try run(["bootstrap", domain, other.path])
        facts["sameLabelBootstrapRejected"] = conflict.exitCode != 0
        XCTAssertTrue(facts["sameLabelBootstrapRejected"] == true)
        let retained = try LaunchdJobObservation.decode(run(["print", target]).output, target: target)
        facts["conflictDidNotReplaceOwnedJob"] = retained.path == first.path && retained.program == observation.program && retained.arguments == observation.arguments
        XCTAssertTrue(facts["conflictDidNotReplaceOwnedJob"] == true)
        try write(first, program: "/usr/bin/false", arguments: ["/usr/bin/false"], suffix: ".changed")
        let unchanged = try LaunchdJobObservation.decode(run(["print", target]).output, target: target)
        facts["loadedConfigurationIndependentOfDisk"] = unchanged.path == first.path && unchanged.program == observation.program && unchanged.arguments == observation.arguments
        XCTAssertTrue(facts["loadedConfigurationIndependentOfDisk"] == true)
        facts["changedFileRetainsLoadedEndpointsAndProperties"] = unchanged.endpoints == observation.endpoints && unchanged.properties == observation.properties
        XCTAssertTrue(facts["changedFileRetainsLoadedEndpointsAndProperties"] == true)
    }
}
