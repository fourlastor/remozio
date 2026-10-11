import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class AuthorityCommandExecutionConfigurationTests: XCTestCase {
    func testRoundTripRetainsExplicitHostSettingsWithoutLeakingPathsInDescriptions() throws {
        let config = try AuthorityCommandExecutionConfiguration(monitorPath: "/Applications/Remozio.app/Contents/Helpers/monitor",
            childPath: "/Applications/Remozio.app/Contents/Helpers/child", preparationMilliseconds: 60000,
            fileCreationMask: 0o027, maximumActiveCommands: 1024, pollIntervalMilliseconds: 1000, maximumPending: 4096)
        let decoded = try AuthorityCommandExecutionConfiguration.decode(config.canonicalBytes)
        XCTAssertEqual(decoded, config)
        XCTAssertEqual(decoded.fileCreationMask, 0o027); XCTAssertEqual(decoded.maximumActiveCommands, 1024)
        XCTAssertEqual(decoded.maximumPending, 4096)
        XCTAssertFalse(config.description.contains("Applications")); XCTAssertFalse(config.debugDescription.contains("Helpers"))
    }

    func testUnsupportedVersionUnknownFieldsAndOverflowNeverDecode() throws {
        let config = try AuthorityCommandExecutionConfiguration(monitorPath: "/monitor", childPath: "/child")
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 2, maxItems: 32)
        guard case .map(let valid) = try DeterministicCBOR.decode(config.canonicalBytes, limits: limits) else {
            return XCTFail("A valid configuration must contain its exact field map")
        }
        for field in UInt64(0)...7 {
            var altered = valid; altered[field] = .unsigned(UInt64.max)
            XCTAssertThrowsError(try AuthorityCommandExecutionConfiguration.decode(DeterministicCBOR.encode(.map(altered), limits: limits)))
        }
        var extra = valid; extra[8] = .unsigned(1)
        XCTAssertThrowsError(try AuthorityCommandExecutionConfiguration.decode(DeterministicCBOR.encode(.map(extra), limits: limits)))
        var missing = valid; missing.removeValue(forKey: 7)
        XCTAssertThrowsError(try AuthorityCommandExecutionConfiguration.decode(DeterministicCBOR.encode(.map(missing), limits: limits)))
    }

    func testPathsAndExecutionBoundsCannotBypassExistingHostRestrictions() throws {
        for path in ["monitor", "/", "/a//monitor", "/a/../monitor", "/a/./monitor", "/a/monitor/", "/a/\0monitor", "/" + String(repeating: "a", count: 256)] {
            XCTAssertThrowsError(try AuthorityCommandExecutionConfiguration(monitorPath: path, childPath: "/child"))
            XCTAssertThrowsError(try AuthorityCommandExecutionConfiguration(monitorPath: "/monitor", childPath: path))
        }
        XCTAssertThrowsError(try AuthorityCommandExecutionConfiguration(monitorPath: "/same", childPath: "/same"))
        for preparation: UInt32 in [99, 60001] {
            XCTAssertThrowsError(try AuthorityCommandExecutionConfiguration(monitorPath: "/monitor", childPath: "/child", preparationMilliseconds: preparation))
        }
        XCTAssertThrowsError(try AuthorityCommandExecutionConfiguration(monitorPath: "/monitor", childPath: "/child", fileCreationMask: 0o1000))
        for active in [0, 1025] {
            XCTAssertThrowsError(try AuthorityCommandExecutionConfiguration(monitorPath: "/monitor", childPath: "/child", maximumActiveCommands: active))
        }
        for poll in [9, 1001] {
            XCTAssertThrowsError(try AuthorityCommandExecutionConfiguration(monitorPath: "/monitor", childPath: "/child", pollIntervalMilliseconds: poll))
        }
    }
}
