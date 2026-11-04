import XCTest

/// Fork measurement only: proves a test file added after a cache restore is discovered and run.
final class CacheTrialDiscoveryTests: XCTestCase {
    func testAddedTestFileRuns() {
        print("CACHE-TRIAL-ADDED-TEST")
    }
}
