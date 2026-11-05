import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class MacAuditUpgradeSettingsTests: XCTestCase, @unchecked Sendable {
    func testUnsetAndSparseValuesKeepTheOtherDefault() throws {
        let defaults = try MacAuditUpgradeSettings(preferences: [:])
        XCTAssertEqual(defaults.readTimeoutMilliseconds, 60_000); XCTAssertEqual(defaults.operationTimeoutMilliseconds, 60_000)
        let read = try MacAuditUpgradeSettings(preferences: [MacAuditUpgradeSettings.readTimeoutKey: "0017"])
        XCTAssertEqual(read.readTimeoutMilliseconds, 17); XCTAssertEqual(read.operationTimeoutMilliseconds, 60_000)
        let operation = try MacAuditUpgradeSettings(preferences: [MacAuditUpgradeSettings.operationTimeoutKey: "300000"])
        XCTAssertEqual(operation.readTimeoutMilliseconds, 60_000); XCTAssertEqual(operation.operationTimeoutMilliseconds, 300_000)
    }
    func testMalformedTypesAndNumbersCannotBecomeConnectionWaits() throws {
        let invalid: [Any] = [true, false, 17, 1.0, NSNull(), "", "0", "-1", "+1", " 1", "1 ", "1.5", "1e3", "١", "18446744073709551616"]
        for key in MacAuditUpgradeSettings.keys {
            for value in invalid { XCTAssertThrowsError(try MacAuditUpgradeSettings(preferences: [key: value])) }
        }
        XCTAssertThrowsError(try MacAuditUpgradeSettings(preferences: [MacAuditUpgradeSettings.readTimeoutKey: "60001"]))
        XCTAssertThrowsError(try MacAuditUpgradeSettings(preferences: [MacAuditUpgradeSettings.operationTimeoutKey: "300001"]))
    }
    func testCaptureReadsOnlyTheExplicitWaitKeys() throws {
        var keys: [String] = []
        let result = try MacAuditUpgradeSettings.capture { key in keys.append(key); return key == MacAuditUpgradeSettings.readTimeoutKey ? "1" : "300000" }
        XCTAssertEqual(keys, MacAuditUpgradeSettings.keys); XCTAssertEqual(result, try .init(readTimeoutMilliseconds: 1, operationTimeoutMilliseconds: 300_000))
    }
    func testEachNewRequestCapturesSettingsAndInvalidValuesFailBeforeOpeningAService() async throws {
        let calls = Mutex(0)
        let driver = NativeMacAuditUpgradeDriver(settings: {
            calls.withLock { $0 += 1 }
            throw MacAuditUpgradeSettingsError.invalidPreferences
        })
        for _ in 0..<2 {
            do { _ = try await driver.progress(); XCTFail("Invalid settings") }
            catch { XCTAssertEqual(error as? MacAuditUpgradeSettingsError, .invalidPreferences) }
        }
        XCTAssertEqual(calls.withLock { $0 }, 2)
    }
}
