import ApplicationServices
import Foundation
import XCTest
@testable import RemozioUIAdapters

final class AXObservationSessionTests: XCTestCase {
    @MainActor
    private final class Driver: AXObservationDriver {
        var failures: [AXObservationEvent: AXStructureFailure] = [:]
        var cleanupFailures: [AXObservationEvent: AXStructureFailure] = [:]
        var attachFailure: AXStructureFailure?
        var contexts: [AXObservationEvent: UnsafeMutableRawPointer] = [:]
        var attached = false
        var calls: [String] = []
        var onDetach: (() -> Void)?
        func register(_ event: AXObservationEvent, context: UnsafeMutableRawPointer) throws {
            calls.append("register:" + event.rawValue)
            if let error = failures[event] { throw error }
            contexts[event] = context
        }
        func attach() throws { calls.append("attach"); if let error = attachFailure { throw error }; attached = true }
        func detach() { calls.append("detach"); onDetach?(); attached = false }
        func unregister(_ event: AXObservationEvent) throws {
            calls.append("remove:" + event.rawValue); contexts[event] = nil
            if let error = cleanupFailures[event] { throw error }
        }
        func emit(_ event: AXObservationEvent) {
            guard attached, let context = contexts[event] else { return }
            Unmanaged<AXObservationMailbox>.fromOpaque(context).takeUnretainedValue().record(event)
        }
    }
    @MainActor func testRepeatedHintsRemainBoundedAndDrainDoesNotCreateHistory() async throws {
        let driver = Driver(), owner = try AXObservationOwner(driver: driver)
        for _ in 0..<10_000 { for event in AXObservationEvent.allCases { driver.emit(event) } }
        XCTAssertEqual(owner.drain(), Set(AXObservationEvent.allCases)); XCTAssertTrue(owner.drain().isEmpty)
        XCTAssertTrue(owner.state.isRunning); owner.close()
    }
    @MainActor func testPartialUnsupportedRegistrationIsExplicitWithoutDisablingOtherHints() async throws {
        let driver = Driver(); driver.failures[.elementDestroyed] = .unsupported
        let owner = try AXObservationOwner(driver: driver)
        XCTAssertEqual(owner.state.registrationFailures, [.elementDestroyed: .unsupported])
        XCTAssertEqual(owner.state.registered.count, 3)
        for event in AXObservationEvent.allCases { driver.emit(event) }
        XCTAssertEqual(owner.drain(), Set(AXObservationEvent.allCases).subtracting([.elementDestroyed]))
        owner.close(); XCTAssertFalse(driver.calls.contains("remove:elementDestroyed"))
    }
    @MainActor func testCloseDisablesCallbacksBeforeDetachmentAndNeverReopens() async throws {
        let driver = Driver(), owner = try AXObservationOwner(driver: driver)
        driver.emit(.windowCreated)
        driver.onDetach = { driver.emit(.focusedWindowChanged) }
        owner.close(); let calls = driver.calls
        driver.emit(.elementDestroyed); owner.mailbox.record(.elementDestroyed)
        XCTAssertTrue(owner.drain().isEmpty); XCTAssertFalse(owner.state.isRunning); XCTAssertTrue(owner.state.registered.isEmpty)
        XCTAssertTrue(driver.contexts.isEmpty); owner.close(); XCTAssertEqual(driver.calls, calls)
        driver.onDetach = nil
    }
    @MainActor func testAllUnsupportedAndFailedAttachmentRemoveEverySuccessfulRegistration() async throws {
        let none = Driver(); none.failures = Dictionary(uniqueKeysWithValues: AXObservationEvent.allCases.map { ($0, .unsupported) })
        XCTAssertThrowsError(try AXObservationOwner(driver: none)) { XCTAssertEqual($0 as? AXStructureFailure, .unsupported) }
        XCTAssertFalse(none.attached); XCTAssertTrue(none.contexts.isEmpty)
        let failed = Driver(); failed.attachFailure = .unavailable
        XCTAssertThrowsError(try AXObservationOwner(driver: failed)) { XCTAssertEqual($0 as? AXStructureFailure, .unavailable) }
        XCTAssertFalse(failed.attached); XCTAssertTrue(failed.contexts.isEmpty)
        XCTAssertEqual(failed.calls.filter { $0.hasPrefix("remove:") }.count, 4)
    }
    @MainActor func testUnavailableRegistrationReportsTheConcretePermissionOrMessagingFailure() async throws {
        for failure in [AXStructureFailure.permissionDenied, .cannotComplete, .invalidElement] {
            let driver = Driver()
            driver.failures = Dictionary(uniqueKeysWithValues: AXObservationEvent.allCases.map { ($0, failure) })
            XCTAssertThrowsError(try AXObservationOwner(driver: driver)) { XCTAssertEqual($0 as? AXStructureFailure, failure) }
            XCTAssertFalse(driver.attached); XCTAssertTrue(driver.contexts.isEmpty)
        }
    }
    @MainActor func testCleanupFailureDoesNotPreventOtherRegistrationsFromClosing() async throws {
        let driver = Driver(); driver.cleanupFailures[.windowCreated] = .cannotComplete
        let owner = try AXObservationOwner(driver: driver); owner.close()
        XCTAssertEqual(owner.state.cleanupFailures, [.windowCreated: .cannotComplete])
        XCTAssertFalse(owner.state.isRunning); XCTAssertFalse(driver.attached); XCTAssertTrue(driver.contexts.isEmpty)
        XCTAssertEqual(driver.calls.filter { $0.hasPrefix("remove:") }.count, 4)
    }
    @MainActor func testDeinitializationClosesTheOwnedDriverOnItsActor() async throws {
        let driver = Driver(); var owner: AXObservationOwner? = try AXObservationOwner(driver: driver)
        weak var original = owner; XCTAssertTrue(owner!.state.isRunning); owner = nil
        XCTAssertNil(original); XCTAssertFalse(driver.attached); XCTAssertTrue(driver.contexts.isEmpty)
        original = nil
    }
    @MainActor func testOwnedNativeRunLoopSourceAttachesAndInvalidatesWithoutAnApplication() async throws {
        var context = CFRunLoopSourceContext()
        let source = try XCTUnwrap(CFRunLoopSourceCreate(nil, 0, &context)), attachment = AXObservationRunLoopSource(source)
        try attachment.attach(); XCTAssertTrue(CFRunLoopContainsSource(CFRunLoopGetMain(), source, .defaultMode))
        attachment.detach(); XCTAssertFalse(CFRunLoopSourceIsValid(source))
        XCTAssertFalse(CFRunLoopContainsSource(CFRunLoopGetMain(), source, .defaultMode))
        XCTAssertThrowsError(try attachment.attach()); attachment.detach()
    }
    @MainActor func testNativeNamesAreWhitelistedAndInvalidPIDStopsBeforePermissionQuery() async throws {
        for event in AXObservationEvent.allCases { XCTAssertEqual(AXObservationEvent.matching(event.nativeName), event) }
        XCTAssertNil(AXObservationEvent.matching("untrusted notification text" as CFString))
        for pid: Int32 in [0, -1] {
            XCTAssertThrowsError(try NativeAXObservationSession(processID: pid)) { XCTAssertEqual($0 as? AXStructureFailure, .wrongProcess) }
        }
    }
}
