import Darwin
import Foundation
import Security
import Synchronization
import XCTest
@testable import RemozioCore

/// Logical transport callbacks do not establish native XPC signing or administrator authorization.
final class PortableSetupImportChannelTests: XCTestCase, @unchecked Sendable {
    private final class Driver: PortableSetupImportDriver, Sendable {
        struct State {
            var version: UInt64 = 9
            var response: SetupClientReply = .progress(Data())
            var history: [String] = []
            var held: (@Sendable (SetupClientReply) -> Void)?
            var closed: (@Sendable () -> Void)?
            var hold = false, closes = 0
        }
        let state = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) { state.withLock { $0.closed = closed } }
        func invoke(_ call: PortableSetupImportCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            let result: SetupClientReply? = state.withLock {
                switch call {
                case .hello: $0.history.append("hello"); return .version($0.version)
                case .progress: $0.history.append("progress")
                case .perform: $0.history.append("perform")
                }
                if $0.hold { $0.held = reply; return nil }; return $0.response
            }
            if let result { reply(result) }
        }
        func close() { state.withLock { $0.closes += 1 } }
        func deliver(_ value: SetupClientReply) { let held = state.withLock { $0.held }; held?(value) }
    }
    private func request() throws -> (RelayProvisioningFixture, SetupAccountOwner, SetupPortableImportOperation) {
        let f = try RelayProvisioningFixture(), owner = try f.owner()
        return try (f, owner, .init(action: .retain, expected: f.progress(owner), proposal: f.f.proposal()))
    }
    private var form: Data { Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size) }
    private func until(_ predicate: () -> Bool) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(3))
        while !predicate() { guard ContinuousClock.now < end else { throw AdministrativeSetupChannelError.timedOut }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testOldOrMissingHandshakeCannotSendCredentialsAndExistingVersionsRemainSupported() async throws {
        let (_, owner, request) = try request(); defer { try? owner.close() }
        XCTAssertTrue(Set(UInt64(1)...8).isSubset(of: AdministrativeSetupInterface.supportedVersions))
        for version: UInt64 in [0, 8, 10] {
            let driver = Driver(); driver.state.withLock { $0.version = version }
            let channel = PortableSetupImportChannel(driver: driver)
            do { try await channel.start(); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .unsupportedVersion) }
            do { _ = try await channel.perform(request, authorization: form); XCTFail() } catch {}
            XCTAssertEqual(driver.state.withLock { $0.history }, ["hello"])
        }
    }
    func testProgressAndResultAreBoundedAndTheExactRequestIsValidated() async throws {
        let (_, owner, request) = try request(); defer { try? owner.close() }
        let driver = Driver(), channel = PortableSetupImportChannel(driver: driver)
        try await channel.start(); let empty = try await channel.progress(); XCTAssertNil(empty)
        driver.state.withLock { $0.response = .progress(try! request.expected.bytes) }
        let progress = try await channel.progress(); XCTAssertEqual(progress, request.expected)
        let result = try SetupPortableImportOperationResult(request: request, progress: request.expected, status: .applied)
        driver.state.withLock { $0.response = .progress(try! result.bytes) }
        let actual = try await channel.perform(request, authorization: form); XCTAssertEqual(actual, result)
        await channel.close()
    }
    func testMalformedAndCrossedRepliesCloseTheChannel() async throws {
        let (_, owner, request) = try request(); defer { try? owner.close() }
        for bytes in [Data(), Data(repeating: 0, count: SetupPortableImportOperationResult.maximumBytes + 1), try request.expected.bytes] {
            let driver = Driver(), channel = PortableSetupImportChannel(driver: driver)
            try await channel.start(); driver.state.withLock { $0.response = .progress(bytes) }
            do { _ = try await channel.perform(request, authorization: form); XCTFail() } catch {}
            do { _ = try await channel.progress(); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .closed) }
        }
    }
    func testBusyCallDoesNotCancelTheOriginalAndLateDuplicateRepliesAreIgnored() async throws {
        let (_, owner, request) = try request(); defer { try? owner.close() }
        let driver = Driver(), channel = PortableSetupImportChannel(driver: driver)
        try await channel.start(); driver.state.withLock { $0.hold = true }
        let first = Task { try await channel.perform(request, authorization: self.form) }
        try await until { driver.state.withLock { $0.held != nil } }
        do { _ = try await channel.progress(); XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .busy) }
        let result = try SetupPortableImportOperationResult(request: request, progress: request.expected, status: .applied)
        driver.deliver(.progress(try result.bytes)); let actual = try await first.value; XCTAssertEqual(actual, result)
        driver.deliver(.failed); driver.state.withLock { $0.hold = false; $0.response = .progress(Data()) }
        let progress = try await channel.progress(); XCTAssertNil(progress); await channel.close()
    }
    func testTimeoutAndAbortDoNotRetryAnUnknownOperation() async throws {
        let (_, owner, request) = try request(); defer { try? owner.close() }
        for mode in 0..<3 {
            let driver = Driver(), channel = PortableSetupImportChannel(driver: driver, operationTimeoutMilliseconds: mode == 0 ? 20 : 5000)
            try await channel.start(); driver.state.withLock { $0.hold = true }
            let pending = Task { try await channel.perform(request, authorization: self.form) }
            try await until { driver.state.withLock { $0.held != nil } }
            if mode == 1 { channel.abort() }
            if mode == 2 { pending.cancel() }
            do { _ = try await pending.value; XCTFail() } catch {}
            driver.deliver(.progress(Data()))
            XCTAssertEqual(driver.state.withLock { $0.history }, ["hello", "perform"])
        }
    }
}
