import Foundation
import XCTest
@testable import RemozioCore

final class MacPortableSetupImportDriverTests: XCTestCase, @unchecked Sendable {
    private enum Failure: Error { case expected }
    private actor Events {
        var values: [String] = []
        func add(_ value: String) { values.append(value) }
    }
    private actor Root: MacPortableSetupImportRoot {
        let events: Events
        let expected: SetupPortableImportProgress?
        let startFails: Bool
        let performFails: Bool
        init(_ events: Events, expected: SetupPortableImportProgress?, startFails: Bool = false, performFails: Bool = false) {
            self.events = events; self.expected = expected; self.startFails = startFails; self.performFails = performFails
        }
        func start() async throws { await events.add("start"); if startFails { throw Failure.expected } }
        func progress() async throws -> SetupPortableImportProgress? { await events.add("progress"); return expected }
        func perform(_ request: SetupPortableImportOperation, authorization: Data) async throws -> SetupPortableImportOperationResult {
            await events.add("perform")
            XCTAssertEqual(authorization, Data([1, 2, 3]))
            if performFails { throw Failure.expected }
            return try .init(request: request, progress: XCTUnwrap(expected), status: .applied)
        }
        func close() async { await events.add("root.close") }
    }
    private actor Administrator: MacPortableSetupImportAdministrator {
        let events: Events
        let cancel: Bool
        init(_ events: Events, cancel: Bool = false) { self.events = events; self.cancel = cancel }
        func authorization() async throws -> Data {
            await events.add("authorize")
            if cancel { withUnsafeCurrentTask { $0?.cancel() } }
            return Data([1, 2, 3])
        }
        func close() async { await events.add("rights.close") }
    }
    private func make(_ events: Events, root: Root, cancel: Bool = false) -> NativeMacPortableSetupImportDriver {
        NativeMacPortableSetupImportDriver(open: { root }, administrator: { Administrator(events, cancel: cancel) })
    }
    func testRefreshAuthenticatesRootAndNeverObtainsAdministratorRights() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let events = Events(), expected = try fixture.progress(owner)
        let driver = make(events, root: Root(events, expected: expected))
        let result = try await driver.progress()
        XCTAssertEqual(result, expected)
        let observed = await events.values
        XCTAssertEqual(observed, ["start", "progress", "root.close"])
    }
    func testExplicitStepChecksTheReviewedProgressBeforeAuthorizationAndClosesBothOwners() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let events = Events(), expected = try fixture.progress(owner)
        let driver = make(events, root: Root(events, expected: expected))
        let request = try SetupPortableImportOperation(action: .retain, expected: expected, proposal: fixture.f.proposal())
        let result = try await driver.perform(request)
        XCTAssertEqual(result.status, .applied)
        let observed = await events.values
        XCTAssertEqual(observed, ["start", "progress", "authorize", "perform", "root.close", "rights.close"])
    }
    func testFailedHandshakeAndChangedProgressCannotObtainRightsOrSendTheProposal() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let request = try SetupPortableImportOperation(action: .retain, expected: fixture.progress(owner), proposal: fixture.f.proposal())
        for startFails in [true, false] {
            let events = Events(), driver = make(events, root: Root(events, expected: nil, startFails: startFails))
            do { _ = try await driver.perform(request); XCTFail("Accepted missing destination") } catch {}
            let observed = await events.values
            XCTAssertEqual(observed, startFails ? ["start", "root.close", "rights.close"] : ["start", "progress", "root.close", "rights.close"])
        }
    }
    func testLostWriteReplyClosesWithoutRetryingOrPretendingToReadBackTheOutcome() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let events = Events(), expected = try fixture.progress(owner)
        let driver = make(events, root: Root(events, expected: expected, performFails: true))
        let request = try SetupPortableImportOperation(action: .retain, expected: expected, proposal: fixture.f.proposal())
        do { _ = try await driver.perform(request); XCTFail("Accepted lost reply") } catch {}
        let observed = await events.values
        XCTAssertEqual(observed, ["start", "progress", "authorize", "perform", "root.close", "rights.close"])
    }
    func testCancellationAfterTheAdministratorPromptCannotDispatchAWrite() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let events = Events(), expected = try fixture.progress(owner)
        let driver = make(events, root: Root(events, expected: expected), cancel: true)
        let request = try SetupPortableImportOperation(action: .retain, expected: expected, proposal: fixture.f.proposal())
        let task = Task { try await driver.perform(request) }
        do { _ = try await task.value; XCTFail("Accepted cancelled authorization") }
        catch { XCTAssertTrue(error is CancellationError) }
        let observed = await events.values
        XCTAssertEqual(observed, ["start", "progress", "authorize", "root.close", "rights.close"])
    }
}
