import Foundation
import XCTest
@testable import RemozioCore

@MainActor
final class MacSetupRecoveryControlsTests: XCTestCase {
    private typealias RecoveryClientFixture = MacSetupRecoveryChannelTests.Fixture
    private typealias Controls = MacSetupRecoveryControls
    private typealias Status = SetupRetainedStatusWire.Observation

    @MainActor
    private final class Harness {
        let fixture = RecoveryClientFixture()
        var status: Status
        var authorizationCount = 0
        var openCount = 0
        var authorization: CheckedContinuation<Controls.Authorization, Never>?
        var onAuthorization: (() -> Void)?
        var readForm: Controls.Authorization = { RecoveryClientFixture.form }

        init() { status = Self.observation(.init(reservationID: UUID(), incarnation: UUID())) }

        static func observation(_ identity: SetupRetainedInvocationStatus.Identity?) -> Status {
            .init(reservation: .orphan, identity: identity, window: nil, operation: nil, restoration: nil,
                worker: .idle, cleanup: .joined, supervisor: nil)
        }

        func controls(eligible: Bool = true, holdRights: Bool = false) -> Controls {
            Controls(read: { self.status }, eligible: { _ in eligible ? .restore : nil }, openRecovery: {
                self.openCount += 1
                return self.fixture.channel()
            }, authorize: {
                self.authorizationCount += 1
                if holdRights {
                    return await withCheckedContinuation { continuation in
                        self.authorization = continuation
                        self.onAuthorization?()
                    }
                }
                return self.readForm
            })
        }
    }

    func testRefreshWithoutProducerApplicabilityOpensNoRecoveryOrRights() async {
        let harness = Harness(), controls = harness.controls(eligible: false)
        await controls.refresh()
        XCTAssertEqual(controls.status, .observed(harness.status))
        XCTAssertNil(controls.selection)
        XCTAssertEqual(harness.authorizationCount, 0)
        XCTAssertEqual(harness.openCount, 0)
    }

    func testMissingIdentityCannotCreateAnActionEvenWithEligibility() async {
        let harness = Harness(), controls = harness.controls()
        harness.status = Harness.observation(nil)
        await controls.refresh()
        XCTAssertNil(controls.selection)
        XCTAssertEqual(harness.openCount, 0)
    }

    func testSupersededObservationCannotOpenRecovery() async throws {
        let harness = Harness(), controls = harness.controls()
        await controls.refresh()
        let selection = try XCTUnwrap(controls.selection)
        await controls.refresh()
        await controls.begin(selection)
        XCTAssertEqual(harness.openCount, 0)
        XCTAssertEqual(harness.authorizationCount, 0)
    }

    func testChangedReservationOrIncarnationDuringRightsCannotSend() async throws {
        for replaceReservation in [false, true] {
            let harness = Harness(), controls = harness.controls(holdRights: true)
            await controls.refresh()
            let selection = try XCTUnwrap(controls.selection), identity = try XCTUnwrap(harness.status.identity)
            let waiting = expectation(description: "Awaiting rights")
            harness.onAuthorization = { waiting.fulfill() }
            let attempt = Task { await controls.begin(selection) }
            await fulfillment(of: [waiting], timeout: 5)
            harness.status = Harness.observation(.init(reservationID: replaceReservation ? UUID() : identity.reservationID,
                incarnation: replaceReservation ? identity.incarnation : UUID()))
            await controls.refresh()
            harness.authorization?.resume(returning: { RecoveryClientFixture.form })
            await attempt.value
            XCTAssertEqual(controls.attempt, .notSubmitted)
            XCTAssertEqual(controls.selectionInvalidation, replaceReservation ? .reservationChanged : .incarnationChanged)
            XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello"])
        }
    }

    func testDuplicateClickCannotOpenSecondChannelOrAuthorize() async throws {
        let harness = Harness(), controls = harness.controls(holdRights: true)
        await controls.refresh()
        let selection = try XCTUnwrap(controls.selection)
        let waiting = expectation(description: "Awaiting rights")
        harness.onAuthorization = { waiting.fulfill() }
        let attempt = Task { await controls.begin(selection) }
        await fulfillment(of: [waiting], timeout: 5)
        await controls.begin(selection)
        harness.authorization?.resume(returning: { RecoveryClientFixture.form })
        await attempt.value
        XCTAssertEqual(harness.authorizationCount, 1)
        XCTAssertEqual(harness.openCount, 1)
        XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello", "start"])
    }

    func testRecordedRequestTracksProgressToRestored() async throws {
        let harness = Harness(), controls = harness.controls()
        await controls.refresh()
        await controls.begin(try XCTUnwrap(controls.selection))
        XCTAssertEqual(controls.attempt, .pending)
        await controls.readProgress()
        XCTAssertEqual(controls.attempt, .pending)
        harness.fixture.state.withLock { $0.progressCode = .restored }
        await controls.readProgress()
        XCTAssertEqual(controls.attempt, .finished(.restored))
        XCTAssertNil(controls.selection)
        XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello", "start", "progress", "progress"])
    }

    func testLostAcknowledgementReadsOriginalRequestWithoutRepeatingStart() async throws {
        let harness = Harness(), controls = harness.controls()
        let dispatched = expectation(description: "Start dispatched")
        harness.fixture.state.withLock {
            $0.holdStart = true
            $0.onHeldStart = { dispatched.fulfill() }
            $0.progressCode = .refusedUnavailable
        }
        await controls.refresh()
        let selection = try XCTUnwrap(controls.selection)
        let start = Task { await controls.begin(selection) }
        await fulfillment(of: [dispatched], timeout: 5)
        let expire = try XCTUnwrap(harness.fixture.state.withLock { $0.expire })
        await expire()
        await start.value
        XCTAssertEqual(controls.attempt, .unconfirmed)
        await controls.readProgress()
        XCTAssertEqual(controls.attempt, .unconfirmed)

        harness.fixture.state.withLock { $0.progressCode = .pending }
        await controls.readProgress()
        XCTAssertEqual(controls.attempt, .pending)
        harness.fixture.state.withLock { $0.progressCode = .refusedUnavailable }
        await controls.readProgress()
        XCTAssertEqual(controls.attempt, .finished(.refusedUnavailable))
        XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello", "start", "progress", "progress", "progress"])
        XCTAssertEqual(harness.authorizationCount, 1)
    }

    func testCancellingViewDuringStartAndReadKeepsOriginalConnection() async throws {
        let harness = Harness(), controls = harness.controls()
        let dispatched = expectation(description: "Start dispatched")
        harness.fixture.state.withLock { $0.holdStart = true; $0.onHeldStart = { dispatched.fulfill() } }
        await controls.refresh()
        let selection = try XCTUnwrap(controls.selection)
        let startingView = Task { await controls.begin(selection) }
        await fulfillment(of: [dispatched], timeout: 5)
        startingView.cancel()
        let requestID = try XCTUnwrap(harness.fixture.state.withLock { $0.request?.requestID })
        let startReply = try Controls.Wire.Reply(requestID: requestID, code: .requestRecorded).bytes
        let finishStart = try XCTUnwrap(harness.fixture.state.withLock { $0.delayedReply })
        finishStart(.progress(startReply))
        await startingView.value
        XCTAssertEqual(controls.attempt, .pending)
        XCTAssertEqual(harness.fixture.state.withLock { $0.closeCount }, 0)

        let reading = expectation(description: "Progress read dispatched")
        harness.fixture.state.withLock { $0.onHeldProgress = { reading.fulfill() }; $0.delayedReply = nil }
        let readingView = Task { await controls.readProgress() }
        await fulfillment(of: [reading], timeout: 5)
        readingView.cancel()
        let progressReply = try Controls.Wire.Reply(requestID: requestID, code: .pending).bytes
        let finishRead = try XCTUnwrap(harness.fixture.state.withLock { $0.delayedReply })
        finishRead(.progress(progressReply))
        await readingView.value
        XCTAssertEqual(controls.attempt, .pending)
        XCTAssertEqual(harness.fixture.state.withLock { $0.closeCount }, 0)
        XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello", "start", "progress"])
        await controls.close()
    }

    func testAuthorizationExportFailureWasNotSubmitted() async throws {
        let harness = Harness(), controls = harness.controls()
        harness.readForm = { throw AdministrativeSetupChannelError.invalidMessage }
        await controls.refresh()
        await controls.begin(try XCTUnwrap(controls.selection))
        XCTAssertEqual(controls.attempt, .notSubmitted)
        XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello"])
    }

    func testPeerChangeBeforeExportWasNotSubmitted() async throws {
        let harness = Harness(), controls = harness.controls(holdRights: true)
        await controls.refresh()
        let selection = try XCTUnwrap(controls.selection)
        let waiting = expectation(description: "Awaiting rights")
        harness.onAuthorization = { waiting.fulfill() }
        let start = Task { await controls.begin(selection) }
        await fulfillment(of: [waiting], timeout: 5)
        let fixture = harness.fixture
        fixture.state.withLock { $0.pid += 1 }
        let authorization = try XCTUnwrap(harness.authorization)
        authorization.resume(returning: {
            fixture.state.withLock { $0.exported = true }
            return RecoveryClientFixture.form
        })
        await start.value
        XCTAssertEqual(controls.attempt, .notSubmitted)
        XCTAssertFalse(fixture.state.withLock { $0.exported })
        XCTAssertEqual(fixture.state.withLock { $0.calls }, ["hello"])
    }

    func testDisconnectedAttemptRequiresReadbackBeforeNewSelection() async throws {
        let harness = Harness(), controls = harness.controls()
        await controls.refresh()
        await controls.begin(try XCTUnwrap(controls.selection))
        harness.fixture.state.withLock { $0.disconnected }?()
        await controls.readProgress()
        XCTAssertEqual(controls.attempt, .unconfirmed)
        await controls.endTracking()
        XCTAssertNil(controls.selection)
        await controls.refresh()
        XCTAssertNotNil(controls.selection)
        XCTAssertEqual(controls.attempt, .unconfirmed)
        XCTAssertEqual(harness.openCount, 1)
    }

    func testNewControllerReadsBeforeOfferingAnyActionAfterClose() async throws {
        let harness = Harness(), original = harness.controls()
        await original.refresh()
        await original.begin(try XCTUnwrap(original.selection))
        await original.close()
        XCTAssertEqual(original.attempt, .unconfirmed)
        let relaunched = harness.controls()
        XCTAssertNil(relaunched.selection)
        await relaunched.refresh()
        XCTAssertNotNil(relaunched.selection)
        XCTAssertEqual(harness.authorizationCount, 1)
    }

    func testLateStatusCannotReplaceTheMoreRecentObservation() async throws {
        let old = Harness.observation(.init(reservationID: UUID(), incarnation: UUID()))
        let fresh = Harness.observation(.init(reservationID: UUID(), incarnation: UUID()))
        let entered = expectation(description: "First status read starts")
        var pending: CheckedContinuation<Status, Never>?, reads = 0
        let controls = Controls(read: {
            reads += 1
            if reads == 1 {
                return await withCheckedContinuation { continuation in
                    pending = continuation
                    entered.fulfill()
                }
            }
            return fresh
        }, openRecovery: { throw AdministrativeSetupChannelError.closed },
           authorize: { throw AdministrativeSetupChannelError.closed })
        let earlier = Task { await controls.refresh() }
        await fulfillment(of: [entered], timeout: 5)
        await controls.refresh()
        pending?.resume(returning: old)
        await earlier.value
        XCTAssertEqual(controls.status, .observed(fresh))
    }

}
