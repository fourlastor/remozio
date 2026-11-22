import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

@MainActor
final class MacSetupRecoveryControlsTests: XCTestCase {
    private typealias RecoveryClientFixture = MacSetupRecoveryChannelTests.Fixture
    private typealias Controls = MacSetupRecoveryControls
    private typealias Status = SetupRetainedStatusWire.Observation

    private nonisolated final class GrantLog: Sendable { let closes = Mutex(0) }

    @MainActor
    private final class Harness {
        let fixture = RecoveryClientFixture()
        var status: Status
        var authorizationCount = 0
        var openCount = 0
        var authorization: CheckedContinuation<Void, Never>?
        var onAuthorization: (() -> Void)?
        var readForm: @Sendable () throws -> Data = { RecoveryClientFixture.form }
        let grantLog = GrantLog()
        var onGrantClose: (@Sendable () -> Void)?
        var authorizationError: SetupAdministratorAuthorizationError?

        init() { status = Self.observation(.init(reservationID: UUID(), incarnation: UUID())) }

        static func observation(_ identity: SetupRetainedInvocationStatus.Identity?,
            reservation: SetupRetainedInvocationStatus.Reservation? = .orphan, matchingWindow: Bool = false,
            applicability: SetupRetainedStatusV3Wire.Applicability? = nil,
            worker: SetupRetainedInvocationStatus.Worker? = .idle) -> Status {
            .init(reservation: reservation, identity: identity,
                window: matchingWindow ? .init(id: Data(repeating: 2, count: 16),
                    revision: Data(repeating: 3, count: 16), purpose: .retainedRuntime) : nil,
                operation: nil, restoration: nil, worker: worker, cleanup: .joined, supervisor: nil,
                applicability: applicability)
        }

        func controls(eligible: Bool? = true, holdRights: Bool = false) -> Controls {
            let selection: (@MainActor (Status) -> Controls.Wire.Action?)?
            if let eligible { selection = { _ in eligible ? .restore : nil } } else { selection = nil }
            return Controls(read: { self.status }, eligible: selection, openRecovery: {
                self.openCount += 1
                return self.fixture.channel()
            }, makeAuthorization: {
                let onClose = self.onGrantClose, log = self.grantLog
                return .init(prepare: {
                    self.authorizationCount += 1
                    if holdRights {
                        await withCheckedContinuation { continuation in
                            self.authorization = continuation
                            self.onAuthorization?()
                        }
                    }
                    if let error = self.authorizationError { throw error }
                }, readForm: self.readForm, close: {
                    log.closes.withLock { $0 += 1 }
                    onClose?()
                })
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
            harness.authorization?.resume()
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
        harness.authorization?.resume()
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
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 0)
        await controls.readProgress()
        XCTAssertEqual(controls.attempt, .pending)
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 0)
        harness.fixture.state.withLock { $0.progressCode = .restored }
        await controls.readProgress()
        XCTAssertEqual(controls.attempt, .finished(.restored))
        XCTAssertEqual(controls.attemptSummary, .restored)
        XCTAssertEqual(controls.health, .unconfirmed)
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 1)
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
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 1)
        XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello"])
    }

    func testPeerChangeBeforeExportWasNotSubmitted() async throws {
        let harness = Harness(), controls = harness.controls(holdRights: true)
        let fixture = harness.fixture
        harness.readForm = {
            fixture.state.withLock { $0.exported = true }
            return RecoveryClientFixture.form
        }
        await controls.refresh()
        let selection = try XCTUnwrap(controls.selection)
        let waiting = expectation(description: "Awaiting rights")
        harness.onAuthorization = { waiting.fulfill() }
        let start = Task { await controls.begin(selection) }
        await fulfillment(of: [waiting], timeout: 5)
        fixture.state.withLock { $0.pid += 1 }
        let authorization = try XCTUnwrap(harness.authorization)
        authorization.resume()
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

    func testProductionPolicyOffersOnlyBoundOrphanRestore() async throws {
        let harness = Harness(), controls = harness.controls(eligible: nil)
        let identity = try XCTUnwrap(harness.status.identity)
        harness.status = Harness.observation(identity, matchingWindow: true, applicability: .restore)
        await controls.refresh()
        XCTAssertEqual(controls.statusSummary, .restoreAvailable)
        XCTAssertEqual(controls.selection?.action, .restore)
        XCTAssertEqual(harness.authorizationCount, 0)
        XCTAssertEqual(harness.openCount, 0)

        await controls.begin(try XCTUnwrap(controls.selection))
        let request = try XCTUnwrap(harness.fixture.state.withLock { $0.request })
        XCTAssertEqual(request.action, .restore)
        XCTAssertEqual(request.identity, identity)
        await controls.close()
    }

    func testProductionPolicyDistinguishesMissingEvidenceAndNoAction() async throws {
        let harness = Harness(), controls = harness.controls(eligible: nil)
        let identity = try XCTUnwrap(harness.status.identity)
        let cases: [(Status, Controls.StatusSummary)] = [
            (Harness.observation(identity, matchingWindow: true), .applicabilityUnavailable),
            (Harness.observation(identity, applicability: .noAction), .noAction),
            (Harness.observation(identity, matchingWindow: true, applicability: .adoptRecordedCompletion), .applicabilityUnavailable),
            (Harness.observation(identity, applicability: .releaseWindowFree), .applicabilityUnavailable),
            (Harness.observation(nil, matchingWindow: true, applicability: .restore), .applicabilityUnavailable),
            (Harness.observation(identity, applicability: .restore), .applicabilityUnavailable),
            (Harness.observation(nil, reservation: .absent, worker: nil), .noSavedWork),
            (Harness.observation(nil, reservation: nil, worker: nil), .unavailable)
        ]
        for (observation, summary) in cases {
            harness.status = observation
            await controls.refresh()
            XCTAssertEqual(controls.statusSummary, summary)
            XCTAssertNil(controls.selection)
        }
        XCTAssertEqual(harness.authorizationCount, 0)
        XCTAssertEqual(harness.openCount, 0)
    }

    func testRelaunchWhileDaemonIsRecoveringShowsBusyAndOffersNoRestore() async throws {
        let harness = Harness(), original = harness.controls(eligible: nil)
        let identity = try XCTUnwrap(harness.status.identity)
        harness.status = Harness.observation(identity, matchingWindow: true, applicability: .restore)
        await original.refresh()
        await original.begin(try XCTUnwrap(original.selection))
        await original.close()

        let relaunched = harness.controls(eligible: nil)
        XCTAssertEqual(relaunched.attemptSummary, .idle)
        XCTAssertNil(relaunched.selection)
        harness.status = Harness.observation(identity, reservation: .recovering, matchingWindow: true, worker: .running)
        await relaunched.refresh()
        XCTAssertEqual(relaunched.statusSummary, .busy)
        XCTAssertNil(relaunched.selection)
        XCTAssertFalse(relaunched.canCheckProgress)

        harness.status = Harness.observation(identity, reservation: .recovering, matchingWindow: true, applicability: .restore)
        await relaunched.refresh()
        XCTAssertEqual(relaunched.statusSummary, .busy)
        XCTAssertNil(relaunched.selection)
        XCTAssertEqual(harness.authorizationCount, 1)
        XCTAssertEqual(harness.openCount, 1)
    }

    func testUnavailableReadDropsRestoreSelection() async throws {
        let harness = Harness()
        let identity = try XCTUnwrap(harness.status.identity)
        let observation = Harness.observation(identity, matchingWindow: true, applicability: .restore)
        var fail = false
        let controls = Controls(read: {
            if fail { throw AdministrativeSetupChannelError.invalidMessage }
            return observation
        }, openRecovery: { throw AdministrativeSetupChannelError.closed },
            makeAuthorization: { throw AdministrativeSetupChannelError.closed })
        await controls.refresh()
        XCTAssertNotNil(controls.selection)
        fail = true
        await controls.refresh()
        XCTAssertEqual(controls.statusSummary, .unavailable)
        XCTAssertNil(controls.selection)
    }

    func testCancelledPromptDestroysGrantWithoutDispatch() async throws {
        let harness = Harness(), controls = harness.controls()
        harness.authorizationError = .cancelled
        await controls.refresh()
        await controls.begin(try XCTUnwrap(controls.selection))
        XCTAssertEqual(controls.attemptSummary, .notSubmitted)
        XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello"])
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 1)
        await controls.close()
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 1)
    }

    func testRefreshDoesNotReplacePendingAttemptOrReleaseGrant() async throws {
        let harness = Harness(), controls = harness.controls()
        await controls.refresh()
        await controls.begin(try XCTUnwrap(controls.selection))
        let requestID = harness.fixture.state.withLock { $0.request?.requestID }
        await controls.refresh()
        XCTAssertEqual(controls.attemptSummary, .pending)
        XCTAssertEqual(harness.fixture.state.withLock { $0.request?.requestID }, requestID)
        XCTAssertNil(controls.selection)
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 0)
        XCTAssertTrue(controls.canCheckProgress)
        XCTAssertFalse(controls.canStopTracking)
        await controls.close()
    }

    func testStopTrackingDestroysGrantAndRequiresNewStatus() async throws {
        let harness = Harness(), controls = harness.controls()
        let dispatched = expectation(description: "Start dispatched")
        harness.fixture.state.withLock { $0.holdStart = true; $0.onHeldStart = { dispatched.fulfill() } }
        await controls.refresh()
        let selection = try XCTUnwrap(controls.selection)
        let start = Task { await controls.begin(selection) }
        await fulfillment(of: [dispatched], timeout: 5)
        let expire = try XCTUnwrap(harness.fixture.state.withLock { $0.expire })
        await expire()
        await start.value
        XCTAssertTrue(controls.canStopTracking)
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 0)
        await controls.endTracking()
        XCTAssertEqual(controls.attemptSummary, .unconfirmed)
        XCTAssertFalse(controls.canCheckProgress)
        XCTAssertNil(controls.selection)
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 1)
        await controls.begin(selection)
        XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello", "start"])
        await controls.refresh()
        XCTAssertNotNil(controls.selection)
    }

    func testIdleTransportLossDestroysGrantWithoutWaitingForProgress() async throws {
        let harness = Harness(), controls = harness.controls()
        let closed = expectation(description: "Grant destroyed")
        harness.onGrantClose = { closed.fulfill() }
        await controls.refresh()
        await controls.begin(try XCTUnwrap(controls.selection))
        let disconnect = try XCTUnwrap(harness.fixture.state.withLock { $0.disconnected })
        disconnect()
        await fulfillment(of: [closed], timeout: 5)
        XCTAssertEqual(controls.attemptSummary, .unconfirmed)
        XCTAssertFalse(controls.canCheckProgress)
        XCTAssertNil(controls.selection)
        XCTAssertEqual(controls.health, .unconfirmed)
        await controls.close()
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 1)
        XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello", "start"])
    }

    func testApplicationCloseDestroysPendingGrantExactlyOnce() async throws {
        let harness = Harness(), controls = harness.controls()
        await controls.refresh()
        await controls.begin(try XCTUnwrap(controls.selection))
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 0)
        await controls.close()
        await controls.close()
        XCTAssertEqual(controls.attemptSummary, .unconfirmed)
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 1)
        XCTAssertNil(controls.selection)
    }

    func testCloseDuringPromptDiscardsLateApproval() async throws {
        let harness = Harness(), controls = harness.controls(holdRights: true)
        let prompt = expectation(description: "Awaiting approval")
        harness.onAuthorization = { prompt.fulfill() }
        await controls.refresh()
        let selection = try XCTUnwrap(controls.selection)
        let start = Task { await controls.begin(selection) }
        await fulfillment(of: [prompt], timeout: 5)
        await controls.close()
        harness.authorization?.resume()
        await start.value
        XCTAssertEqual(controls.attemptSummary, .notSubmitted)
        XCTAssertEqual(harness.grantLog.closes.withLock { $0 }, 1)
        XCTAssertEqual(harness.fixture.state.withLock { $0.calls }, ["hello"])
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
           makeAuthorization: { throw AdministrativeSetupChannelError.closed })
        let earlier = Task { await controls.refresh() }
        await fulfillment(of: [entered], timeout: 5)
        await controls.refresh()
        pending?.resume(returning: old)
        await earlier.value
        XCTAssertEqual(controls.status, .observed(fresh))
    }

}
