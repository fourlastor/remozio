import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

/// Actual Joined and typed intent receipts. Driver replies are synthetic and grant no native qualification.
final class AuthorityMaintenanceUnboundClientTests: XCTestCase, @unchecked Sendable {
    private typealias Row = RuntimeMaintenanceWindowRecord
    private typealias Joined = SetupRetainedOrphanClaim.Joined
    private final class Driver: AuthorityMaintenanceClientDriver, Sendable {
        enum Fault: Equatable, Sendable { case none, replayRelease, wrongIntent, nativeClosing }
        struct State {
            var invalidated: (@Sendable () -> Void)?
            var closed = false
            var priorRelease: Data?
            var releaseRequests: [AuthorityMaintenanceUnboundRequest] = []
        }
        let state = Mutex(State())
        let fault: Fault, hold: AuthorityMaintenanceUnboundGateResponse.Hold
        let admission: Row.GateReadback.Admission
        let outcome: AuthorityMaintenanceUnboundReleaseResponse.Outcome
        init(fault: Fault = .none, hold: AuthorityMaintenanceUnboundGateResponse.Hold = .neverHeld,
            admission: Row.GateReadback.Admission = .available,
            outcome: AuthorityMaintenanceUnboundReleaseResponse.Outcome = .released) {
            self.fault = fault; self.hold = hold; self.admission = admission; self.outcome = outcome
        }
        func start(_ invalidated: @escaping @Sendable () -> Void) { state.withLock { $0.invalidated = invalidated } }
        func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            reply(.hello(AuthorityMaintenanceChannelScope.protocolVersion))
        }
        func observeIncarnation(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let request = try AuthorityMaintenanceIncarnationRequest.decode(bytes)
                reply(.bytes(try AuthorityMaintenanceIncarnationResponse(request: request,
                    incarnation: Data(repeating: 41, count: 16)).encoded))
            } catch { reply(.bytes(nil)) }
        }
        func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            if fault == .nativeClosing { reply(.bytes(nil)); close(); return }
            do {
                let request = try AuthorityMaintenanceUnboundRequest.decode(bytes)
                reply(.bytes(try AuthorityMaintenanceUnboundGateResponse(request: request, hold: hold, admission: admission).encoded))
            } catch { reply(.bytes(nil)) }
        }
        func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
            do {
                let original = try AuthorityMaintenanceUnboundRequest.decode(bytes)
                state.withLock { $0.releaseRequests.append(original) }
                let request: AuthorityMaintenanceUnboundRequest
                if fault == .wrongIntent {
                    request = try .init(kind: original.kind, installationID: original.installationID,
                        accountID: original.accountID, attemptID: original.attemptID, revision: original.revision,
                        rowDigest: original.rowDigest, pendingRevision: original.pendingRevision,
                        intentID: AccountPreparationIntent.randomID(), gate: original.gate,
                        authorityIncarnation: original.authorityIncarnation, challenge: original.challenge)
                } else { request = original }
                let encoded = try AuthorityMaintenanceUnboundReleaseResponse(request: request, outcome: outcome).encoded
                let response = state.withLock { value -> Data in
                    if fault == .replayRelease, let prior = value.priorRelease { return prior }
                    value.priorRelease = encoded; return encoded
                }
                reply(.bytes(response))
            } catch { reply(.bytes(nil)) }
        }
        func close() {
            let invalidated = state.withLock { value -> (@Sendable () -> Void)? in
                guard !value.closed else { return nil }; value.closed = true; return value.invalidated
            }
            invalidated?()
        }
    }
    private func fixture(_ body: @escaping @Sendable (ExplicitStartupFixture) async throws -> Void) throws {
        try RuntimeMaintenanceExplicitRestorationTests().withFixture(body)
    }
    private static func intent(_ f: ExplicitStartupFixture) async throws -> (Joined, Row, PreparationFileIdentity) {
        try f.h.seed(.authorized)
        let joined = try await f.join(), phases = try joined.restorationPhases()
        let pending = try await phases.run {
            let frame = try f.h.frame(), row = try XCTUnwrap(frame.window)
            return try f.h.f.machine().writeRuntimeMaintenanceUnboundIntent(replacing: row, joined: joined,
                expected: frame.source.actual, candidate: f.h.f.candidate, directory: f.h.f.directory,
                admission: f.h.f.admission).record
        }
        let gate = try XCTUnwrap(f.h.frame().source.actual.admission.accounts.first { $0.accountID == pending.scope.authority.accountID })
        return (joined, pending, gate.identity)
    }
    private static func client(_ row: Row, gate: PreparationFileIdentity, driver: Driver,
        joined: Joined) throws -> AuthorityMaintenanceXPCClient {
        let context = try AuthorityMaintenanceChannelRequest(action: .open, accountID: row.scope.authority.accountID,
            attemptID: row.id, revision: row.revision, installationID: row.scope.installationID, gate: gate, binding: nil,
            challenge: AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID())
        return try .openOwned(context: context, driver: driver, recoveryPhases: joined.restorationPhases())
    }
    func testProbePreservesEveryTypedHoldAndAdmissionWithoutCreatingACompletion() throws {
        try fixture { f in
            let (joined, row, gate) = try await Self.intent(f)
            for hold in [AuthorityMaintenanceUnboundGateResponse.Hold.held, .released, .neverHeld, .unknown] {
                for admission in Row.GateReadback.Admission.allCases {
                    let driver = Driver(hold: hold, admission: admission), client = try Self.client(row, gate: gate, driver: driver, joined: joined)
                    let result = try await client.probeUnboundGate(joined: joined, row: row, gate: gate,
                        until: .now.advanced(by: .seconds(20)))
                    XCTAssertEqual(result.hold, hold); XCTAssertEqual(result.admission, admission)
                    XCTAssertEqual(driver.state.withLock { $0.releaseRequests.count }, 0); await client.close()
                }
            }
            XCTAssertEqual(try f.h.frame().window, row); f.retained.assertHeld()
        }
    }
    func testReleasePreservesBusyAndStopRefusalAsDistinctTypedOutcomes() throws {
        try fixture { f in
            let (joined, row, gate) = try await Self.intent(f)
            for outcome in [AuthorityMaintenanceUnboundReleaseResponse.Outcome.released, .alreadyReleased, .busy, .refused] {
                let client = try Self.client(row, gate: gate, driver: Driver(outcome: outcome), joined: joined)
                let result = try await client.releaseUnbound(joined: joined, row: row, gate: gate,
                    until: .now.advanced(by: .seconds(20)))
                XCTAssertEqual(result.outcome, outcome); XCTAssertEqual(result.request.intentID, row.unboundRelease?.intentID)
                await client.close()
            }
            XCTAssertEqual(try f.h.frame().window, row); f.retained.assertHeld()
        }
    }
    func testAReplayedReleaseReplyCannotAnswerAFreshChallenge() throws {
        try fixture { f in
            let (joined, row, gate) = try await Self.intent(f), driver = Driver(fault: .replayRelease)
            let client = try Self.client(row, gate: gate, driver: driver, joined: joined)
            _ = try await client.releaseUnbound(joined: joined, row: row, gate: gate, until: .now.advanced(by: .seconds(20)))
            do {
                _ = try await client.releaseUnbound(joined: joined, row: row, gate: gate, until: .now.advanced(by: .seconds(20)))
                XCTFail("A previous reply answered a new release")
            } catch { XCTAssertEqual(error as? RuntimePreparationError, .changedScope) }
            let requests = driver.state.withLock { $0.releaseRequests }
            XCTAssertEqual(requests.count, 2); XCTAssertNotEqual(requests[0].challenge, requests[1].challenge)
            XCTAssertEqual(requests[0].intentID, requests[1].intentID)
            await client.close(); XCTAssertEqual(try f.h.frame().window, row); f.retained.assertHeld()
        }
    }
    func testAReleaseReplyWithAnotherIntentIsRefused() throws {
        try fixture { f in
            let (joined, row, gate) = try await Self.intent(f)
            let client = try Self.client(row, gate: gate, driver: Driver(fault: .wrongIntent), joined: joined)
            do {
                _ = try await client.releaseUnbound(joined: joined, row: row, gate: gate, until: .now.advanced(by: .seconds(20)))
                XCTFail("A foreign intent answered the release")
            } catch { XCTAssertEqual(error as? RuntimePreparationError, .changedScope) }
            await client.close(); XCTAssertEqual(try f.h.frame().window, row); f.retained.assertHeld()
        }
    }
    func testTheCurrentNativeStyleCloseProducesNoGateSuccess() throws {
        try fixture { f in
            let (joined, row, gate) = try await Self.intent(f)
            let client = try Self.client(row, gate: gate, driver: Driver(fault: .nativeClosing), joined: joined)
            do {
                _ = try await client.probeUnboundGate(joined: joined, row: row, gate: gate, until: .now.advanced(by: .seconds(20)))
                XCTFail("The closed route produced a probe")
            } catch { XCTAssertNotNil(error as? AuthorityMaintenanceClientError) }
            await client.close(); XCTAssertEqual(try f.h.frame().window, row); f.retained.assertHeld()
        }
    }
    func testTheExistingVerifiedPathStillRejectsHeldOrBusyObservations() throws {
        try fixture { f in
            let (joined, row, gate) = try await Self.intent(f)
            for driver in [Driver(hold: .held), Driver(admission: .busy)] {
                let client = try Self.client(row, gate: gate, driver: driver, joined: joined)
                do {
                    _ = try await client.observeUnboundGate(joined: joined, row: row, gate: gate, until: .now.advanced(by: .seconds(20)))
                    XCTFail("An incomplete observation minted a completion proof")
                } catch { XCTAssertEqual(error as? RuntimePreparationError, .changedScope) }
                await client.close()
            }
            XCTAssertEqual(try f.h.frame().window, row); f.retained.assertHeld()
        }
    }
}
