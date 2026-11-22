import Foundation
import Security
import Synchronization
import XCTest
@testable import RemozioCore

@MainActor
final class MacSetupRecoveryChannelTests: XCTestCase {
    nonisolated final class Fixture: MacSetupRecoveryChannelDriver, Sendable {
        typealias Wire = SetupOrphanRecoveryWire
        struct State: Sendable {
            var calls: [String] = []
            var pid: pid_t = 20
            var version = Wire.ipcVersion
            var startCode: Wire.Code = .requestRecorded
            var progressCode: Wire.Code = .pending
            var wrongID = false
            var exported = false
            var holdStart = false
            var onHeldStart: (@Sendable () -> Void)?
            var onHeldProgress: (@Sendable () -> Void)?
            var expire: (@Sendable () async -> Void)?
            var closeCount = 0
            var delayedReply: (@Sendable (SetupClientReply) -> Void)?
            var disconnected: (@Sendable () -> Void)?
            var request: Wire.Request?
        }

        let state = Mutex(State())
        static let form = Data(repeating: 1, count: MemoryLayout<AuthorizationExternalForm>.size)

        func activate(onClose: @escaping @Sendable () -> Void) { state.withLock { $0.disconnected = onClose } }
        func peer() throws -> XPCPeerCredentials { state.withLock { .init(processID: $0.pid, userID: 0, auditSessionID: 1) } }
        func close() { state.withLock { $0.closeCount += 1 } }

        func send(_ call: MacSetupRecoveryCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            var signal: (@Sendable () -> Void)?
            let result: SetupClientReply? = state.withLock { state in
                do {
                    switch call {
                    case .status(let bytes):
                        state.calls.append("status")
                        let request = try SetupRetainedStatusWire.Request.decode(bytes)
                        return .progress(try SetupRetainedStatusWire.reply(request, .unavailable))
                    case .hello:
                        state.calls.append("hello")
                        return .version(state.version)
                    case .start(let bytes, _):
                        state.calls.append("start")
                        let request = try Wire.Request.decode(bytes)
                        state.request = request
                        if state.holdStart {
                            state.delayedReply = reply
                            signal = state.onHeldStart
                            return nil
                        }
                        return .progress(try Wire.Reply(requestID: state.wrongID ? Data(repeating: 0, count: 16) : request.requestID,
                            code: state.startCode).bytes)
                    case .progress(let bytes):
                        state.calls.append("progress")
                        let request = try Wire.Progress.decode(bytes)
                        guard request.requestID == state.request?.requestID else { return .failed }
                        if let onHeldProgress = state.onHeldProgress {
                            state.delayedReply = reply
                            signal = onHeldProgress
                            return nil
                        }
                        return .progress(try Wire.Reply(requestID: request.requestID, code: state.progressCode).bytes)
                    }
                } catch { return .failed }
            }
            signal?()
            if let result { reply(result) }
        }

        func channel(_ lane: MacSetupRecoveryLane = .recovery) -> MacSetupRecoveryChannel {
            .init(lane: lane, driver: self, scheduleTimeout: { expire in
                self.state.withLock { $0.expire = expire }
                return nil
            })
        }
    }

    private func request(action: SetupOrphanRecoveryWire.Action = .restore) throws -> SetupOrphanRecoveryWire.Request {
        try .init(requestID: Data(repeating: 9, count: 16), action: action,
            identity: .init(reservationID: UUID(), incarnation: UUID()))
    }

    private func fails(_ body: () async throws -> Void) async {
        do { try await body(); XCTFail("Expected refusal") } catch {}
    }

    func testStatusIsFirstCallOnSeparateConnection() async throws {
        let status = Fixture(), recovery = Fixture()
        let channel = status.channel(.status)
        let value = try await channel.readStatus()
        XCTAssertNil(value.identity)
        await fails { try await channel.open() }
        try await recovery.channel().open()
        XCTAssertEqual(status.state.withLock { $0.calls }, ["status"])
        XCTAssertEqual(recovery.state.withLock { $0.calls }, ["hello"])
    }

    func testUnsupportedVersionsRefuseBeforeSending() async {
        for version in [UInt64(0), 11, Fixture.Wire.ipcVersion + 1] {
            let fixture = Fixture(), channel = fixture.channel()
            fixture.state.withLock { $0.version = version }
            await fails { try await channel.open() }
            await fails { _ = try await channel.start(request(), readAuthorization: { Fixture.form }) }
            XCTAssertEqual(fixture.state.withLock { $0.calls }, ["hello"])
        }
    }

    func testMissingIdentityRefusesBeforeReadingRights() async throws {
        let fixture = Fixture(), channel = fixture.channel()
        try await channel.open()
        let unbound = try SetupOrphanRecoveryWire.Request(requestID: Data(repeating: 9, count: 16), action: .releaseWindowFree)
        await fails { _ = try await channel.start(unbound) { fixture.state.withLock { $0.exported = true }; return Fixture.form } }
        XCTAssertFalse(fixture.state.withLock { $0.exported })
        XCTAssertEqual(fixture.state.withLock { $0.calls }, ["hello"])
    }

    func testPeerChangeRefusesBeforeExport() async throws {
        let fixture = Fixture(), channel = fixture.channel()
        try await channel.open()
        fixture.state.withLock { $0.pid += 1 }
        await fails { _ = try await channel.start(request()) { fixture.state.withLock { $0.exported = true }; return Fixture.form } }
        XCTAssertFalse(fixture.state.withLock { $0.exported })
        XCTAssertEqual(fixture.state.withLock { $0.calls }, ["hello"])
    }

    func testPeerChangeDuringExportPreventsDispatch() async throws {
        let fixture = Fixture(), channel = fixture.channel()
        try await channel.open()
        await fails {
            _ = try await channel.start(request()) {
                fixture.state.withLock { $0.pid += 1 }
                return Fixture.form
            }
        }
        XCTAssertEqual(fixture.state.withLock { $0.calls }, ["hello"])
    }

    func testWrongRequestIDAndTerminalStartReplyRefuse() async throws {
        for wrongID in [false, true] {
            let fixture = Fixture(), channel = fixture.channel()
            fixture.state.withLock { $0.wrongID = wrongID; $0.startCode = wrongID ? .requestRecorded : .restored }
            try await channel.open()
            await fails { _ = try await channel.start(request(), readAuthorization: { Fixture.form }) }
            await fails { _ = try await channel.readProgress() }
            XCTAssertEqual(fixture.state.withLock { $0.calls }, ["hello", "start"])
        }
    }

    func testLateStartCallbackCannotBecomeProgressOrPermitReplay() async throws {
        let fixture = Fixture(), channel = fixture.channel()
        let dispatched = expectation(description: "Start dispatched")
        fixture.state.withLock { $0.holdStart = true; $0.onHeldStart = { dispatched.fulfill() } }
        try await channel.open()
        let request = try request()
        let start = Task { try await channel.start(request, readAuthorization: { Fixture.form }) }
        await fulfillment(of: [dispatched], timeout: 5)
        let expire = try XCTUnwrap(fixture.state.withLock { $0.expire })
        await expire()
        do {
            _ = try await start.value
            XCTFail("Expected timeout")
        } catch let error as AdministrativeSetupChannelError { XCTAssertEqual(error, .timedOut) }
        let reply = try SetupOrphanRecoveryWire.Reply(requestID: request.requestID, code: .requestRecorded).bytes
        fixture.state.withLock { $0.delayedReply }?(.progress(reply))
        let progress = try await channel.readProgress()
        XCTAssertEqual(progress, .pending)
        await fails { _ = try await channel.start(request, readAuthorization: { Fixture.form }) }
        XCTAssertEqual(fixture.state.withLock { $0.calls }, ["hello", "start", "progress"])
    }

    func testInterruptedConnectionCannotReadOnReplacementLane() async throws {
        let fixture = Fixture(), channel = fixture.channel()
        let replacement = Fixture(), fresh = replacement.channel()
        try await channel.open()
        _ = try await channel.start(request(), readAuthorization: { Fixture.form })
        fixture.state.withLock { $0.disconnected }?()
        await fails { _ = try await channel.readProgress() }
        try await fresh.open()
        await fails { _ = try await fresh.readProgress() }
        XCTAssertEqual(fixture.state.withLock { $0.calls }, ["hello", "start"])
        XCTAssertEqual(replacement.state.withLock { $0.calls }, ["hello"])
    }

    func testRecoveryFormatRequiresTheVerifiedReleaseToDeclareBothSides() throws {
        let withoutRecovery = try XCTUnwrap(RuntimeActivationFixture(nativeConsumerHosts: true).nativeRelease)
        XCTAssertNoThrow(try MacSetupRecoveryChannel.requireFormats(lane: .status, release: withoutRecovery))
        XCTAssertThrowsError(try MacSetupRecoveryChannel.requireFormats(lane: .recovery, release: withoutRecovery))
        let withRecovery = try XCTUnwrap(RuntimeActivationFixture(nativeConsumerHosts: true, auditDelivery: true).nativeRelease)
        XCTAssertNoThrow(try MacSetupRecoveryChannel.requireFormats(lane: .recovery, release: withRecovery))
    }

}
