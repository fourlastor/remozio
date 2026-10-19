import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// The anonymous transport uses an owned peer verifier. Production UID and signed-code admission remain unproven here.
final class GatewaySettingsControlNativeClientTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private final class Listener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        let endpoint: GatewaySettingsControlXPCEndpoint
        private let lock = NSLock()
        private var owned: [NSXPCConnection] = []
        init(_ endpoint: GatewaySettingsControlXPCEndpoint) { self.endpoint = endpoint }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            connection.exportedInterface = NSXPCInterface(with: GatewaySettingsControlXPCProtocol.self)
            connection.exportedObject = endpoint
            lock.withLock { owned.append(connection) }; connection.activate(); return true
        }
        func close() {
            let previous = lock.withLock { let old = owned; owned = []; return old }
            for connection in previous { connection.invalidate() }
            endpoint.close()
        }
    }
    private func exchange(rejectReply: Bool) async throws {
        let binding = try GatewaySettingsControlBinding(accountID: Data(repeating: 1, count: 16), rootEpoch: UUID())
        let change = try AuthorityPhonePushSettingsChange(revisionDigest: Data(repeating: 2, count: 32),
            previousCommitDigest: Data(repeating: 3, count: 32), selectedCommitDigest: Data(repeating: 4, count: 32))
        let executions = Mutex(0), verifications = Mutex(0)
        let endpoint = GatewaySettingsControlXPCEndpoint(binding: binding, verify: {}, verifyCurrent: {},
            budget: try .init(maximum: 1), invalidate: {}, execute: { request in
                XCTAssertEqual(request.change, change); executions.withLock { $0 += 1 }; return .suspended
            })
        let delegate = Listener(endpoint), listener = NSXPCListener.anonymous()
        listener.delegate = delegate; listener.activate()
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        let driver = NativeGatewaySettingsControlDriver(connection: connection, verifyPeer: {
            let count = verifications.withLock { $0 += 1; return $0 }
            if rejectReply && count == 2 { throw Denied() }
        })
        let channel = try GatewaySettingsControlChannel(driver: driver, accountID: binding.accountID,
            expectedRootEpoch: binding.rootEpoch, timeoutMilliseconds: 3000, challenge: { Data(repeating: 5, count: 32) })
        defer { connection.invalidate(); delegate.close(); listener.invalidate() }
        if rejectReply {
            do { _ = try await channel.execute(change, action: .quiesce); XCTFail("An unverified reply cannot acknowledge the action") }
            catch { XCTAssertEqual(error as? GatewaySettingsControlChannelError, .closed) }
        } else {
            let result = try await channel.execute(change, action: .quiesce)
            XCTAssertEqual(result.request.binding, binding); XCTAssertEqual(result.observation, .suspended)
        }
        XCTAssertEqual(verifications.withLock { $0 }, 2); XCTAssertEqual(executions.withLock { $0 }, 1)
        do { _ = try await channel.execute(change, action: .quiesce); XCTFail("No automatic retry of an uncertain action") } catch {}
        XCTAssertEqual(executions.withLock { $0 }, 1)
    }
    func testTheNativeDriverAndClientCompleteAnActualAnonymousNSXPCExchange() async throws {
        try await exchange(rejectReply: false)
    }
    func testFailedPeerVerificationAfterARealReplyDoesNotAcknowledgeOrRepeatTheAction() async throws {
        try await exchange(rejectReply: true)
    }
}
