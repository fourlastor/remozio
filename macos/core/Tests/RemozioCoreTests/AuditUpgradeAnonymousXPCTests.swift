import Darwin
import Foundation
import Security
import Synchronization
import XCTest
@testable import RemozioCore

/// Anonymous ordinary-user XPC verifies selector transport. It does not simulate a trusted Root signature or native rights.
final class AuditUpgradeAnonymousXPCTests: XCTestCase {
    private struct Refused: Error {}
    private final class Host: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        struct State {
            var endpoints: [AdministrativeSetupXPCEndpoint] = []
            var imports = 0
            var importsHadCurrentConnection = true
        }
        let state = Mutex(State())
        let harness: RuntimeAuditUpgradeOperationTests.Harness
        let owner: SetupAccountOwner
        init(harness: RuntimeAuditUpgradeOperationTests.Harness, owner: SetupAccountOwner) { self.harness = harness; self.owner = owner }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            do {
                guard connection.effectiveUserIdentifier == getuid(), connection.processIdentifier == getpid() else { throw Refused() }
                let operations = try SetupAuditUpgradeEndpointOperations.owned(importAuthorization: { [weak connection, self] form in
                    guard let connection, NSXPCConnection.current() === connection,
                          form.count == MemoryLayout<AuthorizationExternalForm>.size else { throw Refused() }
                    state.withLock { $0.imports += 1; $0.importsHadCurrentConnection = $0.importsHadCurrentConnection && NSXPCConnection.current() === connection }
                    return try .openOwned(callerUID: connection.effectiveUserIdentifier, verifyRights: {})
                }, openInvocation: { [self] expected, grant in
                    try .openOwned(owner: owner, expected: expected, authorization: grant, openOperation: harness.operation(scope:))
                })
                let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { [weak connection] in
                    guard let connection, NSXPCConnection.current() === connection,
                          connection.effectiveUserIdentifier == getuid(), connection.processIdentifier == getpid() else { throw Refused() }
                    return connection.effectiveUserIdentifier
                }, authorize: { _ in throw Refused() }, invalidate: { [weak connection] in connection?.invalidate() }, auditUpgradeOperations: operations)
                connection.exportedInterface = NSXPCInterface(with: AdministrativeSetupMaintenanceXPCProtocol.self)
                connection.exportedObject = endpoint
                connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
                connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }
                state.withLock { $0.endpoints.append(endpoint) }; connection.activate(); return true
            } catch { connection.invalidate(); return false }
        }
        func settle() async { for endpoint in state.withLock({ $0.endpoints }) { await endpoint.waitForAuditUpgradeWork() } }
        func close() { for endpoint in state.withLock({ $0.endpoints }) { endpoint.close() } }
    }
    private final class Driver: AuditUpgradeSetupDriver, @unchecked Sendable {
        let connection: NSXPCConnection
        init(_ endpoint: NSXPCListenerEndpoint) {
            connection = NSXPCConnection(listenerEndpoint: endpoint)
            connection.remoteObjectInterface = NSXPCInterface(with: AuditUpgradeSetupXPCProtocol.self)
        }
        func start(closed: @escaping @Sendable () -> Void) {
            connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
        }
        func verifyPeer() throws {
            guard connection.effectiveUserIdentifier == getuid(), connection.processIdentifier == getpid() else { throw Refused() }
        }
        func invoke(_ call: AuditUpgradeSetupCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any AuditUpgradeSetupXPCProtocol else { reply(.failed); return }
            switch call {
            case .hello: proxy.auditUpgradeHello { reply(.version($0)) }
            case .progress: proxy.auditUpgradeProgress { reply(.progress($0)) }
            case .perform(let expected, let form):
                do { proxy.performAuditUpgrade(try expected.bytes, authorization: form) { reply(.progress($0)) } } catch { reply(.failed) }
            }
        }
        func close() { connection.invalidate() }
        deinit { connection.invalidate() }
    }
    private final class ResultBox: @unchecked Sendable {
        let state = Mutex<Result<Void, any Error>?>(nil)
    }
    /// Holds the cutover worker after restart, while the operation still owns the setup reservation.
    private final class Gate: Sendable {
        let held = Mutex(false)
        private let release = DispatchSemaphore(value: 0)
        func hold() { held.withLock { $0 = true }; release.wait(); release.signal() }
        func open() { release.signal() }
    }
    private static func until(_ predicate: () -> Bool) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(10))
        while !predicate() { guard ContinuousClock.now < end else { throw AdministrativeSetupChannelError.timedOut }; try await Task.sleep(for: .milliseconds(5)) }
    }
    func testAnonymousTransportNegotiatesTheCombinedInterfaceAndReconcilesAOneShotMutation() throws {
        let h = try RuntimeAuditUpgradeOperationTests.Harness(gateway: true), owner = try h.owner()
        let host = Host(harness: h, owner: owner), listener = NSXPCListener.anonymous()
        listener.delegate = host; listener.activate()
        defer { host.close(); listener.invalidate(); try? owner.close() }
        let endpoint = listener.endpoint, result = ResultBox(), done = expectation(description: "Anonymous XPC round trip")
        let form = Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)
        Task.detached {
            do {
                let channel = AuditUpgradeSetupChannel(driver: Driver(endpoint), timeoutMilliseconds: 10_000, operationTimeoutMilliseconds: 25_000)
                try await channel.start()
                let initial = try await channel.progress()
                let expected = try XCTUnwrap(initial)
                let actual = try await channel.perform(expected, authorization: form)
                XCTAssertEqual(actual.stage, .registrationObserved)
                XCTAssertEqual(actual.registrationObserved, [.authority, .transport, .notificationGateway])
                await host.settle()
                let recovery = AuditUpgradeSetupChannel(driver: Driver(endpoint), expected: expected, timeoutMilliseconds: 10_000)
                try await recovery.start()
                let recovered = try await recovery.progress()
                let snapshot = try XCTUnwrap(recovered)
                XCTAssertEqual(snapshot.stage, .metadataCommitted); XCTAssertTrue(snapshot.registrationObserved.isEmpty)
                try snapshot.validateScope(of: expected)
                await recovery.close(); await host.settle()
                result.state.withLock { $0 = .success(()) }
            } catch { result.state.withLock { $0 = .failure(error) } }
            done.fulfill()
        }
        wait(for: [done], timeout: 45)
        try result.state.withLock { try XCTUnwrap($0).get() }
        XCTAssertEqual(host.state.withLock { $0.imports }, 1)
        XCTAssertTrue(host.state.withLock { $0.importsHadCurrentConnection })
        try owner.verifyCurrent(); XCTAssertTrue(h.bootstraps.values.allSatisfy { $0 == 1 })
    }
    /// The endpoint refuses reads and handshakes while another connection owns the cutover.
    /// The channel reports unknown state, the running mutation still finishes, and a fresh read sees the committed scope.
    func testOtherConnectionsSeeUnavailableProgressWhileACutoverRuns() throws {
        let h = try RuntimeAuditUpgradeOperationTests.Harness(gateway: true), owner = try h.owner()
        let host = Host(harness: h, owner: owner), listener = NSXPCListener.anonymous(), gate = Gate()
        h.afterRestart = { gate.hold() }
        listener.delegate = host; listener.activate()
        defer { gate.open(); host.close(); listener.invalidate(); try? owner.close() }
        let endpoint = listener.endpoint, result = ResultBox(), done = expectation(description: "Reads during an anonymous XPC cutover")
        let form = Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)
        Task.detached {
            do {
                let channel = AuditUpgradeSetupChannel(driver: Driver(endpoint), timeoutMilliseconds: 10_000, operationTimeoutMilliseconds: 25_000)
                try await channel.start()
                let initial = try await channel.progress()
                let expected = try XCTUnwrap(initial)
                // This connection finishes its handshake before the cutover starts.
                let early = AuditUpgradeSetupChannel(driver: Driver(endpoint), timeoutMilliseconds: 5_000)
                try await early.start()
                let mutation = Task { try await channel.perform(expected, authorization: form) }
                try await AuditUpgradeAnonymousXPCTests.until { gate.held.withLock { $0 } }
                do { _ = try await early.progress(); XCTFail("Read during cutover") }
                catch { XCTAssertEqual(error as? AuditUpgradeSetupChannelError, .progressUnavailable) }
                let late = AuditUpgradeSetupChannel(driver: Driver(endpoint), timeoutMilliseconds: 5_000)
                do { try await late.start(); _ = try await late.progress(); XCTFail("Handshake during cutover") }
                catch { XCTAssertEqual(error as? AuditUpgradeSetupChannelError, .progressUnavailable) }
                gate.open()
                let actual = try await mutation.value
                XCTAssertEqual(actual.stage, .registrationObserved)
                XCTAssertEqual(actual.registrationObserved, [.authority, .transport, .notificationGateway])
                await host.settle()
                let recovery = AuditUpgradeSetupChannel(driver: Driver(endpoint), expected: expected, timeoutMilliseconds: 10_000)
                try await recovery.start()
                let recovered = try await recovery.progress()
                let snapshot = try XCTUnwrap(recovered)
                XCTAssertEqual(snapshot.stage, .metadataCommitted); XCTAssertTrue(snapshot.registrationObserved.isEmpty)
                try snapshot.validateScope(of: expected)
                await recovery.close(); await host.settle()
                result.state.withLock { $0 = .success(()) }
            } catch { gate.open(); result.state.withLock { $0 = .failure(error) } }
            done.fulfill()
        }
        wait(for: [done], timeout: 45)
        try result.state.withLock { try XCTUnwrap($0).get() }
        XCTAssertEqual(host.state.withLock { $0.imports }, 1)
        XCTAssertEqual(h.restarts, 1)
        try owner.verifyCurrent(); XCTAssertTrue(h.bootstraps.values.allSatisfy { $0 == 1 })
    }
}
