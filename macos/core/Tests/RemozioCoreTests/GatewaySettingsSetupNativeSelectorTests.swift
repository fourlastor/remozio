import Darwin
import Foundation
import Security
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsSetupNativeSelectorTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class Reply<Value: Sendable>: Sendable {
        let continuation: Mutex<CheckedContinuation<Value, any Error>?>
        init(_ value: CheckedContinuation<Value, any Error>) {
            continuation = Mutex(value)
            DispatchQueue.global().asyncAfter(deadline: .now() + 5) { [self] in finish(.failure(Failed())) }
        }
        func finish(_ result: Result<Value, any Error>) {
            let current = continuation.withLock { value in let current = value; value = nil; return current }
            current?.resume(with: result)
        }
    }
    private final class Listener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        let owner: SetupAccountOwner
        let rights = Mutex(0)
        private let lock = NSLock()
        private var connections: [NSXPCConnection] = []
        init(_ owner: SetupAccountOwner) { self.owner = owner }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { [weak connection] in
                guard let connection, let invocation = NSXPCConnection.current(),
                      invocation === connection, invocation.effectiveUserIdentifier == getuid() else { throw Failed() }
                return invocation.effectiveUserIdentifier
            }, authorize: { [self] _ in
                guard NSXPCConnection.current() != nil else { throw Failed() }
                rights.withLock { $0 += 1 }
            }, invalidate: { [weak connection] in connection?.invalidate() })
            connection.exportedInterface = NSXPCInterface(with: AdministrativeSetupXPCProtocol.self)
            connection.exportedObject = endpoint
            lock.withLock { connections.append(connection) }; connection.activate(); return true
        }
        func close() {
            let current = lock.withLock { let current = connections; connections = []; return current }
            for connection in current { connection.invalidate(); connection.exportedObject = nil }
        }
    }
    private func exchange<Value: Sendable>(_ connection: NSXPCConnection,
        _ send: (any AdministrativeSetupXPCProtocol, @escaping @Sendable (Value) -> Void) -> Void) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            let reply = Reply(continuation)
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ reply.finish(.failure($0)) }) as? any AdministrativeSetupXPCProtocol else {
                reply.finish(.failure(Failed())); return
            }
            send(proxy) { reply.finish(.success($0)) }
        }
    }
    func testSettingsSelectorsTraverseAnActualAnonymousConnection() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), delegate = Listener(h.owner)
        let listener = NSXPCListener.anonymous(); listener.delegate = delegate; listener.activate()
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: AdministrativeSetupXPCProtocol.self); connection.activate()
        defer { connection.invalidate(); listener.invalidate(); listener.delegate = nil; delegate.close() }
        let version: UInt64 = try await exchange(connection) { $0.gatewaySettingsHello(reply: $1) }
        XCTAssertEqual(version, 8)
        let bytes: Data? = try await exchange(connection) { $0.gatewaySettingsProgress(reply: $1) }
        let empty = try SetupGatewaySettingsProgress.decode(XCTUnwrap(bytes))
        XCTAssertEqual(delegate.rights.withLock { $0 }, 0)
        let form = Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)
        let expected = try empty.bytes, selected = try h.selection.bytes
        let retained: Data? = try await exchange(connection) { $0.retainGatewaySettings(expected, selection: selected, authorization: form, reply: $1) }
        let pending = try SetupGatewaySettingsProgress.decode(XCTUnwrap(retained)), pendingBytes = try pending.bytes
        let completed: Data? = try await exchange(connection) { $0.resumeGatewaySettings(pendingBytes, authorization: form, reply: $1) }
        let done = try SetupGatewaySettingsProgress.decode(XCTUnwrap(completed))
        XCTAssertEqual(try done.activeDigest, try pending.pendingDigest); XCTAssertNil(try done.pendingDigest)
        XCTAssertEqual(delegate.rights.withLock { $0 }, 2)
        // The wire and invocation UID are native. Administrator rights and the transition backend are owned fixtures.
    }
}
