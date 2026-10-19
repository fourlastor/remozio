import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Actual anonymous NSXPC transport with an owned fixture endpoint. This does not exercise production peer authentication.
final class GatewaySettingsControlNativeTests: XCTestCase, @unchecked Sendable {
    private final class Listener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
        let endpoint: GatewaySettingsControlXPCEndpoint
        private let lock = NSLock()
        private var connections: [NSXPCConnection] = []
        init(_ endpoint: GatewaySettingsControlXPCEndpoint) { self.endpoint = endpoint }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            connection.exportedInterface = NSXPCInterface(with: GatewaySettingsControlXPCProtocol.self)
            connection.exportedObject = endpoint
            lock.withLock { connections.append(connection) }
            connection.activate(); return true
        }
        func close() {
            let owned = lock.withLock { let old = connections; connections = []; return old }
            for connection in owned { connection.invalidate() }
            endpoint.close()
        }
    }
    func testActualNSXPCBridgesTheVersionBindingAndBoundedControlReply() async throws {
        let binding = try GatewaySettingsControlBinding(accountID: Data(repeating: 1, count: 16), rootEpoch: UUID())
        let change = try AuthorityPhonePushSettingsChange(revisionDigest: Data(repeating: 2, count: 32),
            previousCommitDigest: Data(repeating: 3, count: 32), selectedCommitDigest: Data(repeating: 4, count: 32))
        let request = try GatewaySettingsControlRequest(binding: binding, change: change, action: .quiesce,
            challenge: Data(repeating: 5, count: 32))
        let executions = Mutex(0)
        let endpoint = GatewaySettingsControlXPCEndpoint(binding: binding, verify: {}, verifyCurrent: {},
            budget: try .init(maximum: 1), invalidate: {}, execute: { received in
                XCTAssertEqual(try received.encoded, try request.encoded); executions.withLock { $0 += 1 }; return .suspended
            })
        let delegate = Listener(endpoint), listener = NSXPCListener.anonymous()
        listener.delegate = delegate; listener.activate()
        let client = NSXPCConnection(listenerEndpoint: listener.endpoint)
        client.remoteObjectInterface = NSXPCInterface(with: GatewaySettingsControlXPCProtocol.self)
        client.activate()
        defer { client.invalidate(); delegate.close(); listener.invalidate() }
        let hello = expectation(description: "Native hello"), control = expectation(description: "Native control")
        let bindingReply = Mutex<Data?>(nil), result = Mutex<Data?>(nil)
        let proxy = try XCTUnwrap(client.remoteObjectProxyWithErrorHandler { error in
            XCTFail("Owned native control transport failed: \(error)"); hello.fulfill(); control.fulfill()
        } as? any GatewaySettingsControlXPCProtocol)
        proxy.hello { version, bytes in
            XCTAssertEqual(version, 1); bindingReply.withLock { $0 = bytes }; hello.fulfill()
        }
        await fulfillment(of: [hello], timeout: 5)
        XCTAssertEqual(try GatewaySettingsControlBinding.decode(XCTUnwrap(bindingReply.withLock { $0 })), binding)
        proxy.control(try request.encoded) { bytes in result.withLock { $0 = bytes }; control.fulfill() }
        await fulfillment(of: [control], timeout: 5)
        XCTAssertEqual(try GatewaySettingsControlResponse.decode(XCTUnwrap(result.withLock { $0 }), expected: request).observation, .suspended)
        XCTAssertEqual(executions.withLock { $0 }, 1)
    }
}
