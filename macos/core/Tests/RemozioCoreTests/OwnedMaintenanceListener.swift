import Darwin
import Foundation
@testable import RemozioCore

/// Test-owned transport for the connection owner. It creates no product Mach service or Root admission.
final class OwnedMaintenanceListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let native: NSXPCListener
    let owner: AuthorityMaintenanceConnections
    private init(_ native: NSXPCListener, _ owner: AuthorityMaintenanceConnections) {
        self.native = native; self.owner = owner; super.init(); native.delegate = self
    }
    static func openOwned(listener: NSXPCListener, builder: any AuthorityMaintenanceEndpointBuilding,
        maximumConnections: Int = 2, maximumOperations: Int = 1, handshakeTimeoutMilliseconds: UInt64 = 5000,
        verifyCurrent: @escaping @Sendable () throws -> Void = {}) throws -> OwnedMaintenanceListener {
        try .init(listener, .openOwned(builder: builder, maximumConnections: maximumConnections,
            maximumOperations: maximumOperations, handshakeTimeoutMilliseconds: handshakeTimeoutMilliseconds, verifyCurrent: verifyCurrent))
    }
    func start() throws { try owner.start(); native.activate() }
    func close() { native.invalidate(); owner.close() }
    func closeAndWait() async { close(); await owner.closeAndWait() }
    func retainedEndpoints() -> Int { owner.retainedEndpoints() }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard listener === native else { connection.invalidate(); return false }; return owner.accept(connection)
    }
    deinit { close() }
}
